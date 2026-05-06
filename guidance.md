# Testing Guidance: Campus Event Portal Security Lab

Panduan ini berisi langkah-langkah untuk menguji dan mendemonstrasikan kerentanan serta kontrol keamanan yang ada di dalam aplikasi.

## 🚀 Persiapan
1. Pastikan server berjalan: `python src/web_server.py`
2. Buka browser di: `http://localhost:8000`
3. Gunakan tombol toggle di kanan atas untuk berpindah antara **Vulnerable Mode** (Merah) dan **Secure Mode** (Hijau).

---

## 1. SQL Injection (SQLi)
*Tab: Event Registration*

### A. Skenario Penyerangan (Vulnerable Mode)
1. Set toggle ke **Vulnerable**.
2. Input Nama: `' OR '1'='1' --`
3. Password: (Kosongkan atau isi sembarang).
4. Klik **Register / Login**.
5. **Hasil:** Login berhasil (**BYPASSED**). Query SQL terganggu oleh karakter `'` sehingga melewati pengecekan password.

### B. Skenario Pertahanan (Secure Mode)
1. Set toggle ke **Secure**.
2. Gunakan input yang sama: `' OR '1'='1' --`
3. Klik **Register / Login**.
4. **Hasil:** Akses ditolak (**BLOCKED**). Sistem menggunakan *Parameterized Queries* yang menganggap input tersebut sebagai data murni, bukan perintah SQL.

---

## 2. Stored Cross-Site Scripting (XSS)
*Tab: Event Comments*

### A. Skenario Penyerangan (Vulnerable Mode)
1. Set toggle ke **Vulnerable**.
2. Masukkan komentar: `<script>alert('Situs ini rentan XSS!')</script>`
3. Klik **Post Comment**.
4. **Hasil:** Muncul jendela alert di browser. Script dieksekusi karena sistem menggunakan `.innerHTML`.

### B. Skenario Pertahanan (Secure Mode)
1. Set toggle ke **Secure**.
2. Masukkan script yang sama.
3. Klik **Post Comment**.
4. **Hasil:** Script muncul sebagai teks biasa di layar. Sistem menggunakan `.textContent` dan `html.escape()` sehingga tag HTML tidak diproses oleh browser.

---

## 3. Broken Access Control (BAC)
*Tab: Admin Dashboard*

### A. Skenario Penyerangan (Vulnerable Mode)
1. Set toggle ke **Vulnerable**.
2. Username: `student_01`
3. Role: Ganti menjadi `admin` (mensimulasikan manipulasi parameter URL/Request).
4. Klik **Access Admin Panel**.
5. **Hasil:** Akses **GRANTED**. Server percaya begitu saja pada parameter `role` yang dikirimkan client.

### B. Skenario Pertahanan (Secure Mode)
1. Set toggle ke **Secure**.
2. Gunakan input yang sama: `student_01` & `admin`.
3. Klik **Access Admin Panel**.
4. **Hasil:** Akses **DENIED**. Server mengabaikan parameter `role` dari client dan melakukan validasi ulang ke database berdasarkan `username`.

---

---

## 4. Email Security & Anti-Phishing
*Tab: Email Security*

Bagian ini mendemonstrasikan kerentanan pada sistem pengiriman email otomatis.

### A. Header Injection Attack
Serangan ini mencoba menyisipkan header email tambahan (seperti Bcc) dengan memanfaatkan karakter newline (`\n`).

1.  **Skenario Penyerangan (Vulnerable Mode):**
    *   Set toggle ke **Vulnerable**.
    *   **Recipient Email:** `victim@uni.edu\nBcc: attacker@evil.com`
    *   **Event Name:** `Free Pizza Event`
    *   **Event Link:** `https://events.youruniversity.edu/e/99` (Isi bebas)
    *   Klik **Check Incoming Notification**.
    *   **Hasil:** Lihat di "Technical Headers". Muncul header baru `Injected-1 (Bcc)` dengan nilai `attacker@evil.com`. Email secara teknis akan terkirim ke `victim@uni.edu` sekaligus ke `attacker@evil.com` secara diam-diam.

2.  **Skenario Pertahanan (Secure Mode):**
    *   Set toggle ke **Secure**.
    *   Gunakan input yang sama: `victim@uni.edu\nBcc: attacker@evil.com`
    *   Klik **Check Incoming Notification**.
    *   **Hasil:** Muncul panel merah **SECURITY BLOCK**. Sistem mendeteksi karakter ilegal (`\n`) dan menghentikan pengiriman sebelum email diproses.

### B. Open Redirect & Phishing
Serangan ini mengarahkan pengguna ke situs jahat melalui link yang seolah-olah valid dari universitas.

1.  **Skenario Penyerangan (Vulnerable Mode):**
    *   Set toggle ke **Vulnerable**.
    *   **Recipient Email:** `student@uni.edu`
    *   **Event Name:** `URGENT: Verify Account`
    *   **Event Link:** `https://attacker-site.com/login?redirect=events.youruniversity.edu`
    *   Klik **Check Incoming Notification**.
    *   **Hasil:**
        *   **SPF/DKIM/DMARC:** Muncul status **FAIL/None** (Email mudah dipalsukan).
        *   **Link:** Link di dalam email mengarah ke situs attacker, namun teks link bisa menipu (Phishing).

2.  **Skenario Pertahanan (Secure Mode):**
    *   Set toggle ke **Secure**.
    *   Gunakan input yang sama (Link attacker).
    *   Klik **Check Incoming Notification**.
    *   **Hasil:** Muncul panel merah **SECURITY BLOCK**. Sistem menggunakan **Domain Whitelist** dan hanya mengizinkan link yang mengarah ke `events.youruniversity.edu`.

### C. Stored HTML Injection (Email Body)
Sama seperti XSS, tapi targetnya adalah aplikasi pembaca email (Email Client).

1.  **Skenario Penyerangan (Vulnerable Mode):**
    *   Set toggle ke **Vulnerable**.
    *   **Recipient Email:** `student@uni.edu`
    *   **Event Name:** `<img src=x onerror=alert('Email_XSS')> Tech Symposium`
    *   **Event Link:** `https://events.youruniversity.edu/e/42`
    *   Klik **Check Incoming Notification**.
    *   **Hasil:** Preview email mengeksekusi script (muncul alert). Ini berbahaya jika email dibuka di webmail yang tidak aman.

2.  **Skenario Pertahanan (Secure Mode):**
    *   Set toggle ke **Secure**.
    *   Gunakan input yang sama (Email, Event Name, dan Link).
    *   Klik **Check Incoming Notification**.
    *   **Hasil:** Script muncul sebagai teks mentah. Sistem melakukan `html.escape()` pada konten sebelum dimasukkan ke dalam template email.

---

## 📊 Summary: Testing Matrix

| Feature | Attack Type | Malicious Input | Vulnerable Result | Secure Result |
| :--- | :--- | :--- | :--- | :--- |
| **1. Registration** | SQL Injection | `' OR '1'='1' --` | **BYPASSED** (Login success) | **BLOCKED** (Query Parameterized) |
| **2. Comments** | Stored XSS | `<script>alert(1)</script>` | **EXECUTED** (Popup alert) | **ESCAPED** (Shows as text) |
| **3. Admin Panel** | Broken Access Control | Role: `admin` | **GRANTED** (Trusted param) | **DENIED** (Server-side check) |
| **4. Email Security** | Header Injection | `user@mail.com\nBcc: evil@com`| **INJECTED** (Headers split) | **BLOCKED** (Input Validation) |
| **4. Email Security** | Open Redirect | `https://evil-site.com` | **ALLOWED** (Phishing link) | **BLOCKED** (Domain Whitelist) |
| **4. Email Security** | Email Spoofing | (Default Check) | **FAIL** (Unauthenticated) | **PASS** (SPF/DKIM/DMARC OK) |

---

## 💡 Tips for Presentation
1.  **Diferensiasi Visual:** Tunjukkan bahwa pada **Secure Mode**, sistem tidak hanya "membersihkan" input, tapi **memblokir** secara proaktif (Fail-Fast) jika mendeteksi payload berbahaya.
2.  **Zero Trust Architecture:** Jelaskan bahwa mode Secure mengasumsikan semua input user adalah jahat sampai terbukti bersih melalui validasi ketat.
3.  **Real-World Context:**
    *   **Header Injection:** Jelaskan bahwa ini sering digunakan untuk mengirim spam/phishing menggunakan server resmi perusahaan.
    *   **SPF/DKIM/DMARC:** Jelaskan bahwa ini adalah "KTP/Paspor" digital untuk email agar tidak dianggap spam oleh Gmail/Outlook.
4.  **UML Alignment:** Tekankan bahwa logika validasi di `email_demo.py` adalah implementasi langsung dari diagram **Input Validation Flow** yang telah dibuat.
