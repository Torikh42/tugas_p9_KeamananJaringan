import urllib.parse

query = "email=victim%40uni.edu%5CnBcc%3A%20attacker%40evil.com"
params = urllib.parse.parse_qs(query)
email = params.get('email')[0]
print(f"Parsed email: {repr(email)}")

replaced = email.replace("\\n", "\n")
print(f"Replaced email: {repr(replaced)}")
