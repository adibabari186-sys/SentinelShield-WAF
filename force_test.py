import requests

BASE_URL = "http://127.0.0.1:5000"

# Sample Attack Payloads to trigger WAF detection
attacks = [
    ("/login?username=admin' OR '1'='1", "SQL Injection"),
    ("/login?username=<script>alert('xss')</script>", "XSS Attack"),
    ("/login?username=../../etc/passwd", "Path Traversal"),
    ("/login?username=UNION SELECT null, username FROM users--", "SQL Injection")
]

print("[*] Sending test payloads to SentinelShield WAF...")

for path, attack_name in attacks:
    try:
        url = BASE_URL + path
        response = requests.get(url)
        print(f"[{response.status_code}] Sent {attack_name} -> Response: {response.text}")
    except Exception as e:
        print(f"[!] Error sending request: {e}")

print("\n[+] Tests sent successfully!")
