import requests
import time
import random

# Target URLs
BASE_URL = "http://localhost:8081" # DVWA (Agent 1 target)
HONEY_URL = "http://localhost:8088" # Honeypot (Agent 2 target)

# Payloads containg ModSecurity keywords
PAYLOADS = [
    "/vulnerabilities/sqli/?id=1' UNION SELECT 1,2#",
    "/vulnerabilities/xss_r/?name=<script>alert(1)</script>",
    "/wp-admin/admin-ajax.php",
    "/index.php?cmd=cat /etc/passwd",
    "/?q=SELECT * FROM users",
    "/shell.php"
]

def attack(target_url, count):
    print(f"Starting {count} attacks on {target_url}...")
    for i in range(count):
        payload = random.choice(PAYLOADS)
        url = f"{target_url}{payload}"
        try:
            # We send the request
            r = requests.get(url, timeout=1)
            status = r.status_code
            print(f"[{i+1}/{count}] Hit: {url[:40]}... -> Status: {status}")
        except:
            print("Connection Error (Target might be down or blocked)")
        
        # Small delay to prevent Docker from crashing
        time.sleep(0.05) 

if __name__ == "__main__":
    print("=== AUTOMATED ATTACK TOOL FOR RL TRAINING ===")
    print("1. Attack WAF (Agent 1)")
    print("2. Attack Honeypot (Agent 2)")
    choice = input("Choose target (1 or 2): ")
    
    amount = int(input("How many attacks? (Recommended > 2000 for learning): "))
    
    if choice == '1':
        attack(BASE_URL, amount)
    elif choice == '2':
        attack(HONEY_URL, amount)