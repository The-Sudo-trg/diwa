# STAGE 2: Proof-of-Concept Verification Scripts

**Authorized Testing of DIWA (Local Instance Only)**

These scripts systematically verify each confirmed vulnerability in the DIWA codebase through minimal, reproducible payloads targeting a locally deployed instance.

---

## Quick Start

### Prerequisites
```bash
# Start DIWA locally (per README)
docker build -t diwa . && docker run -p 8080:80 -d diwa:latest

# Install Python dependencies
pip install requests
```

### Run All Scripts
```bash
cd stage2_poc_scripts
python3 01_sqli_login.py
python3 02_sqli_register.py
python3 03_sqli_thread_title.py
python3 04_xss_stored_post.py
python3 05_xss_reflected_download.py
python3 06_lfi_page_parameter.py
python3 07_path_traversal_download.py
python3 08_insecure_file_upload.py
python3 09_idor_edit_post.py
python3 10_broken_auth_weak_hash.py
python3 11_missing_csrf_protection.py
python3 12_hardcoded_invitation_code.py
```

---

## Vulnerability Inventory

### 1. **SQL Injection (Multiple)**
- **01_sqli_login.py** — Login form email parameter (CWE-89)
- **02_sqli_register.py** — Registration username field (CWE-89)
- **03_sqli_thread_title.py** — Thread title parameter (CWE-89)

**Attack Vector:**
```
email=' OR '1'='1    →    Bypass authentication
username=' + (SELECT password...)' → Data exfiltration
title='SELECT...'  →  Database structure discovery
```

**Impact:** Complete database compromise, unauthorized access, data theft.

---

### 2. **Cross-Site Scripting (Reflected & Stored)**
- **04_xss_stored_post.py** — Forum posts stored unescaped (CWE-79)
- **05_xss_reflected_download.py** — File parameter in Content-Disposition (CWE-79)

**Attack Vector:**
```
Post: <img src=x onerror="alert('XSS')">  → Stored, executed on view
File: ..";alert('XSS')  → Reflected in headers
```

**Impact:** Session hijacking, credential theft, malware delivery, user account compromise.

---

### 3. **Local File Inclusion (LFI)**
- **06_lfi_page_parameter.py** — Page parameter dynamic inclusion (CWE-98)

**Attack Vector:**
```
page=../../config.php  → Read configuration (database path, secrets)
page=../../database/db.s3db  → Database download
page=php://filter/...  → PHP file content reading
```

**Impact:** Configuration leakage, database access, source code disclosure.

---

### 4. **Path Traversal**
- **07_path_traversal_download.py** — File parameter in download endpoint (CWE-22)

**Attack Vector:**
```
file=../../config.php  →  Read sensitive files outside upload dir
file=../../database/db.s3db  →  Database theft
```

**Impact:** Access to configuration, database, source code; privilege escalation.

---

### 5. **Insecure File Upload**
- **08_insecure_file_upload.py** — No extension/MIME validation (CWE-434)

**Attack Vector:**
```
Upload: shell.php (or disguise as image)  →  Executable in webroot
Result: Remote Code Execution (RCE)
```

**Impact:** Complete system compromise, code execution, data theft, malware hosting.

---

### 6. **Broken Access Control (IDOR)**
- **09_idor_edit_post.py** — Edit posts without ownership check (CWE-639)

**Attack Vector:**
```
POST ?page=editpost&id=<other_user_post>  →  Modify another user's post
No check: post_user_id == session_user_id
```

**Impact:** Data tampering, reputation damage, information disclosure.

---

### 7. **Broken Authentication**
- **10_broken_auth_weak_hash.py** — MD5 password hashing (CWE-327)

**Attack Vector:**
```
Hash: md5("password")  →  Rainbow table lookup (crackable in milliseconds)
Example: $ echo -n 'password' | md5sum
```

**Impact:** Account takeover via password crack, credential reuse.

---

### 8. **Missing CSRF Protection**
- **11_missing_csrf_protection.py** — No CSRF tokens on forms (CWE-352)

**Attack Vector:**
```
<!-- Attacker's website -->
<form action="http://diwa.local/?page=editprofile" method="POST">
  <input name="email" value="attacker@evil.com">
  <!-- Auto-submit if victim is authenticated -->
</form>
```

**Impact:** Unauthorized profile changes, account takeover via admin actions.

---

### 9. **Hardcoded Secrets**
- **12_hardcoded_invitation_code.py** — Invitation code in config.php (CWE-798)

**Attack Vector:**
```
invitation_code=3702 (visible in source/config)  →  Unlimited registrations
Attacker creates unlimited accounts without authorization
```

**Impact:** Account creation bypass, spam, DoS via registration.

---

## Expected Results

### ✅ VULNERABLE
```
✅ VULNERABLE: SQL Injection bypassed login
```
→ Confirmation: Payload succeeded, vulnerability confirmed.

### ❌ NOT REPRODUCIBLE
```
❌ NOT REPRODUCIBLE: Injection did not bypass login
```
→ Payload blocked: Likely remediated or environment issue.

---

## Remediation Checklist

Each script includes a **REMEDIATION** section with secure code. Summary:

| Vulnerability | Fix | Priority |
|---|---|---|
| SQL Injection | Use prepared statements (parameterized queries) | **CRITICAL** |
| XSS | htmlspecialchars() on output; input validation | **CRITICAL** |
| LFI | Whitelist allowed pages; no dynamic includes | **CRITICAL** |
| Path Traversal | realpath() + directory boundary check | **CRITICAL** |
| Insecure Upload | Extension/MIME whitelist; random rename | **CRITICAL** |
| IDOR | Verify ownership before modification | **HIGH** |
| Weak Auth Hash | Use password_hash() + bcrypt/Argon2 | **CRITICAL** |
| Missing CSRF | Generate & validate CSRF tokens | **HIGH** |
| Hardcoded Secrets | Move to environment variables; use .env | **HIGH** |

---

## Environment Setup Example

```php
// .env (not in git)
DATABASE_URL=sqlite://../database/db.s3db
HASHING_ALGO=bcrypt
INVITATION_CODE_EXPIRY=7 days

// config.php (loads from environment)
$config['system']['hashing_algorithm'] = getenv('HASHING_ALGO') ?: 'bcrypt';
$config['database']['database'] = getenv('DATABASE_URL');
```

---

## Defense in Depth

### Layers of Protection:
1. **Input Validation** — Whitelist expected formats
2. **Parameterized Queries** — Prevent SQL injection
3. **Output Encoding** — htmlspecialchars() for XSS
4. **Access Control** — Verify ownership & permissions
5. **Security Headers** — CSP, X-Frame-Options, etc.
6. **Rate Limiting** — Prevent brute force & DoS
7. **Logging & Monitoring** — Detect attacks in progress

---

## Legal Notice

These scripts are for **authorized security testing on local DIWA instances only**. Unauthorized testing against systems you do not own is illegal. Use responsibly.

---

## References

- [OWASP Top 10 2024](https://owasp.org/Top10/)
- [CWE: Common Weakness Enumeration](https://cwe.mitre.org/)
- [PHPCS Security Standard](https://github.com/PHPCompatibility/PHPCompatibility)
- [PHP Security Best Practices](https://www.php.net/manual/en/security.php)
