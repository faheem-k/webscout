<div align="center">

```
██╗    ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝ ██║   ██║╚══██╔══╝
██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ██║      ██║   ██║   ██║   
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██║      ██║   ██║   ██║   
╚███╔███╔╝███████╗██████╔╝███████║╚██████╗╚██████╗ ╚██████╔╝   ██║   
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
```

**Web Application Security Header & JWT Analyzer**

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)](scanner.py)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-ff69b4?style=flat-square)](CONTRIBUTING.md)

> **Scan any web app in seconds. Find every missing security header. Crack open JWTs.**  
> Zero dependencies. Pure Python stdlib. One file. Brutal output.

</div>

---

## 🤔 Why Does This Exist?

You've just been handed a web app to audit. You need answers **fast**:

- Is HSTS configured?
- Does the CSP allow `'unsafe-inline'`?
- Are cookies missing `HttpOnly`?
- Is that JWT using `"alg": "none"`?
- Is the server leaking its version in headers?

You don't want to install Burp Suite for a quick check. You don't want to paste tokens into random websites. You want **one command** that gives you a full picture.

That's WebScout.

---

## ⚡ Quickstart

```bash
# No install. No pip. Just run.
git clone https://github.com/yourhandle/webscout
cd webscout
python scanner.py https://your-target.com
```

**That's it.**

---

## 🎯 What It Detects

### 🛡️ Security Headers (11 Checks)

| Header | Severity | What it prevents |
|--------|----------|-----------------|
| `Strict-Transport-Security` | 🔴 HIGH | Forces HTTPS, prevents downgrade attacks |
| `Content-Security-Policy` | 🔴 HIGH | XSS, data injection |
| `X-Frame-Options` | 🟡 MEDIUM | Clickjacking |
| `X-Content-Type-Options` | 🟡 MEDIUM | MIME sniffing attacks |
| `Cross-Origin-Opener-Policy` | 🟡 MEDIUM | Cross-origin info leaks |
| `Referrer-Policy` | 🔵 LOW | Sensitive URL leakage |
| `Permissions-Policy` | 🔵 LOW | Camera/mic/geo abuse |
| `Cross-Origin-Resource-Policy` | 🔵 LOW | Cross-origin data theft |
| `Cross-Origin-Embedder-Policy` | 🔵 LOW | Spectre-style attacks |
| `Cache-Control` | 🔵 LOW | Sensitive data in cache |
| `X-XSS-Protection` | ℹ️ INFO | Legacy XSS filter |

It doesn't just check *presence* — it checks **values**:
- `CSP` with `'unsafe-inline'`? Flagged.
- `CSP` missing `default-src`? Flagged.
- `HSTS` without `includeSubDomains`? Flagged.
- `X-Frame-Options: ALLOWALL`? Flagged.

### 🔑 JWT Analysis (Deep)

WebScout dissects every JWT it finds — in cookies, response headers, or passed via CLI:

| Check | What it catches |
|-------|----------------|
| `alg: none` | 🔴 **CRITICAL** — signature verification bypass |
| No `exp` claim | 🔴 **HIGH** — token never expires |
| Expired token | 🔴 **HIGH** — stale token in use |
| `exp` > 30 days | 🟡 **MEDIUM** — excessive lifetime |
| `kid` SQLi/traversal | 🔴 **CRITICAL** — key injection attack |
| Sensitive fields | 🔴 **HIGH** — passwords/secrets in plaintext base64 |
| Missing `aud` claim | 🔵 **LOW** — replay attack risk |
| Missing `iss` claim | 🔵 **LOW** — unverified token origin |
| Empty signature | 🔴 **CRITICAL** — unsigned token |
| Weak algorithm | ℹ️ **INFO** — symmetric key risks |

### 🍪 Cookie Security

- `Secure` flag missing
- `HttpOnly` flag missing
- `SameSite` missing (CSRF risk)
- `SameSite=None` without `Secure`
- **Auto-detects JWTs stored in cookies** and deep-analyzes them

### 🔍 Information Disclosure

Flags headers that leak your tech stack to attackers:

```
Server: Apache/2.4.51 (Ubuntu)       ← tells attacker exactly what to exploit
X-Powered-By: PHP/7.4.3              ← EOL PHP version, now you're a target
X-AspNet-Version: 4.0.30319          ← .NET version fingerprint
X-Generator: WordPress 6.1.1         ← plugin exploit database, incoming
```

---

## 📸 Example Output

```
──────────────────────────────────────────────────────────
  Target:  https://example.com
  Status:  200
  Score:   52/100  [D]
──────────────────────────────────────────────────────────

🚨 Missing Security Headers (4)
  [HIGH]    Strict-Transport-Security
            Enforces HTTPS connections (HSTS)
            Recommended: max-age=31536000; includeSubDomains; preload

  [HIGH]    Content-Security-Policy
            Prevents XSS and data injection attacks
            Recommended: default-src 'self'; script-src 'self'; object-src 'none'

  [MEDIUM]  X-Frame-Options
            Prevents clickjacking attacks
            Recommended: DENY or SAMEORIGIN

  [MEDIUM]  Cross-Origin-Opener-Policy
            Isolates browsing context from cross-origin documents
            Recommended: same-origin

⚠️  Header Configuration Issues (1)
  [MEDIUM]  Content-Security-Policy
            Allows inline scripts — XSS risk
            Current: default-src *; script-src 'self' 'unsafe-inline'

🔍 Information Disclosure (2)
  [INFO]  Server: nginx/1.18.0
  [INFO]  X-Powered-By: Express

🍪 Cookie Issues (2)
  [MEDIUM]  session_id
             • Missing Secure flag — cookie sent over HTTP
             • Missing HttpOnly flag — accessible via JavaScript (XSS risk)

🔑 JWT Analysis
  Source: Cookie: auth_token
  Algorithm: HS256  |  Type: JWT
  Subject:   user@example.com
  Expires:   2025-12-31T00:00:00+00:00
  [HIGH]   No expiration (exp) claim — token never expires!
  [HIGH]   Sensitive field 'password_hash' found in JWT payload — JWTs are base64, NOT encrypted!
  [LOW]    No audience (aud) claim — token could be replayed to different services
```

---

## 🔧 Usage

```bash
# Basic scan
python scanner.py https://example.com

# Analyze a specific JWT token
python scanner.py https://example.com --jwt eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.

# Save JSON report (for CI/CD pipelines, automation)
python scanner.py https://example.com --output report.json

# Save Markdown report (for GitHub issues, Notion, etc.)
python scanner.py https://example.com --output report.md

# Custom timeout (default: 10s)
python scanner.py https://slow-site.com --timeout 30

# No color output (for logs / piping)
python scanner.py https://example.com --no-color

# Verbose mode
python scanner.py https://example.com --verbose
```

### CI/CD Integration

WebScout exits with code `1` if the security grade is B or below — perfect for pipeline gates:

```yaml
# GitHub Actions example
- name: Security Header Scan
  run: |
    python scanner.py ${{ env.STAGING_URL }} --output report.md
  continue-on-error: false  # Fails the build on poor security grade
```

---

## 📊 Scoring

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100 | A+ | Excellent security posture |
| 80–89 | A | Good, minor improvements possible |
| 70–79 | B | Notable gaps, address soon |
| 60–69 | C | Multiple issues, remediation needed |
| 50–59 | D | Significant exposure |
| 0–49 | F | Critical issues — act immediately |

Scoring deducts:
- **15 pts** per missing HIGH severity header
- **10 pts** per missing MEDIUM severity header
- **5 pts** per missing LOW severity header
- **5 pts** per dangerous CSP value (`unsafe-inline`, `*`, etc.)
- **3 pts** per leaking info header
- **3 pts** per insecure cookie flag

---

## 🧠 JWT Attack Reference

Understanding what WebScout catches:

### `"alg": "none"` — The Classic
```json
{ "alg": "none", "typ": "JWT" }
```
Some libraries accept tokens with no algorithm, skipping signature verification entirely. An attacker can craft any payload and the server accepts it as valid.

### Key Confusion Attack
Libraries that accept both symmetric and asymmetric algorithms can be tricked into verifying an RS256 token using the **public key as an HMAC secret**.

### `kid` Injection
```json
{ "alg": "HS256", "kid": "' UNION SELECT 'attacker-secret'--" }
```
If the server uses the `kid` header to look up a key in a database without sanitization — SQL injection in your auth layer.

### Sensitive Data in Payload
JWTs are **base64-encoded, not encrypted**. Any client can decode the payload with no key needed:
```bash
echo "eyJzdWIiOiJ1c2VyIiwicGFzc3dvcmQiOiJzM2NyM3QifQ==" | base64 -d
# {"sub":"user","password":"s3cr3t"}
```

---

## 🤝 Contributing

Contributions welcome! Ideas for expansion:

- [ ] CORS misconfiguration checks
- [ ] TLS/SSL grade integration
- [ ] Subdomain enumeration mode
- [ ] Recursive crawl mode
- [ ] HTML report output
- [ ] Slack/Discord webhook alerts
- [ ] Docker image

Open an issue or submit a PR.

---

## ⚖️ Legal

> This tool is for **authorized security testing only**.  
> Only scan applications you own or have explicit written permission to test.  
> The authors are not responsible for misuse.

---

## 📜 License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).

---

<div align="center">

**Made with 🖤 for the security community**

*If this saved you time, give it a ⭐ — it helps others find it.*

</div>
