![Alt text](https://github.com/Anvesh464/Web_APP_Test/blob/main/Pilot%20Testing/media/Ashok%20Findings.jpeg?raw=true)

# XSS and Web Security Notes

## Enta pirikodivi evannni niku eandhuku ra

Make life easier, not harder.
You have to take the first step; then people follow.

[PayloadsAllTheThings - GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Application version-related exploits
Search in [exploit-db](https://www.exploit-db.com/)

## Addons

- Hackbar
- FoxyProxy Standard
- Wappalyzer
- Cookies Manager+
- SQL Inject Me
- XSS Me
- Tamper Data
- SecurityFocus Vulnerabilities search plugin
- Packet Storm search plugin
- Offsec Exploit-db Search

## Vulnerability Categories

- XSS
- Host Header Injection
- URL Redirection
- Parameter Tampering
- HTML Injection
- File Inclusion
- SPF Record Misconfiguration
- Insecure CORs Configuration
- SSRF
- Critical File Disclosure
- Source Code Disclosure
- CSRF
- Subdomain Takeover
- SQL Injection
- Command Injection
- File Upload Vulnerabilities
- XML Injection

## cURL to Burp Request Command
```bash
curl -x 127.0.0.1:8080
```

## XSS Payload Example
```html
%3cscript%3ealert%281%29%3c%2fscript%3e
```

---

# Vulnerability, Impact, and Solution

## 1. Information Gathering

- Learn the terminology and gather information about the server, frameworks, and default credentials.
- Identify previous vulnerabilities related to the application.

### Injection Points

- Where vulnerabilities can exist.
- The location of injection vulnerabilities (parameters).

### Information Flow

1. Site
2. Subdomains
3. Select unpopular websites
4. Find IP Address
5. Identify programming language
6. Open ports and services
7. Responsible disclosure ([eur.nl](https://eur.nl))

### Tools for Finding Subdomains

- [VirusTotal](https://www.virustotal.com/gui/home/search)
- [Subbrute](https://github.com/TheRook/subbrute)
  ```bash
  ./subbrute.py -c 50 example.com > example.com
  ```
- [Altdns](https://github.com/infosec-au/altdns)
- [Netcraft](https://searchdns.netcraft.com/)
- [HTTP Status Checker](https://httpstatus.io/)

### Finding IP Address & Open Ports

- Use `ping` or `nmap` for aggressive scanning, OS detection, and vulnerability scanning.

### Server Information & Banner Grabbing

```bash
whatweb domain.name
nikto -h domain.name
nc domain.name 80
```

---

# 2. Burp Suite Certificate Configuration

### Steps to Configure Burp Suite
1. Open `http://burp`.
2. Download CA Certificate.
3. Go to Browser > Preferences > Certificates > View Certificate > Import > Trust all certificates.

---

# 3. Cross-Site Scripting (XSS)

## XSS Background

**Impact of XSS:**
- Cookie theft
- Keylogging
- Phishing
- URL Redirection
- Site defacement

### Common XSS Injection Points

- Comment boxes
- Forums
- Signup/Login pages
- Search bars
- Registration forms
- Feedback forms
- Contact us forms

### How to Hunt for XSS

1. Find an input parameter and provide input.
2. If input reflects or is stored, there may be XSS.
3. Try executing JavaScript.

### XSS Payloads

```html
"><script>alert(1)</script>
"><svg/onload=alert(1)>
```

### White Characters Identifying XSS

- Special characters: `' " < > / // ( ) ^ script img svg div alert prompt`
- Event Handlers:
  ```html
  <div onpointerover="alert(45)">MOVE HERE</div>
  <div onpointerdown="alert(45)">MOVE HERE</div>
  ```

### Bypassing XSS Filters

- UTF-8 Encoding
- Unicode Encoding
- HTML Encoding
- Octal Encoding
- Common WAF Bypass

### Cloudflare XSS Bypass

```html
<svg/OnLoad="`${prompt``}`">
<svg/onload=alert`bohdan`>
```

### Practical XSS Exercises

- [Prompt.ml](https://prompt.ml/0)
- [XSS Lab](http://leettime.net/xsslab1/)

---

# 4. Manual XSS Vector Building

## Steps to Find & Exploit XSS

1. Find an input field that reflects input.
2. Check response in **view-source**.
3. Close any open tags.
4. Use event handlers like `onmouseover` for bypassing sanitization.

Example:
```html
<input type="text" name="name" value='hello'>
<input type="submit" name="submit" value="search">
```
Payload:
```html
'onmouseover='alert(1);
```

---

# References

- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [LeetTime XSS Labs](http://leettime.net/xsslab1/)
- [Prompt.ml](https://prompt.ml/)

---
