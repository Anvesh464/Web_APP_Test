Basic password reset poisoning
==============================

This lab is vulnerable to password reset poisoning. The user carlos will
carelessly click on any links in emails that he receives. To solve the lab, log
in to Carlos's account.

You can log in to your own account using the following credentials:
wiener:peter. Any emails sent to this account can be read via the email client
on the exploit server.

References:

-   https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning

![img](media/5484a9de0f49d6df7f743c81cf8738ff.png)

There is a function to restore forgotten passwords:

![img](media/4c305d73f5b4e4492685fb369d3179b5.png)

It generates a POST request for the user “wiener”:

![img](media/19d52072c00bb9422b61b0218f9b06a9.png)

We can change the “Host” header for the POST request to “/forgot-password” and
the “username” parameter to the value “carlos”:

![img](media/26e9ad3ed9ca1204074326adc17e7734.png)

And there is a request to the exploit server:

![img](media/381e9b70dcfff4ccde7cbae9f6eb3977.png)

Using this token we can change the password:

![img](media/a81e62886cbdcb7e86339355b11f70dc.png)

And access the page as carlos:

![img](media/25c7a0f1bd4c873b72efb84225c10a21.png)

2 Host header authentication bypass
=================================

This lab makes an assumption about the privilege level of the user based on the
HTTP Host header.

To solve the lab, access the admin panel and delete Carlos's account.

References:

-   https://portswigger.net/web-security/host-header/exploiting

![img](media/fa512ed028f10eb37ccd8406ab9f7efc.png)

If we try to access /admin we get this error:

![img](media/b56c8a33a6ef7682a3d722b46e8962f5.png)

We can access using the value “localhost” in the “Host” header:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /admin HTTP/2
Host: localhost
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/92af56f59fa019311d949c35031e41fd.png)

And delete the user:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /admin/delete?username=carlos HTTP/2
Host: localhost
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/0168ba92c2af39bfbea1ff25f6586afc.png)


3 Web cache poisoning via ambiguous requests

This lab is vulnerable to web cache poisoning due to discrepancies in how the cache and the back-end application handle ambiguous requests. An unsuspecting user regularly visits the site's home page.

To solve the lab, poison the cache so the home page executes alert(document.cookie) in the victim's browser.

---------------------------------------------

References: 

- https://portswigger.net/web-security/host-header/exploiting



![img](images/Web%20cache%20poisoning%20via%20ambiguous%20requests/1.png)

---------------------------------------------

We can not find the cache keys using “Pragma: x-get-cache-key” but we can read from the response headers that the cache lasts 30 seconds. 

The “Host” header is reflected but if you use a random one there is a gateway error, so it is necessary to use 2, the first one, malicious, is reflected and the second is the legitimate one:



![img](images/Web%20cache%20poisoning%20via%20ambiguous%20requests/2.png)


We can execute Javascript code with a payload like this:

```
GET / HTTP/2
Host: testing123"></script><script>alert(document.cookie)</script><script>
Host: 0af500ba04a9e93b802c499200750009.web-security-academy.net
...
```



![img](images/Web%20cache%20poisoning%20via%20ambiguous%20requests/3.png)


And we see the alert with the cookie:



![img](images/Web%20cache%20poisoning%20via%20ambiguous%20requests/4.png)

4 Routing-based SSRF
==================

This lab is vulnerable to routing-based SSRF via the Host header. You can
exploit this to access an insecure intranet admin panel located on an internal
IP address.

To solve the lab, access the internal admin panel located in the 192.168.0.0/24
range, then delete Carlos.

Note: To prevent the Academy platform being used to attack third parties, our
firewall blocks interactions between the labs and arbitrary external systems. To
solve the lab, you must use Burp Collaborator's default public server.

References:

-   https://portswigger.net/web-security/host-header/exploiting

![img](media/c1334ddfc9f00101d1ffd32d5957ad98.png)

Intercept a request to “/” and change the “Host” header for a Burp collaborator
url:

![img](media/6e0634abd0a11432d1c4788709bc8e6d.png)

The domain is resolved:

![img](media/234d1877c52c5af80354661dce2621e1.png)

Then send the request to Intruder:

![img](media/1731a77f81fe442500b4bd572c6022f5.png)

We find an admin panel at 192.168.0.127:

![img](media/9bb8d2b0e9431601b7d6c1335291eb65.png)

It seems it is a POST request:

![img](media/ebb7ef63fe19964cc10dc463afd7eeb3.png)

But I tried a GET request and it works as well:

![img](media/c97e4c25d1471c5d7503ea95e17e0ed2.png)


5 - SSRF via flawed request parsing
===================================

This lab is vulnerable to routing-based SSRF due to its flawed parsing of the
request's intended host. You can exploit this to access an insecure intranet
admin panel located at an internal IP address.

To solve the lab, access the internal admin panel located in the 192.168.0.0/24
range, then delete Carlos.

![img](media/7b7b194bf7a85719a74396719b3d8299.png)

Link:
https://portswigger.net/web-security/host-header/exploiting\#routing-based-ssrf

![img](media/937073f466bcc1abdc20ce5c8ee7fd21.png)

https://0a5100f104ffdc65c3832510004000cf.web-security-academy.net/

If you supply the domain of your Collaborator server in the Host header, and
subsequently receive a DNS lookup from the target server or another in-path
system, this indicates that you may be able to route requests to arbitrary
domains.

Error in Host header for "/product?productId=1":

![img](media/19114587a176f25c177c9ac3c29cab14.png)

Gateway error when adding a second Host header:

![img](media/991d54533bbd0846985686fd20cfe63f.png)

Send to Intruder:

![img](media/e4969728cca1ad28bacee0444a9ec5ec.png)

Using 192.168.0.113 we get a 404 error:

![img](media/bd57eac344a89558e05a6c55d2cd40b2.png)

![img](media/f2bc36b9b01383f6d5578294ef75fe05.png)

Repeat the request with the product ID, add the second Host header with that IP
address and change path to "/update":

![img](media/baa9aee9d3e0bac48fca569607687d9f.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /admin/ HTTP/2
Host: 192.168.0.113
Host: 0a5100f104ffdc65c3832510004000cf.web-security-academy.net
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We get this page:

![img](media/ccacb0f69b5ac6c11ca8ad7755a81237.png)

Deleting the user is not possible, so I repeated the process and captured the
response:

![img](media/1a442219da5fcbb0c0e1f45a254d0669.png)

We will send a new request to delete the user knowing the endpoint is
/admin/delete and the parameter is probably username:

![img](media/73ed5c066a25e35c4f206abfe9767ce6.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /admin/delete HTTP/2
Host: 192.168.0.113
Host: 0a5100f104ffdc65c3832510004000cf.web-security-academy.net
...

username=carlos
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We get the error:

![img](media/b699c3a4808663ab15a6e9b470ff173d.png)

Let's repeat the process and add the csrf value in the response to the previous
GET request ("IJTFhUceFHwKZHdbhX2eW0ayNuKksPhv"):

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /admin/delete HTTP/2
Host: 192.168.0.113
Host: 0a5100f104ffdc65c3832510004000cf.web-security-academy.net
...

username=carlos&csrf=IJTFhUceFHwKZHdbhX2eW0ayNuKksPhv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/ae024675af938d2bbf0f937431d805e4.png)

We get a 302 redirection:

![img](media/8467dd4ff0a73caf3ede579416f3b36d.png)

Lab is solved:

![img](media/7246c8aaeea170189d60cda50783f54a.png)

Host validation bypass via connection state attack
==================================================

This lab is vulnerable to routing-based SSRF via the Host header. Although the
front-end server may initially appear to perform robust validation of the Host
header, it makes assumptions about all requests on a connection based on the
first request it receives.

To solve the lab, exploit this behavior to access an internal admin panel
located at 192.168.0.1/admin, then delete the user carlos.

Note: Solving this lab requires features first released in Burp Suite 2022.8.1.

This lab is based on real-world vulnerabilities discovered by PortSwigger
Research. For more details, check out Browser-Powered Desync Attacks: A New
Frontier in HTTP Request Smuggling.

References:

-   https://portswigger.net/web-security/host-header/exploiting

-   https://portswigger.net/research/browser-powered-desync-attacks\#state

![img](media/9a213f2c13ead3ced7215522d5436290.png)

![img](media/f6550e2da38fe63fa16693314f671b88.png)

First send a request to the home page using the legitimate “Host” header:

![img](media/253d3a41eaa346f3f93a0e055734a97e.png)

Then quickly send a request to “/admin” changing the “Host” header to
“192.168.0.1”:

![img](media/a158637a93352f631756a466ff6fb89d.png)

After a redirection you get to the admin panel and can find the “csrf” value:

![img](media/b3eb45f34a105840aa75fc49d6e1b110.png)

After sending a request to “/” with the legitimate “Host” header, send the
request to delete the user:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET / HTTP/2
Host: 0a6a005e030d906b874c2bf300490073.web-security-academy.net
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /admin/delete HTTP/2
Host: 192.168.0.1
...

username=carlos&csrf=CY6qJXGEMwYMKu0z18mEKfFo2zAoE866
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/a172822dd6cbf2ad96f8f5b29b6638bc.png)
