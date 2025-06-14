Excessive trust in client-side controls
=======================================

This lab doesn't adequately validate user input. You can exploit a logic flaw in
its purchasing workflow to buy items for an unintended price. To solve the lab,
buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/c450e7c040e04a17e8210ae7171e29f4.png)

When the product is added to the cart, it is possible to change the price
parameter:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /cart HTTP/2
...

productId=1&redir=PRODUCT&quantity=1&price=133700
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/6f7a3a13e207c20ce58882a474de32ac.png)

Changing the price to “1337” the price is 13,37 and we can purchase it:

![img](media/e52606e3f92982530cef72d5e67b03f8.png)

High-level logic vulnerability
==============================

This lab doesn't adequately validate user input. You can exploit a logic flaw in
its purchasing workflow to buy items for an unintended price. To solve the lab,
buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/5d057ffb5898e3c391a0998d90e4b746.png)

The POST request generated when the product is added to the cart is:

![img](media/9a6ce1ea001925f9339be5407b894106.png)

We can set the quantity to a negative value but we can not purchase it:

![img](media/9a6ce1ea001925f9339be5407b894106.png)

However we can add the item and then a negative number for other product:

![img](media/a9e9fd870f4d3eec6f141d37dcea60ec.png)

And the item is purchased:

![img](media/82f02da1be109db98484d2d3c008f371.png)

Inconsistent security controls
==============================

This lab's flawed logic allows arbitrary users to access administrative
functionality that should only be available to company employees. To solve the
lab, access the admin panel and delete Carlos.

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/50a1909dd3a4f67ad0f55fdb21c4d2dc.png)

I can not register as “carlos” but yes as “test” user:

![img](media/543272575952174b87c540b12a310ac3.png)

It is not possible to access “/admin”:

![img](media/819b38307016cb0fcfdbdf3afcafb086.png)

But you can change the email to one ending with “\@dontwannacry.com”:

![img](media/92ca88efef7cad21aa66213f5a2580bb.png)

And then access “/admin” to delete the user:

![img](media/26738c694f326f007d1f0642d6a3e671.png)

Flawed enforcement of business rules
====================================

This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit
this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/ec1fedd1ba94f8a7babdc1978396e4ac.png)

There is a code for new users:

![img](media/062220e4a8dfff14cb614f9c66f1cf24.png)

It is applied with a POST request:

![img](media/4d783f595244773acb06f8f9dfc1e6e6.png)

But the second time the response is:

![img](media/fb9f0ece547c071657be76428a5b84d3.png)

There is a sign up field:

![img](media/f4f728b79ec26dca2ce9b73dd9adf74e.png)

It returns a new coupon:

![img](media/0b2f0cd823e2b8dd6f0df44c94dd5fbd.png)

We can use this coupon as well:

![img](media/9330690c056b2c3ab76d202ff9028a15.png)

We can not use the same coupon twice in a row but we can use once each until we
get a full discount:

![img](media/421d200dd2bbf68880c38173a3d31aae.png)

Low-level logic flaw
====================

This lab doesn't adequately validate user input. You can exploit a logic flaw in
its purchasing workflow to buy items for an unintended price. To solve the lab,
buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter

Hint: You will need to use Burp Intruder (or Turbo Intruder) to solve this lab.

To make sure the price increases in predictable increments, we recommend
configuring your attack to only send one request at a time. In Burp Intruder,
you can do this from the resource pool settings using the Maximum concurrent
requests option.

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/096ea06ad0bd6063682d9d71493716d1.png)

Add item request:

![img](media/8cc00f8cf0afc2a6b46b6a462285a79e.png)

Checkout request:

![img](media/e4ee30dd6ff15d80c72bebf1dfecf99d.png)

Which gets a redirection to:

![img](media/b55bbea1e798e03db28fc031ae077440.png)

16041 items cost 2 million dollars:

![img](media/700f6fb98bc8c7b28187e66499d3c2d3.png)

16081 items cost -2 million dollars:

![img](media/418815c3492626cf0c9b22189e669028.png)

-   2\^31 − 1 = 2.147.483.647, the maximum value in the backend for an integer.

-   2.147.483.647 / 1337 = 16061 items we could add before this problem happens

![img](media/8123b99518bf5ad3988584b69e08f6c6.png)

![img](media/62e73022b17b48a8ac2319ba29fe41d9.png)

To reach a value next to 0, we will try with 16061\*2 = 32122

![img](media/39cb90938dfd4c842e5bc992e6de4ee0.png)

As we were close enough, I added a different item to get a value between 0 and
100 dollars:

![img](media/7635a85de2618a18595b4964da825695.png)

### Official solution

Intruder for quantity:

![img](media/d4033f20ab5d7cb9e43eb093b485deba.png)

Using “Null payloads”:

![img](media/319d3d3e85791cd42bb0ecf8a8f13560.png)

And “Maximum concurrent threads” to 1:

![img](media/5dd15efa6f0b0238a9aa0b885b2f8f5d.png)

![img](media/8d6ef32c7fece57e2b714bcc90b0cf5f.png)

Inconsistent handling of exceptional input
==========================================

This lab doesn't adequately validate user input. You can exploit a logic flaw in
its account registration process to gain access to administrative functionality.
To solve the lab, access the admin panel and delete Carlos.

Hint: You can use the link in the lab banner to access an email client connected
to your own private mail server. The client will display all messages sent to
\@YOUR-EMAIL-ID.web-security-academy.net and any arbitrary subdomains. Your
unique email ID is displayed in the email client.

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/096ea06ad0bd6063682d9d71493716d1.png)

We can not register as the carlos user as it already exists. We register as the
user “test” with email
“attacker\@exploit-0a67006c0423355d834f36b001cf0030.exploit-server.net”:

![img](media/60a57d7546ce3be81182ab2a0c2ac434.png)

We can not access /admin:

![img](media/4985975962562556c55f054bbdee2427.png)

Using a very long subdomain:

![img](media/66fe24d1d16c92db2abd3b094023c9b4.png)

The email domain is 246 “a” characters:

![img](media/3bcfc575d2ba3a9bd82c1ce9cf282948.png)

With the following email:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /register HTTP/2
...

csrf=alQnzW8wE9JhzqQtr4xigsVi409cfLqF&username=test15&email=attackeraaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%40dontwannacry.com.exploit-0a67006c0423355d834f36b001cf0030.exploit-server.net&password=test15
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/026e9d7040902e2f664814111bf8593a.png)

The domain is dontwannacry.com because the rest of the subdomain is cropped:

![img](media/138d394695a2aa2a62900dd6b0faa4bc.png)

And we can access /admin:

![img](media/3f4534e9bb04bfee6383a1d52b79eec8.png)

Weak isolation on dual-use endpoint
===================================

This lab makes a flawed assumption about the user's privilege level based on
their input. As a result, you can exploit the logic of its account management
features to gain access to arbitrary users' accounts. To solve the lab, access
the administrator account and delete Carlos.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/7d78b94ceaaa039d0a59c19e455105f7.png)

Request generated when changing user's password:

![img](media/447d276e90be4f1be810e0f863bace33.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-password HTTP/2
...

csrf=ujBucKnnF9611L81nMWHpHhtHVneK8JR&username=administrator&new-password-1=test&new-password-2=test
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/3c101218b0fceee91f98c3f909d06fbe.png)

Then we can access with credentials administrator:test:

![img](media/c8cb514f6bfe5533025a6eeddaf7f130.png)

Insufficient workflow validation
================================

This lab makes flawed assumptions about the sequence of events in the purchasing
workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather
jacket".

You can log in to your own account using the following credentials: wiener:peter

Reference:

-   https://portswigger.net/web-security/logic-flaws/examples

Generated link:
https://0a44005d0489eb06819b441c00f2003f.web-security-academy.net/

First I will try to buy some eggs:

![img](media/cbd2e44a0087414f86b2ea249fea399b.png)

Clicking "Place order" generates a POST request:

![img](media/647be3536665d36d848cc66a07596a32.png)

And a GET request to “/cart/order-confirmation?order-confirmed=true”:

![img](media/d30a8aaa6f0f1a0d4b4cd538d9161201.png)

After adding the leather jacket and clicking Place order you get a POST request
and a GET request but to “/cart?err=INSUFFICIENT_FUNDS”:

![img](media/a221443f97b7be69f0190b3d29d347ec.png)

If you substitute that with “/cart/order-confirmation?order-confirmed=true” the
order is created:

![img](media/aa885b2d4772c035b5fa4a8e678d76c0.png)

![img](media/cf2883d86cdf8b0165a530e7e4817554.png)

Authentication bypass via flawed state machine
==============================================

This lab makes flawed assumptions about the sequence of events in the login
process. To solve the lab, exploit this flaw to bypass the lab's authentication,
access the admin interface, and delete Carlos.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/27fde07a228baa80cee0b4ac87668464.png)

The requests generated when logging in:

![img](media/685157e0e822fd7601f645bf9cdd3a15.png)

![img](media/5837d572444943ef0027cb2f66199b8a.png)

Then the user selects a role:

![img](media/6acffaec79135c98831edf4f76934e4e.png)

We can not access /admin:

![img](media/905fddc84b281a7c8f8d2f9c128e3942.png)

After logging in, change the “Location” header in the response to redirect to
“/admin”:

![img](media/cf7a74fe34f6cfc8d76305e20f9f9548.png)

This changes the login to the “administrator” user and it is possible to delete
the user:

![img](media/fefa70c5d64f148272d5eb9bf7aabf6a.png)

Infinite money logic flaw
=========================

This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit
this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/dc293c85c423e12ee95245192de82c34.png)

It is possible to sign up for the newsletter:

![img](media/24076c656c2ab6ab1d29827c5721c279.png)

It returns a coupon:

![img](media/8229ec34e57c39d84b0447a29366ee85.png)

It is possible to use the coupon but only once:

![img](media/0c605537bc6a91a75f3e18c90e0bf8a6.png)

Request to purchase the item “Gift card”:

![img](media/d49d26919cc11adc50208e433fe4709b.png)

It returns a code:

![img](media/f3ce4fd9d6ef1118c11f553624974e49.png)

This code can be redeemed and get money (we get more than the initial 100
dollars):

![img](media/7554da1f4e149356515fea5c93f37828.png)

We will get as many as possible gift cards with the current money and use
intruder to validate all the codes:

![img](media/45fe9a3d37958b5c21c918d33263a1c4.png)

Continue the process, getting a total of (Total money % 7) gift cards and
redeeming them until you get more than 1000 dollars:

![img](media/20fa8371cf64d0ee338bd9751f500b55.png)

Authentication bypass via encryption oracle
===========================================

This lab contains a logic flaw that exposes an encryption oracle to users. To
solve the lab, exploit this flaw to gain access to the admin panel and delete
Carlos.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/logic-flaws/examples

![img](media/53014bb50068d73d186c6e91129b71eb.png)

After logging in, there is a “stay-logged-in” cookie:

![img](media/53f1b85bfbba4988588362865e5904d7.png)

The value seems encrypted:

![img](media/65282c8dbc42924e3a3fb039125184e4.png)

When a comment is sent there is a cookie “notification” with an encrypted value:

![img](media/9974aa9c9f6b41c87bc3db633c48327a.png)

This notification is probably the message that appears in the post, in this case
“Invalid email address: test”:

![img](media/60b5f0863544392ec7afe04528729c13.png)

With a value “a” in this cookie we generate an internal server error:

![img](media/217151b2797feed67356b7494b9a9e49.png)

With a base64-encoded value “YQ==” we see information about the encryption. It
looks it uses padded cipher and blocks of 16 bytes, so it could be AES-128:

![img](media/6be05baae9649d2a2700fa0e5d1915f7.png)

We can decrypt the "stay-logged-in" cookie value, it is “wiener:1683621955878”.
The second value is the EPOCH time when I logged in earlier.

![img](media/9a4525ccd124eeb9d02700f9eeedf2c9.png)

Knowing it uses 16-bytes blocks and there is a prefix of 23 characters ("Invalid
email address: “), we will add 9 characters of ”padding" in that second ciphered
block:

![img](media/ecb50c7907335154dfc3410f2aaced0f.png)

We will take the encrypted value, URL-decode and base64-decode it, and delete
the first 2 16-bytes blocks:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bRmw%2bImnDFvvwECQSiG1J8dfoUcrqKgkyQfr8wfI1J9bRCG%2bSLS06HPtXsMPhzuBQTkxD8oSxM2l3LhRCdZ3IQ%3d%3d
bRmw+ImnDFvvwECQSiG1J8dfoUcrqKgkyQfr8wfI1J9bRCG+SLS06HPtXsMPhzuBQTkxD8oSxM2l3LhRCdZ3IQ==
...
W0Qhvki0tOhz7V7DD4c7gUE5MQ/KEsTNpdy4UQnWdyE=
W0Qhvki0tOhz7V7DD4c7gUE5MQ/KEsTNpdy4UQnWdyE%3d
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/d20690c7c4a21202d0c4cf714962a736.png)

First we will set the value “W0Qhvki0tOhz7V7DD4c7gUE5MQ/KEsTNpdy4UQnWdyE%3d” for
the “notification” cookie to check it is decrypted correctly:

![img](media/bfb442024631cc6d589217e90dce6bd2.png)

We can delete the "session" cookie and use this value to log in:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /my-account?id=administrator HTTP/2
...
Cookie: stay-logged-in=W0Qhvki0tOhz7V7DD4c7gUE5MQ%2fKEsTNpdy4UQnWdyE%3d
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/18a570e2b18a50c3dd26ebb5c2830a30.png)

And then delete the user:

![img](media/8a5b84a75a0216f33fb361b611e1243a.png)
