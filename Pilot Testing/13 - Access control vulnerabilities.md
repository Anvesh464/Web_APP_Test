01 Unprotected admin functionality
==================================

This lab has an unprotected admin panel.

Solve the lab by deleting the user carlos.

References:

-   https://portswigger.net/web-security/access-control

![img](media/e25b52ac586cfffd7a989a601acdba9d.png)

The admin panel path is in the robots.txt file:

![img](media/bc65bffad1d4adc1b8901f76e72a158f.png)

You can delete the user from here:

![img](media/358867deb2ff583413c7a1e625b29d79.png)

02 Unprotected admin functionality with unpredictable URL
=========================================================

This lab has an unprotected admin panel. It's located at an unpredictable
location, but the location is disclosed somewhere in the application.

Solve the lab by accessing the admin panel, and using it to delete the user
carlos.

References:

-   https://portswigger.net/web-security/access-control

![img](media/e25b52ac586cfffd7a989a601acdba9d.png)

By clicking Control+u we can read the source code and find the admin panel:

![img](media/9af55ab116a5220ed753549fff9671c3.png)

And from the admin panel delete the user:

![img](media/21c166965cbd29f57643fa50ecf01abc.png)

03 User role controlled by request parameter
============================================

This lab has an admin panel at /admin, which identifies administrators using a
forgeable cookie.

Solve the lab by accessing the admin panel and using it to delete the user
carlos.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/access-control

![img](media/0aabb23cc0da3130c317fb790f4c6c74.png)

After logging in we see a redirection where the value of the cookie “Admin” is
set to “false”:

![img](media/0a6a2a48d8d2ed589509c61d519fe7c4.png)

Changing it to “true”, we can see and visit the admin panel to delete the user:

![img](media/ec3344aa85edc5eb54827cccdb6512bd.png)

![img](media/0fe0dafb23b2cb5d1cefb00b4a082c75.png)

04 User role can be modified in user profile
============================================

This lab has an admin panel at /admin. It's only accessible to logged-in users
with a roleid of 2.

Solve the lab by accessing the admin panel and using it to delete the user
carlos.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/access-control

![img](media/4d2ff230fbc756e5c58b3d32101c756c.png)

Login process is a POST request:

![img](media/4ce8723ffdf7b65b60fbd16d21a14b49.png)

It responds with a 302 redirect:

![img](media/d827f75e256c9980b08c5d31718441a8.png)

There is a function to update the email address with a POST request:

![img](media/92844e3951786311564d022c18243074.png)

It responds with the personal information:

![img](media/6482e94971c18763c2b75c38c7ce3db3.png)

We can add the roleid parameter to the POST request to change the role of the
user:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-email HTTP/2
...

{"email":"test@test.com", "roleid":2}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/20799362cf794e25b7c034e5ef96e3a7.png)

It is updated:

![img](media/db50c361b95bcc0e63705020416df5a7.png)

Then we can delete the user:

![img](media/423161e8453295d1b7fd8cb8dd464e3c.png)

05 User ID controlled by request parameter
==========================================

This lab has a horizontal privilege escalation vulnerability on the user account
page.

To solve the lab, obtain the API key for the user carlos and submit it as the
solution.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/access-control

![img](media/8dc3caf013a0df85fafb8a257f54978f.png)

Clicking the “Home” button generates this GET request:

![img](media/704632bba7d89d7338efcb4431171fe6.png)

Changing the id to carlos we can get the API key:

![img](media/1e34deef09a3e11ccf6119dabb3aabf0.png)

06 User ID controlled by request parameter, with unpredictable user%20IDs
=========================================================================

This lab has a horizontal privilege escalation vulnerability on the user account
page, but identifies users with GUIDs.

To solve the lab, find the GUID for carlos, then submit his API key as the
solution.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/access-control

![img](media/92e7dbd3c0949cb81aaa2b8c9f139684.png)

Clicking the “Home” button generates this GET request:

![img](media/0357fd306be109b7bbee6f244657ff4c.png)

We can get the administrator's GUID from the blog posts:

![img](media/fdf1dc2930a88566c473dcee0d769015.png)

And create a new request:

![img](media/0ba1d96541b5dde73d045a198df557a4.png)

07 User ID controlled by request parameter with data leakage in redirect
========================================================================

This lab contains an access control vulnerability where sensitive information is
leaked in the body of a redirect response.

To solve the lab, obtain the API key for the user carlos and submit it as the
solution.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/access-control

![img](media/46d6b73cd97bfcb256037008dfa54943.png)

Clicking the “Home” button generates this GET request:

![img](media/49cca2fb0e00a628c55c91fb2455c39d.png)

Changing the id to “carlos” there is a redirection:

![img](media/59cea47fb9e5b0e3786c8a674260ab87.png)

In this redirect response we can find the API key:

![img](media/4419a07e70de778a3425daf111ae64dd.png)

08 User ID controlled by request parameter with password disclosure
===================================================================

This lab has user account page that contains the current user's existing
password, prefilled in a masked input.

To solve the lab, retrieve the administrator's password, then use it to delete
carlos.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/access-control

![img](media/8622b87faf7ff4f590008da64dffd955.png)

Clicking the “Home” button generates this GET request:

![img](media/9de6c8c52bff2007fab462e1836cd034.png)

We can change the id to “administrator”:

![img](media/7f41e03f8bbb2206971d36b5afff6597.png)

Then I changed the type to “text”:

![img](media/47931e9732eac571e9b8ce07a3a4a21c.png)

And delete the user:

![img](media/c2c3e1ceeef2c603f0b13b76c7d81788.png)

09 Insecure direct object references
====================================

This lab stores user chat logs directly on the server's file system, and
retrieves them using static URLs.

Solve the lab by finding the password for the user carlos, and logging into
their account.

References:

-   https://portswigger.net/web-security/access-control

![img](media/0681cc0fedcfba6e52fdc695bd9a06ea.png)

There is a live chat:

![img](media/c7b6ce45d6bea5d34a95f322ccd7d4c3.png)

It is possible to download the transcript:

![img](media/f60866b697c8d9c115aeb27a309ae942.png)

Changing to 1.txt we find the password:

![img](media/bf95318ff349b2307a427165e99088fe.png)

10 URL-based access control can be circumvented
===============================================

This website has an unauthenticated admin panel at /admin, but a front-end
system has been configured to block external access to that path. However, the
back-end application is built on a framework that supports the X-Original-URL
header.

To solve the lab, access the admin panel and delete the user carlos.

References:

-   https://portswigger.net/web-security/access-control

![img](media/a7a5fcd5605a66c4024f6de70613b7f2.png)

Accessing directly /admin returns a 403 error code:

![img](media/f5f9c666aebfcbe9b44dafd2a58ec167.png)

It is possible to access /admin with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET / HTTP/2
...
X-Original-Url: /admin/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/f24e8627ec1ad3c55cb1091cb48581c3.png)

And the we can delete the user with this payload. The parameter “username" must
be in the URL:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /?username=carlos HTTP/2
X-Original-Url: /admin/delete
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/dcefc6dd5f69a7720a3cd344a32f2b50.png)

11. Method-based access control can be circumvented
===================================================

This lab implements access controls based partly on the HTTP method of requests.
You can familiarize yourself with the admin panel by logging in using the
credentials administrator:admin.

To solve the lab, log in using the credentials wiener:peter and exploit the
flawed access controls to promote yourself to become an administrator.

References:

-   https://portswigger.net/web-security/access-control

![img](media/a17d4a138073910b9219e6ae2db9c477.png)

Admin panel has functionality to upgrade users:

![img](media/6a144790facababf928e89883da1f8dd.png)

This is a POST request:

![img](media/7f8d881a2c4014e245c125ce4b56dc40.png)

But it also works if it is a GET request:

![img](media/ef298efa458a5c98c8254a3f260dd63f.png)

If we execute this as wiener we can upgrade ourselves to administrators:

![img](media/204a53394b5c25a16510005c27c935b9.png)

12 Multi-step process with no access control on one step
========================================================

This lab has an admin panel with a flawed multi-step process for changing a
user's role. You can familiarize yourself with the admin panel by logging in
using the credentials administrator:admin.

To solve the lab, log in using the credentials wiener:peter and exploit the
flawed access controls to promote yourself to become an administrator.

Reference: https://portswigger.net/web-security/access-control

Generated link:
https://0ac700520305fa43816f2532000c0090.web-security-academy.net/

We try to send the POST request to upgrade the user:

![img](media/d254c2d306e2da8b809b20e1d177e155.png)

We get a 401 unauthorized error:

![img](media/06bbc2b08a18ab1ecf7f4c7587ad41a7.png)

We try with the confirmed parameter:

![img](media/f64cffdb0d931df6d955886f3aeba475.png)

We get a redirection and then an 401 unauthorized error:

![img](media/fb50e6ba507f565a9d8345ebfff72232.png)

But the user was indeed promoted to administrator and the admin panel is
accessible for wiener now:

![img](media/db82d3be2e7dd2cc2960769608fb71d7.png)

13 Referer-based access control
===============================

This lab controls access to certain admin functionality based on the Referer
header. You can familiarize yourself with the admin panel by logging in using
the credentials administrator:admin.

To solve the lab, log in using the credentials wiener:peter and exploit the
flawed access controls to promote yourself to become an administrator.

References:

-   https://portswigger.net/web-security/access-control

![img](media/0eb51275dcf8c4f48ed7ca56e4b0a565.png)

The process to upgrade the user is generated from the admin panel with a GET
request:

![img](media/d5cbc83fa5a0abc2182fb292f1db79d8.png)

But with “wiener” we get an unauthorized error:

![img](media/d4e40ae93e9dff65ca318c8d78a2b4ea.png)

It works chaning the “Referer” header to /admin:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /admin-roles?username=wiener&action=upgrade HTTP/2
...
Referer: https://0afd00fc039e68c881769dfa009b00b8.web-security-academy.net/admin
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/43d3c8d22243f59c7533f6e1b89e8306.png)


# 15 - Multi-step process with no access control on one step

This lab has an admin panel with a flawed multi-step process for changing a user's role. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin.

To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator.

---------------------------------------------

Reference: https://portswigger.net/web-security/access-control

---------------------------------------------

Generated link: https://0ac700520305fa43816f2532000c0090.web-security-academy.net/


We try to send the POST request to upgrade the user:



![img](images/15%20-%20Multi-step%20process%20with%20no%20access%20control%20on%20one%20step/1.png)

We get a 401 unauthorized error:



![img](images/15%20-%20Multi-step%20process%20with%20no%20access%20control%20on%20one%20step/2.png)

We try with the confirmed parameter:



![img](images/15%20-%20Multi-step%20process%20with%20no%20access%20control%20on%20one%20step/3.png)

We get a redirection and then an 401 unauthorized error:



![img](images/15%20-%20Multi-step%20process%20with%20no%20access%20control%20on%20one%20step/4.png)

But the user was indeed promoted to administrator and the admin panel is accessible for wiener now:



![img](images/15%20-%20Multi-step%20process%20with%20no%20access%20control%20on%20one%20step/5.png)
