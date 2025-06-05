Certainly! Based on the information available from PortSwigger's Web Security Academy, here's a consolidated Markdown file that combines key JWT attack techniques and corresponding labs. This serves as a comprehensive guide to understanding and exploiting various JWT vulnerabilities.

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

---

For more information on JWT attacks and how to work with JWTs in Burp Suite, refer to the following resources:([portswigger.net][8])

* [JWT attacks | Web Security Academy - PortSwigger](https://portswigger.net/web-security/jwt)
* [Working with JWTs in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts)([portswigger.net][1], [portswigger.net][9])

---

If you need further assistance or a downloadable version of this consolidated Markdown file, feel free to ask!

[1]: https://portswigger.net/web-security/jwt?utm_source=chatgpt.com "JWT attacks | Web Security Academy - PortSwigger"
[2]: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature?utm_source=chatgpt.com "Lab: JWT authentication bypass via unverified signature - PortSwigger"
[3]: https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion?utm_source=chatgpt.com "Lab: JWT authentication bypass via algorithm confusion - PortSwigger"
[4]: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification?utm_source=chatgpt.com "Lab: JWT authentication bypass via flawed signature verification"
[5]: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key?utm_source=chatgpt.com "Lab: JWT authentication bypass via weak signing key - PortSwigger"
[6]: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal?utm_source=chatgpt.com "Lab: JWT authentication bypass via kid header path traversal"
[7]: https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key?utm_source=chatgpt.com "Lab: JWT authentication bypass via algorithm confusion with no ..."
[8]: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection?utm_source=chatgpt.com "Lab: JWT authentication bypass via jku header injection - PortSwigger"
[9]: https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts?utm_source=chatgpt.com "Working with JWTs in Burp Suite - PortSwigger"
