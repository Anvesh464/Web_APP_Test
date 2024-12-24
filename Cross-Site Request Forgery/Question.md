### 1. **Can you explain how a Cross-Site Request Forgery (CSRF) attack works and why it is different from Cross-Site Scripting (XSS)?**

**Answer:**
- **CSRF** is an attack where an attacker tricks a logged-in user into making an unwanted request to a web application on which the user is authenticated. It exploits the trust a website has in the user's browser, allowing malicious requests to be made using the user's credentials (typically session cookies). CSRF targets **state-changing requests** like submitting forms or transferring money, but not data theft, as the attacker cannot see the response.

- **XSS**, on the other hand, involves injecting malicious scripts into web pages that are then executed in a user's browser. It targets data theft, session hijacking, and executing arbitrary actions in the victim's context, while CSRF focuses on exploiting the state-changing actions that a user is already authenticated to perform.

### 2. **How does the attacker leverage the session cookies of an authenticated user to perform CSRF attacks? Can a CSRF attack succeed even if the attacker cannot view the response from the server?**

**Answer:**
- When a user logs into a website, the session identifier (usually stored as a cookie) is sent with every request to the website. In a CSRF attack, the attacker crafts a malicious request (such as submitting a form or making an API request) that the user’s browser automatically sends to the target website, including the session cookie. Since the attacker cannot directly view the response, the attack succeeds **if the action was state-changing** (like changing a password, submitting a form, etc.), but the attacker won’t know the outcome.

- **Key point:** The attack doesn't require the attacker to see the response, just that the request is processed with the user’s credentials.

### 3. **Describe some of the common defenses against CSRF attacks. How do anti-CSRF tokens work and how do they mitigate such attacks?**

**Answer:**
- **Anti-CSRF tokens** are a commonly used defense where the web application includes a unique, unpredictable token in the form of a hidden field or HTTP header (e.g., `X-CSRF-Token`). This token is linked to the user's session. On submitting a request, the server checks if the token in the request matches the one stored on the server. If it doesn’t match, the request is rejected, as this prevents the attacker from guessing or forging the correct token.

- **Other defenses include**:
  - **SameSite cookies**: This restricts cookies from being sent with cross-site requests. By setting the `SameSite` attribute to `Strict` or `Lax`, cookies are not sent with requests from third-party websites, thus protecting against CSRF.
  - **Referer header validation**: The server can validate that the `Referer` header matches the domain of the application, but this can be bypassed in some cases.
  - **Double-submit cookies**: The CSRF token is sent in both a cookie and the request body, and the server checks that both values match.

### 4. **How does CSRF affect single-page applications (SPAs) and what specific steps should be taken to prevent CSRF in these kinds of applications?**

**Answer:**
- SPAs are often vulnerable to CSRF since they rely heavily on API calls that are generally protected by session cookies. Since SPAs typically use **AJAX** (like XHR or Fetch), these requests can still carry the session cookie automatically, which can be used for CSRF attacks.

- **Mitigating CSRF in SPAs**:
  - Use **Bearer tokens** (JWT) in the `Authorization` header rather than relying on cookies for authentication, as this avoids automatic cookie sending by the browser.
  - Always use **SameSite cookies** and secure methods of token management, such as including the token in the `Authorization` header or custom headers, which browsers won’t send with cross-origin requests unless explicitly allowed.

### 5. **How can an attacker bypass CSRF protections if the target website uses JavaScript frameworks that rely on custom HTTP headers for authentication (such as using `Authorization` or `Bearer` tokens)?**

**Answer:**
- **CSRF attacks** usually exploit cookies automatically sent by the browser, but if an application uses a custom header (e.g., `Authorization` or `Bearer` token) for authentication, the attacker cannot use a standard CSRF attack. The attacker would need to somehow convince the victim’s browser to send a valid `Authorization` token along with the forged request, but browsers do not automatically send headers like `Authorization` across sites.

- **However**, an attacker could still use methods like social engineering (e.g., tricking the user into revealing their token) or exploiting **Cross-Origin Resource Sharing (CORS)** misconfigurations to bypass this protection.

### 6. **What potential security issues arise when an anti-CSRF token is stored in a non-session cookie (as in the example from PortSwigger)?**

**Answer:**
- Storing the CSRF token in a **non-session cookie** (i.e., a persistent cookie) can be problematic because if the attacker can somehow retrieve this cookie, they can use it to craft a forged request. A persistent CSRF token is not bound to the user’s session and can be potentially leaked or intercepted by malicious scripts running on the user's machine (especially in the case of XSS vulnerabilities).

- **Solution**: The token should be stored in a **session cookie** (which expires when the session ends) to mitigate the risk of token leakage or abuse across sessions.

### 7. **How can CSRF attacks exploit file upload features on a website? Provide an example where an attacker might leverage the `multipart/form-data` encoding type to perform a CSRF attack.**

**Answer:**
- CSRF attacks can target file upload features if the file upload form is vulnerable and does not implement proper protections. For instance, an attacker could craft a malicious form that automatically submits to a vulnerable endpoint with a malicious file. The form would exploit the `multipart/form-data` encoding type, which allows files to be sent via POST requests.

- **Example**: An attacker could inject a malicious payload into an `input[type="file"]` field and use a hidden form that automatically submits (via JavaScript). If the server doesn’t validate the file content or its origin properly, the file could be uploaded with malicious intent (such as an executable or script).

### 8. **Explain how the concept of "complex requests" in CSRF attacks (such as those involving custom headers or JSON payloads) complicates detection and mitigation strategies.**

**Answer:**
- **Complex requests** in CSRF attacks involve additional headers (like `Authorization` or `Content-Type: application/json`) or custom payloads that make the request more sophisticated. The problem with detecting such requests is that they don't follow the standard form submission pattern and may appear to be legitimate API calls, particularly if the application doesn’t implement proper **CORS (Cross-Origin Resource Sharing)** or **CSRF token** validation mechanisms.

- **Mitigation**: Developers should ensure that complex requests are only allowed from trusted origins (by implementing CORS policies and checking the `Origin` or `Referer` headers). The use of **JWT (JSON Web Tokens)** or **OAuth** with secure header validation is another defense mechanism.

### 9. **How does Same-Origin Policy (SOP) interact with CSRF, and why doesn’t it inherently protect against CSRF attacks?**

**Answer:**
- **Same-Origin Policy (SOP)** is a browser security mechanism that prevents web pages from making requests to a domain different from the one that served the page. However, SOP doesn’t protect against **CSRF** because SOP only prevents cross-origin reads (e.g., accessing response data from a different domain), not cross-origin requests.

- **CSRF attacks exploit this** because the victim’s browser will still send the authentication cookies along with cross-origin state-changing requests (like POST or PUT), even if the request’s response cannot be read by the attacker’s domain.

### 10. **What are the potential consequences of a successful CSRF attack on a financial application, such as modifying account details or transferring money?**

**Answer:**
- A **successful CSRF** attack on a financial application could have catastrophic consequences:
  - **Modifying account details**: An attacker could change a user’s account information (like the email address or phone number) without the user’s consent, potentially locking the user out of their account.
  - **Transferring money**: If the victim is logged into a banking app, a CSRF attack could authorize unauthorized fund transfers to the attacker’s account, potentially resulting in financial loss.
  - **Changing security settings**: Attackers could change security preferences like multi-factor authentication (MFA) settings, which could be leveraged for further exploitation or account takeovers.

---

These questions and answers help assess an in-depth understanding of CSRF vulnerabilities, their detection, mitigation, and the real-world implications of CSRF attacks, especially in complex and modern web applications.
