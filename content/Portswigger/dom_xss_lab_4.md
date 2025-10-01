+++
draft = false
author = "bloodstiller"
title = "DOM XSS Lab 4: jQuery anchor href sink with location.search source"
keywords = ["DOM XSS", "jQuery", "anchor href", "location.search", "client-side JavaScript", "URL parameter injection", "XSS prevention"] 
tags = ["WebSecurity", "XSS", "DOM", "JavaScript", "jQuery", "PortSwigger", "web-exploitation", "OWASP", "security-research"] 
description = "Walkthrough of PortSwigger Lab 4: DOM XSS where attacker-controlled input from location.search is used to set a jQuery-selected anchor’s href attribute. Includes source→sink mapping, exploitation steps, and mitigations." 
date = 2025-10-01 
toc = true 
bold = true 
next = true 
lastmod = 2025-10-01
+++

## Lab 4: DOM XSS in jQuery anchor `href` attribute sink using `location.search` source: {#lab-4-dom-xss-in-jquery-anchor-href-attribute-sink-using-location-dot-search-source}

> This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.
>
> To solve this lab, make the "back" link alert `document.cookie`.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}


#### Mapping The Comments Section: {#mapping-the-comments-section}

Looking at a post we can see we can add comments &amp; leave our name, email &amp; website.
![](/ox-hugo/2025-09-30-153613.png)

Let's enter some random values to see what happens. It's easier to use unique strings that we can easily search for afterwards.

```shell
bl00dst1ll3rComment
bl00dst1ll3rName
bl00dst1ll3r@example.com
http://bl00dst1ll3r.com
```

{{< figure src="/ox-hugo/2025-09-30-153806.png" >}}

After submitting the details to the page we can see that our name is hyprlinked &amp; if we click it, it will take us to the website we entered.

Looking at the page source code we can see our website is linked using an `href`.
![](/ox-hugo/2025-09-30-154217.png)

Looking at the form data further down we can see the name of the element is "website".

```html
<h2>Leave a comment</h2>
<form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
    <input required type="hidden" name="csrf" value="Ijn8GzRnLsaDRH0QbXuZmyFcALK99Y1i">
    <input required type="hidden" name="postId" value="2">
    <label>Comment:</label>
    <textarea required rows="12" cols="300" name="comment"></textarea>
            <label>Name:</label>
            <input required type="text" name="name">
            <label>Email:</label>
            <input required type="email" name="email">
            <label>Website:</label>
            <input pattern="(http:|https:).+" type="text" name="website">
    <button class="button" type="submit">Post Comment</button>
</form>
                    </section>
                    <div class="is-linkback">
                        <a href="/">Back to Blog</a>

```

However if we look at the rest of the source code and look for javascript between `<script>` tags there is none other that the `labHeader.js` which is not tied to this so looks like a dead-end.


#### Mapping Submit Feedback: {#mapping-submit-feedback}

Let's map the "Submit Feedback page"


##### Mapping The Submit Feedback form: {#mapping-the-submit-feedback-form}

Again we will enter some unique text.

```shell
bl00dst1ll3rName
bl00dst1ll3r@example.com
bl00dst1ll3rSubject
bl00dst1ll3rMessage
```

{{< figure src="/ox-hugo/2025-09-30-161322.png" >}}

Once we hit "Submit Feedback" we see the below message.
![](/ox-hugo/2025-09-30-161407.png)

If we open the dev tools and perform a search for our unique strings we can see we do not get any hits back which means our input is not being stored directly on the page.
![](/ox-hugo/2025-09-30-161531.png)


##### Mapping The `< Back` Button: {#mapping-the-back-button}

We can see there is a `< Back` button at the bottom of the page.
![](/ox-hugo/2025-09-30-161656.png)

Inspecting the page we can see the backlink button's code. It's using a standard href with a forward slash to signify the domain root.
![](/ox-hugo/2025-09-30-162117.png)

```html
<a id="backLink" href="/">Back</a>
```

Looking further down we can see the code that is responsible for this.
![](/ox-hugo/2025-09-30-162222.png)

We will analyze the source code now, however before we do so we need to understand a few things about jQuery and it's syntax.


### First A Note On jQuery And `$()` Functions: {#first-a-note-on-jquery-and--functions}

If you are unfamiliar with jQuery, `$` is jQuery's main function, it's essentially just an alias that jQuery chose to use for calling jQuery

**Which means these are exactly the same**:

```javascript
$('#backLink')        // Short version
jQuery('#backLink')   // Long version - does the exact same thing!
```

So if we see `$()` in JavaScript it's pretty strong indicator that jQuery is being used like 95% of the time we'll be right, but for the other 5% here's the catch:


#### Other Possibilities When We See `$()`: {#other-possibilities-when-we-see}

**Other libraries**:
A few older JavaScript libraries also used `$`:

-   [Prototype.js](http://prototypejs.org/learn/extensions.html)
-   [Cash](https://kenwheeler.github.io/cash/#docs) (a lightweight jQuery alternative)

+Note+: I'm sure there are most likely others however these are the ones I know of.

**Custom code**:
Someone could theoretically create their own `$` function:

```javascript
   function $(id) {
       return document.getElementById(id);
   }
```


### How To Know For Sure If jQuery Is Being Used: {#how-to-know-for-sure-if-jquery-is-being-used}

There are a few easy ways we can check if jQuery is being used.


#### Search The Code For jQuery: {#search-the-code-for-jquery}

The simplest way is to use devtools &amp; search the source code for the string "jQuery". In the case of this labe can see there is a direct reference to the file `jquery_1-8-2.js` that is being called by the application, so that is a dead giveaway.
![](/ox-hugo/2025-09-30-170546.png)


#### Search For jQuery-specific Methods: {#search-for-jquery-specific-methods}

We can also search for jQuery specific methods being used like `.attr()`, `.addClass()`, `.fadeIn()`, etc.

A full list of DOM manipulation methods can be found here at jQuery's API documentation
<https://api.jquery.com/category/manipulation/>


#### The Biggest jQuery Give-Away `$(document).ready()`: {#the-biggest-jquery-give-away--document--dot-ready}

Again we need to get into the weeds a little to explain this but it will payoff, I promise.


##### What Is `$(document).ready()` In jQuery? {#what-is--document--dot-ready-in-jquery}

When a webpage loads, the browser reads the `HTML` from top to bottom. If the JavaScript tries to manipulate an element before it exists, it will fail. "Document ready" means "wait until all the HTML is loaded, THEN run this code."

So when `$()` is called, jQuery looks at what is inside the parentheses and behaves differently based on the content:

If we pass a string like  `"#backLink"` jQuery will find the elements in the HTML that matches the string.

```javascript
$('#backLink')  // jQuery finds elements matching this selector
```

However if a function is passed (like in this case) jQuery knows to only execute the code once all the code is loaded and the DOM is ready.

```javascript
$(function() { ... })  // jQuery says "oh, run this when the DOM is ready"
```

This is where "document ready" comes from so the jQuery code only runs once the whole `document` is `ready`&#x2026;.see.

+Note+: There's nothing "magical" about passing a function javascript that automatically means "wait for the page." jQuery's creators simply decided: "When someone passes us a function, we'll assume they want it to run when the page is ready."
It's a convention that jQuery created, a shortcut they built into their library to make developers' lives easier!

You can also checkout jQuery's documentation here <https://learn.jquery.com/using-jquery-core/document-ready/>


##### Recognizing `$(document).ready()`: {#recognizing--document--dot-ready}

So now we know that we can use it to recognize when jQuery is being used.

**It's jQuery-specific syntax**
This exact pattern only works if jQuery is loaded.
+Remember+: Vanilla JavaScript doesn't understand `$(function() {...})`.

**The longer jQuery version is**:
This can sometimes be used

```javascript
$(document).ready(function() {
    // code here
});
```

But remember the `$(function() {...})` is just the shortcut version of the above!

**Here is the vanilla JavaScript equivalent**:
Without jQuery, you'd write:

```javascript
document.addEventListener('DOMContentLoaded', function() {
    // code here
});
```

So remember if you see `$(function() { ... })` at the start of code, it's **definitely jQuery**. No other library uses this exact pattern. It's one of jQuery's most recognizable signatures, essentially it's fingerprint!

If you see `$()` in JavaScript code, ****assume it's jQuery**** - that's the safest bet. But if something seems off or isn't working as expected, double-check that jQuery is actually loaded on the page.

In modern JavaScript (without jQuery), you'd typically see `document.querySelector()` or `document.getElementById()` instead.


### Analyzing the Source Code/Behavior: {#analyzing-the-source-code-behavior}

So now we have a good grounding in jQuery let's break down the code.


#### Declaring $( document ).ready() Function: {#declaring--document--dot-ready-function}

```javascript
$(function() {
    $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

As we saw when we see the pattern `$(function() { [code] });` we know that is jQuery's `$(document).ready()` code being used.

This means we know that whatever is contained within this function will run after the whole DOM is loaded.


#### Pass The Value Of `#backLink` As A Parameter: {#pass-the-value-of-backlink-as-a-parameter}

```javascript
$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
```

`$('#backLink')` again the shorthand for jQuery is being used `$()` so the first part of this is saying find the element `#backLink` on the page.

-   +Note+: When we see `#` that's basically saying "find me the element with this ID"

We are now going set the `href` (link) `.attr("href",` of the `backLink` element.

`(new URLSearchParams(window.location.search)).get('returnPath'))` this reads the URL parameters on the current page and looks for the parameter `returnPath` &amp; extracts the value from it. For example if the URL is `example.com/page.html?returnPath=/home`, this extracts `/home`

+In Plain English+: This code finds the `backLink` element on the page (which is what is executed when we click the `>Back` button). It then extracts the value from the `returnPath` parameter in the URL and sets the href (link) of the `>Back` button to this value. Essentially mapping where the user came from so they can easily go back to the previous page.


### Exploitation: Passing A Malicious JavaScript URL: {#exploitation-passing-a-malicious-javascript-url}

The pre-amble to the lab itself actually gives us the correct payload to exploit this vulnerability.
![](/ox-hugo/2025-10-01-072947.png)

Saying we can pass a malicious JavaScript URL however the lab specifies it want's us to trigger `document.cookie`.

**Steps**:

1.  We will modify their existing payload of `javascript:alert(document.domain)` to be `document.cookie`
2.  Final Payload: `javascript:alert(document.cookie)`
3.  Now we pass it as the value to the `returnPath` parameter in the URL:
    `returnPath=javascript:alert(document.cookie)`

**Result**:
![](/ox-hugo/2025-10-01-074528.png)
Then we hit enter and solve the lab:
![](/ox-hugo/2025-10-01-074622.png)


### Why This Is Vulnerable: {#why-this-is-vulnerable}

**Primary Issue**: The code creates a **DOM-based XSS vulnerability** by taking untrusted user input from the URL parameter (`returnPath`) and directly assigning it to the `href` attribute without any validation or sanitization.


#### Specific Vulnerabilities: {#specific-vulnerabilities}

1.  **No Input Validation**: The code blindly trusts whatever value is in the `returnPath` parameter. There's no check to ensure it's a valid, safe URL.

2.  **javascript: Protocol Execution**: When a `javascript:` URL is set as an `href` value, clicking that link executes the JavaScript code in the current page's context. This gives an attacker access to:
    -   Session tokens and cookies (`document.cookie`)
    -   Ability to modify the DOM
    -   Ability to make requests on behalf of the user
    -   Access to any sensitive data on the page

3.  **Client-Side Trust Boundary Violation**: The application assumes URL parameters are safe, but they're completely attacker-controlled (source). Any user (or attacker) can craft a malicious URL and send it to victims.


#### Attack Vector: An attacker can send a victim a link like: {#attack-vector-an-attacker-can-send-a-victim-a-link-like}

```html
https://victim-site.com/page?returnPath=javascript:alert(document.cookie)
```

When the victim loads this page and clicks "Back", their browser executes the attacker's JavaScript.


#### Potential Fixes: {#potential-fixes}

+Disclaimer+, I am not a coder! I would always recommend you read [OWASP DOM XSS Prevention Cheat Sheet over me](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html#dom-based-xss-prevention-cheat-sheet) and also follow security principle best practices.

**Never trust user input.** All data from URL parameters, form inputs, or any user-controlled source should be treated as potentially malicious. According to OWASP, DOM-based XSS occurs when "the application contains client-side code that processes data from an untrusted source in an unsafe way, usually by writing the data back to the DOM."

**Validate and sanitize on input, encode on output.** For URLs specifically:

-   Validate that the URL matches expected patterns (allowlist approach)
-   Never allow `javascript:`, `data:`, or `vbscript:` protocols in href attributes
-   Consider using relative URLs only when possible
-   Always have a safe default fallback


##### Remediation Options: {#remediation-options}

Again a further +disclaimer+, I am not a coder/programmer.

**Option 1: URL Allowlist**:
Only allow specific, known-safe return paths:

```javascript
$(function() {
    const returnPath = (new URLSearchParams(window.location.search)).get('returnPath');

    // Allowlist of valid paths
    const allowedPaths = ['/home', '/products', '/about', '/contact'];

    if (allowedPaths.includes(returnPath)) {
        $('#backLink').attr("href", returnPath);
    } else {
        // Default safe fallback
        $('#backLink').attr("href", '/home');
    }
});
```

**Option 2: URL Validation**:
Validate that the URL is a safe, relative path:

```javascript
$(function() {
    const returnPath = (new URLSearchParams(window.location.search)).get('returnPath');

    // Only allow relative URLs starting with '/'
    // This blocks javascript:, data:, http://, etc.
    if (returnPath && returnPath.startsWith('/') && !returnPath.startsWith('//')) {
        $('#backLink').attr("href", returnPath);
    } else {
        $('#backLink').attr("href", '/home');
    }
});
```

**Option 3: Use URL API for Validation**

```javascript
$(function() {
    const returnPath = (new URLSearchParams(window.location.search)).get('returnPath');

    try {
        const url = new URL(returnPath, window.location.origin);

        // Only allow same-origin URLs
        if (url.origin === window.location.origin) {
            $('#backLink').attr("href", url.pathname + url.search);
        } else {
            $('#backLink').attr("href", '/home');
        }
    } catch (e) {
        // Invalid URL
        $('#backLink').attr("href", '/home');
    }
});
```
