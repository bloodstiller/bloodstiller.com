+++
draft = false
author = "bloodstiller"
title = "DOM XSS Lab 3: Exploiting innerHTML with location.search in the Search Message"
keywords = ["DOM XSS", "innerHTML", "location.search", "DOM-based XSS", "client-side JavaScript", "URL parameter injection", "XSS prevention"] 
tags = ["WebSecurity", "XSS", "DOM", "JavaScript", "PortSwigger", "web-exploitation", "OWASP", "security-research"] 
description = "Walkthrough of PortSwigger Lab 3: DOM XSS where user-controlled input from location.search flows into innerHTML. Covers source → sink mapping, exploitation steps, and mitigations." 
date = 2025-09-30 
toc = true 
bold = true 
next = true 
lastmod = 2025-09-30
+++

## Lab 3: DOM XSS in `innerHTML` sink using source `location.search` {#lab-3-dom-xss-in-innerhtml-sink-using-source-location-dot-search}

> This lab contains a DOM-based cross-site scripting vulnerability in the blog search. It takes data from `location.search` and writes it into the page via `innerHTML`.
>
> To solve the lab, perform a cross-site scripting attack that calls `alert`.

Pre-amble, before the link to the lab. There is this text below, which tells essentially what we need to do and what will or won't work.

> The `innerHTML` sink doesn't execute `<script>` in modern browsers, and `svg onload` won’t fire here. Use alternative elements like `img` or `iframe` with event handlers (e.g., `onerror`, `onload`).
>
> Example: `element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'`


### Initial Reconnaissance / Discovery: {#initial-reconnaissance-discovery}

Logging onto the blog we can see there is a search function at the top of the page.
Let's enter a unique string `bl00dsti113r` and observe the results.

We can see our search string is being directly passed as a paramter in the `url`
`/?search=bl00dsti113r`

{{< figure src="/ox-hugo/2025-09-30-112802.png" >}}

In DevTools, we see the value is written once into the page under the element with id `searchMessage`.
![](/ox-hugo/2025-09-30-112946.png)


### Analyzing the Source Code / Behavior: {#analyzing-the-source-code-behavior}

Let's take a look at the source code and see what is happening.

```javascript
<script>
  function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
  }
  var query = (new URLSearchParams(window.location.search)).get('search');
  if (query) {
    doSearchQuery(query);
  }
</script>
```


#### doSearchQuery Function {#dosearchquery-function}

```javascript
function doSearchQuery(query) {
  document.getElementById('searchMessage').innerHTML = query;
}
```

This finds the element with id `searchMessage` and sets its `innerHTML` to whatever value `query` contains.

+In simple terms+: It replaces the contents of `searchMessage` with the value of `query` as HTML.

If we look further up the page we can see the target element `searchMessage` on the page.
![](/ox-hugo/2025-09-30-113723.png)


#### Query Variable {#query-variable}

```javascript
var query = (new URLSearchParams(window.location.search)).get('search');
```

`URLSearchParams` reads the page’s query string (`window.location.search`).

`.get('search')` extracts the value of the `search` parameter (what we type into the search box).

This is the HTML for the search box. The input’s name is `search`, and the form uses GET, so your text is sent as a query parameter `?search=...`.

```html
<section class=search>
  <form action=/ method=GET>
    <input type=text placeholder='Search the blog...' name=search>
    <button type=submit class=button>Search</button>
  </form>
</section>
```

+In simple terms+: Whatever we type in the search box goes into the URL as `?search=...` and is stored in `query`.


#### Running the Function {#running-the-function}

```javascript
if (query) {
  doSearchQuery(query);
}
```

If `query` has a value, the page writes it into `searchMessage` via `innerHTML`.


#### Summary: Where the data comes from (Source) and where it goes (Sink) {#summary-where-the-data-comes-from--source--and-where-it-goes--sink}

-   **Source (attacker-controlled)**: The value in the page URL, e.g. `?search=...`
    -   Read by: `URLSearchParams(window.location.search).get('search')` → stored in `query`
-   **Sink (dangerous write)**: `document.getElementById('searchMessage').innerHTML = query`

+In plain English+: Whatever we type into the search box ends up in the URL, gets read into `query`, and is then **inserted into the page as HTML**. Because it isn’t encoded or sanitized, the browser can treat our input like code. That’s DOM XSS.

**Flow**:
`URL ?search=...` → `query` → `innerHTML(#searchMessage)` ⇒ **code can run**


### Exploitation: {#exploitation}

Because `innerHTML` is used with untrusted (unsanitized) input, we can inject an element with an event handler.

**Steps**:

1.  Use an element that can fire handlers when it fails, in this case we will use `<img ... onerror=...>`.
2.  Now we force an error by specifying a fake `src` image so that the error triggers: `<img src=1 onerror=`
3.  Now we specify an alert should be triggered in the event of an error `alert(1)`.
4.  **Final Payload** :
    -   `<img src=1 onerror=alert(1)>`

Place it in the URL parameter (URL-encode if needed, in this case it is not needed):
`/?search=%3Cimg%20src%3D1%20onerror%3Dalert(1)%3E`

**Result**: the alert fires and the lab is solved.
![](/ox-hugo/2025-09-30-115148.png)

After dismissing the alert, you’ll see the broken image indicator because the file doesn’t exist.
![](/ox-hugo/2025-09-30-115244.png)


### Why This Is Vulnerable: {#why-this-is-vulnerable}

**Primary issue**: Untrusted input from `location.search` is inserted into the DOM via `innerHTML` without encoding/sanitization.


### How to Fix (Safer Patterns): {#how-to-fix--safer-patterns}

**How To Fix**: [OWASPS Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html#guideline) on making dynamic updates to the DOM recommend:

> RULE #1 - HTML Escape then JavaScript Escape Before Inserting Untrusted Data into HTML Subcontext within the Execution Context
>
> There are several methods and attributes which can be used to directly render HTML content within JavaScript. These methods constitute the HTML Subcontext within the Execution Context. If these methods are provided with untrusted input, then an XSS vulnerability could result.

HTML encoding &amp; also JavaScript encoding all untrusted input.

Guidelines Taken from [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html#guideline):

```javascript
//Dangerous
element.innerHTML = "<HTML> Tags and markup";

//Safer with User Input being encoded
var ESAPI = require('node-esapi');
element.innerHTML = "<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTML(untrustedData))%>";
```

For general other guidance, see OWASP’s DOM-based XSS Prevention Cheat Sheet:

-   <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
