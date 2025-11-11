+++
title = "Authentication Vulnerabilities: Lab 11: Password reset poisoning via middleware"
date = 2025-11-10
lastmod = 2025-11-10
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up password reset link poisoning using host header injection."
tags = [
  "WebSecurity",
  "PortSwigger",
  "web-exploitation",
  "security-research",
  "authentication",
  "login",
  "username-enumeration",
  "response-timing",
  "portswigger-labs",
  "xss",
  "ctf-writeup",
  "password-reset-poisoning",
  "host-header-injection"
]
keywords = [
  "authentication vulnerabilities",
  "timing attacks",
  "password cracking",
  "PortSwigger authentication lab",
  "web security"
]
toc = true
bold = true
next = true
+++

## Lab 11: Password reset poisoning via middleware: {#lab-11-password-reset-poisoning-via-middleware}

> This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: wiener:peter. Any emails sent to this account can be read via the email client on the exploit server.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

As usual we have access to a basic web application which has a "My account" section.
![](/ox-hugo/2025-11-10_07-57.png)

We can also access the exploit server as-well as the email client from the exploit server.
![](/ox-hugo/2025-11-10_07-58.png)


### Initiating The Password Reset Process: {#initiating-the-password-reset-process}

Let's map the password reset process to see how we can exploit it.

Under "My account" we find the "Forgot Password?" link
![](/ox-hugo/2025-11-10_08-00.png)

We can enter our email from the email client to reset our password.
![](/ox-hugo/2025-11-10_08-01.png)

Checking our email client we can see we have received a link to reset the password.

{{< figure src="/ox-hugo/2025-11-10_08-01_1.png" >}}

Looking at this specific request in burp it does not appear to contain anything that we could exploit directly.
![](/ox-hugo/2025-11-10_08-04.png)


### Password Reset Link Enuemration: {#password-reset-link-enuemration}

Let's trigger mulitiple password resets in succession to see if we can glean any information from the links generated.
![](/ox-hugo/2025-11-10_11-19.png)
Looking at the links they do appear to be random as these were generated using the same method &amp; name as opposed to email + name. This means (we already know due to the description of the lab) that the links are generated dynamically.


### Host Header Injection Bypass For Password Link Reset Poisoning: {#host-header-injection-bypass-for-password-link-reset-poisoning}

When we initiate a password reset we send a `POST` request to the endpoint `/forgot-password` with the username or email. As we only need the username we can initiate a password reset on behalf of another user, in this instance "carlos".

First we create a password reset for ourselves which we can then send the request to repeater.
![](/ox-hugo/2025-11-10_11-01.png)

In repeater we will modify the username to be "carlos" we can then add the "`X-Forwaded-Host`" header &amp; add our exploit server as the endpoint.
![](/ox-hugo/2025-11-10_11-12.png)

Now going back to our exploit server if we check the logs we can see we have carlos' password reset token.
![](/ox-hugo/2025-11-10_11-13.png)

We can then take this token &amp; reset carlos' password.
![](/ox-hugo/2025-11-10_11-14.png)

Once done we then login to solve the lab.

![](/ox-hugo/2025-11-10_11-14_1.png)
![](/ox-hugo/2025-11-10_11-15.png)


### Why Does This Work: {#why-does-this-work}

This attack only works as the application is using the `X-Forwarded-Host` header as a source when dynamically building the password reset urls.

The application needs to send carlos a password reset link like: <https://vulnerable-website.com/forgot-password?token=XYZ>

When it builds the full URL it is doing it dynamically this means the server has to decide what the host part is (`vulnerable-website.com`) &amp;, **for some reason**, instead of using a fixed value or the actual `Host` header, the application trusts the our supplied `X-Forwarded-Host` header and does something like the pseudo code below when constructing the reset link.

```shell
host = request.headers["X-Forwarded-Host"] or request.headers["Host"]
reset_link = "https://" + host + "/forgot-password?token=" + token
```

As we control the `X-Forwarded-Host` value we can supply our own exploit server &amp; the application will blindly use the value when composing the link in the email meaning carlos receives. <https://our-exploit-server-id.exploit-server.net/forgot-password?token=VICTIM_TOKEN> which means when carlos clicks the link, his browser makes a request to our server, and the reset token appears in our exploit server access logs.

+Note+: This took me a minute to figure out &amp; the reason being is it's not a technique I was/am overly familiar with but this attack requires injecting host override headers whilst password reset poisoning, below are some links that helped me understand the process more in depth.

-   <https://portswigger.net/web-security/host-header/exploiting#inject-host-override-headers>
-   <https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning>

This also really helps understand why this works.
![](/ox-hugo/2025-11-10_11-41.png)
