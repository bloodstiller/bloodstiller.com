+++
title = "Authentication Vulnerabilities: Lab 6: 2FA simple bypass"
date = 2025-11-06
lastmod = 2025-11-06
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up exploring how to bypass 2FA"
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
  "ctf-writeup",
  "2FA",
  "MFA",
  "2FA-bypass"
]
keywords = [
  "authentication vulnerabilities",
  "timing attacks",
  "PortSwigger authentication lab",
  "web security",
  "login brute force",
  "side-channel analysis",
  "2FA"
]
toc = true
bold = true
next = true
+++

## Lab 6: 2FA simple bypass: {#lab-6-2fa-simple-bypass}

> This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.
>
> Your credentials: wiener:peter
> Victim's credentials carlos:montoya


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

Looking at the application we have access to a simple web app with a login page as well as an email client.
![](/ox-hugo/2025-11-06_10-19.png)

Let's login with our credentials to see the login process.

{{< figure src="/ox-hugo/2025-11-06_10-22.png" >}}

We can see that when we login we are prompted for a 2FA code. If we check out email client we can see it's been emailed.
![](/ox-hugo/2025-11-06_10-23.png)

After entering the code we can see we are directed to the `/my-account?id=[username]` page.
![](/ox-hugo/2025-11-06_10-24.png)


### Bypassing 2FA Login: {#bypassing-2fa-login}

If we re-read the previous section before the lab can see it says the below.

> If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a "logged in" state before they have entered the verification code. In this case, it is worth testing to see if you can directly skip to "logged-in only" pages after completing the first authentication step. Occasionally, you will find that a website doesn't actually check whether or not you completed the second step before loading the page.

Using this logic, let's login as our user and then manually navigate straight to the my-account page and see if it works.

Once presented the 2FA page we can manually change the address as we are "technically" logged in as carlos already.
![](/ox-hugo/2025-11-06_10-27.png)

Once we do &amp; hit enter we can see we bypass the 2FA check and are logged in as carlos.
![](/ox-hugo/2025-11-06_10-28.png)
