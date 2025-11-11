+++
title = "Authentication Vulnerabilities: Lab 10: Password reset broken logic"
date = 2025-11-10
lastmod = 2025-11-10
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up how to bypass flawed password reset logic."
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
  "password-reset-poisoning"

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

## Lab 10: Password reset broken logic: {#lab-10-password-reset-broken-logic}

> This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.
>
> Your credentials: wiener:peter
> Victim's username: carlos


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We have access to a web application with a "My account" section as well as an email client.
![](/ox-hugo/2025-11-10_07-13.png)


### Examining The Password Reset Process: {#examining-the-password-reset-process}

As we know the password reset process is vulnerable, let's go through this process to see how it work &amp; look for where we can exploit it.

Let's navigate to the "My account" page where we can see the "Forgot password?" option.
![](/ox-hugo/2025-11-10_07-15.png)

We are prompted for our username or email, we can enter the provided email client's email.
![](/ox-hugo/2025-11-10_07-17.png)
Once we hit submit we are told to check our email for the link.
![](/ox-hugo/2025-11-10_07-18.png)

Checking our email we are provided the link.
![](/ox-hugo/2025-11-10_07-18_1.png)

Looking at the page we are taken to we have a standard option of providing a new password &amp; looking at the string value it does appear to randomly generated.
![](/ox-hugo/2025-11-10_07-20.png)

Let's put in a new password &amp; copy the url.
![](/ox-hugo/2025-11-10_07-21.png)

If we try and revisit the link again once submitted we can see the token is no longer valid and has been revoked. This is good from a security point of view as these tokens should be revoked once used.
![](/ox-hugo/2025-11-10_07-25.png)

Examining the password reset `POST` request in burp we can see the username `wiener` is part of the request.
![](/ox-hugo/2025-11-10_07-26.png)
Let's initiate another reset but intercept the requests and modify the username to be "carlos" to see if that works.


### Performing A Password Reset On Behalf Of Our Target User: {#performing-a-password-reset-on-behalf-of-our-target-user}

First we initiate another password reset &amp; click the link in the email client.

We turn intercept on in burp suite.

We then enter the password we want to use &amp; submit the request.
![](/ox-hugo/2025-11-10_07-29.png)

We can then modify the username that the password is being reset for to be carlos &amp; forward the request on.
![](/ox-hugo/2025-11-10_07-30.png)

If we try and login as "carlos" we can see it works and we solve the lab.
![](/ox-hugo/2025-11-10_07-31.png)


### Why This Is Vulnerable: {#why-this-is-vulnerable}

When the token is issued it should have a mechanism that ensures that only the correct (user who initiated the request) user's password can be changed and then the token should be destroyed/invalidated. We can see from our testing the token is invalid once a reset has taken place as checking the endpoint `forgot-password?temp-forgot-password-token=[token]` once a token is used will not work, however by intercepting the `POST` request we can change any users password.
