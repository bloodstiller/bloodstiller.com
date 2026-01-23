+++
title = "Authentication Vulnerabilities: Lab 2: Username enumeration via subtly different responses"
date = 2025-11-05
lastmod = 2025-11-05
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up showing how very small visual or textual differences in login responses can still be used to reliably enumerate valid usernames."
tags = [
  "WebSecurity",
  "PortSwigger",
  "web-exploitation",
  "security-research",
  "authentication",
  "login",
  "username-enumeration",
  "subtle-response-differences",
  "visual-diffs",
  "html-diffs",
  "portswigger-labs",
  "ctf-writeup"
]
keywords = [
  "authentication vulnerabilities",
  "username enumeration via subtle differences",
  "login response analysis",
  "side-channel indicators",
  "PortSwigger authentication lab",
  "web security",
  "UI-based enumeration",
  "error state enumeration"
]
toc = true
bold = true
next = true
+++

## Lab 2: Username enumeration via subtly different responses: {#lab-2-username-enumeration-via-subtly-different-responses}

> This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:
>
> Candidate usernames
> Candidate passwords
>
> To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

There is not much in the way of recon for this as we know it's a brute force attack so we can just locate the login page that is under "My account"
![](/ox-hugo/2025-10-16_16-39.png)

We will use burp for this and proxy everything through it.
+Note+: I am using burp-pro but this works just as well with community.

We will enter some creds we know are fake and will not work so we can get a baseline response.
![](/ox-hugo/2025-10-16_16-40.png)
We get the response "Invalid username or password." which is a good response as it does not reveal if the username or password is incorrect it is instead a standardized response.
![](/ox-hugo/2025-10-16_16-42.png)

We will take our request and send it to intruder.
![](/ox-hugo/2025-10-16_16-44.png)

We can paste in our payload list and start the attack:
![](/ox-hugo/2025-10-16_17-03.png)


### Negative Search To Filter Results &amp; Find The Correct Username: {#negative-search-to-filter-results-and-find-the-correct-username}

Now to make ourlives easier and filter the results we can perform a negative search on the response string.
![](/ox-hugo/2025-10-16_17-04.png)

We need to ensure the response string is copied from the page (+don't type it out+) copy and paste it. Trust me I have had things slip through the net as I have misstyped something before, always copy and paste.
![](/ox-hugo/2025-10-16_17-05.png)

And that leaves us with 1 response.
![](/ox-hugo/2025-10-16_17-07.png)
The difference is that this response is missing a full stop. `.` this means that the application does have conditional responses. This is a big no no as it means we now know that the user `activestat` is valid so we can start bruteforcing.


### Bruteforcing For The Password: {#bruteforcing-for-the-password}

This time we change our payload position and put in our password list.
![](/ox-hugo/2025-10-16_17-10.png)

Again we can do a negative match but this time use the string without the full stop.
![](/ox-hugo/2025-10-16_17-11.png)

This leaves again with a single response which is a `302` redirect (which will no doubt be redirecting to another page).
![](/ox-hugo/2025-10-16_17-12.png)

Let's try logging in with the creds `activestat:amanda`
It works as expected & we have solved the lab.
![](/ox-hugo/2025-10-16_17-14.png)

