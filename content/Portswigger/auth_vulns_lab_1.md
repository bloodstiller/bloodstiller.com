+++
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up demonstrating how inconsistent login error messages allow username enumeration via clearly different responses."
title = "Authentication Vulnerabilities: Lab 1: Username enumeration via different responses"
tags = [
  "WebSecurity",
  "PortSwigger",
  "web-exploitation",
  "security-research",
  "authentication",
  "login",
  "username-enumeration",
  "error-messages",
  "login-workflow",
  "portswigger-labs",
  "ctf-writeup"
]
keywords = [
  "authentication vulnerabilities",
  "username enumeration",
  "different login responses",
  "error message analysis",
  "PortSwigger authentication lab",
  "web security",
  "login brute force",
  "information disclosure"
]
toc = true
bold = true
next = true
date = 2025-11-05
lastmod = 2025-11-05
+++

## Lab 1: Username enumeration via different responses: {#lab-1-username-enumeration-via-different-responses}

> This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:
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


### Information Disclosure Via Response: {#information-disclosure-via-response}

We will enter some creds we know are fake and will not work so we can get a baseline response.
![](/ox-hugo/2025-10-16_16-40.png)

As we can see it says "Invalid Username" this is a bad response as it tells us the application checks if the username valid, this means we can use the responses generated to enumerate a valid username from the list we have been provided as it should in theory elicit a different response.
![](/ox-hugo/2025-11-05_07-44.png)


### Bruteforcing A Valid Username: {#bruteforcing-a-valid-username}

We will take our request and send it to intruder &amp; set our injection point as the "username". We will also paste the provided username list to be used as payloads.
![](/ox-hugo/2025-11-05_07-51.png)

Filtering the response via length we can see we get a valid hit for the username "analyzer" as it has a difference response of "Incorrect password"
![](/ox-hugo/2025-11-05_07-52.png)


### Bruteforcing A Valid Password: {#bruteforcing-a-valid-password}

Now we have our username we can repeat the process but this time setting out injection point as the password field and our username as "analyzer"
![](/ox-hugo/2025-11-05_07-54.png)

As we can see we get a valid hit for the password "tigger" as we get a 302 redirect response.
![](/ox-hugo/2025-11-05_07-55.png)

Let's validate the credentials by logging in.
![](/ox-hugo/2025-11-05_07-56_1.png)

Lab solved:
![](/ox-hugo/2025-11-05_07-57.png)


### Why This Is Vulnerable: {#why-this-is-vulnerable}

The main issue is that we were able to elicit a different response based on whether we entered a valid username or password. To partially remediate this there should be a generic response that is presented in either case such as "Invalid username or password" by doing this it's far harder to enumerate a valid username. Obviously other measures should also be in place.
