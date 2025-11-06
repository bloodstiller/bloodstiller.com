+++
title = "Authentication Vulnerabilities: Lab 5: Username enumeration via account lock"
date = 2025-11-06
lastmod = 2025-11-06
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up exploring how to bypass login bruteforcing restrictions via responses"
tags = [
  "WebSecurity",
  "PortSwigger",
  "web-exploitation",
  "security-research",
  "authentication",
  "login",
  "username-enumeration",
  "timing-attack",
  "response-timing",
  "side-channel",
  "portswigger-labs",
  "ctf-writeup"
]
keywords = [
  "authentication vulnerabilities",
  "username enumeration via timing",
  "timing attacks",
  "response time side channel",
  "PortSwigger authentication lab",
  "web security",
  "login brute force",
  "side-channel analysis"
]
toc = true
bold = true
next = true
+++

## Lab 5: Username enumeration via account lock: {#lab-5-username-enumeration-via-account-lock}

> This lab is vulnerable to username enumeration. It uses account locking, but this contains a logic flaw. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.
>
> Candidate usernames
> Candidate passwords


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

As usual we have access to a web page which has a "My account" section.
![](/ox-hugo/2025-11-06_06-35.png)

Let's enter some creds we know won't work to see the response.
![](/ox-hugo/2025-11-06_06-36.png)

So we get a standard response: "Invalid username or password"
![](/ox-hugo/2025-11-06_06-36_1.png)


### Enumerating Usernames By Forcing Account Lockout: {#enumerating-usernames-by-forcing-account-lockout}


#### Manual Method: {#manual-method}

Taking the `POST` request for login, we can send it to burp intruder and set our injection point as the username and paste in the list of supplied usernames. We are doing this to see if we get any other form of response e.g. if the username is valid but the password wrong will we get a some sort of different response.

{{< figure src="/ox-hugo/2025-11-06_06-40.png" >}}

We will get no useful responses from just doing the attack once, however if we perform the attack 5 times in quick succession and filter our response size by length we can see that the user "arizona" has the message "You have made too many incorrect login attempts. Please try again in 1 minute(s)."
![](/ox-hugo/2025-11-06_06-48.png)

This means we have used the websites "safety" mechanism as a means to enumerate valid users


#### Using Automated Null Payloads For Username Enumeration: {#using-automated-null-payloads-for-username-enumeration}

Now the above method of quickly re-issuing the attack 5 times manually worked but this is not a great way to do this as it's error prone. Instead we can use a built in feature of burp which allows us to try payloads with a NULL x amount of times.

To do this we do the following:

-   Select the username value &amp; the password value as injection points.
    -   Ensure there is some sort of value in the password field also. It can be any value.
-   Select the "Cluster bomb attack" type.
-   For the password position select the payload type of "Null payloads"
-   Set the "Payload configuration" generate value to 5.

{{< figure src="/ox-hugo/2025-11-06_09-44.png" >}}

Once we start the attack we can see we get a hit.
![](/ox-hugo/2025-11-06_09-49.png)
+Note+: I added this section once I had already completed the lab and the valid username &amp; password combination changes each time you use the lab hence "announce" being the valid user in this case.

+Important+: For this to be effective we would need to know the lockout policy attempt value. The easiest way to do this is to set the "generate" value to something high meaning that if we do hit on a real username we will ensure we hit the lockout value and get confirmation.


### Bruteforcing The Password: {#bruteforcing-the-password}

We can now take the username and bruteforce using the password list. We repeat what we did before but this time setting the injection point as the password field and using the supplied list of passwords.
![](/ox-hugo/2025-11-06_07-06.png)

Looking through the results in intruder we can see there is a response with a shorter length for the password "hunter".
![](/ox-hugo/2025-11-06_07-06_1.png)

If we check that cominbation after waiting 1 minute we can see it works and we are logged in.
![](/ox-hugo/2025-11-06_07-04.png)


### Understanding The Logic Of This Vulnerability: {#understanding-the-logic-of-this-vulnerability}

Now this approach above doesn't really make much sense as after 5 incorrect login attempts the account is locked out for 1 minute. So is it just by chance we found the correct password&#x2026;well&#x2026;no&#x2026;as I retried the lab to ensure my findings were valid.

How this works is:

**Invalid Username**: If we try an invalid username we get the response <span class="underline">"Invalid username or password"</span>

**Valid Username**: If we try a valid username and hit the lockout limit due to incorrect password being entered we get the response <span class="underline">"You have made too many incorrect login attempts. Please try again in 1 minute(s)."</span>

**Valid Username &amp; Password**: However even if we hit the lockout limit with a valid username if we enter the valid password we still get a standard 200 response with no message (see below) this means we can infer valid usernames &amp; passwords by the applications response &amp; bypass the lockout policy too.
 ![](/ox-hugo/2025-11-06_09-58.png)
