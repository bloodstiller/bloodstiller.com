+++
title = "Authentication Vulnerabilities: Lab 3 : Username enumeration via response timing"
date = 2025-11-05
lastmod = 2025-11-05
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up exploring how timing differences in login responses can be exploited as a side channel to enumerate valid usernames."
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

## Lab 3 : Username enumeration via response timing: {#lab-3-username-enumeration-via-response-timing}

> This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.
>
> Your credentials: wiener:peter

Again we are provided a username and password list.

Due to this being a timing issue we can look at response times when we fuzz.
+Note+: I started this lab a while ago and then went on holiday (vacation), this means that the screenshots and source addresses may seem a bit all over the place, just focus on the theory I provide and it will work.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

First let's login with our credentials and grab the request in burp and send it to intruder.
![](/ox-hugo/2025-10-21_16-04.png)

{{< figure src="/ox-hugo/2025-10-21_16-03.png" >}}

Now we set our injection point and paste in our list.
![](/ox-hugo/2025-10-21_16-05.png)


### Discovering BruteForce Restrictions: {#discovering-bruteforce-restrictions}

Whilst reviewing the results we can see that some form of bruteforce mitigation is in place.
![](/ox-hugo/2025-10-21_16-24.png)


### Reviewing Headers For Bruteforce Mitigation: {#reviewing-headers-for-bruteforce-mitigation}

Looking at the headers there is nothing that is sending our IP to the host. This is usually done via the `X-Forwarded-For` http header.

You can read more about the header here: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For>

We can try and add our IP to the request as a parameter using the `X-Forwarded-For` header &amp; if it works this means we could, **in theory**, supply a list of random IP's that should make the server think the requests are coming from different source addresses and therefore bypass the IP bruteforce restrictions.


### POC: Adding the `X-Forwarded-For` header to bypass IP-Restrictions: {#poc-adding-the-x-forwarded-for-header-to-bypass-ip-restrictions}

Using repeater we can send a POST (login) request and append the `X-Forwarded-For` header to the bottom of the request and supply a random IP `192.168.2.1`. Looking at the response we can see we get a `302` (redirect) which is the correct response as it should now redirect to the "My Account" page, which means this works.
![](/ox-hugo/2025-11-05_04-54.png)


### Using X-Forwarded-For header to bruteforce the application: {#using-x-forwarded-for-header-to-bruteforce-the-application}

Now that we know this works if we had back to intruder we can start our attack.

We can then set our attack to be a "Pitchfork attack" and in the `X-Forwarded-For` position add a list of IP's. You can easily get a list of IP's from seclists or just generate the list yourself.

{{< figure src="/ox-hugo/2025-10-21_17-03.png" >}}

Now when we check the final entry we can see that we have bypassed the bruteforce restrictions.
![](/ox-hugo/2025-10-21_17-04.png)


### Reviewing Response Times for discrepencies {#reviewing-response-times-for-discrepencies}

To view response times we can click the three dots in burpsuite and select the response time from the menu.
![](/ox-hugo/2025-10-21_17-06.png)

Looking at the responses we can see there are discrepencies between received and response values.

For ease I have highlighted all entries with a discrepency and then filtered for them.

{{< figure src="/ox-hugo/2025-10-21_17-15.png" >}}

We can see the one with the biggest discrepancy is the user `vagrant` however when I run the test again I get a different result.
![](/ox-hugo/2025-11-05_05-09.png)

This inconsistency between results happens every time I run the attack which means there is something else we are missing.


### Re-assessing What We Know: {#re-assessing-what-we-know}

With challenges like this it's always good to re-asses what we have done &amp; what we know so we can move forward.

**What we know**:

-   We know we have the correct user &amp; password lists as they are provided by the lab &amp; we know we are looking for a difference in response timing (as that's what's the lab is called).
-   We have 3 fields we can tamper with: username, password &amp; IP.

**What we have done**:

-   So far we have already supplied an additional header to bypass IP bruteforcing restrictions. We need to find the correct username first.

Knowing and have done these things this only leaves the password field as something we can tamper with. We can also re-read the section materials and see the following:

> **Response times**: If most of the requests were handled with a similar response time, any that deviate from this suggest that something different was happening behind the scenes. This is another indication that the guessed username might be correct. <span class="underline">For example, a website might only check whether the password is correct if the username is valid. This extra step might cause a slight increase in the response time. This may be subtle, but an attacker can make this delay more obvious by entering an excessively long password that the website takes noticeably longer to handle.</span>

Using this logic let's see what happens if we provide a long string to the password field and if this elicits a, **repeatable**, different response timing.


### Discovering A Valid Username VIA Response Timings: {#discovering-a-valid-username-via-response-timings}


#### Supplying A Long Password To The Password Paramater To Elicit A Response: {#supplying-a-long-password-to-the-password-paramater-to-elicit-a-response}

For generating random strings we can use: <https://www.gigacalculator.com/randomizers/random-alphanumeric-generator.php>
![](/ox-hugo/2025-11-05_05-55.png)

I set the character length at 255 as this is at the upper limit for most applications which often have a password character limit of between 64 &amp; 256.
![](/ox-hugo/2025-11-05_05-57.png)

Starting the attack again we get a more promising result for the username "app" this time the response time is close to the same time as our known user "wiener".
![](/ox-hugo/2025-11-05_06-01.png)

Let's validate the results by running the attack again.
![](/ox-hugo/2025-11-05_06-05.png)
As we can see we get the same results so we can work on the assumption that the username of "app" is also valid.


### Bruteforcing The Password: {#bruteforcing-the-password}

Now we know the username we can bruteforce the password. To do this we set our injection point as the password field and set our username as "app". We also still want to ensure we are providing the IP address via the `X-Forwarded-For` header.
![](/ox-hugo/2025-11-05_06-10.png)
+Note+: You may need to remove some already used IP addresses from your list to carry on.

We get a hit for the password `qwertyuiop` as we have a 302 response!
![](/ox-hugo/2025-11-05_06-11.png)

Let's validate this by logging in.
![](/ox-hugo/2025-11-05_06-12.png)

And the lab is solved.
![](/ox-hugo/2025-11-05_06-13.png)
