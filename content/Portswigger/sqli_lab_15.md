+++
title = "SQLi Vulnerabilities: Lab 15: SQL injection with filter bypass via XML encoding"
date = 2025-12-09
lastmod = 2025-12-09
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up using XML encoding to bypass WAF and extract data"
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
  "waf",
  "xml"
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

## Lab 15: SQL injection with filter bypass via XML encoding: {#lab-15-sql-injection-with-filter-bypass-via-xml-encoding}

> This lab contains a SQL injection vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.
>
> The database contains a users table, which contains the usernames and passwords of registered users. To solve the lab, perform a SQL injection attack to retrieve the admin user's credentials, then log in to their account.


### Finding SQLi: {#finding-sqli}

If we check one of the product pages we have the ability to check the stock that is available at another store.
![](/ox-hugo/2025-12-09_11-56.png)

If we look at the request we can see it is a POST request.
![](/ox-hugo/2025-12-09_11-57.png)

Looking at the values if we that are sent `productId` &amp; `storeId` we can see if we put in a basic query like `5+2` which resolves to `7` it shows us the stock value for the product `7`
![](/ox-hugo/2025-12-09_11-59.png)

We can further validate this by checking other numbers to ensure that this is not a false positive.
![](/ox-hugo/2025-12-09_12-00.png)

If we check those specific products as well `5` &amp; `1` we can see that the individual values (even when combined) do not match the output of our query `5+2`. This validates that our input is being evaluated and processed on the backend.
![](/ox-hugo/2025-12-09_12-01.png)
![](/ox-hugo/2025-12-09_12-01_1.png)


### Discovering A WAF Is In Use: {#discovering-a-waf-is-in-use}

If we try and put a single quote in we can see that a WAF has detected it and we get an "Attack detected" message.
![](/ox-hugo/2025-12-09_12-15.png)

If we look at the text before the lab we can see the below payload which encodes the first `S` from the `SELECT` statement.

```xml
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

This means we may be able to encode our payloads as a means to bypass the way.


### Using Hackvertor To Bypass The WAF: {#using-hackvertor-to-bypass-the-waf}

There is a burpsuite extension called Hackvertor which is fantastic at encoding payloads, we will install that and use it.
![](/ox-hugo/2025-12-09_12-19.png)

Back in Repeater we will now see a Hackvertor tab.
![](/ox-hugo/2025-12-09_12-20.png)

If we put the payload below

```sql
3 OR 1=1
```

in the `storeId` parameter and select the following encoding method: Encode &#x2013;&gt; html_entities it should look like below.
![](/ox-hugo/2025-12-09_12-21.png)

Now we can send our request. As we can see we get a list of all the entries in the `units` column.
![](/ox-hugo/2025-12-09_12-23.png)

This is because the statement resolves to `True` and that takes precedence over the supplied value of 3 so therefore displays all values, the underlying query will be something like the below.

```sql
SELECT units from products where productId='3' OR True
```

We can verify this further by modifying our payload to be.

```sql
3 OR 1=2
```

And we get back the standard response as our `OR` statement resolves to `False` so therefore the number `3` is evaluated and provided.
![](/ox-hugo/2025-12-09_12-29.png)


### Extracting The Administrators Password: {#extracting-the-administrators-password}

Now we know how to bypass the WAF we can then use a simple `UNION SELECT` statement to extract the administrators password using the below payload.

```sql
3 UNION SELECT password FROM users WHERE username='administrator'
```

![](/ox-hugo/2025-12-09_12-33.png)
We get the password displayed in the response.

And we can login and solve the lab.
![](/ox-hugo/2025-12-09_12-35.png)
