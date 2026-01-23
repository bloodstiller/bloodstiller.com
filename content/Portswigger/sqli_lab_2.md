+++
title = "SQLi Vulnerabilities: Lab 2: SQL injection vulnerability allowing login bypass"
date = 2025-11-12
lastmod = 2025-11-12
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up, login bypass." 
tags = [
  "WebSecurity",
  "PortSwigger",
  "web-exploitation",
  "security-research",
  "portswigger-labs",
  "ctf-writeup",
  "injection",
  "sql",
  "sqli"
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

## Lab 2: SQL injection vulnerability allowing login bypass: {#lab-2-sql-injection-vulnerability-allowing-login-bypass}

> This lab contains a SQL injection vulnerability in the login function.
>
> To solve the lab, perform a SQL injection attack that logs in to the application as the administrator user.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

When we access the application we can see there is a "My account" page. If we click it we can see we can login.
![](/ox-hugo/2025-11-12_05-15.png)

Let's enter some fake credentials to view the login process.
![](/ox-hugo/2025-11-12_05-15_1.png)

This looks like a standard response.
![](/ox-hugo/2025-11-12_05-16.png)


### Finding SQLi Vulnerability In the Username Field: {#finding-sqli-vulnerability-in-the-username-field}

If we send the request to repeater we can add a single quote `'` after the username we have entered and send the request.
![](/ox-hugo/2025-11-12_05-21.png)
Doing so we can see we get a `500 Internal Server Error` response.

If we then add an additional single quote so it reads `test''` we get a `200` OK response. This shows that our input is being interpretted as SQL syntax.
![](/ox-hugo/2025-11-12_05-23.png)


### Inferring The SQL Query Being Run: {#inferring-the-sql-query-being-run}

Looking at the way the page we returns information can infer the query being run is similar to the below. 

```sql
SELECT * FROM users WHERE username = 'test' AND password = 'test'
```

However when we add our single quote it becomes which is syntactically incorrect in SQL as we have an open quotation mark.

```sql
SELECT * FROM users WHERE username = 'test'' AND password = 'test'
```

Then when we add our second single quote this closes our first single quote and the SQL is valid, although ugly.

```sql
SELECT * FROM users WHERE username = 'test''' AND password = 'test'
```

Working along these lines this means we could attempt to comment out the remainder of the SQL query by having a payload of `[username]'--` effectively bypassing the `password` check and allowing us to login.

```sql
SELECT * FROM users WHERE username = 'username'--' AND password = ''
```

If we do this for the "administrator" user.
![](/ox-hugo/2025-11-12_05-31_1.png)
~~Note~~: You can put ANY value you want for the password as it will be ignored.

This works and we are no logged in.
![](/ox-hugo/2025-11-12_05-32.png)

This is due to our payload making the SQL query into the below, bypassing the password check.

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```
