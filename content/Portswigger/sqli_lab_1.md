+++
title = "SQLi Vulnerabilities: Lab 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data"
date = 2025-11-12
lastmod = 2025-11-12
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up, simple WHERE clause retrieval" 
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

## Lab 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data: {#lab-1-sql-injection-vulnerability-in-where-clause-allowing-retrieval-of-hidden-data}

> This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:
> `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
>
> To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We have access to a simple shop front where we can filter for products.
![](/ox-hugo/2025-11-12_04-47.png)

When clicking a category we can see it's passed as a parameter in the url
![](/ox-hugo/2025-11-12_04-49.png)

Let's send a request to repeater so we can start to test for SQli.


### Testing For SQli: {#testing-for-sqli}

In repeater we can add a single quote after the paramater `'` and can see we get 500 error.
![](/ox-hugo/2025-11-12_04-51.png)
If we add an additional quote, thereby closing off the original quote we can see we no longer get an error. This means our input is being interpretted as SQL syntax confirming that the application is vulnerable to SQLi.
![](/ox-hugo/2025-11-12_04-53.png)


### Forcing The Application TO Show All Items In a Category: {#forcing-the-application-to-show-all-items-in-a-category}

We can add the payload `'OR 1=1--`'~ which when url encoded is `'+OR+1%3d1--` this makes the url string.
![](/ox-hugo/2025-11-12_04-59.png)

And if we check the application we can see we have solved the lab.
![](/ox-hugo/2025-11-12_05-01.png)


### Why This Works: {#why-this-works}

As the application is performing a query like below when displaying items.

```sql
SELECT * FROM products WHERE category = 'Accessories' AND released = 1
```

When we add on our payload, the query becomes the below.

```sql
SELECT * FROM products WHERE category = 'Accessories' OR 1=1-- AND released = 1
```

As we are injecting our query of `1=1` which will always resolve to `TRUE` &amp; commenting out the remainder of the query nullifying the `AND` clause so it is never evaluated so the query will fetch ALL items from the accessories category as `1=1`.
