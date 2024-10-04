+++
tags = ["Box", "HTB", "Medium", "Windows", "LDAP"]
draft = true
date = 2024-10-04
title = "Escape HTB Walkthrough"
author = "bloodstiller"
+++

## Escape Hack The Box Walkthrough/Writeup: {#escape-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/%3CBoxName%3E>


## 1. Enumeration: {#1-dot-enumeration}


### NMAP: {#nmap}

- +Testing+:
- =Example=:
-   **Basic Scan**:
    -   `nmap $box -Pn -oA basicScan`
        ```shell
          kali in 46.02-HTB/BlogEntriesMade/Escape/scans/nmap  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
           08:21:02 zsh ❯ nmap $box -Pn -oA basicScan
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-04 08:21 BST
          Nmap scan report for 10.129.228.253
          Host is up (0.042s latency).
          Not shown: 988 filtered tcp ports (no-response)
          PORT     STATE SERVICE
          53/tcp   open  domain
          88/tcp   open  kerberos-sec
          135/tcp  open  msrpc
          139/tcp  open  netbios-ssn
          389/tcp  open  ldap
          445/tcp  open  microsoft-ds
          464/tcp  open  kpasswd5
          593/tcp  open  http-rpc-epmap
          636/tcp  open  ldapssl
          1433/tcp open  ms-sql-s
          3268/tcp open  globalcatLDAP
          3269/tcp open  globalcatLDAPssl

          Nmap done: 1 IP address (1 host up) scanned in 12.52 seconds

        ```
    -   **Some interesting enumeration paths already**:
        -   `53` - DNS:
            -   We can check for interesting records:
        -   `88` - Kerberos:
            -   We can use kerbrute to bruteforce users using pre-auth.
        -   `445` - Good ol' smb:
            -   We can check for null sessions.
        -   `389` - LDAP:
            -   We can check for anonymous binds and enumerate the domain.
        -   `1443` - MSSQL:
            -   A good target in general to go after.

-   **In depth scan**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in 46.02-HTB/BlogEntriesMade/Escape/scans/nmap  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh  took 12s
     08:21:23 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-04 08:21 BST
    Nmap scan report for 10.129.228.253
    Host is up (0.038s latency).
    Not shown: 65515 filtered tcp ports (no-response)
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-04 15:24:15Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject:
    | Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
    | Not valid before: 2024-01-18T23:03:57
    |_Not valid after:  2074-01-05T23:03:57
    |_ssl-date: 2024-10-04T15:25:48+00:00; +8h00m00s from scanner time.
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject:
    | Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
    | Not valid before: 2024-01-18T23:03:57
    |_Not valid after:  2074-01-05T23:03:57
    |_ssl-date: 2024-10-04T15:25:48+00:00; +8h00m00s from scanner time.
    1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
    | ms-sql-ntlm-info:
    |   10.129.228.253:1433:
    |     Target_Name: sequel
    |     NetBIOS_Domain_Name: sequel
    |     NetBIOS_Computer_Name: DC
    |     DNS_Domain_Name: sequel.htb
    |     DNS_Computer_Name: dc.sequel.htb
    |     DNS_Tree_Name: sequel.htb
    |_    Product_Version: 10.0.17763
    | ms-sql-info:
    |   10.129.228.253:1433:
    |     Version:
    |       name: Microsoft SQL Server 2019 RTM
    |       number: 15.00.2000.00
    |       Product: Microsoft SQL Server 2019
    |       Service pack level: RTM
    |       Post-SP patches applied: false
    |_    TCP port: 1433
    |_ssl-date: 2024-10-04T15:25:48+00:00; +8h00m00s from scanner time.
    | ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
    | Not valid before: 2024-10-04T15:17:39
    |_Not valid after:  2054-10-04T15:17:39
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject:
    | Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
    | Not valid before: 2024-01-18T23:03:57
    |_Not valid after:  2074-01-05T23:03:57
    |_ssl-date: 2024-10-04T15:25:48+00:00; +8h00m00s from scanner time.
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject:
    | Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
    | Not valid before: 2024-01-18T23:03:57
    |_Not valid after:  2074-01-05T23:03:57
    |_ssl-date: 2024-10-04T15:25:48+00:00; +8h00m00s from scanner time.
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Not Found
    9389/tcp  open  mc-nmf        .NET Message Framing
    49669/tcp open  msrpc         Microsoft Windows RPC
    49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49694/tcp open  msrpc         Microsoft Windows RPC
    49712/tcp open  msrpc         Microsoft Windows RPC
    49722/tcp open  msrpc         Microsoft Windows RPC
    49743/tcp open  msrpc         Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2019 (89%)
    Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    |_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required
    | smb2-time:
    |   date: 2024-10-04T15:25:11
    |_  start_date: N/A

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 242.11 seconds

    ```


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
         08:22:05 zsh ❯ python3 ldapchecker.py $box
        Attempting to connect to 10.129.228.253 with SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=sequel,DC=htb
            CN=Configuration,DC=sequel,DC=htb
            CN=Schema,CN=Configuration,DC=sequel,DC=htb
            DC=DomainDnsZones,DC=sequel,DC=htb
            DC=ForestDnsZones,DC=sequel,DC=htb
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
            DC=sequel,DC=htb
          ldapServiceName:
            sequel.htb:dc$@SEQUEL.HTB
        ```

        -   The functionality level determines the minimum version of Windows server that can be used for a DC.
            -   Note that any host os can used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
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

                -   Note:
                    -   Each number corresponds to the minimum Windows Server version required for domain controllers in the domain or forest.
                    -   As the functional level increases, additional Active Directory features become available, but older versions of Windows Server may not be supported as domain controllers.

    3.  <span class="underline">We have the full server name</span>:
        -   Again we can see this has the CN as the base (mentioned previously.) So it appears it's a printer server site of some sort. What is also interesting is the CN name "Configuration", this could imply that it is still to be configured. Which is interesting as things that are still being configured may not have had thorough security standards actioned.
            ```shell
             serverName:
                CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=sequel,DC=htb
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.


### DNS `53`: {#dns-53}


#### Using [dnsenum](https://www.kali.org/tools/dnsenum/) to enumerate DNS records: {#using-dnsenum-to-enumerate-dns-records}

-   Run [dnsenum](https://www.kali.org/tools/dnsenum/) to enumerate if there are any interesting records present:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt sequel.htb`
        -   {{< figure src="/ox-hugo/2024-10-04-084509_.png" >}}
            -   Nothing of note other than the standard DNS records for a DC.


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   As kerberos is present we can enumerate users using [kerbrute](https://github.com/ropnop/kerbrute):

    -   `kerbrute userenum -d sequel.htb --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`

    ![](/ox-hugo/2024-10-04-084056_.png)
    Unfortunately we get no hits:


### SMB `445`: {#smb-445}


#### Using [netexec](https://www.kali.org/tools/netexec/) to check for null &amp; guest session on SMB: {#using-netexec-to-check-for-null-and-guest-session-on-smb}

-   **I check for a null sesion using netexec but they have been disabled**:
    -   `netexec smb $box -u '' -p '' --shares`

        {{< figure src="/ox-hugo/2024-10-04-084303_.png" >}}

-   **I check if the guest account has been disabled**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
        ![](/ox-hugo/2024-10-04-084640_.png)

        It looks like we can access the `Public` &amp; `IPC$` We will focus on the `Public` share.


##### Over view of `IPC$` Share: {#over-view-of-ipc-share}

-   **Quick overview if you are unfamiliar with the `IPC$` share**:
    -   The `IPC$` share (`Inter-Process Communication`) is a special administrative share in Windows which allows communication with programs via Named Pipes:
        -   It's mainly used for inter-process communication between hosts over a network.
        -   It also enables remote administration of a system, allowing file and print sharing.
        -   It's a default share on windows systems.
        -   Requires credentials for access, typically used in conjunction with administrative or user rights.
            -   But as you can see `Guest` creds can also work in some instances.
        -   It is possible to use `IPC$` for enumeration (e.g., enumerating users, shares, groups or services).


### RPC `135` &amp; `593` RPC Over HTTP: {#rpc-135-and-593-rpc-over-http}


### MSSQL `1433`: {#mssql-1433}


## 2. Foothold: {#2-dot-foothold}

1.


## 3. Privilege Escalation: {#3-dot-privilege-escalation}

1.


## 4. Ownership: {#4-dot-ownership}


## 5. Persistence: {#5-dot-persistence}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.

2.

3.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.

2.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


## ~~CREDS~~: {#9c69d6}


### SSH Keys: {#ssh-keys}


### Compiled Usernames, Passwords &amp; Hashes: {#compiled-usernames-passwords-and-hashes}


#### Usernames: {#usernames}

```text

```


#### Passwords: {#passwords}

```text

```


#### Username &amp; Pass: {#username-and-pass}

```text

```


#### Hashes: {#hashes}

```text

```
