+++
tags = ["Box", "HTB", "Easy", "Windows", "LDAP"]
draft = true
title = "Outdated HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-10
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

    <!--listend-->

    ```shell

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
            -   ~~Note~~: that any host os can be used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
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

                -   ~~Note~~:
                    -   Each number corresponds to the minimum Windows Server version required for domain controllers in the domain or forest.
                    -   As the functional level increases, additional Active Directory features become available, but older versions of Windows Server may not be supported as domain controllers.

    3.  <span class="underline">We have the full server name</span>:
        -   Again we can see this has the CN as the base (mentioned previously.) So it appears it's a printer server site of some sort. What is also interesting is the CN name "Configuration", this could imply that it is still to be configured. Which is interesting as things that are still being configured may not have had thorough security standards actioned.
            ```shell
            serverName:
                CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=outdated,DC=htb
            ```
-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.

-   ~~Note~~: I was wrong I thought this would be the route forward, maybe it's kerberos&#x2026;
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
-   ~~Note~~: Remember you can only send mail via `SMTP` on the CLI not read. We need `IMAP` or `POP3` to read.


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


#### Logging into the `Shares` to find a `PDF`: {#logging-into-the-shares-to-find-a-pdf}

-   **I login to the SMB share using the guest account &amp; immediatley find a** `pdf`:
    -   `smbclient -U $domain\$guest \\\\$box\\Shares`
    -   {{< figure src="/ox-hugo/2024-10-10-091446_.png" >}}

-   **I download the** `pdf`:
    -   {{< figure src="/ox-hugo/2024-10-10-091600_.png" >}}


#### Attempting to extract creator names from the `.PDF`: {#attempting-to-extract-creator-names-from-the-dot-pdf}

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


#### Reading `NOC_Reminder.pdf` and discovering exploits that the environment is susceptible to: {#reading-noc-reminder-dot-pdf-and-discovering-exploits-that-the-environment-is-susceptible-to}

-   Looking at the PDF it provides a list of vulnerabilities in the environment that they need to patch as well as corresponding CVE's.
    -   {{< figure src="/ox-hugo/2024-10-10-092144_.png" >}}
    -   It also reveals another email address: `itsupport@outdated.htb`
    -   {{< figure src="/ox-hugo/2024-10-10-092155_.png" >}}


#### Investigating the CVE list For an attack path: {#investigating-the-cve-list-for-an-attack-path}

-   **I will use these CVE's as a starting point to see if we can find an easy way in.**


##### CVE-2022-30190 (Remote): {#cve-2022-30190--remote}

-   This is the follina exploit. There is a great writeup here by HTB. It is a microsoft word exploit.
    -   <https://www.hackthebox.com/blog/cve-2022-30190-follina-explained>
    -   John Hammond also has a great video here {{< youtube dGCOhORNKRk >}}


##### CVE-2022-30138 PrintSpooler Privilege Escalation: {#cve-2022-30138-printspooler-privilege-escalation}

-   Good privesc path once we have access as this needs to be performed locally.


##### CVE-2022-30129 Remote Code Execution vulnerability in Visual Studio Code: {#cve-2022-30129-remote-code-execution-vulnerability-in-visual-studio-code}

-   This CVE-2022-30129 pertains to a Remote Code Execution vulnerability in Visual Studio Code, affecting versions less than 1.67.1.


##### CVE-2022-29110 Microsoft Excel Remote Code Execution Vulnerability: {#cve-2022-29110-microsoft-excel-remote-code-execution-vulnerability}

-   Microsoft CVE-2022-29110: Microsoft Excel Remote Code Execution Vulnerability


##### CVE-2022-29130 Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability.: {#cve-2022-29130-windows-lightweight-directory-access-protocol--ldap--remote-code-execution-vulnerability-dot}

-   Microsoft Windows: CVE-2022-29130: Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability.


## <span class="org-todo todo TODO">TODO</span> Use Folina Send via SMTP to the two email addresses we have found {#use-folina-send-via-smtp-to-the-two-email-addresses-we-have-found}


### ?? `8531`: {#8531}


## <span class="org-todo todo TODO">TODO</span> use CVE list to attack: {#use-cve-list-to-attack}


## 2. Foothold: {#2-dot-foothold}

1.


## 3. Privilege Escalation: {#3-dot-privilege-escalation}

1.


## 4. Ownership: {#4-dot-ownership}


## 5. Persistence: {#5-dot-persistence}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.

2.

3.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.

2.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


## ~~CREDS~~: {#9c69d6}


### SSH Keys: {#ssh-keys}


### Compiled Usernames, Passwords &amp; Hashes: {#compiled-usernames-passwords-and-hashes}


#### Usernames: {#usernames}

```text
sflowers
itsupport
```


#### Emails: {#emails}

```text
sflowers@outdated.htb
itsupport@outdated.htb
```


#### Passwords: {#passwords}

```text

```


#### Username &amp; Pass: {#username-and-pass}

```text

```


#### Hashes: {#hashes}

```text

```
