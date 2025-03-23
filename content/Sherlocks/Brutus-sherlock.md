+++
tags = ["wtmp", "linux", "utmp", "sherlock", "auth.log", "defensive", "forensics"]
draft = false
title = "Brutus HTB Sherlock Challenge"
description = "A detailed analysis of a compromised Confluence server through SSH brute-force attack, using wtmp and auth.log files for forensic investigation."
keywords = "HTB, CTF, Linux, Linux forensics, wtmp, auth.log, security analysis"
author = "bloodstiller"
date = 2025-03-23
toc = true
bold = true
next = true
+++

## Brutus Hack The Box Sherlock Challenge Writeup: {#brutus-hack-the-box-sherlock-challenge-writeup}

-   <https://app.hackthebox.com/challenges/%3Csherlock%3E>


## Challenge Information: {#challenge-information}

-   **Difficulty**: Very-Easy
-   **Description**:
    -   In this very easy Sherlock, you will familiarize yourself with Unix `auth.log` and `wtmp` logs.
    -   We'll explore a scenario where a Confluence server was brute-forced via its SSH service.
        -   After gaining access to the server, the attacker performed additional activities, which we can track using `auth.log`.
        -   Although `auth.log` is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.


### Challenge Files: {#challenge-files}

-   **Files Provided**:
    -   `auth.log`
    -   `wtmp`


## Introduction {#introduction}

In this writeup, we'll investigate a security incident on a Confluence server that was compromised through its SSH service. We'll analyze two critical log files - `auth.log` and `wtmp` - to reconstruct the attack timeline and understand the attacker's actions.


### What You'll Learn {#what-you-ll-learn}

-   How to analyze Linux authentication logs (`auth.log`) and login records (`wtmp`)
-   Common patterns in SSH brute-force attacks
-   How attackers establish persistence after initial access
-   Basic Linux forensics techniques using command-line tools


### Investigation Overview {#investigation-overview}

Our analysis will follow this structured approach:

1.  Examining `wtmp` records to identify suspicious logins
2.  Analyzing `auth.log` entries to confirm the breach
3.  Reconstructing the attacker's actions post-compromise
4.  Drawing conclusions and security lessons


## Analysis: {#analysis}


### `wtmp` analysis: {#wtmp-analysis}

We are provided a `wtmp` file but what is a `wtmp` file &amp; what is it used for?


#### What Is A `wtmp` File? {#what-is-a-wtmp-file}

If we check the `man` pages using

```shell
wtmp man
```

We get the following paragraph

> The wtmp file records all logins and logouts.  Its format is exactly like utmp except that a null username indicates a logout on the associated terminal.  Furthermore, the terminal  name  ~  with  username shutdown  or  reboot  indicates a system shutdown or reboot and the pair of terminal names |/} logs the old/new system time when date(1) changes it.  wtmp is maintained by login(1), init(1),  and  some  versions  of getty(8) (e.g., mingetty(8) or agetty(8)).  None of these programs creates the file, so if it is removed, record-keeping is turned off.

-   **What does this mean in plain english?**
    -   The `wtmp` file logs login and logout events over time. It stores a history of all users who have logged in and out of the system, making it an important historical record of the `utmp` file.

-   +Further Context+: The `utmp` file (which is not part of this sherlock) keeps track of who is currently logged into the system. You can view its contents by using the `w` or `who` command, which will show you a list of all active users.


#### `wtmp` file type: {#wtmp-file-type}

The `wtmp` is a binary file which means if we try to `cat` it out it will not work, see below.

-   {{< figure src="/ox-hugo/2025-03-19-173603_.png" >}}

It is possible to open it in a text editor but there is a lot of noise due to it being a binary.

-   {{< figure src="/ox-hugo/2025-03-19-175527_.png" >}}

Luckily thought there is an easy way to get information from this file and filter out all the noise.


#### `wtmp strings` Analysis: {#wtmp-strings-analysis}

As we are dealing with binary data the easiest way to get information is to run `strings` on the file. However if we just ring strings as is it will give us a lot of output &amp; duplicate entries, luckily though we can refine our search further by piping the output into `sort` so that it will sort all lines alphabetically bringing duplicates together &amp; then once the duplicates are together we can further refine the results by removing using `uniq` so we are left with just the unique strings.

```shell
martin in content-org/Walkthroughs/HTB/Sherlocks/Brutus  🍣 main 📝 ×204🛤️  ×5 10GiB/31GiB | 0B/34GiB on ☁️  (eu-west-2) with /usr/bin/zsh
🕙 17:18:58 zsh ❯ strings files/wtmp | sort | uniq -i
203.101.190.9
6.2.0-1017-aws
6.2.0-1018-aws
65.2.161.68
pts/0
pts/1
reboot
runlevel
shutdown
ts/0root
ts/0ubuntu
ts/1cyberjunkie
ts/1root
tty1
tty1LOGIN
ttyS0
tyS0
tyS0LOGIN
```

We have some interesting things here, so let's analyze further.


#### Analysis out of output: {#analysis-out-of-output}


##### Terminal-related entries: {#terminal-related-entries}

-   `tty`: Stands for "`teletype`"
    -   These are terminal devices. They typically represent physical console access e.g. someone using a keyboard and screen directly connected to the machine or through a console port itself.
        -   `ttyS0`: Serial port terminal (console access) often used for remote server management in datacenters.
        -   `tty1`: First virtual console terminal on the system accessible via the physical host (Alt+F1, Alt+F2 etc)
        -   `tyS0`: Likely a typo in the log for "ttyS0"
        -   `tty1LOGIN`, `tyS0LOGIN`: Login events on those terminals
    -   +Findings+: There is not much in the way of findings here, as we know the challenge is about brute-forcing remote access however I felt important to put this here for context as it's important.
    -   +Important Note+:
        -   In **some** configurations, `tty` can also represent certain types of remote access, particularly; serial console servers that provide remote access to the physical serial port &amp; Out-of-band management interfaces like `IPMI/iDRAC` that provide console redirection.

<!--listend-->

-   `pts`: Stands for "pseudo-terminal slave":
    -   These are virtual terminals created for SSH/remote connections. Meaning anytime we see `pts` we can assume that an SSH/remote connection was established.
        -   `pts/0`, `pts/1`: Different pseudo-terminal sessions (numbered sequentially)
        -   `ts/0root`, `ts/1root`: Likely abbreviated entries for terminal sessions for the root user
        -   `ts/0ubuntu`: Terminal session for the `ubuntu` user
        -   `ts/1cyberjunkie`: Terminal session for the `cyberjunkie` user
    -   +Findings+:
        -   From this output we can see that there were remote/ssh sessions for the `root, ubuntu` &amp; `cyberjunkie` users.


##### IP Address Related Entries: {#ip-address-related-entries}

-   We can see that the IP addresses `203.101.190.9` &amp; `65.2.161.68` are listed. These are the remote IP source addresses from which users connected to the host.

-   +Findings+:
    -   We can see that 3 users logged in from the previous section the `root, ubuntu` &amp; `cyberjunkie` users, couple this with the fact that there is only 2 IP addresses we can safely assume that a user logged into two separate accounts from the same source address? Why would they do that&#x2026;it could be a mistake, e.g. someone logged in as root and realized they should not have so re-logged back in as `ubuntu` or `cyberjunkie`.

<!--list-separator-->

-  But what if they use `su` to change users will that not show in `wtmp`?

    "But bloodstiller, what if the user used `su [username]` to switch to another user, could that not account for the 3 users listed above&#x2026;." great question, but no.

    When a user uses `su` to switch to another user the original login session (`pts` or `tty`) remains the same in `wtmp`. The `su` command **is not recorded in** `wtmp` but instead recorded in other log files like `auth.log` or `secure`.

    **Just remember**: If the same user logs in multiple times (even from the same IP), each session gets a new `pts` entry in `wtmp`. This is because the `wtmp` file primarily tracks initial login sessions and system events, not user switching within those sessions.

    To track user switching via `su/sudo`, we would need to examine authentication logs like `/var/log/auth.log` or `/var/log/secure`.


##### System event entries: {#system-event-entries}

-   `reboot`: System restart events
-   `shutdown`: System shutdown events
-   `runlevel`: Changes in system runlevel (system operational states)

<!--list-separator-->

-  System Runlevels Explained:

    Runlevels are a concept in Unix/Linux systems that define different operational states of the system.

    They determine which services and processes are running at any given time. When we see "runlevel" in the `wtmp` file, it indicates that the system changed from one operational state to another, e.g. off to on.

    In traditional `SysV` init systems (which many Linux distributions used before `systemd`), runlevels were numbered 0-6:

    -   **Runlevel 0**: System shutdown
    -   **Runlevel 1**: Single-user mode (also called maintenance mode) - minimal services, no networking, used for system maintenance
    -   **Runlevel 2**: Multi-user mode without networking (rarely used)
    -   **Runlevel 3**: Full multi-user mode with networking, but text-based (command-line interface only)
    -   **Runlevel 4**: Usually undefined/custom
    -   **Runlevel 5**: Full multi-user mode with networking and graphical interface (X11)
    -   **Runlevel 6**: System reboot

    In modern systemd-based systems (like recent Ubuntu versions), traditional runlevels have been replaced with "targets," but for compatibility, the system still records runlevel changes in `wtmp`.

    The "`runlevel`" entry in the `wtmp` file indicates that the system changed its operational state - for example, it might have booted up (changing from no runlevel to runlevel 5), or it might have been switched from graphical mode to text mode (runlevel 5 to 3).

    To see the current runlevel on a Linux system, we can use the `runlevel` command, which actually reads this information from the `wtmp` file.

    Here is an example from a pihole I have running on my home system which runs on the latest version of ubuntu.

    -   {{< figure src="/ox-hugo/2025-03-20-073357_.png" >}}


##### Kernel version entries: {#kernel-version-entries}

-   `6.2.0-1017-aws`, `6.2.0-1018-aws`: Are linux kernel versions running on AWS infrastructure.
    -   +Findings+:
        -   It would appear that there was a system upgrade from `6.2.0-1017-aws` to the `6.2.01018-aws` kernel.
        -   This could account for the reboot of the system as most kernel upgrades require a system reboot.


#### Summary of `wtmp` file findings. {#summary-of-wtmp-file-findings-dot}

We can now see that the `wtmp` file is showing a history of:

-   System events (reboots, shutdowns)
-   User logins (`root, ubuntu, cyberjunkie`)
-   Connection sources (the IP addresses) `203.101.190.9` &amp; `65.2.161.68`
-   Terminal types used for connections: `pts`
-   Kernel updates: `6.2.0-1017-aws` to `6.2.0-1018-aws`


### `auth.log` analysis: {#auth-dot-log-analysis}

We are also provided an `auth.log` file, but what is the `auth.log` file for?


#### What is `auth.log`? {#what-is-auth-dot-log}

If we check for documentation for the `auth.log file`, we find that it's not described in man pages in the same way as `wtmp`, as it's primarily a `syslog` facility rather than a specific file format. The `auth.log` file is typically located at `/var/log/auth.log` on Debian-based systems like Ubuntu, while on Red Hat-based systems, authentication messages are logged to `/var/log/secure`.

-   **But what does it do&#x2026;in plain English?**
    -   The `auth.log` file records authentication events and authorization operations on the system. It stores information about user logins, password changes, sudo command usage, SSH access attempts, and other security-related events.

-   +Further Context+: Unlike `wtmp` which records just login/logout events, `auth.log` **contains detailed information about all authentication attempts (both successful and failed)**. This makes it an invaluable resource for forensic analysis when investigating security breaches. The log entries are timestamped and often include the source IP address of login attempts, making it possible to trace suspicious activities, such as bruteforcing etc.

When investigating a breach, we as security professionals typically examine `auth.log` for:

-   Unusual login times or locations
-   Failed login attempts (potential brute force attacks)
-   Privilege escalation via `sudo`
-   Unauthorized SSH access attempts
-   Changes to user accounts or permissions: `chown/chmod`

This file is automatically maintained by the system's `syslog` daemon, so there's no need to create it manually. However, log rotation policies might archive older logs, so we may need to check both the current file and any archived versions during a forensic investigation.


#### `auth.log` file type: {#auth-dot-log-file-type}

This one is pretty self explanatory as it's a `.log` file, but we can run the `file` command on the file to explain what this is. We can see it's ascii text so we can open this in a standard text editor like, emacs, vim, nano, etc.

-   {{< figure src="/ox-hugo/2025-03-21-073930_.png" >}}


#### `auth.log` Analysis: {#auth-dot-log-analysis}

If we run `head -n 20 auth.log` to view the first 20 lines of the file we can see a number of things. (I will break this down into chunks for ease)

-   **CRON**:
    -   {{< figure src="/ox-hugo/2025-03-21-075334_.png" >}}
        -   These log entries show scheduled tasks (cron jobs) being executed regularly under the confluence user account:
            -   A system user named "`confluence`" with `UID` (User ID) `998`.
                -   This is a service account created specifically for running the Confluence application.
            -   Sessions being opened for the confluence user by the root user (`uid=0`)
            -   Sessions being closed shortly after
            -   **Regular Pattern**: The cron jobs are running at regular intervals (note the timestamps at `06:18:01` and then again at `06:19:01`), suggesting these are automated maintenance tasks for the Confluence application as they are every 1 minute.
            -   +Note+: "confluence" refers to [Atlassian Confluence](https://www.atlassian.com/software/confluence), which is enterprise collaboration software.

-   **SSH Key Issue**:
    -   {{< figure src="/ox-hugo/2025-03-21-114610_.png" >}}
        -   The last line indicates an SSH authentication problem, where the EC2 Instance Connect service tried to verify a key but failed (status 22). This is unrelated to the Confluence entries but could be relevant during a security investigation.
        -   +Note+: for the purposes of this investigation it is not relevant.

    -   **Root SHH Login**:
        -   {{< figure src="/ox-hugo/2025-03-21-115156_.png" >}}
            -   We can see here that there was an accepted ssh connection from the ip `203.101.190.9` and they logged into the root user account using password authentication.
            -   The PAM service opened the session by root for root:
                -   `session opened for user root(uid=0) by (uid=0)`
            -   The new session was established (`session 6`) by `systemd-login`
            -   +Note+: What is important about this is we can see that this service allows root login (serious security risk) &amp; password authentication for root is allowed (even worse security practice)


##### Summary of findings so far: {#summary-of-findings-so-far}

I think it's important to point out we have only looked at 20 lines of this 385 line file and we have already uncovered the below findings.

-   Root login via SSH is allowed which is a serious security risk on it's own.
-   Password authentication for root is enabled this is even worse security practice as this leads the root account to be susceptible to brute force attacks.
-   The source IP (203.101.190.9) should be investigated to determine if it's an expected/authorized source
    -   (We don't have a list of allowed IP's however, but in a real life scenario this should be checked)


#### Discovering evidence of a brute-force attack in `auth.log`: {#discovering-evidence-of-a-brute-force-attack-in-auth-dot-log}

As this file is 385 lines, we can speed up this investigation process by filtering out any information we deem legitimate.

```shell
🕙 12:19:11 zsh ❯ wc -l auth.log
385 auth.log

🕙 12:32:28 zsh ❯ cat auth.log | grep -v "user confluence" | wc -l
287
```

As you can see if we remove all lines that have the word "confluence" in them we can reduce the log by 98 lines.

Lets save this filtered file with no confluence entries to a new file for ease.

```shell
🕙 12:32:33 zsh ❯ cat auth.log | grep -v "user confluence" >> auth_noConfluence.log
```

-   +Note+: Just to be clear I am doing this now, but in a real world scenario, we could for instance, do this but if we did not find something then re-filter for this information in case the breach utilized a legitimate system account such as confluence.

Lets look at this filtered information now:

```shell
head -n 20 auth_noConfluence.log
```

-   {{< figure src="/ox-hugo/2025-03-21-124417_.png" >}}

-   This is very interesting we can see multiple attempts from the IP `65.2.161.68` to login to the host with the user name `admin`, the fact that multiple attempts take place at the same time `06:31:31` we can safely assume this is an automated brute-force attack and not someone with incredible typing skills.

Now that we have a source IP we can further refine our filtering, we also know from earlier that the word "accepted" is used when an ssh connection is established via password authentication, so lets filter for that.

```shell
cat auth_noConfluence.log | grep -Ie "65.2.161.68" | grep -ie "accepted" | wc -l
3
```

Now we can see we are down to 3 results. Let's check these.

-   {{< figure src="/ox-hugo/2025-03-21-131133_.png" >}}
    -   This is interesting, we have an accepted authorization via password to the root account at `6:31:40` &amp; `06:32:44`


#### Establishing Initial Breach Time of `6:31:40`: {#establishing-initial-breach-time-of-6-31-40}

Investigating the successful root login at `6:31:40`

If we filter for that specific time we get a larger view of what was happening at the time.

-   {{< figure src="/ox-hugo/2025-03-21-132137_.png" >}}

As we can see all of this happened at the same time `06:31:40`. At the top is the successful authorization login to the root account from the ip `65.2.161.68` however we can see further brute force attempts for the user names `server_adm` &amp; `svc_account` this is most likely due to having concurrent threads running when attacking and the successful login not stopping the process.

**Findings**:

-   So it appears the initial breach/access of the system took place at `06:31:40` by password brute forcing of the root account and that the subsequent access could have been manual (need to verify this though)
-   It was assigned the New Session number of 34.


#### Establishing Time Of Malicious User &amp; Group Creation `06:32:44`: {#establishing-time-of-malicious-user-and-group-creation-06-32-44}

As we saw there was a subsequent successful root login at `06:32:44` which we should also investigate.

As this is, what I believe to be a manual login, I am going to filter the results to show an additional 10 lines of information

```shell
cat auth_noConfluence.log | grep "06:32:44" -A 11
```

-   +Note+: I am using and additional 11 lines purely for this next part as if I used 10 it would cut off a crucial line, so for demonstrative purposes this is better.
-   {{< figure src="/ox-hugo/2025-03-21-181132_.png" >}}
    -   **Manual root login**:
        -   By the malicious actor at `06:32:44` as expected.
    -   **Group Creation**:
        -   We can then see that they made a group called `cyberjunkie` at `06:34:18`
    -   **User Creation**:
        -   They then created a user called `cyberjunkie` with the password `chauthtok`
    -   **Add User to sudo group**:
        -   We can then see they added the user `cyberjunkie` to the `sudo` group.
    -   **Summary**:
        -   The malicious actor now owns this system by compromising the `root` account they were able to add a new user and give that user full `sudo` privileges.

+Important Note+:

-   If you are doing this on HTB and filling out the answers, for whatever reason the answer is 1 second out, so even though from the logs the initial access `06:32:44` it wants `06:32:45` so the "correct" answer is `06:32:45 2024-03-06`. I wasted my time so you don't have to, you're welcome.


#### Enumerating further action take by `cyberjunkie` {#enumerating-further-action-take-by-cyberjunkie}

Now we know that the hacker has made a user account called `cyberjunkie` we can filter for all lines matching that.

-   +Note+: I understand we could have done that at the start after reading `wtmp` however it's important to look at the larger picture here and the process by which to break this all down.

-   {{< figure src="/ox-hugo/2025-03-21-182539_.png" >}}
    -   **Login**:
        -   We can see here that the user, logged back in as `cyberjunkie`
    -   **Read** `/etc/shadow`:
        -   They then ran `sudo cat /etc/shadow` to extract all the password hashes.
    -   **Download Persistence Tool**:
        -   They finally curled down `https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh` which is a linux persistence toolkit
        -   <https://github.com/montysecurity/linper>


## Attack Timeline: {#attack-timeline}

To tie everthing together here is an overview of the key points of the attack.

| Time (UTC)  | Event              | Details                                  |
|-------------|--------------------|------------------------------------------|
| 06:31:31    | Brute Force Begins | Multiple failed login attempts from      |
|             |                    | 65.2.161.68 using username "admin"       |
| 06:31:40    | Initial Breach     | Successful root login via SSH from       |
|             |                    | 65.2.161.68 (Session 34)                 |
| 06:32:44    | Secondary Access   | Second root login from same IP           |
| 06:34:18    | Persistence Setup  | Creation of "cyberjunkie" group          |
| 06:34:18-19 | User Creation      | "cyberjunkie" user created and           |
|             |                    | added to sudo group                      |
| Post-06:34  | Post-Exploitation  | - Reading /etc/shadow                    |
|             |                    | - Downloading linper.sh persistence tool |


### Key Findings From This Investigation: {#key-findings-from-this-investigation}

1.  **Attack Pattern Analysis**:
    -   Initial compromise through SSH brute force
    -   Quick transition to persistence (&lt; 3 minutes)
    -   Use of automated tools for maintaining access
    -   Classic privilege escalation through root access

2.  **System Vulnerabilities Identified**:
    -   Root SSH access enabled
    -   Password authentication allowed
    -   No brute force protection
    -   Weak access controls


## Further Technical Information: {#further-technical-information}

This is some additional information for users who want it, I find it helpful to add this information to provide further context and paint a larger picture.


### PAM (Pluggable Authentication Modules): {#pam--pluggable-authentication-modules}

-   PAM is a framework that provides authentication services to Linux systems
-   When we see entries like `session opened for user root(uid=0) by (uid=0)`:
    -   First `uid=0` refers to the user being authenticated (root)
    -   Second `uid=0` indicates which user/process initiated the authentication
-   PAM logs all authentication events, making it crucial for forensics


### Root SSH Access Risks: {#root-ssh-access-risks}

Root SSH access is particularly dangerous because of the following:

1.  It bypasses the principle of least privilege
2.  No audit trail of privilege escalation (`sudo` usage)
3.  Single point of failure - if root password is compromised, the whole system is compromised.
4.  No individual accountability when multiple admins have access (each user should have their own key)


### `linper.sh` tool: {#linper-dot-sh-tool}

The attacker downloaded `linper.sh`, a Linux persistence toolkit that can do the following.

-   Creates backdoor accounts
-   Modifies system binaries
-   Establishes reverse shells
-   Manipulates cron jobs
-   Hides malicious processes

This tool's presence indicates the attacker's intent to maintain long-term access, which means further analysis has to be taken, this is not a case of removing access, changing passwords etc.


## Security Recommendations: {#security-recommendations}

So we know what the attacker did, but how do we now prevent attacks &amp; attack paths like the one above?


### SSH Hardening: {#ssh-hardening}

First of all, we should disallow the use of root login, especially with passwords. We can modify the `/etc/ssh/sshd_config` file to do so.

```cfg
# Key SSH configuration changes (/etc/ssh/sshd_config):
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 60
```

-   Use SSH key authentication only.
-   Implement fail2ban for ssh brute force protection.


### Access Control Best Practices: {#access-control-best-practices}

1.  **User Management**:
    -   Require individual accounts for all users, again users should NOT be using the sudo account.
    -   Implement strong password policies, use a password manager to store these (they should so complex that even if you wanted to remember them you couldn't.)
    -   Regular audit of user accounts and permissions.

2.  **Sudo Configuration**:

    -   Configure granular sudo permissions, if a user/system account does need sudo permissions to run a binary grant them that specific permission only.
    -   Enable sudo logging
    -   Require password for sudo access.

    <!--listend-->

    ```cfg
       # /etc/sudoers.d/logging
       Defaults log_output
       Defaults!/usr/bin/sudoreplay !log_output
       Defaults!/sbin/reboot !log_output
    ```

3.  **System Monitoring**:
    -   Configure remote logging
    -   Use SIEM solutions for log analysis, this way there should be notifications in events like this.


### Log Monitoring Setup {#log-monitoring-setup}

-   **Essential Logs to Monitor**:
    ```shell
      # Key files to monitor
      /var/log/auth.log
      /var/log/secure
      /var/log/wtmp     # Historic sudo uses
      /var/log/btmp     # Failed login attempts
      /var/log/lastlog  # Last login information
    ```

<!--listend-->

-   **Regular Auditing Schedule**: (below is not prescriptive, different companies have different needs etc.)
    -   Daily review of failed login attempts
    -   Weekly review of successful root access
    -   Monthly audit of user accounts and permissions
    -   Quarterly review of SSH configurations


## Lessons Learned: {#lessons-learned}


### Technical Lessons: {#technical-lessons}

-   Log correlation is crucial for full attack visibility and to build a whole picture of the events.
    -   Multiple log sources provide better context
-   Automated tools leave distinct patterns, we saw numerous ssh attempts in a single second.
-   Time synchronization is critical for investigation as we can build a timeline of the breach.

+Remember+: Security is a continuous process, not a one-time setup. Regular reviews and updates of security measures are essential for maintaining system integrity, you often can't just "set and forget", defenders need to be right 100% of the time, attackers only need to be right once to get a foothold.


### What did I learn? {#what-did-i-learn}

1.  That by correlating the wtmp &amp; auth.log files we gain a greater understanding of attacks and sudo uses.
2.  How dangerous, root login with weak passwords &amp; no rate limiting can be.


### What mistakes did I make? {#what-mistakes-did-i-make}

1.  None this time, but I'm sure I will make plenty of silly mistakes in the future.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great responsibility. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at bloodstiller dot com


## Resources for Further Learning: {#resources-for-further-learning}

-   [SSH Configuration Guide](https://www.ssh.com/academy/ssh/sshd_config)
-   [Linux Audit Documentation](https://linux-audit.com/)
-   [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
-   [MITRE ATT&amp;CK Framework](https://attack.mitre.org/)
