+++
tags = ["Windows", "LDAP", "msDS-KeyCredentialLink", "Shadow Credentials", "Active Directory", "Rubeus", "Whisker"]
draft = false
title = "Understanding the Shadow Credentials Attack Vector"
author = "bloodstiller"
date = 2024-10-11
+++

## Understanding the Shadow Credentials Attack Vector: {#understanding-the-shadow-credentials-attack-vector}

The Shadow Credentials attack is an advanced technique that exploits Active Directory's certificate-based authentication mechanism to compromise user accounts without changing their passwords. This attack leverages the `msDS-KeyCredentialLink` attribute to add a malicious certificate, allowing an attacker to impersonate the target user stealthily.

**To put it simply**: If we have the `WriteProperty` privilege (specifically for the `msDS-KeyCredentialLink` attribute) over a user or computer object, we can set Shadow Credentials for that object and authenticate as them. You read that right, we can add a certificate-based credential to a user or computer and then authenticate as them. We can also request a `Kerberos` ticket and use it for pass-the-ticket attacks if needed.


### What are Shadow Credentials? {#what-are-shadow-credentials}

The Shadow Credentials attack exploits a feature in Active Directory called Key Trust Account Mapping. This technique allows an attacker to compromise a user account without changing its password, making it particularly stealthy and difficult to detect.


### Key Components of the Shadow Credentials Attack: {#key-components-of-the-shadow-credentials-attack}

1.  **Whisker**: A tool used to manipulate the `msDS-KeyCredentialLink` attribute of a user account.
    -   <https://github.com/eladshamir/Whisker>
2.  **Rubeus**: A tool for interacting with `Kerberos` authentication.
    -   <https://github.com/GhostPack/Rubeus>


### Enumerating Users Susceptible to the Shadow Credentials Attack: {#enumerating-users-susceptible-to-the-shadow-credentials-attack}

-   **In blood-hound look for the** `AddKeyCredentialLink`:
    -   {{< figure src="/ox-hugo/2024-10-11-120229_.png" >}}

-   **Being part of the groups below will often provide us with enough privielges to perform the attack**:
    -   Key Admins
    -   Enterprise Key Admins
    -   Admins Group


### Enumerating for the `WriteProperty`  `msDS-KeyCredentialLink` attribute on users: {#enumerating-for-the-writeproperty-msds-keycredentiallink-attribute-on-users}

1.  **Using** `PowerView`:
    ```powershell
       Get-DomainObjectAcl -Identity "CN=<User Name>,CN=Users,DC=domain,DC=com" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-.*-500" -and $_.ObjectAceType -eq "00000002-0000-0000-c000-000000000000"}
    ```

<!--listend-->

1.  **Using Active Directory PowerShell Module**:
    ```powershell
       Import-Module ActiveDirectory
       (Get-Acl "AD:CN=<User Name>,CN=Users,DC=domain,DC=com").Access |
       Where-Object {$_.ActiveDirectoryRights -match "WriteProperty" -and $_.IdentityReference -match "Domain Admins" -and $_.ObjectType -eq "00000002-0000-0000-c000-000000000000"}
    ```

2.  **Using ADSI Edit**:
    -   A GUI tool for viewing and editing AD objects and their attributes.
    -   Connect to the domain
    -   Navigate to the user object
    -   Right-click and select "Properties"
    -   Go to the "Security" tab
    -   Click "Advanced"
    -   Look for entries with "Write msDS-KeyCredentialLink" permission

3.  **Using dsacls Command-Line Tool**:
    ```cmd
       dsacls "CN=Target User,CN=Users,DC=domain,DC=com" | findstr /i "write.*msDS-KeyCredentialLink"
    ```


### +Shadow Credentials Attack Process: Step by Step+ {#4c7bfe}


#### 1. Initial Access {#1-dot-initial-access}

The attacker starts with some level of access to the domain, typically with privileges to modify user attributes.


#### 2. Whisker Execution {#2-dot-whisker-execution}

The attacker uses Whisker to add a new "shadow credential" to the target account:

```shell
whisker.exe add /target:nbarley /domain:sugarape.local
```

**This command**:

-   Generates a certificate for the target user (in this case, `nbarley`)
-   Updates the `msDS-KeyCredentialLink` attribute of the target account
-   Outputs a Base64-encoded certificate and a password
-   {{< figure src="/ox-hugo/2024-10-11-155959_.png" >}}


#### 3. Certificate Generation and Usage {#3-dot-certificate-generation-and-usage}

**Whisker creates**:

-   An `X.509` certificate
-   An associated private key

**The certificate's role in this attack**:

-   It's added to the user's `msDS-KeyCredentialLink` attribute in Active Directory
-   This attribute allows for certificate-based authentication as an alternative to password-based auth
-   The certificate is not directly used like a `Kerberos` ticket (`.kirbi` file)

**Instead, the process works like this**:

1.  The attacker presents the certificate during the `Kerberos` authentication process
2.  Active Directory validates the certificate against the one stored in `msDS-KeyCredentialLink`
3.  If valid, AD issues a `Kerberos` Ticket Granting Ticket (TGT) for the user


#### 4. Rubeus Exploitation: {#4-dot-rubeus-exploitation}

The attacker then uses Rubeus to leverage the generated certificate:

```shell
Rubeus.exe asktgt /user:nbarley /certificate:[Base64 Certificate] /password:"[Password From Whisker]" /domain:sugarape.local /dc:DC.sugarape.local /getcredentials /show
```

**This command**:

-   Uses the certificate to request a `Kerberos` TGT for Nathan Barley (nbarley)
-   The `/certificate` parameter contains the Base64-encoded certificate
-   The `/getcredentials` flag attempts to decrypt the encrypted NTLM hash from the TGT
-   The `/show` flag displays the ticket details and other information
-   If successful, Rubeus receives a TGT and can extract the NTLM hash


#### 5. Credential Extraction: {#5-dot-credential-extraction}

**As a result of this process**:

-   Rubeus obtains a TGT for Nathan Barley (nbarley) &amp; generates a `.kirbi` file which can be used for pass-the-ticket attacks.
-   It also extracts the user's NTLM hash
-   {{< figure src="/ox-hugo/2024-10-11-160210_.png" >}}


### Impact of the Shadow Credentials Attack: {#impact-of-the-shadow-credentials-attack}

-   The attacker gains the ability to authenticate as Nathan Barley `nbarley`
-   This can lead to further lateral movement or privilege escalation within the domain
-   The attack is stealthy, not triggering typical account modification alerts


### Shadow Credentials Attack Mitigation Strategies: {#shadow-credentials-attack-mitigation-strategies}

To protect against Shadow Credentials attacks:

1.  Monitor for changes to the `msDS-KeyCredentialLink` attribute
2.  Implement strong access controls on who can modify user attributes in Active Directory
3.  Use advanced threat detection systems that can identify unusual certificate-based authentication patterns
4.  Regularly audit and review certificate issuance and usage in your environment
5.  Implement the principle of least privilege for Active Directory administrators
6.  Use Protected Users security group for sensitive accounts
7.  Enable and configure Windows Defender Credential Guard
8.  Regularly patch and update domain controllers and Active Directory services
9.  Implement multi-factor authentication (MFA) for all user accounts, especially privileged ones
10. Consider using Privileged Access Workstations (PAWs) for administrative tasks


### Shadow Credentials Attack Detection Methods {#shadow-credentials-attack-detection-methods}

1.  **Monitor Active Directory Logs**: Look for `Event ID 4662` with the `msDS-KeyCredentialLink` attribute being modified.
2.  **Use PowerShell Scripts**: Develop scripts to regularly check for unexpected changes to the `msDS-KeyCredentialLink` attribute.
3.  **Implement SIEM Rules**: Create alerts for unusual certificate-based authentication attempts, especially from unexpected sources.
4.  **Network Traffic Analysis**: Monitor for unusual `Kerberos` traffic patterns that might indicate certificate-based authentication abuse.


### Conclusion {#conclusion}

The Shadow Credentials attack vector demonstrates the evolving complexity of securing modern Active Directory environments. It highlights the importance of looking beyond traditional password-based security and considering certificate-based authentication mechanisms and critical user attributes.

As defenders, staying informed about these advanced techniques is crucial. By understanding attacks like Shadow Credentials, we can better prepare our defenses and protect our organizations from sophisticated threats.


### Example of a Shadow Credentials Attack in Action: 
- Please see my walkthrough/writeup for the Hack The Box machine "Outdated": 
  - <https://app.hackthebox.com/machines/Outdated>
  - <https://bloodstiller.com/walkthroughs/outdated-box>

### Sources: {#sources}

-   I would recommend reading this for a DEEP dive onto it by the person who created Whisker, Elad Shamir: 
    -  <https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab>


-   Here is a great video also showcasing how simple this attack can be:
    -   {{< youtube IK7qPMqSKMY >}}
