+++
draft = false
tags = ["Active Directory", "Windows", "Server", "Python", "Tools" ]
title = "BloodServer: A Secure File Transfer Tool for Penetration Testers"
author = "bloodstiller"
date = 2024-10-17
toc = true
bold = true
next = true
+++

## BloodServer: A Secure File Transfer Tool for Penetration Testers {#bloodserver-a-secure-file-transfer-tool-for-penetration-testers}

As a penetration tester, securely transferring files during engagements is crucial. That's why I developed BloodServer, a lightweight Python-based server designed specifically for pentesters who need a quick and secure way to transfer files in controlled environments.

Feel free to contribute to the project or report issues on my [GitHub repository](https://github.com/bloodstiller/bloodserver).


### Key Features {#key-features}

1.  **Easy Setup**: BloodServer can be quickly deployed with minimal configuration.
2.  **Authentication**: Basic authentication is built-in to prevent unauthorized access.
3.  **HTTPS Support**: Optional HTTPS encryption for secure data transfer.
4.  **File Upload Capability**: Allows for easy file uploads via POST requests.
5.  **Configurable Options**: Customize port, username, and password via command-line arguments.
6.  **Graceful Shutdown**: Stop the server cleanly with a simple keyboard command.
7.  **Logging**: Server activities are logged for monitoring and debugging.


### Requirements and Installation {#requirements-and-installation}

BloodServer is lightweight and requires only Python 3.6+ and OpenSSL (for HTTPS support). Installation is as simple as cloning the repository:

```bash
git clone https://github.com/bloodstiller/bloodserver.git
cd bloodserver
```

No additional dependencies are needed as BloodServer uses Python standard library modules.


### Usage Example {#usage-example}

To start the server with default settings:

```bash
python bloodserver.py
```

For HTTPS and custom port:

```bash
python bloodserver.py -p 8443 --https
```

You can also specify a custom username and password:

```bash
python bloodserver.py -u bloodstiller --password bl00dst1ll3r --https
```


### Client-Side File Upload {#client-side-file-upload}

BloodServer supports file uploads via POST requests. Here are examples for both Windows (PowerShell) and Linux systems:


#### PowerShell (Windows) {#powershell--windows}

For HTTP:

```powershell
$wc = New-Object System.Net.WebClient; $wc.Headers.Add("Authorization", "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("username:password"))); try { $response = $wc.UploadData("http://serverip:port", [System.IO.File]::ReadAllBytes("path\to\file")); Write-Host "Server response: $([System.Text.Encoding]::UTF8.GetString($response))"; Write-Host "File sent successfully!" } catch { Write-Host "An error occurred: $_" }
```

For HTTPS (ignoring SSL certificate errors):

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $wc = New-Object System.Net.WebClient; $wc.Headers.Add("Authorization", "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("username:password"))); try { $response = $wc.UploadData("https://serverip:port", [System.IO.File]::ReadAllBytes("path\to\file")); Write-Host "Server response: $([System.Text.Encoding]::UTF8.GetString($response))"; Write-Host "File sent successfully!" } catch { Write-Host "An error occurred: $_" }
```


#### Linux {#linux}

For HTTP:

```bash
curl -X POST -u username:password -F "file=@/path/to/your/file" http://serverip:port
```

For HTTPS (ignoring SSL certificate errors):

```bash
curl -X POST -u username:password -F "file=@/path/to/your/file" -k https://serverip:port
```

Replace `username`, `password`, `/path/to/your/file`, `serverip`, and `port` with your specific values.

### Code: 
I have placed the code here for convenience. 

{{< ghcode "https://raw.githubusercontent.com/bloodstiller/bloodserver/refs/heads/main/bloodserver.py" >}}

### Security Considerations {#security-considerations}

While BloodServer provides basic security features, it's important to note:

-   It's designed for temporary use in controlled environments only.
-   Always use HTTPS in production environments.
-   The default self-signed certificate is not suitable for production. Use a proper SSL certificate from a trusted CA.
-   Regularly update the authentication credentials.
-   Be cautious when using commands that ignore SSL certificate errors, as they bypass security checks.


### Responsible Use {#responsible-use}

BloodServer is a tool for professional penetration testers and should only be used in environments where you have explicit permission. Misuse of this tool could lead to security vulnerabilities if deployed in inappropriate settings.


### Conclusion {#conclusion}

BloodServer aims to fill a niche need for penetration testers who require a quick, secure file transfer solution during engagements. While it's a powerful tool in the right hands, always remember the importance of responsible use and adherence to security best practices.

Feel free to contribute to the project or report issues on my [GitHub repository](https://github.com/bloodstiller/bloodserver).

Happy hacking!

Bloodstiller
