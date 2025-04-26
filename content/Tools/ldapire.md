+++
title = "LDAPire: Advanced Active Directory Enumeration Tool"
draft = false
tags = ["Active Directory", "Windows", "LDAP", "Python", "Tools"]
keywords = ["Active Directory enumeration", "LDAP reconnaissance", "AD user enumeration", "Service account detection", "LDAP authentication", "AD group enumeration", "LDAP security", "AD object analysis", "LDAP binary attributes", "AD penetration testing"]
description = "A comprehensive guide to LDAPire, a powerful Python-based tool for Active Directory enumeration and reconnaissance. Learn how to perform detailed AD enumeration, detect service accounts, and analyze LDAP attributes for security assessments."
author = "bloodstiller"
date = 2024-11-13
toc = true
bold = true
next = true
+++

- Originally posted on 2024-10-17 updated on 2024-11-13

## Introducing LDAPire: A Tool for Active Directory Reconnaissance {#introducing-ldapire-a-tool-for-active-directory-reconnaissance}

As penetration testers and security professionals, we often find ourselves needing to quickly assess and enumerate Active Directory environments. Today, I'm excited to share a tool I've developed that streamlines this process: LDAPire - the LDAP Checker and Enumerator.

You can find the full source code and installation instructions for LDAPire on my GitHub repository: [LDAPire on GitHub](https://github.com/bloodstiller/ldapire)

-   It's very much in it's infancy, however I plan on adding more features.


### What is LDAPire? {#what-is-ldapire}

LDAPire is a Python-based tool designed to connect to LDAP servers (primarily Active Directory Domain Controllers), perform authentication, and enumerate users and groups. It's built with flexibility and ease of use in mind, making it an invaluable addition to any pentester's toolkit.


### Key Features {#key-features}

1. **Advanced Connection Handling**: 
   - SSL/TLS support with automatic fallback to non-SSL
   - Support for both anonymous and authenticated binds
   - Secure credential handling and validation

2. **Comprehensive Enumeration**: 
   - Complete enumeration of users, groups, computers, and all domain objects
   - Detailed attribute collection with proper formatting
   - Advanced binary attribute handling (SIDs, GUIDs, Exchange attributes)

3. **Service Account Detection**:
   - Automated identification of potential service accounts
   - Pattern matching for common service account naming conventions
   - Context-aware results with surrounding information

4. **Output Organization**:
   - Basic Information Files:
     - Users.txt: User SAM account names
     - Groups.txt: Group SAM account names
     - Computers.txt: Computer SAM account names
     - Objects.txt: All object SAM account names
   
   - Detailed Information Files:
     - UsersDetailed.txt: Comprehensive user attributes
     - GroupsDetailed.txt: Comprehensive group attributes
     - ComputersDetailed.txt: Comprehensive computer attributes
     - ObjectsDetailedLdap.txt: All domain object details
   
   - Special Reports:
     - AllObjectDescriptions.txt: Consolidated descriptions
     - ServiceAccounts.txt: Potential service account findings

5. **Security Features**:
   - Anonymous bind detection and warning
   - Secure credential handling
   - Informative security status reporting


### Why Use This Tool? {#why-use-this-tool}

1.  **Time-Saving**: Quickly gather essential AD information without manual queries or multiple tools.
2.  **Comprehensive Data**: Get both high-level and detailed views of users and groups in one go.
3.  **Flexibility**: Works with various AD configurations and authentication scenarios.
4.  **Pentesting-Oriented**: Designed with the needs of security professionals in mind.

### Code: 
I have placed the code here for convenience. 

{{< ghcode "https://raw.githubusercontent.com/bloodstiller/ldapire/refs/heads/main/ldapire.py" >}}

### How to Use It {#how-to-use-it}

Using the tool is straightforward. After installation, you can run it with the following syntax:

```bash
python3 ldapire.py [DC_IP] [-u USERNAME] [-p PASSWORD]
```

For example:
```bash
# Authenticated enumeration
python3 ldapire.py 192.168.1.1 -u "DOMAIN\\username" -p "password"

# Anonymous enumeration
python3 ldapire.py 192.168.1.1
```

The tool provides clear console output showing progress:
```bash
============================================================
                LDAP Information Retrieval
                  Domain Enumeration
============================================================

Processing Users...
Processing Groups...
Processing Computers...
Processing All Objects...
Processing Descriptions...
Searching for Service Accounts...
```

### Output and Analysis {#output-and-analysis}

The tool generates several output files for different aspects of enumeration:

1. **Basic Information Files**:
   - `Users.txt`: Simple list of user SAM account names
   - `Groups.txt`: List of group SAM account names
   - `Computers.txt`: List of computer SAM account names
   - `Objects.txt`: List of all object SAM account names

2. **Detailed Information Files**:
   - `UsersDetailed.txt`: Comprehensive user attributes
   - `GroupsDetailed.txt`: Comprehensive group attributes
   - `ComputersDetailed.txt`: Comprehensive computer attributes
   - `ObjectsDetailedLdap.txt`: All domain object details

3. **Special Reports**:
   - `AllObjectDescriptions.txt`: Consolidated descriptions from all objects
   - `ServiceAccounts.txt`: Identified potential service accounts with context

- **The detailed files include proper formatting of binary attributes such as**:
  - Security Identifiers (SIDs)
  - GUIDs
- Exchange-specific attributes
- Other binary data types

### Ethical Considerations {#ethical-considerations}

As with any tool, it's crucial to use LDAPire responsibly and ethically. Always ensure you have explicit permission to test and enumerate the target Active Directory environment.

Happy hunting!

Bloodstiller

P.S. Remember, you can find the full source code and contribute to the project on the [GitHub repository](https://github.com/bloodstiller/ldapire)
