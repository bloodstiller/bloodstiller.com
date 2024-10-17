+++
draft = false
tags = ["Active Directory", "Windows", "LDAP", "Python", "Tools" ]
title = "LDAPire: LDAP Enumeration Tool"
author = "bloodstiller"
date = 2024-10-17
+++

## Introducing LDAPire: A Tool for Active Directory Reconnaissance {#introducing-ldapire-a-tool-for-active-directory-reconnaissance}

As penetration testers and security professionals, we often find ourselves needing to quickly assess and enumerate Active Directory environments. Today, I'm excited to share a tool I've developed that streamlines this process: LDAPire - the LDAP Checker and Enumerator.

You can find the full source code and installation instructions for LDAPire on my GitHub repository: [LDAPire on GitHub](https://github.com/bloodstiller/ldapire)

-   It's very much in it's infancy, however I plan on adding more features.


### What is LDAPire? {#what-is-ldapire}

LDAPire is a Python-based tool designed to connect to LDAP servers (primarily Active Directory Domain Controllers), perform authentication, and enumerate users and groups. It's built with flexibility and ease of use in mind, making it an invaluable addition to any pentester's toolkit.


### Key Features {#key-features}

1.  **Adaptive Connection Attempts**: The tool first attempts to connect using SSL. If that fails, it automatically retries without SSL, ensuring maximum compatibility across different AD configurations.

2.  **Flexible Authentication**: Support for both anonymous binds and authenticated connections, allowing for use in various scenarios you might encounter during a pentest.

3.  **Comprehensive Enumeration**: Retrieves both basic and detailed information about users and groups, providing a wealth of data for further analysis.

4.  **Output Flexibility**: Generates four separate output files, giving you both quick-reference lists and in-depth details about AD objects.

5.  **Robust Error Handling and Logging**: Comprehensive logging helps you understand exactly what's happening during the enumeration process, aiding in troubleshooting and report writing.


### Why Use This Tool? {#why-use-this-tool}

1.  **Time-Saving**: Quickly gather essential AD information without manual queries or multiple tools.
2.  **Comprehensive Data**: Get both high-level and detailed views of users and groups in one go.
3.  **Flexibility**: Works with various AD configurations and authentication scenarios.
4.  **Pentesting-Oriented**: Designed with the needs of security professionals in mind.


### How to Use It {#how-to-use-it}

Using the tool is straightforward. After installation, you can run it with a simple command:

```nil
python3 pythonldap.py <DC_IP> [-u USERNAME] [-p PASSWORD]
```

For example, to perform an authenticated enumeration:

```nil
python3 pythonldap.py 192.168.1.100 -u "DOMAIN\username"
```

The tool will prompt for a password if not provided, ensuring secure credential handling.


### Output and Analysis {#output-and-analysis}

The tool generates four key files:

1.  `usersLdap.txt`: A quick reference list of user sAMAccountNames.
2.  `usersLdap_detailed.txt`: Comprehensive details about each user.
3.  `groupsLdap.txt`: A list of group sAMAccountNames.
4.  `groupsLdap_detailed.txt`: Detailed information about each group.

These files provide a goldmine of information for further analysis, helping you identify potential attack vectors, misconfigurations, or areas for deeper investigation.


### Ethical Considerations {#ethical-considerations}

As with any tool, it's crucial to use LDAPire responsibly and ethically. Always ensure you have explicit permission to test and enumerate the target Active Directory environment.

Happy hunting!

Bloodstiller

P.S. Remember, you can find the full source code and contribute to the project on the [GitHub repository](https://github.com/bloodstiller/ldapire)
