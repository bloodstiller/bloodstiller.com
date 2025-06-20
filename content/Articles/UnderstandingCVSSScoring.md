+++
title = "Common Vulnerability Scoring System (CVSS) - Complete Guide for Security Professionals"
draft = false
tags = ["CVSS", "Security", "Vulnerability Assessment", "Penetration Testing", "Security Scoring", "Risk Assessment", "Cybersecurity", "Security Metrics", "FIRST", "NIST"]
keywords = ["CVSS scoring guide", "Common Vulnerability Scoring System", "vulnerability assessment", "security risk scoring", "CVSS calculator", "penetration testing scoring", "security metrics", "CVSS vector string", "vulnerability severity", "security assessment methodology"]
description = "A comprehensive guide to the Common Vulnerability Scoring System (CVSS) for security professionals and penetration testers. Learn how to score vulnerabilities, understand CVSS metrics, use vector strings, and apply proper scoring methodology in security assessments."
author = "bloodstiller"
date = 2025-06-20
toc = true
bold = true
next = true
lastmod = 2025-06-20
+++

## Introduction: {#introduction}

The Common Vulnerability Scoring System (CVSS) is an industry standard for assessing and communicating the severity of security vulnerabilities. This guide serves as both a comprehensive reference for security professionals and a practical tool for penetration testers.


### What is CVSS? {#what-is-cvss}

CVSS provides a standardized way to score vulnerabilities on a scale of 0.0 to 10.0, where 10.0 represents the most severe vulnerabilities. The system is maintained by the Forum of Incident Response and Security Teams (FIRST) and is widely adopted across the cybersecurity industry.

As penetration testers we typically use CVSS scorings to justify our findings and apply an appropriate score to them.


### CVSS Version Information {#cvss-version-information}

This guide covers CVSS v3.1, the current standard. CVSS v2 is deprecated but may still be encountered in legacy systems &amp; v4 is still not widely adopted as of yet.


### CVSS Score Ranges: {#cvss-score-ranges}

CVSS scores will fall into 1 of 5 scoring categories.

-   **Critical (9.0-10.0)**: Vulnerabilities that can lead to complete system compromise.
-   **High (7.0-8.9)**: Vulnerabilities that can lead to significant data loss or system access.
-   **Medium (4.0-6.9)**: Vulnerabilities that can lead to limited data loss or system access.
-   **Low (0.1-3.9)**: Vulnerabilities that have minimal impact or are considered informational.
-   **None (0.0)**: No impact


## CVSS Scoring Tools: {#cvss-scoring-tools}

There are multiple tools out there that can be used generate CVSS scores, below are just a few examples.

I have generated one myself which is available below, and also at <https://bloodstiller.com/tools/cvss-calculator/>

{{< iframe src="/cvss-calculator.html" width="100%" height="900px" frameborder="0" style="border: 1px solid #ddd; border-radius: 8px;" >}}

**Official Tools**:

-   **NIST Official Calculator**: <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator>
-   **FIRST CVSS Calculator**: <https://www.first.org/cvss/calculator/3.1>

**Third-Party Tools**:

-   **Visual JS Calculator**: (recommended by Tiberius): <https://cvss.js.org/>
-   **Qualys CVSS Calculator**: <https://www.qualys.com/research/security-advisories/cvss/>
    -   This is more of a suite of tools that can be used and incurrs a charge.


## Quick Reference Cheat Sheet: {#quick-reference-cheat-sheet}


### Base Score Metrics Quick Reference: {#base-score-metrics-quick-reference}

Sometimes when scoring the different metrics can overwhelming so here is a simple quick reference.

| Metric              | Values                             | Description                            |
|---------------------|------------------------------------|----------------------------------------|
| Attack Vector       | Network, Adjacent, Local, Physical | Where the attacker needs to be         |
| Attack Complexity   | Low, High                          | How difficult the attack is to execute |
| Privileges Required | None, Low, High                    | What access the attacker needs         |
| User Interaction    | None, Required                     | Whether user action is needed          |
| Scope               | Changed, Unchanged                 | Whether other systems are affected     |
| Confidentiality     | None, Low, High                    | Impact on data confidentiality         |
| Integrity           | None, Low, High                    | Impact on data integrity               |
| Availability        | None, Low, High                    | Impact on system availability          |


## Metrics Explained: {#metrics-explained}


### Base Score Metrics: {#base-score-metrics}

This is the only metric we **have** to fill out to get a score as penetration testers. The Base Score represents the intrinsic characteristics of a vulnerability that are constant over time and across user environments.


#### Exploitability Metrics: {#exploitability-metrics}


##### Attack Vector (AV): {#attack-vector--av}

This is where in space &amp; relation to the target the attacker needs to be to perform the attack.

- `Network` = Internet, the attacker is on a network.
  - **Example**: SQL injection via web application accessible from the internet

- `Adjacent Network` = The attacker is on an adjacent network to the target such as a subnet
  - **Example**: Attack from guest WiFi network against corporate network

- `Local` = The attacker is on the same network as the target.
  - **Example**: ARP spoofing on the same LAN

- `Physical` = The attackers is physically present at the machine or requires physical access.
  - **Example**: USB drop attack, direct console access


##### Attack Complexity: {#attack-complexity}

This is used to gauge the complexity of the attack.

- `Low` = Easy to execute, can be repeated with consistent success
    - **Example**: Simple SQL injection with predictable results

- `High` = Complex, may not work consistently, requires specific conditions
  - **Example**: Race condition that requires precise timing


##### Privileges Required: {#privileges-required}

These are the privileges required before the attack, e.g. what privileges the attacker needs to perform the attack.

- `None` = No access needed.
  - **Example**: Anonymous web user

- `Low` = Normal user account.
    -   **Example**: Authenticated web user

- `High` = Admin/root account.
    -   **Example**: Administrator or root access

+Note+: This can be complex. If the attack is against a webhost with a registration page to create an account, this would not be classed as "low" but instead "none" as the attacker had no privileges and then was able to generate privileges to perform the attack.


##### User Interaction: {#user-interaction}

Whether the victim has to be an active participant in the attack.

- `None` = No user involvement required
    - **Example**: Server-side vulnerability that doesn't require user action

- `Required` = User must be involved
    - **Example**: A user must click a malicious link, opening a file


##### Scope: {#scope}

Does this affect another application other than the one being attacked?

-  `Changed` = Affects more than the targeted application.
    -   **Example**: Stored XSS that steals cookies from admin panel on a different system to the one that is being attacked.

-  `Unchanged` = Only affects the targeted application.
    -   **Example**: SQL injection that only affects the vulnerable database

+Note+: This sometimes requires educated guesswork when making a score as often as testers we will have no direct insight into if the attack on HOST A effects HOST B.


#### Impact Metrics: {#impact-metrics}

These represent the CIA triad and score the impact of the vulnerability on them.


##### Confidentiality Impact: {#confidentiality-impact}

- `None` = No impact on data confidentiality
    -   **Example**: Denial of service vulnerability
- `Low` = Limited impact on data confidentiality
    -   **Example**: Access to some non-sensitive data
- `High` = Complete loss of confidentiality
    -   **Example**: Access to all data, including sensitive information


##### Integrity Impact: {#integrity-impact}

- `None` = No impact on data integrity
    -   **Example**: Information disclosure vulnerability
- `Low` = Limited impact on data integrity
    -   **Example**: Modification of some data
- `High` = Complete loss of integrity
    -   **Example**: Complete data corruption or unauthorized modifications


##### Availability Impact: {#availability-impact}

- `None` = No impact on system availability
    -   **Example**: Information disclosure vulnerability
- `Low` = Limited impact on system availability
    -   **Example**: Reduced performance or intermittent outages
- `High` = Complete loss of availability
    -   **Example**: Complete system crash or denial of service


### Temporal Score Metrics: {#temporal-score-metrics}

These metrics reflect how vulnerability severity changes over time. They can be added later if needed but are not required for basic scoring.


#### Exploit Code Maturity: {#exploit-code-maturity}

This indicates whether exploit code exists for this vulnerability:

-  **Unproven** = No proof that exploit exists
-  **Proof of Concept** = Proof of concept code exists but not functional
-  **Functional** = Functional exploit exists (GitHub, etc.)
-  **High** = Automated exploit exists (Metasploit, automated scripts)


#### Remediation Level: {#remediation-level}

Has the vendor fixed it and in what way:

-  **Official Fix** = Official fix released by vendor
-  **Temporary Fix** = Manual remediation advised, no official fix
-  **Workaround** = Manual configuration changes required
-  **Unavailable** = No fix or workaround exists


#### Report Confidence: {#report-confidence}

Not commonly used in penetration testing:

- **Unknown** = No real proof of existence and impact
- **Reasonable** = Evidence exists but not vendor-confirmed
- **Confirmed** = Vendor has confirmed the vulnerability exists


### Environmental Score Metrics: {#environmental-score-metrics}

As penetration testers, we typically don't modify Environmental Score Metrics as we don't have complete knowledge of the environment. These are usually adjusted by the organization receiving the assessment.

The Environmental metrics mirror the Base Score Metrics, allowing organizations to adjust scores based on their specific environment. For example:

-   A tester might score something as "Adjacent Network" but the organization knows the affected system is segregated on its own subnet
-   A tester might give a high Confidentiality score for SQL injection, but the organization knows the database only contains test data


## What is a CVSS Vector String? {#what-is-a-cvss-vector-string}

A CVSS vector string is a compact, standardized text representation of all the metrics used to calculate a CVSS score. It looks like this.

```java
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Each part after the version number (`CVSS:3.1`) defines a specific metric, such as how the vulnerability is accessed (`AV:N` = network), or how much user interaction is required (`UI:N` = none).

The vector string is "formula" behind the score, as it records the exact combination of conditions and impacts that led to a given score.


### Reversible and Consistent: {#reversible-and-consistent}

One of the key features of CVSS vectors is that they are reversible and consistent. This means that if someone plugs the exact same vector into a CVSS calculator, they will always get the same score and severity. This ensures repeatability and transparency when sharing or comparing vulnerability assessments.

A good way to think about this is like a hashing algorithm. If you take the string "hello world" and run it through a `SHA-256` hash function, you'll always get the same result, and so will everyone else, anywhere in the world. Similarly, a CVSS vector string is a standard representation that, when used, always produces the same score, regardless of who calculates it.

+Note+: Unlike hashes, CVSS vectors are also readable and can be "reversed" to see the exact conditions that produced the score.

Many different vector strings can exist, each describing different combinations of metrics &amp; these will naturally produce different scores and severities.

For example, a vulnerability requiring local access and user interaction will score lower than one exploitable remotely with no user interaction, even if they both affect the same system.

So while a vector string will always map to one unique score, there are countless valid vectors, each representing different scenarios.


### Some Examples Of CVSS Vector Strings: {#some-examples-of-cvss-vector-strings}

- **CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H**
  - Critical (10.0) - Remote code execution
- **CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H**
  - High (8.8) - XSS requiring user interaction
- **CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L** 
  - Medium (5.5) - Local privilege escalation


## Practical Examples: {#practical-examples}


### Example 1: SQL Injection Vulnerability: {#example-1-sql-injection-vulnerability}

**Scenario**: A web application has a SQL injection vulnerability in the login form that allows an attacker to bypass authentication and access the admin panel.

**Scoring**:

-   **Attack Vector**: Network (accessible via internet)
-   **Attack Complexity**: Low (standard SQL injection techniques)
-   **Privileges Required**: None (no authentication needed)
-   **User Interaction**: None (server-side vulnerability)
-   **Scope**: Unchanged (only affects this application)
-   **Confidentiality**: High (access to all data)
-   **Integrity**: High (can modify data)
-   **Availability**: None (doesn't affect system availability)

**CVSS Vector**: 
```java
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
```
  - **Score**: +9.1 (Critical)+


### Example 2: Stored XSS Vulnerability: {#example-2-stored-xss-vulnerability}

**Scenario**: A comment system allows users to post HTML that gets stored and displayed to other users, potentially stealing their session cookies.

**Scoring**:

-   **Attack Vector**: Network (accessible via internet)
-   **Attack Complexity**: Low (standard XSS techniques)
-   **Privileges Required**: Low (authenticated user account)
-   **User Interaction**: Required (victim must view the page)
-   **Scope**: Changed (affects other users' sessions)
-   **Confidentiality**: High (session hijacking)
-   **Integrity**: None (no data modification)
-   **Availability**: None (no system impact)

**CVSS Vector**: 
```java
CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N
```
- **Score**: 7.4 (+High+)


## Common Pitfalls &amp; How to Avoid Them: {#common-pitfalls-and-how-to-avoid-them}


### 1. Confusing Attack Vector with Attack Complexity: {#1-dot-confusing-attack-vector-with-attack-complexity}

-   **Mistake**: Thinking a complex attack means it's "Local" or "Physical"
-   **Reality**: Attack Vector is about location, Attack Complexity is about difficulty


### 2. Over-scoring Privileges Required: {#2-dot-over-scoring-privileges-required}

-   **Mistake**: Rating as "Low" when attacker can create account.
-   **Reality**: If no initial access is needed, it's "None". If anyone can sign up for an account it's classed as "None"


### 3. Misunderstanding Scope: {#3-dot-misunderstanding-scope}

-   **Mistake**: Always marking as "Changed" for web applications.
-   **Reality**: Only "Changed" if it affects systems beyond the target.


### 4. Inconsistent Impact Scoring: {#4-dot-inconsistent-impact-scoring}

-   **Mistake**: Marking all impacts as "High" for critical vulnerabilities.
-   **Reality**: Each CIA component should be scored independently.


### 5. Ignoring User Interaction: {#5-dot-ignoring-user-interaction}

-   **Mistake**: Forgetting to consider if user action is required.
-   **Reality**: This significantly affects the final score.


## Step-by-Step Walkthrough {#step-by-step-walkthrough}


### Walkthrough: Scoring a Buffer Overflow Vulnerability {#walkthrough-scoring-a-buffer-overflow-vulnerability}

Let's score a buffer overflow vulnerability in a network service:

1.  **Attack Vector**: Network (accessible over network)
2.  **Attack Complexity**: Low (standard buffer overflow techniques)
3.  **Privileges Required**: None (no authentication needed)
4.  **User Interaction**: None (no user action required)
5.  **Scope**: Unchanged (only affects this service)
6.  **Confidentiality**: High (can read arbitrary memory)
7.  **Integrity**: High (can modify arbitrary memory)
8.  **Availability**: High (can crash the service)


**Result**: 
```java
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```
- **Score**: +10.0 (Critical)+


### Walkthrough: Scoring a Local Privilege Escalation {#walkthrough-scoring-a-local-privilege-escalation}

Let's score a local privilege escalation vulnerability:

1.  **Attack Vector**: Local (requires local access)
2.  **Attack Complexity**: Low (simple exploit)
3.  **Privileges Required**: Low (normal user account)
4.  **User Interaction**: None (no additional user action)
5.  **Scope**: Unchanged (only affects this system)
6.  **Confidentiality**: High (access to all data)
7.  **Integrity**: High (can modify any data)
8.  **Availability**: High (can control the system)

**Result**: 
```java
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```
- **Score**: 7.8 (High)


## Troubleshooting {#troubleshooting}


## External Resources {#external-resources}


### Official Documentation: {#official-documentation}

-   **FIRST CVSS v3.1 Specification**: <https://www.first.org/cvss/specification-document>
-   **NIST National Vulnerability Database**: <https://nvd.nist.gov/>
-   **CVSS v3.1 User Guide**: <https://www.first.org/cvss/user-guide>


### Learning Resources: {#learning-resources}

-   **OWASP Risk Rating Methodology**: <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>
-   **MITRE CVE Database**: <https://cve.org/>

- **Tib3rius** has released a great video on CVSS scoring:

    {{< youtube AlYtTB2aJPE >}}


### Tools and Calculators {#tools-and-calculators}

-   **NIST CVSS Calculator**: <https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator>
-   **FIRST CVSS Calculator**: <https://www.first.org/cvss/calculator/3.1>
-   **Visual CVSS Calculator**: <https://cvss.js.org/>
-   **My CVSS Calculator**: <https://bloodstiller.com/tools/cvss-calculator/>
