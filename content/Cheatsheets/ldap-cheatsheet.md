+++
draft = false
tags = ["Active Directory", "Windows", "LDAP","CheatSheet", "Pentesting"]
title = "Attacking LDAP: Deep Dive & Cheatsheet"
author = "bloodstiller"
date = 2024-10-16
+++


-   +Protocol for accessing and managing directory information, widely used in enterprise environments.+
    -   LDAP is an open-source and cross-platform protocol used for authentication against various directory services (such as AD).
    -   AD stores user account information and security information such as passwords and facilitates sharing this information with other devices on the network. **LDAP is the language that applications use to communicate with other servers that also provide directory services**. In other words, LDAP is a way that systems in the network environment can "speak" to AD.


## LDAP Overview: {#ldap-overview}

-   Ports: `389`, `636`
-   LDAP (Lightweight Directory Access Protocol)
-   The two most popular implementations of LDAP:
    -   [OpenLDAP](https://www.openldap.org/)
    -   [Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

    -   **Overview**:
        -   Protocol for accessing and managing directory information
        -   Widely used in enterprise environments
        -   Operates over TCP/IP

    -   **Directory Services**:
        -   Hierarchical organization of resources
        -   Includes users, groups, devices, and other objects
        -   A directory is a hierarchical data store that contains information about network resources such as users, groups, computers, printers, and other devices.

    -   **Operations**:
        -   Search: Query directory objects
        -   Add: Insert new records
        -   Delete: Remove existing records
        -   Modify: Update attributes of records

    -   **Authentication**:
        -   Anonymous
        -   Simple (clear-text)
        -   SASL (more secure methods)

    -   **LDAP Data Model**:
        -   DIT (Directory Information Tree)
        -   DN (Distinguished Name)
        -   Attributes: Descriptive elements like username, email, etc.

    -   **Common Implementations**:
        -   Microsoft's Active Directory
        -   OpenLDAP
        -   Novell's eDirectory

    -   **Security Concerns**:
        -   Clear-text password vulnerabilities
        -   LDAP injection attacks
        -   Use LDAPS for secure connections

    -   **Penetration Testing Relevance**:
        -   Enumeration of user accounts and groups
        -   Information gathering for privilege escalation

-   Note: Always perform activities like penetration testing with proper authorization.


## LDAP Requests &amp; Responses (how a session works): {#ldap-requests-and-responses--how-a-session-works}

-   **Model Overview**:
    -   LDAP uses a client-server architecture.
    -   Clients communicate with servers using LDAP messages, encoded in ASN.1 and transmitted over TCP/IP.
    -   Supports various requests like bind, unbind, search, compare, add, delete, modify, etc.

-   **LDAP requests &amp; responses**:
    1.  LDAP requests are messages that clients send to servers to perform operations on data stored in a directory service. An LDAP request is comprised of several components:
        -   **LDAP Requests**:
            1.  **Session Connection**:
                -   Clients connect via an LDAP port (commonly `389` or `636`).
            2.  **Request Type**:
                -   Specifies the operation (e.g., bind, search).
            3.  **Request Parameters**:
                -   The client provides additional information for the request, such as the distinguished name (DN) of the entry to be accessed or modified, the scope and filter of the search query, the attributes and values to be added or changed, etc
            4.  **Request ID**:
                -   Unique identifier for matching requests with responses.

    2.  Once the server receives the request, it processes it and sends back a response message that includes several components:
        -   **LDAP Responses**:
            1.  **Response Type**:
                -   Indicates the operation that was performed in response to the requests.
            2.  **Result Code**:
                -   Indicates success or failure and the reason.
            3.  **Matched DN**:
                -   Returns the DN of the closest matching entry, if applicable.
            4.  **Referral**:
                -   Provides a URL to another server with potentially more relevant information (if applicable).
            5.  **Response Data**:
                -   Additional data related to the response, such as attributes and values of an entry.

    3.  After receiving and processing the response, the client disconnects from the LDAP port.

-   +Example+:
    -   Consider a simple example where a client wants to search for a user's information in the directory:
        1.  **Client sends a search request**:
            1.  Connects to the LDAP server on port `389`.
            2.  Specifies request type: search.
            3.  Provides search parameters: `DN="cn=John Doe,ou=users,dc=example,dc=com"`, `scope="sub"`, `filter="(objectClass=person)"`.
            4.  Provides a request ID.

        2.  **LDAP Server processes the request**:
            -   Searches the directory for entries matching the criteria.
            -   Constructs a response message with the result.

        3.  **Server sends back a response**:
            1.  Response type: searchResult.
            2.  Result code: success (if the entry is found) or an error code.
            3.  Referral: (not applicable in this case)
            4.  Response data: Attributes and values of "John Doe" if the entry is found.

        4.  **Client processes the response**:
            -   Parses the attributes and values of "John Doe".
            -   Disconnects from the server.

-   **Diagram to understand visually**:
    ```shell
        [Client]
            |
            |---[Connect to LDAP Server on Port 389/636]
            |
            |---[Send LDAP Request]
            |       |
            |       |--[Request Type: e.g., Search]
            |       |--[Request Parameters: DN, Scope, Filter]
            |       |--[Request ID: Unique Identifier]
            |
        [LDAP Server]
            |
            |---[Process Request]
            |       |
            |       |--[Perform Operation: e.g., Search Directory]
            |
            |---[Send LDAP Response]
                    |
                    |--[Response Type: e.g., SearchResult]
                    |--[Result Code: Success or Error]
                    |--[Matched DN: Closest Matching Entry]
                    |--[Referral: URL to Another Server (if applicable)]
                    |--[Response Data: Attributes and Values (if found)]
            |
        [Client]
            |
            |---[Process Response]
            |
            |---[Disconnect]
    ```


## LDAP AD Authentication: {#ldap-ad-authentication}

-   LDAP is set up to authenticate credentials against AD using a "BIND" operation to set the authentication state for an LDAP session.
-   **LDAP authentication messages are sent in cleartext by default** so anyone can sniff out LDAP messages on the internal network. It is recommended to use TLS encryption or similar to safeguard this information in transit.

<span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline"><span class="underline">_</span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span></span>

-   **There are two types of LDAP authentication**.
    1.  **Simple Authentication**:
        -   Simple authentication means that a username and password create a BIND request to authenticate to the LDAP server. Simple authentication methods are as follows:
            -   Anonymous authentication
            -   Unauthenticated authentication
            -   Username/password authentication.

    2.  **SASL Authentication**:
        -   Security Layer (SASL) framework uses other authentication services. It can also provide further security due to the separation of authentication methods from application protocols.
            -   SASL Authentication example:(please note there are more methods of SASL Authentication):
                -   [Kerberos](https://en.wikipedia.org/wiki/Kerberos_(protocol)), to bind to the LDAP server and then uses this authentication service to authenticate to LDAP.
                -   The LDAP server uses the LDAP protocol to send an LDAP message to the authorization service which initiates a series of challenge/response messages resulting in either successful or unsuccessful authentication.


## OpenLDAP: {#openldap}

-   <https://www.openldap.org/>

-   **Definition**:
    -   OpenLDAP is an open-source implementation of the Lightweight Directory Access Protocol (LDAP).
    -   Used for directory services to store and manage sensitive information like user credentials, network resources, and permissions.

-   **How It Works**:
    -   Uses a hierarchical data structure (Directory Information Tree, DIT).
    -   Supports a variety of operations like add, delete, modify, and search.

-   **Protocols Involved**:
    -   LDAP
    -   LDAP over SSL/TLS (LDAPS)
    -   SASL for advanced authentication

-   **Importance in Cybersecurity**:
    -   Used as a central repository for user credentials.
    -   Security measures like ACLs (Access Control Lists) can be implemented.

-   **Application in Penetration Testing**:
    -   Test for misconfigurations in ACLs.
    -   Check for weak encryption or lack of signing in communications.

-   **Platform-Specific Implementations**:
    -   Most often used in Unix and Linux environments.
    -   Can be integrated with other platforms like Windows for cross-platform directory services.

-   **Configuration**:
    -   Main configuration file is usually slapd.conf or under _etc/openldap/slapd.d_ in newer versions.
    -   ACLs, logging, and other settings are configurable.

-   **Limitations**:
    -   Complexity can lead to misconfiguration.
    -   Security features must be manually enabled and configured.


## LDAP signing: {#ldap-signing}

-   **Definition**:
    -   LDAP Signing is a security feature that helps prevent man-in-the-middle attacks.
    -   It ensures that LDAP (Lightweight Directory Access Protocol) packets are genuine and unaltered during transmission.

-   **How It Works**
    -   The LDAP server signs all traffic sent to clients.
    -   Clients validate the signature to confirm data integrity.

-   **Protocols Involved**:
    -   [SASL](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer)(Simple Authentication and Security Layer) mechanisms can be used.
    -   LDAP over SSL/TLS also can enforce packet signing.

-   **Importance in Cybersecurity**:
    -   Prevents unauthorized modification of data during transmission.
    -   Increases trustworthiness of LDAP communications.

-   **Application in Penetration Testing**:
    -   Test to ensure LDAP signing is enabled.
    -   Check for vulnerabilities that may bypass or exploit unsigned LDAP traffic.

-   **Platform-Specific Implementations**:
    -   Microsoft AD (Active Directory) often implements this.
    -   OpenLDAP and other directory services can also enforce LDAP signing.

-   **Configuration**:
    -   Often set via Group Policy on Windows systems.
    -   For Linux, configurations are generally in the LDAP configuration files.

-   **Limitations**:
    -   Increases computational overhead.
    -   May not encrypt data, just signs it for integrity. Use with encryption for enhanced security.


## LDAP Bind Request: {#ldap-bind-request}

**A bind request consists of 3 elements**:

1.  The LDAP protocol the clients wants to use:
    -   This is represented by an integer value.
2.  The DN of the client/user to authentication:
    -   For an [Anonymous Bind](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol#Bind_%28authenticate%29) it would be empty. It would also typically be empty for SASL Authentication as SASL uses encoded credentials
3.  The credentials the client/user uses to authentication:
    -   For simple authentication this is the password for the DN specified in part 2. For Anonymous bind the string would be empty, for SASL authentication this is an encoded value.


## LDAP Anonymous Bind: {#ldap-anonymous-bind}

-   LDAP anonymous binds allow us to retrieve information from the domain, such as:
    -   A list of all users
    -   A list of all groups
    -   A list of all computers.
    -   User account attributes.
    -   The domain password policy.
    -   Enumerate users who are susceptible to AS-REPRoasting.
    -   Passwords stored in the description fields

-   Linux hosts running open-source versions of LDAP and Linux vCenter appliances are often configured to allow anonymous binds.


## LDAP Filters: {#ldap-filters}

-   **We can use LDAP Filters with tools like**:
    -   [ldapsearch](https://docs.ldap.com/ldap-sdk/docs/tool-usages/ldapsearch.html)
    -   [Active Directory Powershell Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)
    -   [PowerShell](https://learn.microsoft.com/en-gb/powershell/)  + other powershell cmdlets.


-   **LDAP filters must have one or more criteria**.
    -   If more than one criteria exist, they can be concatenated together using logical `AND` `&` or `OR` `|` operators.
    -   Operators are always placed in the front of the operands:
        -   This is due to it using the [Polish Notation](https://en.wikipedia.org/wiki/Polish_notation)  convention.
-   Definition of the syntax definition for the filter:
    -   <https://datatracker.ietf.org/doc/html/rfc4515>
-   **Guide on building filters**:
    -   <https://learn.microsoft.com/en-us/archive/technet-wiki/5392.active-directory-ldap-syntax-filters>



### LDAP Filter Operands: {#ldap-filter-operands}

-   **LDAP Filter Operands**:
    -   Filter rules are enclosed in parentheses and can be grouped by surrounding the group in parentheses and using one of the following comparison operators:

    -   AND (`&`)
        -   Syntax: `(&amp;(condition1)(condition2))`
        -   Description: Combines multiple conditions with a logical AND. All conditions must be true for a match.

    -   OR (`|`)
        -   Syntax: `(|(condition1)(condition2))`
        -   Description: Combines multiple conditions with a logical OR. At least one condition must be true for a match.

    -   NOT (`!`)
        -   Syntax: `(!(condition))`
        -   Description: Negates a condition. The condition must be false for a match.

-   **Some examples** `AND *and* ~OR` **operations are as follows**:
    -   `AND` Operations:
        -   One criteria:
            -   **Command**: `(&amp; (..C1..) (..C2..))`
            -   +Example+: `(&amp;(ObjectClass=user)(cn=nathan\*))`
            -   +Note+:
                -   Searches for users who's name starts nathan

        -   More than two criteria:
            -   **Command**: `(&amp; (..C1..) (..C2..) (..C3..))`
            -   +Example+: `(&amp;(ObjectClass=user)(cn=jo\*)(ou=IT))`
            -   +Note+:
                -   Searches for users whos name starts with jo\* and they are in the OU IT.

    -   `OR` Operations:
        -   One criteria:
            -   **Command**: `(| (..C1..) (..C2..))`
            -   +Example+: `(|(ObjectClass=user)(ObjectClass=group))`
            -   +Note+:
                -   Will return either users or groups.

        -   More than two criteria:
            -   **Command**: `(| (..C1..) (..C2..) (..C3..))`
            -   +Example+: `(|(ObjectClass=user)(ObjectClass=group)(ou=IT))`
            -   +Note+:
                -   Searches for users or groups that are in the OU IT.

    -   **Nested Operations**:
        -   Nested Operators:
            -   **Command**: `(|(&amp; (..C1..) (..C2..))(&amp; (..C3..) (..C4..)))`
            -   +Example+: `(|(&amp; (ObjectClass=user)(cn=jo\*)) (&amp; (ObjectClass=group)(cn=sql\*)))`
            -   +Note+:
                -   Translates to `"(C1 AND C2) OR (C3 AND C4)"`
                -   Searches for users who's names start with jo or groups who's name start with "sql"


-   **Examples of these being paired with** `ldapsearch`:
    -   We can pair search terms with filters to narrow down information even more.
    -   If I am enumerating a domain and a I know there is a user I want to go after called "Nathan" I can craft the following queries to enumerate them further.
```bash
ldapsearch -H ldap://10.129.204.54 -x -b "DC=sugarape,DC=local" '(&(ObjectClass=user)(cn=nathan*))' logoncount
ldapsearch -H ldap://10.129.204.54 -x -b "DC=sugarape,DC=local" '(&(ObjectClass=user)(cn=nathan*))' sAMAccountName
ldapsearch -H ldap://10.129.204.54 -x -b "DC=sugarape,DC=local" '(&(ObjectClass=user)(cn=nathan*))'
```


### LDAP Logical Operators: {#ldap-logical-operators}

-   When writing an LDAP search filter, we need to specify a rule requirement for the LDAP attribute in question (i.e. "(displayName=william)"). The following rules can be used to specify our search criteria:

| **Operator** | **Meaning**              | **Description**                                                                      |
|--------------|--------------------------|--------------------------------------------------------------------------------------|
| =            | Equality Operator        | Checks for exact match between attribute and value.                                  |
| ~=           | Approximately equal to   | Finds entries where the attribute is approximately equal to the given value.         |
| &gt;=        | Greater than or equal to | Finds entries where the attribute value is greater than or equal to the given value. |
| &lt;=        | Less than or equal to    | Finds entries where the attribute value is less than or equal to the given value.    |
| =\*          | Presence Test            | Checks if an attribute is present, regardless of its value.                          |

+Examples of Operators in use+:

| **Operator**      | **Rule**            | **Example**                                  |
|-------------------|---------------------|----------------------------------------------|
| Equal to          | (attribute=123)     | (&amp;(objectclass=user)(displayName=Smith)) |
| Not equal to      | (!(attribute=123))  | (!(objectClass=group))                       |
| Present           | (attribute=\*)      | (department=\*)                              |
| Not present       | (!(attribute=\*))   | (!homeDirectory=\*)                          |
| Greater than      | (attribute&gt;=123) | (maxStorage&gt;=100000)                      |
| Less than         | (attribute&lt;=123) | (maxStorage&lt;=100000)                      |
| Approximate match | (attribute~=123)    | (sAMAccountName~=Jason)                      |
| Wildcards         | (attribute=\*A)     | (givenName=\*Sam)                            |

-   List of user attributes:
    -   <https://docs.bmc.com/docs/fpsc121/ldap-attributes-and-associated-fields-495323340.html>


### LDAP Filter Item Types: {#ldap-filter-item-types}

| **Type**     | **Meaning**              |
|--------------|--------------------------|
| =            | Simple                   |
| =\*          | Present                  |
| =something\* | Substring                |
| Extensible   | varies depending on type |


### LDAP Filter Escaped Characters: {#ldap-filter-escaped-characters}

-   These must be escaped when making queries

| **Character** | **Represented as Hex** |
|---------------|------------------------|
| \*            | \\2a                   |
| (             | \\28                   |
| )             | \\29                   |
| \\            | \\5c                   |
| NUL           | \\00                   |


## Object Identifiers OID's: {#object-identifiers-oid-s}

### Overview:

- Unique string of numbers used to identify directory objects and attributes
- Hierarchical structure with dot-separated decimal numbers (e.g., 1.2.840.113556.1.4.803)
- Ensures standardization and avoids naming conflicts
- Commonly used in LDAP schemas and search filters

### Structure:

- Each number in the sequence represents a node in a hierarchical tree
- The full OID represents the path from the root to a specific leaf node
- Earlier numbers indicate broader categories, later numbers specify more precise items

Example of the tree structure:
{{< figure src="/ox-hugo/2024-08-23-094816_.png" >}}

### Usage Example:

Breaking down the LDAP query: `userAccountControl:1.2.840.113556.1.4.803:=8192`

1. `userAccountControl`: The attribute being queried
2. `1.2.840.113556.1.4.803`: OID for a specific matching rule (bitwise AND)
3. `:=`: Equality operator in LDAP
4. `8192`: Decimal value for the specific flag being queried (SERVER_TRUST_ACCOUNT)

This query structure allows for precise and standardized searches within LDAP directories.

See [LDAP Filter Using Object Identifiers OID's:](#ldap-filter-using-object-identifiers)

### Additional Resources:

- +Comprehensive List of OID's+ - <https://ldap.com/ldap-oid-reference-guide/>
- <https://en.wikipedia.org/wiki/Object_identifier>
- <https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax>


### LDAP Filter Using [Object Identifiers](https://en.wikipedia.org/wiki/Object_identifier): {#ldap-filter-using-object-identifiers}

-   Used with OID's and UAC bitmasks to filter for certain things. Useful when Living off the land in AD:
-   <https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax>


-   **`And` Operator**:
    -   Matching rule OID: `1.2.840.113556.1.4.803`
    -   String identifier: `LDAP_MATCHING_RULE_BIT_AND`
    -   Description: A match is found only if all bits from the attribute match the value. This rule is equivalent to a bitwise AND operator.
    -   +Example Query+: `(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))`
        -   This will return all administratively disabled user accounts
        -   Combined with [Active Directory PowerShell Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)  we can shorten it to:
        -   +Example+: `Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' | select name`

<!--listend-->

-   **~Or~ Operator**:
    -   Matching rule OID: `1.2.840.113556.1.4.804`
    -   String identifier: `LDAP_MATCHING_RULE_BIT_OR`
    -   Description: A match is found if any bits from the attribute match the value. This rule is equivalent to a bitwise OR operator.
    -   +Example Query+: `(member:1.2.840.113556.1.4.1941:=CN=Nathan Barley,OU=Network Ops,OU=IT,OU=Employees,DC=SUGARAPE,DC=LOCAL)`
        -   This matching rule will find all groups that the user Nathan Barley (`"CN=Nathan Barley,OU=Network Ops,OU=IT,OU=Employees,DC=SUGARAPE,DC=LOCAL"`) is a member of.
        -   +Example+: `Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Nathan Barley,OU=Network Ops,OU=IT,OU=Employees,DC=SUGARAPE,DC=LOCAL)'`

-   **Special Chain Operator**:
    -   Matching rule OID: `1.2.840.113556.1.4.1941`
    -   String identifier: `LDAP_MATCHING_RULE_IN_CHAIN`
    -   Description: This rule is limited to filters that apply to the DN. This is a special "extended" match operator that walks the chain of ancestry in objects all the way to the root until it finds a match.


## LDAP Query/Queries: {#ldap-query-queries}

-   [LDAP Search Terms](#ldap-search-terms):

-   **Computer Related LDAP Queries**:
    -   <https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20Computer%20Related%20LDAP%20Query>
-   **Active Directory User Related Searches**:
    -   <https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20User%20Related%20Searches>
-   **Active Directory Group Related Searches**:
    -   <https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20Group%20Related%20Searches>
-   **Guide on building filters**:
    -   <https://learn.microsoft.com/en-us/archive/technet-wiki/5392.active-directory-ldap-syntax-filters>


## +LDAP Search Terms+  {#ldap-search-terms}

-   **Great Cheat Sheets**: <https://gist.github.com/jonlabelle/0f8ec20c2474084325a89bc5362008a7>
    -   <https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx>
    -   <https://gist.github.com/jonlabelle/0f8ec20c2474084325a89bc5362008a7>

-   +Use these with+:
    -   [ldapsearch](https://docs.ldap.com/ldap-sdk/docs/tool-usages/ldapsearch.html)
    -   [LDAP Filters:](#ldap-filters)
    -   [Active Directory PowerShell Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)



### List [Domain Functionality Level](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels): {#list-domain-functionality-level}
```bash
ldapsearch -x -H ldap://[[DCIP]] -b "" -s base "objectClass=*" domainFunctionality""
ldapsearch -x -H ldap://10.129.42.188 -b "" -s base "objectClass=*" domainFunctionality""
```


### List User Information: {#list-user-information}

-   If none of these are what we need we can see other user attributes here:
    -   <https://docs.bmc.com/docs/fpsc121/ldap-attributes-and-associated-fields-495323340.html>
#### List All User Information:
-   Linux:
```bash
#Ldap Query
'(objectClass=user)' or '(&(objectCategory=person))'
# Examples Using ldapsearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 '(objectClass=user)'
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 '(&(objectCategory=person))'
```

-   Windows:
```powershell
#Ldap Query
Get-ADObject -LDAPFilter '(&(objectCategory=person))' or '(objectClass=user)'

# Examples Using LDAPFilter
Get-ADObject -LDAPFilter '(&(objectCategory=person))'
Get-ADObject -LDAPFilter '(&(objectCategory=person))' | select name | Measure-Object
```
-   The last option selects just the name and the pipes it into measure object which gives us the total number of users on the domain:

#### List a specific Users Information:
-   Linux:
```bash
#Ldap Query
'(&(ObjectClass=user)(cn=<name*>))'

# Examples Using ldapsearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 '(&(ObjectClass=user)(cn=nathan*))'
```
-   +Notes+:
            -   The wildcard `*` is correct after the name as we want to view all information about that account.
            -   Sometimes we will get output like this (this usually means the account is not found in the directory):
                -   {{< figure src="/ox-hugo/2024-07-12-092539_.png" >}}
            -   Where as this account is active and in use by the looks of it:
                -   {{< figure src="/ox-hugo/2024-07-12-092651_.png" >}}
-   Windows:
```powershell
#Ldap Query
Get-ADObject -LDAPFilter '(&(ObjectClass=user)(cn=<name*>))'

# Examples Using LDAPFilter
Get-ADObject -LDAPFilter '(&(objectCategory=user)(cn=carol*))'
```
-   +Note+: This will return all users called Carol, we could further narrow down our search by adding a last name:
            -   `'(&(objectCategory=user)(cn=carol smith))'`

#### List Users Who have Constrained Delegation Privileges:
-   Linux:
```bash
#Ldap Query
(userAccountControl:1.2.840.113556.1.4.803:=524288)

# Examples Using LDAPSearch
ldapsearch -D "cn=sugarape-student,dc=sugarape,DC=LOCAL" -w 'Academy_student_AD!' -H ldap://10.129.2.174 '(userAccountControl:1.2.840.113556.1.4.803:=524288)
```
-   Windows:
```powershell
#Ldap Query
(userAccountControl:1.2.840.113556.1.4.803:=524288)

# Example Using LDAPFilter
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
```
        
#### Users with Administrative Privileges:
-   Linux:
```bash
#Ldap Query
(&(objectClass=user)(adminCount=1))

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 '(&(objectClass=user)(adminCount=1))'

```
-   Windows:
```powershell
# Example Using LDAPFilter
Get-ADObject -LDAPFilter '(&(objectCategory=user)(adminCount=1))'
```

#### List All administratively disabled accounts.:
-   Linux:
```bash
#LDAP Query
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'

```
-   Windows:
```powershell
Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
```
-   +Note+: Don't pipe into `| select samaccountname|` it didn't work for me, I think it may be due to the account being disabled, then maybe the sam account is disabled?


### List User Emails: {#list-user-emails}
-   Linux:
```bash
#LDAP Query
(&(objectClass=user)(mail=*@domain.com))

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 (&(objectClass=user)(mail=*@sugarape.local))
```

-   Windows:
```powershell
#LDAP Query
(&(objectClass=user)(mail=*@domain.com))

# Example Using LDAPFilter
Get-ADObject -LDAPFilter  (&(objectClass=user)(mail=*@sugarape.local))
```

### List Group Information: {#list-group-information}

#### List All Groups:
-   Linux:
```bash
#LDAP Query
(objectClass=group)

# Example Using LDAPSearch
ldapsearch -H ldap://monteverde.MEGABANK.LOCAL -x -b "DC=MEGABANK,DC=LOCAL" -s sub "(&(objectclass=group))" | grep sAMAccountName: | cut -f2 -d" "
```
-   Windows:
```powershell
#LDAP Query
(&(objectCategory=group))

# Example Using LDAPFilter
Get-ADObject -LDAPFilter '(&(objectCategory=group))' | select name | Measure-Object

```
-   +Note+: The example counts the number of groups too by piping into measure object.

#### List Group Membership of a specific user:
-   Linux:
```bash
#LDAP Query
(&(objectClass=group)(member=CN=John Doe,CN=Users,DC=domain,DC=com))

# Example Using LDAPSearch
ldapsearch -x -b "dc=domain,dc=com" -H ldap://10.129.95.210 '(&(objectClass=group)(member=CN=John Doe,CN=Users,DC=domain,DC=com))'
```
-   Windows:
```powershell
#LDAP Query
(&(objectClass=group)(member=CN=John Doe,CN=Users,DC=domain,DC=com)

# Example Using LDAPFilter
Get-ADObject -LDAPFilter '(&(objectClass=group)(member=CN=John Doe,CN=Users,DC=domain,DC=com)'
```
-   +Note+: Can't seem to get to work just yet

#### List Members of a Specific Group:
- Linux:
```bash
#LDAP Query
(&(objectCategory=Person)(sAMAccountName=*)(memberOf=CN=<GroupName>,OU=Groups,DC=[DCNAME],DC=[DCNAME]))

# Example Using LDAPSearch
ldapsearch -H ldap://monteverde.MEGABANK.LOCAL -x -b "DC=MEGABANK,DC=LOCAL" -s sub "(&(objectCategory=Person)(sAMAccountName=*)(memberOf=CN=Helpdesk,OU=Groups,DC=MEGABANK,DC=LOCAL))"
```
- Windows:
```powershell
#LDAP Query
(&(objectCategory=Person)(sAMAccountName=*)(memberOf=CN=<GroupName>,OU=Groups,DC=[DCNAME],DC=[DCNAME]))

# Example Using LDAPFilter
Get-ADObject -LDAPFilter "(&(objectCategory=Person)(sAMAccountName=*)(memberOf=CN=Helpdesk,OU=Groups,DC=MEGABANK,DC=LOCAL))"
```

 -   +Notes+:
        -   Signifies no-one is in this group:
            -   {{< figure src="/ox-hugo/2024-07-12-094154_.png" >}}
        -   Users are part of this group.
            -   {{< figure src="/ox-hugo/2024-07-12-094227_.png" >}}


### List Computers: {#list-computers}

- Linux:
```bash
#LDAP Query
(objectClass=computer)

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 '(objectClass=computer)'
```
- Windows:
```powershell
#LDAP Query
(objectClass=computer)

# Example Using LDAPFilter
Get-ADObject -LDAPFilter "(objectClass=computer)"
```


### List OU information: {#list-ou-information}
#### List All OU's:
- Linux:
```bash
#LDAP Query
(objectClass=OrganizationalUnit)

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 '(objectClass=OrganizationalUnit)'
```
- Windows:
```powershell
#LDAP Query
(objectClass=OrganizationalUnit)

# Example Using LDAPFilter
Get-ADObject -LDAPFilter "(objectClass=OrganizationalUnit)"
```
#### List Specific OU Information:
- Linux:
```bash
#LDAP Query
(ou=[OUName])

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 '(ou=Accounting)'
```
- Windows:
```powershell
#LDAP Query
(ou=[OUName])

# Example Using LDAPFilter
Get-ADObject -LDAPFilter "(ou=Accounting)"
```


### List Account Information: {#list-account-information}

#### List Active Accounts:

- Linux:
```bash
#LDAP Query
(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
ldapsearch -h 172.16.5.5 -x -b "DC=SUGARAPE,DC=LOCAL" -s sub "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" | grep "sugarape.local"
```
-  +Note+: Can pipe into grep as well once an email is discovered to pipe out valid usernames:

- Windows:
```powershell
#LDAP Query
(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Example Using LDAPFilter
Get-ADObject -LDAPFilter  "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
```


<!--listend-->

#### Account Expires in Specific Time Frame:
- Linux:
```bash
#LDAP Query
(&(objectClass=user)(accountExpires>=131342487000000000)(accountExpires<=131395327000000000))

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 "(&(objectClass=user)(accountExpires>=131342487000000000)(accountExpires<=131395327000000000))"
```

- Windows:
```powershell
#LDAP Query
(&(objectClass=user)(accountExpires>=131342487000000000)(accountExpires<=131395327000000000))

# Example Using LDAPFilter
Get-ADObject -LDAPFilter "(&(objectClass=user)(accountExpires>=131342487000000000)(accountExpires<=131395327000000000))"
```
#### List Disabled Accounts:
- Linux:
```bash
#LDAP Query
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
```

- Windows:
```powershell
#LDAP Query

(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))

# Example Using LDAPFilter
Get-ADObject -LDAPFilter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"

```



### Linux System Support: {#linux-system-support}

- Linux:
```bash
#LDAP Query
(&(objectClass=device)(osName=Linux*))

# Example Using LDAPSearch
ldapsearch -x -b "dc=sugarape,dc=local" -H ldap://10.129.95.210 "(&(objectClass=device)(osName=Linux*))"
```

- Windows:
```powershell
#LDAP Query
(&(objectClass=device)(osName=Linux*))

# Example Using LDAPFilter
Get-ADObject -LDAPFilter "(&(objectClass=device)(osName=Linux*))"

```


## SearchBase and SearchScope Parameters: {#searchbase-and-searchscope-parameters}


### The SearchBase parameter: {#the-searchbase-parameter}

-   This parameter specifies an Active Directory path to search under and allows us to begin searching for a user account in a specific OU:
-   It accepts an OU's AD Distinguished Name (DN)
    -   "`OU=Employees,DC=CONTOSO,DC=LOCAL`".


### The SearchScope parameter: {#the-searchscope-parameter}

-   "SearchScope" allows us to define how deep into the OU hierarchy we would like to search.
-   There are three levels of depth we can search when using this parameter:

-   **SearchScope Depth**:
    -   **Depth**: 0
        -   Name: Base
        -   Description: The object is specified as the SearchBase. For example, if we ask for all users in an OU defining a base scope, we get no results. If we specify a user or use Get-ADObject we get just that user or object returned.
    -   **Depth**: 1
        -   Name: OneLevel
        -   Description: Searches for objects in the container defined by the SearchBase but not in any sub-containers.
    -   **Depth**: 2
        -   Name: SubTree
        -   Description: Searches for objects contained by the SearchBase and all child containers, including their children, recursively all the way down the AD hierarchy.

    -   +Example Picture and searches+:
        -   {{< figure src="/ox-hugo/2024-10-16-112948_.png" >}}
        -   {{< figure src="/ox-hugo/2024-10-16-113049_.png" >}}
        -   In the above example with the `SearchBase` set to the AD Operational Unit (OU)  `OU=Employees,DC=SUGARAPE,DC=LOCAL` we can set the scope to the following. We are going to be querying for user, by passing these parameters to `Get-AdUser`:
            -   `Base/0`
                -   Would attempt to query the OU object (Employees) itself.
                -   Result: We would get 0 hits as there are no users directly in the base.
            -   `OneLevel/1`
                -   Would search within the Employees OU only.
                -   Result: We would get the user Amelia Matthews returned as she is sitting nested within it and the first/oneLevel
            -   `SubTree/2`
                -   Queries the Employees OU and all of the sub-OUs underneath it, such as Accounting, Contractors, etc. OUs under those OUs (child containers).
                -   Results: We would get all users nested within the sub-ou's, in this instance 970 users

-   **Passing SearchScope Depth as an argument**:
    -   We can use name or number &amp; they are both interpreted the same:
        -   +Example+: `SearchScope OneLevel`
        -   +Example+: `SearchScope 1`
        -   Both of these are valid and will work.

<!--listend-->

-   **Example Queries**:
```bash
Get-ADUser -SearchBase "OU=Employees,DC=CONTOSO,DC=LOCAL" -SearchScope OneLevel -Filter *
Get-ADUser -SearchBase "OU=IT,DC=CONTOSO,DC=LOCAL" -SearchScope 1 -Filter *
Get-ADUser -SearchBase "OU=Domain Admins,DC=CONTOSO,DC=LOCAL" -SearchScope 2 -Filter *
(Get-ADUser -SearchBase "OU=IT,DC=CONTOSO,DC=LOCAL" -SearchScope 2 -Filter *).count
```


## +Enumerating LDAP+ {#84265d}

-   +If we see LDAP on a server running and there is an application it may be being used for AUTH.+
    -   See [LDAP Injection:](#ldap-injection)

### LDAPire: Custom LDAP Enumeration Tool

LDAPire is my own custom-built Python-based tool for Active Directory reconnaissance and enumeration. It's designed to streamline the process of gathering essential AD information during penetration tests or security assessments.

**Key features**:

- Adaptive connection attempts (SSL and non-SSL)
- Flexible authentication (anonymous and authenticated)
- Comprehensive user and group enumeration
- Multiple output files for quick reference and detailed analysis
- Robust error handling and logging

**Usage**:
```bash
python3 pythonldap.py <DC_IP> [-u USERNAME] [-p PASSWORD]
#Example
python3 pythonldap.py 192.168.1.100 -u "DOMAIN\username"
python3 pythonldap.py 192.168.1.100 "FQDN/IP"
```

**Output files**:
- `usersLdap.txt`: List of user sAMAccountNames
- `usersLdap_detailed.txt`: Detailed user information
- `groupsLdap.txt`: List of group sAMAccountNames
- `groupsLdap_detailed.txt`: Detailed group information

For more information and to access the tool, visit the [LDAPire GitHub repository](https://github.com/bloodstiller/ldapire).
- [https://bloodstiller.com/tools/ldapire/](https://bloodstiller.com/tools/ldapire/)


### Establishing Naming context with `NMAP`: {#establishing-naming-context-with-nmap}

-   **Run Scan**:
    -   **Command**: `nmap --script ldap* -sV -A -Pn [IP] -p389,636 -oA IP-LDAP`
    -   **Location of scripts**:
        -   ls _usr/share/nmap/scripts_ | grep -i ldap
        -   `locate *nse | grep ldap`

<!--listend-->

-   +Example+ **of how I got the necessary information for the box monteverde below and I was able to enumerate using LDAP**:
    -   In the below output we can see from the first lines the domain and the ldap server.
        -   `rootDomainNamingContext: DC=MEGABANK,DC=LOCAL`
            -   DC name is MEGABANK.LOCAL
        -   `ldapServiceName: MEGABANK.LOCAL:monteverde$@MEGABANK.LOCAL`
            -   Ldap server name is monteverde.MEGABANK.LOCAL
        - Writeup here: https://bloodstiller.com/walkthroughs/monteverde-box/

<!--listend-->

```shell
<SNIP>
PORT    STATE SERVICE    VERSION
389/tcp open  ldap       Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL, Site: Default-First-Site-Name)
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=MEGABANK,DC=LOCAL
|       ldapServiceName: MEGABANK.LOCAL:monteverde$@MEGABANK.LOCAL
<SNIP>

```


### Enumerating LDAP using `ldapsearch`: {#enumerating-ldap-using-ldapsearch}


#### Enumerate LDAP naming context server name and domain name: {#enumerate-ldap-naming-context-server-name-and-domain-name-with}

-   +DO THIS FIRST!+ before anything else.
    -   We cannot do ldap queries without knowing the FQDN of the ldap server and the domain name e.g `"dc=sugarape,dc=local"`.


-   **Establish Naming Context**:
```bash
ldapsearch -H ldap://[IP] -x -s base namingcontexts
ldapsearch -H ldap://10.129.228.111 -x -s base namingcontexts
```


#### Check for anonymous bind using `ldapsearch`: {#check-for-anonymous-bind-using-ldapsearch}
```bash
ldapsearch -H ldap://[IP] -x -b "dc=[DOMAIN],dc=[DOMAIN]"
ldapsearch -H ldap://10.129.1.207 -x -b "dc=sugarape,dc=local"
```


#### Enumerate entire domain with `ldapsearch`: {#enumerate-entire-domain-with-ldapsearch}
```bash

ldapsearch -H ldap://[LDAPName] -x -b "DC=[DCName],DC=[DCNAME]"  >> ldapDump.txt
ldapsearch -H ldap://monteverde.MEGABANK.LOCAL -x -b "DC=MEGABANK,DC=LOCAL"  >> ldapDump.txt
```


### Enumerating LDAP using `windapsearch`: {#enumerating-ldap-using-windapsearch}

-   There are two different versions of windapsearch, in my testing it's actually better to use the GO version as it seems to work, there are some issues with the current python version with imports being outdated etc.
-   The syntax is different for the GO version in we have to specify the module with `-m` then the module name e.g. `users`
-   **We can enumerate via ldap with just a password too, alas the Support box**:
    -   +Example+:
        -   `ldapsearch -H ldap://$box -D ldap@[domain].[domain] -w '[Password]' -b "dc=[domain],dc=[domain]" "*"}`
        - https://bloodstiller.com/walkthroughs/support-box/ 


#### Check for anonymous bind using `windapsearch`: {#check-for-anonymous-bind-using-windapsearch}
```bash
python3 windapsearch.py --dc-ip [IP] -u "" --functionality
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" --functionality
```


#### Enumerate all users using `windapsearch`: {#enumerate-all-users-using-windapsearch}
```bash
python3 windapsearch.py --dc-ip [DC-IP] -u "" -U
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U
```


#### Enumerate all computers using `windapsearch`: {#enumerate-all-computers-using-windapsearch}
```bash
python3 windapsearch.py --dc-ip [DC-IP] -u "" -C
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C
```


#### Enumerate all groups using `windapsearch`: {#enumerate-all-groups-using-windapsearch}
```bash
python3 windapsearch.py --dc-ip [DC-IP] -u "" -G
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -G
```


### Scripts for Querying `LDAP`: {#scripts-for-querying-ldap}


#### From within a python console: {#from-within-a-python-console}

```python
from ldap3 import *

s = Server('[IP]',get_info = ALL)
c =  Connection(s, '', '')
c.bind()
## If it returns true we can run the next command it will return all LDAP information
s.info

```


#### Simple Python Script: {#simple-python-script}

```python
from ldap3 import *

srver = input("Enter IP of DC ")

s = Server(srver,get_info = ALL)
c =  Connection(s, '', '')

checkserver = c.bind()

if checkserver == True:
   print(s.info)
else:
    "Server does not allow LDAP Anonymous bind"

```


#### More advanced python script that allows passing username and passwords, also implements SSL: {#more-advanced-python-script-that-allows-passing-username-and-passwords-also-implements-ssl}

```python
from ldap3 import *
import re
import argparse
import logging
import getpass

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

# Setup logging
logging.basicConfig(filename='ldap_test.log', level=logging.INFO)

# Command-line argument parsing
parser = argparse.ArgumentParser(description="LDAP Anonymous Bind Test")
parser.add_argument('dc_ip', help="IP address of the Domain Controller")
parser.add_argument('-u', '--user', help="Username for authentication", default='')
parser.add_argument('-p', '--password', help="Password for authentication", default='')

args = parser.parse_args()

# Validate IP address
srver = args.dc_ip
if not is_valid_ip(srver):
    print("Invalid IP address format.")
    logging.error(f"Invalid IP address format: {srver}")
    exit(1)

# Handle secure password input
user = args.user
password = args.password
if not password and user:
    password = getpass.getpass("Enter password: ")

# Function to attempt LDAP connection
def attempt_connection(use_ssl):
    try:
        s = Server(srver, use_ssl=use_ssl, get_info=ALL)
        c = Connection(s, user, password)
        checkserver = c.bind()
        return s, c, checkserver
    except Exception as e:
        logging.error(f"Error connecting to the server with SSL={use_ssl}: {e}")
        return None, None, False

# Attempt to connect with SSL first
print(f"Attempting to connect to {srver} with SSL...")
logging.info(f"Attempting to connect to {srver} with SSL")
s, c, checkserver = attempt_connection(use_ssl=True)

# If SSL connection fails, retry without SSL
if not checkserver:
    print("Failed to connect with SSL. Retrying without SSL...")
    logging.warning("Failed to connect with SSL. Retrying without SSL...")
    s, c, checkserver = attempt_connection(use_ssl=False)

# Final status check
if checkserver:
    print("Connected successfully. Retrieving server information...")
    logging.info("Connected successfully")
    print(s.info)
else:
    print("Failed to connect: Server does not allow LDAP Anonymous bind or invalid credentials.")
    logging.error("Failed to connect: Server does not allow LDAP Anonymous bind or invalid credentials.")
```


#### Powershell Script to query `LDAP`: {#powershell-script-to-query-ldap}

```powershell
# Create a DirectoryEntry object for the LDAP path
$ldapPath = "LDAP://dc=sugarape,dc=local"
$directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)

# Create a DirectorySearcher object
$searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)

# Define the LDAP filter
$searcher.Filter = "(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))"

# Search in the entire subtree
$searcher.SearchScope = "Subtree"

# Find all matching entries
$results = $searcher.FindAll()

# Iterate through the results and display the properties
foreach ($result in $results) {
    $entry = $result.GetDirectoryEntry()
    $entry.Properties | foreach {
        Write-Output "$($_.PropertyName) = $($_.Value)"
    }
}
```


## +Attacking LDAP+ {#1d1373}

-   **Netexec/Crackmapexec**:
    -   Has alot of amazing modules we can use with LDAP:
    -   **Command**: crackmapexec ldap -L


### Password Spraying &amp; Bruteforcing LDAP: {#password-spraying-and-bruteforcing-ldap}


#### LDAP bruteforcing with hydra: {#ldap-bruteforcing-with-hydra}

-   **Command**: `hydra -l {Username} -P {Big_Passwordlist} {IP} ldap2 -V -f`


### LDAP Injection: {#ldap-injection}

-   LDAP injection attacks are similar to SQL Injection attacks but target the LDAP directory service instead of a database.
-   <https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html>
-   <https://book.hacktricks.xyz/pentesting-web/ldap-injection>
-   </ox-hugo/EN-Blackhat-Europe-2008-LDAP-Injection-Blind-LDAP-Injection.pdf>


-   **We can fuzz using burp**:
    -   Capture request and then use these lists to fuzz injection points:
        -   <https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_FUZZ.txt>
        -   <https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_attributes.txt>


#### Attack Explained. {#attack-explained-dot}

-   To test for LDAP injection, we can use input values that contain special characters or operators that can change the query's meaning:
    -   **Injection Characters**:
        -   `*`
            -   An asterisk \* can match any number of characters.
        -   `( )`
            -   Parentheses ( ) can group expressions.
        -   `|`
            -   A vertical bar | can perform logical OR.
        -   `&`
            -   An ampersand &amp; can perform logical AND.
        -   `(cn=*)`
            -   Input values that try to bypass authentication or authorisation checks by injecting conditions that always evaluate to true can be used. For example, `(cn=*)` or `(objectClass=*)` can be used as input values for a username or password fields.


#### Example of Vulnerable Code {#example-of-vulnerable-code}

```php

$username = $_POST['username'];
$password = $_POST['password'];
$filter = "(&(uid=$username)(userPassword=$password))";
$result = ldap_search($ldapconn, $basedn, $filter);

```

<!--list-separator-->

-  Example of Injection Attack

    :ID:       4826ee7c-d9a3-4bec-afc1-129c87b6f360

    An attacker could input `*)(uid=*))(|(uid=*` as the username, which would modify the LDAP filter to:

    ```shell
    (&(uid=*)(uid=*))(|(uid=*)(userPassword=password))
    ```

    This could potentially bypass authentication.


#### Real-world Example {#real-world-example}

-   For example, suppose an application uses the following `LDAP` query to authenticate users:
    -   `(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))`
        -   This is an actual piece of PHP code that would run.
    -   In this query, `$username` and `$password` contain the user's login credentials.
        -   An attacker could inject the `*` character into either field to modify the LDAP query and bypass authentication as it's not being sanitized.
        -   If injected into the `$username` field the LDAP query will match any user account with any password!!
        -   If injected into the `$password` field the LDAP query match any user account with any password that contains the injected string. This would allow the attacker to gain access to the application with any username
    -   +Lab Example+:
        -   {{< figure src="/ox-hugo/2024-03-14-182350_.png" >}}
        -   I injected the `*` char into the username and password fields and could login as the code was not being sanitized.


#### Prevention Techniques {#prevention-techniques}

1.  **Input Validation**: Sanitize and validate all user inputs before using them in LDAP queries.
2.  **Use Bind Operations**: Instead of constructing search filters with user input, use LDAP bind operations for authentication.
3.  **Escape Special Characters**: Use LDAP-specific escaping functions to neutralize special characters in user input.
4.  **Implement Least Privilege**: Ensure LDAP accounts have minimal necessary permissions.
5.  **Use Prepared Statements**: If available in your programming language, use LDAP prepared statements to separate queries from data.


#### Fix {#fix}

-   To mitigate the risks associated with LDAP injection attacks, it is crucial to thoroughly validate and sanitize user input before incorporating it into LDAP queries. This process should involve removing LDAP-specific special characters like \* and employing parameterised queries to ensure user input is treated solely as data, not executable code.


#### Additional Resources {#additional-resources}

-   OWASP LDAP Injection Prevention Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html>
-   LDAP Injection &amp; Blind LDAP Injection in Web Applications: <https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf>


## Troubleshooting LDAP {#troubleshooting-ldap}

Common LDAP issues and their solutions:

1.  Connection Failures
    -   Check network connectivity
    -   Verify LDAP server is running
    -   Ensure correct LDAP URL (ldap:// or ldaps://)
    -   Check firewall settings

2.  Authentication Issues
    -   Verify correct bind DN and password
    -   Check user account status (not locked or disabled)
    -   Ensure user has necessary permissions

3.  Search Problems
    -   Verify correct base DN
    -   Check search filter syntax
    -   Ensure attributes being searched exist in schema

4.  SSL/TLS Issues
    -   Verify SSL certificates are valid and trusted
    -   Check SSL/TLS configuration on both client and server

5.  Performance Problems
    -   Optimize search filters
    -   Use indexing on frequently searched attributes
    -   Consider implementing connection pooling

6.  Schema Violations
    -   Ensure all required attributes are provided
    -   Check attribute syntax and value constraints

7.  Replication Issues
    -   Check network connectivity between replicas
    -   Verify replication agreements are correctly configured
    -   Check for conflicting updates

Tools for LDAP Troubleshooting:

-   ldapsearch: Command-line tool for performing LDAP searches
-   Wireshark: Network protocol analyzer for inspecting LDAP traffic
-   Directory Server Log Analysis tools


## LDAP Security Best Practices {#ldap-security-best-practices}

1.  Use LDAPS (LDAP over SSL/TLS) to encrypt communications
2.  Implement strong authentication methods (e.g., SASL)
3.  Apply the principle of least privilege for LDAP accounts
4.  Regularly audit and update LDAP configurations
5.  Use input validation and parameterized queries to prevent LDAP injection
6.  Implement proper password policies
7.  Monitor LDAP logs for suspicious activities
8.  Keep LDAP software and related components up to date
9.  Use firewalls to restrict LDAP access to authorized hosts only
10. Implement account lockout policies to prevent brute-force attacks

11. **Fix**:
    -   To mitigate the risks associated with LDAP injection attacks, it is crucial to thoroughly validate and sanitize user input before incorporating it into LDAP queries. This process should involve removing LDAP-specific special characters like \* and employing parameterised queries to ensure user input is treated solely as data, not executable code.


## LDAP Boxes on HTB: {#ldap-boxes-on-htb}

-   **Easy**:
    -   Forest E
    -   Return E
    -   Support E
    -   Active E

-   **Medium**:
    -   Monteverde M
    -   YPuffy M
    -   Lightweight M
    -   Cascade M
    -   StreamIO M
    -   Intelligence M
    -   Outdated M
    -   Scrambled M
    -   Fuse M
    -   Resolute M

-   **Hard**:
    -   Blackfield H
    -   Travel H
    -   Pikaboo H

-   **Insane**:
    -   PivotAPI I
    -   Sekhmet I
    -   Rebound I
    -   Fulcrum I
    -   Absolute I
    -   Coder I
    -   Response I
    -   Sizzle I
    -   CTF I
    -   Multimaster I

-   **Endgames**:
    -   Odyssey

-   **Prolabs**:
    -   RastaLabs I
    -   Cybernetics A
    -   Dante I
    -   APTLabs A
    -   Zephyr I
