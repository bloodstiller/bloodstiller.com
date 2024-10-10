+++
tags = [".NET", "Deserialization", "Serialization"]
draft = false
title = "Understanding .NET Deserialization Exploits: A Deep Dive"
author = "bloodstiller"
date = 2024-10-10
+++

## Understanding `.NET` Deserialization Exploits: A Deep Dive: {#understanding-dot-net-deserialization-exploits-a-deep-dive}

-   `.NET` deserialization exploits have become a common technique; providing a pathway to remote code execution (RCE) on vulnerable systems. Tools like [ysoserial.net](https://github.com/pwntester/ysoserial.net) can generate malicious payloads, allowing attackers to exploit deserialization flaws in .NET applications. But how does this attack vector actually work, and why does it succeed?

In this post, we'll walk through the underlying mechanics, focusing on an example using `BinaryFormatter` with a simple `Student` class. We'll see how a seemingly innocuous application can be vulnerable to severe attacks.


### What is Serialization &amp; Deserialization? {#what-is-serialization-and-deserialization}


#### Serialization: {#serialization}

-   **Serialization is the process of turning objects from a program into a format that’s easy to send (over the network) or save**. Formats such as `XML` and `JSON` are commonly used for this purpose because they are human-readable compared to binary formats. Once serialized, these objects can be sent over the network or saved for later use.


#### Deserialization: {#deserialization}

-   Is the reverse process: converting the transmitted data (e.g., `JSON`) back into a usable object in memory.
-   For instance, consider a `.NET` application with a `Student` class. The code might look like this:

[Serializable]

```csharp
public class Student
{
    public int StudentIDNumber { get; set; }
    public DateTime Birthday { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
}
```

-   When serialized to `JSON` format, it would look like this:

<!--listend-->

```json
{
 "StudentIDNumber":1337,
 "Birthday":29062002,
 "FirstName":"Nathan",
 "LastName":"Barley"
}
```

-   When serialized using `BinaryFormatter`, it would create a binary representation of this object.


### Exploiting Deserialization Vulnerabilities: {#exploiting-deserialization-vulnerabilities}

Imagine an application that allows users to send serialized Student data, which the server converts back into usable objects using BinaryFormatter. If the deserialization process isn't secure, an attacker can modify the data to control what kind of object gets created. Let's explore how this can lead to a serious security vulnerability.


### BinaryFormatter Deserialization Attack: A Detailed Example: {#binaryformatter-deserialization-attack-a-detailed-example}

Let's walk through how an attacker could exploit a vulnerable application that expects to deserialize Student objects but uses `BinaryFormatter` unsafely.


#### Step 1: Understanding the Vulnerable Application: {#step-1-understanding-the-vulnerable-application}

The application might have a method to process student data:

```csharp
public class StudentProcessor
{
    public void ProcessStudentData(string base64Data)
    {
        byte[] binaryData = Convert.FromBase64String(base64Data);

        using (MemoryStream ms = new MemoryStream(binaryData))
        {
            BinaryFormatter formatter = new BinaryFormatter();
            object deserializedObject = formatter.Deserialize(ms);

            if (deserializedObject is Student student)
            {
                // Process the student data
                Console.WriteLine($"Processed student: {student.FirstName} {student.LastName}");
            }
        }
    }
}
```

-   +Note+: This code assumes it's always receiving a serialized `Student` object, which is a dangerous assumption.


#### Step 2: Crafting the Malicious Payload: {#step-2-crafting-the-malicious-payload}

Instead of sending a legitimate Student object, an attacker uses [ysoserial.net](https://github.com/pwntester/ysoserial.net) to create a malicious payload:

-   `ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "cmd /c calc.exe"`

This generates a base64-encoded payload that, when deserialized, will launch the Windows calculator instead of creating a Student object.


#### Step 3: Sending the Payload: {#step-3-sending-the-payload}

The attacker sends this payload to the application, perhaps through an API endpoint or a file upload feature that expects serialized student data.


#### Step 4: Unintended Deserialization: {#step-4-unintended-deserialization}

When the `ProcessStudentData` method runs, it blindly deserializes the input:

```csharp
object deserializedObject = formatter.Deserialize(ms);
```

Instead of creating a Student object, this line now creates and executes the attacker's payload, launching `calc.exe` on the server.


#### Step 5: Execution and Impact: {#step-5-execution-and-impact}

The calculator launches on the server, demonstrating arbitrary code execution. In a real attack, this could be a reverse shell or any other malicious command.


### How Does The Deserialization Attack Work? {#how-does-the-deserialization-attack-work}

When deserializing data, the application should ideally be constrained to deserialize into a predefined set of safe classes. However, in vulnerable systems, this restriction doesn’t exist. Deserialization libraries like `JSON.NET` will attempt to deserialize any class that the attacker specifies.

This is where tools like [ysoserial.net](https://github.com/pwntester/ysoserial.net) come in. They allow attackers to craft payloads that exploit known vulnerable classes and object types within `.NET`. The tool generates serialized objects designed to trigger behaviors (like executing commands) when they are deserialized.

For example, a crafted payload could exploit a method that runs upon deserialization, leveraging classes that allow arbitrary code execution. If a system blindly deserializes this payload without validation, it unwittingly runs the attacker's code.


### Why Does This Happen? {#why-does-this-happen}

The root cause of these exploits is a failure to properly validate or restrict what classes the deserialization process can instantiate. By allowing any arbitrary object to be deserialized, attackers can manipulate the data in a way that turns simple data handling into a serious security vulnerability.


### Understanding [Ysoserial.Net](https://github.com/pwntester/ysoserial.net) Payloads: {#understanding-ysoserial-dot-net-payloads}

Let's break down how [ysoserial.net](https://github.com/pwntester/ysoserial.net) generates a payload for a `BinaryFormatter` deserialization exploit, contrasting it with our `Student` class example:


#### Legitimate Student Object Serialization: {#legitimate-student-object-serialization}

A legitimate serialized Student object using `BinaryFormatter` might look like this in binary format:

```csharp
// Binary representation (simplified for illustration)
[SerializationHeaderRecord][ObjectTypeEnum:SystemObject][AssemblyId][ClassName:Student][MemberCount:4]
[MemberName:StudentIDNumber][PrimitiveTypeEnum:Int32][Value:1337]
[MemberName:Birthday][PrimitiveTypeEnum:DateTime][Value:29062002]
[MemberName:FirstName][PrimitiveTypeEnum:String][Value:Nathan]
[MemberName:LastName][PrimitiveTypeEnum:String][Value:Barley]

```

This representation includes type information and metadata that `BinaryFormatter` uses to reconstruct the object during deserialization.


#### Malicious Payload Generation: {#malicious-payload-generation}

Now, let's examine how [ysoserial.net](https://github.com/pwntester/ysoserial.net) crafts a malicious payload:

`ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "cmd /c calc.exe"`

This command generates a base64-encoded payload. When decoded, it might look something like this (simplified):

```csharp
// Binary representation (simplified for illustration)
[SerializedObjectWithTypeWindowsIdentity][4-byte-length][TypeInfo:WindowsIdentity][MethodToInvoke:Start][Arguments:"cmd.exe", "/c calc.exe"]
```


#### Breaking Down the Payload: {#breaking-down-the-payload}

1.  **Object Type**: Instead of `SerializedStudent`, the payload specifies a `WindowsIdentity` object.
2.  **Malicious Method**: It includes instructions to invoke the `Start` method, which can execute commands.
3.  **Command Arguments**: The payload includes the command to be executed (`calc.exe` in this case).


#### Exploitation Process: {#exploitation-process}

1.  The vulnerable `ProcessStudentData` method receives this payload instead of a legitimate Student object.
2.  When deserialized, instead of creating a Student instance, it creates a `WindowsIdentity` object.
3.  The deserialization process triggers the execution of the `Start` method with the provided arguments.
4.  As a result, `calc.exe` is launched on the server, demonstrating arbitrary code execution.

This example illustrates how an attacker can exploit the flexibility of `BinaryFormatter` to execute arbitrary code, even when the application expects a completely different type of object (in our case, a Student).


### Preventing Deserialization Exploits: {#preventing-deserialization-exploits}

To protect against these types of attacks, even when working with seemingly harmless classes like our Student example:

-   **Whitelist Classes**: Limit deserialization to specific, safe classes and types. For instance, only allow the Student class to be deserialized.
-   **Disable Automatic Deserialization**: Avoid deserialization of user-controlled data unless absolutely necessary. If you must deserialize, consider safer alternatives to BinaryFormatter.
-   **Use Secure Libraries**: Keep libraries updated, as security patches are often released to address deserialization flaws.
-   **Sanitize Inputs**: Always validate and sanitize any data being deserialized to ensure it conforms to expected formats.
-   **Implement Custom Serialization**: For classes like Student, consider implementing custom serialization methods that don't rely on potentially dangerous automatic deserialization.

By implementing these measures, you can significantly reduce the risk of deserialization attacks, even when working with simple data structures.


### Conclusion: {#conclusion}

Deserialization vulnerabilities, particularly those involving `BinaryFormatter`, pose a significant risk to `.NET` applications. As we've seen with our `Student` class example, even seemingly innocuous code can be exploited to execute arbitrary commands. By understanding these risks and implementing proper security measures, developers can create more robust and secure applications.

### Corrections: {#Corrections:}
- Please let me know if I have anything wrong, more than happy to make corrections. 
