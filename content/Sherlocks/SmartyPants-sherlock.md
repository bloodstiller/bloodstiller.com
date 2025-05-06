+++
tags = ["Windows", "sherlock", "EVTX", "forensics", "Windows Logs", "DFIR", "1149", "SmartScreen", "1102", "EvtxECmd", "Timeline Explorer", "Logs", "RDP"]
draft = false
title = "SmartyPants HTB Sherlock Challenge: Analyzing Windows RDP Compromise Through Event Logs and SmartScreen"
description = "A comprehensive forensic analysis of a Windows system compromise through RDP access. Learn how to analyze Windows Event Logs (EVTX), SmartScreen Debug logs, and use tools like EvtxECmd and Timeline Explorer to investigate unauthorized access, data exfiltration, and log tampering."
keywords = ["Windows forensics", "EVTX log analysis", "SmartScreen investigation", "RDP security logs", "Windows event logs", "DFIR investigation", "Windows security forensics", "Event ID 1149", "Event ID 1102", "Windows log analysis", "RDP compromise", "Windows incident response"]
author = "bloodstiller"
date = 2025-05-06
toc = true
bold = true
next = true
+++

## SmartyPants Hack The Box Sherlock Challenge Writeup: {#smartypants-hack-the-box-sherlock-challenge-writeup}

-   <https://app.hackthebox.com/sherlocks/SmartyPants>


## Challenge Information: {#challenge-information}

-   **Difficulty**: Very Easy
-   **Category**: DFIR
-   **Scenario**: Forela's CTO, Dutch, stores important files on a separate Windows system because the domain environment at Forela is frequently breached due to its exposure across various industries. On 24 January 2025, our worst fears were realised when an intruder accessed the fileserver, installed utilities to aid their actions, stole critical files, and then deleted them, rendering them unrecoverable. The team was immediately informed of the extortion attempt by the intruders, who are now demanding money. While our legal team addresses the situation, we must quickly perform triage to assess the incident's extent. Note from the manager: We enabled SmartScreen Debug Logs across all our machines for enhanced visibility a few days ago, following a security research recommendation. These logs can provide quick insights, so ensure they are utilised.
-   **Files Provided**:
    -   358 Windows Event Logs

+Important Note+: Only after completing this Sherlock purely with Event Viewer did I discover some very useful tools, [EvtxECmd](https://ericzimmerman.github.io/#!index.md) &amp; [Timeline Explorer](https://ericzimmerman.github.io/#!index.md), which would have made this easier. I would suggest using these tools, you can see how to set them in the end section [Side Quest: Using EvtxECmd.exe &amp; Timeline Explorer To Easily View Logs:](#side-quest-using-evtxecmd-dot-exe-and-timeline-explorer-to-easily-view-logs)


## Finding Initial Access Time: Windows Event ID 1149: {#finding-initial-access-time-windows-event-id-1149}

We are told that "The attacker logged in to the machine where Dutch saves critical files, via RDP on 24th January 2025. Please determine the timestamp of this login."

Which means we should filter for RDP login events. Looking at this post: <https://woshub.com/rdp-connection-logs-forensics-windows/> &amp; this post <https://frsecure.com/blog/rdp-connection-event-logs/> we can find the following information:

When there is a successful RDP logon to a computer this is logged as an 1149 event. (this is only true for OS's later than Windows 7, &amp; Windows Server 2012. All modern OS versions will log 1149 only if the username in the event was successfully authenticated. The event information also provides us the source IP of the connection which is useful.

We can see these events are logged in: "Microsoft -&gt; Windows -&gt; Terminal-Services-RemoteConnectionManager -&gt; Operational" which is the file "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"

If we open this in event viewer and filter by event ID we can see the 1149 event listed.

-   {{< figure src="/ox-hugo/2025-05-02-071916_.png" >}}

So we can see from the event the attackers logged into the computer "CTO-FILESVR" at 10:15:14 on 24/01/2025.


## Finding Tools Using Microsoft Windows Defender SmartScreen: {#finding-tools-using-microsoft-windows-defender-smartscreen}

We are told: "The attacker downloaded a few utilities that aided them for their sabotage and extortion operation. What was the first tool they downloaded and installed?""

Hack the box themselves have a great article about finding these IOC's.

-   <https://www.hackthebox.com/blog/smartscreen-logs-evidence-execution>

We can also look at Microsoft's official documentation:

-   <https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/>

We can view when specific tools were executed as events are stored in:

-   "Microsoft -&gt; Windows -&gt; SmartScreen -&gt; Debug"
-   `"Microsoft-Windows-SmartScreen%4Debug.evtx"`


### Side Quest: What is Microsoft Windows Defender SmartScreen? {#side-quest-what-is-microsoft-windows-defender-smartscreen}

Windows Defender SmartScreen is an endpoint security tool designed to protect users from malware, phishing sides and malicious downloads/programs. It writes to the logs in real time as events occur.


#### How Microsoft Windows Defender SmartScreen Works: {#how-microsoft-windows-defender-smartscreen-works}

Microsoft Defender SmartScreen works by determining if a downloaded app or app installer is malicious by:

-   Checking the downloaded files against known malicious software sites and unsafe. If a match is found, Microsoft Defender SmartScreen will show a warning to the user to tell them that the site/file may be malicious.
-   It will also check the file against well known and frequently downloaded files. If the file isn't on the list of well known files, Microsoft Defender SmartScreen will show a warning to the user cautioning them that the file could be malicious.

Microsoft Defender SmartScreen works by determining if a site is malicious by:

-   Checking the site and looking for indicators of suspicious behavior. If it determines the page could be suspicions, Microsoft Defender SmartScreen will show a caution warning to the user.
-   It will also check the site against dynamically generated list of known &amp; reported phishing sited and malicious software sites. If a match is found Microsoft Defender SmartScreen will show a caution warning to the user.


#### How to Activate Microsoft Windows Defender Smartscreen: {#how-to-activate-microsoft-windows-defender-smartscreen}

Just to make you aware this is disabled by default. It can be activated by running the below command:

```shell
wevtutil sl Microsoft-Windows-SmartScreen/Debug /e:true
```


#### Limitations of Microsoft Windows Defender Smartscreen: {#limitations-of-microsoft-windows-defender-smartscreen}

It only logs files accessed via the Windows GUI, e.g. from within the client or over RDP. Anything run or accessed via Powershell or CMD will not be recorded.


## Discovering What Tools The Attacker Executed Using Microsoft Windows Defender SmartScreen Logs: {#discovering-what-tools-the-attacker-executed-using-microsoft-windows-defender-smartscreen-logs}

Looking through the log we can see the following entry and can see that the tool WinRar was accessed from the `C:\Files` directory at `10:17:27`

-   {{< figure src="/ox-hugo/2025-05-02-080639_.png" >}}

Immediately after this event we see they executed the tool "[Everything.exe](https://www.voidtools.com/faq/)" which is a file search tool  in `C:\\Users\\Dutch\\Downloads\\Everything.exe` at `10:17:33`:

-   {{< figure src="/ox-hugo/2025-05-02-081816_.png" >}}


## Discovering What Files The Attacker Accessed: {#discovering-what-files-the-attacker-accessed}

There are also two more interesting entries here:

We can see the following `pdfs` were accessed:

The file `Ministry Of Defense Audit.pdf` located at  "C:\Users\Dutch\Documents\\2025- Board of directors Documents\Ministry Of Defense Audit.pdf" was accessed at 10:19:00

The file `2025-BUDGET-ALLOCATION-CONFIDENTIAL.pdf` located at "C:\Users\Dutch\Documents\\2025- Board of directors Documents\\2025-BUDGET-ALLOCATION-CONFIDENTIAL.pdf" was accessed at 10:19:19

{{< figure src="/ox-hugo/2025-05-04-065112_.png" >}}


## Discovering Cloud Tools Used By The Attacker Used to Exfiltrate Data: {#discovering-cloud-tools-used-by-the-attacker-used-to-exfiltrate-data}

Looking further we can see the file the file `MEGAsyncSetup64.exe` was run at 10:20:05, this is a setup file for the cloud sync tool [Mega](https://mega.io/).
![](/ox-hugo/2025-05-04-071256_.png)

We can see it was also launched from the start menu at 10:22:19 as there is entry for accessing the `MEGAsync.lnk` file.
![](/ox-hugo/2025-05-04-072052_.png)


## Inferring An Exfiltration Timeline: {#inferring-an-exfiltration-timeline}

We can see from the below screenshots that the attacker accessed `cmd.exe` at `10:20:35`, then `WinRAR.exe` at `10:21:05` &amp; then `MEGAsync` at `10:22:19`. Which would indicate the attacker moved files at 10:20:35, compressed them at `10:21:05` &amp; then exfiltrated them at `10:22:19`.
![](/ox-hugo/2025-05-04-072431_.png)
![](/ox-hugo/2025-05-04-072646_.png)


## Discovering the Attacker Destroyed Logs: Event 1102 Log Clear: {#discovering-the-attacker-destroyed-logs-event-1102-log-clear}

We can see at `10:26:40` the attacker installed the tool [File Shredder](https://www.fileshredder.org/) which was likely used to cover their tracks by destroying logs.
![](/ox-hugo/2025-05-04-073201_.png)

We can then see this tool was accessed at `10:27:09`
![](/ox-hugo/2025-05-04-073411_.png)

Looking online we can see the event for clearing an audit log is event `1102`

-   <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102>

We can see from the picture these logs are stored in the `Security` log.
![](/ox-hugo/2025-05-04-073815_.png)

If we load the `Security.evtx` we can filter for this log easily by doing the following:

-   Right-click Security, then click Filter Current Log&#x2026;
    -   In the "Event IDs" field, type:
        -   1102
    -   Click OK

{{< figure src="/ox-hugo/2025-05-06-081222_.png" >}}


## Side Quest: Using EvtxECmd.exe &amp; Timeline Explorer To Easily View Logs: {#side-quest-using-evtxecmd-dot-exe-and-timeline-explorer-to-easily-view-logs}

Only after completing this Sherlock did I discover the tools [EvtxECmd](https://github.com/EricZimmerman/evtx) &amp; [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) which would have made this ALOT easier. You can download pre-compiled binaries here: <https://ericzimmerman.github.io/#!index.md>

-   +Note+: Both of these tools are made by Eric Zimmerman and I would encourage you to support his work if you do end up using these tools. You can do that on his [github sponsor page](https://github.com/sponsors/EricZimmerman).


### Easily Export Logs Using EvtxECmd: {#easily-export-logs-using-evtxecmd}

The description of the tool EvtxECmd is:

> Event log (evtx) parser with standardized CSV, XML, and json output! Custom maps, locked file support, and more!

In English this means we can grab all of the exported `.evtx` files and then export them as CSV (can be opened in excel/libreoffice) or XML/JSON files.

Once you have downloaded the application you can do the export as follows. In this case I just poined it at the full directory of `.evtx` log files.

```powershell
.\EvtxECmd.exe -d "[LocationOfLogs]" --[OutputFormat] "[DestintationOfOutput]" --[OutpufFileType] [OutputFileName].[Type]

.\EvtxECmd.exe -d "Z:\SmartyPants\Logs (2)" --csv "Z:\SmartyPants\Logs (2)" --csvf exported.csv
```

{{< figure src="/ox-hugo/2025-05-04-080005_.png" >}}


### Easily View A Timeline of logs using Timeline Explorer: {#easily-view-a-timeline-of-logs-using-timeline-explorer}


## Lessons Learned: {#lessons-learned}


### What did I learn? {#what-did-i-learn}

1.  I learned alot about using event viewer as I have never really used it before for manually filtering logs etc.
2.  I also learned about EvtxECmd &amp; Timeline by Eric Zimmerman, which I am now adding to my arsenal of tools.


### What mistakes did I make? {#what-mistakes-did-i-make}

1.  I went a while manually searching for event 1102 Log Clear before manually just filtering the logs.


## Sign off: {#sign-off}

Remember, folks as always: with great power comes great responsibility. Use this knowledge wisely, and always stay on the right side of the law!

Until next time, hack the planet!

&#x2013; Bloodstiller

&#x2013; Get in touch bloodstiller at bloodstiller dot com
