# MCQ v2 — 100 both-wrong sample

n=100

## 1. mcq-2473  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: According to CWE-1256, which phase can introduce weaknesses by assuming no consequences to unbounded power and clock management?
- options: A) Architecture and Design | B) Implementation | C) Testing | D) Maintenance
- selected_evidence: [A#1|11432|0.444] referenced, or not, from this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with t || [B#1|10296|0.451] Source(s) Tag(s) http://packetstormsecurity.com/files/176574/PixieFail-Proof-Of-Concepts.html CVE, TianoCore.org Third Party Advisory VDB Entry http://www.openwall.com/lists/oss-se || [C#1|11438|0.454] Vulnerabilities CVE-2023-52469 Detail Modified This CVE record has been updated after NVD enrichment efforts were completed. Enrichment data supplied by the NVD may require amend

## 2. mcq-1278  effect=neutral_wrong
- gold=C  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1655", "application vetting", "cyber threat intelligence", "event logs", "file hashes", "network traffic analysis"], "technique_ids": ["T1655"], "cves": [], "actors": [], "relations": ["detection"], "platforms": ["network"]}
- question: Under the MITRE ATT&CK technique T1655 (Masquerading), what is an effective detection method for identifying suspicious applications?
- options: A) Application Vetting via Network Traffic Analysis | B) Application Vetting via Event Logs | C) Application Vetting via API Calls | D) Application Vetting via File Hashes
- selected_evidence: [A#1|1639|0.536] standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider cor || [B#1|3584|0.530] Tactic Type: Post-Adversary Device Access ⓘ Tactic: Defense Evasion ⓘ Platforms: Android, iOS ⓘ MTC ID: APP-14, APP-31 Version: 1.0 Created: 12 July 2023 Last Modified: 16 April 20 || [C#1|3584|0.541] Tactic Type: Post-Adversary Device Access ⓘ Tactic: Defense Evasion ⓘ Platforms: Android, iOS ⓘ MTC ID: APP-14, APP-31 Version: 1.0 Created: 12 July 2023 Last Modified: 16 April 20 

## 3. mcq-2250  effect=neutral_wrong
- gold=A  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["buffer overflow", "cyber threat intelligence", "middle attack", "padding oracle crypto attack"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which of the following is a related attack pattern for CWE-696?
- options: A) Padding Oracle Crypto Attack | B) SQL Injection | C) Buffer Overflow | D) Man-in-the-Middle Attack
- selected_evidence: [A#1|14698|0.499] attack mechanism Quick Info CVE Dictionary Entry: CVE-2019-5459 NVD Published Date: 07/30/2019 NVD Last Modified: 11/20/2024 Source: HackerOne || [B#1|12356|0.515] of the file src/main/java/com/xhb/pay/action/PayTempOrderAction.java. The manipulation leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed  || [C#1|10079|0.553] leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB || [D#1|19887|0.501] attack mechani

## 4. mcq-1442  effect=neutral_wrong
- gold=A  cb=B  rag=B
- abstain=True  contamination=none
- anchors={"entities": ["T1583.004", "cyber threat intelligence"], "technique_ids": ["T1583.004"], "cves": [], "actors": [], "relations": ["detection"], "platforms": []}
- question: What is a detection method mentioned for identifying servers provisioned by adversaries according to the technique T1583.004?
- options: A) Analyzing internet scan response content | B) Inspecting user account creations | C) Monitoring DNS requests | D) Reviewing system logs
- selected_evidence: [A#1|4833|0.653] be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Detection ID Data Source Data Compon || [B#1|4833|0.582] be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Detection ID Data Source Data Compon || [C#1|1557|0.605] for queried domain name system (DNS) registry data that may compromise third-party DNS servers that can be used during targeting. Much of this activity will take place outside the  

## 5. mcq-1795  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is a common consequence of CWE-280 as noted in the document?
- options: A) Leakage of sensitive information | B) Denial of Service | C) Alteration of execution logic | D) Privilege escalation
- selected_evidence: [A#1|18077|0.514] endorse the views expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Please  || [B#1|7462|0.516] CWE-ID CWE Name Source CWE-755 Improper Handling of Exceptional Conditions NIST CISA-ADP Known Affected Software Configurations Switch to CPE 2.2 CPEs loading, please wait. Denotes || [C#1|16660|0.540] CVE, GitHub, Inc. Third Party Advisory Weakness Enumeration CWE-ID CWE Name Source CWE-94 Improper Control of Generation of Code ('Code Injection') NIST CWE-74 Improper Neutraliza

## 6. mcq-1473  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T1586.002", "compromise accounts", "cyber threat intelligence", "email accounts", "email data", "factor authentication", "preventive controls", "regular patching"], "technique_ids": ["T1586.002"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: Considering MITRE ATT&CK technique T1586.002 (Compromise Accounts: Email Accounts), what is a potential mitigation challenges for this technique listed under Preventive Controls?
- options: A) Use of Multi-Factor Authentication (MFA) | B) Encryption of Email Data | C) Pre-compromise measures | D) Regular Patching
- selected_evidence: [A#1|3987|0.548] [24] Mitigations ID Mitigation Description M1036 Account Use Policies Set account lockout policies after a certain number of failed login attempts to prevent passwords from being g || [B#1|6096|0.543] Mitigation Description M1057 Data Loss Prevention Implement Data Loss Prevention (DLP) solutions to monitor, detect, and control the flow of sensitive information. DLP tools can be || [C#1|20438|0.515] can be blocked from execution via AppLocker . As an additional precaution, Rapid7 recommends blocking domains associated with all unapproved RMM solutions. A public GitHub repo con

## 7. mcq-1875  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: In the context of CAPEC-24, what is the primary goal of an attacker when causing filter failure through a buffer overflow?
- options: A) To execute arbitrary code | B) To cause the system to crash | C) To allow unfiltered input into the system | D) To modify logs incorrectly
- selected_evidence: [A#1|13782|0.490] Vulnerabilities CVE-2021-25511 Detail Modified This CVE record has been updated after NVD enrichment efforts were completed. Enrichment data supplied by the NVD may require amendme || [B#1|13782|0.488] Vulnerabilities CVE-2021-25511 Detail Modified This CVE record has been updated after NVD enrichment efforts were completed. Enrichment data supplied by the NVD may require amendme || [C#1|13782|0.496] Vulnerabilities CVE-2021-25511 Detail Modified This CVE record has been updated after NVD enrichment efforts were completed. Enrichment data supplied by the NVD may require amend

## 8. mcq-1831  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["buffer overflow", "cyber threat intelligence", "using doubled characters"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: CAPEC-245 is related to which attack involving CWE-85?
- options: A) SQL Injection using ORMs | B) Common API Misuse | C) XSS Using Doubled Characters | D) Heap-based Buffer Overflow
- selected_evidence: [A#1|8124|0.555] Issue Tracking, Third Party Advisory New CVE Received from MITRE 1/06/2024 12:15:09 AM Action Type Old Value New Value Added Description SQL Injection vulnerability in ABO.CMS v.5. || [B#1|8086|0.540] CWE NIST CWE-77 Added CPE Configuration AND OR *cpe:2.3:o:cisco:wap371_firmware:*:*:*:*:*:*:*:* OR cpe:2.3:h:cisco:wap371:-:*:*:*:*:*:*:* Changed Reference Type https://sec.cloudap || [C#1|9366|0.509] XSS vulnerability located at "/gui/terminal_tool.cgi" in the "data" parameter. Added CWE CERT.PL CWE-79 Added Reference CERT.PL https://cert.pl/en/posts/2024/01/CVE-2023-49253/ [No 

## 9. mcq-1133  effect=neutral_wrong
- gold=B  cb=D  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1646", "ahrat", "cyber threat intelligence", "exfiltration over", "flytrap"], "technique_ids": ["T1646"], "cves": [], "actors": [], "relations": ["software", "platform"], "platforms": []}
- question: Regarding the MITRE ATT&CK technique T1646 (Exfiltration Over C2 Channel) on the Enterprise platform, which malware was noted for exfiltrating cached data from infected devices?
- options: A) AhRat | B) BOULDSPY | C) Drinik | D) FlyTrap
- selected_evidence: [A#1|20419|0.586] of the MITRE ATT&CK framework. Tactic ID Name Description Resource Development T1584.004 Compromise Infrastructure: Server In both Outer Space and Juicy Mix campaigns, OilRig has c || [B#1|20419|0.585] of the MITRE ATT&CK framework. Tactic ID Name Description Resource Development T1584.004 Compromise Infrastructure: Server In both Outer Space and Juicy Mix campaigns, OilRig has c || [C#1|20419|0.580] of the MITRE ATT&CK framework. Tactic ID Name Description Resource Development T1584.004 Compromise Infrastructure: Server In both Outer Space and Juicy Mix campaigns, OilRig has

## 10. mcq-1101  effect=neutral_wrong
- gold=D  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation", "detection"], "platforms": ["network"]}
- question: Which mitigation approach is suggested for the abuse of standard application protocols according to MITRE ATT&CK?
- options: A) Detecting malicious proxies | B) Preventive controls for system features | C) Network-based behavioral analytics | D) Focus on detection at other stages of adversarial behavior
- selected_evidence: [A#1|4281|0.568] can be leveraged to either respond directly to infected machines or to Proxy traffic to an adversary-owned command and control server. [1] [2] [3] As traffic generated by these fun || [B#1|4313|0.547] Execution Prevention Consider using application control to prevent execution of binaries that are susceptible to abuse and not required for a given system or network. M1050 Exploit || [C#1|5824|0.539] Home Techniques ICS Standard Application Layer Protocol Standard Application Layer Protocol Adversaries may establish command and control capabilities over commonly used applicatio 

## 11. mcq-1744  effect=neutral_wrong
- gold=B  cb=D  rag=D
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence", "information disclosure", "technical impact", "unauthorized code execution"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the common consequence of CWE-1246 as described in the document?
- options: A) Escalation of Privileges | B) Technical Impact: DoS: Instability | C) Information Disclosure | D) Unauthorized Code Execution
- selected_evidence: [A#1|19527|0.505] CVE, GitHub, Inc. Third Party Advisory Weakness Enumeration CWE-ID CWE Name Source CWE-287 Improper Authentication GitHub, Inc. Known Affected Software Configurations Switch to CPE || [B#1|7462|0.499] CWE-ID CWE Name Source CWE-755 Improper Handling of Exceptional Conditions NIST CISA-ADP Known Affected Software Configurations Switch to CPE 2.2 CPEs loading, please wait. Denotes || [C#1|18077|0.495] endorse the views expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Please

## 12. mcq-439  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T1480.001", "cyber threat intelligence"], "technique_ids": ["T1480.001"], "cves": [], "actors": [], "relations": ["detection"], "platforms": ["network"]}
- question: How does monitoring command execution help detect MITRE ATT&CK technique T1480.001 implementations?
- options: A) By tracking changes to system configuration settings | B) By identifying command and script usage that gathers victim's physical location | C) By finding attempts to access hardware peripherals | D) By monitoring periodic network connections
- selected_evidence: [A#1|20579|0.544] 2022-02-23 Distribution website MITRE ATT&CK techniques This table was built using version 11 of the ATT&CK framework. Tactic ID Name Description Persistence T1398 Boot or Logon In || [B#1|20579|0.526] 2022-02-23 Distribution website MITRE ATT&CK techniques This table was built using version 11 of the ATT&CK framework. Tactic ID Name Description Persistence T1398 Boot or Logon In || [C#1|2179|0.552] downloads, or program restarts. M0944 Restrict Library Loading Restrict the use of untrusted or unknown libraries, such as remote or unknown DLLs. Detection ID Data Source Data Co

## 13. mcq-950  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "network intrusion prevention", "network segmentation", "user account management"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation", "software"], "platforms": ["network"]}
- question: What mitigation technique is recommended for identifying network traffic of adversary malware using mail protocols?
- options: A) M1030: Network Segmentation | B) M1046: Monitoring | C) M1031: Network Intrusion Prevention | D) M1024: User Account Management
- selected_evidence: [A#1|20196|0.587] Information Discovery [ T1082 ] cmd.exe /C netstat -nap tcp System Information Discovery [ T1082 ] cmd.exe /C whoami System Information Discovery [ T1082 ] Coverage Ways our custom || [B#1|20196|0.603] Information Discovery [ T1082 ] cmd.exe /C netstat -nap tcp System Information Discovery [ T1082 ] cmd.exe /C whoami System Information Discovery [ T1082 ] Coverage Ways our custom || [C#1|20196|0.603] Information Discovery [ T1082 ] cmd.exe /C netstat -nap tcp System Information Discovery [ T1082 ] cmd.exe /C whoami System Information Discovery [ T1082 ] Coverage Ways our cust

## 14. mcq-1227  effect=neutral_wrong
- gold=B  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1630.002", "carbonsteal", "cyber threat intelligence"], "technique_ids": ["T1630.002"], "cves": [], "actors": [], "relations": ["detection"], "platforms": []}
- question: In the context of MITRE ATT&CK’s T1630.002, which operation could CarbonSteal perform to evade detection?
- options: A) Prevent system updates | B) Delete call log entries | C) Delete infected applications’ update packages | D) Manipulate SMS messages
- selected_evidence: [A#1|1308|0.504] could be prevented from being reported. This type of modification can also prevent operators or devices from performing actions to keep the system in a safe state. If critical repo || [B#1|908|0.477] signaled with I/O An alarm bit set in a flag (and read) In ICS environments, the adversary may have to suppress or contend with multiple alarms and/or alarm propagation to achieve  || [C#1|485|0.496] The impact file deletion will have depends on the type of data as well as the goals and objectives of the adversary, but can include deleting update files to evade detection or del ||

## 15. mcq-957  effect=neutral_wrong
- gold=A  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T0864", "cyber threat intelligence", "transient cyber asset"], "technique_ids": ["T0864"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Adversaries may target which type of devices that are transient across ICS networks for initial access according to MITRE ATT&CK technique T0864 (Transient Cyber Asset)?
- options: A) Workstations | B) Mobile devices | C) Intranet servers | D) Firewalls
- selected_evidence: [A#1|3496|0.698] Home Techniques ICS Transient Cyber Asset Transient Cyber Asset Adversaries may target devices that are transient across ICS networks and external networks. Normally, transient ass || [B#1|3496|0.669] Home Techniques ICS Transient Cyber Asset Transient Cyber Asset Adversaries may target devices that are transient across ICS networks and external networks. Normally, transient ass || [C#1|3496|0.693] Home Techniques ICS Transient Cyber Asset Transient Cyber Asset Adversaries may target devices that are transient across ICS networks and external networks. Normally, transient ass 

## 16. mcq-1336  effect=neutral_wrong
- gold=D  cb=A  rag=A
- abstain=True  contamination=none
- anchors={"entities": ["T1635.001", "application developer guidance", "application vetting", "cyber threat intelligence", "use recent", "user guidance"], "technique_ids": ["T1635.001"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: For MITRE ATT&CK Technique T1635.001, which mitigation strategy explicitly involves a first-come-first-served principle?
- options: A) Application Developer Guidance | B) Application Vetting | C) User Guidance | D) Use Recent OS Version
- selected_evidence: [A#1|20438|0.467] can be blocked from execution via AppLocker . As an additional precaution, Rapid7 recommends blocking domains associated with all unapproved RMM solutions. A public GitHub repo con || [B#1|20438|0.463] can be blocked from execution via AppLocker . As an additional precaution, Rapid7 recommends blocking domains associated with all unapproved RMM solutions. A public GitHub repo con || [C#1|20438|0.454] can be blocked from execution via AppLocker . As an additional precaution, Rapid7 recommends blocking domains associated with all unapproved RMM solutions. A public GitHub repo c

## 17. mcq-1270  effect=neutral_wrong
- gold=B  cb=A  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "tiktok pro"], "technique_ids": [], "cves": [], "actors": [], "relations": ["software", "group"], "platforms": []}
- question: Which threat actor has used C2 commands that can move the malware in and out of the foreground, according to the MITRE ATT&CK documentation?
- options: A) Mandrake | B) Drinik | C) TERRACOTTA | D) Tiktok Pro
- selected_evidence: [A#1|20624|0.549] use the command @0133, though it can be found in fcd.dll. Figure 5: @0133 can be found in fcd.dll. Despite the numbering, the payload only supports 139 actions. In addition, some s || [B#1|20624|0.550] use the command @0133, though it can be found in fcd.dll. Figure 5: @0133 can be found in fcd.dll. Despite the numbering, the payload only supports 139 actions. In addition, some s || [C#1|20624|0.549] use the command @0133, though it can be found in fcd.dll. Figure 5: @0133 can be found in fcd.dll. Despite the numbering, the payload only supports 139 actions. In addition, some

## 18. mcq-1386  effect=neutral_wrong
- gold=A  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1631.001", "cyber threat intelligence", "process injection", "ptrace system calls"], "technique_ids": ["T1631.001"], "cves": [], "actors": [], "relations": [], "platforms": ["network"]}
- question: When investigating potential malicious activity leveraging MITRE ATT&CK technique T1631.001 (Process Injection: Ptrace System Calls), which situation would most likely indicate such an attack against a running process?
- options: A) The presence of PTRACE_CONT calls in system logs | B) Unexpected high CPU usage correlating with PTRACE_CONT calls | C) Unusual outbound network traffic from a process shortly after a PTRACED call | D) Sudden changes in memory allocation patterns without corresponding process behaviors
- selected_evidence: [A#1|5833|0.617] Home Techniques Mobile Process Injection Ptrace System Calls Process Injection: Ptrace System Calls Adversaries may inject malicious code into processes via ptrace (process trace)  || [B#1|5833|0.607] Home Techniques Mobile Process Injection Ptrace System Calls Process Injection: Ptrace System Calls Adversaries may inject malicious code into processes via ptrace (process trace)  || [C#1|5833|0.594] Home Techniques Mobile Process Injection Ptrace System Calls Process Injection: Ptrace System Calls Adversaries may inject malicious code into processes via ptrace (process trace)  

## 19. mcq-357  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "webproxyenabled"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": ["macos"]}
- question: Which file entry indicates an application does not use the quarantine flag under macOS?
- options: A) LSFileQuarantineEnabled set to false LSLaunchAtLoginEnabled set to true | B) LSFileQuarantineEnabled not set | C) automaticQuarantineEnabled unspecified | D) WebProxyEnabled unknown
- selected_evidence: [A#1|5037|0.728] Metadata Review false values under the LSFileQuarantineEnabled entry in an application's Info.plist file (required by every application). false under LSFileQuarantineEnabled indica || [B#1|5037|0.729] Metadata Review false values under the LSFileQuarantineEnabled entry in an application's Info.plist file (required by every application). false under LSFileQuarantineEnabled indica || [C#1|5037|0.708] Metadata Review false values under the LSFileQuarantineEnabled entry in an application's Info.plist file (required by every application). false under LSFileQuarantineEnabled indica 

## 20. mcq-1817  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "macos"], "technique_ids": [], "cves": [], "actors": [], "relations": ["platform"], "platforms": ["windows", "linux", "macos"]}
- question: What specific platform is explicitly mentioned as relevant to CWE-1386?
- options: A) Unix-based systems | B) Linux-based systems | C) Windows | D) MacOS
- selected_evidence: [A#1|14630|0.495] this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with the facts presented on the || [B#1|14630|0.484] this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with the facts presented on the || [C#1|14630|0.481] this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with the facts presented on t

## 21. mcq-1308  effect=neutral_wrong
- gold=B  cb=A  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1425", "T1426", "T1427", "T1428", "cyber threat intelligence", "system information discovery"], "technique_ids": ["T1425", "T1426", "T1427", "T1428"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What technique ID corresponds to System Information Discovery in the MITRE ATT&CK framework?
- options: A) T1425 | B) T1426 | C) T1427 | D) T1428
- selected_evidence: [A#1|20579|0.548] 2022-02-23 Distribution website MITRE ATT&CK techniques This table was built using version 11 of the ATT&CK framework. Tactic ID Name Description Persistence T1398 Boot or Logon In || [B#1|20579|0.542] 2022-02-23 Distribution website MITRE ATT&CK techniques This table was built using version 11 of the ATT&CK framework. Tactic ID Name Description Persistence T1398 Boot or Logon In || [C#1|20579|0.545] 2022-02-23 Distribution website MITRE ATT&CK techniques This table was built using version 11 of the ATT&CK framework. Tactic ID Name Description Persistence T1398 Boot or Logon 

## 22. mcq-1787  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the primary technical impact of CWE-1177 on a product?
- options: A) Reduce security posture | B) Reduce maintainability | C) Reduce performance | D) Reduce usability
- selected_evidence: [A#1|15202|0.520] purpose. NIST does not necessarily endorse the views expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may b || [B#1|6898|0.498] expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Please address comments a || [C#1|12507|0.495] from this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with the facts presented 

## 23. mcq-1272  effect=neutral_wrong
- gold=A  cb=C  rag=C
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence", "encrypt sensitive data", "restrict external storage usage", "secure storage directory", "use recent"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: Under the MITRE ATT&CK framework, which mitigation strategy is recommended to prevent file and directory discovery on mobile platforms?
- options: A) M1006 - Use Recent OS Version | B) M1007 - Restrict External Storage Usage | C) M1005 - Secure Storage Directory | D) M2004 - Encrypt Sensitive Data
- selected_evidence: [A#1|3826|0.571] Home Techniques Mobile File and Directory Discovery File and Directory Discovery Adversaries may enumerate files and directories or search in specific device locations for desired  || [B#1|3826|0.603] Home Techniques Mobile File and Directory Discovery File and Directory Discovery Adversaries may enumerate files and directories or search in specific device locations for desired  || [C#1|3826|0.595] Home Techniques Mobile File and Directory Discovery File and Directory Discovery Adversaries may enumerate files and directories or search in specific device locations for desired  

## 24. mcq-1399  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association", "software"], "platforms": []}
- question: Which of the following packers has been specifically mentioned as used by the malware Gustuff in the context of MITRE ATT&CK?
- options: A) UPX | B) Petite | C) FTT | D) MPRESS
- selected_evidence: [A#1|20419|0.532] of the MITRE ATT&CK framework. Tactic ID Name Description Resource Development T1584.004 Compromise Infrastructure: Server In both Outer Space and Juicy Mix campaigns, OilRig has c || [B#1|4788|0.527] but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses. ID: T1406.002 Sub-technique of: T1406 Tactic T || [C#1|4788|0.536] but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses. ID: T1406.002 Sub-technique of: T1406 Tactic T

## 25. mcq-476  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T1567.001", "based content", "code repository", "cyber threat intelligence", "exfiltration over web service", "restrict web"], "technique_ids": ["T1567.001"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": ["network"]}
- question: According to MITRE ATT&CK T1567.001 (Exfiltration Over Web Service: Exfiltration to Code Repository), which mitigation strategy can be employed to prevent unauthorized use of external services for data exfiltration?
- options: A) Implement multi-factor authentication | B) Isolate code repositories from sensitive data | C) Restrict Web-Based Content | D) Use network segmentation
- selected_evidence: [A#1|965|0.594] Capabilities ), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store  || [B#1|965|0.676] Capabilities ), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store  || [C#1|965|0.639] Capabilities ), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store  || 

## 26. mcq-189  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=True  contamination=none
- anchors={"entities": ["T1216.001", "behavior prevention", "cyber threat intelligence", "pubprn", "system script proxy execution", "updating windows defender", "using application control"], "technique_ids": ["T1216.001"], "cves": [], "actors": [], "relations": ["mitigation", "association"], "platforms": ["windows"]}
- question: Which of the following mitigations is associated with Behavior Prevention on Endpoint in relation to MITRE ATT&CK technique T1216.001 – System Script Proxy Execution: PubPrn?
- options: A) Using Application Control to block script execution | B) Updating Windows Defender application control policies to block older versions of PubPrn | C) Block all scripts via GPO | D) Whitelist approved scripts only
- selected_evidence: [A#1|2195|0.551] Home Techniques Enterprise System Script Proxy Execution System Script Proxy Execution Sub-techniques (2) ID Name T1216.001 PubPrn T1216.002 SyncAppvPublishingServer Adversaries ma || [B#1|3505|0.635] of: T1216 ⓘ Tactic: Defense Evasion ⓘ Platforms: Windows Contributors: Atul Nair, Qualys Version: 2.1 Created: 03 February 2020 Last Modified: 16 April 2025 Version Permalink Live  || [C#1|3505|0.553] of: T1216 ⓘ Tactic: Defense Evasion ⓘ Platforms: Windows Contributors: Atul Nair, Qualys Version: 2.1 Created: 03 February 2020 Last Modified: 16 April 2025 Version Permalink Live  

## 27. mcq-932  effect=neutral_wrong
- gold=B  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T0820", "application isolation", "cyber threat intelligence", "exploit protection", "threat intelligence program", "update software"], "technique_ids": ["T0820"], "cves": [], "actors": [], "relations": ["mitigation", "software"], "platforms": []}
- question: An adversary has successfully exploited a firmware RAM/ROM consistency check on a control device. According to T0820: Exploitation for Evasion, which of the following mitigations would be most relevant to prevent future exploits?
- options: A) Threat Intelligence Program | B) Application Isolation and Sandboxing | C) Exploit Protection | D) Update Software
- selected_evidence: [A#1|2032|0.705] Home Techniques ICS Exploitation for Evasion Exploitation for Evasion Adversaries may exploit a software vulnerability to take advantage of a programming error in a program, servic || [B#1|2032|0.689] Home Techniques ICS Exploitation for Evasion Exploitation for Evasion Adversaries may exploit a software vulnerability to take advantage of a programming error in a program, servic || [C#1|2032|0.674] Home Techniques ICS Exploitation for Evasion Exploitation for Evasion Adversaries may exploit a software vulnerability to take advantage of a programming error in a program, servic 

## 28. mcq-519  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T1133", "application log", "cyber threat intelligence", "external remote services", "logon session", "network traffic", "network traffic flow"], "technique_ids": ["T1133"], "cves": [], "actors": [], "relations": ["detection", "datasource"], "platforms": ["network"]}
- question: What data source should be monitored to detect follow-on activities when authentication to an exposed remote service is not required? (Technique ID: T1133, External Remote Services, Enterprise)
- options: A) Logon Session | B) Network Traffic | C) Application Log | D) Network Traffic Flow
- selected_evidence: [A#1|1214|0.598] Application Log Content When authentication is not required to access an exposed remote service, monitor for follow-on activities such as anomalous external use of the exposed API  || [B#1|1214|0.575] Application Log Content When authentication is not required to access an exposed remote service, monitor for follow-on activities such as anomalous external use of the exposed API  || [C#1|1214|0.615] Application Log Content When authentication is not required to access an exposed remote service, monitor for follow-on activities such as anomalous external use of the exposed API  

## 29. mcq-2061  effect=neutral_wrong
- gold=A  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: In the context of CWE-262, which phase is critical for implementing user password aging policies to mitigate the threat?
- options: A) Architecture and Design | B) Implementation | C) Testing | D) Operations
- selected_evidence: [A#1|3605|0.538] services. M1027 Password Policies Refer to NIST guidelines when creating password policies. [24] M1051 Update Software Upgrade management services to the latest supported and compa || [B#1|3605|0.538] services. M1027 Password Policies Refer to NIST guidelines when creating password policies. [24] M1051 Update Software Upgrade management services to the latest supported and compa || [C#1|3605|0.535] services. M1027 Password Policies Refer to NIST guidelines when creating password policies. [24] M1051 Update Software Upgrade management services to the latest supported and compa 

## 30. mcq-466  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T1567.004", "cyber threat intelligence"], "technique_ids": ["T1567.004"], "cves": [], "actors": [], "relations": ["platform"], "platforms": []}
- question: Which of the following commands could be indicative of an adversary attempting to create a new webhook configuration in a SaaS service? (Platform: Enterprise, ID: T1567.004)
- options: A) git fetch | B) devops webhook add | C) gh webhook forward | D) cl runtime config
- selected_evidence: [A#1|1676|0.570] IN ("add_webhook"), 8)| where risk_score >= 8| table _time, host, user, action, service_name, webhook_url, risk_score DS0017 Command Command Execution Monitor executed commands and || [B#1|1676|0.601] IN ("add_webhook"), 8)| where risk_score >= 8| table _time, host, user, action, service_name, webhook_url, risk_score DS0017 Command Command Execution Monitor executed commands and || [C#1|1676|0.603] IN ("add_webhook"), 8)| where risk_score >= 8| table _time, host, user, action, service_name, webhook_url, risk_score DS0017 Command Command Execution Monitor executed commands and 

## 31. mcq-1953  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence", "data structures", "environment manipulation", "insufficient logging"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which attack pattern is related to CWE-1233?
- options: A) CAPEC-77: Manipulation of Data Structures | B) CAPEC-302: Exploitation of Insufficient Logging and Monitoring | C) CAPEC-176: Configuration/Environment Manipulation | D) CAPEC-16: Abuse of Functionality
- selected_evidence: [A#1|14855|0.545] attack mechanism Quick Info CVE Dictionary Entry: CVE-2020-20691 NVD Published Date: 09/27/2021 NVD Last Modified: 11/21/2024 Source: MITRE || [B#1|7735|0.534] Added CWE NIST CWE-79 Added CWE NIST CWE-116 Added CPE Configuration OR *cpe:2.3:a:myeventon:eventon:*:*:*:*:*:wordpress:*:* versions up to (excluding) 2.2.7 *cpe:2.3:a:myeventon:e || [C#1|15363|0.526] attack mechanism Quick Info CVE Dictionary Entry: CVE-2021-32285 NVD Published Date: 09/20/2021 NVD Last Modified: 11/21/2024 Source: MITRE || [D#1|15363|0.556] attack mechanism Quick Info CVE Dictionary Entry: CVE-2021-

## 32. mcq-1907  effect=neutral_wrong
- gold=B  cb=D  rag=D
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence", "system configuration"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: In the context of CWE-201, which phase is specifically mentioned for ensuring that sensitive data specified in the requirements is verified to ensure it is either a calculated risk or mitigated?
- options: A) Requirements | B) Implementation | C) System Configuration | D) Architecture and Design
- selected_evidence: [A#1|15326|0.479] OR cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:* Changed Reference Type https://f-security.jp/v6/support/information/100193.html No Types Assigned https://f-security.jp/v6/support || [B#1|16851|0.489] Enumeration CWE-ID CWE Name Source CWE-829 Inclusion of Functionality from Untrusted Control Sphere NIST Known Affected Software Configurations Switch to CPE 2.2 CPEs loading, plea || [C#1|18748|0.500] CVE, Canonical Ltd. Patch Vendor Advisory https://security.netapp.com/advisory/ntap-20210716-0004/ CVE, Canonical Ltd. Third Party Advisory https://ubuntu.com/security/notices/US

## 33. mcq-953  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T0878", "alarm suppression", "band communications channel", "cyber threat intelligence", "network allowlists", "network segmentation", "static network configuration"], "technique_ids": ["T0878"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": ["network"]}
- question: What mitigation strategy involves restricting unnecessary network connections to combat MITRE ATT&CK Technique T0878 (Alarm Suppression)?
- options: A) Network Segmentation | B) Network Allowlists | C) Out-of-Band Communications Channel | D) Static Network Configuration
- selected_evidence: [A#1|910|0.578] simultaneous sessions they support. M0930 Network Segmentation Segment operational assets and their management devices based on their functional role within the process. Enabling m || [B#1|5448|0.580] Mitigations ID Mitigation Description M0802 Communication Authenticity Protocols used for control functions should provide authenticity through MAC functions or digital signatures. || [C#1|5659|0.553] of the network preventing them from issuing any controls. [8] Mitigations ID Mitigation Description M0953 Data Backup Take and store data backups from end user systems and critical |

## 34. mcq-1597  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "diamond model", "intrusion analysis"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the initial step in creating activity groups in the Diamond Model of Intrusion Analysis as described?
- options: A) Identifying adversary infrastructure | B) Conducting incident response | C) Cognitive clustering comparisons | D) Notifying law enforcement
- selected_evidence: [A#1|4804|0.469] and network discovery techniques normally occur throughout an operation as an adversary learns the environment, and also to an extent in normal network operations. Therefore discov || [B#1|14877|0.456] Analysis by NIST 12/02/2021 8:50:00 AM Action Type Old Value New Value Changed Reference Type http://packetstormsecurity.com/files/164423/Dahua-Authentication-Bypass.html No Types  || [C#1|4804|0.444] and network discovery techniques normally occur throughout an operation as an adversary learns the environment, and also to an extent in normal network operations. Therefore discov

## 35. mcq-598  effect=neutral_wrong
- gold=B  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1652", "cyber threat intelligence", "device driver discovery", "network traffic", "windows registry"], "technique_ids": ["T1652"], "cves": [], "actors": [], "relations": ["detection", "datasource"], "platforms": ["windows", "network"]}
- question: According to MITRE ATT&CK technique T1652 (Device Driver Discovery), which data source is recommended for detecting potentially malicious enumeration of device drivers through API calls?
- options: A) Command | B) Windows Registry | C) Network Traffic | D) Process
- selected_evidence: [A#1|4473|0.596] Home Techniques Enterprise Device Driver Discovery Device Driver Discovery Adversaries may attempt to enumerate local device drivers on a victim host. Information about device driv || [B#1|4476|0.648] Monitor processes ( lsmod , driverquery.exe , etc.) for events that may highlight potentially malicious attempts to enumerate device drivers. DS0024 Windows Registry Windows Regist || [C#1|4473|0.580] Home Techniques Enterprise Device Driver Discovery Device Driver Discovery Adversaries may attempt to enumerate local device drivers on a victim host. Information about device driv 

## 36. mcq-2126  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "resource consumption"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the primary impact of exploiting CWE-920 in mobile technologies?
- options: A) Unauthorized data access | B) Denial of Service (DoS): Resource Consumption | C) Privilege escalation | D) Code injection
- selected_evidence: [A#1|3537|0.514] Home Techniques Mobile Exploitation for Initial Access Exploitation for Initial Access Adversaries may exploit software vulnerabilities to gain initial access to a mobile device. T || [B#1|749|0.532] Home Techniques Mobile Network Denial of Service Network Denial of Service Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of t || [C#1|1800|0.515] Home Techniques Mobile Exploitation for Privilege Escalation Exploitation for Privilege Escalation Adversaries may exploit software vulnerabilities in order to elevate privileges.  |

## 37. mcq-631  effect=neutral_wrong
- gold=C  cb=A  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1584.004", "compromise infrastructure", "cyber threat intelligence", "indrik spider", "operation dream job", "sandworm team", "volt typhoon"], "technique_ids": ["T1584.004"], "cves": [], "actors": [], "relations": ["group"], "platforms": []}
- question: In the context of MITRE ATT&CK T1584.004 (Compromise Infrastructure: Server), which group is known for using compromised PRTG servers from other organizations for C2?
- options: A) Sandworm Team | B) Indrik Spider | C) Volt Typhoon | D) Operation Dream Job
- selected_evidence: [A#1|3511|0.604] web servers to use for C2. [9] C0022 Operation Dream Job For Operation Dream Job , Lazarus Group compromised servers to host their malicious tools. [10] [11] [12] C0013 Operation S || [B#1|3511|0.564] web servers to use for C2. [9] C0022 Operation Dream Job For Operation Dream Job , Lazarus Group compromised servers to host their malicious tools. [10] [11] [12] C0013 Operation S || [C#1|3511|0.579] web servers to use for C2. [9] C0022 Operation Dream Job For Operation Dream Job , Lazarus Group compromised servers to host their malicious tools. [10] [11] [12] C0013 Operation S 

## 38. mcq-1371  effect=neutral_wrong
- gold=B  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1636.003", "cyber threat intelligence", "flubot"], "technique_ids": ["T1636.003"], "cves": [], "actors": [], "relations": ["software"], "platforms": ["ios"]}
- question: Which malware is known to steal contacts from an infected device as part of MITRE ATT&CK technique T1636.003?
- options: A) Mandrake | B) FluBot | C) Exobot | D) Pegasus for iOS
- selected_evidence: [A#1|6086|0.546] East. Retrieved September 11, 2020. R. Unuchek. (2017, June 8). Dvmap: the first Android malware with code injection. Retrieved December 10, 2019. A. Kumar, K. Del Rosso, J. Albrec || [B#1|1245|0.570] McNeil . (2021, April 27). FluBot Android Malware Spreading Rapidly Through Europe, May Hit U.S. Soon. Retrieved February 28, 2023. Filip TRUȚĂ, Răzvan GOSA, Adrian Mihai GOZOB. (2 || [C#1|20581|0.556] Bahamut spyware can extract the contact list. T1636.004 Protected User Data: SMS Messages Bahamut spyware can extract SMS messages. Command and Control T1437.001 Application Layer 

## 39. mcq-1470  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T1586.003", "cloud accounts", "compromise accounts", "cyber threat intelligence"], "technique_ids": ["T1586.003"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: What mitigation strategy is identified for technique ID T1586.003 Compromise Accounts: Cloud Accounts in the provided text?
- options: A) A. Implement strong anti-virus solutions. | B) B. Use multi-factor authentication. | C) C. Pre-compromise (M1056) | D) D. Conduct regular employee training.
- selected_evidence: [A#1|1328|0.619] control. [6] Mitigations ID Mitigation Description M1056 Pre-compromise This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed  || [B#1|3937|0.614] Home Techniques Enterprise Compromise Accounts Compromise Accounts Sub-techniques (3) ID Name T1586.001 Social Media Accounts T1586.002 Email Accounts T1586.003 Cloud Accounts Adve || [C#1|1328|0.609] control. [6] Mitigations ID Mitigation Description M1056 Pre-compromise This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed  

## 40. mcq-206  effect=neutral_wrong
- gold=D  cb=C  rag=C
- abstain=True  contamination=none
- anchors={"entities": ["APT11", "APT12", "APT32", "APT41", "cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": ["APT11", "APT12", "APT32", "APT41"], "relations": [], "platforms": []}
- question: Which of the following groups used the command "net localgroup administrators" to enumerate administrative users?
- options: A) APT11 | B) APT12 | C) APT41 | D) APT32
- selected_evidence: [A#1|658|0.605] may enumerate members of Active Directory groups. [1] ID: T1087.002 Sub-technique of: T1087 ⓘ Tactic: Discovery ⓘ Platforms: Linux, Windows, macOS Contributors: ExtraHop; Miriam Wi || [B#1|658|0.601] may enumerate members of Active Directory groups. [1] ID: T1087.002 Sub-technique of: T1087 ⓘ Tactic: Discovery ⓘ Platforms: Linux, Windows, macOS Contributors: ExtraHop; Miriam Wi || [C#1|658|0.614] may enumerate members of Active Directory groups. [1] ID: T1087.002 Sub-technique of: T1087 ⓘ Tactic: Discovery ⓘ Platforms: Linux, Windows, macOS Contributors: ExtraHop; Miriam Wi || 

## 41. mcq-2141  effect=neutral_wrong
- gold=A  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is a primary cause for the inability to update or patch certain components in a product's architecture?
- options: A) Expense considerations | B) Requirements development oversight | C) Both technical complexity and cost are the primary concerns | D) Efforts to avoid redundancy in design
- selected_evidence: [A#1|2462|0.482] update/distribution mechanisms Compromised/infected system images (multiple cases of removable media infected at the factory) [1] [2] Replacement of legitimate software with modifi || [B#1|5348|0.467] from occurring. [103] Many of these protections depend on the architecture and target application binary for compatibility. M1051 Update Software Perform regular software updates t || [C#1|2462|0.472] update/distribution mechanisms Compromised/infected system images (multiple cases of removable media infected at the factory) [1] [2] Replacement of legitimate software with modifi 

## 42. mcq-1331  effect=neutral_wrong
- gold=A  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1409", "cyber threat intelligence", "fakespy"], "technique_ids": ["T1409"], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: Which malware is known to request the GET_ACCOUNTS permission to gather a list of accounts on the device as part of Technique ID T1409?
- options: A) Escobar | B) Exodus | C) Mandrake | D) FakeSpy
- selected_evidence: [A#1|5200|0.583] be used to enumerate local accounts. On ESXi servers, the esxcli system account list command can list local user accounts. [4] ID: T1087.001 Sub-technique of: T1087 ⓘ Tactic: Disco || [B#1|5091|0.581] or permissions in the targeted environment. For examples, cloud environments typically provide easily accessible interfaces to obtain user lists. [1] [2] On hosts, adversaries can  || [C#1|4326|0.568] Vetting Permissions Requests Application vetting services can detect and closely scrutinize applications that utilize Device Administrator access. DS0042 User Interface System Sett 

## 43. mcq-1232  effect=neutral_wrong
- gold=A  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1630.001", "application vetting", "cyber threat intelligence", "file monitoring", "system logging", "user interface"], "technique_ids": ["T1630.001"], "cves": [], "actors": [], "relations": ["detection", "datasource", "software"], "platforms": []}
- question: To detect misuse of the accessibility service for uninstalling malware as described in MITRE ATT&CK T1630.001, what data source should be monitored?
- options: A) Application Vetting | B) User Interface | C) System Logging | D) File Monitoring
- selected_evidence: [A#1|2379|0.610] Users should be taught how to boot into safe mode to uninstall malicious applications that may be interfering with the uninstallation process. Detection ID Data Source Data Compone || [B#1|2379|0.614] Users should be taught how to boot into safe mode to uninstall malicious applications that may be interfering with the uninstallation process. Detection ID Data Source Data Compone || [C#1|2379|0.598] Users should be taught how to boot into safe mode to uninstall malicious applications that may be interfering with the uninstallation process. Detection ID Data Source Data Compone 

## 44. mcq-13  effect=neutral_wrong
- gold=D  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["application log", "cyber threat intelligence", "system audit log", "user account authentication", "user account security log"], "technique_ids": [], "cves": [], "actors": [], "relations": ["detection", "datasource"], "platforms": []}
- question: Which specific data source should be monitored to detect failed authentication attempts that could indicate a brute force attack?
- options: A) Application Log | B) User Account Security Log | C) System Audit Log | D) User Account Authentication
- selected_evidence: [A#1|1214|0.591] Application Log Content When authentication is not required to access an exposed remote service, monitor for follow-on activities such as anomalous external use of the exposed API  || [B#1|654|0.577] on detecting other adversary behavior used to acquire credential materials, such as OS Credential Dumping or Kerberoasting . DS0002 User Account User Account Authentication Monitor || [C#1|654|0.590] on detecting other adversary behavior used to acquire credential materials, such as OS Credential Dumping or Kerberoasting . DS0002 User Account User Account Authentication Monitor ||

## 45. mcq-288  effect=neutral_wrong
- gold=D  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["datasource"], "platforms": []}
- question: Which data source ID would you use to monitor the execution and arguments of mshta.exe?
- options: A) DS0017 | B) DS0022 | C) DS0029 | D) DS0009
- selected_evidence: [A#1|976|0.659] potential misuse by adversaries. For example, in Windows 10 and Windows Server 2016 and above, Windows Defender Application Control (WDAC) policy rules may be applied to block the  || [B#1|976|0.656] potential misuse by adversaries. For example, in Windows 10 and Windows Server 2016 and above, Windows Defender Application Control (WDAC) policy rules may be applied to block the  || [C#1|976|0.656] potential misuse by adversaries. For example, in Windows 10 and Windows Server 2016 and above, Windows Defender Application Control (WDAC) policy rules may be applied to block the  || 

## 46. mcq-116  effect=neutral_wrong
- gold=D  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "during operation spalax"], "technique_ids": [], "cves": [], "actors": [], "relations": ["software", "group"], "platforms": []}
- question: During Operation Spalax, what technique did threat actors use to evade anti-analysis checks?
- options: A) Encrypting C2 communications | B) Just-in-time decryption of strings | C) Using WMI for persistence | D) Running anti-analysis checks before executing malware
- selected_evidence: [A#1|3386|0.524] 20, 2016. Sanmillan, I.. (2020, May 13). Ramsay: A cyber‑espionage toolkit tailored for air‑gapped networks. Retrieved May 27, 2020. Grunzweig, J. and Miller-Osborn, J.. (2016, Feb || [B#1|3386|0.529] 20, 2016. Sanmillan, I.. (2020, May 13). Ramsay: A cyber‑espionage toolkit tailored for air‑gapped networks. Retrieved May 27, 2020. Grunzweig, J. and Miller-Osborn, J.. (2016, Feb || [C#1|247|0.535] Something About WMI. Retrieved November 17, 2024. Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016. |

## 47. mcq-800  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "device authentication", "filter network traffic", "network allowlists", "network segmentation", "software process"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation", "software"], "platforms": ["network"]}
- question: Which mitigation technique involves using allow/denylists to block access based on excessive I/O connections?
- options: A) Network Allowlists | B) Network Segmentation | C) Filter Network Traffic | D) Software Process and Device Authentication
- selected_evidence: [A#1|1610|0.591] or reporting messages. Allow/denylist techniques need to be designed with sufficient accuracy to prevent the unintended blocking of valid reporting messages. M0807 Network Allowlis || [B#1|1610|0.604] or reporting messages. Allow/denylist techniques need to be designed with sufficient accuracy to prevent the unintended blocking of valid reporting messages. M0807 Network Allowlis || [C#1|1547|0.571] Interface (HMI) A0005 Intelligent Electronic Device (IED) A0012 Jump Host A0003 Programmable Logic Controller (PLC) A0004 Remote Terminal Unit (RTU) A0014 Routers A0010 Safety Cont 

## 48. mcq-2200  effect=neutral_wrong
- gold=B  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "data exfiltration", "information disclosure", "privilege escalation"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: What is the primary security concern associated with the CWE-924 weakness when an endpoint is spoofed?
- options: A) Denial of Service | B) Privilege Escalation | C) Data Exfiltration | D) Information Disclosure
- selected_evidence: [A#1|2166|0.516] . There are examples of adversaries remotely causing a Device Restart/Shutdown by exploiting a vulnerability that induces uncontrolled resource consumption. [2] [3] [4] ID: T0814 S || [B#1|1360|0.523] an endpoint system that has been properly configured and limits other privilege escalation methods. Adversaries may bring a signed vulnerable driver onto a compromised machine so t || [C#1|14750|0.504] Vulnerabilities CVE-2020-3492 Detail Modified This CVE record has been updated after NVD enrichment efforts were completed. Enrichment data supplied by the NVD may require amendmen

## 49. mcq-1433  effect=neutral_wrong
- gold=D  cb=B  rag=B
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["detection", "association", "software"], "platforms": ["network"]}
- question: Which detection strategy is suggested for identifying adversaries using web services as infrastructure according to MITRE ATT&CK?
- options: A) A. Monitor file hashes of downloads | B) B. Analyze network traffic for known C2 patterns | C) C. Investigate anomalies in DNS queries | D) D. Look for unique characteristics associated with adversary software in response content from internet scans
- selected_evidence: [A#1|6019|0.616] may be focused on related stages of the adversary lifecycle, such as during Command and Control. DS0035 Internet Scan Response Content Once adversaries have provisioned infrastruct || [B#1|6019|0.615] may be focused on related stages of the adversary lifecycle, such as during Command and Control. DS0035 Internet Scan Response Content Once adversaries have provisioned infrastruct || [C#1|4833|0.605] be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Detection ID Data Source Data Compon 

## 50. mcq-963  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: For the procedure example S1009 associated with Triton, what method does Triton use to achieve privilege escalation?
- options: A) Exploiting a buffer overflow in the Tricon MP3008 firmware | B) Achieving arbitrary code execution via a 0-day vulnerability | C) Leverage insecurely-written system calls for arbitrary writes | D) Bypassing standard user access controls
- selected_evidence: [A#1|925|0.611] Escalation ⓘ Platforms: None Version: 1.1 Created: 13 April 2021 Last Modified: 16 April 2025 Version Permalink Live Version Procedure Examples ID Name Description S1045 INCONTROLL || [B#1|2188|0.569] [4] S1009 Triton Triton leveraged the TriStation protocol to download programs onto Triconex Safety Instrumented System. [5] C0030 Triton Safety Instrumented System Attack In the T || [C#1|2188|0.586] [4] S1009 Triton Triton leveraged the TriStation protocol to download programs onto Triconex Safety Instrumented System. [5] C0030 Triton Safety Instrumented System Attack In the T |

## 51. mcq-2207  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "information disclosure", "privilege escalation", "resource consumption"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the main consequence of a successful CAPEC-25 attack?
- options: A) Information Disclosure | B) Availability | C) Resource Consumption | D) Privilege Escalation
- selected_evidence: [A#1|4628|0.479] Adversaries may also abuse external sharing features to share sensitive documents with recipients outside of the organization (i.e., Transfer Data to Cloud Account ). The following || [B#1|2489|0.448] exploitation of remote services is for lateral movement to enable access to a remote system. An adversary may need to determine if the remote system is in a vulnerable state, which || [C#1|6447|0.455] AC10U 15.03.06.49_multi_TDE01. It has been declared as critical. Affected by this vulnerability is the function fromDhcpListClient. The manipulation of the argument page/listN lead 

## 52. mcq-2049  effect=neutral_wrong
- gold=D  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "data breach", "memory corruption", "predictable exploitation", "quality degradation", "rampant exploits", "simple recovery", "technical impact", "unexpected state"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is a common consequence of CWE-544?
- options: A) Technical Impact: Data Breach; Unexpected State | B) Technical Impact: Rampant Exploits; Simple Recovery | C) Technical Impact: Memory Corruption; Predictable Exploitation | D) Technical Impact: Quality Degradation; Unexpected State
- selected_evidence: [A#1|10651|0.493] endorse the views expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Please  || [B#1|17665|0.507] views expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Please address comm || [C#1|18077|0.519] endorse the views expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Pleas

## 53. mcq-83  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T1204.002", "behavior prevention", "cyber threat intelligence", "execution prevention", "network segmentation", "user training"], "technique_ids": ["T1204.002"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": ["windows", "network"]}
- question: In the context of MITRE ATT&CK T1204.002, which mitigation strategy involves using specific rules on Windows 10 to prevent execution of potentially malicious executables?
- options: A) Execution Prevention | B) Behavior Prevention on Endpoint | C) User Training | D) Network Segmentation
- selected_evidence: [A#1|4313|0.574] Execution Prevention Consider using application control to prevent execution of binaries that are susceptible to abuse and not required for a given system or network. M1050 Exploit || [B#1|1729|0.576] to gather information. [181] Mitigations ID Mitigation Description M1040 Behavior Prevention on Endpoint On Windows 10, enable Attack Surface Reduction (ASR) rules to block process || [C#1|934|0.569] Ensure anti-virus solution can detect malicious files that allow user execution (e.g., Microsoft Office Macros, program installers). M0945 Code Signing Prevent the use of unsigned  |

## 54. mcq-94  effect=neutral_wrong
- gold=B  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1078.001", "cyber threat intelligence", "default accounts", "hyperstack", "magic hound", "valid accounts"], "technique_ids": ["T1078.001"], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: In the context of T1078.001 Valid Accounts: Default Accounts, which malware leveraged default credentials to connect to IPC$ shares on remote machines?
- options: A) Stuxnet | B) HyperStack | C) Mirai | D) Magic Hound
- selected_evidence: [A#1|1978|0.569] gathered earlier in the intrusion. [30] [31] C0024 SolarWinds Compromise During the SolarWinds Compromise , APT29 used domain administrators' accounts to help facilitate lateral mo || [B#1|1975|0.540] malware. [10] S0154 Cobalt Strike Cobalt Strike can use known credentials to run commands and spawn processes as a domain user account. [11] [12] [13] S1024 CreepySnail CreepySnail || [C#1|1975|0.544] malware. [10] S0154 Cobalt Strike Cobalt Strike can use known credentials to run commands and spawn processes as a domain user account. [11] [12] [13] S1024 CreepySnail CreepySnail 

## 55. mcq-1574  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=True  contamination=none
- anchors={"entities": ["T1110.003", "cyber threat intelligence"], "technique_ids": ["T1110.003"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which of the following ports is commonly targeted during password spraying attacks as per MITRE ATT&CK ID T1110.003?
- options: A) 25/TCP | B) 53/TCP | C) 80/TCP | D) 161/TCP
- selected_evidence: [A#1|3982|0.532] forcing a single account with many passwords. [1] Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the fo || [B#1|3982|0.527] forcing a single account with many passwords. [1] Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the fo || [C#1|3982|0.529] forcing a single account with many passwords. [1] Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the fo 

## 56. mcq-1081  effect=neutral_wrong
- gold=A  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1071", "application layer protocol", "cyber threat intelligence", "network intrusion prevention"], "technique_ids": ["T1071"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": ["network"]}
- question: Which of the following is a mitigation technique for T1071 - Application Layer Protocol?
- options: A) Network Intrusion Prevention (M1031) | B) Using HTTPS instead of HTTP | C) Perform DNS sinkholing | D) Only allowing traffic over known ports and protocols
- selected_evidence: [A#1|2225|0.597] or FTP). ID: T1048.001 Sub-technique of: T1048 ⓘ Tactic: Exfiltration ⓘ Platforms: ESXi, Linux, Windows, macOS Version: 1.1 Created: 15 March 2020 Last Modified: 15 April 2025 Vers || [B#1|3013|0.541] Home Techniques Mobile Application Layer Protocol Application Layer Protocol Sub-techniques (1) ID Name T1437.001 Web Protocols Adversaries may communicate using application layer  || [C#1|2903|0.551] Home Techniques Enterprise Application Layer Protocol DNS Application Layer Protocol: DNS Other sub-techniques of Application Layer Protocol (5) ID Name T1071.001 Web Protocols T10 

## 57. mcq-2218  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: Which mitigation strategy helps reduce the risk of CAPEC-74 exploitation?
- options: A) Storing user states exclusively in cookies | B) Encrypting all cookies | C) Handling all possible states in hardware finite state machines | D) Using plaintext storage for sensitive information
- selected_evidence: [A#1|4027|0.535] Configure browsers or tasks to regularly delete persistent cookies. Additionally, minimize the length of time a web cookie is viable to potentially reduce the impact of stolen cook || [B#1|4020|0.530] cookies in memory (e.g. apps which authenticate to cloud services). Session cookies can be used to bypasses some multi-factor authentication protocols. [1] There are several exampl || [C#1|1422|0.494] unsafe conditionals to go unchecked. Detection of a Loss of Safety by operators can result in the shutdown of a process due to strict policies regarding safety systems. This can ca 

## 58. mcq-1856  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence", "physical systems", "unauthorized access", "unauthorized data exfiltration"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which of the following is a common consequence of CWE-451?
- options: A) Unauthorized Data Exfiltration | B) Non-Repudiation | C) Denial of Service | D) Unauthorized Access to Physical Systems
- selected_evidence: [A#1|2944|0.500] Home Techniques Enterprise Automated Exfiltration Automated Exfiltration Sub-techniques (1) ID Name T1020.001 Traffic Duplication Adversaries may exfiltrate data, such as sensitive || [B#1|6784|0.442] Institute Third Party Advisory Weakness Enumeration CWE-ID CWE Name Source CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') NIST Spanish  || [C#1|749|0.475] Home Techniques Mobile Network Denial of Service Network Denial of Service Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of t |

## 59. mcq-615  effect=neutral_wrong
- gold=A  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["active directory", "adfind", "bloodhound", "cyber threat intelligence", "magic hound"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which procedure/example specifically mentions using both AdFind and the Nltest utility to enumerate Active Directory trusts?
- options: A) Akira | B) BloodHound | C) FIN8 | D) Magic Hound
- selected_evidence: [A#1|3017|0.734] call, .NET methods, and LDAP. [3] The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts. [4] ID: T1482 Sub-techniques: No sub-techniques ⓘ Tactic || [B#1|3017|0.699] call, .NET methods, and LDAP. [3] The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts. [4] ID: T1482 Sub-techniques: No sub-techniques ⓘ Tactic || [C#1|3017|0.720] call, .NET methods, and LDAP. [3] The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts. [4] ID: T1482 Sub-techniques: No sub-techniques ⓘ Tactic 

## 60. mcq-570  effect=neutral_wrong
- gold=A  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["APT28", "APT41", "T1030", "cyber threat intelligence", "data transfer size limits", "luminousmoth"], "technique_ids": ["T1030"], "cves": [], "actors": ["APT28", "APT41"], "relations": ["group"], "platforms": []}
- question: In the context of MITRE ATT&CK T1030 (Data Transfer Size Limits), which group's method emphasizes exfiltrating files in chunks smaller than 1MB?
- options: A) APT28 | B) APT41 | C) LuminousMoth | D) Carbanak
- selected_evidence: [A#1|952|0.596] Home Techniques Enterprise Data Transfer Size Limits Data Transfer Size Limits An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes be || [B#1|952|0.593] Home Techniques Enterprise Data Transfer Size Limits Data Transfer Size Limits An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes be || [C#1|954|0.556] C2 server. [8] S0487 Kessel Kessel can split the data to be exilftrated into chunks that will fit in subdomains of DNS queries. [9] S1020 Kevin Kevin can exfiltrate data to the C2  || 

## 61. mcq-2129  effect=neutral_wrong
- gold=A  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: Which phase is NOT associated with the introduction of CWE-1310?
- options: A) Test and Evaluation | B) Architecture and Design | C) Implementation | D) Manufacturing
- selected_evidence: [A#1|17484|0.508] Removed CWE Reason CWE-119 / More specific CWE option available Initial Analysis by NIST 5/21/2021 10:15:13 AM Action Type Old Value New Value Added CVSS V3.1 NIST AV:N/AC:L/PR:N/U || [B#1|17484|0.492] Removed CWE Reason CWE-119 / More specific CWE option available Initial Analysis by NIST 5/21/2021 10:15:13 AM Action Type Old Value New Value Added CVSS V3.1 NIST AV:N/AC:L/PR:N/U || [C#1|17484|0.502] Removed CWE Reason CWE-119 / More specific CWE option available Initial Analysis by NIST 5/21/2021 10:15:13 AM Action Type Old Value New Value Added CVSS V3.1 NIST AV:N/AC:L/PR:N

## 62. mcq-2453  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the main consequence of the CWE-164 weakness according to its description?
- options: A) It leads to data exfiltration. | B) It causes denial of service (DoS). | C) It compromises the integrity of the system, leading to unexpected states. | D) It results in privilege escalation.
- selected_evidence: [A#1|18882|0.496] Advisory Weakness Enumeration CWE-ID CWE Name Source CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') NIST Known Affected Software Config || [B#1|18882|0.490] Advisory Weakness Enumeration CWE-ID CWE Name Source CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') NIST Known Affected Software Config || [C#1|14771|0.501] Advisory Weakness Enumeration CWE-ID CWE Name Source CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') huntr.dev Known Affected So

## 63. mcq-2182  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["access control bypass", "authentication bypass", "cyber threat intelligence", "memory leak", "resource consumption"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is a likely impact of CWE-1322 on a system?
- options: A) DoS: Authentication Bypass | B) Access Control Bypass | C) DoS: Resource Consumption (CPU) | D) Memory Leak
- selected_evidence: [A#1|14875|0.556] Authentication Bypass Vulnerability 08/21/2024 09/11/2024 Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable. Weakness Enume || [B#1|14875|0.521] Authentication Bypass Vulnerability 08/21/2024 09/11/2024 Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable. Weakness Enume || [C#1|14760|0.513] CWE Name Source CWE-770 Allocation of Resources Without Limits or Throttling NIST Known Affected Software Configurations Switch to CPE 2.2 CPEs loading, please wait. Denotes Vuln

## 64. mcq-2413  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "data corruption", "data exfiltration", "privilege escalation"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the primary technical impact of CWE-1394, where the product uses a default cryptographic key for critical functionality?
- options: A) Data Exfiltration | B) Denial of Service (DoS) | C) Privilege Escalation | D) Data Corruption
- selected_evidence: [A#1|1919|0.517] [2] This can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. Like other Execution Guardrails , environmental || [B#1|1919|0.505] [2] This can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. Like other Execution Guardrails , environmental || [C#1|14875|0.501] Authentication Bypass Vulnerability 08/21/2024 09/11/2024 Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable. Weakness Enume

## 65. mcq-556  effect=neutral_wrong
- gold=C  cb=B  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "gamaredon group"], "technique_ids": [], "cves": [], "actors": [], "relations": ["group"], "platforms": []}
- question: What specific capability does the adversary group Gamaredon Group possess concerning removable media as described in the document?
- options: A) Collect data from connected MTP devices | B) Collect files from USB thumb drives | C) Steal data from newly connected logical volumes, including USB drives | D) Monitor removable drives and exfiltrate files matching a given extension list
- selected_evidence: [A#1|282|0.547] Crutch can monitor removable drives and exfiltrate files matching a given extension list. [9] S0569 Explosive Explosive can scan all .exe files located in the USB drive. [10] S0036 || [B#1|282|0.607] Crutch can monitor removable drives and exfiltrate files matching a given extension list. [9] S0569 Explosive Explosive can scan all .exe files located in the USB drive. [10] S0036 || [C#1|282|0.614] Crutch can monitor removable drives and exfiltrate files matching a given extension list. [9] S0569 Explosive Explosive can scan all .exe files located in the USB drive. [10] S0036 || 

## 66. mcq-114  effect=neutral_wrong
- gold=B  cb=D  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1497", "black basta", "cyber threat intelligence", "stonedrill"], "technique_ids": ["T1497"], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: Which of the following malware samples is known to perform system checks to determine if the environment is running on VMware, as part of the technique T1497?
- options: A) Bisonal | B) Black Basta | C) Carberp | D) StoneDrill
- selected_evidence: [A#1|5554|0.581] SVCReady has the ability to determine if its runtime environment is virtualized. [72] S0242 SynAck SynAck checks its directory location in an attempt to avoid launching in a sandbo || [B#1|5541|0.600] timing, and API's to detect code emulation or sandboxing. [8] [9] S1180 BlackByte Ransomware BlackByte Ransomware checks for files related to known sandboxes. [10] S0657 BLUELIGHT  || [C#1|5539|0.579] instructions. [2] In applications like VMWare, adversaries can also use a special I/O port to send commands and receive output. Hardware checks, such as the presence of the fan, te 

## 67. mcq-2315  effect=neutral_wrong
- gold=B  cb=C  rag=C
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence", "interface manipulation"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the typical likelihood and severity of an Interface Manipulation attack as described in CAPEC-113?
- options: A) High likelihood and low severity | B) Medium likelihood and medium severity | C) Low likelihood and high severity | D) High likelihood and high severity
- selected_evidence: [A#1|19887|0.513] attack mechanism Quick Info CVE Dictionary Entry: CVE-2021-39516 NVD Published Date: 09/20/2021 NVD Last Modified: 11/21/2024 Source: MITRE || [B#1|18873|0.487] must voluntarily interact with attack mechanism Quick Info CVE Dictionary Entry: CVE-2021-39556 NVD Published Date: 09/20/2021 NVD Last Modified: 11/21/2024 Source: MITRE || [C#1|19887|0.512] attack mechanism Quick Info CVE Dictionary Entry: CVE-2021-39516 NVD Published Date: 09/20/2021 NVD Last Modified: 11/21/2024 Source: MITRE || [D#1|19887|0.515] attack mechanism Quick Info CVE Dictionary Entry: CVE-2021-39516 NVD

## 68. mcq-864  effect=neutral_wrong
- gold=B  cb=C  rag=C
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence", "killdisk"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: Which MITRE ATT&CK technique is associated with the capability to stop services by logging in as a user?
- options: A) EKANS | B) Industroyer | C) KillDisk | D) REvil
- selected_evidence: [A#1|1296|0.558] Home Techniques ICS Service Stop Service Stop Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical servi || [B#1|1296|0.527] Home Techniques ICS Service Stop Service Stop Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical servi || [C#1|1297|0.557] EKANS Before encrypting the process, EKANS first kills the process if its name matches one of the processes defined on the kill-list. [2] [2] EKANS also utilizes netsh commands to  

## 69. mcq-258  effect=neutral_wrong
- gold=A  cb=C  rag=C
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: In the document, what mitigation ID involves preventing administrator accounts from being enumerated during elevation?
- options: A) M1028 | B) M1031 | C) M1026 | D) M1033
- selected_evidence: [A#1|668|0.636] M1028 Operating System Configuration Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of accoun || [B#1|668|0.627] M1028 Operating System Configuration Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of accoun || [C#1|668|0.634] M1028 Operating System Configuration Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of accoun || 

## 70. mcq-732  effect=neutral_wrong
- gold=B  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T0892", "cyber threat intelligence", "intelligent electronic device", "machine interface", "remote terminal unit", "safety controller"], "technique_ids": ["T0892"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which of the following targeted assets would be most impacted by the MITRE ATT&CK technique T0892 in an ICS environment?
- options: A) Human-Machine Interface (HMI) (A0002) | B) Remote Terminal Unit (RTU) (A0004) | C) Safety Controller (A0010) | D) Intelligent Electronic Device (IED) (A0005)
- selected_evidence: [A#1|5669|0.503] operators from getting reporting messages from a device. [4] Targeted Assets ID Asset A0007 Control Server A0009 Data Gateway A0013 Field I/O A0002 Human-Machine Interface (HMI) A0 || [B#1|5669|0.495] operators from getting reporting messages from a device. [4] Targeted Assets ID Asset A0007 Control Server A0009 Data Gateway A0013 Field I/O A0002 Human-Machine Interface (HMI) A0 || [C#1|1423|0.514] an unsafe state or hazard. [1] Mitigations ID Mitigation Description M0805 Mechanical Protection Layers Protection devices should have minimal digital components to prevent exposur 

## 71. mcq-240  effect=neutral_wrong
- gold=D  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: Which of the following malware examples triggers on a magic packet in TCP or UDP packets?
- options: A) BUSHWALK | B) Ryuk | C) SYNful Knock | D) Penquin
- selected_evidence: [A#1|522|0.522] for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs. On network devices, adver || [B#1|522|0.535] for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs. On network devices, adver || [C#1|521|0.556] predefined sequence of closed ports (i.e. Port Knocking ), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, openin || 

## 72. mcq-1756  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is a prerequisite for an attacker to successfully execute the attack described in CAPEC-166?
- options: A) The targeted application must have a mechanism for storing user credentials securely. | B) The targeted application must have a reset function that returns the configuration to an earlier state. | C) The attacker must have physical access to the server running the application. | D) The targeted application must be based on open-source code.
- selected_evidence: [A#1|2413|0.500] Home Techniques Enterprise Exploitation for Credential Access Exploitation for Credential Access Adversaries may exploit software vulnerabilities in an attempt to collect credentia || [B#1|9624|0.484] 1/08/2024 1:15:44 AM Action Type Old Value New Value Added Description A vulnerability was found in Totolink N200RE 9.3.5u.6139_B20201216. It has been declared as critical. Affecte || [C#1|269|0.505] the user again. [1] Adversaries may access restricted data or services protected by TCC through abusing applications previously granted permissions through Process Injection or exe |

## 73. mcq-161  effect=neutral_wrong
- gold=B  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": ["linux"]}
- question: Which of the following Linux commands can be used by adversaries to gather the current time on a Linux device?
- options: A) `gettimeofday()` | B) `time()` | C) `clock_gettime()` | D) `timespec_get()`
- selected_evidence: [A#1|3093|0.628] time or gathered by using w32tm /tz . [2] In addition, adversaries can discover device uptime through functions such as GetTickCount() to determine how long it has been since the s || [B#1|3093|0.638] time or gathered by using w32tm /tz . [2] In addition, adversaries can discover device uptime through functions such as GetTickCount() to determine how long it has been since the s || [C#1|3093|0.645] time or gathered by using w32tm /tz . [2] In addition, adversaries can discover device uptime through functions such as GetTickCount() to determine how long it has been since the s 

## 74. mcq-1730  effect=neutral_wrong
- gold=C  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": ["network"]}
- question: Steve works as an analyst in a UK-based firm. He was asked to perform network monitoring to find any evidence of compromise. During the network monitoring, he came to know that there are multiple logins from different locations in a short time span. Moreover, he also observed certain irregular log i
- options: A) Unusual outbound network traffic | B) Unexpected patching of systems | C) Unusual activity through privileged user account | D) Geographical anomalies
- selected_evidence: [A#1|3940|0.554] inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitou || [B#1|3432|0.542] Detection ID Data Source Data Component Detects DS0028 Logon Session Logon Session Creation Monitor for logon behavior that may abuse credentials of existing accounts as a means of || [C#1|3432|0.586] Detection ID Data Source Data Component Detects DS0028 Logon Session Logon Session Creation Monitor for logon behavior that may abuse credentials of existing accounts as a means of 

## 75. mcq-2028  effect=neutral_wrong
- gold=D  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: In the context of CWE-1025, what is the recommended phase to focus on to mitigate this weakness effectively?
- options: A) Design | B) Implementation | C) Deployment | D) Testing
- selected_evidence: [A#1|12507|0.492] from this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with the facts presented o || [B#1|10925|0.508] CVE, kernel.org Patch https://git.kernel.org/stable/c/3cd1d92ee1dbf3e8f988767eb75f26207397792b CVE, kernel.org Patch https://git.kernel.org/stable/c/475426ad1ae0bfdfd8f160ed9750903 || [C#1|12507|0.496] from this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with the facts presented

## 76. mcq-1340  effect=neutral_wrong
- gold=B  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1635", "application developer guidance", "cyber threat intelligence", "use recent", "user guidance"], "technique_ids": ["T1635"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: What should developers use to prevent malicious applications from intercepting redirections, according to the mitigation strategies for technique T1635?
- options: A) Use Recent OS Version | B) Application Developer Guidance | C) User Guidance | D) Mandating explicit intents
- selected_evidence: [A#1|4281|0.557] can be leveraged to either respond directly to infected machines or to Proxy traffic to an adversary-owned command and control server. [1] [2] [3] As traffic generated by these fun || [B#1|4281|0.551] can be leveraged to either respond directly to infected machines or to Proxy traffic to an adversary-owned command and control server. [1] [2] [3] As traffic generated by these fun || [C#1|4281|0.565] can be leveraged to either respond directly to infected machines or to Proxy traffic to an adversary-owned command and control server. [1] [2] [3] As traffic generated by these fun 

## 77. mcq-401  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=True  contamination=none
- anchors={"entities": ["T1057.003", "T1112.004", "T1546.006", "T1546.010", "appinit", "cyber threat intelligence", "event triggered execution"], "technique_ids": ["T1057.003", "T1112.004", "T1546.006", "T1546.010"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which technique ID corresponds to Event Triggered Execution: AppInit DLLs in the MITRE ATT&CK framework?
- options: A) T1546.006 | B) T1546.010 | C) T1057.003 | D) T1112.004
- selected_evidence: [A#1|3377|0.548] Home Techniques Enterprise Event Triggered Execution AppInit DLLs Event Triggered Execution: AppInit DLLs Other sub-techniques of Event Triggered Execution (17) ID Name T1546.001 C || [B#1|3377|0.549] Home Techniques Enterprise Event Triggered Execution AppInit DLLs Event Triggered Execution: AppInit DLLs Other sub-techniques of Event Triggered Execution (17) ID Name T1546.001 C || [C#1|3377|0.541] Home Techniques Enterprise Event Triggered Execution AppInit DLLs Event Triggered Execution: AppInit DLLs Other sub-techniques of Event Triggered Execution (17) ID Name T1546.001 C 

## 78. mcq-2420  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: According to the example instances provided in CAPEC-24, what is one possible consequence of leveraging a buffer overflow to make a filter fail in a web application?
- options: A) Executing unauthorized commands | B) Destroying log files | C) Bypassing authentication mechanisms | D) Accessing confidential files
- selected_evidence: [A#1|6518|0.474] Operations within the Bounds of a Memory Buffer NIST CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') HYPR Corp Known Affected Software Configurations || [B#1|9500|0.460] Vulnerabilities CVE-2024-20819 Detail Modified This CVE record has been updated after NVD enrichment efforts were completed. Enrichment data supplied by the NVD may require amendme || [C#1|11838|0.475] A specially crafted HTTP request can lead to captcha bypass, which can be abused by an attacker to brute force user credentials. An attacker can send a series of HTTP requests to t

## 79. mcq-2080  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the primary goal of CAPEC-48 attacks?
- options: A) Stealing financial data from users through phishing | B) Executing remote code through malicious URLs | C) Accessing local files and sending them to attacker-controlled sites | D) Exploiting SQL injection vulnerabilities
- selected_evidence: [A#1|3938|0.528] gathering credentials via Phishing for Information , purchasing credentials from third-party sites, brute forcing credentials (ex: password reuse from breach credential dumps), or  || [B#1|3504|0.542] malicious payloads hosted on remote sites. [2] To do so, adversaries may set the second script: parameter to reference a scriptlet file (.sct) hosted on a remote site. An example c || [C#1|5502|0.489] Home Techniques Mobile Exploitation for Client Execution Exploitation for Client Execution Adversaries may exploit software vulnerabilities in client applications to execute code.  

## 80. mcq-1164  effect=neutral_wrong
- gold=A  cb=C  rag=C
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: What encryption algorithm is used by PROMETHIUM during C0033 for C2 communication?
- options: A) AES | B) Blowfish | C) RC4 | D) Curve25519
- selected_evidence: [A#1|1055|0.534] Command and Control ⓘ Platforms: Android, iOS Version: 1.0 Created: 05 April 2022 Last Modified: 16 April 2025 Version Permalink Live Version Procedure Examples ID Name Description || [B#1|3682|0.557] model, version and serial number, telephone number, and IP address. [1] S1095 AhRat AhRat can exfiltrate collected data to the C2, such as audio recordings and files. [2] S1215 Bin || [C#1|1055|0.524] Command and Control ⓘ Platforms: Android, iOS Version: 1.0 Created: 05 April 2022 Last Modified: 16 April 2025 Version Permalink Live Version Procedure Examples ID Name Description 

## 81. mcq-605  effect=neutral_wrong
- gold=C  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "ninjacopy", "scattered spider"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association", "group"], "platforms": []}
- question: Which of the following utilities is used by the Scattered Spider group for creating volume shadow copies of virtual domain controller disks?
- options: A) vssadmin | B) wbadmin | C) esentutl | D) NinjaCopy
- selected_evidence: [A#1|3677|0.537] [3] ID: T1006 Sub-techniques: No sub-techniques ⓘ Tactic: Defense Evasion ⓘ Platforms: Network Devices, Windows Contributors: Tom Simpson, CrowdStrike Falcon OverWatch Version: 2.3 || [B#1|3677|0.539] [3] ID: T1006 Sub-techniques: No sub-techniques ⓘ Tactic: Defense Evasion ⓘ Platforms: Network Devices, Windows Contributors: Tom Simpson, CrowdStrike Falcon OverWatch Version: 2.3 || [C#1|3677|0.529] [3] ID: T1006 Sub-techniques: No sub-techniques ⓘ Tactic: Defense Evasion ⓘ Platforms: Network Devices, Windows Contributors: Tom Simpson, CrowdStrike Falcon OverWatch Version: 2.3 

## 82. mcq-924  effect=neutral_wrong
- gold=D  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T0800", "activate firmware update mode", "cyber threat intelligence", "machine interface", "programmable logic controller", "protection relay", "remote terminal unit"], "technique_ids": ["T0800"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which targeted asset could be most affected by entering and leaving the firmware update mode as described under 'Activate Firmware Update Mode' (T0800)?
- options: A) Human-Machine Interface (HMI) | B) Remote Terminal Unit (RTU) | C) Programmable Logic Controller (PLC) | D) Protection Relay
- selected_evidence: [A#1|1848|0.564] Home Techniques ICS Activate Firmware Update Mode Activate Firmware Update Mode Adversaries may activate firmware update mode on devices to prevent expected response functions from || [B#1|1848|0.558] Home Techniques ICS Activate Firmware Update Mode Activate Firmware Update Mode Adversaries may activate firmware update mode on devices to prevent expected response functions from || [C#1|3523|0.557] output is written to, sequence C intercepts the output and ensures it is not written to the process image output. The output is the instructions the PLC sends to a device to change 

## 83. mcq-1736  effect=neutral_wrong
- gold=A  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Mr. Bob, a threat analyst, is performing analysis of competing hypotheses (ACH). He has reached to a stage where he is required to apply his analysis skills effectively to reject as many hypotheses and select the best hypotheses from the identified bunch of hypotheses, and this is done with the help
- options: A) Diagnostics | B) Evidence | C) Inconsistency | D) Refinement
- selected_evidence: [A#1|2091|0.433] September 17). Indicators of Compromise Associated with Rana Intelligence Computing, also known as Advanced Persistent Threat 39, Chafer, Cadelspy, Remexi, and ITG07. Retrieved Dec || [B#1|4620|0.435] Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016. || [C#1|4620|0.436] Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016. || [D#1|2091|0.431] September 17). Indicators of Compromise Associated with Rana Intelligence Computing, also known 

## 84. mcq-1414  effect=neutral_wrong
- gold=B  cb=C  rag=C
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: In the context of MITRE ATT&CK and mobile platforms, which of the following malware families has used native code to disguise its malicious functionality?
- options: A) Asacub | B) Bread | C) TERRACOTTA | D) CHEMISTGAMES
- selected_evidence: [A#1|275|0.591] choose to use native functions to execute malicious code since native actions are typically much more difficult to analyze than standard, non-native behaviors. [2] ID: T1575 Sub-te || [B#1|275|0.559] choose to use native functions to execute malicious code since native actions are typically much more difficult to analyze than standard, non-native behaviors. [2] ID: T1575 Sub-te || [C#1|275|0.548] choose to use native functions to execute malicious code since native actions are typically much more difficult to analyze than standard, non-native behaviors. [2] ID: T1575 Sub-te || 

## 85. mcq-2155  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "data authenticity", "immutable data", "insufficient verification", "side enforcement", "side security", "web posting"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: Which of the following CWE weaknesses is NOT associated with CAPEC-386?
- options: A) Modification of Assumed-Immutable Data (CWE-471) | B) Client-Side Enforcement of Server-Side Security (CWE-602) | C) Manipulation of Web Posting (CWE-434) | D) Insufficient Verification of Data Authenticity (CWE-345)
- selected_evidence: [A#1|18882|0.520] Advisory Weakness Enumeration CWE-ID CWE Name Source CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') NIST Known Affected Software Config || [B#1|19891|0.525] Advisory Weakness Enumeration CWE-ID CWE Name Source CWE-502 Deserialization of Untrusted Data NIST Known Affected Software Configurations Switch to CPE 2.2 CPEs loading, please wa || [C#1|17568|0.533] not necessarily endorse the views expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on th

## 86. mcq-1546  effect=neutral_wrong
- gold=A  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "getbucketacl", "list blobs", "listobjectsv2", "listpolicies"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which API call could adversaries use to enumerate AWS storage services?
- options: A) List Blobs | B) ListObjectsV2 | C) GetBucketACL | D) ListPolicies
- selected_evidence: [A#1|467|0.630] Home Techniques Enterprise Cloud Storage Object Discovery Cloud Storage Object Discovery Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this || [B#1|467|0.618] Home Techniques Enterprise Cloud Storage Object Discovery Cloud Storage Object Discovery Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this || [C#1|2870|0.567] Home Techniques Enterprise Cloud Infrastructure Discovery Cloud Infrastructure Discovery An adversary may attempt to discover infrastructure and resources that are available within ||

## 87. mcq-655  effect=neutral_wrong
- gold=C  cb=B  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["APT28", "APT29", "T1136.003", "cyber threat intelligence"], "technique_ids": ["T1136.003"], "cves": [], "actors": ["APT28", "APT29"], "relations": ["group"], "platforms": []}
- question: Which group is known for creating global admin accounts in targeted organizations for persistence based on MITRE ATT&CK technique T1136.003?
- options: A) APT28 | B) APT29 | C) LAPSUS$ | D) Fin7
- selected_evidence: [A#1|5631|0.509] then manipulate that account to ensure persistence and allow access to additional resources - for example, by adding Additional Cloud Credentials or assigning Additional Cloud Role || [B#1|5631|0.504] then manipulate that account to ensure persistence and allow access to additional resources - for example, by adding Additional Cloud Credentials or assigning Additional Cloud Role || [C#1|5631|0.540] then manipulate that account to ensure persistence and allow access to additional resources - for example, by adding Additional Cloud Credentials or assigning Additional Cloud Role 

## 88. mcq-1345  effect=neutral_wrong
- gold=C  cb=D  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "sharkbot", "tanglebot"], "technique_ids": [], "cves": [], "actors": [], "relations": ["software", "platform"], "platforms": []}
- question: Which malware specifically can set itself as the default SMS handler, modifying SMS messages on the user's device? (Platform: Mobile)
- options: A) Mandrake | B) Terracotta | C) SharkBot | D) TangleBot
- selected_evidence: [A#1|1237|0.641] Home Techniques Mobile SMS Control SMS Control Adversaries may delete, alter, or send SMS messages without user authorization. This could be used to hide C2 SMS messages, spread ma || [B#1|1237|0.651] Home Techniques Mobile SMS Control SMS Control Adversaries may delete, alter, or send SMS messages without user authorization. This could be used to hide C2 SMS messages, spread ma || [C#1|1237|0.618] Home Techniques Mobile SMS Control SMS Control Adversaries may delete, alter, or send SMS messages without user authorization. This could be used to hide C2 SMS messages, spread ma 

## 89. mcq-1122  effect=neutral_wrong
- gold=C  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["application logging", "application vetting", "cyber threat intelligence", "host network communication", "user account monitoring"], "technique_ids": [], "cves": [], "actors": [], "relations": ["detection"], "platforms": ["network"]}
- question: Which detection method pertains to identifying applications that perform Discovery or utilize existing connectivity to remotely access hosts within an internal enterprise network?
- options: A) Application Logging (DS0001) | B) User Account Monitoring (DS0002) | C) Application Vetting (DS0041) | D) Host Network Communication (DS0013)
- selected_evidence: [A#1|3240|0.618] functions being sent to many outstations. Note that some ICS protocols use broadcast or multicast functionality, which may produce false positives. Also monitor for hosts enumerati || [B#1|3240|0.618] functions being sent to many outstations. Note that some ICS protocols use broadcast or multicast functionality, which may produce false positives. Also monitor for hosts enumerati || [C#1|3240|0.612] functions being sent to many outstations. Note that some ICS protocols use broadcast or multicast functionality, which may produce false positives. Also monitor for hosts enumerati 

## 90. mcq-1300  effect=neutral_wrong
- gold=B  cb=C  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1422.002", "cyber threat intelligence", "system network configuration discovery"], "technique_ids": ["T1422.002"], "cves": [], "actors": [], "relations": ["mitigation", "software"], "platforms": ["android", "network"]}
- question: Which mitigation strategy could help prevent adversaries from using Technique T1422.002 (System Network Configuration Discovery: Wi-Fi Discovery) on Android devices?
- options: A) Enforce multi-factor authentication | B) Use recent OS version | C) Disable Wi-Fi and cellular data | D) Install anti-virus software
- selected_evidence: [A#1|2216|0.594] Home Techniques Mobile System Network Configuration Discovery Wi-Fi Discovery System Network Configuration Discovery: Wi-Fi Discovery Other sub-techniques of System Network Configu || [B#1|2216|0.637] Home Techniques Mobile System Network Configuration Discovery Wi-Fi Discovery System Network Configuration Discovery: Wi-Fi Discovery Other sub-techniques of System Network Configu || [C#1|2216|0.606] Home Techniques Mobile System Network Configuration Discovery Wi-Fi Discovery System Network Configuration Discovery: Wi-Fi Discovery Other sub-techniques of System Network Configu 

## 91. mcq-607  effect=neutral_wrong
- gold=B  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["command execution", "cyber threat intelligence", "direct volume access", "drive access", "executable metadata", "file access permissions"], "technique_ids": [], "cves": [], "actors": [], "relations": ["detection"], "platforms": []}
- question: According to the document, what data component should be monitored to detect command execution related to Direct Volume Access?
- options: A) Executable Metadata | B) Command Execution | C) File Access Permissions | D) Drive Access
- selected_evidence: [A#1|2086|0.554] such as Windows Management Instrumentation and PowerShell . For network devices, monitor executed commands in AAA logs, especially those run by unexpected or unauthorized users. DS || [B#1|2354|0.545] be easily mitigated with preventive controls since it is based on the abuse of system features. Detection ID Data Source Data Component Detects DS0017 Command Command Execution Mon || [C#1|2354|0.570] be easily mitigated with preventive controls since it is based on the abuse of system features. Detection ID Data Source Data Component Detects DS0017 Command Command Execution Mon 

## 92. mcq-2334  effect=neutral_wrong
- gold=A  cb=D  rag=D
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: What strategy is recommended for mitigating CWE-168 during the implementation phase?
- options: A) Input sanitization | B) Process isolation | C) Output encoding | D) Privilege separation
- selected_evidence: [A#1|16314|0.522] expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Please address comments a || [B#1|12507|0.499] from this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with the facts presented o || [C#1|2714|0.479] Home Techniques Enterprise Data Encoding Data Encoding Sub-techniques (2) ID Name T1132.001 Standard Encoding T1132.002 Non-Standard Encoding Adversaries may encode data to make t

## 93. mcq-2115  effect=neutral_wrong
- gold=A  cb=D  rag=D
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is a primary risk when a Java application uses JNI to call code written in another language?
- options: A) Access control issues can occur | B) Performance degradation may happen | C) Java garbage collection could malfunction | D) Multi-threading issues could arise
- selected_evidence: [A#1|274|0.548] Home Techniques Mobile Native API Native API Adversaries may use Android’s Native Development Kit (NDK) to write native functions that can achieve execution of binaries or function || [B#1|274|0.553] Home Techniques Mobile Native API Native API Adversaries may use Android’s Native Development Kit (NDK) to write native functions that can achieve execution of binaries or function || [C#1|274|0.557] Home Techniques Mobile Native API Native API Adversaries may use Android’s Native Development Kit (NDK) to write native functions that can achieve execution of binaries or function || 

## 94. mcq-1534  effect=neutral_wrong
- gold=C  cb=D  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T1134.002", "cyber threat intelligence", "zxshell"], "technique_ids": ["T1134.002"], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: Which malware from the given list uses the runas command to create a new process with administrative rights, according to MITRE ATT&CK ID T1134.002?
- options: A) Aria-body | B) Azorult | C) REvil | D) ZxShell
- selected_evidence: [A#1|755|0.543] malware, admin@338 actors created a file containing a list of commands to be executed on the compromised computer. [7] S0045 ADVSTORESHELL ADVSTORESHELL can create a remote shell a || [B#1|755|0.566] malware, admin@338 actors created a file containing a list of commands to be executed on the compromised computer. [7] S0045 ADVSTORESHELL ADVSTORESHELL can create a remote shell a || [C#1|755|0.563] malware, admin@338 actors created a file containing a list of commands to be executed on the compromised computer. [7] S0045 ADVSTORESHELL ADVSTORESHELL can create a remote shell a || 

## 95. mcq-130  effect=neutral_wrong
- gold=C  cb=D  rag=D
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence", "darktortilla", "guloader"], "technique_ids": [], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: Which malware example uses the kernel32.dll Sleep function to delay execution for up to 300 seconds?
- options: A) SVCReady | B) Clop | C) DarkTortilla | D) GuLoader
- selected_evidence: [A#1|5966|0.598] Sleep function to delay execution for up to 300 seconds before implementing persistence or processing an addon package. [19] S0694 DRATzarus DRATzarus can use the GetTickCount and  || [B#1|5965|0.592] Bisonal has checked if the malware is running in a virtual environment with the anti-debug function GetTickCount() to compare the timing. [11] [12] S1063 Brute Ratel C4 Brute Ratel || [C#1|5965|0.602] Bisonal has checked if the malware is running in a virtual environment with the anti-debug function GetTickCount() to compare the timing. [11] [12] S1063 Brute Ratel C4 Brute Ratel 

## 96. mcq-1702  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which of the following types of threat attribution deals with the identification of the specific person, society, or a country sponsoring a well-planned and executed intrusion or attack over its target?
- options: A) Nation-state attribution | B) True attribution | C) Campaign attribution | D) Intrusion-set attribution
- selected_evidence: [A#1|20557|0.474] Unit 42’s Attribution Framework Advanced Persistent Threat Bookworm Nomenclature Read now Trend Reports July 30, 2025 2025 Unit 42 Global Incident Response Report: Social Engineeri || [B#1|15046|0.473] Types Assigned https://www.cisa.gov/uscert/ics/advisories/icsa-21-238-03 Third Party Advisory, US Government Resource Added CVSS V2 Metadata Victim must voluntarily interact with a || [C#1|20557|0.482] Unit 42’s Attribution Framework Advanced Persistent Threat Bookworm Nomenclature Read now Trend Reports July 30, 2025 2025 Unit 42 Global Incident Response Report: Social Enginee

## 97. mcq-2148  effect=neutral_wrong
- gold=B  cb=A  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: Which phase is recommended for mitigating weaknesses identified in CWE-184?
- options: A) Design | B) Implementation | C) Testing | D) Maintenance
- selected_evidence: [A#1|19970|0.494] referenced, or not, from this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with t || [B#1|19970|0.503] referenced, or not, from this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with t || [C#1|15979|0.501] Atlassian, CVE Exploit Third Party Advisory VDB Entry http://www.rapid7.com/db/modules/exploit/multi/http/confluence_widget_connector Atlassian, CVE Exploit Third Party Advisory 

## 98. mcq-2463  effect=neutral_wrong
- gold=B  cb=D  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: Which attack pattern is associated with using slashes and URL encoding to bypass validation logic, related to CWE-172?
- options: A) CAPEC-72 | B) CAPEC-64 | C) CAPEC-120 | D) CAPEC-3
- selected_evidence: [A#1|15791|0.552] server could then decode slash sequences and normalize path and provide an attacker access beyond the scope provided for by the access control policy. ### Impact Escalation of Priv || [B#1|15791|0.557] server could then decode slash sequences and normalize path and provide an attacker access beyond the scope provided for by the access control policy. ### Impact Escalation of Priv || [C#1|15791|0.565] server could then decode slash sequences and normalize path and provide an attacker access beyond the scope provided for by the access control policy. ### Impact Escalation of Pr

## 99. mcq-1074  effect=neutral_wrong
- gold=C  cb=B  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1623", "cyber threat intelligence", "javascript", "scripting interpreter", "tianyspy"], "technique_ids": ["T1623"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which procedure example utilizes malicious JavaScript to steal information in the scope of MITRE ATT&CK technique T1623 (Command and Scripting Interpreter)?
- options: A) Mirai | B) Kovter | C) TianySpy | D) Emotet
- selected_evidence: [A#1|5859|0.579] has the ability to execute arbitrary JavaScript code on a compromised host. [77] G1033 Star Blizzard Star Blizzard has used JavaScript to redirect victim traffic from an adversary  || [B#1|5856|0.578] execute JavaScript files. [47] G0094 Kimsuky Kimsuky has used JScript for logging and downloading additional tools. [48] [49] Kimsuky has used TRANSLATEXT , which contained four Ja || [C#1|4825|0.569] arbitrary commands. Commands and scripts can be embedded in Initial Access payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2.  

## 100. mcq-1258  effect=neutral_wrong
- gold=D  cb=B  rag=B
- abstain=True  contamination=none
- anchors={"entities": ["cyber threat intelligence", "disable system apps", "use recent", "user guidance"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": ["android"]}
- question: Which mitigation specifically addresses suppressing application icons in Android versions before Android 10?
- options: A) M1006 - Use Recent OS Version | B) M1011 - User Guidance | C) Disable System Apps | D) Install a reliable antivirus
- selected_evidence: [A#1|5055|0.605] Home Techniques Mobile Hide Artifacts Suppress Application Icon Hide Artifacts: Suppress Application Icon Other sub-techniques of Hide Artifacts (3) ID Name T1628.001 Suppress Appl || [B#1|5055|0.620] Home Techniques Mobile Hide Artifacts Suppress Application Icon Hide Artifacts: Suppress Application Icon Other sub-techniques of Hide Artifacts (3) ID Name T1628.001 Suppress Appl || [C#1|5055|0.610] Home Techniques Mobile Hide Artifacts Suppress Application Icon Hide Artifacts: Suppress Application Icon Other sub-techniques of Hide Artifacts (3) ID Name T1628.001 Suppress Appl 
