# MCQ v2 — 50 damages

n=50

## 1. mcq-48  effect=damage
- gold=C  cb=C  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "initialization service", "login daemon", "login hook", "startup script"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": ["macos"]}
- question: Which of the following is a deprecated method for executing scripts upon user login in macOS 10.11 and later?
- options: A) Login Daemon | B) Startup Script | C) Login Hook | D) Initialization Service
- selected_evidence: [A#1|6032|0.560] Home Techniques Enterprise Boot or Logon Initialization Scripts Login Hook Boot or Logon Initialization Scripts: Login Hook Other sub-techniques of Boot or Logon Initialization Scr || [B#1|6032|0.590] Home Techniques Enterprise Boot or Logon Initialization Scripts Login Hook Boot or Logon Initialization Scripts: Login Hook Other sub-techniques of Boot or Logon Initialization Scr || [C#1|6032|0.581] Home Techniques Enterprise Boot or Logon Initialization Scripts Login Hook Boot or Logon Initialization Scripts: Login Hook Other sub-techniques of Boot or Logon Initialization Scr 

## 2. mcq-51  effect=damage
- gold=B  cb=B  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["APT29", "T1037", "cyber threat intelligence", "logon initialization scripts", "rotajakiro"], "technique_ids": ["T1037"], "cves": [], "actors": ["APT29"], "relations": ["group", "platform"], "platforms": []}
- question: Which threat group is known for hijacking legitimate application-specific startup scripts for persistence using technique T1037 (Boot or Logon Initialization Scripts) on the Enterprise platform?
- options: A) Rocke | B) APT29 | C) RotaJakiro | D) None of the above
- selected_evidence: [A#1|5510|0.644] Home Techniques Enterprise Boot or Logon Initialization Scripts RC Scripts Boot or Logon Initialization Scripts: RC Scripts Other sub-techniques of Boot or Logon Initialization Scr || [B#1|5510|0.633] Home Techniques Enterprise Boot or Logon Initialization Scripts RC Scripts Boot or Logon Initialization Scripts: RC Scripts Other sub-techniques of Boot or Logon Initialization Scr || [C#1|5510|0.631] Home Techniques Enterprise Boot or Logon Initialization Scripts RC Scripts Boot or Logon Initialization Scripts: RC Scripts Other sub-techniques of Boot or Logon Initialization Scr 

## 3. mcq-146  effect=damage
- gold=B  cb=B  rag=C
- abstain=False  contamination=D:foreign_actor ['APT29']
- anchors={"entities": ["APT12", "APT28", "T1102.002", "cyber threat intelligence", "google drive"], "technique_ids": ["T1102.002"], "cves": [], "actors": ["APT12", "APT28"], "relations": ["group"], "platforms": []}
- question: In the provided examples, which adversary group uses Google Drive for command and control according to Technique ID T1102.002?
- options: A) APT12 | B) APT28 | C) Carbanak | D) HEXANE
- selected_evidence: [A#1|1973|0.498] a high level of privileges, through various means such as OS Credential Dumping or password reuse, allowing access to privileged resources of the domain. ID: T1078.002 Sub-techniqu || [B#1|1670|0.502] of scanning, such as large quantities originating from a single source (especially if the source is known to be associated with an adversary/botnet). References ClearSky Cyber Secu || [C#1|257|0.499] and Google Drive can be turned off altogether, blocked for certain domains, or restricted to certain users. [9] [10] M1018 User Account Management Limit user account and IAM polici |

## 4. mcq-210  effect=damage
- gold=C  cb=C  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "getuserdefaultuilanguage"], "technique_ids": [], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: Which malware uses GetUserDefaultUILanguage to identify and terminate executions based on system language?
- options: A) Ke3chang | B) Mazeera | C) REvil | D) Cuba
- selected_evidence: [A#1|2423|0.573] such as system defaults and keyboard layouts. Specific checks will vary based on the target and/or adversary, but may involve behaviors such as Query Registry and calls to Native A || [B#1|2428|0.600] MarkiRAT can use the GetKeyboardLayout API to check if a compromised host's keyboard is set to Persian. [25] S0449 Maze Maze has checked the language of the machine with function G || [C#1|2428|0.575] MarkiRAT can use the GetKeyboardLayout API to check if a compromised host's keyboard is set to Persian. [25] S0449 Maze Maze has checked the language of the machine with function G 

## 5. mcq-303  effect=damage
- gold=A  cb=A  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1087.003", "account discovery", "cyber threat intelligence", "email account", "global address list", "globaladdresslist", "google workspace", "google workspace directory", "google workspace sync", "microsoft outlook"], "technique_ids": ["T1087.003"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which technique can be used in Google Workspace to enable Microsoft Outlook users to access the Global Address List (GAL) according to T1087.003 Account Discovery: Email Account?
- options: A) Google Workspace Sync for Microsoft Outlook (GWSMO) | B) Google Workspace Directory | C) Get-GlobalAddressList LDAP Query | D) Both A and B
- selected_evidence: [A#1|618|0.685] Home Techniques Enterprise Account Discovery Email Account Account Discovery: Email Account Other sub-techniques of Account Discovery (4) ID Name T1087.001 Local Account T1087.002  || [B#1|618|0.686] Home Techniques Enterprise Account Discovery Email Account Account Discovery: Email Account Other sub-techniques of Account Discovery (4) ID Name T1087.001 Local Account T1087.002  || [C#1|618|0.673] Home Techniques Enterprise Account Discovery Email Account Account Discovery: Email Account Other sub-techniques of Account Discovery (4) ID Name T1087.001 Local Account T1087.002  || 

## 6. mcq-429  effect=damage
- gold=B  cb=B  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1546.002", "behavior prevention", "cyber threat intelligence", "execution prevention", "group policy", "remove feature", "scheduled task"], "technique_ids": ["T1546.002"], "cves": [], "actors": [], "relations": ["mitigation", "group"], "platforms": []}
- question: In the context of T1546.002, which mitigation involves using Group Policy?
- options: A) M1038: Execution Prevention | B) M1042: Disable or Remove Feature or Program | C) M1029: Scheduled Task | D) M1040: Behavior Prevention on Endpoint
- selected_evidence: [A#1|4313|0.534] Execution Prevention Consider using application control to prevent execution of binaries that are susceptible to abuse and not required for a given system or network. M1050 Exploit || [B#1|2378|0.544] can resist removal by going to the home screen during uninstall. [5] Mitigations ID Mitigation Description M1012 Enterprise Policy An EMM/MDM can use the Android DevicePolicyManage || [C#1|4085|0.541] System Configuration Configure settings for scheduled tasks to force tasks to run under the context of the authenticated account instead of allowing them to run as SYSTEM. The asso 

## 7. mcq-477  effect=damage
- gold=B  cb=B  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1567.001", "code repository", "command execution", "cyber threat intelligence", "exfiltration over web service", "file access", "network traffic content", "network traffic flow"], "technique_ids": ["T1567.001"], "cves": [], "actors": [], "relations": ["detection", "datasource"], "platforms": ["network"]}
- question: What type of data source is recommended for detecting command execution that may exfiltrate data to a code repository in MITRE ATT&CK T1567.001 (Exfiltration Over Web Service: Exfiltration to Code Repository)?
- options: A) File Access | B) Command Execution | C) Network Traffic Content | D) Network Traffic Flow
- selected_evidence: [A#1|965|0.563] Capabilities ), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store  || [B#1|3215|0.555] code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network. ID: T1567.001 Sub-technique of: || [C#1|3215|0.568] code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network. ID: T1567.001 Sub-technique of: |

## 8. mcq-501  effect=damage
- gold=D  cb=D  rag=C
- abstain=False  contamination=A:foreign_actor ['APT33', 'APT37']; B:foreign_cve ['CVE-2023-47194']; C:foreign_cve ['CVE-2017-11882', 'CVE-2018-0798', 'CVE-2018-0802', 'CVE-2018-8174', 'CVE-2019-9489', 'CVE-2020-8468']; D:foreign_cve ['CVE-2020-23061']
- anchors={"entities": ["APT32", "CVE-2017-0213", "cosmicduke", "cyber threat intelligence", "threat group", "tonto team"], "technique_ids": [], "cves": ["CVE-2017-0213"], "actors": ["APT32"], "relations": ["group"], "platforms": []}
- question: Which of the following adversaries has exploited the CVE-2017-0213 vulnerability?
- options: A) APT32 | B) CosmicDuke | C) Tonto Team | D) Threat Group-3390
- selected_evidence: [A#1|5336|0.628] RTF document that includes an exploit to execute malicious code. (CVE-2017-11882) [15] G0064 APT33 APT33 has attempted to exploit a known vulnerability in WinRAR (CVE-2018-20250),  || [B#1|12727|0.600] Vulnerabilities CVE-2023-47194 Detail Modified This CVE record has been updated after NVD enrichment efforts were completed. Enrichment data supplied by the NVD may require amendme || [C#1|5345|0.625] for execution. [85] G0089 The White Company The White Company has taken advantage of a known vulnerability in Microsoft Word (CVE 2012-0158) to execute code. [86] G0027 Threat Grou

## 9. mcq-648  effect=damage
- gold=D  cb=D  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1609", "container administration command", "cyber threat intelligence", "initial access", "privilege escalation"], "technique_ids": ["T1609"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which specific attack technique does T1609 (Container Administration Command) enhance the risk of, when applied to Kubernetes?
- options: A) Initial Access | B) Exfiltration | C) Privilege Escalation | D) Execution
- selected_evidence: [A#1|3867|0.624] can be deployed by various means, such as via Docker's create and start APIs or via a web application such as the Kubernetes dashboard or Kubeflow. [2] [3] [4] In Kubernetes enviro || [B#1|3867|0.626] can be deployed by various means, such as via Docker's create and start APIs or via a web application such as the Kubernetes dashboard or Kubeflow. [2] [3] [4] In Kubernetes enviro || [C#1|1050|0.660] T1543 ⓘ Tactics: Persistence , Privilege Escalation ⓘ Platforms: Containers Version: 1.0 Created: 15 February 2024 Last Modified: 15 April 2025 Version Permalink Live Version Mitig 

## 10. mcq-674  effect=damage
- gold=A  cb=A  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "imagepath", "ukraine electric power attack"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: During the 2016 Ukraine Electric Power Attack, which specific method did the adversaries use to achieve persistence?
- options: A) Replacing the ImagePath registry value with a new backdoor binary | B) Registering a new service | C) Modifying an existing service | D) Using service utilities such as sc.exe
- selected_evidence: [A#1|1660|0.567] ⓘ Tactic: Impact ⓘ Platforms: None Contributors: Dragos Threat Intelligence Version: 1.0 Created: 21 May 2020 Last Modified: 15 April 2025 Version Permalink Live Version Procedure  || [B#1|3425|0.562] ID: T0859 Sub-techniques: No sub-techniques ⓘ Tactics: Persistence , Lateral Movement ⓘ Platforms: None Version: 1.1 Created: 21 May 2020 Last Modified: 15 April 2025 Version Perma || [C#1|1660|0.575] ⓘ Tactic: Impact ⓘ Platforms: None Contributors: Dragos Threat Intelligence Version: 1.0 Created: 21 May 2020 Last Modified: 15 April 2025 Version Permalink Live Version Procedure  

## 11. mcq-685  effect=damage
- gold=A  cb=A  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T1543.001", "cyber threat intelligence", "launch agents", "privilege escalation"], "technique_ids": ["T1543.001"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which tactics do adversaries generally achieve by creating or modifying Launch Agents according to MITRE ATT&CK technique T1543.001?
- options: A) Persistence | B) Execution | C) Privilege Escalation | D) Evasion
- selected_evidence: [A#1|2990|0.553] files use the Label , ProgramArguments , and RunAtLoad keys to identify the Launch Agent's name, executable location, and execution time. [4] Launch Agents are often installed to p || [B#1|2990|0.569] files use the Label , ProgramArguments , and RunAtLoad keys to identify the Launch Agent's name, executable location, and execution time. [4] Launch Agents are often installed to p || [C#1|2990|0.580] files use the Label , ProgramArguments , and RunAtLoad keys to identify the Launch Agent's name, executable location, and execution time. [4] Launch Agents are often installed to p 

## 12. mcq-717  effect=damage
- gold=C  cb=C  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["CVE-2015-5374", "T0816", "cyber threat intelligence", "sandworm team", "ukraine electric power attack"], "technique_ids": ["T0816"], "cves": ["CVE-2015-5374"], "actors": [], "relations": ["software"], "platforms": []}
- question: In MITRE ATT&CK for ICS (ID: T0816), what method did the Sandworm Team use during the 2015 Ukraine Electric Power Attack to execute device shutdown?
- options: A) They exploited the CVE-2015-5374 vulnerability. | B) They used a malware called Industroyer. | C) They scheduled the UPS to shutdown data and telephone servers through the UPS management interface. | D) They performed a direct DoS attack on SIPROTEC devices.
- selected_evidence: [A#1|3729|0.608] Electric Power Attack During the 2015 Ukraine Electric Power Attack , Sandworm Team opened the breakers at the infected sites, shutting the power off for thousands of businesses an || [B#1|3729|0.634] Electric Power Attack During the 2015 Ukraine Electric Power Attack , Sandworm Team opened the breakers at the infected sites, shutting the power off for thousands of businesses an || [C#1|3729|0.592] Electric Power Attack During the 2015 Ukraine Electric Power Attack , Sandworm Team opened the breakers at the infected sites, shutting the power off for thousands of businesses an 

## 13. mcq-750  effect=damage
- gold=D  cb=D  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T0835", "authentication logs", "cyber threat intelligence", "network traffic", "remote service", "system calls"], "technique_ids": ["T0835"], "cves": [], "actors": [], "relations": ["detection", "datasource", "software"], "platforms": ["network"]}
- question: Regarding detection strategies for T0835, which data source and component should be analyzed to identify a manipulated I/O image?
- options: A) Asset, Network Traffic | B) Identity, Authentication Logs | C) Remote Service, System Calls | D) Asset, Software
- selected_evidence: [A#1|4167|0.520] all messages between master and outstation assets. Detection ID Data Source Data Component Detects DS0015 Application Log Application Log Content Monitor asset application logs whi || [B#1|572|0.537] controls since it is based on the abuse of system features. Detection ID Data Source Data Component Detects DS0022 File File Modification There is no documented method for defender || [C#1|735|0.553] Home Techniques ICS I/O Image I/O Image Adversaries may seek to capture process values related to the inputs and outputs of a PLC. During the scan cycle, a PLC reads the status of  ||

## 14. mcq-765  effect=damage
- gold=C  cb=C  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T0812", "cyber threat intelligence", "defense evasion", "initial access", "lateral movement"], "technique_ids": ["T0812"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which MITRE ATT&CK tactic does T0812 represent?
- options: A) Initial Access | B) Execution | C) Lateral Movement | D) Defense Evasion
- selected_evidence: [A#1|20579|0.505] 2022-02-23 Distribution website MITRE ATT&CK techniques This table was built using version 11 of the ATT&CK framework. Tactic ID Name Description Persistence T1398 Boot or Logon In || [B#1|20419|0.502] of the MITRE ATT&CK framework. Tactic ID Name Description Resource Development T1584.004 Compromise Infrastructure: Server In both Outer Space and Juicy Mix campaigns, OilRig has c || [C#1|7496|0.454] V3.1 NIST AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H Added CWE NIST CWE-78 Added CPE Configuration AND OR *cpe:2.3:o:totolink:a3300r_firmware:17.0.0cu.557_b20221024:*:*:*:*:*:*:* OR cpe:

## 15. mcq-857  effect=damage
- gold=C  cb=C  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T0859", "cyber threat intelligence", "initial access", "lateral movement", "valid accounts"], "technique_ids": ["T0859"], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: 1. In the context of MITRE ATT&CK for ICS, what tactic can be associated with the technique "Valid Accounts" (T0859)?
- options: A) Initial Access | B) Collection | C) Lateral Movement | D) Execution
- selected_evidence: [A#1|1972|0.529] Home Techniques Enterprise Valid Accounts Domain Accounts Valid Accounts: Domain Accounts Other sub-techniques of Valid Accounts (4) ID Name T1078.001 Default Accounts T1078.002 Do || [B#1|1972|0.515] Home Techniques Enterprise Valid Accounts Domain Accounts Valid Accounts: Domain Accounts Other sub-techniques of Valid Accounts (4) ID Name T1078.001 Default Accounts T1078.002 Do || [C#1|3401|0.492] Home Techniques Enterprise Account Manipulation Account Manipulation Sub-techniques (7) ID Name T1098.001 Additional Cloud Credentials T1098.002 Additional Email Delegate Permissio 

## 16. mcq-886  effect=damage
- gold=A  cb=A  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T0893", "cyber threat intelligence", "data loss prevention", "directory permissions", "encrypt sensitive information", "restrict file", "user training"], "technique_ids": ["T0893"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: What mitigation strategy aims to limit access to sensitive data stored on local systems for MITRE ATT&CK technique ID T0893?
- options: A) M0922 - Restrict File and Directory Permissions | B) M0803 - Data Loss Prevention | C) M0941 - Encrypt Sensitive Information | D) M0917 - User Training
- selected_evidence: [A#1|4220|0.551] Asset A0007 Control Server A0006 Data Historian Mitigations ID Mitigation Description M0947 Audit Consider periodic reviews of accounts and privileges for critical and sensitive re || [B#1|1842|0.554] an unintended or adversarial manner. ID: T0815 Sub-techniques: No sub-techniques ⓘ Tactic: Impact ⓘ Platforms: None Version: 1.1 Created: 21 May 2020 Last Modified: 15 April 2025 V || [C#1|4220|0.535] Asset A0007 Control Server A0006 Data Historian Mitigations ID Mitigation Description M0947 Audit Consider periodic reviews of accounts and privileges for critical and sensitive re 

## 17. mcq-891  effect=damage
- gold=D  cb=D  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["application log", "cyber threat intelligence", "network traffic", "operational databases"], "technique_ids": [], "cves": [], "actors": [], "relations": ["detection", "datasource"], "platforms": ["network"]}
- question: What data source should be monitored to detect changes in an asset’s operating mode according to MITRE ATT&CK?
- options: A) Application Log | B) Network Traffic | C) Operational Databases | D) All of the above
- selected_evidence: [A#1|3252|0.529] require that user authenticate for all remote or local management sessions. The authentication mechanisms should also support Account Use Policies, Password Policies, and User Acco || [B#1|4167|0.537] all messages between master and outstation assets. Detection ID Data Source Data Component Detects DS0015 Application Log Application Log Content Monitor asset application logs whi || [C#1|1312|0.533] Detection ID Data Source Data Component Detects DS0015 Application Log Application Log Content Monitor ICS asset application logs that indicate alarm settings have changed, althoug 

## 18. mcq-910  effect=damage
- gold=A  cb=A  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "data loss prevention", "endpoint detection", "filter network traffic", "network intrusion prevention"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation", "detection"], "platforms": ["network"]}
- question: Among the listed mitigations, which one specifically advises the resolution of DNS requests with on-premise or proxy servers to disrupt adversary attempts?
- options: A) M1037 - Filter Network Traffic | B) M1031 - Network Intrusion Prevention | C) M1050 - Data Loss Prevention | D) M1040 - Endpoint Detection and Response
- selected_evidence: [A#1|2912|0.598] on-premise/proxy servers may also disrupt adversary attempts to conceal data within DNS packets. M1031 Network Intrusion Prevention Network intrusion detection and prevention syste || [B#1|2912|0.605] on-premise/proxy servers may also disrupt adversary attempts to conceal data within DNS packets. M1031 Network Intrusion Prevention Network intrusion detection and prevention syste || [C#1|2912|0.593] on-premise/proxy servers may also disrupt adversary attempts to conceal data within DNS packets. M1031 Network Intrusion Prevention Network intrusion detection and prevention syste 

## 19. mcq-919  effect=damage
- gold=C  cb=C  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "ukraine electric power attack"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which specific incident involved the Sandworm team blocking command messages by making serial-to-ethernet converters inoperable?
- options: A) Stuxnet (C0030) | B) Triton (C0029) | C) 2015 Ukraine Electric Power Attack (C0028) | D) Industroyer (S0604)
- selected_evidence: [A#1|4853|0.594] Home Techniques ICS Block Command Message Block Command Message Adversaries may block a command message from reaching its intended target to prevent command execution. In OT networ || [B#1|4853|0.599] Home Techniques ICS Block Command Message Block Command Message Adversaries may block a command message from reaching its intended target to prevent command execution. In OT networ || [C#1|4853|0.618] Home Techniques ICS Block Command Message Block Command Message Adversaries may block a command message from reaching its intended target to prevent command execution. In OT networ 

## 20. mcq-934  effect=damage
- gold=C  cb=C  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T0820", "application log content", "cyber threat intelligence"], "technique_ids": ["T0820"], "cves": [], "actors": [], "relations": ["detection"], "platforms": []}
- question: What is a significant limitation of relying solely on Application Log Content for detecting T0820: Exploitation for Evasion according to the detection section?
- options: A) It cannot track firmware alterations | B) High chance of false positives | C) Exploits may not always succeed or cause crashes | D) It requires constant manual monitoring
- selected_evidence: [A#1|2032|0.568] Home Techniques ICS Exploitation for Evasion Exploitation for Evasion Adversaries may exploit a software vulnerability to take advantage of a programming error in a program, servic || [B#1|5348|0.553] from occurring. [103] Many of these protections depend on the architecture and target application binary for compatibility. M1051 Update Software Perform regular software updates t || [C#1|5348|0.586] from occurring. [103] Many of these protections depend on the architecture and target application binary for compatibility. M1051 Update Software Perform regular software updates t 

## 21. mcq-942  effect=damage
- gold=A  cb=A  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T0863", "application log", "cyber threat intelligence", "network traffic", "user execution"], "technique_ids": ["T0863"], "cves": [], "actors": [], "relations": ["datasource"], "platforms": ["network"]}
- question: Which data source would most effectively identify scripts or installers that depend on user interaction as described in User Execution (T0863)?
- options: A) Process (DS0009) | B) Application Log (DS0015) | C) Network Traffic (DS0029) | D) Command (DS0017)
- selected_evidence: [A#1|1044|0.591] search local system sources, such as file systems or local databases, to find files of interest and sensitive data. Process Creation Monitor for newly executed processes that may s || [B#1|1044|0.598] search local system sources, such as file systems or local databases, to find files of interest and sensitive data. Process Creation Monitor for newly executed processes that may s || [C#1|4461|0.589] .pdf, .docx, .jpg) viewed for collecting internal data. DS0029 Network Traffic Network Traffic Content Monitor for information collection on assets that may indicate deviations fro 

## 22. mcq-962  effect=damage
- gold=C  cb=C  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T0720", "T0890", "T1068", "T1128", "cyber threat intelligence", "privilege escalation", "remote services", "secure boot"], "technique_ids": ["T0720", "T0890", "T1068", "T1128"], "cves": [], "actors": [], "relations": ["platform"], "platforms": []}
- question: Which MITRE ATT&CK pattern technique ID and name best relates to leveraging a vulnerable driver to load unsigned code? (Platform: None)
- options: A) T1068: Exploitation for EoP | B) T0720: Exploitation of Remote Services | C) T0890: Exploitation for Privilege Escalation | D) T1128: Exploitation of Secure Boot
- selected_evidence: [A#1|1360|0.513] an endpoint system that has been properly configured and limits other privilege escalation methods. Adversaries may bring a signed vulnerable driver onto a compromised machine so t || [B#1|571|0.516] increase the speed of the encryption process as well as to prevent malicious tampering. When an adversary takes control of such a device, they may disable the dedicated hardware, f || [C#1|1360|0.552] an endpoint system that has been properly configured and limits other privilege escalation methods. Adversaries may bring a signed vulnerable driver onto a compromised machine so t |

## 23. mcq-1000  effect=damage
- gold=B  cb=B  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["APT41", "T1071.002", "cyber threat intelligence"], "technique_ids": ["T1071.002"], "cves": [], "actors": ["APT41"], "relations": [], "platforms": []}
- question: APT41 is noted for using which method in the context of MITRE ATT&CK's T1071.002?
- options: A) HTTP Beaconing | B) Exploit payloads that initiate download via FTP | C) Peer-to-peer communication using IRC | D) Communicating over SSH
- selected_evidence: [A#1|4882|0.518] domains to download additional frameworks. The group has also used downloaded encrypted payloads over HTTP. [21] [22] G0064 APT33 APT33 has used HTTP for command and control. [23]  || [B#1|996|0.576] that transfer files may be very common in environments. Packets produced from these protocols may have many fields and headers in which data can be concealed. Data could also be co || [C#1|4882|0.489] domains to download additional frameworks. The group has also used downloaded encrypted payloads over HTTP. [21] [22] G0064 APT33 APT33 has used HTTP for command and control. [23]  |

## 24. mcq-1025  effect=damage
- gold=D  cb=D  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T0817", "cyber threat intelligence"], "technique_ids": ["T0817"], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which of the following adversary groups is known to use drive-by compromise techniques to infiltrate electric utilities, according to the MITRE ATT&CK framework (ID: T0817)?
- options: A) Dragonfly | B) OILRIG | C) TEMP.Veles | D) ALLANITE
- selected_evidence: [A#1|20637|0.557] Ukraine’s power system in 2015 and 2016 were attributed to a cyber attack and led to power outages affecting hundreds of thousands of people. In recent months, there have also been || [B#1|20379|0.512] is one of the threat actor groups who are most actively targeting South Korea. The group mainly attacked their victims in the early days to obtain information related to security,  || [C#1|886|0.520] Home Techniques Mobile Supply Chain Compromise Compromise Hardware Supply Chain Supply Chain Compromise: Compromise Hardware Supply Chain Other sub-techniques of Supply Chain Compr

## 25. mcq-1050  effect=damage
- gold=C  cb=C  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T0815", "cyber threat intelligence", "maroochy water breach"], "technique_ids": ["T0815"], "cves": [], "actors": [], "relations": [], "platforms": ["network"]}
- question: In the context of MITRE ATT&CK T0815 - Denial of View, which adversary tactic was specifically employed during the Maroochy Water Breach to disrupt oversight?
- options: A) Blocking serial COM channels | B) Corrupting operational processes | C) Shutting an investigator out of the network | D) Triggering false alarms
- selected_evidence: [A#1|5658|0.592] None Version: 1.1 Created: 21 May 2020 Last Modified: 15 April 2025 Version Permalink Live Version Procedure Examples ID Name Description C0028 2015 Ukraine Electric Power Attack D || [B#1|5658|0.549] None Version: 1.1 Created: 21 May 2020 Last Modified: 15 April 2025 Version Permalink Live Version Procedure Examples ID Name Description C0028 2015 Ukraine Electric Power Attack D || [C#1|5658|0.571] None Version: 1.1 Created: 21 May 2020 Last Modified: 15 April 2025 Version Permalink Live Version Procedure Examples ID Name Description C0028 2015 Ukraine Electric Power Attack D 

## 26. mcq-1064  effect=damage
- gold=A  cb=A  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "lock bootloader", "security updates", "system partition integrity"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation", "detection"], "platforms": []}
- question: What might be a suitable mitigation technique for detecting unauthorized modifications to the system partition, according to the MITRE ATT&CK framework?
- options: A) Attestation | B) Lock Bootloader | C) Security Updates | D) System Partition Integrity
- selected_evidence: [A#1|4651|0.565] can remount the system partition as read/write to install attacker-specified certificates. [4] S0316 Pegasus for Android Pegasus for Android attempts to modify the device's system  || [B#1|4652|0.567] M1003 Lock Bootloader A locked bootloader could prevent unauthorized modifications of protected operating system files. M1001 Security Updates Security updates frequently contain f || [C#1|4651|0.559] can remount the system partition as read/write to install attacker-specified certificates. [4] S0316 Pegasus for Android Pegasus for Android attempts to modify the device's system  

## 27. mcq-1071  effect=damage
- gold=B  cb=B  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1623.001", "application vetting", "command execution", "cyber threat intelligence"], "technique_ids": ["T1623.001"], "cves": [], "actors": [], "relations": ["detection", "datasource"], "platforms": []}
- question: Which of the following data sources is most relevant for detecting command-line activities as specified under MITRE ATT&CK technique T1623.001?
- options: A) Application Vetting | B) Command | C) Process | D) Command Execution
- selected_evidence: [A#1|20579|0.541] 2022-02-23 Distribution website MITRE ATT&CK techniques This table was built using version 11 of the ATT&CK framework. Tactic ID Name Description Persistence T1398 Boot or Logon In || [B#1|935|0.531] or by policy from suspicious sites as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some download scanning devices can open and analyze compressed a || [C#1|4777|0.538] on the abuse of system features. Detection ID Data Source Data Component Detects DS0017 Command Command Execution Monitor executed commands and arguments that can leverage a comput 

## 28. mcq-1116  effect=damage
- gold=C  cb=C  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T1626.001", "cyber threat intelligence", "privilege escalation"], "technique_ids": ["T1626.001"], "cves": [], "actors": [], "relations": ["mitigation", "software"], "platforms": ["android"]}
- question: Which mitigation strategy is recommended to counter adversaries abusing Android’s device administration API as per MITRE ATT&CK (T1626.001) for the Privilege Escalation tactic?
- options: A) Use an older OS version | B) Disable device administration API | C) Update to newer OS versions | D) Use third-party antivirus software
- selected_evidence: [A#1|4289|0.625] Home Techniques Mobile Abuse Elevation Control Mechanism Abuse Elevation Control Mechanism Sub-techniques (1) ID Name T1626.001 Device Administrator Permissions Adversaries may cir || [B#1|1835|0.630] Home Techniques Mobile Abuse Elevation Control Mechanism Device Administrator Permissions Abuse Elevation Control Mechanism: Device Administrator Permissions Adversaries may abuse  || [C#1|4289|0.629] Home Techniques Mobile Abuse Elevation Control Mechanism Abuse Elevation Control Mechanism Sub-techniques (1) ID Name T1626.001 Device Administrator Permissions Adversaries may cir 

## 29. mcq-1119  effect=damage
- gold=D  cb=D  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T1626", "abuse elevation control mechanism", "application vetting", "cyber threat intelligence", "network traffic", "user interface"], "technique_ids": ["T1626"], "cves": [], "actors": [], "relations": ["datasource"], "platforms": ["network"]}
- question: Which data source is used to monitor permissions requests at the user interface level according to MITRE ATT&CK's technique for "Abuse Elevation Control Mechanism" (T1626)?
- options: A) Application Vetting | B) Network Traffic | C) DNS Logs | D) User Interface
- selected_evidence: [A#1|267|0.569] Home Techniques Enterprise Abuse Elevation Control Mechanism TCC Manipulation Abuse Elevation Control Mechanism: TCC Manipulation Other sub-techniques of Abuse Elevation Control Me || [B#1|267|0.567] Home Techniques Enterprise Abuse Elevation Control Mechanism TCC Manipulation Abuse Elevation Control Mechanism: TCC Manipulation Other sub-techniques of Abuse Elevation Control Me || [C#1|3794|0.534] features turned on. [77] M1017 User Training Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engin ||

## 30. mcq-1135  effect=damage
- gold=B  cb=B  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["T1646", "cyber threat intelligence", "exfiltration over", "flubot"], "technique_ids": ["T1646"], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: For the MITRE ATT&CK technique T1646 (Exfiltration Over C2 Channel) in the Enterprise context, which malware uses HTTP PUT requests for data exfiltration?
- options: A) Pallas | B) eSurv | C) Chameleon | D) FluBot
- selected_evidence: [A#1|3683|0.573] using HTTP PUT requests. [10] S1080 Fakecalls Fakecalls can send exfiltrated data back to the C2 server. [11] S1067 FluBot FluBot can send contact lists to its C2 server. [12] S109 || [B#1|3683|0.575] using HTTP PUT requests. [10] S1080 Fakecalls Fakecalls can send exfiltrated data back to the C2 server. [11] S1067 FluBot FluBot can send contact lists to its C2 server. [12] S109 || [C#1|3683|0.589] using HTTP PUT requests. [10] S1080 Fakecalls Fakecalls can send exfiltrated data back to the C2 server. [11] S1067 FluBot FluBot can send contact lists to its C2 server. [12] S109 

## 31. mcq-1193  effect=damage
- gold=B  cb=B  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "google authenticator"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: Which procedure example is associated with collecting Google Authenticator codes?
- options: A) Jiwifty | B) Escobar | C) Viceroy | D) Viscount
- selected_evidence: [A#1|5472|0.470] Retrieved June 26, 2020. B. Toulas. (2022, March 12). Android malware Escobar steals your Google Authenticator MFA codes. Retrieved September 28, 2023. ThreatFabric. (2021, Septemb || [B#1|4249|0.481] RFC 7636: Proof Key for Code Exchange by OAuth Public Clients. Retrieved December 21, 2016. Google. (n.d.). Verify Android App Links. Retrieved September 11, 2020. Apple. (n.d.). U || [C#1|19803|0.469] authentication for a few audit directories. Removed Reference https://manageengine.com [No Types Assigned] Quick Info CVE Dictionary Entry: CVE-2021-44514 NVD Published Date: 12/09

## 32. mcq-1237  effect=damage
- gold=D  cb=D  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T1629.003", "abstractemu", "cyber threat intelligence"], "technique_ids": ["T1629.003"], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: Which of the following malware has been documented to modify SELinux configuration as described in MITRE ATT&CK ID T1629.003?
- options: A) AbstractEmu (S1061) | B) Anubis (S0422) | C) BRATA (S1094) | D) Zen (S0494)
- selected_evidence: [A#1|20342|0.501] appears to be connected to Jupiter / EarlyRAT , another malware family Kaspersky recently wrote about and attributed to Andariel , a subgroup within the Lazarus Group umbrella of t || [B#1|20419|0.515] of the MITRE ATT&CK framework. Tactic ID Name Description Resource Development T1584.004 Compromise Infrastructure: Server In both Outer Space and Juicy Mix campaigns, OilRig has c || [C#1|20419|0.518] of the MITRE ATT&CK framework. Tactic ID Name Description Resource Development T1584.004 Compromise Infrastructure: Server In both Outer Space and Juicy Mix campaigns, OilRig has

## 33. mcq-1277  effect=damage
- gold=A  cb=A  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1595.002", "cyber threat intelligence"], "technique_ids": ["T1595.002"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": []}
- question: Which mitigation strategy is suggested for vulnerability scanning techniques like T1595.002?
- options: A) M1056: Pre-compromise | B) M1234: Post-compromise | C) Custom policy enforcement by enterprise firewalls | D) Isolation of vulnerable systems
- selected_evidence: [A#1|3995|0.572] Home Techniques Enterprise Active Scanning Vulnerability Scanning Active Scanning: Vulnerability Scanning Other sub-techniques of Active Scanning (3) ID Name T1595.001 Scanning IP  || [B#1|3995|0.567] Home Techniques Enterprise Active Scanning Vulnerability Scanning Active Scanning: Vulnerability Scanning Other sub-techniques of Active Scanning (3) ID Name T1595.001 Scanning IP  || [C#1|3995|0.552] Home Techniques Enterprise Active Scanning Vulnerability Scanning Active Scanning: Vulnerability Scanning Other sub-techniques of Active Scanning (3) ID Name T1595.001 Scanning IP  

## 34. mcq-1312  effect=damage
- gold=C  cb=C  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "golfspy", "rumms", "viceleaker"], "technique_ids": [], "cves": [], "actors": [], "relations": ["software"], "platforms": []}
- question: Which malware is known to query its running environment for device metadata including make, model, and power levels?
- options: A) RuMMS | B) ViceLeaker | C) Monokle | D) GolfSpy
- selected_evidence: [A#1|4196|0.556] Home Techniques Mobile System Information Discovery System Information Discovery Adversaries may attempt to get detailed information about a device’s operating system and hardware, || [B#1|4205|0.558] system version information and transmits it to a command and control server. [46] S1062 S.O.V.A. S.O.V.A. can gather data about the device. [47] S1082 Sunbird Sunbird can exfiltrat || [C#1|5541|0.548] timing, and API's to detect code emulation or sandboxing. [8] [9] S1180 BlackByte Ransomware BlackByte Ransomware checks for files related to known sandboxes. [10] S0657 BLUELIGHT  

## 35. mcq-1375  effect=damage
- gold=A  cb=A  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T1636.002", "application vetting", "cyber threat intelligence", "network traffic", "system logs", "user interface"], "technique_ids": ["T1636.002"], "cves": [], "actors": [], "relations": ["detection", "datasource"], "platforms": ["network"]}
- question: For detecting applications that may attempt to access call logs, which data source should a security professional monitor according to the detection methods listed for T1636.002?
- options: A) Application Vetting | B) System Logs | C) User Interface | D) Network Traffic
- selected_evidence: [A#1|2170|0.585] Application Log Application Log Content Monitor for application logging, messaging, and/or other artifacts that may result from Denial of Service (DoS) attacks which degrade or blo || [B#1|2170|0.598] Application Log Application Log Content Monitor for application logging, messaging, and/or other artifacts that may result from Denial of Service (DoS) attacks which degrade or blo || [C#1|2170|0.595] Application Log Application Log Content Monitor for application logging, messaging, and/or other artifacts that may result from Denial of Service (DoS) attacks which degrade or blo 

## 36. mcq-1395  effect=damage
- gold=A  cb=A  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["T1660", "cyber threat intelligence", "email filtering", "network segmentation", "user guidance"], "technique_ids": ["T1660"], "cves": [], "actors": [], "relations": ["mitigation"], "platforms": ["network"]}
- question: In the context of MITRE ATT&CK T1660, which mitigation technique could be used to block traffic to known phishing websites on mobile devices?
- options: A) Antivirus/Antimalware | B) User Guidance | C) Email Filtering | D) Network Segmentation
- selected_evidence: [A#1|1968|0.561] LightSpy has delivered malicious links through Telegram channels and Instagram posts. [7] [8] S0289 Pegasus for iOS Pegasus for iOS has been distributed via malicious links in SMS  || [B#1|20438|0.566] can be blocked from execution via AppLocker . As an additional precaution, Rapid7 recommends blocking domains associated with all unapproved RMM solutions. A public GitHub repo con || [C#1|20438|0.564] can be blocked from execution via AppLocker . As an additional precaution, Rapid7 recommends blocking domains associated with all unapproved RMM solutions. A public GitHub repo co

## 37. mcq-1432  effect=damage
- gold=C  cb=C  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "earth lusca", "magic hound", "muddywater"], "technique_ids": [], "cves": [], "actors": [], "relations": ["group"], "platforms": []}
- question: Which threat group has used Amazon S3 buckets to host trojanized digital products as per their MITRE ATT&CK profile?
- options: A) A. Magic Hound | B) B. Earth Lusca | C) C. FIN7 | D) D. MuddyWater
- selected_evidence: [A#1|2450|0.593] has registered algorithmically generated Twitter handles that are used for C2 by malware, such as HAMMERTOSS . APT29 has also used legitimate web services such as Dropbox and Const || [B#1|2450|0.609] has registered algorithmically generated Twitter handles that are used for C2 by malware, such as HAMMERTOSS . APT29 has also used legitimate web services such as Dropbox and Const || [C#1|2450|0.594] has registered algorithmically generated Twitter handles that are used for C2 by malware, such as HAMMERTOSS . APT29 has also used legitimate web services such as Dropbox and Const 

## 38. mcq-1440  effect=damage
- gold=A  cb=A  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["T1583.004", "acquire infrastructure", "cyber threat intelligence"], "technique_ids": ["T1583.004"], "cves": [], "actors": [], "relations": ["mitigation", "detection"], "platforms": []}
- question: Which mitigation strategy is recommended for the technique T1583.004, Acquire Infrastructure: Server?
- options: A) M1056 (Pre-compromise) | B) Detecting during Command and Control | C) Use of SSL/TLS certificates | D) Monitoring response metadata
- selected_evidence: [A#1|3508|0.549] Home Techniques Enterprise Compromise Infrastructure Server Compromise Infrastructure: Server Other sub-techniques of Compromise Infrastructure (8) ID Name T1584.001 Domains T1584. || [B#1|4829|0.554] Home Techniques Enterprise Acquire Infrastructure Server Acquire Infrastructure: Server Other sub-techniques of Acquire Infrastructure (8) ID Name T1583.001 Domains T1583.002 DNS S || [C#1|4829|0.517] Home Techniques Enterprise Acquire Infrastructure Server Acquire Infrastructure: Server Other sub-techniques of Acquire Infrastructure (8) ID Name T1583.001 Domains T1583.002 DNS S 

## 39. mcq-1464  effect=damage
- gold=C  cb=C  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "ukraine electric power attack", "windows calculator", "windows explorer", "windows media player", "windows notepad"], "technique_ids": [], "cves": [], "actors": [], "relations": ["software"], "platforms": ["windows"]}
- question: During the 2016 Ukraine Electric Power Attack, which software was trojanized to add a layer of persistence for Industroyer?
- options: A) A. Windows Calculator | B) B. Windows Media Player | C) C. Windows Notepad | D) D. Windows Explorer
- selected_evidence: [A#1|5950|0.566] malware discovered in Ukraine. Retrieved March 23, 2022. Malhotra, A. (2022, March 15). Threat Advisory: CaddyWiper. Retrieved March 23, 2022. Neeamni, D., Rubinfeld, A.. (2021, Ju || [B#1|5950|0.558] malware discovered in Ukraine. Retrieved March 23, 2022. Malhotra, A. (2022, March 15). Threat Advisory: CaddyWiper. Retrieved March 23, 2022. Neeamni, D., Rubinfeld, A.. (2021, Ju || [C#1|5950|0.580] malware discovered in Ukraine. Retrieved March 23, 2022. Malhotra, A. (2022, March 15). Threat Advisory: CaddyWiper. Retrieved March 23, 2022. Neeamni, D., Rubinfeld, A.. (2021, Ju 

## 40. mcq-1508  effect=damage
- gold=A  cb=A  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["blackenergy", "cyber threat intelligence", "sandworm team", "ukraine electric power attack"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: During which Ukraine Electric Power Attack did Sandworm Team use a VBA script to install a primary BlackEnergy implant?
- options: A) 2015 Ukraine Electric Power Attack | B) 2016 Ukraine Electric Power Attack | C) 2017 Ukraine Electric Power Attack | D) 2018 Ukraine Electric Power Attack
- selected_evidence: [A#1|1412|0.569] ID Name Description C0025 2016 Ukraine Electric Power Attack During the 2016 Ukraine Electric Power Attack , Sandworm Team utilized VBS and batch scripts for file movement and as w || [B#1|1412|0.569] ID Name Description C0025 2016 Ukraine Electric Power Attack During the 2016 Ukraine Electric Power Attack , Sandworm Team utilized VBS and batch scripts for file movement and as w || [C#1|1412|0.571] ID Name Description C0025 2016 Ukraine Electric Power Attack During the 2016 Ukraine Electric Power Attack , Sandworm Team utilized VBS and batch scripts for file movement and as w 

## 41. mcq-1524  effect=damage
- gold=C  cb=C  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["T1059.002", "applescript", "cyber threat intelligence"], "technique_ids": ["T1059.002"], "cves": [], "actors": [], "relations": ["platform"], "platforms": []}
- question: How does the Dok adversary use AppleScript according to the provided document? (MITRE ATT&CK: T1059.002, Platform: None)
- options: A) To send keystrokes to the Finder application | B) To interact with SSH connections | C) To create a login item for persistence | D) To execute a reverse shell via Python
- selected_evidence: [A#1|2637|0.522] techniques as well such as a reverse shell via Python . [4] ID: T1059.002 Sub-technique of: T1059 ⓘ Tactic: Execution ⓘ Platforms: macOS Contributors: Phil Stokes, SentinelOne Vers || [B#1|2637|0.525] techniques as well such as a reverse shell via Python . [4] ID: T1059.002 Sub-technique of: T1059 ⓘ Tactic: Execution ⓘ Platforms: macOS Contributors: Phil Stokes, SentinelOne Vers || [C#1|2637|0.627] techniques as well such as a reverse shell via Python . [4] ID: T1059.002 Sub-technique of: T1059 ⓘ Tactic: Execution ⓘ Platforms: macOS Contributors: Phil Stokes, SentinelOne Vers 

## 42. mcq-1530  effect=damage
- gold=D  cb=D  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "encodedcommand", "powershell", "scriptblocklogging"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: Which technique involves executing PowerShell scripts without using the powershell.exe binary?
- options: A) ScriptBlockLogging | B) EncodedCommand | C) Direct PowerShell Execution | D) . NET Assemblies
- selected_evidence: [A#1|5226|0.609] to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the I || [B#1|5226|0.596] to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the I || [C#1|5226|0.675] to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the I 

## 43. mcq-1539  effect=damage
- gold=D  cb=D  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["APT19", "APT37", "T1059", "cyber threat intelligence", "oilrig", "scripting interpreter"], "technique_ids": ["T1059"], "cves": [], "actors": ["APT19", "APT37"], "relations": [], "platforms": []}
- question: Which of the following is NOT an example of an adversary abusing Command and Scripting Interpreter (T1059)?
- options: A) APT37 using Ruby scripts to execute payloads | B) APT19 downloading and launching code within a SCT file | C) OilRig using WMI to script data collection | D) FIN7 using SQL scripts to perform tasks
- selected_evidence: [A#1|1411|0.574] for many different systems. Scripting languages, such as Python, have their interpreters shipped as a default with many Linux distributions. In addition to being a useful tool for  || [B#1|1261|0.554] capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell . There are  || [C#1|1411|0.562] for many different systems. Scripting languages, such as Python, have their interpreters shipped as a default with many Linux distributions. In addition to being a useful tool for  

## 44. mcq-1860  effect=damage
- gold=C  cb=C  rag=D
- abstain=False  contamination=none
- anchors={"entities": ["buffer overflow", "cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is the typical severity of a Buffer Overflow in an API Call attack?
- options: A) Low | B) Moderate | C) High | D) Critical
- selected_evidence: [A#1|12425|0.482] V3.1 NIST AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H Added CWE NIST CWE-120 Added CPE Configuration OR *cpe:2.3:a:broadcom:symantec_messaging_gateway:*:*:*:*:*:*:*:* versions up to (inclu || [B#1|12425|0.491] V3.1 NIST AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H Added CWE NIST CWE-120 Added CPE Configuration OR *cpe:2.3:a:broadcom:symantec_messaging_gateway:*:*:*:*:*:*:*:* versions up to (inclu || [C#1|12425|0.492] V3.1 NIST AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H Added CWE NIST CWE-120 Added CPE Configuration OR *cpe:2.3:a:broadcom:symantec_messaging_gateway:*:*:*:*:*:*:*:* versions up to (inc

## 45. mcq-2030  effect=damage
- gold=B  cb=B  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "path traversal", "product released", "release configuration", "site scripting"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: Which CWE ID is associated with CAPEC-439?
- options: A) CWE-89: SQL Injection | B) CWE-1269: Product Released in Non-Release Configuration | C) CWE-79: Cross-Site Scripting (XSS) | D) CWE-22: Path Traversal
- selected_evidence: [A#1|18882|0.527] Advisory Weakness Enumeration CWE-ID CWE Name Source CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') NIST Known Affected Software Config || [B#1|19399|0.522] CWE-255 Added CPE Configuration AND OR *cpe:2.3:o:arris:dg950a_firmware:7.10.145:*:*:*:*:*:*:* OR cpe:2.3:o:arris:dg950a:3.0:*:*:*:*:*:*:* Added CPE Configuration AND OR *cpe:2.3:o || [C#1|9366|0.521] XSS vulnerability located at "/gui/terminal_tool.cgi" in the "data" parameter. Added CWE CERT.PL CWE-79 Added Reference CERT.PL https://cert.pl/en/posts/2024/01/CVE-2023-49253/ [N

## 46. mcq-2048  effect=damage
- gold=B  cb=B  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["buffer overflow", "cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is a potential technical impact of exploiting the CWE-51 weakness?
- options: A) Denial of Service (DoS) | B) Unauthorized read or modification of files and directories | C) Buffer Overflow | D) SQL Injection
- selected_evidence: [A#1|6898|0.508] expressed, or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Please address comments a || [B#1|18797|0.504] or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Please address comments about this p || [C#1|17396|0.549] on these sites. Please address comments about this page to [email protected] . URL Source(s) Tag(s) http://packetstormsecurity.com/files/165193/Reprise-License-Manager-14.2-Buffer

## 47. mcq-2249  effect=damage
- gold=D  cb=D  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["buffer overflow", "cyber threat intelligence", "nosql", "site scripting"], "technique_ids": [], "cves": [], "actors": [], "relations": [], "platforms": []}
- question: What is a related attack pattern to CWE-943 as stated in the document?
- options: A) SQL Injection | B) Buffer Overflow | C) Cross-Site Scripting (XSS) | D) NoSQL Injection
- selected_evidence: [A#1|12356|0.547] of the file src/main/java/com/xhb/pay/action/PayTempOrderAction.java. The manipulation leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed  || [B#1|10079|0.574] leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB || [C#1|10600|0.578] which creates a Cross-Site Scripting (XSS) vulnerability via /icehrm/app/fileupload_page.php, in multiple parameters. An attacker could exploit this vulnerability by sending a sp

## 48. mcq-2299  effect=damage
- gold=B  cb=B  rag=A
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation", "software"], "platforms": []}
- question: In the context of CWE-449, which mitigation strategy is recommended to address this UI-related weakness?
- options: A) Conducting security code reviews | B) Performing extensive functionality testing of the UI | C) Implementing stricter access controls | D) Applying frequent software patches and updates
- selected_evidence: [A#1|1540|0.521] Mitigations This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features. Detection ID Data Source Data Compo || [B#1|1540|0.490] Mitigations This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features. Detection ID Data Source Data Compo || [C#1|4151|0.523] privileges corresponding to the restriction of a GUI session to control system operations (examples include HMI read-only vs. read-write modes). Ensure local users, such as operato 

## 49. mcq-2382  effect=damage
- gold=B  cb=B  rag=C
- abstain=False  contamination=none
- anchors={"entities": ["algorithm analysis", "cryptographic techniques", "cyber threat intelligence", "input validation", "output encoding"], "technique_ids": [], "cves": [], "actors": [], "relations": ["mitigation", "association"], "platforms": []}
- question: Which strategy is recommended during the implementation phase to mitigate the risk associated with CWE-156?
- options: A) Algorithm Analysis | B) Output Encoding | C) Input Validation | D) Cryptographic Techniques
- selected_evidence: [A#1|19970|0.488] referenced, or not, from this page. There may be other web sites that are more appropriate for your purpose. NIST does not necessarily endorse the views expressed, or concur with t || [B#1|2714|0.480] Home Techniques Enterprise Data Encoding Data Encoding Sub-techniques (2) ID Name T1132.001 Standard Encoding T1132.002 Non-Standard Encoding Adversaries may encode data to make th || [C#1|19155|0.523] or concur with the facts presented on these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites. Please address comments about this 

## 50. mcq-2488  effect=damage
- gold=D  cb=D  rag=B
- abstain=False  contamination=none
- anchors={"entities": ["cyber threat intelligence", "password brute forcing", "physically hacking hardware", "site scripting"], "technique_ids": [], "cves": [], "actors": [], "relations": ["association"], "platforms": []}
- question: Which related attack pattern is associated with exploiting CWE-1263?
- options: A) CAPEC-101: Password Brute Forcing | B) CAPEC-200: SQL Injection | C) CAPEC-301: Cross-Site Scripting (XSS) | D) CAPEC-401: Physically Hacking Hardware
- selected_evidence: [A#1|6447|0.515] AC10U 15.03.06.49_multi_TDE01. It has been declared as critical. Affected by this vulnerability is the function fromDhcpListClient. The manipulation of the argument page/listN lead || [B#1|10453|0.551] in code-projects Online Faculty Clearance 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /production/designee_view_st || [C#1|13278|0.559] was classified as problematic, has been found in SourceCodester House Rental Management System 1.0. This issue affects some unknown processing of the file index.php. The manipulat
