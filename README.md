# 🎯 Threat-Hunting-Scenario-Operation-Jackal-Spear 

![DALL·E 2025-01-30 13 43 55 - A dramatic and intense cybersecurity-themed thumbnail  The background features a digital world map with South Africa and Egypt highlighted in red, sym](https://github.com/user-attachments/assets/d443fb6d-8aec-4e0c-84c5-122ba2a7b62e)


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

# 🕵️ **Scenario: APT Threat Alert** 🚨  

### 🔥 **Newly Discovered Threat: "Jackal Spear"**  
🚀 **Origin:** South Africa 🇿🇦 (Occasionally operating in Egypt 🇪🇬)  
🎯 **Target:** Large corporations & high-level executives 🏢💼  
📩 **Attack Methods:**   
- 🛂 **Credential Stuffing** – Exploiting stolen passwords for easy system access  

### ⚠️ **How They Operate:**  
🔓 **Step 1:** Gain access using stolen credentials with minimal login attempts.  
👤 **Step 2:** Establish persistence by creating a secondary account with a similar username.  
📡 **Step 3:** Use this stealth account to exfiltrate sensitive data while avoiding detection.  

---

## 🎯 **Your Mission:** 🕵️‍♂️🔍  
🚀 **Management has tasked me with uncovering Indicators of Compromise (IoCs) related to "Jackal Spear."**  

### High-Level Related IoC Discovery Plan

- **Check `DeviceProcessEvents`** for any New-LocalUser.
- **Check `DeviceLogonEvents`** for any signs of login success or fail.
- **Check `DeviceFileEvents`** for any file changes.

---

### 🕵️ **Step 1: Investigation Initiation: Tracing the Attacker** 🔍  

To kick off the investigation, I delved into the **DeviceProcessEvents** table, hunting for any traces of **suspicious user account creation**. 🚨  

🔎 **Key Discovery:**  
💻 **Compromised Device:** `corpnet-1-ny` 🖥️  
👤 **Newly Created User:** `chadwick.s` 🆕  
⚡ **Creation Method:** **PowerShell Command** 🖥️⚙️ 

---

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("New-LocalUser")
| project DeviceName, AccountName, ProcessCommandLine
```
---
![Screenshot 2025-01-30 182243](https://github.com/user-attachments/assets/31b5ae61-0af6-461a-b520-b9f316aab842)


## 🔍 **Step 2: Investigating Suspicious Logins** 🚨  

### 🕵️ **What I Did:**  
I kicked off the investigation by searching the **DeviceLogonEvents** table, which logs all **successful and failed login attempts**. 📊  

🎯 **Our Goal:**  
✅ Detect **brute-force attacks** 🔨🔐  
✅ Identify **credential stuffing attempts** 🎭🔑  
✅ Uncover **unauthorized access patterns** 🚫💻  

## 🕵️‍♂️ **Refining the Investigation: Login Analysis** 🔍  

### **🔎 Key Investigation Steps:**  

📅 **Time Range:** Expanded to **last 7 days** to capture recent login activity. ⏳📊  

🚫 **Excluding System Accounts:** Removed `"admin"`, `"labuser"`, and `"root"` since they are not typically used by regular users. 🔒⚙️  

📌 **Failed vs. Successful Logins:** Tracked **failed login attempts** and **successful logins** for each account-device combination. 📈👤  

⚠️ **Identifying Suspicious Logins:**  
✅ Focused on accounts with **5+ failed attempts** followed by **at least one successful login**—a red flag for **brute-force attacks!** 🚨🔑  

🔍 Every login attempt tells a story. Let’s uncover the truth! 🧩🔥
---
---
```kql
let SuspiciousLogins = 
   DeviceLogonEvents
   | where Timestamp > ago(7d)
   | where not(AccountName in~ ("admin", "labuser", "root"))  
   | summarize
       FailedAttempts = countif(ActionType == "LogonFailed"),  
       SuccessfulLogins = countif(ActionType == "LogonSuccess")
     by AccountName, DeviceName, RemoteIP  
   | where FailedAttempts > 5 and SuccessfulLogins > 0;
SuspiciousLogins
```

![Screenshot 2025-01-30 133603](https://github.com/user-attachments/assets/bbb4f25a-4474-487d-919e-b1a48aee959b)

---

![Screenshot 2025-01-30 135308](https://github.com/user-attachments/assets/7f3973dc-11f9-4f44-a20c-a99d3bd6dd47)

---

## 📂 **Step 3: Investigating File Events** 🖥️  

### **🔍 What I Did:**  
🔎 Focused on **file creation, renaming, and modification** activities on the compromised device **"corpnet-1-ny"**.  
📂 **Target File Types:** `.html`, `.pdf`, `.zip`, `.txt` – likely containing **sensitive data**. 🔓📜  

🚀 **Next Move:**  
I’ll now analyze **file movement & exfiltration** attempts to determine if critical data was stolen! 🚨💾   

🔎 **Query Results Included:**  
- `python3.exe` 🐍  
- `mini-wallet.html` 💳  
- `wallet-crypto.html` 🏦  
- `wallet-buynow.html` 🛒  
- `tokenized-card.html` 🏷️  
- `wallet.html` 📂 

```kql
DeviceFileEvents
| where DeviceName == "corpnet-1-ny"  // Target the compromised machine
| where ActionType has_any ("FileCreated", "FileRenamed", "FileModified")  // Capture relevant file operations
| where RequestAccountName == "chadwick.s"  // Specify the user account
| where Timestamp >= datetime(2025-01-29 00:00:00) and Timestamp <= datetime(2025-01-29 23:59:59)  // Restrict to the given date
| project Timestamp, RequestAccountName, ActionType, FileName, DeviceName  // Select key columns
| sort by Timestamp desc  // Order by most recent activity
```  

![Screenshot 2025-01-30 142420](https://github.com/user-attachments/assets/fce8b0fa-a4e7-490a-a216-aabdf872d784)

## 🚀 **Step 4: Investigating File Events** 📝🔍  

### **🔎 What I'm Doing:**  
I leveraged **DeviceFileEvents** to monitor **file activities** such as:  
📂 **Creation**  
📝 **Renaming**  
✍️ **Modification**  

Our goal? **Identify sensitive files** that may have been accessed or tampered with during the attack! 🎯💻  

### **🛠️ Why This Matters:**  
🔐 Attackers often modify, encrypt, or exfiltrate **critical files** after gaining access.  
🚨 Tracking these events helps us pinpoint potential **data theft or unauthorized changes**.  

### **🕵️‍♂️ Key Focus Areas:**  
✅ **Timestamp Analysis** – When were the files last accessed or changed? ⏳  
✅ **File Types of Interest** – `.html`, `.pdf`, `.zip`, `.txt` (Potential sensitive data) 📂  
✅ **User Activity** – Which accounts interacted with these files? 👤  

This step brings us **one step closer** to uncovering how the attacker moved within the system! 🕵️‍♂️💡

---

```KQL
DeviceFileEvents
| where DeviceName == "corpnet-1-ny"  // Focus on the compromised machine
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")  // Filter for creation, renaming, and modification
| where RequestAccountName == "chadwick.s"  // Filter by user account
| where FileName endswith ".pdf" or FileName endswith ".zip" or FileName endswith ".txt"  // Filter by file extensions
| project Timestamp, RequestAccountName, ActionType, FileName, DeviceName  // Show relevant columns
| order by Timestamp desc  // Sort by most recent events
```

![Screenshot 2025-01-30 150649](https://github.com/user-attachments/assets/2303e5f7-2bb7-402d-a08b-dc7e59e34e57)

---

## 📂 Step 5: Detailed File Access Information

I retrieved detailed information about the accessed file. The query showed that the files was accessed on the compromised machine.

### **File Access Details:**
This confirms that the attacker **read this file** during the compromise, which is a significant clue in understanding their movements and intentions. 🔍

```kusto
DeviceEvents
| where DeviceName contains "corpnet-1-ny"  // Focus on the compromised machine
| where InitiatingProcessAccountName contains "chadwick.s"  // Filter by the account used for the attack
| where ActionType contains "SensitiveFileRead"  // Track sensitive file reads
```

![Screenshot 2025-01-30 151344](https://github.com/user-attachments/assets/4ce05550-2108-47cb-88ee-bfb54db9c4f8)

---

### 🎯 **MITRE ATT&CK Framework - "Jackal Spear" Threat Group**  

| **Tactic**              | **Technique**                                                   | **Procedure (Jackal Spear)** |
|-------------------------|-----------------------------------------------------------------|-----------------------------|
| **Initial Access**      | [T1078.003] Valid Accounts: Local Accounts                     | Used stolen credentials for direct access. |
|                         | [T1110.004] Credential Stuffing                                | Attempted multiple stolen credentials until successful authentication. |
| **Execution**           | [T1059.001] Command and Scripting Interpreter: PowerShell      | Created new local user via PowerShell. |
| **Persistence**         | [T1136.001] Create Account: Local Account                      | Created secondary user account for persistence. |
| **Privilege Escalation** | [T1548.002] Abuse Elevation Control Mechanism: Bypass UAC     | Potentially escalated privileges using admin-level execution. |
| **Defense Evasion**     | [T1070.006] Indicator Removal on Host: Timestomp              | Modified timestamps to evade detection. |
|                         | [T1027] Obfuscated Files or Information                       | Used encoded PowerShell commands. |
| **Credential Access**   | [T1555] Credentials from Password Stores                      | Attempted to retrieve credentials from local stores. |
| **Discovery**           | [T1083] File and Directory Discovery                          | Enumerated files on the compromised machine. |
|                         | [T1016] System Network Configuration Discovery                | Gathered network information about the compromised environment. |
| **Lateral Movement**    | [T1570] Lateral Tool Transfer                                 | Moved tools/files between systems. |
|                         | [T1021.001] Remote Services: Remote Desktop Protocol (RDP)   | Used RDP to pivot across systems. |
| **Collection**          | [T1560.001] Archive Collected Data: Archive via Utility       | Compressed stolen data for exfiltration. |
|                         | [T1005] Data from Local System                                | Accessed local files for sensitive data. |
| **Exfiltration**        | [T1048] Exfiltration Over Alternative Protocol                | Used non-standard channels to exfiltrate data. |
|                         | [T1567.002] Exfiltration Over Web Service                     | Uploaded stolen data to cloud-based services. |
| **Impact**              | [T1486] Data Encrypted for Impact                             | Potentially encrypted files before exfiltration. |

---

### 🔍 **Summary of Findings**  

🔴 **Compromised Device:** `corpnet-1-ny`  
🌍 **Attacker's Public IP Address:** `102.37.140.95`  
🔐 **Failed Login Attempts:** `14`  
👤 **Unauthorized Account Created:** `chadwick.s`  

📂 **Stolen Files:**  
📁 `gene_editing_papers.zip`  
📄 `"CRISPR-X: Next-Generation Gene Editing for Artificial Evolution.pdf"`  
📄 `"Genetic Drift in Hyper-Evolving Species: A Case Study.pdf"`  
📄 `"Mutagenic Pathways and Cellular Adaptation.pdf"`  
📄 `"Mutational Therapy: Theoretical Applications in Human Enhancement.pdf"`  
📄 `"Spontaneous Mutations in Simulated Microbial Ecosystems.pdf"`  

---

### 🚨 **Response Taken**  

✅ **Isolated** `corpnet-1-ny`, block IPAddress. </br>
✅ **Flagged & Investigated** unauthorized account `chadwick.s`.  
✅ **Alerted** Create Detection Rules, Setup MFA, 3 Login attempt before lockout, tell incident response teams about stolen research files.  
✅ **Preserved** Do a Vulnerability Scan, Malware scan, system logs for forensic analysis and evidence collection.  

🔎 **Next Steps:** Continue monitoring for suspicious activity, strengthen security protocols, and conduct a full forensic audit and Do a Vulnerability Scan, Malware scan. 🛡️
