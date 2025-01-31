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
🚀 **Management has tasked you with uncovering Indicators of Compromise (IoCs) related to "Jackal Spear."**  

🔎 **Your objectives:**  
✅ Investigate **system logs** for suspicious activity.  
✅ Identify any unauthorized **secondary accounts**.  
✅ Track **attacker movements** and map their **Tactics, Techniques, and Procedures (TTPs)**.  
✅ **Solve the challenge** by piecing together their attack pattern! 🧩  

💡 **Stay sharp! Every clue brings us closer to shutting down this APT!** 🔐🔥

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

Every login attempt leaves a trace—now it's time to connect the dots! 🧩🔎
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

## 🕵️‍♂️ **Refining the Investigation: Login Analysis** 🔍  

### **🔎 Key Investigation Steps:**  

📅 **Time Range:** Expanded to **last 7 days** to capture recent login activity. ⏳📊  

🚫 **Excluding System Accounts:** Removed `"admin"`, `"labuser"`, and `"root"` since they are not typically used by regular users. 🔒⚙️  

📌 **Failed vs. Successful Logins:** Tracked **failed login attempts** and **successful logins** for each account-device combination. 📈👤  

⚠️ **Identifying Suspicious Logins:**  
✅ Focused on accounts with **5+ failed attempts** followed by **at least one successful login**—a red flag for **brute-force attacks!** 🚨🔑  

🔍 Every login attempt tells a story. Let’s uncover the truth! 🧩🔥



![Screenshot 2025-01-30 133603](https://github.com/user-attachments/assets/bbb4f25a-4474-487d-919e-b1a48aee959b)

---

![Screenshot 2025-01-30 135308](https://github.com/user-attachments/assets/7f3973dc-11f9-4f44-a20c-a99d3bd6dd47)

---


## 🔍 **Refining Our Investigation: Login & File Events** 🚨  

### 🕵️ **Step 1: Detecting Suspicious Logins** 🔑  

📅 **Time Range:** Focused on **last 7 days** to capture recent login activity. ⏳🔍  
🚫 **Excluding System Accounts:** Removed `"admin"`, `"labuser"`, and `"root"` to filter out non-relevant logins. 🔒⚙️  
📊 **Summarizing Events:** Aggregated login attempts to count both **failed** and **successful** logins. 📈👤  
⚠️ **Red Flag:** Highlighted accounts with **5+ failed attempts** followed by **at least one successful login**, signaling **brute-force attacks!** 🚨🔐  

### 🧩 **What We Learned:**  
This query exposed devices with **repeated login failures** leading to **successful logins**, indicating a potential **credential stuffing attack** or bypass attempt. 🔥🕵️‍♂️  

---

## 🌍 **Step 2: Identifying Egypt-Based IPs** 🌐  

### **🔎 What We Did:**  
📡 **IP Cross-Check:** Compared IP addresses in logs against **publicly available Egypt-based IP ranges**. 📍  
⚠️ **Why It Matters:**  
- APT groups like **"Jackal Spear"** are known to operate from this region. 🦊💀  
- Mapping **geolocation** helps confirm the **attack’s origin** and aligns with known TTPs. 🌍  

---

## 📂 **Step 3: Investigating File Events** 🖥️  

### **🔍 What We Did:**  
🔎 Focused on **file creation, renaming, and modification** activities on the compromised device **"corpnet-1-ny"**.  
📂 **Target File Types:** `.html`, `.pdf`, `.zip`, `.txt` – likely containing **sensitive data**. 🔓📜  

🚀 **Next Move:**  
We’ll now analyze **file movement & exfiltration** attempts to determine if critical data was stolen! 🚨💾  

---

```kql
DeviceFileEvents
| where DeviceName == "corpnet-1-ny"  // Target the compromised machine
| where ActionType has_any ("FileCreated", "FileRenamed", "FileModified")  // Capture relevant file operations
| where RequestAccountName == "chadwick.s"  // Specify the user account
| where Timestamp >= datetime(2025-01-29 00:00:00) and Timestamp <= datetime(2025-01-29 23:59:59)  // Restrict to the given date
| project Timestamp, RequestAccountName, ActionType, FileName, DeviceName  // Select key columns
| sort by Timestamp desc  // Order by most recent activity
```

## 🚨 **Challenges in File Investigation** 🔍  

### **📌 What Happened:**  
I dedicated significant time analyzing **file creation & modification events**, but pinpointing the exact **malicious file** remained difficult. ❌🕵️‍♂️  

🔎 **Query Results Included:**  
- `python3.exe` 🐍  
- `mini-wallet.html` 💳  
- `wallet-crypto.html` 🏦  
- `wallet-buynow.html` 🛒  
- `tokenized-card.html` 🏷️  
- `wallet.html` 📂  

![Screenshot 2025-01-30 142420](https://github.com/user-attachments/assets/fce8b0fa-a4e7-490a-a216-aabdf872d784)

## 🚀 **Step 4: Investigating File Events** 📝🔍  

### **🔎 What We're Doing:**  
We leveraged **DeviceFileEvents** to monitor **file activities** such as:  
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

## 🔍 Step 5: Using DeviceEvents for File Access

```kusto
DeviceEvents
| where DeviceName contains "corpnet-1-ny"  // Focus on the compromised machine
| where InitiatingProcessAccountName contains "chadwick.s"  // Filter by the account used for the attack
| where ActionType contains "SensitiveFileRead"  // Track sensitive file reads
```

- `DeviceName contains "corpnet-1-ny"`: Focused on the compromised device.
- `ActionType contains "SensitiveFileRead"`: Focused on tracking when **sensitive files** are **accessed** or **read**.

![Screenshot 2025-01-30 151344](https://github.com/user-attachments/assets/4ce05550-2108-47cb-88ee-bfb54db9c4f8)

### **What We Learned:**
This query helped us identify when sensitive files were **accessed** or **read** by the attacker. Even if files were not modified, this could indicate **exfiltration** attempts.

---

## 📂 Step 6: Detailed File Access Information

### **What We're Doing:**
We retrieved detailed information about the accessed file. The query showed that the file **CRISPR-X_Next-Generation_Gene_Editing_for_Artificial_Evolution.pdf** was accessed on the compromised machine.

### **File Access Details:**
This confirms that the attacker **read this file** during the compromise, which is a significant clue in understanding their movements and intentions. 🔍

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

✅ **Isolated** `corpnet-1-ny` to halt further data exfiltration.  
✅ **Flagged & Investigated** unauthorized account `chadwick.s`.  
✅ **Alerted** Create Detection Rules,tell incident response teams about stolen research files.  
✅ **Preserved** system logs for forensic analysis and evidence collection.  

🔎 **Next Steps:** Continue monitoring for suspicious activity, strengthen security protocols, and conduct a full forensic audit. 🛡️
