# 🌍 Threat-Hunting-Scenario-Operation-Jackal-Spear 🦁

![DALL·E 2025-01-30 13 43 55 - A dramatic and intense cybersecurity-themed thumbnail  The background features a digital world map with South Africa and Egypt highlighted in red, sym](https://github.com/user-attachments/assets/d443fb6d-8aec-4e0c-84c5-122ba2a7b62e)


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

Recent reports reveal a newly discovered Advanced Persistent Threat (APT) group known as **"Jackal Spear,"** originating from South Africa and occasionally operating in Egypt. This group has been targeting large corporations using **spear-phishing campaigns** and **credential stuffing attacks**. By exploiting stolen credentials, they can gain access to systems with minimal login attempts.

Their primary targets are **executives**. Once they successfully compromise an account, they establish persistence by creating a secondary account on the same system with a similar username. This new account is then used to exfiltrate sensitive data while avoiding detection. 🚨

## 🎯 Your Mission:
Management has tasked you with identifying **Indicators of Compromise (IoCs)** related to this South African/Egyptian APT within our systems. If you find any IoCs, conduct a thorough investigation to track the attacker’s movements and piece together their tactics, techniques, and procedures (TTPs) until you’ve “solved the challenge.” 🔍

### High-Level Related IoC Discovery Plan

- **Check `DeviceProcessEvents`** for any New-LocalUser
- **Check `DeviceLogonEvents`** 
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

## 💥 Step 1: Investigating Suspicious Logins

We began by looking for **suspicious login activities** by querying the **DeviceLogonEvents** table. These events track successful and failed login attempts on devices. We aimed to detect any **brute-force attacks** or credential stuffing attempts.

---
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("New-LocalUser")
| project DeviceName, AccountName, ProcessCommandLine
```
---

![Screenshot 2025-01-30 182243](https://github.com/user-attachments/assets/2a3368d7-d258-4390-a75a-716a65d2aaa6)

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

- **Time Range**: We expanded the time range to the **last 7 days** to capture recent login attempts.
- **Excluding System Accounts**: We excluded **system accounts** such as `"admin"`, `"labuser"`, and `"root"`, since these accounts are typically not used by regular users and may not be relevant to our investigation.
- **Failed and Successful Logins**: We counted the number of **failed logins** and **successful logins** for each account and device combination.
- **Filter Suspicious Logins**: We looked for accounts with **more than 5 failed attempts** followed by at least one successful login. This pattern suggests a **brute-force attack**.

![Screenshot 2025-01-30 133603](https://github.com/user-attachments/assets/bbb4f25a-4474-487d-919e-b1a48aee959b)

---

![Screenshot 2025-01-30 135308](https://github.com/user-attachments/assets/7f3973dc-11f9-4f44-a20c-a99d3bd6dd47)

---

### **Breakdown of the Code:**
- `Timestamp > ago(30d)`: Focused on the past **7 days** to capture recent events.
- `where not(AccountName in ("admin", "labuser", "root"))`: Filtered out system accounts.
- `summarize`: Aggregated the login attempts to count the number of failed and successful logins.
- `where FailedAttempts > 5 and SuccessfulLogins > 0`: We focused on accounts with **multiple failed attempts** and **at least one successful login**.

### **What We Learned:**
This query helped us identify devices that had frequent **login failures** followed by **successful logins**, suggesting a possible **brute-force attack** or attempt to bypass authentication systems.

---

## 🌍 Step 3: Identifying Egypt-Based IPs

### **What We're Doing:**
To identify **Egypt-based IPs**, we cross-referenced the IP addresses found in the logs with **publicly available IP ranges** assigned to Egypt. This is crucial because APT groups like "Jackal Spear" are known to operate from this region.

### **Why It Matters:**
By identifying the **location of IPs**, we can better understand the geographical source of the attack and check if the attack aligns with the known TTPs of the group.

---
## 📝 Step 3: Investigating File Events

At this stage, we wanted to investigate **file creation**, **renaming**, and **modification** on the compromised machine **"corpnet-1-ny"**. We specifically looked for relevant files that could have been accessed or modified by the attacker, particularly focusing on file types like `.html`, `.pdf`, `.zip`, and `.txt`.


```kql
DeviceFileEvents
| where DeviceName == "corpnet-1-ny"  // Target the compromised machine
| where ActionType has_any ("FileCreated", "FileRenamed", "FileModified")  // Capture relevant file operations
| where RequestAccountName == "chadwick.s"  // Specify the user account
| where Timestamp >= datetime(2025-01-29 00:00:00) and Timestamp <= datetime(2025-01-29 23:59:59)  // Restrict to the given date
| project Timestamp, RequestAccountName, ActionType, FileName, DeviceName  // Select key columns
| sort by Timestamp desc  // Order by most recent activity
```
### **What Happened:**
I spent a significant amount of time here trying to search through the file creation and modification events. The results from the query showed numerous files being created and modified, but it was **difficult to pinpoint** the exact file relevant to the attack. The query returned a list of files like:

- `python3.exe`
- `mini-wallet.html`
- `wallet-crypto.html`
- `wallet-buynow.html`
- `tokenized-card.html`
- `wallet.html`

While these files were being created and modified, I was unable to identify a specific one that stood out as suspicious or tied to the **exfiltration** or **malicious activity** directly. At this stage, I couldn't conclusively link any of these files to the attacker's movements, which made it challenging to identify the exact files of interest. 

**Here’s what I encountered**:
- The **file names** didn’t directly hint at any sensitive information or key files, which made it hard to identify what had been accessed.
- It was a time-consuming process, manually reviewing and analyzing the files involved, without finding a concrete match. 🔍

### **Key Challenge:**
Even though I had a detailed log of file modifications, I couldn't narrow it down to the specific **exfiltrated files** or those **directly related** to the attack. This required a further adjustment of our investigation approach in later steps. 🧠

**Screenshot of the query results**:

![Screenshot 2025-01-30 142420](https://github.com/user-attachments/assets/fce8b0fa-a4e7-490a-a216-aabdf872d784)

## 📝 Step 4: Investigating File Events

### **What We're Doing:**
We used **DeviceFileEvents** to track file activities such as **creation**, **renaming**, or **modification** on the compromised machine. This is to identify any **sensitive files** that were altered or created during the attack.

### **The Query:**

### **KQL Code**

```KQL
DeviceFileEvents
| where DeviceName == "corpnet-1-ny"  // Focus on the compromised machine
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")  // Filter for creation, renaming, and modification
| where RequestAccountName == "chadwick.s"  // Filter by user account
| where FileName endswith ".pdf" or FileName endswith ".zip" or FileName endswith ".txt"  // Filter by file extensions
| project Timestamp, RequestAccountName, ActionType, FileName, DeviceName  // Show relevant columns
| order by Timestamp desc  // Sort by most recent events
```
The query tracked file events on the compromised machine **"corpnet-1-ny"**. We filtered by file extensions (e.g., `.pdf`, `.zip`, `.txt`) to identify relevant files that could contain sensitive data.


![Screenshot 2025-01-30 150649](https://github.com/user-attachments/assets/2303e5f7-2bb7-402d-a08b-dc7e59e34e57)

### **Breakdown of the Code:**
- `DeviceName == "corpnet-1-ny"`: Focused the query on the compromised device.
- `ActionType in ("FileCreated", "FileRenamed", "FileModified")`: Filtered for file creation, renaming, or modification events.
- `where FileName endswith ".pdf" or FileName endswith ".zip" or FileName endswith ".txt"`: Focused on specific file types that are commonly associated with sensitive data.
- `order by Timestamp desc`: Sorted the results by **most recent events**.

### **What Happened:**
Unfortunately, this query didn’t show the specific **.pdf** file we were looking for because **file access** (reads or exfiltrations) wasn't captured by this query. We needed to adjust our approach to track **file access events** instead.

---

## 🔍 Step 5: Using DeviceEvents for File Access

### **What We're Doing:**
Since **file modification** wasn’t captured, we switched to **DeviceEvents**, which can track **file access** events (such as **reads**), which are critical for detecting unauthorized access or exfiltration.

### **The Query:**
We focused on events that track sensitive file **reads** (file access):

### **KQL Code**

```kusto
DeviceEvents
| where DeviceName contains "corpnet-1-ny"  // Focus on the compromised machine
| where InitiatingProcessAccountName contains "chadwick.s"  // Filter by the account used for the attack
| where ActionType contains "SensitiveFileRead"  // Track sensitive file reads
```

- `DeviceName contains "corpnet-1-ny"`: Focused on the compromised device.
- `ActionType contains "SensitiveFileRead"`: Focused on tracking when **sensitive files** are **accessed** or **read**.

### **What it looks like in KQL**
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

## ✅ Conclusion

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
✅ **Alerted** incident response teams about stolen research files.  
✅ **Preserved** Create A Rule for detection,system logs for forensic analysis and evidence collection.  

🔎 **Next Steps:** Continue monitoring for suspicious activity, strengthen security protocols, and conduct a full forensic audit. 🛡️
