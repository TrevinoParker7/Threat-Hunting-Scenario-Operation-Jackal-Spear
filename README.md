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

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

---

## 💥 Step 1: Investigating Suspicious Logins

### **What We're Doing:**
We began by looking for **suspicious login activities** by querying the **DeviceLogonEvents** table. These events track successful and failed login attempts on devices. We aimed to detect any **brute-force attacks** or credential stuffing attempts.
### **The Query:**

### **KQL Code**

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

### **What it looks like in KQL**

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

## 🌍 Step 2: Identifying Egypt-Based IPs

### **What We're Doing:**
To identify **Egypt-based IPs**, we cross-referenced the IP addresses found in the logs with **publicly available IP ranges** assigned to Egypt. This is crucial because APT groups like "Jackal Spear" are known to operate from this region.

### **Why It Matters:**
By identifying the **location of IPs**, we can better understand the geographical source of the attack and check if the attack aligns with the known TTPs of the group.

---
## 📝 Step 3: Investigating File Events

### **What We're Doing:**
At this stage, we wanted to investigate **file creation**, **renaming**, and **modification** on the compromised machine **"corpnet-1-ny"**. We specifically looked for relevant files that could have been accessed or modified by the attacker, particularly focusing on file types like `.html`, `.pdf`, `.zip`, and `.txt`.
### ** KQL Code**

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

### **What it looks like in KQL**

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

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## ✅ Conclusion

By initially investigating **suspicious login attempts** using the **DeviceLogonEvents** query, and then adjusting our approach to track **file access events** using **DeviceEvents**, we successfully identified the **compromised machine** and the **sensitive file accessed** during the attack. 

This allowed us to trace the **attacker's movements** and better understand their **tactics, techniques, and procedures (TTPs)**. We now have a clearer picture of the attack and the data exfiltrated during the compromise. 🚨

---

## Response Taken

Brute force was confirmed on the endpoint `corpnet-1-ny` by the user `chadwicks and chadwick.s`. The device was isolated, IPAddress block, created a rule to detected if it happens again and manager was notified.

---

### ⚠️ Always Stay Alert! ✨

Remember, detecting and mitigating attacks like these requires constant vigilance and quick action. Stay secure! 🔐
