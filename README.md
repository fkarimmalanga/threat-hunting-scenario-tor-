<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/fkarimmalanga/threat-hunting-scenario-tor-/edit/main/README.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "fatawu2025" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at ` 2025-05-06T06:43:49.6970468Z`. These events began at `2025-05-06T05:42:55.0244761Z`.

**Query used to locate events:**

```kql
//Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events
DeviceFileEvents
| where DeviceName == "fatawu-mde-test"
| where InitiatingProcessAccountName == "fatawu2025"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-05-06T05:42:55.0244761Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<![image](https://github.com/user-attachments/assets/21f4ec39-e114-4721-b707-5c1c158f1be3)
>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.1.exe". Based on the logs returned, at `2025-05-06T05:49:47.9379127Z`, an employee on the "fatawu-mde-test" device ran the file `tor-browser-windows-x86_64-portable-14.5.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

// Check DeviceProcessEvents for any signs of installation or usage
DeviceProcessEvents
| where DeviceName == "fatawu-mde-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<![image](https://github.com/user-attachments/assets/a5510d91-3128-462c-af6c-4be0b2467c87)
>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "fatawu2025" actually opened the TOR browser. There was evidence that they did open it at `2025-05-06T05:56:04.6947264Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
// check to see if there is any filename tor.exe that was executed/run
DeviceProcessEvents
| where DeviceName == "fatawu-mde-test"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<![image](https://github.com/user-attachments/assets/ede3f728-fa8b-426b-a3b7-672e7a49a942)
>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-06T05:56:37.4968955Z`, an employee on the "fatawu-mde-test" device successfully established a connection to the remote IP address `176.198.159.33` on port `9150`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\fatawu2025\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
//Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports
DeviceNetworkEvents
| where DeviceName == "fatawu-mde-test"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName  in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030" "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<![image](https://github.com/user-attachments/assets/6cde5e6e-f711-4371-aaf0-b8bb5c27e21f)
>

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-06T05:42:55.0244761Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\fatawu2025\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-06T05:49:47.9379127Z`
- **Event:** The user "fatawu2025" executed the file `tor-browser-windows-x86_64-portable-14.5.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.1.exe /S`
- **File Path:** `C:\Users\fatawu2025\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-06T05:56:04.6947264Z`
- **Event:** User "fatawu2025" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\fatawu2025\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-06T05:56:37.4968955Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9150` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\fatawu2025\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-06T05:56:30.8941375Z` - Connected to `192.129.10.18` on port `443`.
  - `2025-05-06T05:56:37.4968955Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "fatawu2025" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-06T05:42:55.0244761Z`
- **Event:** The user "fatawu2025" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\fatawu2025\Desktop\tor-shopping-list.txt`

---

## Summary

The user "faawu2025" on the "fatawu-mde-test" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `fatawu-mde-test` by the user `fatawu2025`. The device was isolated, and the user's direct manager was notified.

---
