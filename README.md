<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ChavezCyberWorks/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “lacha156” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of file called “tor-shopping-list.txt” on the desktop at 2025-07-08T01:51:54.9649864Z. These events began at: 2025-07-08T01:22:33.1910021Z


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "final-threat-vm"
| where InitiatingProcessAccountName == "lacha156"
| where FileName contains "tor"
| where Timestamp >= datetime(Jul 7, 2025 6:22:33 PM)
| order by Timestamp desc 
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName


```


<img width="1239" height="958" alt="Query used to locate events " src="https://github.com/user-attachments/assets/3255f758-9fba-492a-8bae-253116b40834" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommand Line that contained the string “tor-browser-windows-x86_64-portable-14.5.4.exe”. Based on the logs returned at 2025-07-08T01:22:50.2721736Z, an employee on the “final-threat-vm” device ran the file tor-browser-windows-x86_64-portable-14.5.4.exe from their Downloads folder, using a command that triggered a silent installation.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "final-threat-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine


```
<img width="1644" height="462" alt="DeviceProcessEvents Table" src="https://github.com/user-attachments/assets/7dd21057-3d04-43e0-a9e8-9db0cbdc43da" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “lacha156” opened the tor browser. There was evidence that they did open it at 2025-07-08T01:23:30.1988974Z. There were several other instances of firefox.exe(Tor) as well as tor.exe spawned afterwards.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == “final-threat-vm”
| where FileName has_any (“tor.exe”, “firefox.exe”, “tor-browser.exe”)
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestap desc

```
<img width="1587" height="932" alt="Screenshot 2025-07-22 at 5 54 11 PM" src="https://github.com/user-attachments/assets/a9640a97-0d81-4bf6-ac86-0de5747e6eba" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using  any of the known tor port numbers. On 2025-07-08T01:34:10.592133Z an employee on the “final-threat-vm” device successfully established a connection to the remote IP address 111.69.37.214. The connection was initiated by the process tor.exe, located in the folder c:\users\lacha156\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a couple connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "final-threat-vm"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001","9030","9040","9050","9051","9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl,InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc


```
<img width="1731" height="561" alt="Screenshot 2025-07-22 at 5 57 24 PM" src="https://github.com/user-attachments/assets/97bf3c19-e8c1-45f3-8005-3908f045054d" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- Timestamp: 2025-07-08T1:22:33.1910021Z
- Event: The user “lacha156” downloaded a file named tor-browser-windows-x86_64-portable-14.5.4.exe to the desktop.
-	Action: File download detected.
-	File Path: c:\users\lacha156\desktop\tor browser\browser\torbrowser\tor\tor.exe

### 2. Process Execution - TOR Browser Installation

-	Timestamp: 2025-07-08T01:22:50.2721736Z
-	Event: User “lacha156” executed the file tor-browser-windows-x86_64-portable-14.5.4.exe
-	Action: Process creation detected.
-	Command: tor-browser-windows-x86_64-portable-14.5.4.ex /S
-	File Path: c:\users\lacha156\desktop\tor browser\browser\torbrowser\tor\tor.exe

### 3. Process Execution - TOR Browser Launch

-	Timestamp: 2025-07-08T01:23:30.1988974Z
-	Event: User “lacha156” executed the file tor-browser-windows-x86_64-portable-14.5.4.exe
-	Action: Process creation detected.
-	Command: tor-browser-windows-x86_64-portable-14.5.4.exe—silent
-	File Path: c:\users\lacha156\desktop\tor browser\browser\torbrowser\tor\tor.exe

### 4. Network Connection - TOR Network

-	Timestamp: 2025-07-08T01:34:10.592133Z
-	Event: A network connection to IP 111.69.37.214 on port 9001 by user “lacha156” was established using tor.exe, confirming Tor browser network activity.
-	Action: Connection success
-	Process: tor.exe
-	File Path: c:\users\lacha156\desktop\tor browser\browser\torbrowser\tor\tor.exe

### 5. Additional Network Connections - TOR Browser Activity

-	Timestamps:
    * 2025-07-08T01:34:11.0046439Z – Connected to 193.23.244.244 on port 443
    *	2025-07-08T01:34:14.22303Z- Local connection to 127.0.0.1 on port 9150
    *	2025-07-08T01:34:14.5706387Z – Connected to 152.53.19.3 on port 9001
    *	2025-07-08T01:34:38.8298143Z- Connected to 135.181.67.210 on port 443
    *	2025-07-08T01:34:38.8703054Z – Connected to 111.69.37.214 on port 9001
-	Event: Additional Tor network connections were established, indicating ongoing activity through the Tor browser.
- Action: Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

-	Timestamp: 2025-07-08T01:51:54.9649864Z
-	Event: User “lacha156” created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their Tor browser activities.
-	Action: File creation detected
-	File Path: C:\users\lacha156\desktop\tor-shopping-list.txt

---

## Summary

The user “lacha156” on the “final-threat-vm” device initiated and completed the installation of the Tor browser. They proceeded to launch the browser, establish connections within the Tor network, and created various files related to Tor on their desktop, including a file named tor-shopping-list.txt. This sequence of activities indicates that the user actively installed, configured, and used the Tor browser, likely for anonymous browsing purposes, with possible documentation in the form of the “shopping list” file.


---

## Response Taken

TOR usage was confirmed on endpoint final-threat-vm by the user lacha156. The device was isolated, and the user's direct manager was notified.


---
