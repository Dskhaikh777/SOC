# SOC-SIEM Home Lab: Threat Detection and Incident Response

In this project, I have implemented the concept of the Security Operations Centre (SOC), simulating a real-life SOC environment. With the use of SIEM (Security Information and Event Management), I extracted logs from the Windows host and performed threat detection while learning more about the MITRE ATT&CK framework.

### Project Overview:

The main idea of this project was to create an environment similar to a SOC and understand the concept of threat detection within such infrastructure. To do that, I used Splunk as a SIEM platform and analyzed the data retrieved from the Windows host via Sysmon, Windows Event Logs, and Windows Filtering Platform to identify and document various malicious behaviors as per the MITRE ATT&CK framework.

### Lab Infrastructure:

SIEM Server: Ubuntu server (Splunk Enterprise): 192.168.239.130

Attacker Machine (Red Team): Kali Linux: 192.168.41.135

Target Machine (Blue Team): Windows 10 (Splunk Universal Forwarder, Sysmon): 192.168.239.131 (192.168.41.133)

![images/download.png](download.png)

### Tools and Technologies:

SIEM: Splunk Enterprise, Splunk Universal Forwarder, Windows Advanced Audit Policies

Endpoint Monitoring: sysmon, SwiftOnSecurity

Offensive Security Tools: CrackMapExec, Nmap, Netcat, PowerShell

### 1. Authentication Brute Force Attack (SMB)

**Purpose**: To perform a brute-force attack against the Windows SMB service and then detect this malicious activity with Splunk.

**Attack simulation (Red Team):**

I launched a brute-force attack against the Windows 10 machine (192.168.41.133) from Kali Linux (192.168.41.135). In particular, I used CrackMapExec with a custom password list to repeatedly attempt to connect to the remote machine’s Administrator account. This activity is designed to trigger the account lockout mechanism on the target system.

Command: **`crackmapexec smb 192.168.41.133 -u Administrator -p pass.txt`**

![image.png](image.png)

**Detection & Analysis (Blue Team):**
To detect the attack, I enabled the “Audit Logon Events (Failure)” security policy via the Local Security Policy (secpol.msc) UI on the target Windows machine. Then, the Universal Forwarder was used to collect the relevant logs and forward them to Splunk, where a custom search panel was created using the following query:

**SPL Query Used:**

```
index=windows EventCode=4625
| stats count by Account_Name, Source_Network_Address, ComputerName, Failure_Reason
| sort - count
| rename Account_Name as "Target User", Source_Network_Address as "Attacker IP", ComputerName as "Target Machine", Failure_Reason as "Status", count as "Total Failed Attempts"
```

I have created a search panel in Splunk that successfully detected the attacker’s IP address by analysing the failed logon attempts. Moreover, the account lockout was also properly detected, as seen in the `STATUS_ACCOUNT_LOCKED_OUT` event that occurred after 21 failed logon attempts.

![image.png](image%201.png)

### 2. Suspicious PowerShell / Outbound Network Connection (Reverse Shell)

**Purpose:** Detect unauthorized outbound network connections from native Windows binaries (Living-off-the-Land) which indicate a potential reverse shell or C2 beaconing.

**Attack simulation (Red Team):**
Set up a Netcat listener on the Kali Linux machine (Port `4444`). On the target Windows 10 machine, I executed a PowerShell command to initiate a network connection back to the attacker machine, mimicking a reverse shell payload.
*Command (Windows):* `Test-NetConnection -ComputerName 192.168.41.135 -Port 4444`

![image.png](image%202.png)

![image.png](image%203.png)

**Detection & Analysis (Blue Team):**
Sysmon was configured (using SwiftOnSecurity rules) to log process network connections (Event ID 3). The Splunk universal forwarder was shipping the logs to the SIEM.

I used the following SPL query to extract the XML event data in which the process is `powershell.exe`, the destination IP (`192.168.41.135`) is the Kali machine, and the destination port is `4444` (a non-standard port), thus raising an alert for a potentially malicious outbound connection.

**SPL Query Used:**

```
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational*" "<EventID>3</EventID>" "4444"
| rex field=_raw "<Data Name="Image">(?<Process_Name>[^<]+)</Data>"
| rex field=_raw "<Data Name="DestinationIp">(?<Attacker_IP>[^<]+)</Data>"
| rex field=_raw "<Data Name="DestinationPort">(?<Target_Port>[^<]+)</Data>"
| stats count by Process_Name, Attacker_IP, Target_Port
| rename Process_Name as "Suspicious Process", Attacker_IP as "Attacker IP", Target_Port as "Port"
```

![image.png](image%204.png)

### 3. Network Enumeration / Port Scanning (Nmap)

**Purpose:** To detect unauthorized port scanning and network enumeration attempts targeting the Windows endpoint.

**Attack simulation (Red Team):**

I have performed an attack by simulating an attacker performing network attack surface reconnaissance by conducting a TCP Connect scan (**-sT**) originating from the Kali Linux machine (**192.168.41.135**) against the Windows machine (**192.168.41.133**)
*Command:* `nmap -sT -p 1-1000 -T4 192.168.41.133`

![image.png](image%205.png)

**Detection & Analysis (Blue Team):**
In order to detect and analyze the attack, Windows Filtering Platform (WFP) logs were leveraged to capture any connection events coming into the machine.

Event ID 5156 (The Windows Filtering Platform has allowed a connection.) was constantly ingested into Splunk by using the Universal Forwarder.

By applying filters in Event Viewer on the attacker’s IP and grouping by destination ports, we can clearly see all the connection attempts and the respective ports targeted by the attacker. This query can be implemented as a correlation search to automatically detect similar anomalous behaviors and trigger an alert.

**SPL Query Used:**

```
index=windows EventCode=5156 Source_Address="192.168.41.135"
| stats count by Destination_Port, Source_Address
| sort - count
| rename Destination_Port as "Scanned Port", Source_Address as "Attacker IP", count as "Connection Attempts"
```

![image.png](image%206.png)

### **MITRE ATT&CK Mapping**

To standardize the threat hunting and incident response process, all detected malicious activities were analyzed and mapped to the relevant MITRE ATT&CK tactics and techniques:

### MITRE ATT&CK Mapping

To standardize the threat hunting and incident response process, all detected malicious activities were analyzed and mapped to the relevant MITRE ATT&CK tactics and techniques:

| Attack Scenario | MITRE Tactic | MITRE Technique (ID) |
| :--- | :--- | :--- |
| **Authentication Brute Force (SMB)** | Credential Access | Brute Force: Password Guessing (T1110.001) |
| **Suspicious PowerShell / Reverse Shell** | Execution <br> Command and Control | Command and Scripting Interpreter: PowerShell (T1059.001) <br> Non-Standard Port (T1571) |
| **Network Enumeration / Port Scan** | Discovery | Network Service Discovery (T1046) |
---
