## **🛡️ Windows Investigation Cheatsheet**

## **1. User Sessions & History**

- **Find last logon times (PowerShell)**:
    
    `Get-LocalUser | Select-Object Name, LastLogon`
    
- **Find active/disconnected sessions (CMD)**:
    
    `quser`
    
- **Find a specific user's last login (CMD)**:
    
    `net user username | findstr /C:"Last logon"`
    

## **2. Privilege Escalation & Audit Logs**

- **Extract specific privilege assignment times (Event ID 4672)**:
    
    `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} | Select-Object TimeCreated, Message | Format-Table -Wrap`
    
- **Find newly installed system services (Event ID 7045 - *Catch PsExec/Backdoors*)**:
    
    `wevtutil qe System "/q:*[System[(EventID=7045)]]" /f:text | findstr /i "Date: Service"`
    
- **Check if logs were intentionally wiped (Event ID 1102)**:
    
    `wevtutil qe Security "/q:*[System[(EventID=1102)]]" /f:text | findstr /i "Date"`
    

## **3. Network Traffic Logging (Offline-Safe)**

- **Turn on boot firewall logging**:
    
    `netsh advfirewall set currentprofile logging allowedconnections enable
    netsh advfirewall set currentprofile logging filename "C:\startup_ips.log"`
    
- **Turn off firewall logging (Run after a reboot/capture)**:
    
    `netsh advfirewall set currentprofile logging allowedconnections disable`
    

## **4. Persistence & Scheduled Tasks**

- **List tasks with their execution paths**:
    
    `schtasks /query /v /fo LIST | findstr /I "TaskName: Author: Task: Run:"`
    
- **Find the exact creation date of a suspicious task file**:
    
    `dir /T:C /A "C:\Windows\System32\Tasks\TASK_NAME"`
    
- **Red flags to look for**:
    - Tasks running out of `\AppData\Local\Temp\` or `\Users\...\` instead of `\System32\`.
    - Random character names (`Update_a9f3x`) or commands hidden with `WindowStyle Hidden`.

## **5. Web Shells & DNS Hijacking**

- **Inspect the web server directory for uploaded shells (`.jsp`, `.php`, `.asp`)**:
    
    `dir C:\inetpub\wwwroot`
    
- **Check for local DNS poisoning (Hosts file modification)**:
    
    `type C:\Windows\System32\drivers\etc\hosts`
    

## **6. Firewall Backdoors**

- **List all custom firewall rules and ports**:
    
    `netsh advfirewall firewall show rule name=all | findstr /I "LocalPort Rule"`
    

---
