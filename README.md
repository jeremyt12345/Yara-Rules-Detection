# Yara-Rules-Detection
Build a YARA rule to detect a sample that uses sandbox/VM evasion, on disk and in memory


Objective: Build a YARA rule to detect a sample that uses sandbox/VM evasion, on disk and in memory

Environment. An isolated Windows analysis VM (FLARE VM via HTB Academy), HxD, and yara64.

Static analysis
Finding: The string “Sandbox detected” (hex 53616e64626f78206465746563746564) was found in C:\Samples\MalwareAnalysis\shell.exe at offset 0x2D28

<img width="1902" height="637" alt="image" src="https://github.com/user-attachments/assets/a0f6a817-8c43-4d12-be31-87b8029d1544" />


Behavior: Combined with the nearby VMware Tools registry path, this suggests the sample checks whether it’s running in a virtual machine and may change or stop its behavior to evade analysis.


Detection value: The string is unlikely to appear in legitimate software, making it a strong, low-false-positive indicator for a YARA rule.

<img width="938" height="306" alt="image" src="https://github.com/user-attachments/assets/759c174a-1bea-4ab7-b898-a6e6e7fe43f6" />


Rule Logic for what would be added to Yara Rule Detection( AI Assisted)
<img width="954" height="523" alt="image" src="https://github.com/user-attachments/assets/ce05d53c-23f6-4335-9e33-049ccee3ffbb" />





rule shell_sandbox_evasion
{
    meta:
        author      = "Jeremy Thomas"
        description = "Detects shell.exe sample using VMware sandbox evasion, fake update User-Agent, and lookalike download domain"
        date        = "2026-10-23"
        sha256      = "bd841e796feed0088ae670284ab991f212cf709f2391310a85443b2ed1312bda"




    strings:
    
        $sandbox = "Sandbox detected" ascii wide
        
        $vmware  = "SOFTWARE\\VMware, Inc.\\VMware Tools" ascii wide nocase
        
        $ua      = "Windows-Update/7.6.7600.256" ascii wide
        
        $domain  = "ms-windows-update.com" ascii wide nocase
        
        $ping    = "/k ping 127.0.0.1 -n 5" ascii wide
        
        $runkey  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase

        

    condition:
        $sandbox and 3 of ($vmware, $ua, $domain, $ping, $runkey)
}



