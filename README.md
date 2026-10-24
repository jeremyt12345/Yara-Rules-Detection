# Yara-Rules-Detection
Build a YARA rule to detect a sample that uses sandbox/VM evasion, on disk and in memory


Objective: Build a YARA rule to detect a sample that uses sandbox/VM evasion, on disk and in memory

Environment. An isolated Windows analysis VM (FLARE VM via HTB Academy), HxD, and yara64.

Static analysis
Finding: The string “Sandbox detected” (hex 53616e64626f78206465746563746564) was found in C:\Samples\MalwareAnalysis\shell.exe at offset 0x2D28

Behavior: Combined with the nearby VMware Tools registry path, this suggests the sample checks whether it’s running in a virtual machine and may change or stop its behavior to evade analysis.


Detection value: The string is unlikely to appear in legitimate software, making it a strong, low-false-positive indicator for a YARA rule.

Rule Logic for what would be added to Yara Rule Detection( AI Assisted)
<img width="954" height="523" alt="image" src="https://github.com/user-attachments/assets/ce05d53c-23f6-4335-9e33-049ccee3ffbb" />



