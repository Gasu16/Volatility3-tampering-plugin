La prima cosa da fare come modello di output è quella di mostrare a video i valori delle chiavi di registro di Windows come il TamperProtection, etc...

Prendere come spunto Downloads\userassist.py o altri plugin che operano sul registro di Windows dalla pagina github
https://github.com/volatilityfoundation/volatility3/tree/develop/volatility3/framework/plugins/windows/registry

A volatility plugin to detect MS Defender tampering attempts

What is tampering? It's an attempt to avoid detection after compromising a machine, often doing by disable  Windows Defender, this is often done by running the sc.exe command in Windows

Which OS are supported? Windows, MacOS, GNU/Linux

What are the ways to disable/tamper Windows Defender?
- collect logs (event log 5013 specifically) to detect any tampering attempts
- sc.exe query|config|stop WinDefend
- Change registry key
- Run specific software like AdvancedRun utility by Nirsoft
- taskkill command
- SystemSettingsAdminFlows.exe, a native Windows Utility to detect Defender tampering
- Via WMI tasks
- Editing/Removing files related to Windows Defender folder path
- Suddenly an entire path or drive has been added to the exclusions

Which information should be displayed? 
In order to provide a full capable investigation:
- The registry key that detects if an attempt has been made, and their value
- Learn the most common tampering techniques from MITRE ATTACK
- The tampering tentatives
- Which process attempted to run the tamper and disable MS Defender
- The timestamp
- Full path 
- Full command line of the process
- The user who invoked this process 
- The parent of the process (PPID)
- How many threads this process has
- Tokens and security context of this process
- Privileges of the process who attempted the tampering


In order to provide a fully functional plugin it should be done a little testing on Windows 10 and 11 machines, although testing it on MacOS and Linux environments
