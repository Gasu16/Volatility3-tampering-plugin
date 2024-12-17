## A volatility plugin to detect Microsoft Windows Defender tampering

### What is tampering? 
- It's a defense evasion technique accomplished by disabling or removing, even partially, defense tools such as Windows Defender or any other kind of AV/EDR/XDR platforms installed on a system

### In which ways we can disable/tamper Windows Defender?
There are many ways Defender can be tampered, most commons are:
- sc.exe query|config|stop WinDefend
- Edit registry key
- Run specific software like AdvancedRun utility by Nirsoft
- taskkill command
- SystemSettingsAdminFlows.exe, a native Windows Utility to detect Defender tampering
- Via WMI tasks
- Editing/Removing files related to Windows Defender folder path

### How Memory Forensics can help us to investigate over tampering
When it comes to EDR core business solutions like MS Defender, security specialists know that a fully functionally and up-to-date EDR is essential for the IT environment security, due to its advanced monitoring behaviour and analysis which can help to perform a quick response on the vast majority of threats.

However, Windows Defender just like others EDRs solutions are not really immune to tampering, which kinda interferee with their functionalities and even can turn off the product, allowing malware and threats to spread across the environment and increase damages to the systems such as PC clients, Servers, Mobiles, etc...

A real quick and useful move to detect if a tampering has been done is to read the correct Windows Registry values

### Usage
Tampering plugin comes with normal mode (no option, more detailed) and essential mode (through <code>--essentials</code> option) which aims to read only the essential registry keys that help to identify a tampering attempt

<code>python3 vol.py -f memdump.dmp windows.registry.tampering</code>

At this point, start to search for the registry keys changes.

An example of registry keys you can keep track of to detect if they've been edited are:


| Key name               | Default value |
| ---------------------- | ------------- |
| DisableAntiSpyware     | 0             |
| DisableAntiVirus       | 0             |
| IsServiceRunning       | 1             |
| PUAProtection          | 2             |
| TamperProtection       | 5             |
| TamperProtectionSource | 64            |


You can easily detect the most important key through the <code>--essentials</code> option like this:

<code>python3 vol.py -f memdump.dmp windows.registry.tampering --essentials</code>

### Useful links
- https://attack.mitre.org/techniques/T1562/001/
- https://cloudbrothers.info/en/edr-silencers-exploring-methods-block-edr-communication-part-1/
- https://www.alteredsecurity.com/post/disabling-tamper-protection-and-other-defender-mde-components