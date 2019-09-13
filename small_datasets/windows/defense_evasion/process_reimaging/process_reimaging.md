# Process Reimaging:
Process Reimaging is an attack technique that leverages inconsistencies in how the Windows Operating System determines process image FILE_OBJECT locations. This means that an attacker can drop a binary on disk and hide the physical location of that file by replacing its initial execution full file path with a trusted binary. , This in turn allows an adversary to bypass Windows operating system process attribute verification, hiding themselves in the context of the process image of their choosing. 

There are three stages involved in this attack:
A binary dropped to disk - This assumes breach and that the attacker can drop a binary to disk.
Undetected binary loaded. This will be the original image loaded after process creation.
The malicious binary is “reimaged” to a known good binary they’d like to appear as. This is achievable because the Virtual Address Descriptors (VADs) don’t update when the image is renamed. Consequently, this allows the wrong process image file information to be returned when queried by applications. 


## Technique(s) ID

Not yet mapped in MITRE ATT&CK

## Creators

Jonathan Johnson [@jsecurity101](https://twitter.com/jsecurity101)

## Dataset

[process_reimaging.tar.gz](./process_reimaging.tar.gz)

| Dataset Name | Data Type |
|------------|---------| 
| process_reimaging_2019-09-12174205.json | Host Data |


## Network Environment

Shire

## Time Taken

2019-09-12174205

## About this file

| log_name                                 | source_name                         | task                                                   |   record_number |
|------------------------------------------|-------------------------------------|--------------------------------------------------------|-----------------|
| Windows PowerShell                       | PowerShell                          | Pipeline Execution Details                             |              57 |
| Security                                 | Microsoft-Windows-Security-Auditing | Filtering Platform Connection                          |             114 |
| Security                                 | Microsoft-Windows-Security-Auditing | Registry                                               |              48 |
| Security                                 | Microsoft-Windows-Security-Auditing | Handle Manipulation                                    |              12 |
| Security                                 | Microsoft-Windows-Security-Auditing | Process Creation                                       |               3 |
| Security                                 | Microsoft-Windows-Security-Auditing | Process Termination                                    |               3 |
| Security                                 | Microsoft-Windows-Security-Auditing | Group Membership                                       |               2 |
| Security                                 | Microsoft-Windows-Security-Auditing | Logoff                                                 |               2 |
| Security                                 | Microsoft-Windows-Security-Auditing | Logon                                                  |               2 |
| Security                                 | Microsoft-Windows-Security-Auditing | Sensitive Privilege Use                                |               2 |
| Security                                 | Microsoft-Windows-Security-Auditing | Special Logon                                          |               2 |
| Security                                 | Microsoft-Windows-Security-Auditing | Authorization Policy Change                            |               1 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            | Process accessed (rule: ProcessAccess)                 |             994 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            | Registry object added or deleted (rule: RegistryEvent) |             737 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            | Registry value set (rule: RegistryEvent)               |             117 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            | Image loaded (rule: ImageLoad)                         |              75 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            | Network connection detected (rule: NetworkConnect)     |              27 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            | File created (rule: FileCreate)                        |              11 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            |                                                        |               5 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            | Process Create (rule: ProcessCreate)                   |               3 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            | Process terminated (rule: ProcessTerminate)            |               3 |
| Microsoft-Windows-Sysmon/Operational     | Microsoft-Windows-Sysmon            | Pipe Connected (rule: PipeEvent)                       |               1 |
| Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell        | Executing Pipeline                                     |              48 |
| Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell        | Starting Command                                       |               5 |
| Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell        | Stopping Command                                       |               5 |
| Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell        | Execute a Remote Command                               |               2 |


## Attacker Activity

```
.\CSProcessReimagingPOC.exe C:\Windows\System32\svchost.exe C:\Windows\System32\lsass.exe
```