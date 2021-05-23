# Invoke-SRUMDump
Invoke-SRUMDump is a pure PowerShell/ .Net capability that enables the dumping of the System Resource Utilization Management (SRUM) database for CSVs. The database generally contains 30 days of information that is vital to incident response and forensics. 

The database can be found on Windows 8 and newer client operating systems in [systemroot]\windows\system32\sru\. The capability has the ability to dump the database from a live system or be supplied the database and Software hive from another system. 

# Script Execution
* Live machine:
```
PS C:\> .\Invoke-SRUMDump.ps1 -live 
```

* Offline machine:
```
PS C:\> .\Invoke-SRUMDump.ps1 -offline -srum [path to srum db] -hive [path to Software hive]

```

# References
| Title | Author | Link
| ------------- | ------------- |
| System Resource Usage Monitor (SRUM) database  | Joachim Metz | https://github.com/libyal/esedb-kb/blob/master/documentation/System%20Resource%20Usage%20Monitor%20(SRUM).asciidoc
| SRUM forensics | Yogesh Khatri  |
