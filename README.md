# Invoke-SRUMDump
Invoke-SRUMDump is a pure PowerShell/ .Net capability that enables the dumping of the System Resource Utilization Management (SRUM) database for CSVs. The database generally contains 30 days of information that is vital to incident response and forensics. 

The database can be found on Windows 8 and newer client operating systems in [systemroot]\windows\system32\sru\. The capability has the ability to dump the database from a live system or be supplied the database and Software hive from another system. 

# Script Execution
* If wanting to dump a SRUM db from a live machine
```
PS C:\> .\git.ps1
```

2. Log into your Azure and 0365 environment, when prompted
3. Data will output to a directory on your desktop with the script name
