# Microsoft Defender for Identity (MDI)
## Recon
### Public DNS Enumeration
You can find out if a target environment has MDI registered by checking the following two DNS entries:   
```
dig +short <azure_tenant_name>sensorapi.atp.azure.com
dig +short <azure_tenant_name>.atp.azure.com. 
```

### On-Premises
It might be possible to identify on-premises MDI by searching the description field of gMSA (group managed service accounts) objects.   
After dumping all AD objects using ADExplorer, you can generate the ndjson file using ADExplorerSnapshot.py (GitHub: c3c/ADExplorerSnapshot.py) with the -m objects method. Afterwards, the AD objects can be searched using e.g. PowerShell:   
```powershell
$ndjson = Get-Content "C:\ADExplorer_1675164450_objects.ndjson" | ConvertFrom-Json
$ndjson | Where-Object { (($_.description -like "*Defender for Identity*") -and ($_.objectCategory -like "*ms-DS-Group-Managed-Service-Account*"))}
```
