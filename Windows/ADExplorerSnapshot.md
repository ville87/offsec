### PowerShell parsing ADExplorerSnapshot.py output
Get uac, spn, logon and pw last changed info of all users:   
```powershell
$objects = @();$ndjson | Where-Object { $_.objectCategory -like "CN=Person*"} | % { $data = [PSCustomObject]@{samaccountname = $($_.samaccountname);servicePrincipalName = "$($_.servicePrincipalName)";useraccountcontrol = "$($_.useraccountcontrol)"; created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); logonCount = $($_.logonCount); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );pwdLastSet = $( get-date ([datetime]::FromFileTime($($_.pwdLastSet))) -f "dd/MM/yyyy HH:mm" )}; $objects += $data }
```
Get all objects with "Windows*" operating systems:   
```powershell
$objects = @();$ndjson | Where-Object { $_.operatingSystem -like "Windows*"} | % { $data = [PSCustomObject]@{name = $($_.name);operatingSystem = $($_.operatingSystem);  created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );}; $objects += $data}
```
Get all objects with an SPN:   
```powershell
$objects = @();$ndjson | Where-Object { ($_.servicePrincipalName -ne $null)} | % { $data = [PSCustomObject]@{samaccname = $($_.samaccountname); servicePrincipalName = "$($_.servicePrincipalName)"; memberOf = "$($_.memberOf)";useraccountcontrol = $($_.useraccountcontrol);operatingsystem = "$($_.operatingSystem)";created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); logonCount = $($_.logonCount); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );pwdLastSet = $( get-date ([datetime]::FromFileTime($($_.pwdLastSet))) -f "dd/MM/yyyy HH:mm" )}; $objects += $data }
```
Get all subnets:   
```powershell
$subnets = $ndjson | Where-Object { $_.objectCategory -like "CN=Subnet,CN=Schema,CN=Configuration,DC=domain,DC=local"}
```
Get all LAPS managed systems:   
```powershell
$LAPSobjects = @();$ndjson | where-object { $_.'ms-mcs-AdmPwdExpirationTime' -ne $null } | % { $data = [PSCustomObject]@{samaccountname = $($_.samaccountname);useraccountcontrol = "$($_.useraccountcontrol)"; created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );operatingSystem = "$($_.operatingSystem)";memberOf = "$($_.memberOf)";description = "$($_.description)";};  $LAPSobjects += $data }
```