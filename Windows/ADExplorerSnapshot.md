### PowerShell parsing ADExplorerSnapshot.py output
First take the dat from the ADExplorer Snapshot and create an ndjson using ADExplorerSnapshot.py: `python3 ADExplorerSnapshot.py ad-snapshot.dat -o output-folder -m objects`   
Afterwards, use PowerShell to parse.

## PowerShell Examples
### Users with PW last changed
Get all users from files created by ADDumpParser (users changed their pw by month) and get their corresponding email attribute for a M365 spraying userlist:
First create the userlist files with ADDumpParser: `./ADdumpparser.sh <ADExplorer Objects dump file>.ndjson`   
```powershell
$files = Get-ChildItem ".\spraying\usernames_by_pwdLastSet_mon_*"
foreach($file in $files){
    $adusers = get-content $file.fullname
    foreach($user in $adusers){ $mail = $ndjson | Where-Object { $_.userprincipalname -like $user };write-host "MonthChanged: $((($file.name).split("."))[0] -replace "usernames_by_pwdLastSet_mon_"); UserPrincipalName: $user; Email: $($mail.mail) "}
}
```
### PKI Cert Templates
```powershell
$certtemplates = $ndjson | Where-Object { $_.objectClass -like "*pKICertificateTemplate*"}
```
### Misc
Get uac, spn, logon and pw last changed info of all users:   
```powershell
$objects = @();$ndjson | Where-Object { ($_.objectClass -like "User")} | % { $data = [PSCustomObject]@{samaccountname = $($_.samaccountname);servicePrincipalName = "$($_.servicePrincipalName)";useraccountcontrol = "$($_.useraccountcontrol)"; created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); logonCount = $($_.logonCount); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );pwdLastSet = $( get-date ([datetime]::FromFileTime($($_.pwdLastSet))) -f "dd/MM/yyyy HH:mm" )}; $objects += $data }
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
Get all enabled unconstrained delegation objects (systems and users):   
```powershell
$ndjson | ? { (($($_.userAccountControl) -band 524288) -and !($($_.userAccountControl) -band 2) ) }
```
Get all enabled unconstrained delegation objects (systems and users) EXCLUDING domain controllers:   
```powershell
$ndjson | ? { (($($_.userAccountControl) -band 524288) -and !($($_.userAccountControl) -band 2) -and ($_.distinguishedname -notmatch "OU=Domain Controllers")) }
```
Get all users with flag "this account is sensitive and cannot be delegated:   
```powershell
$ndjson | Where-Object { (($_.objectClass -like "User") -and ($($_.userAccountControl) -band 1048576) )}
```
Get all users with the flag "Store password using reversible encryption":   
```powershell
$ndjson| ? { (($($_.userAccountControl) -band 128) -and !($($_.userAccountControl) -band 2) ) }
```
## Specific stuff
### PW Spraying list (domain admins by pwdlastset month / year)
1. Export all domain admins from BloodHound into `.\domainadmins_bhexport.json`
2. Sort out all unique years for pwdlastset property from ADExplorer snapshot into `.\uniqueyears.txt`
3. Collect domain user list for pw spraying:   
```powershell
$years = get-content .\uniqueyears.txt
$domainadmins = get-content .\domainadmins_bhexport.json | ConvertFrom-Json
$domadmins = ($domainadmins.m.properties.name) | select -Unique
$domainadminsobjects = foreach($user in $domadmins){ $ndjson | Where-Object { $_.userprincipalname -like $user } }
$objects = @();$domainadminsobjects | % { $data = [PSCustomObject]@{samaccountname = $($_.samaccountname);servicePrincipalName = "$($_.servicePrincipalName)";useraccountcontrol = "$($_.useraccountcontrol)"; created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); logonCount = $($_.logonCount); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );pwdLastSet = $( get-date ([datetime]::FromFileTime($($_.pwdLastSet))) -f "dd/MM/yyyy HH:mm" )}; $objects += $data }


foreach($year in $years){
    1..12 | % { $month = "{0:00}" -f $_; $results = $objects | Where-Object { (!($($_.userAccountControl) -band 2) -and ( $_.pwdLastSet -like "*$month/$year*" ))};if(($results |Measure-Object).count -gt 0){$results | select -ExpandProperty samaccountname |out-file .\pwspray_domainadmins_$year`_$month.txt}}
}
```
