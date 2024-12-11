### PowerShell parsing ADExplorerSnapshot.py output
First take the dat from the ADExplorer Snapshot and create an ndjson using ADExplorerSnapshot.py:   
`python3 ADExplorerSnapshot.py ad-snapshot.dat -o output-folder -m objects`   
Afterwards, use PowerShell to parse.   
`$ndjson = Get-Content "C:\ADExplorer_1675164450_objects.ndjson" | ConvertFrom-Json`   

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
Get uac, spn, logon and pw last changed info of all enabled users:   
```powershell
$objects = @();$ndjson | Where-Object { ($_.samAccountType -like "805306368") -and !($($_.userAccountControl) -band 2)} | %
{
    $data = [PSCustomObject]@{
        samaccountname = $($_.samaccountname);
        servicePrincipalName = "$($_.servicePrincipalName)";
        useraccountcontrol = "$($_.useraccountcontrol)";
        created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm");
        logonCount = $($_.logonCount);
        lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );
        lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );
        pwdLastSet = $( get-date ([datetime]::FromFileTime($($_.pwdLastSet))) -f "dd/MM/yyyy HH:mm" );
        adminCount = $($_.adminCount);
        distinguishedName = $($_.distinguishedName);
        memberOf = $($_.memberOf | Out-String);
    };
    $objects += $data
}
```
Get all objects with "Windows*" operating systems:   
```powershell
$windowsobjects = @();$ndjson | Where-Object { $_.operatingSystem -like "Windows*"} | % { $data = [PSCustomObject]@{name = $($_.name);description = $($_.description);operatingSystem = $($_.operatingSystem);  created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );userAccountControl = $($_.userAccountControl)}; $windowsobjects += $data}
```
Get all windows systems and include IP address from adidnsdump records.csv:    
```powershell
$dnsrecords = Import-Csv .\records.csv
$windowsobjects = @();
$ndjson | Where-Object { $_.operatingSystem -like "Windows*"} | % { 
    $name = $($_.name)
    $dnsrecord = ($dnsrecords | ? { $_.name -like $name}).value
    $data = [PSCustomObject]@{
        name = $name;
        description = $($_.description);
        operatingSystem = $($_.operatingSystem);  
        created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); 
        lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );
        lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );
        userAccountControl = $($_.userAccountControl)
        IPAddress = if($dnsrecord -notmatch "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"){"N/A"}else{$dnsrecord}
    }; 
    $windowsobjects += $data
}
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
Enum Fine Grained PW Policy stuff (TO FINISH):   
```powershell
$ndjson | ? { $_.'msDS-PSOApplied' -ne $null}
```
MachineAccountQuota:   
```
$ndjson | ? { $_.distinguishedName -like "DC=domain,DC=local" } | select ms-DS-MachineAccountQuota

ms-DS-MachineAccountQuota
-------------------------
{10}
```
### PW Spraying list (all users by pwdlastset month / year)
1. Get all enabled users with their pwdlastset:
```
$users = @();$ndjson | Where-Object { ($_.samAccountType -like "805306368") -and !($($_.userAccountControl) -band 2)} | % {
    $data = [PSCustomObject]@{
        samaccountname = $($_.samaccountname);
        pwdLastSet = $( get-date ([datetime]::FromFileTime($($_.pwdLastSet))) -f "dd/MM/yyyy HH:mm" );
    };
    $users += $data
}
```
2. Get unique years of pwdlastchanged of all users: `$uniqueyears = $users | % { (($_.pwdlastset -split "/")[2] -split " ")[0] } | select -Unique`
3. Create text files with users for relevant month & year:
```
foreach($year in $uniqueyears){
    1..12 | % { $month = "{0:00}" -f $_; $results = $users | Where-Object { ($_.pwdLastSet -like "*$month/$year*" )};if(($results |Measure-Object).count -gt 0){$results | select -ExpandProperty samaccountname |out-file .\pwspray_users_$year`_$month.txt}}
}
```

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
### Parsing DateTime values in PowerShell
If you have a specific format of a date time string, you can try to parse it using the `[datetime]` structure. Example:   
```powershell
PS> $objects[1].lastlogonTimestamp
13/03/2014 09:27
PS> [datetime]::ParseExact($objects[1].lastlogonTimestamp, 'dd/MM/yyyy HH:mm',$null)
Thursday, March 13, 2014 9:27:00 AM
```
To e.g. use this to check if the last logon was after the first of July 2023:   
```powershell
PS> ([datetime]::ParseExact($objects[1].lastlogonTimestamp, 'dd/MM/yyyy HH:mm',$null)) -gt (Get-Date 2023-07-01)
False
```
NOTE: For the 24h clock format, the datetime string format has to be defined with HH:mm and for the 12h clock format with hh:mm!   
