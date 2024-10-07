# PowerShell Active Directory Module
## Exporting list of AD Objects
The following commands can be used to export all users, computers or service accounts from AD into CSV files.   
Note however, that there are various properties which wont be readable without further scripting (e.g. MemberOf -> `Microsoft.ActiveDirectory.Management.ADPropertyValueCollection`, ntSecurityDescriptor -> `System.DirectoryServices.ActiveDirectorySecurity` etc.)    
```powershell
Get-ADUser -Filter * -Properties * | Export-Csv -Path "$env:userprofile\Desktop\All_ADUsers.csv" -NoTypeInformation -Delimiter ";"
Get-ADComputer -Filter * -Properties * | Export-Csv -Path "$env:userprofile\Desktop\All_ADComputers.csv" -NoTypeInformation -Delimiter ";"
Get-ADServiceAccount -Filter * -Properties * | Export-Csv -Path "$env:userprofile\Desktop\All_ADSvcAccs.csv" -NoTypeInformation -Delimiter ";"
```
## Parsing Exports of AD Module
If you have a CSV file containing users exported via Get-ADUsers command, the following script can be used to parse them:   
```powershell
$users = Import-Csv .\ADUsers.csv -Delimiter ";" 
$enabledusers = $users | ? { !($($_.userAccountControl) -band 2) } 
$objects = @();$enabledusers  | % {
    $data = [PSCustomObject]@{
        samaccountname = $($_.samaccountname);
        useraccountcontrol = "$($_.useraccountcontrol)";
        created = "$($_.created)";
        createdTimeStamp = "$($_.createdTimeStamp)";
        lastLogonDate = $($_.lastLogonDate);
        lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );
        pwdLastSet = $( get-date ([datetime]::FromFileTime($($_.pwdLastSet))) -f "dd/MM/yyyy HH:mm" );
        adminCount = $($_.adminCount);
        Modified = $($_.Modified);
        modifyTimeStamp = $($_.modifyTimeStamp);
        mail = $($_.mail);
        description = $($_.description);
        title = $($_.title);
        lockedout = $($_.lockedout);
        PasswordExpired = $($_.PasswordExpired);
        DistinguishedName = $($_.DistinguishedName);
    };
    $objects += $data
}
```
If you want to quickly get lists of users who changed their password within the last 12 months:   

```powershell
$months = 1..12
$currentMonth = get-date -Format 'MM'
$currentYear = get-date -Format 'yyyy'
foreach($month in $months){
    if($month -le $currentMonth){
        $users = $objects | ? { $_.pwdlastset -match "$month/$currentYear" } 
        Write-host "Found $($users.count) users who changed their pwd in $month/$currentYear"
        $users | Export-Csv -NoTypeInformation -Delimiter ";" -Path ".\Users_changedPWD_$month`_$currentYear.csv"
    }else{
        $lastYear = $currentYear - 1
        $users = $objects | ? { $_.pwdlastset -match "$month/$lastYear" } 
        Write-host "Found $($users.count) users who changed their pwd in $month/$lastYear"
        $users | Export-Csv -NoTypeInformation -Delimiter ";" -Path ".\Users_changedPWD_$month`_$lastYear.csv"
    }
}
```
