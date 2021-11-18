# ADSI Queries PowerShell

## ADSISearcher

Basic usage:   
```shell
$search = [adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User))"
$search.PageSize = 10000
$users = $search.FindAll()
```

The following example searches for all computers in a different domain (with alternate credentials):   
```shell
$search = [adsisearcher]"(ObjectClass=computer)"
$domain = new-object DirectoryServices.DirectoryEntry("LDAP://192.168.1.1","targetdomain\username", "Password")
$search.searchRoot = $domain
$search.PageSize = 10000
$computers = $search.FindAll()
```

To get specific properties of the result list, get them from the resulting hashtable as follows:   
```shell
$name = @{n="Name";e={$_.properties.'name'}}
$distinguishedName = @{n="distinguishedName";e={$_.properties.'distinguishedname'}}
$operatingSystem = @{n="OperatingSystem";e={$_.properties.'operatingsystem'}}
$description = @{n="Description";e={$_.properties.'description'}}
$computers | Select-Object -Property $name, $distinguishedName, $operatingSystem, $description
```

```shell
# List User Membership
$search = [adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User)(samaccountname=vkoch))"
$users = $search.FindAll()
foreach($user in $users) {
    $CN = $user.Properties['CN']
    $DisplayName = $user.Properties['DisplayName']
    $SamAccountName = $user.Properties['SamAccountName']
    write-output "CN is $CN"
    write-output "Display Name is $DisplayName"
    write-output "SamAccountName is $SamAccountName"
    write-output "The user is member of:"$user.Properties.memberof
}
```

```shell
# Get local computers OU:
Function Get-OSCComputerOU
{
    $ComputerName = $env:computername
    $Filter = "(&(objectCategory=Computer)(Name=$ComputerName))"
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher
    $DirectorySearcher.Filter = $Filter
    $SearcherPath = $DirectorySearcher.FindOne()
    $DistinguishedName = $SearcherPath.GetDirectoryEntry().DistinguishedName
    $OUName = ($DistinguishedName.Split(","))[1]
    $OUMainName = $OUName.SubString($OUName.IndexOf("=")+1)   
    $Obj = New-Object -TypeName PSObject -Property @{"ComputerName" = $ComputerName
                                                     "BelongsToOU" = $OUMainName}
    $Obj
}
Get-OSCComputerOU
```

Get Subnet information from AD:   
```shell
([System.DirectoryServices.ActiveDirectory.Forest]::Getcurrentforest()).Sites.Subnets
```

Get all computers in the OU "server":   
```shell
(New-Object -TypeName adsisearcher -ArgumentList ([adsi]'LDAP://OU=Servers,DC=contoso,DC=com', '(objectclass=computer)')).FindAll()
```

Get accounts with "PasswordNeverExpires" into csv: (import into excel and sort out all "mailbox" accounts and such for documentation)   
```shell
$search = ([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=66048)(!userAccountControl:1.2.840.113556.1.4.803:=514))')
$search.PageSize = 10000
$userpwneverexpires = $search.FindAll()
$itemarray = @()
$outfile = "c:\users\$env:username\desktop\out.csv"
foreach($user in $userpwneverexpires) {
    $descr = $user.Properties['description']
    $SamAccountName = $user.Properties['SamAccountName']
    $distinguishedname = $user.Properties['distinguishedname']
    $data = @{
        name = $SamAccountName
        description = $descr
        distinguishedname = $distinguishedname
    }
    $itemarray += New-Object psobject -Property $data
}
$itemarray | Export-Csv -NoTypeInformation -Append $outfile -Force
```

All users not require to have a password:   
```shell
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=544))').FindAll()

```

All users with "Do not require kerberos preauthentication" enabled:   
```shell
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))').FindAll()

```

Get "PasswordNeverExpires", "Enabled" and "PasswordExpired":   
```shell
$ACCOUNTDISABLE = 0x000002
$DONT_EXPIRE_PASSWORD = 0x010000
$PASSWORD_EXPIRED = 0x800000
 
$searcher = [adsisearcher]"(&(objectClass=user)(objectCategory=person))"
$searcher.FindAll() | % {
$user = [adsi]$_.Properties.adspath[0]
New-Object -Type PSCustomObject -Property @{
SamAccountName = $user.sAMAccountName[0]
Name = $user.name[0]
Mail = $user.mail[0]
PasswordLastSet = [DateTime]::FromFileTime($_.Properties.pwdlastset[0])
Enabled = -not [bool]($user.userAccountControl[0] -band
$ACCOUNTDISABLE)
PasswordNeverExpires = [bool]($user.userAccountControl[0] -band
$DONT_EXPIRE_PASSWORD)
PasswordExpired = [bool]($user.userAccountControl[0] -band
$PASSWORD_EXPIRED)
}
}
```

All users with Logon Script field set:   
```shell
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(scriptPath=*))').FindAll()
```

Get LAPS PWs of all systems in the domain (where the user running the command has the permission):   
```shell
([adsisearcher]"((objectCategory=computer))").FindAll() | % {write-host $_.Properties['name'] "--->" $_.Properties['ms-mcs-admpwd'] }
```
Get LAPS PW of single system:   
```shell
([adsisearcher]"(&(objectCategory=computer)(name=ws1))").FindAll().Properties['ms-mcs-admpwd']
```

Get Failed logon attempts (badpwdcount):   
```shell
([adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User))").FindAll() | % {write-host $_.Properties['name'] "--->" $_.Properties['badpwdcount'] }
```
Get group membership recursively   
```shell
$findgroup = { param($groupname) ([adsisearcher]"(&(ObjectClass=Group)(CN=$groupname))").FindOne() }
$recursegroup = { param($object, $prefix="") if ($object.Properties['ObjectClass'] -notcontains "group") { Write-Verbose "NOTAGROUP"; Write-Host $prefix"-"$object.Properties['cn'] } else { Write-Verbose "AGROUP"; Write-Host $prefix $object.Properties['name']; $object.Properties['member'] | % { $recursegroup.Invoke([ADSI]"LDAP://$_", $prefix+"|") } } }
$recursegroup.Invoke($findgroup.Invoke("Domain Admins"))
```

Get trusted domains and trusted forests:   
```shell
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()
```
Get all users with DCSync permissions:   
```shell
$Root = [ADSI]"LDAP://RootDSE"
$ADObject = [ADSI]"LDAP://$($Root.rootDomainNamingContext)"
$aclObject = $ADObject.psbase.ObjectSecurity
$aclList = $aclObject.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])
$output=@()
foreach($acl in $aclList) {
$objSID = New-Object System.Security.Principal.SecurityIdentifier($acl.IdentityReference)
$info = @{
'ActiveDirectoryRights' = $acl.ActiveDirectoryRights;
'InheritanceType' = $acl.InheritanceType;
'ObjectType' = $acl.ObjectType;
'InheritedObjectType' = $acl.InheritedObjectType;
'ObjectFlags' = $acl.ObjectFlags;
'AccessControlType' = $acl.AccessControlType;
'IdentityReference' = $acl.IdentityReference;
'NTAccount' = $objSID.Translate( [System.Security.Principal.NTAccount] );
'IsInherited' = $acl.IsInherited;
'InheritanceFlags' = $acl.InheritanceFlags;
'PropagationFlags' = $acl.PropagationFlags;
}
$obj = New-Object -TypeName PSObject -Property $info
$output+=$obj
}
# list only permissions for the extendedright GUIDs for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
# see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
$output | Where-Object { ($_.ObjectType -like "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") -or ($_.ObjectType -like "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")}
```