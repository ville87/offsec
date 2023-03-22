# ADSI Queries PowerShell

## ADSISearcher
### Links
 - https://github.com/PwnDefend/Active_Directory_ADSI_Audit_Powershell/blob/main/audit_v1_wip.ps1
 - Debug Privileges ADSI Research paper: [Managing Active Directory objects with ADSI Edit](debugprivilege_adsi-edit-en-v1.1.pdf)

### Basic usage   
Search for users:   
```shell
$search = [adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User))"
$search.PageSize = 10000
$users = $search.FindAll()
```
Note: There is a more efficient way to search for users in AD, which only specifies one adsisearcher criteria:   
`$search = [adsisearcher]"(samAccountType=805306368)"`   

Search for groups:   
```shell
$objSearcher=[adsisearcher]'(&(objectCategory=group)(name=GroupNameX*))'
$objSearcher.PageSize = 10000
$groups = $objSearcher.FindAll()
```
Oneliner:
```
([adsisearcher]'(&(objectCategory=group)(name=Groupxy*))').FindAll()
```
### Different Domain Search
The following example searches for all computers in a different domain (with alternate credentials):   
```shell
$search = [adsisearcher]"(ObjectClass=computer)"
$domain = new-object DirectoryServices.DirectoryEntry("LDAP://192.168.1.1","targetdomain\username", "Password")
$search.searchRoot = $domain
$search.PageSize = 10000
$computers = $search.FindAll()
```
Find user:
```
$search = [adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User)(samaccountname=testuserabc))"
$domain = new-object DirectoryServices.DirectoryEntry("LDAP://192.168.1.1","domain.local\testuser1", "xxxxxxx")
$search.searchRoot = $domain
$user = $search.FindOne()
```
Find group:
```
$search = ([adsisearcher]"(&(objectClass=group)(CN=AD-ADMINS))")
$domain = new-object DirectoryServices.DirectoryEntry("LDAP://192.168.1.1","domain.local\testuser2", "xxxxxx")
$search.searchRoot = $domain
$group = $search.FindOne()
$group.Properties['member']
```
### Add member to group
Add group member:
```
$group = [adsi]"LDAP://192.168.1.1/CN=AD-ADMINS,OU=ADMANAGEMENT,DC=DOMAIN,DC=LOCAL""
$user = [adsi]"LDAP://192.168.1.1/CN=Wayne John,OU=Users,OU=UserAccounts,DC=DOMAIN,DC=LOCAL"
$group.add($user.path)
```

### Listing Properties
To get specific properties of the result list, get them from the resulting hashtable as follows:   
```shell
$name = @{n="Name";e={$_.properties.'name'}}
$distinguishedName = @{n="distinguishedName";e={$_.properties.'distinguishedname'}}
$operatingSystem = @{n="OperatingSystem";e={$_.properties.'operatingsystem'}}
$description = @{n="Description";e={$_.properties.'description'}}
$computers | Select-Object -Property $name, $distinguishedName, $operatingSystem, $description
```

### List Membership
```shell
# List User Membership
$search = [adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User)(samaccountname=MyUser))"
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
List all nested groups of one specific group:   
```shell
PS C:\Users\jdoe> ([ADSISEARCHER]"(&(objectCategory=Group)(memberOf:1.2.840.113556.1.4.1941:=CN=Marketing,CN=Users,DC=dumpsterfire,DC=local))").FindAll()

Path                                                          Properties
----                                                          ----------
LDAP://CN=nestedgroup1,CN=Users,DC=dumpsterfire,DC=local      {usnchanged, distinguishedname, grouptype, whencreated...
LDAP://CN=nestedgrouplevel2,CN=Users,DC=dumpsterfire,DC=local {usnchanged, distinguishedname, grouptype, whencreated...
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

Get all computers in the OU "server":   
```shell
(New-Object -TypeName adsisearcher -ArgumentList ([adsi]'LDAP://OU=Servers,DC=contoso,DC=com', '(objectclass=computer)')).FindAll()
```

Get group membership   
```
([adsisearcher]"(&(ObjectClass=Group)(CN=ADMINISTRATORS))").FindOne().Properties['member']
```
Get group membership recursively   
```shell
$findgroup = { param($groupname) ([adsisearcher]"(&(ObjectClass=Group)(CN=$groupname))").FindOne() }
$recursegroup = { param($object, $prefix="") if ($object.Properties['ObjectClass'] -notcontains "group") { Write-Verbose "NOTAGROUP"; Write-Host $prefix"-"$object.Properties['cn'] } else { Write-Verbose "AGROUP"; Write-Host $prefix $object.Properties['name']; $object.Properties['member'] | % { $recursegroup.Invoke([ADSI]"LDAP://$_", $prefix+"|") } } }
$recursegroup.Invoke($findgroup.Invoke("Domain Admins"))
```

### AD Information
Get Subnet information from AD:   
```shell
([System.DirectoryServices.ActiveDirectory.Forest]::Getcurrentforest()).Sites.Subnets
```
### User Account Control (and other stuff)
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

All users with "Do not require kerberos preauthentication" enabled (AS-REP Roasting):   
```shell
([adsisearcher]"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))").FindAll()
```
Get Kerberoastable accounts:
```shell
([adsisearcher]"(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))").FindAll()
```
Get unconstrained delegation systems:
```shell
([adsisearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))").FindAll()
```
Get constrained delegations: (Check both user and computers)
```shell
([adsisearcher]"(&(objectCategory=computer)(msds-allowedtodelegateto=*))").FindAll() | % { $_.Properties['msds-allowedtodelegateto'] }
([adsisearcher]"(&(objectCategory=user)(msds-allowedtodelegateto=*))").FindAll() | % { $_.Properties['msds-allowedtodelegateto'] }
```

No Password Required:   
`(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))`   

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

Shadow Credentials:   
`(msDS-KeyCredentialLink=*)`   

User Objects with Description:   
`(&(objectCategory=user)(description=*))`   


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

## AD UserAccountControl Values

Get uac value:   
```shell
([adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User)(samaccountname=kochv2))").Findall().Properties.useraccountcontrol
```

You might have to combine queries so that e.g. disabled accounts are not included,e.g.:   
```shell
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=66048)(!userAccountControl:1.2.840.113556.1.4.803:=514))')
```

### Values
512 - Enable Account   
514 - Disable account   
544 - Account Enabled - Require user to change password at first logon   
4096 - Workstation/server   
66048 - Enabled, password never expires   
66050 - Disabled, password never expires   
66080 - Enabled, DONT_EXPIRE_PASSWORD - PASSWD_NOTREQD   
262656 - Smart Card Logon Required   
532480 - Domain controller   

 Flag value (binary) | (decimal)	 | Description 
----------|-------------|------:	
0000000000000000000000000000000x|	1 	| Reserved, the value must always be 0
00000000000000000000000000000010|	2 	| UF_ACCOUNT_DISABLE
00000000000000000000000000000x00|	4 	 | Reserved, the value must always be 0
00000000000000000000000000001000|	8 	| UF_HOMEDIR_REQUIRED
00000000000000000000000000010000|	16 	| UF_LOCKOUT
00000000000000000000000000100000|	32 	| UF_PASSWD_NOTREQD
00000000000000000000000001000000|	64 	| UF_PASSWD_CANT_CHANGE
00000000000000000000000010000000|	128 	| UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED
00000000000000000000000x00000000|	256 	| Reserved, the value must always be 0
00000000000000000000001000000000|	512 	| UF_NORMAL_ACCOUNT
000000000000000000000x0000000000|	1024 	| Reserved, the value must always be 0
00000000000000000000100000000000|	2048 	| UF_INTERDOMAIN_TRUST_ACCOUNT
00000000000000000001000000000000|	4096 	| UF_WORKSTATION_TRUST_ACCOUNT
00000000000000000010000000000000|	8192 	|UF_SERVER_TRUST_ACCOUNT
00000000000000000x00000000000000|	16384 	| Reserved, the value must always be 0
0000000000000000x000000000000000|	32768 	| Reserved, the value must always be 0
00000000000000010000000000000000|	65536 	| UF_DONT_EXPIRE_PASSWD
00000000000000100000000000000000|	131072 	| UF_MNS_LOGON_ACCOUNT
00000000000001000000000000000000|	262144 	| UF_SMARTCARD_REQUIRED
00000000000010000000000000000000|	524288 	| UF_TRUSTED_FOR_DELEGATION
00000000000100000000000000000000|	1048576 |	 UF_NOT_DELEGATED
00000000001000000000000000000000|	2097152 |	 UF_USE_DES_KEY_ONLY
00000000010000000000000000000000|	4194304 |	 UF_DONT_REQUIRE_PREAUTH
00000000100000000000000000000000|	8388608 |	 UF_PASSWORD_EXPIRED
00000001000000000000000000000000|	16777216 |	 UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
00000010000000000000000000000000|	33554432 |	 UF_NO_AUTH_DATA_REQUIRED
00000100000000000000000000000000|	67108864 |	 UF_PARTIAL_SECRETS_ACCOUNT
0000x000000000000000000000000000|	134217728 |	 Reserved, the value must always be 0
000x0000000000000000000000000000|	268435456 | Reserved, the value must always be 0
00x00000000000000000000000000000|	536870912  | Reserved, the value must always be 0
0x000000000000000000000000000000|	1073741824 | Reserved, the value must always be 0
x0000000000000000000000000000000|	2147483648 | Reserved, the value must always be 0
