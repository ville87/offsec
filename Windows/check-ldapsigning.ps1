# Ugly PS script to check if ldap signing is enforced on domain controllers in the current domain
# 
# get all dcs in the domain
$dcs = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
# to test with the currently logged on user, env variables are being used, otherwise change this to e.g. hardcoded user
$username = "$env:userdomain\$env:username"
$credentials = new-object "System.Net.NetworkCredential" -ArgumentList $UserName,(Read-Host "Password" -AsSecureString)
# for every dc in the domain, check if you can connect with basic auth, to see if LDAP signing is enforced or not
foreach($dc in $dcs){
  $hostname = $dc.Name
  $Null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
  $LDAPConnect = New-Object System.DirectoryServices.Protocols.LdapConnection "$HostName"
  $LdapConnect.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
  $LDAPConnect.Bind($credentials)
  write-host "signing on DC $hostname`:"
	$LDAPConnect.SessionOptions.Signing
  if(($error[0] | select-string -Pattern "Strong authentication is required for this operation") -ne $null){ write-output "[OK] LDAP Signing is enforced on domain controller $hostname"} 
}
