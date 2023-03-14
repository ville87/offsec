# All Things BloodHound
## BloodHound & Neo4j on Linux
```
sudo apt-get install openjdk-11-jdk
sudo vi /etc/profile
# Add: 
JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
export JAVA_HOME
export JRE_HOME
export PATH
```
Download the .deb packages for Neo4j Community Edition 4.x.xx and Cypher Shell 4.x from https://neo4j.com/download-center/#community.   
Install them with:   
`sudo dpkg -i <pkg.deb>`   

Start neo4j and verify no errors appear:   
```
cd /usr/bin
./neo4j console
```
Open neo4j console in browser: http://localhost:7474   

## Python Collector 
`python3 bloodhound.py -u xxxxxx@domain.local -dc dc01.domain.local -d domain.local -ns 192.168.1.1 --dns-tcp --computerfile /home/kali/Desktop/WindowsServers_LastLogon2023_excludeDCs.txt -w 4 -c LocalAdmin,RDP,Session,LoggedOn --dns-timeout 10`   

## Tips and Tricks
In larger environments if runtime is long, run DCOnly first, afterwards run ComputerOnly

## Abusing AD Permissions
There is some documentation to be found online, about what you can do with specific permissions.    
E.g.: https://github.com/surajpkhetani/Active-Directory-Permission-Abuse   

BloodHound Abuse texts can be found here:   
https://github.com/BloodHoundAD/BloodHound/tree/master/src/components/Modals/HelpTexts   

### Notes
**GenericAll**
- Container: Does not allow to add e.g. members to groups within the container


## Custom Queries
You can directly download a custom queries file to your Windows box running BloodHound:   
`PS C:\> Invoke-WebRequest -Uri "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/customqueries.json" -OutFile "$env:USERPROFILE\AppData\Roaming\bloodhound\customqueries.json"`   

## Queries
Big list of queries: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md   
https://gist.github.com/seajaysec/a4d4a545047a51053d52cba567f78a9b

Show all groups a specific user can AddMember (might take a long time!):   
`MATCH p=((n)-[r:MemberOf|AddMember*1..]->(m:Group)) WHERE n.name =~ 'TESTUSER@DOMAIN.LOCAL' return p`   
Show all groups a specific group can AddMember:   
`MATCH p=((g)-[r:AddMember*1..]->(m:Group)) WHERE g.name =~ 'GROUPMANAGERS@DOMAIN.LOCAL' return p`   

## BloodHoundLoader
Python tool to manipulate neo4j db data: https://github.com/CompassSecurity/BloodHoundQueries/tree/master/BloodHound_Loader   
Mark list of users as owned:   
`python .\BloodHoundLoader.py --dburi bolt://localhost:7687 --dbuser neo4j --dbpassword secretpass -m o .\owned.txt`    

## Parsing neo4j JSON files
**Get pwd last set and SPNs from kerberoastable accounts**
Cypher Query to get kerberoastable accounts:
`MATCH (d:Domain {name: "SPRVP.DOM"})-[r:Contains*1..]->(u {hasspn: true}) RETURN u`   
Export to JSON (Note: Replace backslashes in JSON if necessary) and parse with PowerShell:   
```
$data = @()
$krbjson.u | % { $values = [PSCustomObject]@{
 samaccountname = $_.properties.samaccountname
 unconstraineddelegation = $_.properties.unconstraineddelegation
 spns = $_.properties.serviceprincipalnames -join ","
 pwdlastset = Get-Date -Date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(($($_.properties.pwdlastset))))) -Format "dd/MM/yyyy HH:mm"
 }
 $data += $values }
```

## AzureHound
Collect everything:   
`.\azurehound.exe -u "<user>" -p "<pw>" list --tenant "<tenantname>.onmicrosoft.com" -o output-all.json`  
Collect on specific subscription only (has to be verified, currently no data in the subscription was collected):   
`.\azurehound.exe -u "<user>" -p "<pw>" list subscriptions --subscriptionId <SPECIFIC_SUBSCRIPTION_ID> --tenant "<tenantname>.onmicrosoft.com" -o output-sub.json`  

Recommended permissions and roles for AzureHound user:   
- Directory Reader on Azure AD Tenant
- Reader on all Azure Subscriptions
- Read.All on Microsoft Graph


## Random Queries
Get users which have changed the password within the last year and limit output to 50:   
`MATCH p=(n:User)-[r:MemberOf*1..]->(m:Group {name:'DOMAIN USERS@DOMAIN.LOCAL'}) WHERE n.pwdlastset > (datetime().epochseconds - (365 * 86400)) RETURN p LIMIT 50`  

## ADExplorer
1. Make Snapshot with ADExplorer
2. dat to ndjson using ADExplorerSnapshot.py with **objects mode**: `python3 ADExplorerSnapshot.py ad-snapshot.dat -m Objects -o output-folder`  
3. use jq to parse the ndjson

**Notes**
 - pwdLastSet is a special format, convert with: `[datetime]::FromFileTime(133195491194415500)`   

### JQ Examples
`cat $ndjson | jq '.|select(.userAccountControl==[512])|{name:.userPrincipalName,UAC:.userAccountControl,logoncount:.logonCount,badPwdCount:.badPwdCount,whencreated:.whenCreated,pwdLastSet:.pwdLastSet}|select(.pwdLastSet!=[0])' | out-file .\jqparsedjson.json`   

### PowerShell parsing JQ output
Get uac, spn, logon and pw last changed info of all users:   
```
$objects = @();$ndjson | Where-Object { $_.objectCategory -like "CN=Person*"} | % { $data = [PSCustomObject]@{samaccountname = $($_.samaccountname);servicePrincipalName = "$($_.servicePrincipalName)";useraccountcontrol = "$($_.useraccountcontrol)"; created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); logonCount = $($_.logonCount); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );pwdLastSet = $( get-date ([datetime]::FromFileTime($($_.pwdLastSet))) -f "dd/MM/yyyy HH:mm" )}; $objects += $data }

```
Get all objects with "Windows*" operating systems:   
```
$objects = @();$ndjson | Where-Object { $_.operatingSystem -like "Windows*"} | % { $data = [PSCustomObject]@{name = $($_.name);operatingSystem = $($_.operatingSystem);  created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );}; $objects += $data}
```
Get all objects with an SPN:   
```
$objects = @();$ndjson | Where-Object { ($_.servicePrincipalName -ne $null)} | % { $data = [PSCustomObject]@{samaccname = $($_.samaccountname); servicePrincipalName = "$($_.servicePrincipalName)"; memberOf = "$($_.memberOf)";useraccountcontrol = $($_.useraccountcontrol);operatingsystem = "$($_.operatingSystem)";created = $(get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$($_.whencreated)")))) -Format "dd/MM/yyyy HH:mm"); logonCount = $($_.logonCount); lastLogon = $( get-date ([datetime]::FromFileTime($($_.lastLogon))) -f "dd/MM/yyyy HH:mm" );lastLogonTimestamp = $( get-date ([datetime]::FromFileTime($($_.lastLogonTimestamp))) -f "dd/MM/yyyy HH:mm" );pwdLastSet = $( get-date ([datetime]::FromFileTime($($_.pwdLastSet))) -f "dd/MM/yyyy HH:mm" )}; $objects += $data }
```
