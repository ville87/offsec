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
Install daemon with `apt install daemon`   
Download the .deb packages for Neo4j Community Edition 4.x.xx and Cypher Shell 4.x from https://neo4j.com/download-center/#community.   
Install first cypher-shell and then neo4j with:   
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
Big list of queries:   
- https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md   
- https://gist.github.com/seajaysec/a4d4a545047a51053d52cba567f78a9b
- https://github.com/ZephrFish/Bloodhound-CustomQueries/blob/main/customqueries.json

Show all groups a specific user can AddMember (might take a long time!):   
`MATCH p=((n)-[r:MemberOf|AddMember*1..]->(m:Group)) WHERE n.name =~ 'TESTUSER@DOMAIN.LOCAL' return p`   
Show all groups a specific group can AddMember:   
`MATCH p=((g)-[r:AddMember*1..]->(m:Group)) WHERE g.name =~ 'GROUPMANAGERS@DOMAIN.LOCAL' return p`   
Show all local admin rights of owned users:   
`MATCH p=shortestPath((m:User {owned: TRUE})-[r:HasSession|AdminTo|MemberOf*1..]->(n:Computer)) RETURN p`   
Mark list of users as owned:   
`MATCH (n) where n.name in ["user1","user2",...] SET n.owned=true;`   
Remove all CanRDP edges:   
`MATCH ()-[r:CanRDP]->() DELETE r;`   

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
- Reader on all Azure Subscriptions (or "Reader" on the tenants "Root Management Group")
- Directory.Read.All on Microsoft Graph

### AzureHound using Refresh Token
Note: The client_id value of “1950a258-227b-4e31-a9cf-717495945fc2" is the known Azure AD PowerShell client and the same for every environment.   
First run the following code to start the auth process:   
```powershell
$body = @{
    "client_id" =     "1950a258-227b-4e31-a9cf-717495945fc2"
    "resource" =      "https://graph.microsoft.com"
}
$UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
$Headers=@{}
$Headers["User-Agent"] = $UserAgent
$authResponse = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$authResponse
```
The output should show a user_code   
Open a browser and go to: https://microsoft.com/devicelogin   
Enter the user code and complete the login.   
Now run the following code to get the Refresh Token:   
```powershell
$body=@{
    "client_id" =  "1950a258-227b-4e31-a9cf-717495945fc2"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code" =       $authResponse.device_code
}
$Tokens = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$Tokens
```
You should have a Refresh Token now.

**Running AzureHound**
You can now collect data with AzureHound using this Refresh Token:

`./azurehound -r "<refresh-token-value>" list --tenant "<domain name>" -o output.json`   

### Azure Queries
Source: https://falconforce.nl/automating-things-0x01-azurehound-for-blue-teams   
Find users who have high privileges on a subscription with their normal account   
Goal: Find all paths starting from a user that has high/owner privileges on a subscription. Exclude admin accounts.   
Option 1: Find all non-admin users that have a path to subscription ownership. Show only the first 1000 paths.   
```
MATCH p = (n:AZUser)-[*]->()-[r:AZOwns]->(g:AZSubscription)
WHERE NOT(tolower(n.userprincipalname) STARTS WITH 'admin_')
RETURN p
LIMIT 1000
```
Option 2: Find the shortest path for all non-admin users with a path to high privileges on a subscription.   
```
MATCH p = shortestpath((n:AZUser)-[*]->(g:AZSubscription))
WHERE NOT(tolower(n.userprincipalname)
STARTS WITH 'admin_')
RETURN p
```
Option 3: List all non-admin users, ordered by the number of subscriptions they have high privileges on.   
```
MATCH p = shortestpath((n:AZUser)-[*]->(g:AZSubscription))
WHERE NOT(tolower(n.userprincipalname)
STARTS WITH 'admin_')
RETURN n.userprincipalname,
COUNT(g) ORDER BY COUNT(g) DESC
```
Find apps with interesting delegated permissions   
Goal: Find all Azure apps that have access to resources which might be unexpected, due to nested group memberships.   

Option 1: Find all apps that have a path which ends in another resource with a relationship that is not “RunAs” and not “MemberOf”. These relationships can be on the path, but not at the end of the path.   
```
MATCH p = (n:AZApp)-[*]->()-[r]->(g)
WHERE any(r in relationships(p)
WHERE NOT(r:AZRunsAs)) and NOT(r:AZMemberOf)
RETURN p
LIMIT 3000
```
Option 2: The same as option 1, but for all service principals (not all apps are necessarily a service principal).   
```
MATCH p = (n:AZServicePrincipal)-[*]->()-[r]->(g)
WHERE any(r in relationships(p)
WHERE NOT(r:AZRunsAs)) and NOT(r:AZMemberOf)
RETURN p
LIMIT 3000
```
Find all VMs with a managed identity that has access to interesting resources   
Goal: Find VMs which can have a high impact in case they get compromized.   
```
MATCH p=(v:AZVM)-->(s:AZServicePrincipal)
MATCH q=shortestpath((s)-[*]->(r))
WHERE s <> r
RETURN q
```
Find shortest path from a compromized device to interesting resources   
Goal: Find a path from a compromized Azure-joined device to a resource.   
```
MATCH p = shortestpath((n:AZDevice)-[*]->(g))
WHERE n <> g
RETURN p
LIMIT 100
```
Find external user with odd permissions on Azure objects   
Goal: Find users from an external directory which have odd permissions.   
Option 1: Find external users with directly assigned permissions.   
```
MATCH p = (n:AZUser)-[r]->(g)
WHERE n.name contains "#EXT#" AND NOT(r:AZMemberOf)
RETURN n.name, COUNT(g.name), type(r), COLLECT(g.name)
ORDER BY COUNT(g.name) DESC
```
Option 2: Find external users with Owner or Contributor permissions on a subscription.   
```
MATCH (n:AZUser) WHERE n.name contains "#EXT#"
MATCH p = (n)-[*]->()-[r:AZOwns]->(g:AZSubscription)
RETURN p
```
Option 3: Find external users with generic high privileges in Azure.   
```
MATCH p = (n:AZUser)-[*]->(g)
WHERE n.name contains "#EXT#" AND any(r in relationships(p) WHERE NOT(r:AZMemberOf))
RETURN p
```
Find objects with the user administrator role   
Goal: Find any object that has indirect access to the user administrator role. Note that you can modify this role in the below queries to any other role you deem relevant.   
Option 1: Find all objects with a path to a specific role. In this case "user administrator".   
```
MATCH p = (n)-[*]->(g:AZRole)
WHERE n<>g and NOT(n:AZTenant) AND g.name starts with "USER ADMINISTRATOR"
RETURN p
```
Option 2: Find all objects, which are not users, with an indirect role assignment.
```
MATCH p = shortestpath((n)-[*]->(g:AZRole))
WHERE n<>g and NOT(n:AZTenant) AND NOT(n:AZManagementGroup) and NOT(n:AZUser)
RETURN p 
```
Option 3: The same as option 2, except we exclude directory readers, since this is a common role to have.   
```
MATCH p = shortestpath((n)-[*]->(g:AZRole))
WHERE n<>g and NOT(n:AZTenant) AND NOT(n:AZManagementGroup) and NOT(n:AZUser) and NOT(g.name starts with "DIRECTORY READERS")
RETURN p 
```
Find users with high privileges on most objects   
Goal: Identify users with high privileges (owner/contributor) on most objects (non-transitive). Find the top 100 users with most direct contributor permissions. The permission can be changed for AZOwner as well.   
```
MATCH p = (n)-[r:AZContributor]->(g)
RETURN n.name, COUNT(g)
ORDER BY COUNT(g) DESC
LIMIT 100
```
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
