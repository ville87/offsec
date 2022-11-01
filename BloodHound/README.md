# All Things BloodHound

## Custom Queries
You can directly download a custom queries file to your Windows box running BloodHound:   
`PS C:\> Invoke-WebRequest -Uri "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/customqueries.json" -OutFile "$env:USERPROFILE\AppData\Roaming\bloodhound\customqueries.json"`   

## Queries
Big list of queries: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md   

## AzureHound
Collect everything:   
`.\azurehound.exe -u "<user>" -p "<pw>" list --tenant "<tenantname>.onmicrosoft.com" -o output-all.json`  
Collect on specific subscription only (has to be verified, currently no data in the subscription was collected):   
`.\azurehound.exe -u "<user>" -p "<pw>" list subscriptions --subscriptionId <SPECIFIC_SUBSCRIPTION_ID> --tenant "<tenantname>.onmicrosoft.com" -o output-sub.json`  

## Random Queries
Get users which have changed the password within the last year and limit output to 50:   
`MATCH p=(n:User)-[r:MemberOf*1..]->(m:Group {name:'DOMAIN USERS@DOMAIN.LOCAL'}) WHERE n.pwdlastset > (datetime().epochseconds - (365 * 86400)) RETURN p LIMIT 50`  
