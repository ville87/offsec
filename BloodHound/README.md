# All Things BloodHound

## Queries
Big list of queries: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md   

## AzureHound
Collect everything:   
`.\azurehound.exe -u "<user>" -p "<pw>" list --tenant "<tenantname>.onmicrosoft.com" -o output-all.json`  
Collect on specific subscription only (has to be verified, currently no data in the subscription was collected):   
`.\azurehound.exe -u "<user>" -p "<pw>" list subscriptions --subscriptionId <SPECIFIC_SUBSCRIPTION_ID> --tenant "<tenantname>.onmicrosoft.com" -o output-sub.json`  

