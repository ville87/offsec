# All things about Azure

## Querying data with PowerShell

### Azure AD Roles
Get all roles and their members:   
`Get-AzureADDirectoryRole | % { $rolemembers = Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId; if($rolemembers.count -gt 0){ Write-output "`r`n`r`nMembers of $($_.DisplayName):"; $rolemembers | Get-AzureADUser } }`   

## Microsoft Graph API
Microsoft Graph API base URL: https://graph.microsoft.com   

### Linking Graph URIs and PS cmdlets
| MS Graph API | PowerShell Cmdlet|
| ------------ | ----------------- |
| /v1.0/applications | Get-AzADApplication |
| /v1.0/servicePrincipals | Get-AzADServicePrincipal |
| /v1.0/users | Get-AzADUser |
| /v1.0/servicePrincipals/{ServicePrincipalID}/appRoleAssignments | Get-AzRoleAssignment |
