# Testing JWT

## JWT-Tool
https://github.com/ticarpi/jwt_tool   
1. Create burp collaborator URL and add to jwtconfig.io to "httplistener" value.   
2. Run tool with: `python .\jwt_tool.py -t "https://api.website.com/api/User/13" -rh "Some-Mandatory-header: xyz" -rh "Authorization: Bearer eyJ...DDSw" -M at -cv "Some text which is in response body if successful"`   
Note: Use a GET request or figure out how to do POST requests...

## Open ID
Good explanation about the different Open ID connect flows: https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660   

## Decoding JWT
Decoding JWT with PowerShell:   
```
$token = "eyJ...ouI" # add JWT here
if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
#Header
$tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
#Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
#Payload
$tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
#Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
#Convert to Byte array
$tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
#Convert to string array
$tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
#Convert from JSON to PSObject
$tokobj = $tokenArray | ConvertFrom-Json
#Convert from Base64 encoded string to PSObject all at once
[System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | fl | Out-Default
return $tokobj
```
