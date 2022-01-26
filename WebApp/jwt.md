# Testing JWT

## JWT-Tool
https://github.com/ticarpi/jwt_tool   
1. Create burp collaborator URL and add to jwtconfig.io to "httplistener" value.   
2. Run tool with: `python .\jwt_tool.py -t "https://api.website.com/api/User/13" -rh "Some-Mandatory-header: xyz" -rh "Authorization: Bearer eyJ...DDSw" -M at -cv "Some text which is in response body if successful"`   
Note: Use a GET request or figure out how to do POST requests...

## Open ID
Good explanation about the different Open ID connect flows: https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660   
