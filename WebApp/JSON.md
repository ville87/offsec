# Testing JSON 
## JSON Requests
_Application Behavior_   
Check if the application does JSON requests with wrong content-type.   
You can check this with the search tool in burp, by using following regex:    
`Content-Type: (?!.*application/json).*\r\n\r\n[\[{]`   
Set Options:Regex and Locations:Request Headers + Request Body   

## JSON Responses
To search for JSON Responses with wrong content-type you can use the search tool in burp.   
Find JSON responses with content-type other than application/json or application/whatever+json with the following regex:   
`Content-Type: (?!application/(.+\+)?json).*\r\n\r\n[\[{]`   
Set Options:Regex and Locations:Response Headers + Response Body   
