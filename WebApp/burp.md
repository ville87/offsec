# Burp Stuff

## Add Burp Cert to Systems Trust Store (Linux)
In kali, open a browser and goto http://burp to download the CA cert.   
Convert it to a crt file:   
`openssl x509 -in cacert.der -inform DER -out burp.crt`   
Copy it to the systems CA store:   
`sudo cp burp.crt /usr/local/share/ca-certificates/`   
Update cert store:   
`sudo update-ca-certificates`   

## Parsing Burp Files
If you save a bunch of burp requests as a file, the result is an XML with CDATA entries which are base64 encoded. With PowerShell you cannot unfortunately easily parse those as XML, due to the structure...
An ugly but working hack is to use string split:
```powershell
get-content .\burpresponses.txt | select-string -SimpleMatch '<response base64="true"><![CDATA[' | % { ((($_ -split "\[")[2]) -split "\]")[0] } | % { [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($_))}
``` 
## Burp Search Regexes
Search for any JSON requests which do not use Content-Type “application/json”:   
`Content-Type: (?!.*application/json).*\r\n\r\n[\[{]`   
Set Locations to Request Headers + Request Body   

Search for JSON responses which weren´t served with Content-Type “application/json”:   
`Content-Type: (?!application/(.+\+)?json).*\r\n\r\n[\[{]`   
Set Locations to Response Headers + Response Body   
 
The following regex looks for responses missing the “Cache-Control: no-store” header and filters out static files like PNG,GIF,CSS and JavaScript:   
`Cache-Control: (?!.*no-store)((.|\n)*)Content-Type: (?!((text\/css|image\/(png|gif)|application\/javascript))).*`   
Set Locations to “Response headers” only   

List all responses missing the content-security-policy header which have the content-type set to text/html:   
`^((?!.*Content-Security-Policy).*)((.|\n)*)Content-Type: (text\/html).*`   
Set Locations to “Response headers” only   

Search for POST requests which are not anything with `application/*json`:   
`(?!application/(.+\+)?json)`   
Set Location to "Request headers" only
