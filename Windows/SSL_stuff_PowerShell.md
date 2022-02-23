# Doing SSL Stuff with PowerShell
## Get Public cert of WebServer
``` 
$WebRequest = [Net.WebRequest]::Create("https://targetwebsite/")
try { $WebRequest.GetResponse() } catch { Write-Warning "Could not connect!" }
$cert = $WebRequest.ServicePoint.Certificate
$bytes = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
Set-Content -value $bytes -Encoding Byte -Path "$pwd\targetwebsite.cer"
```
