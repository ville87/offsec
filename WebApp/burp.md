# Burp Stuff

## Add Burp Cert to Systems Trust Store (Linux)
In kali, open a browser and goto http://burp to download the CA cert.   
Convert it to a crt file:   
`openssl x509 -in cacert.der -inform DER -out burp.crt`   
Copy it to the systems CA store:   
`sudo cp burp.crt /usr/local/share/ca-certificates/`   
Update cert store:   
`sudo update-ca-certificates`   
