# Windows based Pentesting

## Tools
- Nmap   
  Download https://nmap.org/dist/nmap-7.91-setup.exe   

- **PowerView**   
  Get write accessible shares:   
  `Find-DomainShare -CheckShareAccess`   
  Find accounts which have ACLs for account takeover:   
  `Get-DomainObjectAcl -SearchBase "CN=Users,DC=domain,DC=local" | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-3263068140-2042698922-2891547269-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl`   

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

## Port Forwarding on Windows
- Setup netsh based port forwarder:      
  `netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp`   
- Show port forwardings:   
  `netsh interface portproxy show v4tov4`   
- Remove:
  `netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444`   
  
