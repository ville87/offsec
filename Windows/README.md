# Windows based Pentesting

## Tools
- Nmap   
  Download https://nmap.org/dist/nmap-7.91-setup.exe   

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

## Helpful PowerShell commands  
### Recon
- Portscanning on single port without ping test:   
  `New-Object System.Net.Sockets.TCPClient -ArgumentList "hostname.domain.local",3389`   
