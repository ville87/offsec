# Windows based Pentesting

## Tools
- Nmap:   
  Download https://nmap.org/dist/nmap-7.91-setup.exe   

- Crackmapexec:   
  Download and setup Python 3 from: https://www.python.org/downloads/windows/   
  Download and setup MS Build Tools for C++ from: https://visualstudio.microsoft.com/de/visual-cpp-build-tools/   
  Open cmd.exe and run:   
  `python -m pip install pipx`   
  `pipx ensurepath`  
  `pipx install crackmapexec`   
  Use CrackMapExec in cmd.exe with e.g.:   
  `cme smb 172.21.11.0/24 -u user1 -p 'password' --shares`   

- Impacket:   
  After setting up python, download the impacket repository and unpack it: https://github.com/SecureAuthCorp/impacket   
  Afterwards set up with:   
  `pip install .`   
  `pip install pyReadline`   

- Inveigh:   
  PowerShell based Responder: https://github.com/Kevin-Robertson/Inveigh   
  Note: Requires elevated privileges!   
