# NMAP Reporting
Different ways to parse / report Nmap results...

## PowerShell
Get date and time of executed Nmap scans from all nmap files in local dir:   
`Get-ChildItem -Filter "*.nmap" | % {get-content $_ } | % { ($_ | Select-String -Pattern "[a-zA-Z]{3} [a-zA-Z]{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}" -all).Matches.Value}`   

## Bash
Get all hosts with any open port:   
`# awk '/open/{ print $2 }' *.gnmap | sort -u`   

Get all IPs with specific port open:   
`grep -E '445/open/tcp' nmap_service_scan_tcp.gnmap | awk '{print $2}'`   

List IPs and their open ports from greppable nmap file:   
```
NMAP_FILE=nmap_SYN_scan.gnmap
cat $NMAP_FILE | awk '{printf "%s\t", $2;
for (i=4;i<=NF;i++) {
split($i,a,"/");
if (a[2]=="open") printf ",%s",a[1];}
print ""}' |
sed -e 's/,//'
```   

Get list of IPs which have specific keyword in nmap file output (.nmap):   
`cat nmap_file.nmap | grep -E "Nmap scan report for|SMBv1" | grep -B1 SMBv1 | grep -o -E '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'`   


## nmap-parse-output
https://github.com/ernw/nmap-parse-output   

## nmaptocsv
Create CSV out of nmap scan results: https://github.com/maaaaz/nmaptocsv
`python nmaptocsv.py -x SMBClientScan.xml -f ip-port-protocol-service-version-os >> output.csv`   

## Parse Nmap output with PowerShell
Get all open ports from all nmap files:   
`PS> ls *.nmap | % { gc $_.FullName | select-string -Pattern "\b\d{1,5}\/(udp|tcp).*open\b" | % { $_.matches }| % { $_.Value } }`   

Get all IPs and their open ports from gnmap file:   
``` 
$regexIPAddress = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
$nmap = gc .\file.gnmap
foreach($line in $nmap){ 
    $affectedlinesIP = Select-String -Pattern "$regexIPAddress" -InputObject $line | % { $_.matches }| % { $_.Value }
    $affectedlinesPorts = Select-String -Pattern "[0-9]+/open/(tcp|udp)" -InputObject $line -AllMatches 
    if($affectedlinesIP.count -gt 0){
        if($affectedlinesPorts.count -gt 0){
            $ports = ($affectedlinesPorts.matches.value | % { ($_ -split "/")[0]  }) -join ","
            Write-host "$affectedlinesIP`:$ports"
        }
    } 
}
```   
