# WIP, TODO: 
# - Improve the credential handling, cause its ugly now...
$search = [adsisearcher]"(&(objectClass=DnsZone))"
$domain = new-object DirectoryServices.DirectoryEntry("LDAP://10.0.0.1","domain\username", "Password")
$search.searchRoot = $domain
$search.PageSize = 10000
$dnszoneobjects = $search.FindAll()

foreach($dnszoneobj in $dnszoneobjects){
    $dnszonepath = $dnszoneobj.path
    $dnszonesearch = [adsisearcher]"(&(objectClass=DnsZone))"
    $direntrypath = new-object DirectoryServices.DirectoryEntry("$dnszonepath","domain\username", "Password")
    $dnszonesearch.searchRoot = $direntrypath
    $dnszonesearch.PageSize = 10000
    $dnszoneentries = $dnszonesearch.FindAll()
    if($dnszoneentries.count -gt 0){
        Write-Debug "Found $($dnszoneentries.count) entries in zone $($dnszoneobj.properties.name). Exporting to JSON..."
        $zonefilename = $dnszoneobj.properties.name.Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
        $dnszoneentries | ConvertTo-Json -Depth 100 | out-file -filepath "$env:userprofile\Desktop\dnszoneentries_$zonefilename.json"
        Write-Host "DNS zone entries exported to $($env:userprofile)\Desktop\dnszoneentries_$zonefilename.json"
    }
}

# ------------------------------------------------------------
$dc = "10.0.1.10"
$username = "domain\user"
$password = "password"

$zonePath = "LDAP://$dc/DC=DomainDNSZones,DC=testlab,DC=local"
$zoneEntry = New-Object DirectoryServices.DirectoryEntry($zonePath, $username, $password)

$searcher = New-Object DirectoryServices.DirectorySearcher($zoneEntry)
$searcher.Filter = "(objectClass=dnsNode)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.Add("name") | Out-Null
$searcher.PropertiesToLoad.Add("dnsRecord") | Out-Null
$searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null

$results = $searcher.FindAll()
foreach($result in $results ){
    # Sample dnsRecord (this is the raw binary data)
    $dnsRecord = $result.Properties["dnsrecord"][0]

    # Extract the last 4 bytes (IPv4 address), which are usually the last part of an A record
    $ipAddressBytes = $dnsRecord[-4..-1]  # Get the last 4 bytes

    # Convert the byte array to a human-readable IP address
    $ipAddress = [System.Net.IPAddress]::new($ipAddressBytes)

    # Output the human-readable IP Address
    Write-Host "$($result.properties.name) has address: $ipAddress"
}
