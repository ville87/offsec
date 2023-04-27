# WIP, TODO: 
# - Check why so called "legacy DNS zone entries" are not found this way...
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


