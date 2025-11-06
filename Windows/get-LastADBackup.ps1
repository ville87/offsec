# Script to get last AD backup time
# TODO: Port to native PowerShell ADSI
Import-Module ActiveDirectory

[string]$dnsRoot = (Get-ADDomain).DNSRoot
[string[]]$Partitions = (Get-ADRootDSE).namingContexts
$contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
$context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext($contextType,$dnsRoot)
$domainController = [System.DirectoryServices.ActiveDirectory.DomainController]::findOne($context)

ForEach($partition in $partitions)
{
   $domainControllerMetadata = $domainController.GetReplicationMetadata($partition)
   $dsaSignature = $domainControllerMetadata.Item("dsaSignature")
   Write-Host "$partition was backed up $($dsaSignature.LastOriginatingChangeTime.DateTime)`n"
}
