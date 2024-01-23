# Mark Of The Web (MOTW) Stuff
## Zone ID
```
(default: 3):
0: Local machine (URLZONE_LOCAL_MACHINE)
1: Local intranet (URLZONE_INTRANET)
2: Trusted sites (URLZONE_TRUSTED)
3: Internet (URLZONE_INTERNET)
4: Untrusted sites (URLZONE_UNTRUSTED)
This parameter is always set unless AppZoneId is specified.
```
## Enumerate using PowerShell
```powershell
# Check if MOTW exists
Get-Item -Force -Stream * .\Downloads\azure-cli-2.56.0-x64.msi | select Stream

Stream
------
:$DATA
Zone.Identifier

# Get all details
PS> Get-content -Force -Stream Zone.Identifier .\Downloads\azure-cli-2.56.0-x64.msi
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://learn.microsoft.com/
HostUrl=https://azcliprod.blob.core.windows.net/msi/azure-cli-2.56.0-x64.msi
```

## Set MOTW using PowerShell
```powershell
    $motw = "[ZoneTransfer]`r`n"
    $motw += "HostIpAddress=$HostIpAddress`r`n"
    $motw += "AppZoneId=$AppZoneId`r`n" # Note: Cannot be used at the same time with ZoneId
    $motw += "ZoneId=$ZoneId`r`n"
    $motw += "LastWriterPackageFamilyName=$LastWriterPackageFamilyName`r`n"
    $motw += "AppDefinedZoneId=$AppDefinedZoneId`r`n" # Note: Cannot be used at the same time with AppZoneId
    $motw += "ReferrerUrl=$ReferrerUrl`r`n"
    $motw += "HostUrl=$HostUrl`r`n"

    if ($PSVersionTable.PSVersion.Major -lt 6 -and [Console]::OutputEncoding.CodePage -eq 65001) {
        # This is necessary to write Zone.Identfier without byte order mark on the environment with UTF-8 locale and PowerShell 5 or older
        $utf8nobom = New-Object System.Text.UTF8Encoding $false
        Set-Content -ErrorVariable error -Path $filepath -Stream Zone.Identifier -Encoding Byte -NoNewline -Value $utf8nobom.GetBytes($motw)
    } else {
        Set-Content -ErrorVariable error -Path $filepath -Stream Zone.Identifier -Encoding oem -NoNewline -Value $motw
    }
```
