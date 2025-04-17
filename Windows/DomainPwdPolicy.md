# AD Domain Password Policy

In e.g. ldapsearch output, the password policy values might be displayed like that:
```
lockoutDuration: -72000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 5
maxPwdAge: -311040000000000
minPwdAge: -864000000000
minPwdLength: 10
pwdProperties: 1
pwdHistoryLength: 24
```
To translate this using PowerShell:
```powershell
# Raw values from domain policy
$lockoutDuration = -72000000000
$lockOutObservationWindow = -18000000000
$lockoutThreshold = 5
$maxPwdAge = -311040000000000
$minPwdAge = -864000000000
$minPwdLength = 10
$pwdProperties = 1
$pwdHistoryLength = 24

# Convert FILETIME durations (in 100-nanosecond units) to TimeSpan
function Convert-FileTimeToDuration($filetime) {
    return [TimeSpan]::FromTicks([int64]$filetime).Duration()
}

Write-Host "Lockout Policy"
Write-Host "Lockout Duration:              $(Convert-FileTimeToDuration $lockoutDuration)"
Write-Host "Lockout Observation Window:    $(Convert-FileTimeToDuration $lockOutObservationWindow)"
Write-Host "Lockout Threshold:             $lockoutThreshold attempts"

Write-Host "Password Age"
Write-Host "Maximum Password Age:          $(Convert-FileTimeToDuration $maxPwdAge) days"
Write-Host "Minimum Password Age:          $(Convert-FileTimeToDuration $minPwdAge) day(s)"

Write-Host "Password Requirements"
Write-Host "Minimum Password Length:       $minPwdLength characters"
Write-Host "Password Complexity Required:  $(if ($pwdProperties -band 1) {'Yes'} else {'No'})"
Write-Host "Password History Length:       $pwdHistoryLength remembered passwords"
```
