# NTLMv1
Enable logging of NTLMv1 events: 
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name AuditReceivingNTLMTraffic -Value 1 -Type DWORD
```

Collect logged events:
```powershell
$Events = Get-WinEvent -Logname security -FilterXPath "Event[System[(EventID=4624)]]and Event[EventData[Data[@Name='LmPackageName']='NTLM V1']]" | Select-Object `
@{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
@{Label='UserName';Expression={$_.Properties[5].Value}},
@{Label='WorkstationName';Expression={$_.Properties[11].Value}},
@{Label='LogonType';Expression={$_.properties[8].value}},
@{Label='ImpersonationLevel';Expression={$_.properties[20].value}}

$Events | Out-GridView
```
