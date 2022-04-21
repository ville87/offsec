# All Kind of WMI Stuff

## Run WMI Remotely
You can run WMI commands remotely without using WinRM or PSExec:   
```
# define scriptblock to run
$SB = {
    $Folders = Get-ChildItem -Path "$env:SystemDrive\" -Directory
    $Output = "$env:TEMP\Folders_$env:UserName_$pid.csv"
    $Folders | Select-Object -Property Name, FullName, CreationTime, LastWriteTime | Export-Csv $Output -Force -NoClobber -NoTypeInformation
}
 
# encode the scriptblock
$SBString = $SB.ToString()
$SBBytes = [System.Text.Encoding]::Unicode.GetBytes($SBString)
$SBEncoded = [Convert]::ToBase64String($SBBytes)
 
# create the command to run on the target
$Command = "powershell.exe -encodedCommand $SBEncoded -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden"
 
# run the command remotely via WMI
Invoke-CimMethod -ComputerName MyServer -Namespace root\cimv2 -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$Command}
```
