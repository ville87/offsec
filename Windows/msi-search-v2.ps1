<# 
  Script which lists all msi files from local machine
  Original from: https://github.com/mandiant/msi-search/blob/main/msi_search.ps1
  Changed output from console to CSV file

  To look for potential MSIs where the repair function can be abused for local privesc, list the MSIs 
  using this script, run each MSI's repair function with: 
  "msiexec.exe /fa C:\Windows\Installer\[XXXXX].msi".
  Check with procmon for the MSIs which run any file as NT AUTHORITY\SYSTEM and any DLL loading from a 
  path where the user has write access (e.g. C:\Windows\Temp\xxx, C:\Users\userprofile etc)
  This would provide you with a DLL hijacking vulnerability for privesc.

#>
$folderPath = "C:\Windows\Installer"
$msiFiles = Get-ChildItem -Path $folderPath -Filter "*.msi" -File
$exportfilepath = "$env:userprofile\MSIfilelist.csv"
$MSIObj = @()
foreach ($file in $msiFiles) {
    #Write-Output "-----------------------------"
    try {
        $database = (New-Object -ComObject WindowsInstaller.Installer).OpenDatabase($file.FullName, 0)
        $view = $database.OpenView("SELECT `Value` FROM `Property` WHERE `Property`='Manufacturer'")
        $view.Execute()
        $record = $view.Fetch()
        if ($record -ne $null) {
            $manufacturer = $record.StringData(1)
            #Write-Output "Manufacturer: $manufacturer"
        }else{
            $manufacturer = "N/A"
        }
        

        $view = $database.OpenView("SELECT `Value` FROM `Property` WHERE `Property`='ProductName'")
        $view.Execute()
        $record = $view.Fetch()
        if ($record -ne $null) {
            $productName = $record.StringData(1)
            #Write-Output "ProductName: $productName"
        }else{
            $productName = "N/A"
        }
        

        $view = $database.OpenView("SELECT `Value` FROM `Property` WHERE `Property`='ProductVersion'")
        $view.Execute()
        $record = $view.Fetch()
        if ($record -ne $null) {
            $productVersion = $record.StringData(1)
            #Write-Output "ProductVersion: $productVersion"
        }else{
            $productVersion = "N/A"
        }


        $File = $($file.FullName)

        $data = [pscustomobject]@{
            Manufacturer = $manufacturer
            ProductName = $productName
            ProductVersion = $productVersion
            File = $File
        }
        $MSIObj += $data 
    
    }
    catch {
        Write-Output "Error: $($_.Exception.Message)"
    }
}
Write-Host "Found $(($MSIObj | Measure-Object).count) MSI objects. Exporting them to $exportfilepath..."
$MSIObj | Export-Csv -Path $exportfilepath