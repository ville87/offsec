<# 
  Script which lists all msi files from local machine
  Original from: https://github.com/mandiant/msi-search/blob/main/msi_search.ps1
  Changed output from console to CSV file
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