# Script which allows you to watch filesystem changes on a target path, even if you have absolutely no permissions.
# E.g.: If the administrator creates a file or changes the filename, it will show up in your console
Function Start-FileSystemWatcher  {
  [cmdletbinding()]
  Param (
  [parameter()]
  [string]$Path,
  [parameter()]
  <#[ValidateSet('Changed','Created','Deleted','Renamed')]#>
  [string[]]$EventName,
  [parameter()]
  [string]$Filter,
  [parameter()]
  [System.IO.NotifyFilters]$NotifyFilter,
  [parameter()]
  [switch]$Recurse,
  [parameter()]
  [scriptblock]$Action
  )
  #region Build  FileSystemWatcher
  $FileSystemWatcher  = New-Object  System.IO.FileSystemWatcher
  If (-NOT $PSBoundParameters.ContainsKey('Path')){
  $Path  = $PWD
  }
  $FileSystemWatcher.Path = $Path
  If ($PSBoundParameters.ContainsKey('Filter')) {
  $FileSystemWatcher.Filter = $Filter
  }
  If ($PSBoundParameters.ContainsKey('NotifyFilter')) {
  $FileSystemWatcher.NotifyFilter =  $NotifyFilter
  }
  If ($PSBoundParameters.ContainsKey('Recurse')) {
  $FileSystemWatcher.IncludeSubdirectories =  $True
  }
  If (-NOT $PSBoundParameters.ContainsKey('EventName')){
  $EventName  = 'Changed','Created','Deleted','Renamed'
  }
  If (-NOT $PSBoundParameters.ContainsKey('Action')){
  $Action  = {
  Switch  ($Event.SourceEventArgs.ChangeType) {
  'Renamed'  {
  $Object  = "{0} was  {1} to {2} at {3}" -f $Event.SourceArgs[-1].OldFullPath,
  $Event.SourceEventArgs.ChangeType,
  $Event.SourceArgs[-1].FullPath,
  $Event.TimeGenerated
  }
  Default  {
  $Object  = "{0} was  {1} at {2}" -f $Event.SourceEventArgs.FullPath,
  $Event.SourceEventArgs.ChangeType,
  $Event.TimeGenerated
  }
  }
  $WriteHostParams  = @{
  ForegroundColor = 'Green'
  BackgroundColor = 'Black'
  Object =  $Object
  }
  Write-Host  @WriteHostParams
  }
  }
#endregion  Build FileSystemWatcher
    #region  Initiate Jobs for FileSystemWatcher
  $ObjectEventParams  = @{
  InputObject =  $FileSystemWatcher
  Action =  $Action
  }
  ForEach  ($Item in  $EventName) {
  $ObjectEventParams.EventName = $Item
  $ObjectEventParams.SourceIdentifier =  "File.$($Item)"
  Write-Verbose  "Starting watcher for Event: $($Item)"
  $Null  = Register-ObjectEvent  @ObjectEventParams
  }
  #endregion  Initiate Jobs for FileSystemWatcher
}
