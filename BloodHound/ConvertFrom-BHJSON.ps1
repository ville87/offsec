# Taken from https://gist.github.com/martinsohn/1f3bb6960a7ec81b81a3851d377818dd
# See examples here: https://twitter.com/martinsohndk/status/1783470845119152340
# Add the below to your PowerShell profile
# 1. In PowerShell, run: Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
# 2. In PowerShell, run: if(!(Test-Path $PROFILE)){New-Item $PROFILE -ItemType File -Force}; notepad.exe $PROFILE
# 3. Add the function to your PowerShell profile
# 4. (Optional) Change the default behaviour from Clipboard to some other in 'DefaultParameterSetName'
# 5. Start a new PowerShell instance
# 6. Export JSON from BloodHound
# 7. Convert the JSON with 'ConvertFrom-BHJSON' or the alias 'cfb'

function ConvertFrom-BHJSON {

<#
.SYNOPSIS
    Converts BloodHound exported JSON to PowerShell objects

.DESCRIPTION
    ConvertFrom-BHJSON is a function that converts BloodHound exported JSON data
    into PowerShell objects for further processing. It is designed to handle JSON
    data exported from BloodHound, a tool used for analyzing Active Directory environments.

.PARAMETER JSON
    Specifies the JSON data directly as a string to be converted into PowerShell objects.

.PARAMETER Clipboard
    Indicates whether to retrieve JSON data from the clipboard. If this parameter
    is not specified, the function defaults to retrieving data from the clipboard.
    Use the -Clipboard switch to explicitly indicate retrieval from the clipboard.

.PARAMETER Downloads
    Specifies whether to retrieve JSON data from the latest BloodHound JSON file in the user's Downloads folder.
    The function looks for the latest file matching the pattern 'bh-graph*.json' which is the default name when exported from BloodHound.

.PARAMETER Path
    Specifies the path to a JSON file. The function retrieves JSON data from the specified file.

.PARAMETER FullOutput
    Indicates whether to include additional properties in the output objects.
    By default, the function returns simplified objects. Use this switch to include additional properties in the output.

.EXAMPLE
    ConvertFrom-BHJSON
    # Converts JSON data JSON stored in the clipboard (the default parameter set) into PowerShell objects

.EXAMPLE
    $jsonString | cfb
    # Using the alias, reads JSON data from a variable named jsonString by implicitly using the -JSON parameter and converts it into PowerShell objects.

.EXAMPLE
    $jsonString | ConvertFrom-BHJSON
    # Reads JSON data from a variable named jsonString by implicitly using the -JSON parameter and converts it into PowerShell objects.

.EXAMPLE
    ConvertFrom-BHJSON -Path .\Documents\bh-graph.json
    # Retrieves JSON data from a the file path .\Documents\bh-graph.json and converts it into PowerShell objects.

.INPUTS
    String

.OUTPUTS
    PSCustomObject

.NOTES
    Author: Martin Sohn Christensen
    X/Twitter: @martinsohndk
#>

    [CmdletBinding(DefaultParameterSetName = 'Clipboard')]
    [Alias("cfb")]
    param (
        [Parameter(ParameterSetName = 'Clipboard')]
        [switch]$Clipboard,
        
        [Parameter(ParameterSetName = 'Downloads')]
        [switch]$Downloads,

        [Parameter(ParameterSetName = 'JSON', ValueFromPipeline)]
        [string]$JSON,

        [Parameter(ParameterSetName = 'Path')]
        [string]$Path,

        [switch]$FullOutput
    )

    try {
        # Switch to determine the parameter set and retrieve JSON data accordingly
        switch ($PSCmdlet.ParameterSetName) {
            'Clipboard' {
                $JSONData = (Get-Clipboard | ConvertFrom-Json)
            }
            'Downloads' {
                $Path = (Join-Path -Path $env:USERPROFILE -ChildPath 'Downloads')
                $File = Get-ChildItem -LiteralPath $Path -Filter 'bh-graph*.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                $JSONData = $File | Get-Content | ConvertFrom-Json
            }
            'JSON' {
                $JSONData = $JSON | ConvertFrom-Json
            }
            'Path' {
                $JSONData = Get-Content -Path $Path | ConvertFrom-Json
            }
        }
    } catch {
        throw "Failed to retrieve or parse JSON data: $_"
    }
    
    # If the JSON data has a 'data' property, extract it. Otherwise assume the JSON is at top level
    if ($JSONData.data) {
        $JSONData = $JSONData.data
    }

    $Nodes = $JSONData.nodes
    $Edges = $JSONData.edges

    # If there are no edges, output just nodes
    if (-not $Edges) {
        if ($FullOutput) {
            Write-Output $Nodes.psobject.properties.value
        } else {
            Write-Output ($Nodes.psobject.properties.value | select -ExpandProperty label)
        }
        return
    }

    # Process each edge
    foreach ($Edge in $Edges) {
	    $Source = $Nodes.($Edge.source)
        $Target = $Nodes.($Edge.target)

        if ($FullOutput) {
            # If FullOutput is enabled, add additional properties from source and target nodes to each edge
            foreach ($prop in $source.psobject.properties) {
                $Edge | Add-Member -MemberType NoteProperty -Name ("source"+$prop.name) -Value $prop.value
            }
            foreach ($prop in $target.psobject.properties) {
                $Edge | Add-Member -MemberType NoteProperty -Name ("target"+$prop.name) -Value $prop.value
            }
        } else {
            # If FullOutput is not enabled, update source and target properties with node labels
	        $Edge.source = $Source.label
            $Edge.target = $Target.label
        }
    }

    # Output edges with or without additional properties depending on FullOutput switch
    if ($FullOutput) {
        $Edges | select -ExcludeProperty source,target,exploreGraphId,label -Property *
    } else {
        $Edges | select source,target,kind
    }
}