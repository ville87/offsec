# List known TTPs for given TA
The following PowerShell script lists all known TTPs for a given TA from the MITRE CTI github repo:

```powershell
# Load the json from github: git clone https://github.com/mitre/cti/
# Change the path below to the location of the enterprise-attack.json
$ATTCK_JSON = Get-Content C:\path\to\folder\enterprise-attack.json | ConvertFrom-Json
<# Alternatively, download the json directly from github:
$ATTCK_JSON = (Invoke-WebRequest -Uri https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json).content | convertfrom-json
#>
# Define APT / Groupname to search TTPs for
$TAname = "APT31"
$ThreatActorData = $ATTCK_JSON.objects | ? { $_.type -eq "intrusion-set" -and $_.aliases -like "*$TAname*" }
if(($ThreatActorData | Measure-Object).count -gt 1){
    Write-Warning "Found more than one TA with the alias $TAname! Please check and correct the TA name and rerun script..."
}elseif(($ThreatActorData | Measure-Object).count -lt 1){
    Write-Warning "Found no TA with the alias name $TAname!"
}else{        
    # Find relationships (links between Threat Actor and Techniques)
    $RelatedTTPs = $ATTCK_JSON.objects | Where-Object { 
        $_.type -eq "relationship" -and $_.source_ref -eq $ThreatActorData.id -and $_.relationship_type -eq "uses"
    } | Select-Object -ExpandProperty target_ref

    # Extract Techniques (attack-patterns) from relationships
    $Techniques = $ATTCK_JSON.objects | Where-Object { 
        $_.id -in $RelatedTTPs -and $_.type -eq "attack-pattern"
    } | Select-Object id, name, external_references, kill_chain_phases

    # Map tactics to techniques using "kill_chain_phases"
    Write-Host "Known TTPs for $TAname`:`n"

    $Techniques | ForEach-Object { 
        $TechniqueID = if ($_.external_references) { $_.external_references[0].external_id } else { "No ID" }
        $TechniqueUrl = if ($_.external_references) { $_.external_references[0].url } else { "No url" }
        $Techniquename = $($_.name)
        # Extract the correct ATT&CK tactic name from "kill_chain_phases"
        $RelatedTacticNames = $_.kill_chain_phases | Where-Object { $_.kill_chain_name -eq "mitre-attack" } | Select-Object -ExpandProperty phase_name

        if ($RelatedTacticNames) {
            $RelatedTacticNames | ForEach-Object {
                Write-Output "$_ - $TechniqueID - $Techniquename - $TechniqueUrl"
            }
        } else {
            Write-Output "Unknown Tactic - $TechniqueID - $Techniquename - $TechniqueUrl"
        }
    }
}
```
The list will look something like this:
```
Known TTPs for APT31:

discovery - T1033 - System Owner/User Discovery - https://attack.mitre.org/techniques/T1033
resource-development - T1584.008 - Network Devices - https://attack.mitre.org/techniques/T1584/008
command-and-control - T1573.001 - Symmetric Cryptography - https://attack.mitre.org/techniques/T1573/001
initial-access - T1566.002 - Spearphishing Link - https://attack.mitre.org/techniques/T1566/002
reconnaissance - T1598.003 - Spearphishing Link - https://attack.mitre.org/techniques/T1598/003
discovery - T1082 - System Information Discovery - https://attack.mitre.org/techniques/T1082
defense-evasion - T1218.007 - Msiexec - https://attack.mitre.org/techniques/T1218/007
[...]
```