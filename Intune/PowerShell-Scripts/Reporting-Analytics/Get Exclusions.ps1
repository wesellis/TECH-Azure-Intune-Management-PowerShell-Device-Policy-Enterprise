<#
.SYNOPSIS
    Get Exclusions

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules
#>

<#
.SYNOPSIS
    We Enhanced Get Exclusions

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


[CmdletBinding()]
function WE-Get-Exclusions -ErrorAction Stop {



$WEErrorActionPreference = "Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
function WE-Get-Exclusions -ErrorAction Stop {
   ;  $WEPrefs = Get-MpPreference -ErrorAction Stop
    $WEPrefs.ExclusionExtension | ForEach-Object { [PSCustomObject]@{ Item = $_; Type = " Extension" } }
    $WEPrefs.ExclusionProcess | ForEach-Object { [PSCustomObject]@{ Item = $_; Type = " Process" } }
    $WEPrefs.ExclusionPath | ForEach-Object { [PSCustomObject]@{ Item = $_; Type = " Path" } }
    $WEPrefs.ExclusionIpAddress | ForEach-Object { [PSCustomObject]@{ Item = $_; Type = " IpAddress" } }
}

Get-Exclusions -ErrorAction Stop | ConvertTo-Csv -NoTypeInformation



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================