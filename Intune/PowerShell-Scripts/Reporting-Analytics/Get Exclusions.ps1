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


function WE-Get-Exclusions {



$WEErrorActionPreference = "Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

function WE-Get-Exclusions {
   ;  $WEPrefs = Get-MpPreference
    $WEPrefs.ExclusionExtension | ForEach-Object { [PSCustomObject]@{ Item = $_; Type = " Extension" } }
    $WEPrefs.ExclusionProcess | ForEach-Object { [PSCustomObject]@{ Item = $_; Type = " Process" } }
    $WEPrefs.ExclusionPath | ForEach-Object { [PSCustomObject]@{ Item = $_; Type = " Path" } }
    $WEPrefs.ExclusionIpAddress | ForEach-Object { [PSCustomObject]@{ Item = $_; Type = " IpAddress" } }
}

Get-Exclusions | ConvertTo-Csv -NoTypeInformation



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================