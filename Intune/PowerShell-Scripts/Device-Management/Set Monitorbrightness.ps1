<#
.SYNOPSIS
    Set Monitorbrightness

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
    We Enhanced Set Monitorbrightness

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#
    .SYNOPSIS
        Set Monitor brightness level.
        Some device models set display level to 100% during OOBE

    .NOTES
        https://techibee.com/powershell/powershell-change-monitor-brightness




$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [ValidateRange(0, 100)]
    [System.Int32] $WEBrightness = 30
)

try {
   ;  $params = @{
        Namespace   = " RootWmi"
        Class       = " WmiMonitorBrightnessMethods"
        ErrorAction = " SilentlyContinue"
    }
   ;  $WEMonitor = Get-CimInstance @params
    $WEMonitor.WmiSetBrightness(5, $WEBrightness)
    exit 0
}
catch {
    throw $_
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================