<#
.SYNOPSIS
    Detect Real Time Protection Status

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
    We Enhanced Detect Real Time Protection Status

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


try {
}


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

try {
   ;  $computerstatus = Get-MpComputerStatus -ErrorAction Stop
        
    if ($computerstatus.RealTimeProtectionEnabled -eq $WETrue){
        #Exit 0 for Intune if NO error
        Write-WELog " Real-time protection status is enabled!" " INFO"
        exit 0
    }
    else {
        #Exit 1 for Intune if error
        Write-WELog " Real-time protection status is NOT enabled!" " INFO"
        exit 1
    }
}
catch {
   ;  $errMsg = $_.Exception.Message
    return $errMsg
    exit 1
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================