<#
.SYNOPSIS
    Msdt Detect

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
    We Enhanced Msdt Detect

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$reg_path = " HKEY_CLASSES_ROOT\ms-msdt" # Enter the Registry key path.
try {
   ;  $regentry = Get-ItemProperty -Path Registry::$reg_path
        
    if ($regentry) {
        #Exit 0 for Intune if NO error
        Write-WELog " Setting is disabled! Exiting." " INFO"
        exit 1
    }
    ElseIf ($regentry -eq $null) {        
        #Exit 1 for Intune if error
        Write-WELog " Registry Key does not exist! Exiting." " INFO"
        exit 0
    }
    else {
        #Exit 1 for Intune if error
        Write-WELog " Setting is not disabled. Running again!" " INFO"
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