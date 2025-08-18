<#
.SYNOPSIS
    Detect Acrobat Pro 11 Flash

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
    We Enhanced Detect Acrobat Pro 11 Flash

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

$reg_path = " HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" # Enter the Registry key path.
$reg_key = " bEnableFlash" # Enter the Registry key dword name.
$reg_value = 0 # Enter the desired value to REMEDIATE the vulnerability.

try {
   ;  $regentry = Get-ItemProperty -Path Registry::$reg_path -Name $reg_key
        
    if ($regentry.$reg_key -eq 0){
        #Exit 0 for Intune if NO error
        Write-WELog " Setting is disabled! Exiting." " INFO"
        exit 0
    }
    ElseIf ($regentry.$null -eq $reg_key){        
        #Exit 1 for Intune if error
        Write-WELog " Registry Key does not exist! Exiting." " INFO"
        exit 0}
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