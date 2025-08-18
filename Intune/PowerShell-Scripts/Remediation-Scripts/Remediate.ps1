<#
.SYNOPSIS
    Remediate

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
    We Enhanced Remediate

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

$reg_path = "" # Enter the Registry key path.
$reg_key = "" # Enter the Registry key dword name.
$reg_value = 1 # Enter the desired value to remediate the vulnerability.
$reg_type = " DWORD" # Do not change unless the value is not a DWORD

try {
    # Create or update the registry key value
    New-ItemProperty -Path " Registry::$reg_path" -Name $reg_key -PropertyType $reg_type -Value $reg_value -Force
   ;  $regentry = Get-ItemProperty -Path " Registry::$reg_path" -Name $reg_key
        
    if ($regentry.$reg_key -eq $reg_value) {
        # Exit with code 0 if the setting is disabled
        Write-WELog " Setting is disabled! Exiting." " INFO"
        exit 0
    }
    ElseIf ($null -eq $regentry.$reg_key) {        
        # Exit with code 1 if the registry key does not exist
        Write-WELog " Registry key does not exist! Exiting." " INFO"
        exit 1
    }
    else {
        # Exit with code 1 if the setting is not disabled
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