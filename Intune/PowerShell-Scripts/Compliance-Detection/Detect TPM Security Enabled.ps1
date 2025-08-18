<#
.SYNOPSIS
    Detect Tpm Security Enabled

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
    We Enhanced Detect Tpm Security Enabled

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
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
    Import-Module DellBIOSProvider
   ;  $setting = get-item -path DellSmbios:\TpmSecurity\TpmSecurity
        
    if ($setting.CurrentValue -eq " Enabled" ){
        #Exit 0 for Intune if NO error
        Write-WELog " TPM security already enabled!" " INFO"
        exit 0
    }
    else {
        #Exit 1 for Intune if error
        Write-WELog " TPM security NOT already enabled!" " INFO"
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