<#
.SYNOPSIS
    Remediate Tpm Activation

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
    We Enhanced Remediate Tpm Activation

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



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
    Import-Module DellBIOSProvider
    set-item -Path DellSmbios:\TpmSecurity\TpmActivation " Enabled"
   ;  $setting = get-item -path DellSmbios:\TpmSecurity\TpmActivation
        
    if ($setting.CurrentValue -eq " Enabled" ){
        #Exit 0 for Intune if NO error
        Write-WELog " TPM activation enabled!" " INFO"
        exit 0
    }
    else {
        #Exit 1 for Intune if error
        Write-WELog " TPM activation NOT enabled!" " INFO"
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