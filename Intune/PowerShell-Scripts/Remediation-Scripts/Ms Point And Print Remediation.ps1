<#
.SYNOPSIS
    Ms Point And Print Remediation

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
    We Enhanced Ms Point And Print Remediation

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
    New-ItemProperty -Path Registry::" HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name " RestrictDriverInstallationToAdministrators" -PropertyType " DWORD" -Value " 0" -Force
   ;  $regentry = Get-ItemProperty -Path Registry::" HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name " RestrictDriverInstallationToAdministrators"
        
    if ($regentry.RestrictDriverInstallationToAdministrators -eq 0){
        #Exit 0 for Intune if NO error
        Write-WELog " Setting was disabled!" " INFO"
        exit 0
    }
    ElseIf ($null -eq $regentry.RestrictDriverInstallationToAdministrators){        
        #Exit 1 for Intune if error
        Write-WELog " Registry Key does not exist!" " INFO"
        exit 1}
    else {
        #Exit 1 for Intune if error
        Write-WELog " Setting was NOT disabled!" " INFO"
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