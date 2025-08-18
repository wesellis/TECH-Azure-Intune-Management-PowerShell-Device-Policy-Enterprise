<#
.SYNOPSIS
    Remediate Adobe Reader Javascript

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
    We Enhanced Remediate Adobe Reader Javascript

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
    New-ItemProperty -Path Registry::" HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name " bDisableJavaScript" -PropertyType " DWORD" -Value " 1" -Force
   ;  $readerreg = Get-ItemProperty -Path Registry::" HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name " bDisableJavaScript"
        
    if ($readerreg.bDisableJavaScript -eq 1){
        #Exit 0 for Intune if NO error
        Write-WELog " Successfully disabled Adobe Reader Javascript!" " INFO"
        exit 0
    }
    else {
        #Exit 1 for Intune if error
        Write-WELog " Failed to disable Adobe Reader Javascript!" " INFO"
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