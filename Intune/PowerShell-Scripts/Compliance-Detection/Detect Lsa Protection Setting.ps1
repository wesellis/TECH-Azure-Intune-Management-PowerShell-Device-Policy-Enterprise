<#
.SYNOPSIS
    Detect Lsa Protection Setting

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
    We Enhanced Detect Lsa Protection Setting

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
   ;  $regentry = Get-ItemProperty -Path Registry::" HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name " RunAsPPL"
        

    if ($regentry.RunAsPPL -eq 1){
        #Exit 0 for Intune if NO error
        Write-WELog " Setting is disabled!" " INFO"
        exit 0
    }
    ElseIf ($regentry.RunAsPPL -eq $null){        
        #Exit 1 for Intune if error
        Write-WELog " Registry Key does not exist!" " INFO"
        exit 1}
    else {
        #Exit 1 for Intune if error
        Write-WELog " Setting is NOT disabled!" " INFO"
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