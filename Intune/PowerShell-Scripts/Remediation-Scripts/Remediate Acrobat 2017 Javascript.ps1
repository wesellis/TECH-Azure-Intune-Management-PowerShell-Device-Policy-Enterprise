<#
.SYNOPSIS
    Remediate Acrobat 2017 Javascript

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
    We Enhanced Remediate Acrobat 2017 Javascript

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

$reg_path = " HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\2017\FeatureLockDown" # Enter the Registry key path. Remove <>.
$reg_key = " bDisableJavaScript" # Enter the Registry key dword name. Remove <>
$reg_value = 1 # Enter the desired value to REMEDIATE the vulnerability.
$reg_type = " DWORD" # Do not change unless the Value is not a DWORD

try {
    New-ItemProperty -Path Registry::$reg_path -Name $reg_key -PropertyType $reg_type -Value $reg_value -Force
   ;  $regentry = Get-ItemProperty -Path Registry::$reg_path -Name $reg_key
        
    if ($regentry.$reg_key -eq $reg_value){
        #Exit 0 for Intune if NO error
        Write-WELog " Setting is disabled! Exiting." " INFO"
        exit 0
    }
    ElseIf ($regentry.$reg_key -eq $null){        
        #Exit 0 for Intune if the registry does not exist, indicating the remediation is unnecessary. 
        Write-WELog " Registry Key does not exist! Exiting." " INFO"
        exit 0}
    else {
        #Exit 1 for Intune if error. This re-runs the remediation.
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