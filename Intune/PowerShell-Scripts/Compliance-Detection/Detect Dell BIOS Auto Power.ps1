<#
.SYNOPSIS
    Detect Dell Bios Auto Power

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
    We Enhanced Detect Dell Bios Auto Power

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
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Import-Module DellBIOSProvider
    $autoon = get-item -path DellSmbios:\PowerManagement\autoon
    $autoonhr = get-Item -Path DellSmbios:\PowerManagement\AutoOnHr
   ;  $autoonmn = get-Item -Path DellSmbios:\PowerManagement\AutoOnMn
        
    if ($autoon.CurrentValue -eq 'Everyday' -AND $autoonhr.CurrentValue -eq 21 -AND $autoonmn.CurrentValue -eq 00){
        #Exit 0 for Intune if NO error
        Write-WELog " Auto-on already set to everyday, 9PM!" " INFO"
        exit 0
    }
    else {
        #Exit 1 for Intune if error
        Write-WELog " Auto-on NOT set to everyday, 9PM!" " INFO"
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