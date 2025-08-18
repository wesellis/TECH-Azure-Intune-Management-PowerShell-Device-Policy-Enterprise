<#
.SYNOPSIS
    Enablefullcontextmenu

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
    We Enhanced Enablefullcontextmenu

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$registryPath = "HKCU:\SOFTWARE\CLASSES\CLSID\"
}


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }
; 
$registryPath = " HKCU:\SOFTWARE\CLASSES\CLSID\" ; 
$keyName = " {86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"

if (-not (Test-Path " $registryPath$keyName" )) {
    New-Item -Path " $registryPath$keyName" -Force
    New-Item -Path " $registryPath$keyName\InprocServer32" -Force

    Set-ItemProperty -Path " $registryPath$keyName\InprocServer32" -Name " (Default)" -Value ""
    
    Write-WELog " Registry key created successfully. Please restart your computer to apply changes." " INFO"
} else {
    Write-WELog " Registry key already exists." " INFO"
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================