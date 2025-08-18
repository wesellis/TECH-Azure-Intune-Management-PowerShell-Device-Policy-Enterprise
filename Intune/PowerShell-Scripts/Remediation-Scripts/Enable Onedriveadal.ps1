<#
.SYNOPSIS
    Enable Onedriveadal

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
    We Enhanced Enable Onedriveadal

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

$WEPath = " HKCU:\SOFTWARE\Microsoft\OneDrive"; 
$WEName = " EnableADAL" ; 
$WEValue = 1


if (-not(Test-Path -Path $WEPath)) {
    New-Item -Path $WEPath -Force | Out-Null
    New-ItemProperty -Path $WEPath -Name $WEName -Value $WEValue -PropertyType DWORD -Force | Out-Null
}
else {
    New-ItemProperty -Path $WEPath -Name $WEName -Value $WEValue -PropertyType DWORD -Force | Out-Null
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================