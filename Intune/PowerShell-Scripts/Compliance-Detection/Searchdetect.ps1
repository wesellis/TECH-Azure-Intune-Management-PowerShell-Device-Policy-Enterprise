<#
.SYNOPSIS
    Searchdetect

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
    We Enhanced Searchdetect

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
}


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$path = " HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; 
$name = " SearchOnTaskbarMode"
; 
$currentSetting = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue

if($currentSetting -ne 1)
{
    Write-WELog " Search box not set to 1" " INFO"
    Exit 1
}
else
{
    Write-WELog " Search box is already set to 1" " INFO"
    Exit 0
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================