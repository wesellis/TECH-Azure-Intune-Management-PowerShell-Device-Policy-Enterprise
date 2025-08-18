<#
.SYNOPSIS
    Usercheck

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
    We Enhanced Usercheck

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$userName = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName
$userName | Out-File "C:\ProgramData\Scripts\primaryUser.txt"


$WEErrorActionPreference = " Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }
; 
$userName = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName

$userName | Out-File " C:\ProgramData\Scripts\primaryUser.txt"


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================