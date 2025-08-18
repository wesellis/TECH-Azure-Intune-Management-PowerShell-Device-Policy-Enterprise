<#
.SYNOPSIS
    Installtask

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
    We Enhanced Installtask

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$destination = "C:\ProgramData\Scripts"
schtasks.exe /create /xml " $($psscriptroot)\Primary User Check.xml" /tn " Primary User Check" /f | Out-Host


$WEErrorActionPreference = " Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }
; 
$destination = " C:\ProgramData\Scripts"
if(!(Test-Path $WEDestination)
{
	mkdir $WEDestination
}

Copy-Item -Path " $($psscriptroot)\userCheck.ps1" -Destination $WEDestination -Recurse -Force

schtasks.exe /create /xml " $($psscriptroot)\Primary User Check.xml" /tn " Primary User Check" /f | Out-Host


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================