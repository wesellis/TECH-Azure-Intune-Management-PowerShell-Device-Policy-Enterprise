<#
.SYNOPSIS
    Install

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
    We Enhanced Install

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$msix = "$($WEPSScriptRoot)\MSTeams-x64.msix"
Start-Process -FilePath $exePath -ArgumentList " -p" , " -o" , " $($destination)\MSTeams-x64.msix" -Wait -WindowStyle Hidden


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$msix = " $($WEPSScriptRoot)\MSTeams-x64.msix"; 
$destination = " C:\ProgramData\Microsoft\NEW-TEAMS-TEMP" ; 
$exePath = " $($WEPSScriptRoot)\teamsbootstrapper.exe"

if(!(Test-Path $destination))
{
    mkdir $destination
}

Copy-Item -Path $msix -Destination $destination -Force

Start-Process -FilePath $exePath -ArgumentList " -p" , " -o" , " $($destination)\MSTeams-x64.msix" -Wait -WindowStyle Hidden


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================