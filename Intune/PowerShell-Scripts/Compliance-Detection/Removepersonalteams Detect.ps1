<#
.SYNOPSIS
    Removepersonalteams Detect

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
    We Enhanced Removepersonalteams Detect

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WETeamsApp = Get-AppxPackage -ErrorAction Stop "*Teams*" -AllUsers -ErrorAction SilentlyContinue
}


$WEErrorActionPreference = " Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }
; 
$WETeamsApp = Get-AppxPackage -ErrorAction Stop " *Teams*" -AllUsers -ErrorAction SilentlyContinue
if($WETeamsApp.Name -eq " MicrosoftTeams" )
{
    Write-WELog " Built-in Teams App found" " INFO"
    Exit 1
}
else
{
    Write-WELog " Built-in Teams App found" " INFO"
    Exit 0
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================