<#
.SYNOPSIS
    Create Adgroups

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
    We Enhanced Create Adgroups

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEGroups = @("AOVPN-Servers" , " AOVPN-Users" , " NDES-Servers" , " NPS-Servers" )
}


$WEErrorActionPreference = " Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }
; 
$WEGroups = @(" AOVPN-Servers" , " AOVPN-Users" , " NDES-Servers" , " NPS-Servers" )
Foreach ($WEGroup in $WEGroups) {
    New-ADGroup -GroupScope " Global" -Name $WEGroup
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================