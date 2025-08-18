<#
.SYNOPSIS
    Create Gmsa

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
    We Enhanced Create Gmsa

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEDomainName = "byteben.com"
New-ADServiceAccount -Name $WEName -DNSHostName $WEDNSHostName -ManagedPasswordIntervalInDays $WEPasswordInterval -PrincipalsAllowedToRetrieveManagedPassword $WEAllowedPrincipals -Enabled $true


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$WEDomainName = " byteben.com"
$WEName = " gMSA_ndes"
$WEDNSHostName = " $($WEName).$($WEDomainName)"; 
$WEPasswordInterval = 30; 
$WEAllowedPrincipals = " NDES-Servers"
New-ADServiceAccount -Name $WEName -DNSHostName $WEDNSHostName -ManagedPasswordIntervalInDays $WEPasswordInterval -PrincipalsAllowedToRetrieveManagedPassword $WEAllowedPrincipals -Enabled $true


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================