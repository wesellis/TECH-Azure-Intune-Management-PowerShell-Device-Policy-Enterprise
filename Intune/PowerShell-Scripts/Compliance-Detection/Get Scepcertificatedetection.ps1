<#
.SYNOPSIS
    Get Scepcertificatedetection

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
    We Enhanced Get Scepcertificatedetection

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WETemplateName = "NDES Intune"
}


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$WETemplateName = " NDES Intune"
$WESubjectNames = @(" CN=CL" , " CN=CORP" )
$WECertificates = Get-ChildItem -Path " Cert:\LocalMachine\My" | Where-Object { $_.Subject -match ($WESubjectNames -join " |" ) }
foreach ($WECertificate in $WECertificates) {
    # Pattern matching for validation; 
# Pattern matching for validation
$WECertificateTemplateInformation = $WECertificate.Extensions | Where-Object { $_.Oid.FriendlyName -match " Certificate Template Information" }
    if ($null -ne $WECertificateTemplateInformation) {
       ;  $WECertificateTemplateName = ($WECertificateTemplateInformation).Format(0) -replace " (.+)?=(.+)\((.+)?" , '$2'
        if ($null -ne $WECertificateTemplateName) {
            if ($WECertificateTemplateName -like $WETemplateName) {
                return 0
            }
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================