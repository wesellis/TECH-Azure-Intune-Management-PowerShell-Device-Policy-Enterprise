<#
.SYNOPSIS
    Mdmcertcheck

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
    We Enhanced Mdmcertcheck

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

$certStore = " Cert:\LocalMachine\My"


$searchCriteria = " Microsoft Intune MDM Device CA"


Write-WELog " Searching for Intune Device Certificates in $certStore..." " INFO"; 
$certificates = Get-ChildItem -Path $certStore | Where-Object {
    $_.Issuer -like " *$searchCriteria*" -or $_.Subject -like " *$searchCriteria*"
}

if ($certificates) {
    Write-WELog " Found Intune Device Certificate(s):" " INFO" -ForegroundColor Green
    foreach ($cert in $certificates) {
        Write-WELog " Subject: $($cert.Subject)" " INFO"
        Write-WELog " Issuer: $($cert.Issuer)" " INFO"
        Write-WELog " Thumbprint: $($cert.Thumbprint)" " INFO"
        Write-WELog " Not Before: $($cert.NotBefore)" " INFO"
        Write-WELog " Not After: $($cert.NotAfter)" " INFO"
        Write-WELog " -----------------------------------------" " INFO"
    }
} else {
    Write-WELog " No Intune Device Certificate found." " INFO" -ForegroundColor Red
}

; 
$validCertificates = $certificates | Where-Object {
    $_.NotAfter -gt (Get-Date) -and $_.NotBefore -lt (Get-Date)
}

if ($validCertificates) {
    Write-WELog " Valid Intune Device Certificate(s) Found:" " INFO" -ForegroundColor Green
    foreach ($cert in $validCertificates) {
        Write-WELog " Subject: $($cert.Subject)" " INFO"
        Write-WELog " Expires On: $($cert.NotAfter)" " INFO"
    }
} else {
    Write



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================