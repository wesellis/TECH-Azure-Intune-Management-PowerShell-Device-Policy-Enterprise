<#
.SYNOPSIS
    Clientscript

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
    We Enhanced Clientscript

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


# Pattern matching for validation
$deviceId = ((Get-ChildItem -Path " Cert:\LocalMachine\My" | Where-Object {$_.Issuer -match " Microsoft Intune MDM Device CA" } | Select-Object Subject).Subject).TrimStart(" CN=" )


$payload = @{
    deviceId = $deviceId
} | ConvertTo-Json


$cutoffDate = ((Get-Date).AddDays(-30).ToString()); 
$currentRotationValue = Get-ItemPropertyValue -Path " HKLM:\SOFTWARE\BitLockerRotation" -Name " RotationDate"

if($null -eq $currentRotationValue -or $currentRotationValue -lt $cutoffDate)
{
    Write-Output " BitLocker recovery key was rotated more than 30 days ago. Attempting to rotate"
    reg.exe add " HKLM\SOFTWARE\BitLockerRotation" /v " RotationDate" /t REG_SZ /d (Get-Date).ToString() /f | Out-Host
    # send payload to webhook
   ;  $webhook = ""
    Invoke-WebRequest -Uri $webhook -Method POST -Body $payload -UseBasicParsing
    Exit 1
}
else
{
    Write-Output " Bitlocker recovery key was rotated within 30 days.  No action needed."    
    Exit 0
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================