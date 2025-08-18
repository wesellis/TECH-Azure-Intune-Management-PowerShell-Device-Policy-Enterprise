<#
.SYNOPSIS
    Webhookscript

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
    We Enhanced Webhookscript

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

[cmdletbinding()]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [object]$WEWebhookData
)

if($WEWebhookData)
{
    $bodyData = ConvertFrom-Json -InputObject $WEWebhookData.RequestBody
   ;  $deviceId = ((($bodyData.deviceId) | Out-String).Trim())
}


Connect-MgGraph -Identity

Write-Output " Recovery key for deviceId $($deviceId) was not updated within the last 30 days, attempting to rotate..."
try
{
    Invoke-MgGraphRequest -Method POST -Uri " https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($deviceId)/rotateBitlockerKeys"
    Write-Output " Successfully rotated BitLocker key."
}
catch
{
   ;  $message = $_.Exception.Message
    Write-Output " Failed to rotate BitLocker key: $message"
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================