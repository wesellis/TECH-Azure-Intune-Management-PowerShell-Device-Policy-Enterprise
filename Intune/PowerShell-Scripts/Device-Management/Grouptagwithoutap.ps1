<#
.SYNOPSIS
    Grouptagwithoutap

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
    We Enhanced Grouptagwithoutap

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

$clientID = " YOUR_CLIENT_ID"
$groupTag = " YOUR_GROUP_TAG"
$clientSecret = " YOUR_CLIENT SECRET"
$tenant = " YOUR_TENANT_NAME.COM"

$headers = New-Object -ErrorAction Stop " System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add(" Content-Type" , " application/x-www-form-urlencoded" )

$body = " grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body = $body + -join (" &client_id=" , $clientId, " &client_secret=" , $clientSecret)

$response = Invoke-RestMethod " https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body


$token = -join (" Bearer " , $response.access_token)


$headers = New-Object -ErrorAction Stop " System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add(" Authorization" , $token)
$headers.Add(" Content-Type" , " application/json" )


# Pattern matching for validation
$entraDeviceId = ((Get-ChildItem -ErrorAction Stop Cert:\LocalMachine\My | Where-Object {$_.Issuer -match " MS-Organization-Access" } | Select-Object Subject).Subject).TrimStart(" CN=" )
$physicalIds = (Invoke-RestMethod GET -Uri " https://graph.microsoft.com/beta/devices/$($entraDeviceId)" -Headers $headers).physicalIds
$groupTag = " [OrderID]:$($groupTag)"; 
$physicalIds = $physicalIds + $groupTag
; 
$body = @{
    physicalIds = $physicalIds
} | ConvertTo-Json

Invoke-RestMethod -Method PATCH -Uri " https://graph.microsoft.com/beta/devices/$($entraDeviceId)" -Headers $headers -Body $body



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================