<#
.SYNOPSIS
    Writeextensionattribute

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
    We Enhanced Writeextensionattribute

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

$clientId = " <CLIENTID>"
$clientSecret = " <CLIENTSECRET>"
$tenant = " <TENANTNAME>"

$headers = New-Object -ErrorAction Stop " System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add(" Content-Type" , " application/x-www-form-urlencoded" )

$body = " grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
$body = $body + -join (" &client_id=" , $clientId, " &client_secret=" , $clientSecret)

$response = Invoke-RestMethod " https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body


$token = -join (" Bearer " , $response.access_token)


$headers = New-Object -ErrorAction Stop " System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add(" Authorization" , $token)
$headers.Add(" Content-Type" , " application/json" )
Write-WELog " MS Graph Authenticated" " INFO"




$activeUsername = (Get-CimInstance -ErrorAction Stop Win32_ComputerSystem | Select-Object | username).username
$objUser = New-Object -ErrorAction Stop System.Security.Principal.NTAccount(" $activeUsername" )
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
$userSID = $strSID.Value


$regPath = " HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($userSID)\IdentityCache\$($userSID)"
$upn = Get-ItemPropertyValue -Path $regPath -Name UserName
; 
$userObject = Invoke-RestMethod -Method GET -Uri " https://graph.microsoft.com/beta/users/$($upn)" -Headers $headers
; 
$attribute = $userObject.Value.extensionAttribute7

reg.exe add 'HKLM\SOFTWARE\IntuneMigration' /v ExtensionAttribute /t REG_SZ /d $attribute /f /reg:64 | Out-Host



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================