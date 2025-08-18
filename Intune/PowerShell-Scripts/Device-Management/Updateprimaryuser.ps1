<#
.SYNOPSIS
    Updateprimaryuser

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
    We Enhanced Updateprimaryuser

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

$clientId = " your-client-id"
$tenantId = " your-tenant-id"
$clientSecret = " your-client-secret"
$scope = " https://graph.microsoft.com/.default"


$body = @{
    grant_type    = " client_credentials"
    scope         = $scope
    client_id     = $clientId
    client_secret = $clientSecret
}
$tokenResponse = Invoke-WebRequest -Uri " https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method Post -ContentType " application/x-www-form-urlencoded" -Body $body
$token = ($tokenResponse.Content | ConvertFrom-Json).access_token


function WE-Get-LastLoggedOnUser($deviceId, $token) {
    $uri = " https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId"
    $headers = @{
        Authorization = " Bearer $token"
    }
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get
    $deviceDetails = $response.Content | ConvertFrom-Json
    return $deviceDetails.userPrincipalName
}


function WE-Get-PrimaryUser($deviceId, $token) {
    $uri = " https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId/users"
    $headers = @{
        Authorization = " Bearer $token"
    }
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get
    $primaryUser = ($response.Content | ConvertFrom-Json).value | Where-Object { $_.isPrimaryUser -eq $true }
    return $primaryUser.userPrincipalName
}


function WE-Update-PrimaryUser($deviceId, $newPrimaryUser, $token) {
    $uri = " https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId/assignUser"
    $headers = @{
        Authorization = " Bearer $token"
        " Content-Type" = " application/json"
    }
    $body = @{
        userPrincipalName = $newPrimaryUser
    } | ConvertTo-Json
    Invoke-WebRequest -Uri $uri -Headers $headers -Method Post -Body $body
    Write-Output " Updated primary user to $newPrimaryUser for device $deviceId"
}


$uri = " https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
$headers = @{
    Authorization = " Bearer $token"
}
$response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get
$devices = ($response.Content | ConvertFrom-Json).value

foreach ($device in $devices) {
    $deviceId = $device.id
   ;  $lastLoggedOnUser = Get-LastLoggedOnUser -deviceId $deviceId -token $token
   ;  $primaryUser = Get-PrimaryUser -deviceId $deviceId -token $token

    if ($lastLoggedOnUser -ne $primaryUser) {
        Write-Output " Mismatch found for device $deviceId. Updating primary user from $primaryUser to $lastLoggedOnUser"
        Update-PrimaryUser -deviceId $deviceId -newPrimaryUser $lastLoggedOnUser -token $token
    } else {
        Write-Output " No mismatch for device $deviceId. Primary user: $primaryUser, Last logged on user: $lastLoggedOnUser"
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================