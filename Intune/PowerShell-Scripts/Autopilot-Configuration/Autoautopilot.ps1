<#
.SYNOPSIS
    Automatic Windows Autopilot device registration via Graph API.

.DESCRIPTION
    Registers the current device to Windows Autopilot automatically using Microsoft Graph API.
    Retrieves hardware information from the local device and uploads to Autopilot service.

.PARAMETER ClientId
    Azure AD Application Client ID with DeviceManagementServiceConfig.ReadWrite.All permissions.

.PARAMETER ClientSecret
    Azure AD Application Client Secret.

.PARAMETER TenantId
    Azure AD Tenant ID.

.PARAMETER GroupTag
    Optional group tag to assign to the device (default: "M365").

.EXAMPLE
    .\Autoautopilot.ps1 -ClientId "your-client-id" -ClientSecret "your-secret" -TenantId "your-tenant-id"

.EXAMPLE
    .\Autoautopilot.ps1 -ClientId "your-client-id" -ClientSecret "your-secret" -TenantId "your-tenant-id" -GroupTag "Finance"

.NOTES
    Author: Wesley Ellis
    Version: 2.0
    Requires: DeviceManagementServiceConfig.ReadWrite.All Graph API permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$GroupTag = "M365"
)

$ErrorActionPreference = "Stop"
$VerbosePreference = if ($PSBoundParameters.ContainsKey('Verbose')) { "Continue" } else { "SilentlyContinue" }

try {
    Write-Verbose "Starting Autopilot device registration..."

    # Authenticate to Microsoft Graph
    Write-Verbose "Authenticating to Microsoft Graph..."
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenRequestBody = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenRequestBody
    $accessToken = $tokenResponse.access_token

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }

    Write-Verbose "✓ Successfully authenticated"

    # Get hardware information from local device
    Write-Verbose "Retrieving hardware information..."
    $serialNumber = (Get-CimInstance -Class Win32_BIOS).SerialNumber
    $hardwareId = (Get-CimInstance -Namespace root/cimv2/mdm/dmmap `
                    -Class MDM_DevDetail_Ext01 `
                    -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData

    Write-Verbose "  Serial Number: $serialNumber"
    Write-Verbose "  Group Tag: $GroupTag"

    # Construct Autopilot device identity JSON
    $deviceIdentity = @{
        "@odata.type"              = "#microsoft.graph.importedWindowsAutopilotDeviceIdentity"
        groupTag                   = $GroupTag
        serialNumber               = $serialNumber
        productKey                 = ""
        hardwareIdentifier         = $hardwareId
        assignedUserPrincipalName  = ""
        state                      = @{
            "@odata.type"         = "microsoft.graph.importedWindowsAutopilotDeviceIdentityState"
            deviceImportStatus    = "pending"
            deviceRegistrationId  = ""
            deviceErrorCode       = 0
            deviceErrorName       = ""
        }
    }

    $json = $deviceIdentity | ConvertTo-Json -Depth 10

    # Register device with Autopilot
    Write-Verbose "Registering device with Autopilot..."
    $uri = "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities"
    $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $json

    Write-Host "✓ Device successfully registered with Autopilot" -ForegroundColor Green
    Write-Host "  Serial Number: $serialNumber" -ForegroundColor Cyan
    Write-Host "  Group Tag: $GroupTag" -ForegroundColor Cyan
    Write-Host "  Import Status: $($response.state.deviceImportStatus)" -ForegroundColor Cyan

    return $response
}
catch {
    Write-Error "Failed to register device with Autopilot: $_"
    throw
}
