<#
.SYNOPSIS
    Test Autopilotazureaddeviceassociation

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
    We Enhanced Test Autopilotazureaddeviceassociation

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#PSScriptInfo


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

.VERSION 1.0.0
.GUID c30dcb72-e391-49ae-ad06-e5438b8c72a1
.AUTHOR NickolajA
.DESCRIPTION Validate that the configured Azure AD device record for all Autopilot device identities exist in Azure AD.
.COMPANYNAME MSEndpointMgr
.COPYRIGHT 
.TAGS AzureAD Autopilot Windows Intune
.LICENSEURI 
.PROJECTURI https://github.com/MSEndpointMgr/Intune/blob/master/Autopilot/Test-AutopilotAzureADDeviceAssociation.ps1
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES

<#
.SYNOPSIS
    Validate that the configured Azure AD device record for all Autopilot device identities exist in Azure AD.

.DESCRIPTION
    This script will retrieve all Autopilot identities and foreach validate if the given Azure AD device record that's 
    currently associated actually exist in Azure AD.

.PARAMETER TenantID
    Specify the tenant name or ID, e.g. tenant.onmicrosoft.com or <GUID>.

.EXAMPLE
    .\Test-AutopilotAzureADDeviceAssociation.ps1 -TenantID " tenantname.onmicrosoft.com"

.NOTES
    FileName:    Test-AutopilotAzureADDeviceAssociation.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2021-05-06
    Updated:     2021-05-06

    Version history:
    1.0.0 - (2021-05-06) Script created

[CmdletBinding(SupportsShouldProcess = $true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $true, HelpMessage = " Specify the tenant name or ID, e.g. tenant.onmicrosoft.com or <GUID>." )]
    [ValidateNotNullOrEmpty()]
    [string]$WETenantID
)
Process {
    # Functions
    function WE-Get-AutopilotDevice {
        <#
        .SYNOPSIS
            Retrieve all Autopilot device identities.
            
        .DESCRIPTION
            Retrieve all Autopilot device identities.
            
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-01-27
            Updated:     2021-01-27

            Version history:
            1.0.0 - (2021-01-27) Function created
        #>    
        Process {
            # Retrieve all Windows Autopilot device identities
            $WEResourceURI = " deviceManagement/windowsAutopilotDeviceIdentities"
            $WEGraphResponse = Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource $WEResourceURI

            # Handle return response
            return $WEGraphResponse
        }
    }

    function WE-Get-AzureADDeviceRecord {
        <#
        .SYNOPSIS
            Retrieve an Azure AD device record.
            
        .DESCRIPTION
            Retrieve an Azure AD device record.

        .PARAMETER DeviceId
            Specify the Device ID of the Azure AD device record.
            
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-05-05
            Updated:     2021-05-05

            Version history:
            1.0.0 - (2021-05-05) Function created
        #> 
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Specify the Device ID of the Azure AD device record." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEDeviceId
        )   
        Process {
            # Retrieve all Windows Autopilot device identities
            $WEResourceURI = " devices?`$filter=deviceId eq '$($WEDeviceId)'"
            $WEGraphResponse = (Invoke-MSGraphOperation -Get -APIVersion " v1.0" -Resource $WEResourceURI).value

            # Handle return response
            return $WEGraphResponse
        }
    }

    # Get access token
    $WEAccessToken = Get-AccessToken -TenantID $WETenantID

    # Construct array list for all Autopilot device identities with broken associations
    $WEAutopilotDeviceList = New-Object -TypeName " System.Collections.ArrayList"

    # Gather Autopilot device details
    Write-Verbose -Message " Attempting to retrieve all Autopilot device identities, this could take some time"
    $WEAutopilotDevices = Get-AutopilotDevice

    # Measure detected Autopilot identities count
    $WEAutopilotIdentitiesCount = ($WEAutopilotDevices | Measure-Object).Count

    if ($WEAutopilotDevices -ne $null) {
        Write-Verbose -Message " Detected count of Autopilot identities: $($WEAutopilotIdentitiesCount)"

        # Construct and start a timer for output
        $WETimer = [System.Diagnostics.Stopwatch]::StartNew()
        $WEAutopilotIdentitiesCurrentCount = 0
        $WESecondsCount = 0

        # Process each Autopilot device identity
        foreach ($WEAutopilotDevice in $WEAutopilotDevices) {
            # Increase current progress count
            $WEAutopilotIdentitiesCurrentCount++

            # Handle output count for progress visibility
            if ([math]::Round($WETimer.Elapsed.TotalSeconds) -gt ($WESecondsCount + 30)) {
                # Increase minutes count for next output frequence
                $WESecondsCount = [math]::Round($WETimer.Elapsed.TotalSeconds)

                # Write output every 30 seconds
                Write-Verbose -Message " Elapsed time: $($WETimer.Elapsed.Hours) hour $($WETimer.Elapsed.Minutes) min $($WETimer.Elapsed.Seconds) seconds"
                Write-Verbose -Message " Progress count: $($WEAutopilotIdentitiesCurrentCount) / $($WEAutopilotIdentitiesCount)"
                Write-Verbose -Message " Detected devices: $($WEAutopilotDeviceList.Count)"
            }

            # Handle access token refresh if required
            $WEAccessTokenRenew = Test-AccessToken
            if ($WEAccessTokenRenew -eq $false) {
                $WEAccessToken = Get-AccessToken -TenantID $WETenantID -Refresh
            }

            # Get Azure AD device record for associated device based on what's set for the Autopilot identity
           ;  $WEAzureADDevice = Get-AzureADDeviceRecord -DeviceId $WEAutopilotDevice.azureAdDeviceId
            if ($WEAzureADDevice -eq $null) {
                # Construct custom object for output
               ;  $WEPSObject = [PSCustomObject]@{
                    Id = $WEAutopilotDevice.id
                    SerialNumber = $WEAutopilotDevice.serialNumber
                    Model = $WEAutopilotDevice.model
                    Manufacturer = $WEAutopilotDevice.manufacturer
                }
                $WEAutopilotDeviceList.Add($WEPSObject) | Out-Null
            }
        }

        # Handle output at script completion
        Write-Verbose -Message " Successfully detected a total of '$($WEAutopilotDeviceList.Count)' Autopilot identities with a broken Azure AD device association"
        Write-Output -InputObject $WEAutopilotDeviceList
    }
    else {
        Write-Warning -Message " Could not detect any Autopilot device identities"
    }
}



} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
