<#
.SYNOPSIS
    Rename Intunedeviceconfigurationprofile

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
    We Enhanced Rename Intunedeviceconfigurationprofile

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    Rename a specified string (match pattern) in Device Configuration profile display names with a new string (replace pattern).

.DESCRIPTION
    Rename a specified string (match pattern) in Device Configuration profile display names with a new string (replace pattern).

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER Match
    Specify the match pattern as a string that's represented in the device configuration profile name and will be updated with that's specified for the Replace parameter.

.PARAMETER Replace
    Specify the replace pattern as a string that will replace what's matched in the device configuration profile name.    

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

.PARAMETER PromptBehavior
    Set the prompt behavior when acquiring a token.

.EXAMPLE
    # Rename all Device Configuration Profiles with a display name that matches 'Win10' with 'W10' in a tenant named 'domain.onmicrosoft.com':
    .\Rename-IntuneDeviceConfigurationProfile.ps1 -TenantName " domain.onmicrosoft.com" -Match " Win10" -Replace " W10" -Verbose

.NOTES
    FileName:    Rename-IntuneDeviceConfigurationProfile.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-10-15
    Updated:     2019-10-15

    Version history:
    1.0.0 - (2019-10-15) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)
    PSIntuneAuth (Install-Module -Name PSIntuneAuth)    

[CmdletBinding(SupportsShouldProcess=$true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $true, HelpMessage = " Specify the tenant name, e.g. domain.onmicrosoft.com." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WETenantName,

    [parameter(Mandatory = $true, HelpMessage = " Specify the match pattern as a string that's represented in the device configuration profile name and will be updated with that's specified for the Replace parameter." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEMatch,

    [parameter(Mandatory = $true, HelpMessage = " Specify the replace pattern as a string that will replace what's matched in the device configuration profile name." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEReplace,

    [parameter(Mandatory = $false, HelpMessage = " Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEApplicationID = " d1ddf0e4-d672-4dae-b554-9d5bdfd93547" ,

    [parameter(Mandatory=$false, HelpMessage=" Set the prompt behavior when acquiring a token." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" Auto" , " Always" , " Never" , " RefreshSession" )]
    [string]$WEPromptBehavior = " Auto"
)
Begin {
    # Determine if the PSIntuneAuth module needs to be installed
    try {
        Write-Verbose -Message " Attempting to locate PSIntuneAuth module"
        $WEPSIntuneAuthModule = Get-InstalledModule -Name PSIntuneAuth -ErrorAction Stop -Verbose:$false
        if ($WEPSIntuneAuthModule -ne $null) {
            Write-Verbose -Message " Authentication module detected, checking for latest version"
            $WELatestModuleVersion = (Find-Module -Name PSIntuneAuth -ErrorAction Stop -Verbose:$false).Version
            if ($WELatestModuleVersion -gt $WEPSIntuneAuthModule.Version) {
                Write-Verbose -Message " Latest version of PSIntuneAuth module is not installed, attempting to install: $($WELatestModuleVersion.ToString())"
               ;  $WEUpdateModuleInvocation = Update-Module -Name PSIntuneAuth -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " Unable to detect PSIntuneAuth module, attempting to install from PSGallery"
        try {
            # Install NuGet package provider
           ;  $WEPackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false

            # Install PSIntuneAuth module
            Install-Module -Name PSIntuneAuth -Scope AllUsers -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            Write-Verbose -Message " Successfully installed PSIntuneAuth"
        }
        catch [System.Exception] {
            Write-Warning -Message " An error occurred while attempting to install PSIntuneAuth module. Error message: $($_.Exception.Message)" ; break
        }
    }

    # Check if token has expired and if, request a new
    Write-Verbose -Message " Checking for existing authentication token"
    if ($WEGlobal:AuthToken -ne $null) {
        $WEUTCDateTime = (Get-Date).ToUniversalTime()
        $WETokenExpireMins = ($WEGlobal:AuthToken.ExpiresOn.datetime - $WEUTCDateTime).Minutes
        Write-Verbose -Message " Current authentication token expires in (minutes): $($WETokenExpireMins)"
        if ($WETokenExpireMins -le 0) {
            Write-Verbose -Message " Existing token found but has expired, requesting a new token"
            $WEGlobal:AuthToken = Get-MSIntuneAuthToken -TenantName $WETenantName -ClientID $WEApplicationID -PromptBehavior $WEPromptBehavior
        }
        else {
            if ($WEPromptBehavior -like " Always" ) {
                Write-Verbose -Message " Existing authentication token has not expired but prompt behavior was set to always ask for authentication, requesting a new token"
                $WEGlobal:AuthToken = Get-MSIntuneAuthToken -TenantName $WETenantName -ClientID $WEApplicationID -PromptBehavior $WEPromptBehavior
            }
            else {
                Write-Verbose -Message " Existing authentication token has not expired, will not request a new token"
            }
        }
    }
    else {
        Write-Verbose -Message " Authentication token does not exist, requesting a new token"
        $WEGlobal:AuthToken = Get-MSIntuneAuthToken -TenantName $WETenantName -ClientID $WEApplicationID -PromptBehavior $WEPromptBehavior
    }
}
Process {
    # Functions
    function WE-Get-ErrorResponseBody {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Exception]$WEException
        )

        # Read the error stream
        $WEErrorResponseStream = $WEException.Response.GetResponseStream()
        $WEStreamReader = New-Object System.IO.StreamReader($WEErrorResponseStream)
        $WEStreamReader.BaseStream.Position = 0
        $WEStreamReader.DiscardBufferedData()
        $WEResponseBody = $WEStreamReader.ReadToEnd()

        # Handle return object
        return $WEResponseBody
    }

    function WE-Invoke-IntuneGraphRequest {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, ParameterSetName = " Get" )]
            [parameter(ParameterSetName = " Patch" )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEURI,

            [parameter(Mandatory = $true, ParameterSetName = " Patch" )]
            [ValidateNotNullOrEmpty()]
            [System.Object]$WEBody
        )
        try {
            # Construct array list for return values
            $WEResponseList = New-Object -TypeName System.Collections.ArrayList

            # Call Graph API and get JSON response
            switch ($WEPSCmdlet.ParameterSetName) {
                " Get" {
                    Write-Verbose -Message " Current Graph API call is using method: Get"
                    $WEGraphResponse = Invoke-RestMethod -Uri $WEURI -Headers $WEAuthToken -Method Get -ErrorAction Stop -Verbose:$false
                    if ($WEGraphResponse -ne $null) {
                        if ($WEGraphResponse.value -ne $null) {
                            foreach ($WEResponse in $WEGraphResponse.value) {
                                $WEResponseList.Add($WEResponse) | Out-Null
                            }
                        }
                        else {
                            $WEResponseList.Add($WEGraphResponse) | Out-Null
                        }
                    }
                }
                " Patch" {
                    Write-Verbose -Message " Current Graph API call is using method: Patch"
                    $WEGraphResponse = Invoke-RestMethod -Uri $WEURI -Headers $WEAuthToken -Method Patch -Body $WEBody -ContentType " application/json" -ErrorAction Stop -Verbose:$false
                    if ($WEGraphResponse -ne $null) {
                        foreach ($WEResponseItem in $WEGraphResponse) {
                            $WEResponseList.Add($WEResponseItem) | Out-Null
                        }
                    }
                    else {
                        Write-Warning -Message " Response was null..."
                    }
                }
            }

            return $WEResponseList
        }
        catch [System.Exception] {
            # Construct stream reader for reading the response body from API call
            $WEResponseBody = Get-ErrorResponseBody -Exception $_.Exception
    
            # Handle response output and error message
            Write-Output -InputObject " Response content:`n$WEResponseBody"
            Write-Warning -Message " Request to $($WEURI) failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
        }
    }

    function WE-Get-IntuneDeviceConfigurationProfile {
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/deviceConfigurations"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        $WEGraphResponse = Invoke-IntuneGraphRequest -URI $WEGraphURI

        # Handle return objects from response
        return $WEGraphResponse
    }

    function WE-Set-IntuneDeviceConfigurationProfileDisplayName {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEDeviceConfigurationProfileID,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$WEBody
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/deviceConfigurations/$($WEDeviceConfigurationProfileID)"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        $WEGraphResponse = Invoke-IntuneGraphRequest -URI $WEGraphURI -Body $WEBody
    }    

    # Get all device configuration profiles and process each object
    $WEDeviceConfigurationProfiles = Get-IntuneDeviceConfigurationProfile
    if ($WEDeviceConfigurationProfiles -ne $null) {
        foreach ($WEDeviceConfigurationProfile in $WEDeviceConfigurationProfiles) {
            Write-Verbose -Message " Processing current device configuration profile with name: $($WEDeviceConfigurationProfile.displayName)"

            if ($WEDeviceConfigurationProfile.displayName -match $WEMatch) {
                Write-Verbose -Message " Match found for current device configuration profile, will attempt to rename object"

                # Construct JSON object for POST call
                $WENewName = $WEDeviceConfigurationProfile.displayName.Replace($WEMatch, $WEReplace)
               ;  $WEJSONTable = @{
                    '@odata.type' = $WEDeviceConfigurationProfile.'@odata.type'
                    'id' = $WEDeviceConfigurationProfile.id
                    'displayName' = $WENewName
                }
               ;  $WEJSONData = $WEJSONTable | ConvertTo-Json
                
                # Call Graph API post operation with new display name
                Write-Verbose -Message " Attempting to rename '$($WEDeviceConfigurationProfile.displayName)' profile to: $($WENewName)"
                Set-IntuneDeviceConfigurationProfileDisplayName -DeviceConfigurationProfileID $WEDeviceConfigurationProfile.id -Body $WEJSONData
            }
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================