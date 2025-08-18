<#
.SYNOPSIS
    Set Intuneiosmanagedappassignment

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
    We Enhanced Set Intuneiosmanagedappassignment

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
    Update the UninstallOnDeviceRemoval property value to either $true or $false for iOS managed app assignments.

.DESCRIPTION
    Update the UninstallOnDeviceRemoval property value to either $true or $false for iOS managed app assignments.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER UninstallOnDeviceRemoval
    Specify either True or False to change the Uninstall on device removal app assignment setting.

.PARAMETER Force
    When passed the script will set the UninstallOnDeviceRemoval property value even if it's been set before.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

.PARAMETER PromptBehavior
    Set the prompt behavior when acquiring a token.

.EXAMPLE
    .\Set-IntuneiOSManagedAppAssignment.ps1 -TenantName 'name.onmicrosoft.com' -UninstallOnDeviceRemoval $true -Force -Verbose

.NOTES
    FileName:    Set-IntuneiOSManagedAppAssignment.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-10-01
    Updated:     2019-10-27
    
    Version history:
    1.0.0 - (2019-10-01) Script created
    1.0.1 - (2019-10-27) Changed the filter for mobileApps resource to include managed apps too.

    Required modules:
    AzureAD (Install-Module -Name AzureAD)
    PSIntuneAuth (Install-Module -Name PSIntuneAuth)

[CmdletBinding(SupportsShouldProcess = $true)]
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

    [parameter(Mandatory = $true, HelpMessage = " Specify either True or False to change the Uninstall on device removal app assignment setting." )]
    [ValidateNotNullOrEmpty()]
    [bool]$WEUninstallOnDeviceRemoval,

    [parameter(Mandatory = $false, HelpMessage = " When passed the script will set the UninstallOnDeviceRemoval property value even if it's been set before." )]
    [ValidateNotNullOrEmpty()]
    [switch]$WEForce,    

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

    function WE-Get-IntuneManagedApp {
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceAppManagement/mobileApps"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        $WEGraphResponse = Invoke-IntuneGraphRequest -URI $WEGraphURI

        # Handle return objects from response
        return $WEGraphResponse
    }

    function WE-Get-IntuneManagedAppAssignment {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEAppID
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceAppManagement/mobileApps/$($WEAppID)/assignments"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        $WEGraphResponse = Invoke-IntuneGraphRequest -URI $WEGraphURI

        # Handle return objects from response
        return $WEGraphResponse        
    }

    function WE-Set-IntuneManagedAppAssignment {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAppID,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAssignmentID,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$WEBody            
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceAppManagement/mobileApps/$($WEAppID)/assignments/$($WEAssignmentID)"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        $WEGraphResponse = Invoke-IntuneGraphRequest -URI $WEGraphURI -Body $WEBody

        # Handle return objects from response
        return $WEGraphResponse
    }

    # Retrieve all managed apps and filter on iOS
    # Pattern matching for validation
# Pattern matching for validation
$WEManagedApps = Get-IntuneManagedApp | Where-Object { $_.'@odata.type' -match " iosVppApp|iosStoreApp|managedIOSStoreApp" }

    # Process each managed app
    foreach ($WEManagedApp in $WEManagedApps) {
        Write-Verbose -Message " Attempting to retrieve assignments for managed app: $($WEManagedApp.displayName)"

        # Retrieve assignments for current managed iOS app
        $WEManagedAppAssignments = Get-IntuneManagedAppAssignment -AppID $WEManagedApp.id

        # Continue if id property is not null, meaning that there's assignments for the current managed app
        if ($WEManagedAppAssignments.id -ne $null) {
            Write-Verbose -Message " Detected assignments for current managed app"

            foreach ($WEManagedAppAssignment in $WEManagedAppAssignments) {
                # Handle uninstall at device removal value
                if ($WEManagedAppAssignment.settings.uninstallOnDeviceRemoval -eq $null) {
                    Write-Verbose -Message " Detected empty property value for uninstall at device removal, updating property value"
                    $WEManagedAppAssignment.settings.uninstallOnDeviceRemoval = $WEUninstallOnDeviceRemoval
                }

                # Force update non-set property values
                if ($WEPSBoundParameters[" Force" ]) {
                    $WEManagedAppAssignment.settings.uninstallOnDeviceRemoval = $WEUninstallOnDeviceRemoval
                }
                
                # Construct JSON object for POST call
                $WEJSONTable = @{
                    'id' = $WEManagedAppAssignment.id
                    'settings' = $WEManagedAppAssignment.settings
                }
               ;  $WEJSONData = $WEJSONTable | ConvertTo-Json
                
                # Call Graph API post operation with updated settings values for assignment
                Write-Verbose -Message " Attempting to update uninstallOnDeviceRemoval for assignment ID '$($WEManagedAppAssignment.id)' with value: $($WEUninstallOnDeviceRemoval)"
               ;  $WEInvocation = Set-IntuneManagedAppAssignment -AppID $WEManagedApp.id -AssignmentID $WEManagedAppAssignment.id -Body $WEJSONData
            }           
        }
        else {
            Write-Verbose -Message " Empty query returned for managed app assignments"
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================