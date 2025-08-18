<#
.SYNOPSIS
    Export Intunedeviceconfigurationprofile

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
    We Enhanced Export Intunedeviceconfigurationprofile

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
    Export device configuration profiles for Windows, iOS/iPadOS, AndroidEnterprise, macOS platforms in Intune to a local path as JSON files.

.DESCRIPTION
    Export device configuration profiles for Windows, iOS/iPadOS, AndroidEnterprise, macOS platforms in Intune to a local path as JSON files.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER Platform
    Specify the given platforms that device configuration profiles should be exported for.

.PARAMETER Path
    Specify an existing local path to where the exported Device Configuration JSON files will be stored.

.PARAMETER SkipPrefix
    When specified, the prefix (e.g. COMPANY-) in the following naming convention 'COMPANY-W10-Custom' will be removed.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

.PARAMETER PromptBehavior
    Set the prompt behavior when acquiring a token.    

.EXAMPLE
    # Export all device configuration profiles for all platforms from a tenant named 'domain.onmicrosoft.com' to local path 'C:\Temp\Intune':
    .\Export-IntuneDeviceConfigurationProfile.ps1 -TenantName " domain.onmicrosoft.com" -Platform " Windows" , " iOS" , " AndroidEnterprise" , " macOS" -Path C:\Temp\Intune -Verbose

.NOTES
    FileName:    Export-IntuneDeviceConfigurationProfile.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-10-04
    Updated:     2019-10-04

    Version history:
    1.0.0 - (2019-10-04) Script created

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

    [parameter(Mandatory = $false, HelpMessage = " Specify the given platforms that device configuration profiles should be exported for." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" Windows" , " iOS" , " AndroidEnterprise" , " macOS" )]
    [string[]]$WEPlatform,

    [parameter(Mandatory = $true, HelpMessage = " Specify an existing local path to where the exported Device Configuration JSON files will be stored." )]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern(" ^[A-Za-z]{1}:\\\w+" )]
    [ValidateScript({
        # Check if path contains any invalid characters
        if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            Write-Warning -Message " $(Split-Path -Path $_ -Leaf) contains invalid characters"
        }
        else {
            # Check if the whole path exists
            if (Test-Path -Path $_ -PathType Container) {
                    return $true
            }
            else {
                Write-Warning -Message " Unable to locate part of or the whole specified path, specify a valid path"
            }
        }
    })]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath,

    [parameter(Mandatory = $false, HelpMessage = " When specified, the prefix (e.g. COMPANY-) in the following naming convention 'COMPANY-W10-Custom' will be removed." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESkipPrefix,    

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
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEURI
        )
        try {
            # Construct array list for return values
            $WEResponseList = New-Object -TypeName System.Collections.ArrayList

            # Call Graph API and get JSON response
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

            # Handle return objects from response
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

    function WE-Export-JSON {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$WEInputObject,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEName,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet(" General" , " AdministrativeTemplate" )]
            [string]$WEType
        )
        try {
            # Handle removal of prefix from display name
            if ($WEType -like " General" ) {
                if ($WEScript:PSBoundParameters[" SkipPrefix" ]) {
                    $WEInputObject.displayName = $WEInputObject.displayName.Replace($WESkipPrefix, "" )
                    $WEName = $WEName.Replace($WESkipPrefix, "" )
                }
            }

            # Convert input data to JSON and remove unwanted properties
            $WEJSONData = ($WEInputObject | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags | ConvertTo-Json -Depth 10).Replace(" \u0027" ," '" )

            # Construct file name
            $WEFilePath = Join-Path -Path $WEPath -ChildPath (-join($WEName, " .json" ))

            # Output to file
            Write-Verbose -Message " Exporting device configuration profile with name: $($WEName)"
            $WEJSONData | Set-Content -Path $WEFilePath -Encoding " Ascii" -Force -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message " Failed to export JSON input data to path '$($WEFilePath)'. Error message: $($_.Exception.Message)"
        }
    }

    function WE-Get-IntuneDeviceConfigurationProfile {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEPlatform
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/deviceConfigurations"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        $WEResponseList = New-Object -TypeName System.Collections.ArrayList
        $WEGraphResponse = Invoke-IntuneGraphRequest -URI $WEGraphURI

        if ($WEGraphResponse -ne $null) {
            foreach ($WEResponseItem in $WEGraphResponse) {
                switch -Regex ($WEResponseItem.'@odata.type') {
                    " microsoft.graph.androidDeviceOwner" {
                        $WEPlatformType = " AndroidEnterprise"
                    }
                    " microsoft.graph.androidWorkProfile" {
                        $WEPlatformType = " AndroidEnterprise"
                    }
                    " microsoft.graph.windows" {
                        $WEPlatformType = " Windows"
                    }
                    " microsoft.graph.ios" {
                        $WEPlatformType = " iOS"
                    }
                }

                if ($WEPlatformItem -like $WEPlatformType) {
                    $WEResponseList.Add($WEResponseItem) | Out-Null
                }
            }
        }

        # Handle return objects from response
        return $WEResponseList
    }    

    function WE-Get-IntuneAdministrativeTemplateProfiles {
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/groupPolicyConfigurations"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        $WEResponseList = New-Object -TypeName System.Collections.ArrayList
        $WEGraphResponse = Invoke-IntuneGraphRequest -URI $WEGraphURI

        foreach ($WEResponseItem in $WEGraphResponse) {
            $WEResponseList.Add($WEResponseItem) | Out-Null
        }

        # Handle return objects from response
        return $WEResponseList
    }

    function WE-Get-IntuneAdministrativeTemplateDefinitionValues {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEAdministrativeTemplateId
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/groupPolicyConfigurations/$($WEAdministrativeTemplateId)/definitionValues"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $WEGraphURI
    }

    function WE-Get-IntuneAdministrativeTemplateDefinitionValuesPresentationValues {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAdministrativeTemplateId,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEDefinitionValueID
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/groupPolicyConfigurations/$($WEAdministrativeTemplateId)/definitionValues/$($WEDefinitionValueID)/presentationValues"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $WEGraphURI
    }

    function WE-Get-IntuneAdministrativeTemplateDefinitionValuesDefinition {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAdministrativeTemplateId,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEDefinitionValueID
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/groupPolicyConfigurations/$($WEAdministrativeTemplateId)/definitionValues/$($WEDefinitionValueID)/definition"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $WEGraphURI
    }

    function WE-Get-IntuneAdministrativeTemplateDefinitionsPresentations {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAdministrativeTemplateId,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEDefinitionValueID
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/groupPolicyConfigurations/$($WEAdministrativeTemplateId)/definitionValues/$($WEDefinitionValueID)/presentationValues?`$expand=presentation"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        (Invoke-IntuneGraphRequest -URI $WEGraphURI).presentation
    }

    # Process export operation based on specified platforms
    foreach ($WEPlatformItem in $WEPlatform) {
        Write-Verbose -Message " Currently processing device configuration profiles for platform: $($WEPlatformItem)"
        
        # Retrieve all device configuration profiles for current platform
        $WEDeviceConfigurationProfiles = Get-IntuneDeviceConfigurationProfile -Platform $WEPlatformItem

        if (($WEDeviceConfigurationProfiles | Measure-Object).Count -ge 1) {
            foreach ($WEDeviceConfigurationProfile in $WEDeviceConfigurationProfiles) {
                $WEDeviceConfigurationProfileName = $WEDeviceConfigurationProfile.displayName
                Export-JSON -InputObject $WEDeviceConfigurationProfile -Path $WEPath -Name $WEDeviceConfigurationProfileName -Type " General"
            }
        }
        else {
            Write-Warning -Message " Empty query result for device configuration profiles for platform: $($WEPlatformItem)"
        }

        # Retrieve all device configuration administrative templates for current platform
        if ($WEPlatformItem -like " Windows" ) {
            $WEAdministrativeTemplateProfiles = Get-IntuneAdministrativeTemplateProfiles
            if (($WEAdministrativeTemplateProfiles | Measure-Object).Count -ge 1) {
                foreach ($WEAdministrativeTemplateProfile in $WEAdministrativeTemplateProfiles) {
                    Write-Verbose -Message " Exporting administrative template with name: $($WEAdministrativeTemplateProfile.displayName)"
                    
                    # Handle removal of prefix
                    $WEAdministrativeTemplateProfileName = $WEAdministrativeTemplateProfile.displayName
                    if ($WEPSBoundParameters[" SkipPrefix" ]) {
                        $WEAdministrativeTemplateProfileName = $WEAdministrativeTemplateProfile.displayName.Replace($WESkipPrefix ,"" )
                    }

                    # Define new folder with administrative template profile name to contain any subsequent JSON files
                    $WEAdministrativeTemplateProfileFolderPath = Join-Path -Path $WEPath -ChildPath $WEAdministrativeTemplateProfileName
                    if (-not(Test-Path -Path $WEAdministrativeTemplateProfileFolderPath)) {
                        New-Item -Path $WEAdministrativeTemplateProfileFolderPath -ItemType Directory -Force | Out-Null
                    }     

                    # Retrieve all definition values for current administrative template and loop through them
                    $WEAdministrativeTemplateDefinitionValues = Get-IntuneAdministrativeTemplateDefinitionValues -AdministrativeTemplateId $WEAdministrativeTemplateProfile.id
                    foreach ($WEAdministrativeTemplateDefinitionValue in $WEAdministrativeTemplateDefinitionValues) {
                        # Retrieve the defintion of the current definition value
                        $WEDefinitionValuesDefinition = Get-IntuneAdministrativeTemplateDefinitionValuesDefinition -AdministrativeTemplateId $WEAdministrativeTemplateProfile.id -DefinitionValueID $WEAdministrativeTemplateDefinitionValue.id
                        $WEDefinitionValuesDefinitionID = $WEDefinitionValuesDefinition.id
                        $WEDefinitionValuesDefinitionDisplayName = $WEDefinitionValuesDefinition.displayName

                        # Retrieve the presentations of the current definition value
                        $WEDefinitionsPresentations = Get-IntuneAdministrativeTemplateDefinitionsPresentations -AdministrativeTemplateId $WEAdministrativeTemplateProfile.id -DefinitionValueID $WEAdministrativeTemplateDefinitionValue.id

                        # Rertrieve the presentation values of the current definition value
                        $WEDefinitionValuesPresentationValues = Get-IntuneAdministrativeTemplateDefinitionValuesPresentationValues -AdministrativeTemplateId $WEAdministrativeTemplateProfile.id -DefinitionValueID $WEAdministrativeTemplateDefinitionValue.id

                        # Create custom definition object to be exported
                        $WEPSObject = New-Object -TypeName PSCustomObject
                        $WEPSObject | Add-Member -MemberType " NoteProperty" -Name " definition@odata.bind" -Value " https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($WEDefinitionValuesDefinition.id)')"
                        $WEPSObject | Add-Member -MemberType " NoteProperty" -Name " enabled" -Value $($WEAdministrativeTemplateDefinitionValue.enabled.ToString().ToLower())
 
                        # Check whether presentation values exist for current definition value
                        if (($WEDefinitionValuesPresentationValues.id | Measure-Object).Count -ge 1) {
                            $i = 0
                            $WEPresentationValues = New-Object -TypeName System.Collections.ArrayList
                            foreach ($WEPresentationValue in $WEDefinitionValuesPresentationValues) {
                                # Handle multiple items in case of an array
                                if (($WEDefinitionsPresentations.id).Count -ge 1) {
                                    $WEDefinitionsPresentationsID = $WEDefinitionsPresentations[$i].id
                                }
                                else {
                                   ;  $WEDefinitionsPresentationsID = $WEDefinitionsPresentations.id
                                }

                                # Construct new presentation value object
                               ;  $WECurrentObject = $WEPresentationValue | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
                                $WECurrentObject | Add-Member -MemberType " NoteProperty" -Name " presentation@odata.bind" -Value " https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($WEDefinitionValuesDefinition.id)')/presentations('$($WEDefinitionsPresentationsID)')"
                                $WEPresentationValues.Add($WECurrentObject) | Out-Null
                                $i++
                            }

                            # Add all presentation value objects to custom object
                            $WEPSObject | Add-Member -MemberType NoteProperty -Name " presentationValues" -Value $WEPresentationValues
                        }

                        Write-Verbose -Message " Exporting administrative template setting with name: $($WEDefinitionValuesDefinitionDisplayName)"
                        Export-JSON -InputObject $WEPSObject -Path $WEAdministrativeTemplateProfileFolderPath -Name $WEDefinitionValuesDefinitionDisplayName -Type " AdministrativeTemplate"
                    }
                }
            }
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================