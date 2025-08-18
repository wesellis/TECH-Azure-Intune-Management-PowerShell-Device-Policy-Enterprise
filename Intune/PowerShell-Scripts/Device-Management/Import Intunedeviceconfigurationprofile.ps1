<#
.SYNOPSIS
    Import Intunedeviceconfigurationprofile

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
    We Enhanced Import Intunedeviceconfigurationprofile

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
    Import device configuration profiles for Windows, iOS/iPadOS, AndroidEnterprise, macOS platforms stored as JSON files into a specific Intune tenant.

.DESCRIPTION
    Import device configuration profiles for Windows, iOS/iPadOS, AndroidEnterprise, macOS platforms stored as JSON files into a specific Intune tenant.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER Platform
    Specify the given platforms that device configuration profiles should be imported for.

.PARAMETER Path
    Specify an existing local path to where the Device Configuration JSON files are located.

.PARAMETER Prefix
    Specify the prefix that will be added to the device configuration profile name.    

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

.PARAMETER PromptBehavior
    Set the prompt behavior when acquiring a token.

.EXAMPLE
    # Import all device configuration profiles for all platforms from 'C:\Temp\Intune' into a tenant named 'domain.onmicrosoft.com':
    .\Import-IntuneDeviceConfigurationProfile.ps1 -TenantName " domain.onmicrosoft.com" -Platform " Windows" , " iOS" , " AndroidEnterprise" , " macOS" -Path C:\Temp\Intune -Prefix " CompanyName" -Verbose

.NOTES
    FileName:    Import-IntuneDeviceConfigurationProfile.ps1
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

    [parameter(Mandatory = $false, HelpMessage = " Specify the given platforms that device configuration profiles should be imported for." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" Windows" , " iOS" , " AndroidEnterprise" , " macOS" )]
    [string[]]$WEPlatform,

    [parameter(Mandatory = $true, HelpMessage = " Specify an existing local path to where the Device Configuration JSON files are located." )]
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

    [parameter(Mandatory = $false, HelpMessage = " Specify the prefix that will be added to the device configuration profile name." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPrefix,

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

    # Validate that given path contains JSON files
    try {
        $WEJSONFiles = Get-ChildItem -Path $WEPath -Filter *.json -ErrorAction Stop
        if ($WEJSONFiles -eq $null) {
           ;  $WESkipDeviceConfigurationProfiles = $true
            Write-Warning -Message " Specified path doesn't contain any .json files, skipping device configuration profile import actions"
        }
        else {
           ;  $WESkipDeviceConfigurationProfiles = $false
            Write-Verbose -Message " Specified path contains .json files for device configuration profiles, will include those for import"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to validate .json files existence in given path. Error message: $($_.Exception.Message)" ; break
    }

    # Check if given path contains any directories assuming they're exported administrative templates
    try {
        $WEAdministrativeTemplateFolders = Get-ChildItem -Path $WEPath -Directory -ErrorAction Stop
        if ($WEAdministrativeTemplateFolders -eq $null) {
           ;  $WESkipAdministrativeTemplateProfiles = $true
            Write-Warning -Message " Specified path doesn't contain any exported Administrative Template folders, skipping administrative template profile import actions"
        }
        else {
            Write-Verbose -Message " Specified path contains exported administrative template folders, will include those for import"
           ;  $WESkipAdministrativeTemplateProfiles = $false
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to validate administrative template folders existence in given path. Error message: $($_.Exception.Message)" ; break
    }
}
Process {
    # Functions
    function WE-Get-ErrorResponseBody {
        [CmdletBinding()]
$ErrorActionPreference = "Stop"
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
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEURI,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$WEBody
        )
        try {
            # Call Graph API and get JSON response
            $WEGraphResponse = Invoke-RestMethod -Uri $WEURI -Headers $WEAuthToken -Method Post -Body $WEBody -ContentType " application/json" -ErrorAction Stop -Verbose:$false

            return $WEGraphResponse
        }
        catch [System.Exception] {
            # Construct stream reader for reading the response body from API call
            $WEResponseBody = Get-ErrorResponseBody -Exception $_.Exception
    
            # Handle response output and error message
            Write-Output -InputObject " Response content:`n$WEResponseBody"
            Write-Warning -Message " Request to $($WEURI) failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
        }
    }

    function WE-Test-JSON {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$WEInputObject
        )
        try {
            # Convert from hash-table to JSON
            ConvertTo-Json -InputObject $WEInputObject -ErrorAction Stop
    
            # Return true if conversion was successful
            return $true
        }
        catch [System.Exception] {
            return $false
        }
    }

    function WE-Get-Platform {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEInputObject
        )
        switch -Regex ($WEInputObject) {
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

        # Handle return value
        return $WEPlatformType
    }

    function WE-New-IntuneDeviceConfigurationProfile {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEJSON
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/deviceConfigurations"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $WEGraphURI -Body $WEJSON
    }

    function WE-New-IntuneAdministrativeTemplateProfile {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEJSON
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/groupPolicyConfigurations"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        $WEGraphResponse = Invoke-IntuneGraphRequest -URI $WEGraphURI -Body $WEJSON

        # Handle return value
        return $WEGraphResponse.id
    }

    function WE-New-IntuneAdministrativeTemplateDefinitionValues {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAdministrativeTemplateID,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEJSON
        )
        # Construct Graph variables
        $WEGraphVersion = " beta"
        $WEGraphResource = " deviceManagement/groupPolicyConfigurations/$($WEAdministrativeTemplateID)/definitionValues"
        $WEGraphURI = " https://graph.microsoft.com/$($WEGraphVersion)/$($WEGraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $WEGraphURI -Body $WEJSON
    }    

    # Ensure all given platforms are available in a list array for further reference
    $WEPlatformList = New-Object -TypeName System.Collections.ArrayList
    foreach ($WEPlatformItem in $WEPlatform) {
        $WEPlatformList.Add($WEPlatformItem) | Out-Null
    }

    # Process each JSON file located in given path
    if ($WESkipDeviceConfigurationProfiles -eq $false) {
        foreach ($WEJSONFile in $WEJSONFiles.FullName) {
            Write-Verbose -Message " Processing JSON data file from: $($WEJSONFile)"
    
            try {
                # Read JSON data from current file
                $WEJSONDataContent = Get-Content -Path $WEJSONFile -ErrorAction Stop -Verbose:$false
    
                try {
                    $WEJSONData = $WEJSONDataContent | ConvertFrom-Json -ErrorAction Stop | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags
                    $WEJSONPlatform = Get-Platform -InputObject $WEJSONData.'@odata.type'
                    $WEJSONDisplayName = $WEJSONData.displayName
    
                    # Handle device configuration profile name if prefix parameter is specified
                    if ($WEPSBoundParameters[" Prefix" ]) {
                        $WEJSONDisplayName = -join($WEPrefix, $WEJSONData.displayName)
                        $WEJSONData.displayName = $WEJSONDisplayName
                    }
    
                    if ($WEJSONPlatform -in $WEPlatform) {
                        Write-Verbose -Message " Validating JSON data content import for profile: $($WEJSONDisplayName)"
    
                        if (Test-JSON -InputObject $WEJSONData) {
                            Write-Verbose -Message " Successfully validated JSON data content for import, proceed to import profile"
                            
                            # Convert from object to JSON string
                            $WEJSONDataConvert = $WEJSONData | ConvertTo-Json -Depth 5
    
                            # Create new device configuration profile based on JSON data
                            Write-Verbose -Message " Attempting to create new device configuration profile with name: $($WEJSONDisplayName)"
                            $WEGraphRequest = New-IntuneDeviceConfigurationProfile -JSON $WEJSONDataConvert
    
                            if ($WEGraphRequest.'@odata.type' -like $WEJSONPlatform) {
                                Write-Verbose -Message " Successfully created device configuration profile"
                            }
                        }
                        else {
                            Write-Verbose -Message " Failed to validate JSON data object to be converted to JSON string"
                        }
                    }
                    else {
                        Write-Verbose -Message " Current JSON data file for platform type '$($WEJSONPlatform)' was not allowed to be imported, skipping"
                    }
                }
                catch [System.Exception] {
                    Write-Warning -Message " Failed to convert JSON data content. Error message: $($_.Exception.Message)"
                }
            }
            catch [System.Exception] {
                Write-Warning -Message " Failed to read JSON data content from file '$($WEJSONFile)'. Error message: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Verbose -Message " Skipping device configuration profile import actions as no .json files was found in given location"
    }

    # Process each administrative template folder
    if ($WESkipAdministrativeTemplateProfiles -eq $false) {
        foreach ($WEAdministrativeTemplateFolder in $WEAdministrativeTemplateFolders) {
            # Get administrative template variable parameters
            $WEAdministrativeTemplateName = $WEAdministrativeTemplateFolder.Name
            $WEAdministrativeTemplatePath = $WEAdministrativeTemplateFolder.FullName

            # Validate that current administrative template folder contains JSON files
            $WEAdministrativeTemplateFolderJSONFiles = Get-ChildItem -Path $WEAdministrativeTemplatePath -Filter *.json
            if ($WEAdministrativeTemplateFolderJSONFiles -ne $null) {
                # Handle administrative template profile name if prefix parameter is specified
                if ($WEPSBoundParameters[" Prefix" ]) {
                    $WEAdministrativeTemplateName = -join($WEPrefix, $WEAdministrativeTemplateName)
                }

                # Construct new administrative template profile object
                Write-Verbose -Message " Attempting to create new administrative template profile with name: $($WEAdministrativeTemplateName)"
                $WEAdministrativeTemplateProfileJSONDataTable = @{
                    " displayName" = $WEAdministrativeTemplateName
                    " description" = [string]::Empty
                }
                $WEAdministrativeTemplateProfileJSONData = $WEAdministrativeTemplateProfileJSONDataTable | ConvertTo-Json
                $WEAdministrativeTemplateProfileID = New-IntuneAdministrativeTemplateProfile -JSON $WEAdministrativeTemplateProfileJSONData
                
                # Process each subsequent JSON file in current administrative template profile folder
                foreach ($WEAdministrativeTemplateFolderJSONFile in $WEAdministrativeTemplateFolderJSONFiles) {
                    # Read JSON data from current file
                    $WEJSONDataContent = Get-Content -Path $WEAdministrativeTemplateFolderJSONFile.FullName -ErrorAction Stop -Verbose:$false

                    try {
                        $WEJSONData = $WEJSONDataContent | ConvertFrom-Json -ErrorAction Stop
                        Write-Verbose -Message " Validating JSON data content import for defintion values: $($WEAdministrativeTemplateFolderJSONFile.Name)"
    
                        if (Test-JSON -InputObject $WEJSONData) {
                            Write-Verbose -Message " Successfully validated JSON data content for import, proceed to import defintion values"
                            
                            # Convert from object to JSON string
                           ;  $WEJSONDataConvert = $WEJSONData | ConvertTo-Json -Depth 5
    
                            # Create new administrative template definition values based on JSON data
                            Write-Verbose -Message " Attempting to create new administrative template definition values with name: $($WEAdministrativeTemplateFolderJSONFile.Name)"
                           ;  $WEGraphRequest = New-IntuneAdministrativeTemplateDefinitionValues -AdministrativeTemplateID $WEAdministrativeTemplateProfileID -JSON $WEJSONDataConvert

                            if ($WEGraphRequest.configurationType -like " policy" ) {
                                Write-Verbose -Message " Successfully created administrative template definition values"
                            }
                        }
                        else {
                            Write-Verbose -Message " Failed to validate JSON data object to be converted to JSON string"
                        }                        
                    }
                    catch [System.Exception] {
                        Write-Warning -Message " Failed to convert JSON data content from file. Error message: $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Warning -Message " Failed to locate sub-sequent .json files within administrative template profile folder: $($WEAdministrativeTemplatePath)"
            }
        }
    }
    else {
        Write-Verbose -Message " Skipping administrative template import actions as no sub-directories was found in given location"
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================