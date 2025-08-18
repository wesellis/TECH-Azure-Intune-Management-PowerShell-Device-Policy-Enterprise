<#
.SYNOPSIS
    New Msintuneiosapp

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
    We Enhanced New Msintuneiosapp

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
    Add a single or multiple new managed or non-managed iOS apps in Intune.

.DESCRIPTION
    This script will add a single or multiple new managed or non-managed iOS apps in the specified Intune tenant. Application information
    will automatically be detected from the iTunes app store and passed to the app created in Intune.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER AppName
    Name of the app that will be added.

.PARAMETER AppType
    App type, either Managed or Non-Managed. A managed app wraps the Intune SDK.

.PARAMETER Featured
    Use this switch if the app should be set as featured in the Company Portal app.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration.

.EXAMPLE
    # Add a single app called 'Microsoft Outlook':
    .\New-MSIntuneiOSApp.ps1 -TenantName domain.onmicrosoft.com -AppName 'Microsoft Outlook' -AppType ManagedApp

    # Add two apps called 'Microsoft Outlook' and 'Microsoft Word':
    .\New-MSIntuneiOSApp.ps1 -TenantName domain.onmicrosoft.com -AppName 'Microsoft Outlook', 'Microsoft Word' -AppType ManagedApp

.NOTES
    FileName:    New-MSIntuneiOSApp.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2017-07-25
    Updated:     2017-07-25
    
    Version history:
    1.0.0 - (2017-07-25) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)

[CmdletBinding(SupportsShouldProcess=$true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory=$true, HelpMessage=" Specify the tenant name, e.g. domain.onmicrosoft.com." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WETenantName,

    [parameter(Mandatory=$true, HelpMessage=" Name of the app that will be added." )]
    [ValidateNotNullOrEmpty()]
    [string[]]$WEAppName,

    [parameter(Mandatory=$true, HelpMessage=" App type, either Managed or Non-Managed. A managed app wraps the Intune SDK." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" ManagedApp" , " NonManagedApp" )]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAppType,

    [parameter(Mandatory=$false, HelpMessage=" Use this switch if the app should be set as featured in the Company Portal app." )]
    [switch]$WEFeatured,

    [parameter(Mandatory=$false, HelpMessage=" Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEApplicationID = " d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
)
Begin {
    # Determine if the PSIntuneAuth module needs to be installed or updated
    try {
        Write-Verbose -Message " Attempting to locate PSIntuneAuth module"
        $WEPSIntuneAuthModule = Get-InstalledModule -Name PSIntuneAuth -ErrorAction Stop -Verbose:$false
        if ($null -ne $WEPSIntuneAuthModule) {
            Write-Verbose -Message " Authentication module detected, checking for latest version"
           ;  $WELatestModuleVersion = (Find-Module -Name PSIntuneAuth -ErrorAction Stop -Verbose:$false).Version
            if ($WELatestModuleVersion -gt $WEPSIntuneAuthModule.Version) {
                Write-Verbose -Message " Latest version of PSIntuneAuth module is not installed, attempting to install: $($WELatestModuleVersion.ToString())"
               ;  $WEUpdateModuleInvocation = Update-Module -Name PSIntuneAuth -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " Unable to detect PSIntuneAuth module, attempting to install from PSGallery"
        try {
            Install-Module -Name PSIntuneAuth -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
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
            $WEGlobal:AuthToken = Get-MSIntuneAuthToken -TenantName $WETenantName -ClientID $WEApplicationID
        }
        else {
            Write-Verbose -Message " Existing authentication token has not expired, will not request a new token"
        }        
    }
    else {
        Write-Verbose -Message " Authentication token does not exist, requesting a new token"
        $WEGlobal:AuthToken = Get-MSIntuneAuthToken -TenantName $WETenantName -ClientID $WEApplicationID
    }
}
Process {
    # Define Intune Graph API resources
    $WEGraphURI = " https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"

    # Process each app from parameter input
    foreach ($WEApp in $WEAppName) {
        # Trim app name if it contains spaces
        $WEAppUntrimmed = $WEApp
        $WEApp = ($WEApp -replace " " , " +" ).ToLower()

        # Construct app store search URL
        $WEAppStoreURL = " https://itunes.apple.com/search?term=$($WEApp)&entity=software&limit=1"
        
        # Call app store for objects matching name
        try {
            Write-Verbose -Message " Attempting to locate '$($WEAppUntrimmed)' in iTunes app store"
           ;  $WEWebRequest = Invoke-WebRequest -Method Get -Uri $WEAppStoreURL -ErrorAction Stop
           ;  $WEAppStoreContent = ConvertFrom-Json -InputObject $WEWebRequest.Content -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message " An error occurred while attempting retrieve apps from iTunes app store. Error message: $($_.Exception.Message)" ; break
        }

        # Validate results from web request
        if ($WEAppStoreContent.results -ne $null) {
            # Set app object
            $WEAppResult = $WEAppStoreContent.results
            Write-Verbose -Message " App search returned object: $($WEAppResult.trackName)"

            # Determine app icon URL
            Write-Verbose -Message " Attempting to use app icon size: 60x60"
            $WEAppIconURL = $WEAppResult.artworkUrl60
            if ([System.String]::IsNullOrEmpty($WEAppIconURL)) {
                Write-Verbose -Message " Attempting to use app icon size: 100x100"
                $WEAppIconURL = $WEAppResult.artworkUrl100
                if ([System.String]::IsNullOrEmpty($WEAppIconURL)) {
                    Write-Verbose -Message " Attempting to use app icon size: 512x512"
                    $WEAppIconURL = $WEAppResult.artworkUrl512
                }
            }

            # Get icon information
            try {
                $WEIconWebRequest = Invoke-WebRequest -Uri $WEAppIconURL -ErrorAction Stop
               ;  $WEIconContent = [System.Convert]::ToBase64String($WEIconWebRequest.Content)
               ;  $WEIconType = $WEIconWebRequest.Headers[" Content-Type" ]
            }
            catch [System.Exception] {
                Write-Warning -Message " An error occurred while reading icon content. Error message: $($_.Exception.Message)" ; break
            }

            # Get app general information
            Write-Verbose -Message " Processing app details: minimumOSVersion, description, appVersion"
            $WEAppSystemVersion = [System.Version]$WEAppResult.minimumOsVersion
            $WEAppVersion = -join($WEAppSystemVersion.Major, " ." , $WEAppSystemVersion.Minor)
            $WEAppDescription = $WEAppResult.description -replace " [^\x00-\x7F]+" ,""

            # Detect app supported devices
            Write-Verbose -Message " Processing app details: supportedDevices"
            if ($WEAppResult.supportedDevices -match " iPad" ) {
                $iPadSupport = $true
            }
            else {
                $iPadSupport = $false
            }
            if ($WEAppResult.supportedDevices -match " iPhone" ) {
                $iPhoneSupport = $true
            }
            else {
                $iPhoneSupport = $false
            }

            # Determine odata type
           ;  $WEODataTypeTable = @{
                " NonManagedApp" = " #microsoft.graph.iosStoreApp"
                " ManagedApp" = " #microsoft.graph.managedIOSStoreApp"
            }

            # Construct hash-table object of the application
            Write-Verbose -Message " Construct hash-table with required properties for BODY"
           ;  $WEAppDataTable = @{
                '@odata.type' = " $($WEODataTypeTable[$WEAppType])" ;
                displayName = $WEAppResult.trackName;
                publisher = $WEAppResult.artistName;
                description = $WEAppDescription;
                largeIcon = @{
                    type = $WEIconType;
                    value = $WEIconContent;
                };
                isFeatured = $false;
                appStoreUrl = $WEAppResult.trackViewUrl;
                applicableDeviceType=@{
                    iPad = $iPadSupport;
                    iPhoneAndIPod = $iPhoneSupport;
                };
                minimumSupportedOperatingSystem = @{
                    v8_0 = $WEAppVersion -lt 9.0;
                    v9_0 = $WEAppVersion -eq 9.0;
                    v10_0 = $WEAppVersion -gt 9.0;
                };
            };            
            
            # Convert to JSON and create application
            Write-Verbose -Message " Converting hash-table data to JSON"
            $WEAppDataJSON = ConvertTo-Json -InputObject $WEAppDataTable
            Write-Verbose -Message " Attempting to create app: $($WEAppUntrimmed)"
           ;  $WEInvocationResult = Invoke-RestMethod -Uri $WEGraphURI -Method Post -ContentType " application/json" -Body $WEAppDataJSON -Headers $WEAuthToken
            Write-Verbose -Message " Successfully created app '$($WEAppUntrimmed)' with ID: $($WEGraphURI)/$($WEInvocationResult.id)"
        }
        else {
            Write-Warning -Message " iTunes app store search returned zero matches for '$($WEAppUntrimmed)'"
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================