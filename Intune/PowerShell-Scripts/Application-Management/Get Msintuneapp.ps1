<#
.SYNOPSIS
    Get Msintuneapp

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
    We Enhanced Get Msintuneapp

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
    Get app details for a specific mobile app from a Microsoft Intune tenant.

.DESCRIPTION
    This script will get app details for a specific mobile app from a Microsoft Intune tenant, by matching the objects returned from deviceAppManagement/mobileApps resource
    with the given value for AppName parameter.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER AppName
    Name of an existing mobile app.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration.

.EXAMPLE
    # Get app details for an app called 'Outlook', using the well known Microsoft Intune PowerShell app registration:
    .\Get-IntuneApp.ps1 -TenantName 'domain.onmicrosoft.com' -AppName 'Outlook'

    # Get app details for an app called 'Outlook', using a custom native app registration:
    .\Get-IntuneApp.ps1 -TenantName 'domain.onmicrosoft.com' -AppName 'Outlook' -ApplicationID '<GUID>'

.NOTES
    FileName:    Get-IntuneApp.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2017-07-25
    Updated:     2017-07-25
    
    Version history:
    1.0.0 - (2017-07-25) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)    

[CmdletBinding(SupportsShouldProcess=$true)]
[OutputType('MSIntuneGraph.Application')]
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

    [parameter(Mandatory=$true, HelpMessage=" Name of an existing mobile app." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAppName,

    [parameter(Mandatory=$false, HelpMessage=" Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEApplicationID = " d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
)
Begin {
    # Determine if the PSIntuneAuth module needs to be installed or updated
    try {
        Write-Verbose -Message " Attempting to locate PSIntuneAuth module"
        $WEPSIntuneAuthModule = Get-InstalledModule -Name PSIntuneAuth -ErrorAction Stop
        if ($null -ne $WEPSIntuneAuthModule) {
            Write-Verbose -Message " Authentication module detected, checking for latest version"
           ;  $WELatestModuleVersion = (Find-Module -Name PSIntuneAuth -ErrorAction Stop -Verbose:$false).Version
            if ($WELatestModuleVersion -gt $WEPSIntuneAuthModule.Version) {
                Write-Verbose -Message " Latest version of PSIntuneAuth module is not installed, attempting to install: $($WELatestModuleVersion.ToString())"
               ;  $WEUpdateModuleInvocation = Update-Module -Name PSIntuneAuth -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " Unable to detect PSIntuneAuth module, attempting to install from PSGallery"
        try {
            Install-Module -Name PSIntuneAuth -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false
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
            
    # Get app from Graph API
   ;  $WEMobileApps = (Invoke-RestMethod -Uri $WEGraphURI -Method Get -Headers $WEAuthToken).Value | Where-Object { $_.displayName -like " *$($WEAppName)*" }

    foreach ($WEMobileApp in $WEMobileApps) {
        # Create MSIntuneGraph.Application custom object
       ;  $WEPSObject = [PSCustomObject]@{
            PSTypeName = " MSIntuneGraph.Application"
            ODataType = $WEMobileApp.'@odata.type'
            Id = $WEMobileApp.id
            DisplayName = $WEMobileApp.displayName
            Publisher = $WEMobileApp.publisher
            Created = $WEMobileApp.createdDateTime
            LastModified = $WEMobileApp.lastModifiedDateTime
            IsFeatured = $WEMobileApp.isFeatured
            BundleID = $WEMobileApp.bundleId
            Description = $WEMobileApp.description
        }

        # Output object to pipeline
        Write-Output -InputObject $WEPSObject
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================