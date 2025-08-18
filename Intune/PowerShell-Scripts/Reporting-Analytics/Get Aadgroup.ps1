<#
.SYNOPSIS
    Get Aadgroup

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
    We Enhanced Get Aadgroup

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
    Get an Azure AD group object through Microsoft Graph API.

.DESCRIPTION
    This script will get an Azure AD group through Microsoft Graph API and return a custom object showing
    the display name, id and created date of that group.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER GroupName
    Name of the Azure AD group name.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration.

.EXAMPLE
    # Get an Azure AD group called 'All Users':
    .\Get-AADGroup.ps1 -TenantName " domain.onmicrosoft.com" -GroupName " All Users"

.NOTES
    FileName:    Get-AADGroup.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2017-10-12
    Updated:     2017-10-12
    
    Version history:
    1.0.0 - (2017-10-12) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)        

[CmdletBinding(SupportsShouldProcess=$true)]
[OutputType('MSIntuneGraph.AADGroup')]
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

    [parameter(Mandatory=$true, HelpMessage=" Name of the Azure AD group name." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEGroupName,

    [parameter(Mandatory=$false, HelpMessage=" Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEApplicationID = " d1ddf0e4-d672-4dae-b554-9d5bdfd93547"    
)
Begin {
    # Determine if the PSIntuneAuth module needs to be installed
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
            Install-Module -Name PSIntuneAuth -Scope AllUsers -Force -ErrorAction Stop -Confirm:$false
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
    # Graph URI
    $WEGraphURI = " https://graph.microsoft.com/v1.0/groups?`$filter=displayname eq '$($WEGroupName)'"

    # Get group object from Graph API
   ;  $WEAADGroup = (Invoke-RestMethod -Uri $WEGraphURI -Method Get -Headers $WEAuthToken).Value
    if ($null -ne $WEAADGroup) {
       ;  $WEPSObject = [PSCustomObject]@{
            PSTypeName = " MSIntuneGraph.AADGroup"
            DisplayName = $WEAADGroup.displayName
            GroupID = $WEAADGroup.id
            CreatedDateTime = $WEAADGroup.createdDateTime
        }

        # Output object to pipeline
        Write-Output -InputObject $WEPSObject
    }
    else {
        Write-Warning -Message " Unable to find a group matching specified '$($WEGroupName)'"
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================