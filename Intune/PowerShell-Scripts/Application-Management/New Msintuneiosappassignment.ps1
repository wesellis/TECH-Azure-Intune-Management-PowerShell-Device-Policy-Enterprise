<#
.SYNOPSIS
    New Msintuneiosappassignment

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
    We Enhanced New Msintuneiosappassignment

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
    Assign an iOS app in Intune to an Azure AD group.

.DESCRIPTION
    This script will create a new app assignment for an iOS app in Intune for an Azure AD group.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER ApplicationID
    Application ID property of the application that will be assigned to a given Azure AD group.

.PARAMETER GroupID
    Group ID property of an Azure AD group.

.PARAMETER InstallIntent
    Specify the installation intent for the app assignment. Valid values are: available, notApplicable, required, uninstall, availableWithoutEnrollment.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration.

.EXAMPLE
    # Assign an iOS app in Intune called 'App1' to an Azure AD group called 'All Users':
    .\New-MSIntuneiOSAppAssignment.ps1 -TenantName " domain.onmicrosoft.com" -AppID " <GUID>" -GroupID " <GUID>" -InstallIntent available

.NOTES
    FileName:    New-MSIntuneiOSAppAssignment.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2017-10-12
    Updated:     2017-10-12
    
    Version history:
    1.0.0 - (2017-10-12) Script created

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

    [parameter(Mandatory=$true, HelpMessage=" Application ID property of the application that will be assigned to a given Azure AD group." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAppID,
    
    [parameter(Mandatory=$true, HelpMessage=" Group ID property of an Azure AD group." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEGroupID,

    [parameter(Mandatory=$true, HelpMessage=" Specify the installation intent for the app assignment. Valid values are: available, notApplicable, required, uninstall, availableWithoutEnrollment." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" available" , " notApplicable" , " required" , " uninstall" , " availableWithoutEnrollment" )]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEInstallIntent,

    [parameter(Mandatory=$false, HelpMessage=" Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEApplicationID = " d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
)
Begin {
    # Determine if the PSIntuneAuth module needs to be installed
    try {
        Write-Verbose -Message " Attempting to locate PSIntuneAuth module"
        $WEPSIntuneAuthModule = Get-InstalledModule -Name PSIntuneAuth -ErrorAction Stop
        if ($WEPSIntuneAuthModule -ne $null) {
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
    $WEGraphURI = " https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($WEAppID)/groupAssignments"

    # Construct hash-table object of the app assignment
    $WEAssignmentDataTable = @{
        " @odata.type" = " #microsoft.graph.mobileAppGroupAssignment"
        " targetGroupId" = " $($WEGroupID)"
        " installIntent" = " $($WEInstallIntent)"
    }

    # Convert to JSON and create application
    Write-Verbose -Message " Converting hash-table data to JSON"
   ;  $WEAssignmentDataJSON = ConvertTo-Json -InputObject $WEAssignmentDataTable
    Write-Verbose -Message " Attempting to create app assignment for app with ID: $($WEAppID)"
   ;  $WEInvocationResult = Invoke-RestMethod -Uri $WEGraphURI -Method Post -ContentType " application/json" -Body $WEAssignmentDataJSON -Headers $WEAuthToken
    Write-Verbose -Message " Successfully created app assignment"
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================