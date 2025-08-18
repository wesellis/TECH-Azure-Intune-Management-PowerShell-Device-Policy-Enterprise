<#
.SYNOPSIS
    Upload Windowsautopilotdeviceinfo

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
    We Enhanced Upload Windowsautopilotdeviceinfo

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
.VERSION 1.2.1
.GUID 8d3532b3-ff9f-4031-b06f-25fcab76c626
.AUTHOR NickolajA
.DESCRIPTION Gather device hash from local machine and automatically upload it to Autopilot
.COMPANYNAME MSEndpointMgr.com
.COPYRIGHT 
.TAGS Autopilot Windows Intune
.LICENSEURI 
.PROJECTURI https://github.com/MSEndpointMgr/Intune/blob/master/Autopilot/Upload-WindowsAutopilotDeviceInfo.ps1
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES

<#
.SYNOPSIS
    Gather device hash from local machine and automatically upload it to Autopilot.

.DESCRIPTION
    This script automatically gathers the device hash, serial number, manufacturer and model and uploads that data into Autopilot.
    Authentication is required within this script and required permissions for creating Autopilot device identities are needed.

.PARAMETER TenantID
    Specify the tenant name, e.g. tenantname.onmicrosoft.com.

.PARAMETER ClientID
    Application ID (Client ID) for an Azure AD service principal. Uses by default the 'Microsoft Intune PowerShell' service principal Application ID.

.PARAMETER ClientSecret
    Application secret (Client Secret) for an Azure AD service principal.

.PARAMETER GroupTag
    Specify the group tag to easier differentiate Autopilot devices, e.g. 'ABCSales'.

.PARAMETER UserPrincipalName
    Specify the primary user principal name, e.g. 'firstname.lastname@domain.com'.

.EXAMPLE
    # Gather device hash from local computer and upload to Autopilot using Intune Graph API's:
    .\Upload-WindowsAutopilotDeviceInfo.ps1 -TenantID "tenant.onmicrosoft.com"

    # Gather device hash from local computer and upload to Autopilot using Intune Graph API's with a given group tag as 'AADUserDriven':
    .\Upload-WindowsAutopilotDeviceInfo.ps1 -TenantID " tenant.onmicrosoft.com" -GroupTag " AADUserDriven"

    # Gather device hash from local computer and upload to Autopilot using Intune Graph API's with a given group tag as 'AADUserDriven' and 'somone@domain.com' as the assigned user:
    .\Upload-WindowsAutopilotDeviceInfo.ps1 -TenantID " tenant.onmicrosoft.com" -GroupTag " AADUserDriven" -UserPrincipalName " someone@domain.com"

.NOTES
    FileName:    Upload-WindowsAutopilotDeviceInfo.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-03-21
    Updated:     2023-06-07
    
    Version history:
    1.0.0 - (2019-03-21) Script created.
    1.1.0 - (2019-10-29) Added support for specifying the primary user assigned to the uploaded Autopilot device as well as renaming the OrderIdentifier parameter to GroupTag. Thanks to @Stgrdk for his contributions. Switched from Get-CimSession to Get-CimInstance to get device details from WMI.
    1.1.1 - (2021-03-24) Script now uses the groupTag property instead of the depcreated OrderIdentifier property. Also removed the code section that attempted to perform an Autopilot sync operation
    1.1.2 - (2021-03-24) Corrected a spelling mistake of 'GroupTag' to 'groupTag'
    1.2.0 - (2023-06-03) Switched from AzureAD and PSIntuneAuth modules to MSAL.PS and MSGraphRequest
    1.2.1 - (2023-06-07) Improved access token retrieval, now supports client credentials flow using ClientID and ClientSecret parameters

[CmdletBinding(SupportsShouldProcess=$true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Alias(" TenantName" )]
    [parameter(Mandatory = $true, ParameterSetName = " Interactive" , HelpMessage = " Specify the tenant name, e.g. tenantname.onmicrosoft.com." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WETenantID,

    [Alias(" ApplicationID" )]
    [parameter(Mandatory = $false, ParameterSetName = " Interactive" , HelpMessage = " Application ID (Client ID) for an Azure AD service principal. Uses by default the 'Microsoft Intune PowerShell' service principal Application ID." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEClientID,

    [parameter(Mandatory = $false, ParameterSetName = " Interactive" , HelpMessage = " Application secret (Client Secret) for an Azure AD service principal." )]
    [parameter(Mandatory = $true, ParameterSetName = " ClientSecret" )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEClientSecret,

    [parameter(Mandatory = $false, ParameterSetName = " Interactive" , HelpMessage = " Specify the group tag to easier differentiate Autopilot devices, e.g. 'ABCSales'." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEGroupTag,

    [parameter(Mandatory = $false, ParameterSetName = " Interactive" , HelpMessage = " Specify the primary user principal name, e.g. 'firstname.lastname@domain.com'." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEUserPrincipalName
)
Begin {
    Write-Verbose -Message " Parameter set name in use: $($WEPSCmdlet.ParameterSetName)"

    # Ensure required modules are installed and running the latest version
    $WEModules = @(" MSAL.PS" , " MSGraphRequest" )
    foreach ($WEModule in $WEModules) {
        try {
            Write-Verbose -Message " Attempting to locate $($WEModule) module"
            $WEModuleItem = Get-InstalledModule -Name $WEModule -ErrorAction Stop -Verbose:$false
            if ($WEModuleItem -ne $null) {
                Write-Verbose -Message " $($WEModule) module detected, checking for latest version"
                $WELatestModuleItemVersion = (Find-Module -Name $WEModule -ErrorAction Stop -Verbose:$false).Version
                if ($WELatestModuleItemVersion -gt $WEModuleItem.Version) {
                    Write-Verbose -Message " Latest version of $($WEModule) module is not installed, attempting to install: $($WELatestModuleVersion.ToString())"
                   ;  $WEUpdateModuleInvocation = Update-Module -Name $WEModule -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                }
            }
        }
        catch [System.Exception] {
            Write-Warning -Message " Unable to detect $($WEModule) module, attempting to install from PSGallery"
            try {
                # Install NuGet package provider
               ;  $WEPackageProvider = Install-PackageProvider -Name " NuGet" -Force -Verbose:$false
    
                # Install MSAL.PS module
                Install-Module -Name $WEModule -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                Write-Verbose -Message " Successfully installed $($WEModule)"
            }
            catch [System.Exception] {
                Write-Warning -Message " An error occurred while attempting to install $($WEModule) module. Error message: $($_.Exception.Message)" ; break
            }
        }
    }

    # Determine the correct RedirectUri (also known as Reply URL) to use with MSAL.PS
    if (-not([string]::IsNullOrEmpty($WEClientID))) {
        Write-Verbose -Message " Using custom Azure AD service principal specified with Application ID: $($WEClientID)"

        # Adjust RedirectUri parameter input in case non was passed on command line
        if ([string]::IsNullOrEmpty($WERedirectUri)) {
            switch -Wildcard ($WEPSVersionTable[" PSVersion" ]) {
                " 5.*" {
                    $WERedirectUri = " https://login.microsoftonline.com/common/oauth2/nativeclient"
                }
                " 7.*" {
                    $WERedirectUri = " http://localhost"
                }
            }
        }
    }
    else {
        # Define static variables
        $WEClientID = " d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
        $WERedirectUri = " urn:ietf:wg:oauth:2.0:oob"

        Write-Verbose -Message " Using the default 'Microsoft Intune PowerShell' service principal with Application (Client) ID: $($WEClientID)"
        Write-Verbose -Message " Using RedirectUri with value: $($WERedirectUri)"

        # Set default error action preference configuration
        $WEErrorActionPreference = " Stop"
    }

    # Construct table with common parameter input for Get-AccessToken function
    $WEAccessTokenArguments = @{
        " TenantId" = $WETenantID
        " ClientId" = $WEClientID
        " RedirectUri" = $WERedirectUri
        " ErrorAction" = " Stop"
    }

    # Dynamically add parameter input for Get-MsalToken based on parameter set name
    switch ($WEPSCmdlet.ParameterSetName) {
        " ClientSecret" {
            Write-Verbose " Using clientSecret"
            $WEAccessTokenArguments.Add(" ClientSecret" , $(ConvertTo-SecureString -String $WEClientSecret -AsPlainText -Force))
        }
    }

    # Retrieve access token
    Write-Verbose -Message " Retrieving access token"
    $WEGlobal:AccessToken = Get-AccessToken @AccessTokenArguments
}
Process {
    # Functions
    function WE-Get-ErrorResponseBody {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Exception]$WEException
        )

        # Read the error stream
        $WEErrorResponseStream = $WEException.Response.GetResponseStream()
       ;  $WEStreamReader = New-Object System.IO.StreamReader($WEErrorResponseStream)
        $WEStreamReader.BaseStream.Position = 0
        $WEStreamReader.DiscardBufferedData()
       ;  $WEResponseBody = $WEStreamReader.ReadToEnd();

        # Handle return object
        return $WEResponseBody
    }

    # Gather device hash data
    Write-Verbose -Message " Gather device hash data from local machine"
    $WEDeviceHashData = (Get-CimInstance -Namespace " root/cimv2/mdm/dmmap" -Class " MDM_DevDetail_Ext01" -Filter " InstanceID='Ext' AND ParentID='./DevDetail'" -Verbose:$false).DeviceHardwareData
    $WESerialNumber = (Get-CimInstance -Class " Win32_BIOS" -Verbose:$false).SerialNumber
    $WEProductKey = (Get-CimInstance -Class " SoftwareLicensingService" -Verbose:$false).OA3xOriginalProductKey

    # Construct Graph variables
    $WEGraphResource = " deviceManagement/importedWindowsAutopilotDeviceIdentities"

    # Construct hash table for new Autopilot device identity and convert to JSON
    Write-Verbose -Message " Constructing required JSON body based upon parameter input data for device hash upload"
    $WEAutopilotDeviceIdentity = [ordered]@{
        '@odata.type' = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
        'groupTag' = if ($WEGroupTag) { " $($WEGroupTag)" } else { "" }
        'serialNumber' = " $($WESerialNumber)"
        'productKey' = if ($WEProductKey) { " $($WEProductKey)" } else { "" }
        'hardwareIdentifier' = " $($WEDeviceHashData)"
        'assignedUserPrincipalName' = if ($WEUserPrincipalName) { " $($WEUserPrincipalName)" } else { "" }
        'state' = @{
            '@odata.type' = 'microsoft.graph.importedWindowsAutopilotDeviceIdentityState'
            'deviceImportStatus' = 'pending'
            'deviceRegistrationId' = ''
            'deviceErrorCode' = 0
            'deviceErrorName' = ''
        }
    }
   ;  $WEAutopilotDeviceIdentityJSON = $WEAutopilotDeviceIdentity | ConvertTo-Json

    try {
        # Call Graph API and post JSON data for new Autopilot device identity
        Write-Verbose -Message " Attempting to post data for hardware hash upload"
        Invoke-MSGraphOperation -Post -APIVersion " Beta" -Resource $WEGraphResource -Body $WEAutopilotDeviceIdentityJSON -ErrorAction " Stop"
    }
    catch [System.Exception] {
        # Construct stream reader for reading the response body from API call
       ;  $WEResponseBody = Get-ErrorResponseBody -Exception $_.Exception

        # Handle response output and error message
        Write-Output -InputObject " Response content:`n$WEResponseBody"
        Write-Warning -Message " Failed to upload hardware hash. Request failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
    }  
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================