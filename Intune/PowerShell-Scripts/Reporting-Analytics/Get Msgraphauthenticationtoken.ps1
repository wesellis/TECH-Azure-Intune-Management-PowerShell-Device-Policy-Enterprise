<#
.SYNOPSIS
    Get Msgraphauthenticationtoken

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
    We Enhanced Get Msgraphauthenticationtoken

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


[CmdletBinding()]
function WE-Get-MSGraphAuthenticationToken -ErrorAction Stop {
}


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
function WE-Get-MSGraphAuthenticationToken -ErrorAction Stop {
    <#
    .SYNOPSIS
        Get an authentication token required for interacting with Microsoft Intune using Microsoft Graph API
        NOTE: This function requires that AzureAD module is installed. Use 'Install-Module -Name AzureAD' to install it.

    .PARAMETER TenantName
        A tenant name should be provided in the following format: tenantname.onmicrosoft.com.

    .PARAMETER ClientID
        Application ID for an Azure AD application.

    .PARAMETER RedirectUri
        Redirect URI for Azure AD application. Leave empty to leverage Azure PowerShell well known redirect URI.

    .EXAMPLE
        Get-MSGraphAuthenticationToken -TenantName domain.onmicrsoft.com -ClientID " <GUID>"

    .NOTES
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2017-09-27
    Updated:     2017-09-27

    Version history:
    1.0.0 - (2017-09-27) Script created
    1.0.1 - (2017-09-28) N/A - module manifest update
    1.0.2 - (2017-10-08) Added ExpiresOn property

    #>
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [parameter(Mandatory=$true, HelpMessage=" A tenant name should be provided in the following format: tenantname.onmicrosoft.com." )]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WETenantName,

        [parameter(Mandatory=$true, HelpMessage=" Application ID for an Azure AD application." )]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEClientID,

        [parameter(Mandatory=$false, HelpMessage=" Redirect URI for Azure AD application. Leave empty to leverage Azure PowerShell well known redirect URI." )]
        [ValidateNotNullOrEmpty()]
        [string]$WERedirectUri = " urn:ietf:wg:oauth:2.0:oob"
    )

    try {
        # Get installed Azure AD modules
        $WEAzureADModules = Get-InstalledModule -Name " AzureAD" -ErrorAction Stop -Verbose:$false

        if ($null -ne $WEAzureADModules) {
            # Check if multiple modules exist and determine the module path for the most current version
            if (($WEAzureADModules | Measure-Object).Count -gt 1) {
                $WELatestAzureADModule = ($WEAzureADModules | Select-Object -Property Version | Sort-Object)[-1]
                $WEAzureADModulePath = $WEAzureADModules | Where-Object { $_.Version -like $WELatestAzureADModule.Version } | Select-Object -ExpandProperty InstalledLocation
            }
            else {
                $WEAzureADModulePath = Get-InstalledModule -Name " AzureAD" | Select-Object -ExpandProperty InstalledLocation
            }

            # Construct array for required assemblies from Azure AD module
            $WEAssemblies = @(
                (Join-Path -Path $WEAzureADModulePath -ChildPath " Microsoft.IdentityModel.Clients.ActiveDirectory.dll" ),
                (Join-Path -Path $WEAzureADModulePath -ChildPath " Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll" )
            )
            Add-Type -Path $WEAssemblies -ErrorAction Stop

            try {
                $WEAuthority = " https://login.microsoftonline.com/$($WETenantName)/oauth2/token"
                $WEResourceRecipient = " https://graph.microsoft.com"

                # Construct new authentication context
                $WEAuthenticationContext = New-Object -TypeName " Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $WEAuthority

                # Construct platform parameters
                $WEPlatformParams = New-Object -TypeName " Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList " Always" # Arguments: Auto, Always, Never, RefreshSession

                # Acquire access token
               ;  $WEAuthenticationResult = ($WEAuthenticationContext.AcquireTokenAsync($WEResourceRecipient, $WEClientID, $WERedirectUri, $WEPlatformParams)).Result
                
                # Check if access token was acquired
                if ($WEAuthenticationResult.AccessToken -ne $null) {
                    # Construct authentication hash table for holding access token and header information
                   ;  $WEAuthentication = @{
                        " Content-Type" = " application/json"
                        " Authorization" = -join(" Bearer " , $WEAuthenticationResult.AccessToken)
                        " ExpiresOn" = $WEAuthenticationResult.ExpiresOn
                    }

                    # Return the authentication token
                    return $WEAuthentication                    
                }
                else {
                    Write-Warning -Message " Failure to acquire access token. Response with access token was null" ; break
                }
            }
            catch [System.Exception] {
                Write-Warning -Message " An error occurred when constructing an authentication token: $($_.Exception.Message)" ; break
            }
        }
        else {
            Write-Warning -Message " Azure AD PowerShell module is not present on this system, please install before you continue" ; break
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " Unable to load required assemblies (Azure AD PowerShell module) to construct an authentication token. Error: $($_.Exception.Message)" ; break
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================