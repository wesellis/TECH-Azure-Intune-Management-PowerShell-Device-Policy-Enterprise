<#
.SYNOPSIS
    Set Msintuneprofiletypescopetag

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
    We Enhanced Set Msintuneprofiletypescopetag

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
    Set a specific Scope Tag for all or specific platforms, e.g. Windows and/or macOS (supported for iOS and Android as well) on the desired profiles types, e.g. DeviceConfigurations, SecurityBaselines and more.

.DESCRIPTION
    This script can perform multiple methods to manage Scope Tags on configuration profiles, such as:
    - Add
      - This method will add a specific Scope Tag to defined profile types, leaving existing Scope Tags still assigned
    - Remove
      - This method will remove a specific Scope Tag from defined profile types, leaving any other Scope Tag still assigned
    - Replace
      - This method will replace all existing Scope Tags on defined profile types, with the specific Scope Tag

    NOTE: The default method used by this script, when the Method parameter is not passed on the command line, is 'Add'.

    The following configuration profiles, policies and script item types are supported:
    - DeviceConfiguration
    - DeviceCompliance
    - SettingsCatalog
    - SecurityBaseline
    - EndpointSecurityAntivirus
    - EndpointSecurityDiskEncryption
    - EndpointSecurityFirewall
    - EndpointSecurityAttackSurfaceReduction
    - EndpointSecurityEndpointDetectionAndResponse
    - EndpointSecurityAccountProtection
    - DeviceManagementScripts
    - DeviceHealthScripts
    - WindowsFeatureUpdateProfiles
    - WindowsQualityUpdateProfiles
    - WindowsDriverUpdateProfiles
    - AssignmentFilters
    - DeviceShellScripts
    - DeviceCustomAttributeShellScripts
    - GroupPolicyConfigurations
    - DeviceEnrollmentConfigurations
    - WindowsAutopilotDeploymentProfiles
    - EnrollmentNotifications
    - DeviceEnrollmentStatusPage
    - IntuneBrandingProfiles
    - AppleVPPTokens
    - MicrosoftTunnelSites
    - MicrosoftTunnelConfigurations

    NOTE: By default, when the ProfileType parameter is not passed on the command line, all profile types are used.

.PARAMETER TenantID
    Specify the Azure AD tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.

.PARAMETER ClientID
    Specify the service principal (also known as an app registration) Client ID (also known as Application ID). If not specified, script will default to well known 'Microsoft Intune PowerShell' application.

.PARAMETER Platform
    Specify platform to scope the desired configuration profiles.

.PARAMETER ScopeTagName
    Specify the name of an existing Scope Tag that will be assigned to all specified profile types per platform.

.PARAMETER Include
    Specify a string pattern to match for the name or displayName property of each profile type, to include only the the matching profiles when adding a Scope Tag.

.PARAMETER Exclude
    Specify a string pattern to match for the name or displayName property of each profile type, to exclude adding a Scope Tag to the matching profiles.

.PARAMETER Method
    Specify 'Add' to append the specific Scope Tag, 'Replace' to replace all existing Scope Tags with the specific Scope Tag or 'Remove' to remove the specific Scope Tag.

.PARAMETER First
    Specify the amount of profile type items to limit the overall operation to, e.g. only the first 3 items.

.PARAMETER ProfileType
    Specify the profile type to include where the specified Scope Tag will be added. By default, all profile types are specified.

.PARAMETER ThrottleInSeconds
    Specify the time in seconds to wait in between multiple PATCH requests, when adding or removing Scope Tags.

.EXAMPLE
    # Add a scope tag named 'NewYork' to all Windows configuration profile types:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'NewYork'

    # Add a scope tag named 'NewYork' to all Windows configuration profile types where the display name matches the 'NY' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'NewYork' -Include 'NY'

    # Add a scope tag named 'NewYork' to all Windows and macOS configuration profile types where the display name matches the 'NY' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows', 'macOS' -ScopeTagName 'NewYork' -Include 'NY'

    # Add a scope tag named 'NewYork' to all Windows and macOS configuration profile types where the display name matches the 'NY' pattern and excludes any profiles matching 'LDN':
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows', 'macOS' -ScopeTagName 'NewYork' -Include 'NY' -Exclude 'LDN'

    # Add a scope tag named 'NewYork' to all Linux configuration profile types where the display name matches the 'NY' pattern, but validate the alterations before hand using -WhatIf:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Linux' -ScopeTagName 'NewYork' -Include 'NY' -WhatIf

    # Add a scope tag named 'NewYork' to only the first 3 Windows configuration profile types where the display name matches the 'NY' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'NewYork' -Include 'NY' -First 3

    # Remove a scope tag named 'London' from all iOS configuration profile types:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'iOS' -ScopeTagName 'London' -Method 'Remove'

    # Remove a scope tag named 'London' from all iOS configuration profile types where the display name matches the 'LDN' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'iOS' -ScopeTagName 'London' -Include 'LDN' -Method 'Remove'

    # Remove a scope tag named 'London' from only the first 3 iOS configuration profile types where the display name matches the 'LDN' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'iOS' -ScopeTagName 'London' -Include 'LDN' -Method 'Remove' -First 3

    # Replace all existing scope tags with a scope tag named 'Stockholm' on all Windows configuration profile types:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'Stockholm' -Method 'Replace'

    # Replace all existing scope tags with a scope tag named 'Stockholm' on all Windows configuration profile types where the display name matches the 'STH' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'Stockholm' -Method 'Replace'

    # Replace all existing scope tags with a scope tag named 'Stockholm' for only the first 3 Windows configuration profile types where the display name matches the 'STH' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'Stockholm' -Method 'Replace' -First 3

.NOTES
    FileName:    Set-MSIntuneProfileTypeScopeTag.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2022-12-05
    Updated:     2023-02-16

    Version history:
    1.0.0 - (2022-12-05) Script created
    1.0.1 - (2023-02-16) Changed Pattern parameter to be named Include instead and added a new Exclude parameter

[CmdletBinding(SupportsShouldProcess)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $true, HelpMessage = " Specify the Azure AD tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'." )]
    [ValidateNotNullOrEmpty()]
    [string]$WETenantID = " ericsson.onmicrosoft.com" ,

    [parameter(Mandatory = $false, HelpMessage = " Specify the service principal (also known as an app registration) Client ID (also known as Application ID). If not specified, script will default to well known 'Microsoft Intune PowerShell' application." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEClientID,

    [parameter(Mandatory = $true, HelpMessage = " Specify platform to scope the desired configuration profiles." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" Windows" , " macOS" , " Linux" , " iOS" , " Android" )]
    [string[]]$WEPlatform,

    [parameter(Mandatory = $true, HelpMessage = " Specify the name of an existing Scope Tag that will be assigned to all specified profile types per platform." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEScopeTagName,

    [parameter(Mandatory = $false, HelpMessage = " Specify a string pattern to match for the name or displayName property of each profile type, to include only the the matching profiles when adding a Scope Tag." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEInclude,

    [parameter(Mandatory = $false, HelpMessage = " Specify a string pattern to match for the name or displayName property of each profile type, to exclude adding a Scope Tag to the matching profiles." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEExclude,

    [parameter(Mandatory = $false, HelpMessage = " Specify 'Add' to append the specific Scope Tag, 'Replace' to replace all existing Scope Tags with the specific Scope Tag or 'Remove' to remove the specific Scope Tag." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" Add" , " Remove" , " Replace" )]
    [string]$WEMethod = " Add" ,

    [parameter(Mandatory = $false, HelpMessage = " Specify the amount of profile type items to limit the overall operation to, e.g. only the first 3 items." )]
    [ValidateNotNullOrEmpty()]
    [int]$WEFirst,

    [parameter(Mandatory = $false, HelpMessage = " Specify the profile type to include where the specified Scope Tag will be added. By default, all profile types are specified." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" DeviceConfiguration" , " DeviceCompliance" , " SettingsCatalog" , " SecurityBaseline" , " EndpointSecurityAntivirus" , " EndpointSecurityDiskEncryption" , " EndpointSecurityFirewall" , " EndpointSecurityAttackSurfaceReduction" , " EndpointSecurityEndpointDetectionAndResponse" , " EndpointSecurityAccountProtection" , " DeviceManagementScripts" , " DeviceHealthScripts" , " WindowsFeatureUpdateProfiles" , " WindowsQualityUpdateProfiles" , " WindowsDriverUpdateProfiles" , " AssignmentFilters" , " DeviceShellScripts" , " DeviceCustomAttributeShellScripts" , " GroupPolicyConfigurations" , " DeviceEnrollmentConfigurations" , " WindowsAutopilotDeploymentProfiles" , " EnrollmentNotifications" , " DeviceEnrollmentStatusPage" , " IntuneBrandingProfiles" , " AppleVPPTokens" , " MicrosoftTunnelSites" , " MicrosoftTunnelConfigurations" )]
    [string[]]$WEProfileType = @(" DeviceConfiguration" , " DeviceCompliance" , " SettingsCatalog" , " SecurityBaseline" , " EndpointSecurityAntivirus" , " EndpointSecurityDiskEncryption" , " EndpointSecurityFirewall" , " EndpointSecurityAttackSurfaceReduction" , " EndpointSecurityEndpointDetectionAndResponse" , " EndpointSecurityAccountProtection" , " DeviceManagementScripts" , " DeviceHealthScripts" , " WindowsFeatureUpdateProfiles" , " WindowsQualityUpdateProfiles" , " WindowsDriverUpdateProfiles" , " AssignmentFilters" , " DeviceShellScripts" , " DeviceCustomAttributeShellScripts" , " GroupPolicyConfigurations" , " DeviceEnrollmentConfigurations" , " WindowsAutopilotDeploymentProfiles" , " EnrollmentNotifications" , " DeviceEnrollmentStatusPage" , " IntuneBrandingProfiles" , " AppleVPPTokens" , " MicrosoftTunnelSites" , " MicrosoftTunnelConfigurations" ),

    [parameter(Mandatory = $false, HelpMessage = " Specify the time in seconds to wait in between multiple PATCH requests, when adding or removing Scope Tags." )]
    [ValidateNotNullOrEmpty()]
    [ValidateRange(1,15)]
    [int]$WEThrottleInSeconds = 3
)
Begin {
    # Use TLS 1.2 connection when invoking web requests
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Process {
    try {
        # Retrieve access token
        if ($WEPSBoundParameters[" ClientID" ]) {
            Write-Verbose -Message " Requesting access token for tenant '$($WETenantID)' with ClientID: $($WEClientID)"
            $WEAuthToken = Get-AccessToken -TenantID $WETenantID -ClientID $WEClientID -ErrorAction " Stop"
        }
        else {
            Write-Verbose -Message " Requesting access token for tenant: $($WETenantID)"
            $WEAuthToken = Get-AccessToken -TenantID $WETenantID -ErrorAction " Stop"
        }

        # Ensure a Scope Tag exists by given name from parameter input
        $WEScopeTagsUri = " deviceManagement/roleScopeTags?`$filter=displayName eq '$($WEScopeTagName)'"
        $WEScopeTag = Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource $WEScopeTagsUri
        if ($WEScopeTag -ne $null) {
            Write-Verbose -Message " Found Scope Tag with display name '$($WEScopeTag.displayName)' and id: $($WEScopeTag.id)"

            # Construct list of profiles where the specified Scope Tag should be added
            $WEProfilesList = New-Object -TypeName " System.Collections.ArrayList"

            # Process each platform
            foreach ($WEPlatformItem in $WEPlatform) {
                Write-Verbose -Message " Enumerating platform '$($WEPlatformItem)' specific profiles"

                # Define the platform data types used to filter objects returned from configuration profiles request
                switch ($WEPlatformItem) {
                    " Windows" {
                        $WEPlatformDataTypes = @(" microsoft.graph.windows" , " microsoft.graph.securityBaseline" , " microsoft.graph.sharedPC" )
                    }
                    " macOS" {
                        $WEPlatformDataTypes = @(" microsoft.graph.macOS" )
                    }
                    " iOS" {
                        $WEPlatformDataTypes = @(" microsoft.graph.ios" )
                    }
                    " Android" {
                        $WEPlatformDataTypes = @(" microsoft.graph.android" )
                    }
                }
                Write-Verbose -Message " Using platform specific data type filtering options: $($WEPlatformDataTypes -join " , " )"

                # Process all profile types
                foreach ($WEProfileTypeItem in $WEProfileType) {
                    Write-Verbose -Message " Current profile type: $($WEProfileTypeItem)"

                    # Instantiate resource, uri and filter variables
                    $WEResourceUri = $null
                    $WEFilterScript = $false

                    # Define request and filter variables for all platforms
                    switch ($WEProfileTypeItem) {
                        " DeviceConfiguration" {
                            $WEResource = " deviceConfigurations"
                            $WEResourceUri = " deviceManagement/$($WEResource)"
                            $WEFilterScript = $true
                        }
                        " AssignmentFilters" {
                            $WEResource = " assignmentFilters"
                            $WEResourceUri = " deviceManagement/$($WEResource)"
                        }
                        " EnrollmentNotifications" {
                            $WEResourceUri = " deviceManagement/deviceEnrollmentConfigurations?`$filter=deviceEnrollmentConfigurationType eq 'EnrollmentNotificationsConfiguration'"
                        }
                        " IntuneBrandingProfiles" {
                            $WEResource = " intuneBrandingProfiles"
                            $WEResourceUri = " deviceManagement/$($WEResource)"
                        }
                    }

                    # Define request variables for Windows, macOS, iOS and Android specific profile types
                    if ($WEPlatformItem -match " Windows|macOS|iOS|Android" ) {
                        switch ($WEProfileTypeItem) {
                            " DeviceCompliance" {
                                $WEResource = " deviceCompliancePolicies"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                                $WEFilterScript = $true
                            }
                            " SettingsCatalog" {
                                $WEResourceUri = " deviceManagement/configurationPolicies?`$filter=templateReference/templateFamily eq 'none'"
                            }
                        }
                    }

                    # Define request variables for Windows specific profile types in the Endpoint Protection
                    if ($WEPlatformItem -match " Windows|macOS|Linux" ) {
                        switch ($WEProfileTypeItem) {
                            " EndpointSecurityAntivirus" {
                                $WEResource = " endpointSecurityAntivirus"
                                $WEResourceUri = " deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($WEResource)'"
                            }
                            " EndpointSecurityDiskEncryption" {
                                $WEResource = " endpointSecurityDiskEncryption"
                                $WEResourceUri = " deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($WEResource)'"
                            }
                            " EndpointSecurityFirewall" {
                                $WEResource = " endpointSecurityFirewall"
                                $WEResourceUri = " deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($WEResource)'"
                            }
                            " EndpointSecurityAttackSurfaceReduction" {
                                $WEResource = " endpointSecurityAttackSurfaceReduction"
                                $WEResourceUri = " deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($WEResource)'"
                            }
                            " EndpointSecurityEndpointDetectionAndResponse" {
                                $WEResource = " endpointSecurityEndpointDetectionAndResponse"
                                $WEResourceUri = " deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($WEResource)'"
                            }
                            " EndpointSecurityAccountProtection" {
                                $WEResource = " endpointSecurityAccountProtection"
                                $WEResourceUri = " deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($WEResource)'"
                            }
                        }
                    }

                    # Define request variables for macOS and iOS specific profile types
                    if ($WEPlatformItem -match " macOS|iOS" ) {
                        switch ($WEProfileTypeItem) {
                            " AppleVPPTokens" {
                                $WEResource = " vppTokens"
                                $WEResourceUri = " deviceAppManagement/$($WEResource)"
                            }
                        }
                    }

                    # Define request variables for Android and iOS specific profile types
                    if ($WEPlatformItem -match " Android|iOS" ) {
                        switch ($WEProfileTypeItem) {
                            " MicrosoftTunnelSites" {
                                $WEResource = " microsoftTunnelSites"
                                $WEResourceUri = " deviceAppManagement/$($WEResource)"
                            }
                            " MicrosoftTunnelConfigurations" {
                                $WEResource = " microsoftTunnelConfigurations"
                                $WEResourceUri = " deviceAppManagement/$($WEResource)"
                            }
                        }
                    }

                    # Define request variables for Windows specific profile types
                    if ($WEPlatformItem -like " Windows" ) {
                        switch ($WEProfileTypeItem) {
                            " SecurityBaseline" {
                                $WEResourceUri = " deviceManagement/templates?`$filter=templateType eq 'securityBaseline'"
                            }
                            " GroupPolicyConfigurations" {
                                $WEResource = " groupPolicyConfigurations"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                            " DeviceManagementScripts" {
                                $WEResource = " deviceManagementScripts"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                            " DeviceHealthScripts" {
                                $WEResource = " deviceHealthScripts"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                            " WindowsFeatureUpdateProfiles" {
                                $WEResource = " windowsFeatureUpdateProfiles"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                            " WindowsQualityUpdateProfiles" {
                                $WEResource = " windowsQualityUpdateProfiles"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                            " WindowsDriverUpdateProfiles" {
                                $WEResource = " windowsDriverUpdateProfiles"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                            " DeviceEnrollmentStatusPage" {
                                $WEResourceUri = " deviceManagement/deviceEnrollmentConfigurations?`$filter=deviceEnrollmentConfigurationType eq 'Windows10EnrollmentCompletionPageConfiguration'"
                            }
                            " WindowsAutopilotDeploymentProfiles" {
                                $WEResource = " windowsAutopilotDeploymentProfiles"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                        }
                    }

                    # Define request variables for macOS specific profile types
                    if ($WEPlatformItem -eq " macOS" ) {
                        switch ($WEProfileTypeItem) {
                            " DeviceShellScripts" {
                                $WEResource = " deviceShellScripts"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                            " DeviceCustomAttributeShellScripts" {
                                $WEResource = " deviceCustomAttributeShellScripts"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                        }
                    }

                    # Define request variables for Linux specific profile types
                    if ($WEPlatformItem -eq " Linux" ) {
                        switch ($WEProfileTypeItem) {
                            " DeviceCompliance" {
                                $WEResource = " compliancePolicies"
                                $WEResourceUri = " deviceManagement/$($WEResource)"
                            }
                        }
                    }

                    # Process current profile item type if matching resource uri was set in any of the previous switch statements
                    if ($WEResourceUri -ne $null) {
                        try {
                            # Retrieve profiles for current profile type
                            switch ($WEProfileTypeItem) {
                                " SecurityBaseline" {
                                    Write-Verbose -Message " Request will use Uri: $($WEResourceUri)"
                                    $WESecurityBaselineTemplates = Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource $WEResourceUri -ErrorAction " Stop"
                                    $WESecurityBaselineTemplatesCount = ($WESecurityBaselineTemplates | Measure-Object).Count
                                    if ($WESecurityBaselineTemplatesCount -ge 1) {
                                        $WEResourceUri = " deviceManagement/intents?`$filter=templateId eq '$($WESecurityBaselineTemplates.id -join " ' or templateId eq '" )'"
                                        Write-Verbose -Message " Request will use Uri: $($WEResourceUri)"
                                        $WEProfiles = Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource $WEResourceUri -ErrorAction " Stop"
                                    }
                                }
                                default {
                                    Write-Verbose -Message " Request will use Uri: $($WEResourceUri)"
                                    $WEProfiles = Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource $WEResourceUri -ErrorAction " Stop"
                                }
                            }
                            
                            # Measure profiles count from request and continue if greater than or equal to 1
                            $WEProfilesCount = ($WEProfiles | Measure-Object).Count
                            if ($WEProfilesCount -ge 1) {
                                Write-Verbose -Message " Found count of profiles: $($WEProfilesCount)"
                                
                                # Apply additional filtering using specific platform data types
                                if ($WEFilterScript -eq $true) {
                                    Write-Verbose -Message " Applying platform filter script logic"
                                    $WEProfiles = $WEProfiles | Where-Object { $WEPSItem.'@odata.type' -match ($WEPlatformDataTypes -join " |" ) }
                                    $WEProfilesCount = ($WEProfiles | Measure-Object).Count
                                    Write-Verbose -Message " Filtered count of profiles: $($WEProfilesCount)"
                                }
    
                                # Process each profile returned from request and add required data to profile list
                                foreach ($WEProfile in $WEProfiles) {
                                    # Instantiate variables custom object to ensure it's reset for each current item in the loop
                                    $WEScopeTagPropertyName = $null

                                    # Determine whether to use property name 'roleScopeTagIds' or 'roleScopeTag' as the Graph API schema is not consistent across profile types
                                    if ($WEProfile.PSObject.Properties -match " roleScopeTagIds" ) {
                                        $WEScopeTagPropertyName = " roleScopeTagIds"
                                    }
                                    else {
                                        if ($WEProfile.PSObject.Properties -match " roleScopeTag" ) {
                                            $WEScopeTagPropertyName = " roleScopeTags"
                                        }
                                    }

                                    # Determine whether to use property name 'displayName' or 'name' as the Graph API schema is not consistent across profile types
                                    if ($WEProfile.PSObject.Properties -match " displayName" ) {
                                        $WEDisplayNamePropertyName = " displayName"
                                    }
                                    else {
                                        if ($WEProfile.PSObject.Properties -match " name" ) {
                                            $WEDisplayNamePropertyName = " name"
                                        }
                                    }

                                    # Test if scope tags property is empty, an additional direct request could be required to determine the applied scope tags
                                    if (($WEProfile.$WEScopeTagPropertyName | Measure-Object).Count -eq 0) {
                                        $WEUri = -join@(($WEResourceUri -split " \?" )[0], " /" , $WEProfile.id)
                                        $WEScopeTagIds = (Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource $WEUri).$WEScopeTagPropertyName
                                    }
                                    else {
                                        $WEScopeTagIds = $WEProfile.$WEScopeTagPropertyName
                                    }
                                    
                                    $WEPSObject = [PSCustomObject]@{
                                        " @odata.type" = if ($WEProfile.'@odata.type' -ne $null) { $WEProfile.'@odata.type' } else { $null }
                                        " Id" = $WEProfile.id
                                        " DisplayName" = $WEProfile.$WEDisplayNamePropertyName
                                        " ScopeTagIds" = $WEScopeTagIds
                                        " Uri" = ($WEResourceUri -split " \?" )[0]
                                        " Count" = ($WEScopeTagIds | Measure-Object).Count
                                        " PropertyName" = $WEScopeTagPropertyName
                                    }

                                    # Ensure ProfileList array doesn't contain duplicate entries with same profile id if executed for multiple platforms
                                    if ($WEProfile.id -notin $WEProfilesList.id) {
                                        $WEProfilesList.Add($WEPSObject) | Out-Null
                                    }
                                }
                            }
                            else {
                                Write-Warning -Message " Could not find profiles matching profile type '$($WEProfileTypeItem)' for platform '$($WEPlatformItem)'"
                            }
    
                            # Write output of current list count after current ProfileTypeItem
                            Write-Verbose -Message " Current ProfileList count: $($WEProfilesList.Count)"
                        }
                        catch [System.Exception] {
                            throw " $($WEMyInvocation.MyCommand): Failed to get profiles for type $($WEProfileTypeItem) with error message: $($_.Exception.Message)"
                        }
                    }
                }
            }

            # Filter list by Include parameter input if present
            if ($WEPSBoundParameters[" Include" ]) {
                Write-Verbose -Message " Applying 'Include' filtering on profile types based on displayName property using pattern: $($WEInclude)"
                $WEProfilesList = $WEProfilesList | Where-Object { $WEPSItem.displayName -match $WEInclude }
            }

            # Filter list by Exclude parameter input if present
            if ($WEPSBoundParameters[" Exclude" ]) {
                Write-Verbose -Message " Applying 'Exclude' filtering on profile types based on displayName property using pattern: $($WEExclude)"
                $WEProfilesList = $WEProfilesList | Where-Object { $WEPSItem.displayName -notmatch $WEExclude }
            }

            # Filter list by First parameter input if present
            if ($WEPSBoundParameters[" First" ]) {
                $WEProfilesList = $WEProfilesList | Select-Object -First $WEFirst
            }

            if (($WEPSBoundParameters[" Include" ]) -or ($WEPSBoundParameters[" Exclude" ]) -or ($WEPSBoundParameters[" First" ])) {
                # Write output of current list count after filters have been applied
                Write-Verbose -Message " Filtered ProfileList count: $($WEProfilesList.Count)"
            }

            # Construct output stream list of profile items that's been amended by the script
            $WEProfilesListOutput = New-Object -TypeName " System.Collections.ArrayList"

            # Process each item in profiles list
            $WEProcessedProfileItems = 0
            $WEProfileItemsCount = ($WEProfilesList | Measure-Object).Count
            foreach ($WEProfileItem in $WEProfilesList) {
                Write-Verbose -Message " Processing current profile item with name: '$($WEProfileItem.DisplayName)'"

                # Increase processed profile item counter
                $WEProcessedProfileItems++

                # Construct inital array list for the request body to contain scope tags to either be added, removed or replaced
                $WEScopeTagsIdList = New-Object -TypeName " System.Collections.ArrayList"

                # Instantiate variable for current profile type item to be added as output
                $WEProcessProfileTypeOutput = $false

                switch ($WEMethod) {
                    " Add" {
                        # Test if Scope Tag id is already present for current profile
                        if ($WEScopeTag.id -notin $WEProfileItem.ScopeTagIds) {
                            Write-Verbose -Message " Scope Tag with ID '$($WEScopeTag.id)' is not present in '$($WEProfileItem.PropertyName)', constructing request body for PATCH operation"

                            # Add existing scope tags from current profile to list, and add scope tag from parameter input
                            $WEScopeTagsIdList.AddRange($WEProfileItem.ScopeTagIds) | Out-Null
                            $WEScopeTagsIdList.Add($WEScopeTag.id) | Out-Null
                            $WEBodyTable = @{
                                $WEProfileItem.PropertyName = @($WEScopeTagsIdList)
                            }

                            # Add data type property to request body, if required
                            if ($WEProfileItem.'@odata.type' -ne $null) {
                                $WEBodyTable.Add('@odata.type', $WEProfileItem.'@odata.type')
                            }

                            try {
                                # Invoke patch request and amend scope tag property
                                if ($WEPSCmdlet.ShouldProcess($WEProfileItem.DisplayName, " $($WEMethod) scope tag '$($WEScopeTagName)'" )) {
                                    $WEProfileItemUri = -join@($WEProfileItem.Uri, " /" , $WEProfileItem.Id)
                                    Write-Verbose -Message " Invoke request for PATCH operation for Uri: $($WEProfileItemUri)"
                                    $WEResponse = Invoke-MSGraphOperation -Patch -APIVersion " Beta" -Resource $WEProfileItemUri -Body ($WEBodyTable | ConvertTo-Json) -ContentType " application/json" -Verbose:$false -ErrorAction " Stop"
                                    $WEProcessProfileTypeOutput = $true
                                }
                            }
                            catch [System.Exception] {
                                Write-Warning -Message " Failed to perform PATCH operation. Error message: $($_.Exception.Message)"
                            }
                        }
                        else {
                            Write-Verbose -Message " Scope Tag with ID '$($WEScopeTag.id)' is already present in '$($WEProfileItem.PropertyName)' property value: $($WEProfileItem.ScopeTagIds -join " , " )"
                        }
                    }
                    " Remove" {
                        # Test if Scope Tag id is in array of current profile
                        if ($WEScopeTag.id -in $WEProfileItem.ScopeTagIds) {
                            Write-Verbose -Message " Scope Tag with ID '$($WEScopeTag.id)' is configured for profile '$($WEProfileItem.PropertyName)' and will be removed"

                            # Amend array list and filtering out the specific ID from parameter input
                            $WEScopeTagsIdList.AddRange($WEProfileItem.ScopeTagIds) | Out-Null
                            $WEScopeTagsIdList = $WEScopeTagsIdList | Where-Object { $WEPSItem -ne $WEScopeTag.id }
                            $WEBodyTable = @{
                                $WEProfileItem.PropertyName = @($WEScopeTagsIdList)
                            }

                            # Add data type property to request body, if required
                            if ($WEProfileItem.'@odata.type' -ne $null) {
                                $WEBodyTable.Add('@odata.type', $WEProfileItem.'@odata.type')
                            }

                            try {
                                # Invoke patch request and amend scope tag property
                                if ($WEPSCmdlet.ShouldProcess($WEProfileItem.DisplayName, " $($WEMethod) scope tag '$($WEScopeTagName)'" )) {
                                    $WEProfileItemUri = -join@($WEProfileItem.Uri, " /" , $WEProfileItem.Id)
                                    Write-Verbose -Message " Invoke request for PATCH operation for Uri: $($WEProfileItemUri)"
                                    $WEResponse = Invoke-MSGraphOperation -Patch -APIVersion " Beta" -Resource $WEProfileItemUri -Body ($WEBodyTable | ConvertTo-Json) -ContentType " application/json" -Verbose:$false -ErrorAction " Stop"
                                    $WEProcessProfileTypeOutput = $true
                                }
                            }
                            catch [System.Exception] {
                                Write-Warning -Message " Failed to perform PATCH operation. Error message: $($_.Exception.Message)"
                            }
                        }
                    }
                    " Replace" {
                        Write-Verbose -Message " Scope Tag with ID '$($WEScopeTag.id)' will replace existing IDs '$($WEProfileItem.ScopeTagIds -join " , " )', constructing request body for PATCH operation"

                        # Add scope tag to array list for replace operation
                        $WEScopeTagsIdList.Add($WEScopeTag.id) | Out-Null
                        $WEBodyTable = @{
                            $WEProfileItem.PropertyName = @($WEScopeTagsIdList)
                        }

                        # Add data type property to request body, if required
                        if ($WEProfileItem.'@odata.type' -ne $null) {
                            $WEBodyTable.Add('@odata.type', $WEProfileItem.'@odata.type')
                        }
                        
                        try {
                            # Invoke patch request and amend scope tag property
                            if ($WEPSCmdlet.ShouldProcess($WEProfileItem.DisplayName, " $($WEMethod) all scope tags with '$($WEScopeTagName)'" )) {
                                $WEProfileItemUri = -join@($WEProfileItem.Uri, " /" , $WEProfileItem.Id)
                                Write-Verbose -Message " Invoke request for PATCH operation for Uri: $($WEProfileItemUri)"
                                $WEResponse = Invoke-MSGraphOperation -Patch -APIVersion " Beta" -Resource $WEProfileItemUri -Body ($WEBodyTable | ConvertTo-Json) -ContentType " application/json" -Verbose:$false -ErrorAction " Stop"
                               ;  $WEProcessProfileTypeOutput = $true
                            }
                        }
                        catch [System.Exception] {
                            Write-Warning -Message " Failed to perform PATCH operation. Error message: $($_.Exception.Message)"
                        }
                    }
                }

                # Add current profile type item to output array list, since it has been changed by the script in previous request
                if ($WEProcessProfileTypeOutput -eq $true) {
                    # Construct output object for console
                   ;  $WEPSObject = [PSCustomObject]@{
                        " @odata.type" = if ($WEProfileItem.'@odata.type' -ne $null) { $WEProfileItem.'@odata.type' } else { $null }
                        " id" = $WEProfileItem.Id
                        " displayName" = $WEProfileItem.DisplayName
                        " NewScopeTagIds" = @($WEScopeTagsIdList)
                        " PreviousScopeTagIds" = @($WEProfileItem.ScopeTagIds)
                    }
                    $WEProfilesListOutput.Add($WEPSObject) | Out-Null
                }

                if ($WEProcessedProfileItems -lt $WEProfileItemsCount) {
                    # Handle throttling
                    Write-Verbose -Message (" Throttling requests, next request in $($WEThrottleInSeconds) second{0}" -f $(if ($WEThrottleInSeconds -eq 1) { [string]::Empty } else { " s" }))
                    Start-Sleep -Seconds $WEThrottleInSeconds
                }
            }

            # Handle return value
            return $WEProfilesListOutput
        }
        else {
            Write-Warning -Message " Could not find Scope Tag with specified display name: $($WEScopeTagName)"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " Failed to get access token for tenant $($WETenantID) with error message: $($_.Exception.Message)"
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================