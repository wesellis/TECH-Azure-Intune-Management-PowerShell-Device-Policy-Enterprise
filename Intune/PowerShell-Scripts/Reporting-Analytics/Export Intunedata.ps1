<#
.SYNOPSIS
    Export Intunedata

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
    We Enhanced Export Intunedata

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

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.




[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(HelpMessage = " Azure AD Username" , Mandatory = $true)]
    [string]
    $WEUsername,
    [Parameter(HelpMessage = " User principal name to export data for" , Mandatory = $true)]
    [string]
    $WEUpn,
    [Parameter(HelpMessage = " Include AzureAD data in export" )]
    [switch]
    $WEIncludeAzureAD,
    [Parameter(HelpMessage = " Include data For Non Azure AD Upn in export" )]
    [switch]
    $WEIncludeNonAzureADUpn,
    [Parameter(HelpMessage = " Include all data in the export" )]
    [switch]
    $WEAll,
    [Parameter(HelpMessage = " Path to export data to" , Mandatory = $true)]
    [string]
    $WEOutputPath,
    [Parameter(HelpMessage = " Format to export data in" )]
    [ValidateSet(" JSON" , " CSV" , " XML" )]
    $WEExportFormat = " JSON" ,
    [Parameter(DontShow = $true)]
    [string]
    $WEMsGraphVersion = " beta" ,
    [Parameter(DontShow = $true)]
    [string]
    $WEMsGraphHost = " graph.microsoft.com" ,
    [Parameter(DontShow = $true)]
    [string]
    $WEConfigurationFile
)



function WE-Log-Verbose($message) {
    Write-Verbose " [$([System.DateTime]::Now)] - $message"
}



function WE-Log-Info ($message) {
    Write-Information " INFO: [$([System.DateTime]::Now)] - $message" -InformationAction Continue
}



function WE-Log-Warning ($message) {
    Write-Warning " [$([System.DateTime]::Now)] - $message" -WarningAction Continue  
}



function WE-Log-Error ($message) {
    Write-Error " [$([System.DateTime]::Now)] - $message" -WarningAction Continue
}



function WE-Log-FatalError($message) {
    Write-Error " [$([System.DateTime]::Now)] - $message" -WarningAction Continue
    Write-Error " Script will now exit"
    exit
}



[CmdletBinding()]
function WE-Get-AuthToken -ErrorAction Stop {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken -ErrorAction Stop
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken -ErrorAction Stop
    #>
    
    [cmdletbinding()]
    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$true)]
        $WEUser
    )
    
    $userUpn = New-Object -ErrorAction Stop " System.Net.Mail.MailAddress" -ArgumentList $WEUser
    
    $tenant = $userUpn.Host
    
    Write-WELog " Checking for AzureAD module..." " INFO"
    
        $WEAadModule = Get-Module -Name " AzureAD" -ListAvailable
    
        if ($null -eq $WEAadModule) {
    
            Write-WELog " AzureAD PowerShell module not found, looking for AzureADPreview" " INFO"
            $WEAadModule = Get-Module -Name " AzureADPreview" -ListAvailable
    
        }
    
        if ($null -eq $WEAadModule) {
            Write-Information write-host " AzureAD Powershell module not installed..." -f Red
            Write-Information " Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            Write-Information " Script can't continue..." -f Red
            Write-Information exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($WEAadModule.count -gt 1){
    
            $WELatest_Version = ($WEAadModule | select version | Sort-Object)[-1]
    
            $aadModule = $WEAadModule | ? { $_.version -eq $WELatest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($WEAadModule.count -gt 1){
    
                $aadModule = $WEAadModule | select -Unique
    
                }
    
            $adal = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    # Using this authentication method requires a clientID.  Register a new app in the Entra ID admin center to obtain a clientID.  More information
    # on app registration and clientID is available here: https://learn.microsoft.com/entra/identity-platform/quickstart-register-app 

    $clientId = " <replace with your clientID>"
    
    $redirectUri = " urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = " https://graph.microsoft.com"
    
    $authority = " https://login.microsoftonline.com/$WETenant"
    
        try {
    
        $authContext = New-Object -ErrorAction Stop " Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object -ErrorAction Stop " Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList " Auto"
    
        $userId = New-Object -ErrorAction Stop " Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($WEUser, " OptionalDisplayableId" )

        $WEMethodArguments = [Type[]]@(" System.String" , " System.String" , " System.Uri" , " Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior" , " Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" )
        $WENonAsync = $WEAuthContext.GetType().GetMethod(" AcquireToken" , $WEMethodArguments)
    
        if ($null -ne $WENonAsync) {
            $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, [Uri]$redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto, $userId)
        } else {
            $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, [Uri]$redirectUri, $platformParameters, $userId).Result 
        }
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'=" Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Information Write-WELog " Authorization Access Token is null, please re-run authentication..." " INFO"
            Write-Information break
    
            }
    
        }
    
        catch {
    
        Write-Information $_.Exception.Message -f Red
        Write-Information $_.Exception.ItemName -f Red
        Write-Information break
    
        }
    
    }
    


function WE-Get-MsGraphObject($WEPath, [switch]$WEIgnoreNotFound) {
    $WEFullUri = " https://$WEMsGraphHost/$WEMsGraphVersion/$WEPath"
    Log-Verbose " GET $WEFullUri"

    try {
        return  Invoke-RestMethod -Method Get -Uri $WEFullUri -Headers $WEAuthHeader
    } 
    catch {
        $WEResponse = $_.Exception.Response
        if ($WEIgnoreNotFound -and $WEResponse.StatusCode -eq " NotFound" ) {
            return $null
        }
        $WEResponseStream = $WEResponse.GetResponseStream()
        $WEResponseReader = New-Object -ErrorAction Stop System.IO.StreamReader $WEResponseStream
        $WEResponseContent = $WEResponseReader.ReadToEnd()
        Log-Error " Request Failed: $($_.Exception.Message)`n$($_.ErrorDetails)"
        Log-Error " Request URL: $WEFullUri"
        Log-Error " Response Content:`n$WEResponseContent"
        break
    }
}



function WE-Get-MsGraphCollection($WEPath) {
    $WEFullUri = " https://$WEMsGraphHost/$WEMsGraphVersion/$WEPath"
    $WECollection = @()
    $WENextLink = $WEFullUri

    do {
        try {
            Log-Verbose " GET $WENextLink"
            $WEResult = Invoke-RestMethod -Method Get -Uri $WENextLink -Headers $WEAuthHeader
            $WECollection = $WECollection + $WEResult.value
            $WENextLink = $WEResult.'@odata.nextLink'
        } 
        catch {
            $WEResponseStream = $_.Exception.Response.GetResponseStream()
            $WEResponseReader = New-Object -ErrorAction Stop System.IO.StreamReader $WEResponseStream
            $WEResponseContent = $WEResponseReader.ReadToEnd()
            Log-Error " Request Failed: $($_.Exception.Message)`n$($_.ErrorDetails)"
            Log-Error " Request URL: $WENextLink"
            Log-Error " Response Content:`n$WEResponseContent"
            break
        }
    } while ($null -ne $WENextLink)
    Log-Verbose " Got $($WECollection.Count) object(s)"

    return $WECollection
}



function WE-Post-MsGraphObject($WEPath, $WERequestBody) {
    $WEFullUri = " https://$WEMsGraphHost/$WEMsGraphVersion/$WEPath"

    try {
        Log-Verbose " POST $WEFulluri"

        $WERequestBodyJson = $WERequestBody | ConvertTo-Json

        Log-Verbose " Request Body Json:"
        Log-Verbose $WERequestBodyJson

        $WEResult = Invoke-RestMethod -Method Post -Uri $WEFullUri -Headers $WEAuthHeader -Body $WERequestBodyJson
        return $WEResult
    } 
    catch {
        $WEResponseStream = $_.Exception.Response.GetResponseStream()
        $WEResponseReader = New-Object -ErrorAction Stop System.IO.StreamReader $WEResponseStream
        $WEResponseContent = $WEResponseReader.ReadToEnd()
        Log-Error " Request Failed: $($_.Exception.Message)`n$($_.ErrorDetails)"
        Log-Error " Request URL: $WENextLink"
        Log-Error " Response Content:`n$WEResponseContent"
        break
    }
}



[CmdletBinding()]
function WE-Get-User -ErrorAction Stop {
    Log-Info " Getting Azure AD User data for UPN $WEUPN"
    return Get-MsGraphObject -ErrorAction Stop " users/$WEUpn" -IgnoreNotFound
}





[CmdletBinding()]
function WE-Test-IntuneUser {
    Log-Info " Checking if User $WEUPN is a Microsoft Intune user"

    try {
        Invoke-RestMethod -Method Get -Uri " https://$WEMsGraphHost/$WEMsGraphVersion/users/$($WEUserId)/managedDevices" -Headers $WEAuthHeader
    } 
    catch {
        $WEResponse = $_.Exception.Response
        if ($WEResponse.StatusCode -eq " NotFound" ) {
            return $false
        }
    }

    return $true
}



[CmdletBinding()]
function WE-Get-GroupMemberships -ErrorAction Stop {
    Log-Info " Getting Azure AD Group memberships for User $WEUPN"
    return Get-MsGraphCollection -ErrorAction Stop " users/$WEUpn/memberOf/microsoft.graph.group"
}



[CmdletBinding()]
function WE-Get-RegisteredDevices -ErrorAction Stop {
    Log-Info " Getting Azure AD Registered Devices for User $WEUPN"
    return Get-MsGraphCollection -ErrorAction Stop " users/$WEUpn/registeredDevices"
}



[CmdletBinding()]
function WE-Get-ManagedDevices -ErrorAction Stop {
    Log-Info " Getting managed devices for User $WEUPN"
    
    $WEDeviceIds = @(Get-MsGraphCollection -ErrorAction Stop " users/$WEUserId/managedDevices?`$select=id" | Select-Object -ExpandProperty id)

    $WEDevices = @()

    foreach ($WEDeviceId in $WEDeviceIds) {
        $WEDevice = Get-MsGraphObject -ErrorAction Stop " deviceManagement/managedDevices/$($WEDeviceId)?`$expand=detectedApps"
        $WECategory = Get-MsGraphObject -ErrorAction Stop " deviceManagement/managedDevices/$($WEDevice.id)/deviceCategory"
        Add-Member -InputObject $WEDevice " deviceCategory" $WECategory

        $WEDeviceConfigurationStates = Get-MsGraphCollection -ErrorAction Stop " deviceManagement/managedDevices/$($WEDevice.id)/deviceConfigurationStates"

        $WEApplicableDeviceConfigurationStates = @($WEDeviceConfigurationStates | Where-Object {$_.state -ne " notApplicable" })

        foreach ($WEApplicableDeviceConfigurationState in $WEApplicableDeviceConfigurationStates) {
            $WEApplicableDeviceConfigurationState.settingStates = @(Get-MsGraphCollection -ErrorAction Stop " deviceManagement/managedDevices/$($WEDevice.id)/deviceConfigurationStates/$($WEApplicableDeviceConfigurationState.id)/settingStates" )
        }

        Add-Member NoteProperty -InputObject $WEDevice -Name " deviceConfigurationStates" -Value @()
        foreach ($dcs in $WEApplicableDeviceConfigurationStates) {
            $WEDevice.deviceConfigurationStates += $dcs
        }
        $WEDeviceCompliancePolicyStates = Get-MsGraphCollection -ErrorAction Stop " deviceManagement/managedDevices/$($WEDevice.id)/deviceCompliancePolicyStates"

        $WEApplicableDeviceCompliancePolicyStates = @($WEDeviceCompliancePolicyStates | Where-Object {$_.state -ne " notApplicable" })
        foreach ($WEApplicableDeviceCompliancePolicyState in $WEApplicableDeviceCompliancePolicyStates) {
            $WEApplicableDeviceCompliancePolicyState.settingStates = @(Get-MsGraphCollection -ErrorAction Stop " deviceManagement/managedDevices/$($WEDevice.id)/deviceCompliancePolicyStates/$($WEApplicableDeviceCompliancePolicyState.id)/settingStates" )
        }

        Add-Member NoteProperty -InputObject $WEDevice -Name " deviceCompliancePolicyStates" -Value @()
        foreach ($dcs in $WEApplicableDeviceCompliancePolicyStates) {
            $WEDevice.deviceCompliancePolicyStates += $dcs
        }
        $WEDeviceWithHardwareInfo = Get-MsGraphObject -ErrorAction Stop " deviceManagement/managedDevices/$($WEDevice.id)/?`$select=id,hardwareInformation"
        $WEDevice.hardwareInformation = $WEDeviceWithHardwareInfo.hardwareInformation
        $WEDevices = $WEDevices + $WEDevice
    }
    return $WEDevices
}



[CmdletBinding()]
function WE-Get-AuditEvents -ErrorAction Stop {
    Log-Info " Getting audit events for User $WEUPN"
    
    return Get-MsGraphCollection -ErrorAction Stop " `deviceManagement/auditEvents?`$filter=actor/userPrincipalName eq '$WEUPN'"
}



[CmdletBinding()]
function WE-Get-ManagedAppRegistrations -ErrorAction Stop {
    Log-Info " Getting managed app registrations for User $WEUPN"
    
    return Get-MsGraphCollection -ErrorAction Stop " `users/$WEUserId/managedAppRegistrations?`$expand=appliedPolicies,intendedPolicies,operations"
}



[CmdletBinding()]
function WE-Get-AppleVppEbooks -ErrorAction Stop {
    Log-Info " Getting Apple VPP EBooks for User $WEUPN"

    return Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/managedEbooks?`$filter=microsoft.graph.iosVppEBook/appleId eq '$WEUPN'"
}



[CmdletBinding()]
function WE-Get-AppleDepSettings -ErrorAction Stop {
    Log-Info " Getting Apple DEP Settings for User $WEUPN"

    return Get-MsGraphCollection -ErrorAction Stop " deviceManagement/depOnboardingSettings?`$filter=appleIdentifier eq '$WEUPN'"
}



function WE-Has-UserStatus($WEInstallSummary) {
    return ($WEInstallSummary.installedUserCount -gt 0) -or 
    ($WEInstallSummary.failedUserCount -gt 0) -or 
    ($WEInstallSummary.notApplicableUserCount -gt 0) -or 
    ($WEInstallSummary.notInstalledUserCount -gt 0) -or 
    ($WEInstallSummary.pendingInstallUserCount -gt 0)
}



[CmdletBinding()]
function WE-Get-AppInstallStatuses -ErrorAction Stop {
    Log-Info " Getting App Install Statuses for User $WEUPN"

    $WEUrl = " deviceAppManagement/mobileApps?`$expand=installSummary"

    if (-not $WEAll) {
        $WEUrl = $WEUrl + " &`$select=id,displayName,publisher,privacyInformationUrl,informationUrl,owner,developer"
    }

    $WEApps = Get-MsGraphCollection -ErrorAction Stop $WEUrl
    # Filter the list of apps to only the apps that have install status
    $WEAppsWithStatus = $WEApps | Where-Object { Has-UserStatus $_.installSummary }
    Log-Verbose " Found $($WEAppsWithStatus.Count) apps with install statuses"

    $WEAppStatuses = @()

    foreach ($WEApp in $WEAppsWithStatus) {
        Log-Verbose " Getting App Install Status for App '$($WEApp.displayName) $($WEApp.Id)"

        $WEUserStatusesForApp = Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/mobileApps/$($WEApp.id)/userStatuses"
        $WEDeviceStatusesForApp = Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/mobileApps/$($WEApp.id)/deviceStatuses" 
        $WEDeviceStatusesForUser = @()
        $WEDeviceStatusesForUser = $WEDeviceStatusesForUser + $WEDeviceStatusesForApp | Where-Object { 
            $_.userPrincipalName -ieq $WEUPN
        }

        $WEUserStatusesForUser = @()
        $WEUserStatusesForUser = $WEUserStatusesForUser + $WEUserStatusesForApp | Where-Object { 
            $_.userPrincipalName -ieq $WEUPN
        }
        
        if ($WEUserStatusesForUser.Count -gt 0 -or $WEDeviceStatusesForUser.Count -gt 0) {
            Add-Member NoteProperty -InputObject $WEApp -Name " deviceStatuses" -Value @()
            foreach ($WEUserStatus in $WEDeviceStatusesForUser) {
                $WEApp.deviceStatuses += $WEUserStatus
            }
            Add-Member NoteProperty -InputObject $WEApp -Name " userStatuses" -Value @()
            foreach ($WEUserStatus in $WEUserStatusesForUser) {
                $WEApp.userStatuses += $WEUserStatus
            }
            $WEAppStatuses = $WEAppStatuses + $WEApp
        }
    }

    return $WEAppStatuses
}



[CmdletBinding()]
function WE-Get-EbookInstallStatuses -ErrorAction Stop {
    Log-Info " Getting Ebook Install Statuses for User $WEUPN"

    $WEEbooks = Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/managedEBooks?`$expand=installSummary"

    $WEEbooksStatuses = @()

    foreach ($WEEbook in $WEEbooks) {
        Log-Verbose " Getting Ebook Install Status for Ebook '$($WEEbook.displayName) $($WEEbook.Id)"

        $WEUserStatusesForEbook = Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/managedEBooks/$($WEEbook.id)/userStateSummary"
        $WEDeviceStatusesForEbook = Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/managedEBooks/$($WEEbook.id)/deviceStates" 
        $WEDeviceStatusesForUser = @()
        $WEDeviceStatusesForUser = $WEDeviceStatusesForUser + $WEDeviceStatusesForEbook | Where-Object { 
            $_.userName -ieq $WEUserDisplayName
        }

        $WEUserStatusesForUser = @()
        $WEUserStatusesForUser = $WEUserStatusesForUser + $WEUserStatusesForEbook | Where-Object { 
            $_.userName -ieq $WEUserDisplayName
        }
        
        if ($WEUserStatusesForUser.Count -gt 0 -or $WEDeviceStatusesForUser.Count -gt 0) {
            Add-Member NoteProperty -InputObject $WEEbook -Name " deviceStates" -Value @()
            foreach ($WEUserStatus in $WEDeviceStatusesForUser) {
                $WEEbook.deviceStates += $WEUserStatus
            }
            Add-Member NoteProperty -InputObject $WEEbook -Name " userStateSummary" -Value @()
            foreach ($WEUserStatus in $WEUserStatusesForUser) {
                $WEEbook.userStateSummary += $WEUserStatus
            }
            $WEEbooksStatuses = $WEEbooksStatuses + $WEEbook
        }
    }

    return $WEEbooksStatuses
}



function WE-Get-WindowsManagementAppHealthStates($WEManagedDevices) {
    Log-Info " Getting WindowsManagementApp Status for User $WEUPN"
    $WEStatesForDevice = @()
    foreach ($WEManagedDevice in $WEManagedDevices) {
        # Escape any ' in the device name
        $WEEscapedDeviceName = $WEManagedDevice.deviceName.Replace(" '" , " ''" )
        $WEStatesForDevice = $WEStatesForDevice + Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/windowsManagementApp/healthStates?`$filter=deviceName eq '$($WEEscapedDeviceName)'"
    }

    return $WEStatesForDevice
}



function WE-Get-WindowsProtectionStates($WEManagedDevices) {
    Log-Info " Getting Windows Protection States for User $WEUPN"
    $WEStatesForDevice = @()
    foreach ($WEManagedDevice in $WEManagedDevices) {
        $WEStatesForDevice = $WEStatesForDevice + Get-MsGraphObject -ErrorAction Stop " deviceManagement/managedDevices/$($WEManagedDevice.id)?`$expand=windowsProtectionState"
    }
}



[CmdletBinding()]
function WE-Get-RemoteActionAudits -ErrorAction Stop {
    Log-Info " Getting Remote Action Audits for User $WEUPN"

    $WERemoteActionAudits = Get-MsGraphCollection -ErrorAction Stop " deviceManagement/remoteActionAudits?`$filter=initiatedByUserPrincipalName eq '$WEUPN'"
    return $WERemoteActionAudits | Where-Object { $_.initiatedByUserPrincipalName -ieq $WEUPN -or $_.userName -ieq $WEUPN}
}



[CmdletBinding()]
function WE-Get-DeviceManagementTroubleshootingEvents -ErrorAction Stop {
    Log-Info " Getting Device Management Troubleshooting Events for user $WEUPN"
    return Get-MsGraphCollection -ErrorAction Stop " users/$($WEUser.id)/deviceManagementTroubleshootingEvents"
}



[CmdletBinding()]
function WE-Get-IosUpdateStatuses -ErrorAction Stop {
    Log-Info " Getting iOS Update Statuses for user $WEUPN"
    $WEIosUpdateStatuses = @(Get-MsGraphCollection -ErrorAction Stop " deviceManagement/iosUpdateStatuses" | Where-Object { $_.userPrincipalName -ieq $WEUPN })
    return $WEIosUpdateStatuses
}



function WE-Get-ManagedDeviceMobileAppConfigurationStatuses -ErrorAction Stop ($WEDevices) {
    Log-Info " Getting Mobile App Configurations Statuses for user $WEUPN"
    $WEMobileAppConfigurationsStatuses = @()
    $WEMobileAppConfigurations = Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/mobileAppConfigurations"
    
    $WEDeviceIds = $WEDevices | Select-Object -ExpandProperty id

    foreach ($WEMobileAppConfiguration in $WEMobileAppConfigurations) {
        $WEDeviceStatuses = Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/mobileAppConfigurations/$($WEMobileAppConfiguration.id)/deviceStatuses"
        $WEUserStatuses = Get-MsGraphCollection -ErrorAction Stop " deviceAppManagement/mobileAppConfigurations/$($WEMobileAppConfiguration.id)/userStatuses"


        $WEDeviceStatusesForUser = @()
        
        foreach ($WEDeviceId in $WEDeviceIds) {
            $WEDeviceStatusesForUser = $WEDeviceStatusesForUser + $WEDeviceStatuses | Where-Object { 
                $_.id.Contains($WEDeviceId)
            }
        }

        $WEUserStatusesForUser = @()
        $WEUserStatusesForUser = $WEUserStatusesForUser + $WEUserStatuses | Where-Object { 
            $_.userPrincipalName -ieq $WEUPN
        }

        if ($WEDeviceStatusesForUser.Count -gt 0 -or $WEUserStatusesForUser.Count -gt 0) {
            $WEMobileAppConfiguration | Add-Member -Name " deviceStatuses" -Value $WEDeviceStatusesForUser -MemberType NoteProperty
            $WEMobileAppConfiguration | Add-Member -Name " userStatuses" -Value $WEUserStatusesForUser -MemberType NoteProperty
            $WEMobileAppConfigurationsStatuses = $WEMobileAppConfigurationsStatuses + $WEMobileAppConfiguration
        }
    }

    return $WEMobileAppConfigurationsStatuses
}



function WE-Get-DeviceManagementScriptRunStates -ErrorAction Stop ($WEManagedDevices){
    Log-Info " Getting Device Management Script Run States for user $WEUPN"
    $WEDeviceManagementScripts = Get-MsGraphCollection -ErrorAction Stop " deviceManagement/deviceManagementScripts"
    $WEDeviceManagementScriptRunStates = @()

    foreach ($WEDeviceManagementScript in $WEDeviceManagementScripts) {
        $WEUserRunStates = Get-MsGraphCollection -ErrorAction Stop " deviceManagement/deviceManagementScripts/$($WEDeviceManagementScript.id)/userRunStates"

        $WEUserRunStatesForUser = @()
        $WEUserRunStatesForUser = $WEUserRunStatesForUser + $WEUserRunStates | Where-Object { 
            $_.userPrincipalName -ieq $WEUPN
        }

        if ($WEUserRunStatesForUser.Count -gt 0) {
            $WEDeviceManagementScript | Add-Member -Name " userRunStates" -Value $WEUserRunStatesForUser -MemberType NoteProperty
            $WEDeviceManagementScriptRunStates = $WEDeviceManagementScriptRunStates + $WEDeviceManagementScript
        }
    }

    return $WEDeviceManagementScriptRunStates
}



[CmdletBinding()]
function WE-Export-RemainingData{
    Log-Info " Getting other data for user $WEUpn"

    $WEOtherData = Get-MsGraphCollection -ErrorAction Stop " users/$WEUpn/exportDeviceAndAppManagementData()/content"
    if ($WEOtherData.Count -gt 0) {
        foreach ($WEDataItem in $WEOtherData)
        {
            if ($WEDataItem.data -ne $null)
            {
                $WEEntities = @($WEDataItem.data)
                if ($WEEntities.Count -gt 0) 
                {
                    Log-Info " Found $($WEEntities.Count) $($WEDataItem.displayName)"
                    $WECollectionName = $WEDataItem.displayName
                    if ($WECollectionName -ieq " Users" )
                    {
                        $WECollectionName = " Intune Users"
                    }
                    $WEEntityName = $WECollectionName.TrimEnd('s')

                    Export-Collection -CollectionType $WECollectionName -ObjectType $WEEntityName -Collection $WEEntities 
                }
                else {
                    Log-Info " No $($WEDataItem.displayName) data found"
                }
            }
        }
    }
}



[CmdletBinding()]
function WE-Get-AppProtectionUserStatuses -ErrorAction Stop {
    Log-Info " Getting Managed App Protection Status Report for user $WEUPN"

    $WEStatus = Get-MsGraphObject -ErrorAction Stop " deviceAppManagement/managedAppStatuses('userstatus')?userId=$WEUserId"

    return $WEStatus
}



[CmdletBinding()]
function WE-Get-WindowsProtectionSummary -ErrorAction Stop {
    Log-Info " Getting Windows Protection Summary for user $WEUPN"
    $WEProtectionSummary = Get-MsGraphObject -ErrorAction Stop " deviceAppManagement/managedAppStatuses('windowsprotectionreport')"

    return Filter-ManagedAppReport $WEProtectionSummary
}



[CmdletBinding()]
function WE-Get-ManagedAppUsageSummary -ErrorAction Stop {
    Log-Info " Getting Managed App Usage Summary for user $WEUPN"

    $WEUsageSummary = Get-MsGraphObject -ErrorAction Stop " deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=UserId,DisplayName,UserEmail,ApplicationName,ApplicationInstanceId,ApplicationVersion,DeviceName,DeviceType,DeviceManufacturer,DeviceModel,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,Platform,PlatformVersion,ManagementLevel,PolicyName,LastCheckInDate"
    $WEReport = $WEUsageSummary.content.body
    $WEFilteredRows = @()
    if ($WEReport.Count -gt 0) {
        foreach ($WERow in $WEReport) {
            if ($WERow.values[0] -ieq $WEUserId) {
                $WEFilteredRows = $WEFilteredRows + $WERow
            }
        }
    }
    $WEReport = $WEFilteredRows
    $WEUsageSummary.content.body = $WEReport

    return $WEUsageSummary
}



[CmdletBinding()]
function WE-Get-ManagedAppConfigurationStatusReport -ErrorAction Stop {
    Log-Info " Getting Managed App Configuration Status for user $WEUPN"
    $WEStatusReport = Get-MsGraphObject -ErrorAction Stop " deviceAppManagement/managedAppStatuses('userconfigstatus')?userId=$WEUserId"

    return $WEStatusReport
}



[CmdletBinding()]
function WE-Filter-ManagedAppReport {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param($WEReport)
    #Filter the report summary to only the target user
    if ($null -ne $WEReport -and $WEReport.content -ne $null)
    {
        $WEHeaderCount = $WEReport.content.header.Count
        $WEDataRows = $WEReport.content.body.values
        $WEFilteredDataRows = @()

        if ($WEDataRows.Count -eq $WEHeaderCount) 
        {
            # Special case for only one row of data
            if ($WEDataRows[0]  -ieq $WEUserId)
            {
                $WEFilteredDataRows = $WEFilteredDataRows + @($WEDataRows)
            }
        } elseif ($null -ne $WEDataRows -and $WEDataRows.Count -gt 0) {
            foreach ($WEDataRow in $WEDataRows) {
                if ($WEDataRow[0] -ieq $WEUserId) {
                    $WEFilteredDataRows = $WEFilteredDataRows + $WEDataRow
                }
            }
        }

        $WEDataRows = $WEFilteredDataRows
    }

    return $WEReport
}



[CmdletBinding()]
function WE-Get-TermsAndConditionsAcceptanceStatuses -ErrorAction Stop {
    Log-Info " Exporting Terms and Conditions Acceptance Statuses for user $WEUPN"

    $WETermsAndConditions = Get-MsGraphCollection -ErrorAction Stop " deviceManagement/termsAndConditions"
    $WETermsAndConditionsAcceptanceStatuses = @()

    foreach ($WETermsAndCondition in $WETermsAndConditions) {
        $WEAcceptanceStatuses = Get-MsGraphCollection -ErrorAction Stop " deviceManagement/termsAndConditions/$($WETermsAndCondition.id)/acceptanceStatuses"

        $WETermsAndConditionsAcceptanceStatuses = $WETermsAndConditionsAcceptanceStatuses + ($WEAcceptanceStatuses | Where-Object { $_.id.Contains($WEUserId) })
    }

    return $WETermsAndConditionsAcceptanceStatuses
}



function WE-Export-IntuneReportUsingGraph($WERequestBody, $WEZipName) {
    Log-Info " Exporting Intune Report Using Graph for user '$WEUPN'"

    $WEIntuneReportDataPOSTResponse = Post-MsGraphObject " deviceManagement/reports/exportJobs" $WERequestBody
    Log-Verbose $WEIntuneReportDataPOSTResponse

    $WEReportId = $WEIntuneReportDataPOSTResponse.Id
    $WEReportIdPath = " deviceManagement/reports/exportJobs('" + $WEReportId + " ')"

    $WEAttempts = 0
    $WEMaxAttempts = 20
    do {
        Start-Sleep -Seconds 15
        $WEIntuneReportDataGETResponse = Get-MsGraphObject -ErrorAction Stop $WEReportIdPath
        Log-Verbose $WEIntuneReportDataGETResponse
        $WEAttempts = $WEAttempts + 1
    }
    while (($WEIntuneReportDataGETResponse.status -ne " completed" ) -or $WEAttempts -ge $WEMaxAttempts)

    if ($WEAttempts -ge $WEMaxAttempts) {
        Log-Error " Attempt count exceeded, report not generated"
        return
    }

    $WEIntuneReportOutFile = $WEOutputPath + " /" + $WEZipName + " .zip"
    $WEDownloadZipFile = Invoke-RestMethod -Method Get -Uri $WEIntuneReportDataGETResponse.url -ContentType " application/zip" -Outfile $WEIntuneReportOutFile
    Log-Verbose " Zip file downloaded to $WEIntuneReportOutFile"
}



[CmdletBinding()]
function WE-Export-ChromeOSDeviceReportData {
    Log-Info " Exporting ChromeOS Device Report Data for user '$WEUPN'"

    $WEFilterString = " (MostRecentUserEmail eq '" + $WEUPN + " ')"

    $WEChromeRequestBody = @{ 
        reportName = " ChromeOSDevices"
        localizationType = " LocalizedValuesAsAdditionalColumn"
        filter = $WEFilterString
        format = " json"
    }

    Export-IntuneReportUsingGraph $WEChromeRequestBody " ChromeOSDeviceReport"
}







function WE-Export-ObjectJson($WEObjectType, $WEObject) {
    $WEExportPath = $(Join-Path $WEOutputPath " $WEObjectType.json" )
    Log-Info " Writing $WEObjectType data to $WEExportPath"
    $WEObject | ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 -FilePath $WEExportPath
}



function WE-Export-ObjectCSV($WEObjectType, $WEObject) {
    Log-Info " Writing $WEObjectType data to $(Join-Path $WEOutputPath " $WEObjectType.csv" )"
    $WEObject | Export-Csv -NoTypeInformation -Path (Join-Path $WEOutputPath " $WEObjectType.csv" ) -Encoding utf8 
}



function WE-Export-ObjectXML($WEObjectType, $WEObject) {
    Log-Info " Writing $WEObjectType data to $(Join-Path $WEOutputPath " $WEObjectType.xml" )"
    $WEObject | ConvertTo-XML -Depth 20 -NoTypeInformation -As String| Out-File -Encoding utf8 -FilePath (Join-Path $WEOutputPath " $WEObjectType.xml" )
}



function WE-Export-Object ($WEObjectType, $WEObject){
    Log-Info " Exporting data for $WEObjectType ID:$($WEObject.id)"

    if (-not $WEAll) {
        Filter-Entity -EntityName $WEObjectType -Entity $WEObject
    }

    if ($WEExportFormat -eq " CSV" )
    {
        Export-ObjectCsv $WEObjectType $WEObject
    }
    if ($WEExportFormat -eq " JSON" )
    {
        Export-ObjectJson $WEObjectType $WEObject
    }
    if ($WEExportFormat -eq " XML" )
    {
        Export-ObjectXML $WEObjectType $WEObject
    }
}



function WE-Export-Collection ($WECollectionType, $WEObjectType, $WECollection) {
    if ($WECollection.Count -eq 0) {
        Log-Info " No $WEObjectType data found to export"
        return
    }

    if (-not $WEAll) {
        $WECollection | ForEach-Object { Filter-Entity -EntityName $WEObjectType -Entity $_ }
    }

    if ($WEExportFormat -eq " JSON" )
    {
        $WEExportPath = (Join-Path $WEOutputPath " $WECollectionType.json" )
        $WECollection | ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 -FilePath $WEExportPath
        Log-Info " Exported $($WECollection.Count) $WECollectionType to $WEExportPath"
    }
    if ($WEExportFormat -eq " XML" )
    {
        $WEExportPath = (Join-Path $WEOutputPath " $WECollectionType.xml" )
        $WECollection | ConvertTo-XML -Depth 20 -NoTypeInformation -As String| Out-File -Encoding utf8 -FilePath $WEExportPath
        Log-Info " Exported $($WECollection.Count) $WECollectionType to $WEExportPath"
    }
    if ($WEExportFormat -eq " CSV" )
    {
        $WEExportPath = (Join-Path $WEOutputPath " $WECollectionType.csv" )
        $WECollection | Export-Csv -NoTypeInformation -Path $WEExportPath -Encoding utf8 
        Log-Info " Exported $($WECollection.Count) $WECollectionType to $WEExportPath"
    }
}





[CmdletBinding()]
function WE-Filter-Entity {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        $WEEntityName,
        $WEEntity
    )

    Log-Verbose " Filtering entity $WEEntityName"

    if ($null -eq $WEEntity) {
        return
    }

    $WEAllEntityConfiguration = $WEExportConfiguration.All
    $WEEntityConfiguration = $WEExportConfiguration." $WEEntityName"

    $WEPropertiesToRemove = @()
    if ($WEAllEntityConfiguration.columnsToExclude.Count -gt 0) {
        $WEPropertiesToRemove = $WEPropertiesToRemove + $WEAllEntityConfiguration.columnsToExclude
    }
    if ($WEEntityConfiguration.columnsToExclude.Count -gt 0) {
        $WEPropertiesToRemove = $WEPropertiesToRemove + $WEEntityConfiguration.columnsToExclude
    }

    $WEPropertiesToRename = @()
    if ($WEAllEntityConfiguration.columnsToRename.Count -gt 0) {
        $WEPropertiesToRename = $WEPropertiesToRename + $WEAllEntityConfiguration.columnsToRename
    }
    if ($WEEntityConfiguration.columnsToRename.Count -gt 0) {
        $WEPropertiesToRename = $WEPropertiesToRename + $WEEntityConfiguration.columnsToRename
    }

    foreach ($WEPropertyToRemove in $WEPropertiesToRemove) {
        $WEEntity.PSObject.Properties.Remove($WEPropertyToRemove)
    }    

    foreach ($WEPropertyToRename in $WEPropertiesToRename) {
        $WEOldPropertyName = $WEPropertyToRename | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

        #Check if the old property exists on the entity      
        $WEOldPropertyExists = (($WEEntity | Get-Member -MemberType NoteProperty -Name $WEOldPropertyName) -ne $null)

        if (-not $WEOldPropertyExists) {
            continue
        }

        $WENewPropertyName = $WEPropertyToRename." $WEOldPropertyName"
        $WEPropertyValue = $WEEntity." $WEOldPropertyName"
        $WEEntity.PSObject.Properties.Remove(" $WEOldPropertyName" )
        Add-Member -MemberType NoteProperty -InputObject $WEEntity -Name $WENewPropertyName -Value $WEPropertyValue
    }

    $WENestedArrays = @($WEEntity | Get-Member -MemberType NoteProperty | Where-Object { $_.Definition.StartsWith(" Object[]" )})
    $WENestedObjects = @($WEEntity | Get-Member -MemberType NoteProperty | Where-Object { $_.Definition.StartsWith(" System.Management.Automation.PSCustomObject" )})

    foreach ($WENestedArray in $WENestedArrays) {
        $WEArray = $WEEntity." $($WENestedArray.Name)"
        if ($WEArray.Count -eq 0) {
            continue
        }
        foreach ($WEValue in $WEArray) {
            Filter-Entity -EntityName " $WEEntityName.$($WENestedArray.Name)" -Entity $WEValue
        }
    }
    foreach ($WENestedObject in $WENestedObjects) {
        $WEObject = $WEEntity." $($WENestedObject.Name)"
        Filter-Entity -EntityName " $WEEntityName.$($WENestedObject.Name)" -Entity $WEObject
    }
}



if (-not (Test-Path $WEOutputPath)) {
    Log-Verbose " Creating Folder $WEOutputPath"
    New-Item -ItemType Directory -Path $WEOutputPath | Out-Null
}



if ([string]::IsNullOrWhiteSpace($WEConfigurationFile)) {
    $WEConfigurationFile = Join-Path $WEPSScriptRoot " ExportConfiguration.json"
}

Log-Verbose " Loading configuration from $WEConfigurationFile"

if (Test-Path $WEConfigurationFile) {
    $WEExportConfiguration = (Get-Content -ErrorAction Stop $WEConfigurationFile | ConvertFrom-Json)
} else {
    Log-Warning " Configuration file $WEConfigurationFile not found"
}



$WEUPN = $WEUpn.ToLowerInvariant()

Log-Info " Exporting user data for user $WEUpn to $WEOutputPath"

if ($WEAll) {
    Log-Info " All data will be exported"
} elseif ($WEIncludeAzureAD) {
    Log-Info " Including AzureAD data in export"
} 



$WEAuthHeader = Get-AuthToken -User $WEUsername





if ($WEIncludeNonAzureADUpn -or $WEAll) {
    Export-ChromeOSDeviceReportData
}





$WEUser = Get-User -ErrorAction Stop

if ($null -eq $WEUser) {
    Log-Warning " Azure AD User with UPN $WEUPN was not found"
    return
}

$WEUserId = $WEUser.id
Log-Info " Exporting data for user `" $($WEUser.displayName)`" with UPN $($WEUser.userPrincipalName) and ID $WEUserId"
$WEUserDisplayName = $WEUser.displayName



if (-not (Test-IntuneUser)) {
    Log-Warning " User with UPN $WEUPN is not a Microsoft Intune user"
    return
}

Log-Info " User is a valid Microsoft Intune user"



if ($WEIncludeAzureAD -or $WEAll) {
    Export-Object " Azure AD User" $WEUser

    $WEGroups = Get-GroupMemberships -ErrorAction Stop
    Export-Collection " Azure AD Groups" " Azure AD Group" $WEGroups

    $WEGroups = Get-RegisteredDevices -ErrorAction Stop
    Export-Collection " Azure AD Registered Devices" " Azure AD Registered Device" $WEGroups
}



$WEManagedDevices = Get-ManagedDevices -ErrorAction Stop
Export-Collection " ManagedDevices" " ManagedDevice" $WEManagedDevices

$WEAuditEvents = Get-AuditEvents -ErrorAction Stop
Export-Collection " AuditEvents" " AuditEvent" $WEAuditEvents

$WEManagedAppRegistrations = Get-ManagedAppRegistrations -ErrorAction Stop
Export-Collection " ManagedAppRegistrations" " ManagedAppRegistration" $WEManagedAppRegistrations

$WEAppleDepSettings = Get-AppleDepSettings -ErrorAction Stop
Export-Collection " AppleDEPSettings" " AppleDEPSetting" $WEAppleDepSettings

$WEAppInstallStatuses = Get-AppInstallStatuses -ErrorAction Stop
Export-Collection " AppInstallStatuses" " AppInstallStatus" $WEAppInstallStatuses

$WEEbookInstallStatuses = Get-EbookInstallStatuses -ErrorAction Stop
Export-Collection " EbookInstallStatuses" " EbookInstallStatus" $WEEbookInstallStatuses

$WEWindowsManagementAppStatuses = Get-WindowsManagementAppHealthStates -ErrorAction Stop $WEManagedDevices
Export-Collection " WindowsManagementAppHealthStates" " WindowsManagementApp" $WEWindowsManagementAppStatuses

$WEWindowsProtectionStates = Get-WindowsProtectionStates -ErrorAction Stop $WEManagedDevices
Export-Collection " WindowsProtectionStates" " WindowsProtectionState" $WEWindowsProtectionStates

$WERemoteActionAudits = Get-RemoteActionAudits -ErrorAction Stop
Export-Collection " RemoteActionAudits" " RemoteActionAudit" $WERemoteActionAudits

$WEDeviceManagementTroubleshootingEvents = Get-DeviceManagementTroubleshootingEvents -ErrorAction Stop
Export-Collection " DeviceManagementTroubleshootingEvents" " DeviceManagementTroubleshootingEvents" $WEDeviceManagementTroubleshootingEvents

$WEIosUpdateStatues = Get-IosUpdateStatuses -ErrorAction Stop
Export-Collection " iOSUpdateStatus" " iOSUpdateStatuses" $WEIosUpdateStatues

$WEManagedDeviceMobileAppConfigurationStatuses = Get-ManagedDeviceMobileAppConfigurationStatuses -ErrorAction Stop  $WEManagedDevices
Export-Collection " MobileAppConfigurationStatuses" " MobileAppConfigurationStatus" $WEManagedDeviceMobileAppConfigurationStatuses

$WEDeviceManagementScriptRunStates = Get-DeviceManagementScriptRunStates -ErrorAction Stop 
Export-Collection " DeviceManagementScriptRunState" " DeviceManagementScriptRunStates" $WEDeviceManagementScriptRunStates

$WEAppProtectionUserStatus = Get-AppProtectionUserStatuses -ErrorAction Stop
Export-Object " ManagedAppProtectionStatusReport" $WEAppProtectionUserStatus

$WEWindowsProtectionSummary = Get-WindowsProtectionSummary -ErrorAction Stop
Export-Object " WindowsProtectionSummary" $WEWindowsProtectionSummary

$WEManagedAppUsageSummary = Get-ManagedAppUsageSummary -ErrorAction Stop
Export-Object " ManagedAppUsageSummary" $WEManagedAppUsageSummary
; 
$WEManagedAppConfigurationStatusReport = Get-ManagedAppConfigurationStatusReport -ErrorAction Stop
Export-Object " ManagedAppConfigurationStatusReport" $WEManagedAppConfigurationStatusReport
; 
$WETermsAndConditionsAcceptanceStatuses = Get-TermsAndConditionsAcceptanceStatuses -ErrorAction Stop
Export-Collection " TermsAndConditionsAcceptanceStatus" " TermsAndConditionsAcceptanceStatuses" $WETermsAndConditionsAcceptanceStatuses

Export-RemainingData

Log-Info " Export complete, files can be found at $WEOutputPath"
Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================