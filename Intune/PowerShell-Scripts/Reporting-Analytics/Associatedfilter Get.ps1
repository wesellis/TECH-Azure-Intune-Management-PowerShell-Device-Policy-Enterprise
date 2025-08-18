<#
.SYNOPSIS
    Associatedfilter Get

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
    We Enhanced Associatedfilter Get

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

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

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



Function Get-AADGroups(){

<#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup -ErrorAction Stop
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEGroupName,
    $id,
    [switch]$WEMembers
)


$graphApiVersion = " beta"
$WEGroup_resource = " groups"
    
    try {

        if($id){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)?`$filter=id eq '$id'"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }
        
        elseif($WEGroupName -eq "" -or $null -eq $WEGroupName){
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if(!$WEMembers){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)?`$filter=displayname eq '$WEGroupName'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
            }
            
            elseif($WEMembers){
            
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)?`$filter=displayname eq '$WEGroupName'"
            $WEGroup = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
                if($WEGroup){

                $WEGID = $WEGroup.id

                $WEGroup.displayName
                Write-Information $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)/$WEGID/Members"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                }

            }
        
        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Get-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to get device compliance policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device compliance policies
.EXAMPLE
Get-DeviceCompliancePolicy -ErrorAction Stop
Returns any device compliance policies configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -Android
Returns any device compliance policies for Android configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -iOS
Returns any device compliance policies for iOS configured in Intune
.NOTES
NAME: Get-DeviceCompliancePolicy -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEName,
    [Parameter(HelpMessage = " Compliance Platform" )]
    [ValidateSet(" Android" ," iOS" ," Windows10" ," AndroidEnterprise" ," macOS" )]
    $WEPlatform

)

$graphApiVersion = " Beta"
$WEResource = " deviceManagement/deviceCompliancePolicies?`$expand=assignments"

    try {


        if($WEPlatform -eq " Android" ){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" android" ) }

        }

        elseif($WEPlatform -eq " iOS" ){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" ios" ) }

        }

        elseif($WEPlatform -eq " Windows10" ){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" windows10CompliancePolicy" ) }

        }

        elseif($WEName){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains(" $WEName" ) }

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Get-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to get device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device configuration policies
.EXAMPLE
Get-DeviceConfigurationPolicy -ErrorAction Stop
Returns any device configuration policies configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicy -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $name
)

$graphApiVersion = " Beta"
$WEDCP_resource = " deviceManagement/deviceConfigurations?`$expand=assignments"

    try {

        if($WEName){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains(" $WEName" ) }

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Get-AdministrativeTemplates(){

<#
.SYNOPSIS
This function is used to get Administrative Templates from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Administrative Templates
.EXAMPLE
Get-AdministrativeTemplates -ErrorAction Stop
Returns any Administrative Templates configured in Intune
.NOTES
NAME: Get-AdministrativeTemplates -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $name
)

$graphApiVersion = " beta"
$WEResource = " deviceManagement/groupPolicyConfigurations?`$expand=assignments"

    try {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Get-AssignmentFilters(){

<#
.SYNOPSIS
This function is used to get assignment filters from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any assignment filters
.EXAMPLE
Get-AssignmentFilters -ErrorAction Stop
Returns any assignment filters configured in Intune
.NOTES
NAME: Get-AssignmentFilters -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $name
)

$graphApiVersion = " beta"
$WEResource = " deviceManagement/assignmentFilters"

    try {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Get-SettingsCatalogPolicy(){

<#
.SYNOPSIS
This function is used to get Settings Catalog policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Settings Catalog policies
.EXAMPLE
Get-SettingsCatalogPolicy -ErrorAction Stop
Returns any Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform windows10
Returns any Windows 10 Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform macOS
Returns any MacOS Settings Catalog policies configured in Intune
.NOTES
NAME: Get-SettingsCatalogPolicy -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory=$false)]
    [ValidateSet(" windows10" ," macOS" )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPlatform,
    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    $id
)

$graphApiVersion = " beta"

    if($WEPlatform){
        
        $WEResource = " deviceManagement/configurationPolicies?`$filter=platforms has '$WEPlatform' and technologies has 'mdm'"

    }

    elseif($id){

        $WEResource = " deviceManagement/configurationPolicies('$id')/assignments"

    }

    else {

        $WEResource = " deviceManagement/configurationPolicies?`$filter=technologies has 'mdm'"

    }

    try {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}



Function Get-IntuneApplication(){

<#
.SYNOPSIS
This function is used to get applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any applications added
.EXAMPLE
Get-IntuneApplication -ErrorAction Stop
Returns any applications configured in Intune
.NOTES
NAME: Get-IntuneApplication -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEName
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileApps?`$expand=assignments"

    try {

        if($WEName){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains(" $WEName" ) -and (!($_.'@odata.type').Contains(" managed" )) -and (!($_.'@odata.type').Contains(" #microsoft.graph.iosVppApp" )) }

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { (!($_.'@odata.type').Contains(" managed" )) }

        }

    }

    catch {

    $ex = $_.Exception
    Write-WELog " Request to $WEUri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" " INFO" -f Red
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break

    }

}





Write-Information if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        Write-Information " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        Write-Information # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if($null -eq $WEUser -or $WEUser -eq "" ){

            $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
            Write-Information }

        $script:authToken = Get-AuthToken -User $WEUser

        }
}



else {

    if($null -eq $WEUser -or $WEUser -eq "" ){

    $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Information }


$script:authToken = Get-AuthToken -User $WEUser

}





Write-Information " Filters Name:" -f Yellow
$WEFilterName = Read-Host

if($null -eq $WEFilterName -or $WEFilterName -eq "" ){

    Write-Information " Filter Name is Null..."
    Write-WELog " Script can't continue..." " INFO" -ForegroundColor Red
    Write-Information break

}



$WEFilters = Get-AssignmentFilters -ErrorAction Stop

$WEFilter = $WEFilters | ? { $_.displayName -eq " $WEFilterName" }

if(!$WEFilter){

    Write-Information Write-WELog " Filter with Name '$WEFilterName' doesn't exist..." " INFO"
    Write-WELog " Script can't continue..." " INFO" -ForegroundColor Red
    Write-Information break

}

if($WEFilter.count -gt 1){

    Write-Information Write-WELog " There are multiple filters with the same display name '$WEFilterName', unique names should be used..." " INFO"
    Write-WELog " Script can't continue..." " INFO" -ForegroundColor Red
    Write-Information break

}

Write-Information Write-Information " -------------------------------------------------------------------"
Write-Information Write-WELog " Filter found..." " INFO" -f Green
Write-WELog " Filter Id:       " " INFO" $WEFilter.id
Write-WELog " Filter Name:     " " INFO" $WEFilter.displayName
Write-WELog " Filter Platform: " " INFO" $WEFilter.platform
Write-WELog " Filter Rule:     " " INFO" $filter.rule
Write-WELog " Filter Scope Tag:" " INFO" $filter.roleScopeTags
Write-Information $WEActivity = " Filter Usage Check"





$WECPs = Get-DeviceCompliancePolicy -ErrorAction Stop

Write-Information " -------------------------------------------------------------------"
Write-Information " Device Compliance Policies" -f Cyan
Write-Information " -------------------------------------------------------------------"

if(@($WECPs).count -ge 1){

    $WECPCount = @($WECPs).count
    $i = 1

    $WECP_Count = 0

    foreach($WECP in $WECPs){

    $id = $WECP.id

    $WEDCPA = $WECP.assignments

        if($WEDCPA){

            foreach($WECom_Group in $WEDCPA){

                if($WECom_Group.target.deviceAndAppManagementAssignmentFilterId -eq $WEFilter.id){

                    Write-Information Write-WELog " Policy Name: " " INFO" -NoNewline
                    Write-Information $WECP.displayName -f green
                    Write-WELog " Filter Type:" " INFO" $WECom_Group.target.deviceAndAppManagementAssignmentFilterType
                    
                    if($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allDevicesAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Devices" " INFO"

                    }

                    elseif($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allLicensedUsersAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Users" " INFO"

                    }

                    else {

                        Write-WELog " AAD Group Name:" " INFO" (Get-AADGroups -id $WECom_Group.target.groupId).displayName

                    }

                    Write-Information $WECP_Count++

                }

            }

        }

        Write-Progress -Activity " $WEActivity" -status " Checking Device Compliance Policy $i of $WECPCount" `
        -percentComplete ($i / $WECPCount*100)
        $i++

    }

    Write-Progress -Completed -Activity " $WEActivity"

    if($WECP_Count -eq 0){

        Write-Information Write-WELog " Filter '$WEFilterName' not used..." " INFO"
        Write-Information }

}

else {

Write-Information write-host " No Device Compliance Policies Found..." -f Red
Write-Information }







$WEDCPs = Get-DeviceConfigurationPolicy -ErrorAction Stop

Write-Information " -------------------------------------------------------------------"
Write-Information " Device Configuration Policies" -f Cyan
Write-Information " -------------------------------------------------------------------"

if($WEDCPs){

    $WEDCPsCount = @($WEDCPs).count
    $i = 1
    
    $WEDCP_Count = 0

    foreach($WEDCP in $WEDCPs){

    $id = $WEDCP.id

    $WECPA = $WEDCP.assignments

        if($WECPA){

            foreach($WECom_Group in $WECPA){

                if($WECom_Group.target.deviceAndAppManagementAssignmentFilterId -eq $WEFilter.id){

                    Write-Information Write-WELog " Policy Name: " " INFO" -NoNewline
                    Write-Information $WEDCP.displayName -f green
                    Write-WELog " Filter Type:" " INFO" $WECom_Group.target.deviceAndAppManagementAssignmentFilterType
                    
                    if($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allDevicesAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Devices" " INFO"

                    }

                    elseif($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allLicensedUsersAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Users" " INFO"

                    }

                    else {

                        Write-WELog " AAD Group Name:" " INFO" (Get-AADGroups -id $WECom_Group.target.groupId).displayName

                    }

                    Write-Information $WEDCP_Count++

                }
            

            }

        }

        Write-Progress -Activity " $WEActivity" -status " Checking Device Configuration Policy $i of $WEDCPsCount" `
        -percentComplete ($i / $WEDCPsCount*100)
        $i++

    }

    Write-Progress -Completed -Activity " $WEActivity"

    if($WEDCP_Count -eq 0){

        Write-Information Write-WELog " Filter '$WEFilterName' not used..." " INFO"
        Write-Information }

}

else {

    Write-Information Write-Information " No Device Configuration Policies Found..."
    Write-Information }







$WESCPolicies = Get-SettingsCatalogPolicy -ErrorAction Stop

Write-Information " -------------------------------------------------------------------"
Write-Information " Settings Catalog Policies" -f Cyan
Write-Information " -------------------------------------------------------------------"

if($WESCPolicies){

    $WESCPCount = @($WESCPolicies).count
    $i = 1

    $WESC_Count = 0

    foreach($WESCPolicy in $WESCPolicies){

    $id = $WESCPolicy.id

    $WESCPolicyAssignment = Get-SettingsCatalogPolicy -id $id

        if($WESCPolicyAssignment){

            foreach($WECom_Group in $WESCPolicyAssignment){
            
                if($WECom_Group.target.deviceAndAppManagementAssignmentFilterId -eq $WEFilter.id){

                    Write-Information Write-WELog " Policy Name: " " INFO" -NoNewline
                    Write-Information $WESCPolicy.name -f green
                    Write-WELog " Filter Type:" " INFO" $WECom_Group.target.deviceAndAppManagementAssignmentFilterType
                    
                    if($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allDevicesAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Devices" " INFO"

                    }

                    elseif($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allLicensedUsersAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Users" " INFO"

                    }

                    else {

                        Write-WELog " AAD Group Name:" " INFO" (Get-AADGroups -id $WECom_Group.target.groupId).displayName

                    }

                    Write-Information $WESC_Count++

                }

            }

        }

        Write-Progress -Activity " $WEActivity" -status " Checking Settings Catalog $i of $WESCPCount" `
        -percentComplete ($i / $WESCPCount*100)
        $i++

    }

    Write-Progress -Completed -Activity " $WEActivity"

    if($WESC_Count -eq 0){

        Write-Information Write-WELog " Filter '$WEFilterName' not used..." " INFO"
        Write-Information }

}

else {

    Write-Information Write-Information " No Settings Catalog Policies Found..."
    Write-Information }







$WEADMXPolicies = Get-AdministrativeTemplates -ErrorAction Stop

Write-Information " -------------------------------------------------------------------"
Write-Information " Administrative Templates Policies" -f Cyan
Write-Information " -------------------------------------------------------------------"

if($WEADMXPolicies){

    $WEATCount = @($WEADMXPolicies).count
    $i = 1

    $WEAT_Count = 0

    foreach($WEADMXPolicy in $WEADMXPolicies){

    $id = $WEADMXPolicy.id

    $WEATPolicyAssignment = $WEADMXPolicy.assignments

        if($WEATPolicyAssignment){

            foreach($WECom_Group in $WEATPolicyAssignment){

                if($WECom_Group.target.deviceAndAppManagementAssignmentFilterId -eq $WEFilter.id){

                    Write-Information Write-WELog " Policy Name: " " INFO" -NoNewline
                    Write-Information $WEADMXPolicy.displayName -f green
                    Write-WELog " Filter Type:" " INFO" $WECom_Group.target.deviceAndAppManagementAssignmentFilterType
                    
                    if($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allDevicesAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Devices" " INFO"

                    }

                    elseif($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allLicensedUsersAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Users" " INFO"

                    }

                    else {

                        Write-WELog " AAD Group Name:" " INFO" (Get-AADGroups -id $WECom_Group.target.groupId).displayName

                    }

                    Write-Information $WEAT_Count++

                }

            }

        }

        Write-Progress -Activity " $WEActivity" -status " Checking Administrative Templates Policy $i of $WEATCount" `
        -percentComplete ($i / $WEATCount*100)
        $i++

    }

    Write-Progress -Completed -Activity " $WEActivity"

    if($WEAT_Count -eq 0){

        Write-Information Write-WELog " Filter '$WEFilterName' not used..." " INFO"
        Write-Information }

}

else {

Write-Information Write-Information " No Administrative Templates Policies Found..."
Write-Information }







$WEApps = Get-IntuneApplication -ErrorAction Stop

Write-Information " -------------------------------------------------------------------"
Write-Information " Intune Applications" -f Cyan
Write-Information " -------------------------------------------------------------------"

if($WEApps){

    $WEAppsCount = @($WEApps).count
    $i = 1

    $WEApp_Count = 0

    foreach($WEApp in $WEApps){

    $id = $WEApp.id

   ;  $WEAppAssignment = $app.assignments

        if($WEAppAssignment){

            foreach($WECom_Group in $WEAppAssignment){
            
                if($WECom_Group.target.deviceAndAppManagementAssignmentFilterId -eq $WEFilter.id){

                    Write-Information Write-WELog " Application Name: " " INFO" -NoNewline
                    Write-Information $WEApp.displayName -f green
                    Write-WELog " Filter Type:" " INFO" $WECom_Group.target.deviceAndAppManagementAssignmentFilterType

                    if($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allDevicesAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Devices" " INFO"

                    }

                    elseif($WECom_Group.target.'@odata.type' -eq " #microsoft.graph.allLicensedUsersAssignmentTarget" ){

                        Write-WELog " AAD Group Name: All Users" " INFO"

                    }

                    else {

                        Write-WELog " AAD Group Name:" " INFO" (Get-AADGroups -id $WECom_Group.target.groupId).displayName

                    }

                    Write-Information $WEApp_Count++

                }

            }

        }

        Write-Progress -Activity " $WEActivity" -status " Checking Intune Application $i of $WEAppsCount" `
        -percentComplete ($i / $WEAppsCount*100)
        $i++

    }

    Write-Progress -Completed -Activity " $WEActivity"

    if($WEApp_Count -eq 0){

        Write-Information Write-WELog " Filter '$WEFilterName' not used..." " INFO"
        Write-Information }

}

else {

Write-Information Write-Information " No Intune Applications Found..."
Write-Information }





Write-Information " -------------------------------------------------------------------"
Write-WELog " Overall Analysis" " INFO" -ForegroundColor Cyan
Write-Information " -------------------------------------------------------------------"
Write-WELog " Status of each area of MEM that support Filters assignment status" " INFO"
Write-Information Write-WELog " Applicable OS Type: " " INFO" -NoNewline
Write-Information $WEFilter.Platform -ForegroundColor Yellow
Write-Information Write-WELog " Compliance Policies:           " " INFO" $WECP_Count
Write-Information " Device Configuration Policies: " $WEDCP_Count
Write-WELog " Settings Catalog Policies:     " " INFO" $WESC_Count
Write-WELog " Administrative Templates:      " " INFO" $WEAT_Count
Write-WELog " Intune Applications:           " " INFO" $WEApp_Count
Write-Information ; 
$WECountFilters = $WECP_Count + $WEDCP_Count + $WESC_Count + $WEAT_Count + $WEApp_Count

Write-WELog " Total Filters Assigned:" " INFO" $WECountFilters
Write-Information Write-Information " -------------------------------------------------------------------"
Write-WELog " Evaluation complete..." " INFO" -ForegroundColor Green
Write-Information " -------------------------------------------------------------------"
Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================