<#
.SYNOPSIS
    User Policy Report Get

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
    We Enhanced User Policy Report Get

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



Function Get-AADUser(){

<#
.SYNOPSIS
This function is used to get AAD Users from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any users registered with AAD
.EXAMPLE
Get-AADUser -ErrorAction Stop
Returns all users registered with Azure AD
.EXAMPLE
Get-AADUser -userPrincipleName user@domain.com
Returns specific user by UserPrincipalName registered with Azure AD
.NOTES
NAME: Get-AADUser -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $userPrincipalName,
    $WEProperty
)


$graphApiVersion = " v1.0"
$WEUser_resource = " users"
    
    try {
        
        if($userPrincipalName -eq "" -or $null -eq $userPrincipalName){
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEUser_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if($WEProperty -eq "" -or $null -eq $WEProperty){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEUser_resource)/$userPrincipalName"
            Write-Verbose $uri
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

            }

            else {

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEUser_resource)/$userPrincipalName/$WEProperty"
            Write-Verbose $uri
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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



Function Get-AADUserDevices(){

<#
.SYNOPSIS
This function is used to get an AAD User Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a users devices registered with Intune MDM
.EXAMPLE
Get-AADUserDevices -UserID $WEUserID
Returns all user devices registered in Intune MDM
.NOTES
NAME: Get-AADUserDevices -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true,HelpMessage=" UserID (guid) for the user you want to take action on must be specified:" )]
    $WEUserID
)


$graphApiVersion = " beta"
$WEResource = " users/$WEUserID/managedDevices"
    
    try {
    
    $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
    Write-Verbose $uri
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



Function Get-AADGroup(){

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


$graphApiVersion = " v1.0"
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
    [switch]$WEAndroid,
    [switch]$iOS,
    [switch]$WEWin10,
    $WEName
)

$graphApiVersion = " Beta"
$WEDCP_resource = " deviceManagement/deviceCompliancePolicies"
    
    try {
        
        # windows81CompliancePolicy
        # windowsPhone81CompliancePolicy

        $WECount_Params = 0

        if($WEAndroid.IsPresent){ $WECount_Params++ }
        if($iOS.IsPresent){ $WECount_Params++ }
        if($WEWin10.IsPresent){ $WECount_Params++ }

        if($WECount_Params -gt 1){
        
        Write-Information " Multiple parameters set, specify a single parameter -Android -iOS or -Win10 against the function" -f Red
        
        }
        
        elseif($WEAndroid){
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" android" ) }
        
        }
        
        elseif($iOS){
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" ios" ) }
        
        }

        elseif($WEWin10){
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" windows10CompliancePolicy" ) }
        
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



Function Get-DeviceCompliancePolicyAssignment(){

<#
.SYNOPSIS
This function is used to get device compliance policy assignment from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a device compliance policy assignment
.EXAMPLE
Get-DeviceCompliancePolicyAssignment -id $id
Returns any device compliance policy assignment configured in Intune
.NOTES
NAME: Get-DeviceCompliancePolicyAssignment -ErrorAction Stop

    
[cmdletbinding()]
    
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true,HelpMessage=" Enter id (guid) for the Device Compliance Policy you want to check assignment" )]
    $id
)
    
$graphApiVersion = " Beta"
$WEDCP_resource = " deviceManagement/deviceCompliancePolicies"
    
    try {
    
    $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)/$id/assignments"
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



Function Get-UserDeviceStatus(){

[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [switch]$WEAnalyze
)

Write-WELog " Getting User Devices..." " INFO" -ForegroundColor Yellow
Write-Information $WEUserDevices = Get-AADUserDevices -UserID $WEUserID

    if($WEUserDevices){

        Write-Information " -------------------------------------------------------------------"
        Write-Information foreach($WEUserDevice in $WEUserDevices){

        $WEUserDeviceId = $WEUserDevice.id
        $WEUserDeviceName = $WEUserDevice.deviceName
        $WEUserDeviceAADDeviceId = $WEUserDevice.azureActiveDirectoryDeviceId
        $WEUserDeviceComplianceState = $WEUserDevice.complianceState

        Write-Information " Device Name:" $WEUserDevice.deviceName -f Cyan
        Write-WELog " Device Id:" " INFO" $WEUserDevice.id
        Write-Information " Owner Type:" $WEUserDevice.ownerType
        Write-Information " Last Sync Date:" $WEUserDevice.lastSyncDateTime
        Write-Information " OS:" $WEUserDevice.operatingSystem
        Write-Information " OS Version:" $WEUserDevice.osVersion

            if($WEUserDevice.easActivated -eq $false){
            Write-Information " EAS Activated:" $WEUserDevice.easActivated -ForegroundColor Red
            }

            else {
            Write-Information " EAS Activated:" $WEUserDevice.easActivated
            }

        Write-WELog " EAS DeviceId:" " INFO" $WEUserDevice.easDeviceId

            if($WEUserDevice.aadRegistered -eq $false){
            Write-Information " AAD Registered:" $WEUserDevice.aadRegistered -ForegroundColor Red
            }

            else {
            Write-Information " AAD Registered:" $WEUserDevice.aadRegistered
            }
        
        Write-Information " Enrollment Type:" $WEUserDevice.enrollmentType
        Write-Information " Management State:" $WEUserDevice.managementState

            if($WEUserDevice.complianceState -eq " noncompliant" ){
            
                Write-Information " Compliance State:" $WEUserDevice.complianceState -f Red

                $uri = " https://graph.microsoft.com/beta/deviceManagement/managedDevices/$WEUserDeviceId/deviceCompliancePolicyStates"
                
                $deviceCompliancePolicyStates = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                    foreach($WEDCPS in $deviceCompliancePolicyStates){

                        if($WEDCPS.State -eq " nonCompliant" ){

                        Write-Information Write-WELog " Non Compliant Policy for device $WEUserDeviceName" " INFO"
                        Write-Information " Display Name:" $WEDCPS.displayName

                        $WESettingStatesId = $WEDCPS.id

                        $uri = " https://graph.microsoft.com/beta/deviceManagement/managedDevices/$WEUserDeviceId/deviceCompliancePolicyStates/$WESettingStatesId/settingStates?`$filter=(userId eq '$WEUserID')"

                        $WESettingStates = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                            foreach($WESS in $WESettingStates){

                                if($WESS.state -eq " nonCompliant" ){

                                    Write-Information Write-WELog " Setting:" " INFO" $WESS.setting
                                    Write-WELog " State:" " INFO" $WESS.state -ForegroundColor Red

                                }

                            }

                        }

                    }

                # Getting AAD Device using azureActiveDirectoryDeviceId property
                $uri = " https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$WEUserDeviceAADDeviceId'"
                $WEAADDevice = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                $WEAAD_Compliant = $WEAADDevice.isCompliant

                # Checking if AAD Device and Intune ManagedDevice state are the same value

                Write-Information Write-WELog " Compliance State - AAD and ManagedDevices" " INFO"
                Write-WELog " AAD Compliance State:" " INFO" $WEAAD_Compliant
                Write-WELog " Intune Managed Device State:" " INFO" $WEUserDeviceComplianceState
            
            }
            
            else {

                Write-Information " Compliance State:" $WEUserDevice.complianceState -f Green

                # Getting AAD Device using azureActiveDirectoryDeviceId property
                $uri = " https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$WEUserDeviceAADDeviceId'"
                $WEAADDevice = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                $WEAAD_Compliant = $WEAADDevice.isCompliant

                # Checking if AAD Device and Intune ManagedDevice state are the same value

                Write-Information Write-WELog " Compliance State - AAD and ManagedDevices" " INFO"
                Write-WELog " AAD Compliance State:" " INFO" $WEAAD_Compliant
                Write-WELog " Intune Managed Device State:" " INFO" $WEUserDeviceComplianceState
            
            }

        Write-Information Write-Information " -------------------------------------------------------------------"
        Write-Information }

    }

    else {

    #Write-Information " User Devices:" -f Yellow
    Write-Information " User has no devices"
    Write-Information }

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





Write-Information " User Principal Name:" -f Yellow
$WEUPN = Read-Host

$WEUser = Get-AADUser -userPrincipalName $WEUPN

$WEUserID = $WEUser.id

Write-Information Write-Information " Display Name:" $WEUser.displayName
Write-Information " User ID:" $WEUser.id
Write-Information " User Principal Name:" $WEUser.userPrincipalName
Write-Information $WEMemberOf = Get-AADUser -userPrincipalName $WEUPN -Property MemberOf

$WEAADGroups = $WEMemberOf | ? { $_.'@odata.type' -eq " #microsoft.graph.group" }

    if($WEAADGroups){

    Write-Information " User AAD Group Membership:" -f Yellow
        
        foreach($WEAADGroup in $WEAADGroups){
        
        (Get-AADGroup -id $WEAADGroup.id).displayName

        }

    Write-Information }

    else {

    Write-Information " AAD Group Membership:" -f Yellow
    Write-Information " No Group Membership in AAD Groups"
    Write-Information }



$WECPs = Get-DeviceCompliancePolicy -ErrorAction Stop

if($WECPs){

    Write-Information " Assigned Compliance Policies:" -f Yellow
    $WECP_Names = @()

    foreach($WECP in $WECPs){

   ;  $id = $WECP.id

   ;  $WEDCPA = Get-DeviceCompliancePolicyAssignment -id $id

        if($WEDCPA){

            foreach($WECom_Group in $WEDCPA){
            
                if($WEAADGroups.id -contains $WECom_Group.target.GroupId){

               ;  $WECP_Names = $WECP_Names + $WECP.displayName + " - " + $WECP.'@odata.type'

                }

            }

        }

    }

    if($null -ne $WECP_Names){
    
    $WECP_Names
    
    }
    
    else {
    
    Write-Information " No Device Compliance Policies Assigned"
    
    }

}

else {

Write-Information " Device Compliance Policies:" -f Yellow
Write-Information " No Device Compliance Policies Assigned"

}

Write-Information Get-UserDeviceStatus -ErrorAction Stop





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================