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





function WE-Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    $WEUser
)

$userUpn = New-Object " System.Net.Mail.MailAddress" -ArgumentList $WEUser

$tenant = $userUpn.Host

Write-WELog " Checking for AzureAD module..." " INFO"

    $WEAadModule = Get-Module -Name " AzureAD" -ListAvailable

    if ($WEAadModule -eq $null) {

        Write-WELog " AzureAD PowerShell module not found, looking for AzureADPreview" " INFO"
        $WEAadModule = Get-Module -Name " AzureADPreview" -ListAvailable

    }

    if ($WEAadModule -eq $null) {
        write-host
        write-host " AzureAD Powershell module not installed..." -f Red
        write-host " Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host " Script can't continue..." -f Red
        write-host
        exit
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

    $authContext = New-Object " Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object " Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList " Auto"

    $userId = New-Object " Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($WEUser, " OptionalDisplayableId" )

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

        Write-Host
        Write-WELog " Authorization Access Token is null, please re-run authentication..." " INFO" -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}



Function Get-AADUser(){

<#
.SYNOPSIS
This function is used to get AAD Users from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any users registered with AAD
.EXAMPLE
Get-AADUser
Returns all users registered with Azure AD
.EXAMPLE
Get-AADUser -userPrincipleName user@domain.com
Returns specific user by UserPrincipalName registered with Azure AD
.NOTES
NAME: Get-AADUser


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
        
        if($userPrincipalName -eq "" -or $userPrincipalName -eq $null){
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEUser_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if($WEProperty -eq "" -or $WEProperty -eq $null){

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
   ;  $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

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
NAME: Get-AADUserDevices


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
   ;  $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}



Function Get-AADGroup(){

<#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup


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
        
        elseif($WEGroupName -eq "" -or $WEGroupName -eq $null){
        
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
                write-host

                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)/$WEGID/Members"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                }

            }
        
        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
   ;  $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}



Function Get-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to get device compliance policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device compliance policies
.EXAMPLE
Get-DeviceCompliancePolicy
Returns any device compliance policies configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -Android
Returns any device compliance policies for Android configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -iOS
Returns any device compliance policies for iOS configured in Intune
.NOTES
NAME: Get-DeviceCompliancePolicy


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
        
        write-host " Multiple parameters set, specify a single parameter -Android -iOS or -Win10 against the function" -f Red
        
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
   ;  $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

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
NAME: Get-DeviceCompliancePolicyAssignment

    
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
   ;  $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break
    
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
Write-Host

$WEUserDevices = Get-AADUserDevices -UserID $WEUserID

    if($WEUserDevices){

        write-host " -------------------------------------------------------------------"
        Write-Host

        foreach($WEUserDevice in $WEUserDevices){

        $WEUserDeviceId = $WEUserDevice.id
        $WEUserDeviceName = $WEUserDevice.deviceName
        $WEUserDeviceAADDeviceId = $WEUserDevice.azureActiveDirectoryDeviceId
        $WEUserDeviceComplianceState = $WEUserDevice.complianceState

        write-host " Device Name:" $WEUserDevice.deviceName -f Cyan
        Write-WELog " Device Id:" " INFO" $WEUserDevice.id
        write-host " Owner Type:" $WEUserDevice.ownerType
        write-host " Last Sync Date:" $WEUserDevice.lastSyncDateTime
        write-host " OS:" $WEUserDevice.operatingSystem
        write-host " OS Version:" $WEUserDevice.osVersion

            if($WEUserDevice.easActivated -eq $false){
            write-host " EAS Activated:" $WEUserDevice.easActivated -ForegroundColor Red
            }

            else {
            write-host " EAS Activated:" $WEUserDevice.easActivated
            }

        Write-WELog " EAS DeviceId:" " INFO" $WEUserDevice.easDeviceId

            if($WEUserDevice.aadRegistered -eq $false){
            write-host " AAD Registered:" $WEUserDevice.aadRegistered -ForegroundColor Red
            }

            else {
            write-host " AAD Registered:" $WEUserDevice.aadRegistered
            }
        
        write-host " Enrollment Type:" $WEUserDevice.enrollmentType
        write-host " Management State:" $WEUserDevice.managementState

            if($WEUserDevice.complianceState -eq " noncompliant" ){
            
                write-host " Compliance State:" $WEUserDevice.complianceState -f Red

                $uri = " https://graph.microsoft.com/beta/deviceManagement/managedDevices/$WEUserDeviceId/deviceCompliancePolicyStates"
                
                $deviceCompliancePolicyStates = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                    foreach($WEDCPS in $deviceCompliancePolicyStates){

                        if($WEDCPS.State -eq " nonCompliant" ){

                        Write-Host
                        Write-WELog " Non Compliant Policy for device $WEUserDeviceName" " INFO" -ForegroundColor Yellow
                        write-host " Display Name:" $WEDCPS.displayName

                        $WESettingStatesId = $WEDCPS.id

                        $uri = " https://graph.microsoft.com/beta/deviceManagement/managedDevices/$WEUserDeviceId/deviceCompliancePolicyStates/$WESettingStatesId/settingStates?`$filter=(userId eq '$WEUserID')"

                        $WESettingStates = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                            foreach($WESS in $WESettingStates){

                                if($WESS.state -eq " nonCompliant" ){

                                    write-host
                                    Write-WELog " Setting:" " INFO" $WESS.setting
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

                Write-Host
                Write-WELog " Compliance State - AAD and ManagedDevices" " INFO" -ForegroundColor Yellow
                Write-WELog " AAD Compliance State:" " INFO" $WEAAD_Compliant
                Write-WELog " Intune Managed Device State:" " INFO" $WEUserDeviceComplianceState
            
            }
            
            else {

                write-host " Compliance State:" $WEUserDevice.complianceState -f Green

                # Getting AAD Device using azureActiveDirectoryDeviceId property
                $uri = " https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$WEUserDeviceAADDeviceId'"
                $WEAADDevice = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                $WEAAD_Compliant = $WEAADDevice.isCompliant

                # Checking if AAD Device and Intune ManagedDevice state are the same value

                Write-Host
                Write-WELog " Compliance State - AAD and ManagedDevices" " INFO" -ForegroundColor Yellow
                Write-WELog " AAD Compliance State:" " INFO" $WEAAD_Compliant
                Write-WELog " Intune Managed Device State:" " INFO" $WEUserDeviceComplianceState
            
            }

        write-host
        write-host " -------------------------------------------------------------------"
        Write-Host

        }

    }

    else {

    #write-host " User Devices:" -f Yellow
    write-host " User has no devices"
    write-host

    }

}





write-host


if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        write-host " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        write-host

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if($WEUser -eq $null -or $WEUser -eq "" ){

            $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $WEUser

        }
}



else {

    if($WEUser -eq $null -or $WEUser -eq "" ){

    $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Host

    }


$global:authToken = Get-AuthToken -User $WEUser

}





write-host " User Principal Name:" -f Yellow
$WEUPN = Read-Host

$WEUser = Get-AADUser -userPrincipalName $WEUPN

$WEUserID = $WEUser.id

write-host
write-host " Display Name:" $WEUser.displayName
write-host " User ID:" $WEUser.id
write-host " User Principal Name:" $WEUser.userPrincipalName
write-host



$WEMemberOf = Get-AADUser -userPrincipalName $WEUPN -Property MemberOf

$WEAADGroups = $WEMemberOf | ? { $_.'@odata.type' -eq " #microsoft.graph.group" }

    if($WEAADGroups){

    write-host " User AAD Group Membership:" -f Yellow
        
        foreach($WEAADGroup in $WEAADGroups){
        
        (Get-AADGroup -id $WEAADGroup.id).displayName

        }

    write-host

    }

    else {

    write-host " AAD Group Membership:" -f Yellow
    write-host " No Group Membership in AAD Groups"
    Write-Host

    }



$WECPs = Get-DeviceCompliancePolicy

if($WECPs){

    write-host " Assigned Compliance Policies:" -f Yellow
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

    if($WECP_Names -ne $null){
    
    $WECP_Names
    
    }
    
    else {
    
    write-host " No Device Compliance Policies Assigned"
    
    }

}

else {

write-host " Device Compliance Policies:" -f Yellow
write-host " No Device Compliance Policies Assigned"

}

write-host



Get-UserDeviceStatus





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================