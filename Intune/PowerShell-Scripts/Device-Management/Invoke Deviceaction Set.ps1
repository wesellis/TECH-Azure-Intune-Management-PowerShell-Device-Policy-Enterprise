<#
.SYNOPSIS
    Invoke Deviceaction Set

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
    We Enhanced Invoke Deviceaction Set

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



Function Invoke-DeviceAction(){

<#
.SYNOPSIS
This function is used to set a generic intune resources from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets a generic Intune Resource
.EXAMPLE
Invoke-DeviceAction -DeviceID $WEDeviceID -remoteLock
Resets a managed device passcode
.NOTES
NAME: Invoke-DeviceAction


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [switch]$WERemoteLock,
    [switch]$WEResetPasscode,
    [switch]$WEWipe,
    [switch]$WERetire,
    [switch]$WEDelete,
    [switch]$WESync,
    [switch]$WERename,
    [Parameter(Mandatory=$true,HelpMessage=" DeviceId (guid) for the Device you want to take action on must be specified:" )]
    $WEDeviceID
)

$graphApiVersion = " Beta"

    try {

        $WECount_Params = 0

        if($WERemoteLock.IsPresent){ $WECount_Params++ }
        if($WEResetPasscode.IsPresent){ $WECount_Params++ }
        if($WEWipe.IsPresent){ $WECount_Params++ }
        if($WERetire.IsPresent){ $WECount_Params++ }
        if($WEDelete.IsPresent){ $WECount_Params++ }
        if($WESync.IsPresent){ $WECount_Params++ }
        if($WERename.IsPresent){ $WECount_Params++ }

        if($WECount_Params -eq 0){

        Write-Information " No parameter set, specify -RemoteLock -ResetPasscode -Wipe -Delete -Sync or -rename against the function" -f Red

        }

        elseif($WECount_Params -gt 1){

        Write-Information " Multiple parameters set, specify a single parameter -RemoteLock -ResetPasscode -Wipe -Delete or -Sync against the function" -f Red

        }

        elseif($WERemoteLock){

        $WEResource = " deviceManagement/managedDevices/$WEDeviceID/remoteLock"
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
        write-verbose $uri
        Write-Verbose " Sending remoteLock command to $WEDeviceID"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

        }

        elseif($WEResetPasscode){

            Write-Information Write-Information " Are you sure you want to reset the Passcode this device? Y or N?"
            $WEConfirm = read-host

            if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

            $WEResource = " deviceManagement/managedDevices/$WEDeviceID/resetPasscode"
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose " Sending remotePasscode command to $WEDeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

            }

            else {

            Write-WELog " Reset of the Passcode for the device $WEDeviceID was cancelled..." " INFO"

            }

        }

        elseif($WEWipe){

        Write-Information Write-Information " Are you sure you want to wipe this device? Y or N?"
        $WEConfirm = read-host

            if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

            $WEResource = " deviceManagement/managedDevices/$WEDeviceID/wipe"
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose " Sending wipe command to $WEDeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

            }

            else {

            Write-WELog " Wipe of the device $WEDeviceID was cancelled..." " INFO"

            }

        }

        elseif($WERetire){

        Write-Information Write-Information " Are you sure you want to retire this device? Y or N?"
        $WEConfirm = read-host

            if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

            $WEResource = " deviceManagement/managedDevices/$WEDeviceID/retire"
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose " Sending retire command to $WEDeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

            }

            else {

            Write-WELog " Retire of the device $WEDeviceID was cancelled..." " INFO"

            }

        }

        elseif($WEDelete){

        Write-Information Write-Warning " A deletion of a device will only work if the device has already had a retire or wipe request sent to the device..."
        Write-Information Write-Information " Are you sure you want to delete this device? Y or N?"
        $WEConfirm = read-host

            if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

            $WEResource = " deviceManagement/managedDevices('$WEDeviceID')"
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose " Sending delete command to $WEDeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete

            }

            else {

            Write-WELog " Deletion of the device $WEDeviceID was cancelled..." " INFO"

            }

        }
        
        elseif($WESync){

        Write-Information Write-Information " Are you sure you want to sync this device? Y or N?"
        $WEConfirm = read-host

            if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

            $WEResource = " deviceManagement/managedDevices('$WEDeviceID')/syncDevice"
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose " Sending sync command to $WEDeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

            }

            else {

            Write-WELog " Sync of the device $WEDeviceID was cancelled..." " INFO"

            }

        }

        elseif($WERename){

        Write-Information " Please type the new device name:"
        $WENewDeviceName = Read-Host

$WEJSON = @"

{
    deviceName:" $($WENewDeviceName)"
}

" @

        Write-Information Write-Information " Note: The RenameDevice remote action is only supported on supervised iOS and Windows 10 Azure AD joined devices"
        Write-Information " Are you sure you want to rename this device to" $($WENewDeviceName) " (Y or N?)"
        $WEConfirm = read-host

            if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

            $WEResource = " deviceManagement/managedDevices('$WEDeviceID')/setDeviceName"
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose " Sending rename command to $WEDeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJson -ContentType " application/json"

            }

            else {

            Write-WELog " Rename of the device $WEDeviceID was cancelled..." " INFO"

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





Write-Information if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        Write-Information " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        Write-Information # Defining User Principal Name if not present

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





Write-Information write-host " User Principal Name:" -f Yellow
$WEUPN = Read-Host

Write-Information $WEUser = Get-AADUser -userPrincipalName $WEUPN

$id = $WEUser.Id
Write-Information " User ID:" $id



Write-Information Write-WELog " Checking if the user" " INFO" $WEUser.displayName " has any devices assigned..."

$WEDevices = Get-AADUserDevices -UserID $id



if($WEDevices){

$WEDeviceCount = @($WEDevices).count

Write-Information Write-WELog " User has $WEDeviceCount devices added to Intune..." " INFO"
Write-Information if($WEDevices.id.count -gt 1){

   ;  $WEManaged_Devices = $WEDevices.deviceName | sort -Unique

   ;  $menu = @{}

    for ($i=1;$i -le $WEManaged_Devices.count; $i++) 
    { Write-WELog " $i. $($WEManaged_Devices[$i-1])" " INFO" 
    $menu.Add($i,($WEManaged_Devices[$i-1]))}

    Write-Information [int]$ans = Read-Host 'Enter Device id (Numerical value)'
    $selection = $menu.Item($ans)

        if($selection){

       ;  $WESelectedDevice = $WEDevices | ? { $_.deviceName -eq " $WESelection" }

       ;  $WESelectedDeviceId = $WESelectedDevice | select -ExpandProperty id

        Write-Information " User" $WEUser.userPrincipalName " has device" $WESelectedDevice.deviceName
        #Invoke-DeviceAction -DeviceID $WESelectedDeviceId -RemoteLock -Verbose
        #Invoke-DeviceAction -DeviceID $WESelectedDeviceId -Retire -Verbose
        #Invoke-DeviceAction -DeviceID $WESelectedDeviceId -Wipe -Verbose
        #Invoke-DeviceAction -DeviceID $WESelectedDeviceId -Delete -Verbose
        #Invoke-DeviceAction -DeviceID $WESelectedDeviceId -Sync -Verbose
        #Invoke-DeviceAction -DeviceID $WESelectedDeviceId -Rename -Verbose

        }

    }

    elseif($WEDevices.id.count -eq 1){

        Write-Information " User" $WEUser.userPrincipalName " has one device" $WEDevices.deviceName
        #Invoke-DeviceAction -DeviceID $WEDevices.id -RemoteLock -Verbose
        #Invoke-DeviceAction -DeviceID $WEDevices.id -Retire -Verbose
        #Invoke-DeviceAction -DeviceID $WEDevices.id -Wipe -Verbose
        #Invoke-DeviceAction -DeviceID $WEDevices.id -Delete -Verbose
        #Invoke-DeviceAction -DeviceID $WEDevices.id -Sync -Verbose
        #Invoke-DeviceAction -DeviceID $WEDevices.id -Rename -Verbose

    }

}

else {

Write-Information write-host " User $WEUPN doesn't have any owned Devices..." -f Yellow

}

Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================