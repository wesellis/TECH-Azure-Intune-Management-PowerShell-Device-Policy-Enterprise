<#
.SYNOPSIS
    Managedapppolicy Wipe

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
    We Enhanced Managedapppolicy Wipe

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



Function Get-AADUserManagedAppRegistrations(){

<#
.SYNOPSIS
This function is used to get an AAD User Managed App Registrations from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a users Managed App Registrations registered with AAD
.EXAMPLE
Get-AADUser
Returns all Managed App Registration for a User registered with Azure AD
.EXAMPLE
Get-AADUserManagedAppRegistrations -id $id
Returns specific user by id registered with Azure AD
.NOTES
NAME: Get-AADUserManagedAppRegistrations


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $id
)


$graphApiVersion = " beta"
$WEUser_resource = " users/$id/managedAppRegistrations"
    
    try {
        
        if(!$id){

        Write-WELog " No AAD User ID was passed to the function, specify a valid AAD User ID" " INFO" -ForegroundColor Red
        Write-Host
        break

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEUser_resource"

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





write-host


if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        write-host " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

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





write-host
write-host " User Principal Name:" -f Yellow
$WEUPN = Read-Host

$WEUser = Get-AADUser -userPrincipalName $WEUPN

$WEUserID = $WEUser.id

write-host
write-host " Display Name:" $WEUser.displayName
write-host " User ID:" $WEUser.id
write-host " User Principal Name:" $WEUser.userPrincipalName
write-host



$WEManagedAppReg = Get-AADUserManagedAppRegistrations -id $WEUserID

    if($WEManagedAppReg){

    $WEDeviceTag = $WEManagedAppReg.deviceTag | sort -Unique

        # If user has only 1 device with managed application follow this flow
        if($WEDeviceTag.count -eq 1){

        $WEDeviceName = $WEManagedAppReg.deviceName
    
        $uri = " https://graph.microsoft.com/beta/users('$WEUserID')/wipeManagedAppRegistrationByDeviceTag"

$WEJSON = @"

    {
        " deviceTag" : " $WEDeviceTag"
    }

" @
            
            write-host " Are you sure you want to wipe application data on device $WEDeviceName`? Y or N?" -f Yellow
            $WEConfirm = read-host

            if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"

            }

            else {

            Write-Host
            Write-WELog " Wipe application data for the device $WEDeviceName was cancelled..." " INFO"
            Write-Host

            }

        }

        # If the user has more than 1 device with managed application follow this flow
        else {

        Write-WELog " More than one device found with MAM Applications" " INFO" -ForegroundColor Yellow
        Write-Host

       ;  $WEMAM_Devices = $WEManagedAppReg.deviceName | sort -Unique
        
        # Building menu from Array to show more than one device

       ;  $menu = @{}

        for ($i=1;$i -le $WEMAM_Devices.count; $i++) 
        { Write-WELog " $i. $($WEMAM_Devices[$i-1])" " INFO" 
        $menu.Add($i,($WEMAM_Devices[$i-1]))}

        Write-Host
        [int]$ans = Read-Host 'Enter Device to wipe MAM Data (Numerical value)'
        $selection = $menu.Item($ans)

            If($selection){

            Write-WELog " Device selected:" " INFO" $selection
            Write-Host

            $WESelectedDeviceTag = $WEManagedAppReg | ? { $_.deviceName -eq " $WESelection" } | sort -Unique | select -ExpandProperty deviceTag

            $uri = " https://graph.microsoft.com/beta/users('$WEUserID')/wipeManagedAppRegistrationByDeviceTag"
; 
$WEJSON = @"

    {
        " deviceTag" : " $WESelectedDeviceTag"
    }

" @

                write-host " Are you sure you want to wipe application data on this device? Y or N?" -ForegroundColor Yellow
               ;  $WEConfirm = read-host

                if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"

                }

                else {

                Write-Host
                Write-WELog " Wipe application data for this device was cancelled..." " INFO"
                Write-Host

                }

            }

            else {

            Write-WELog " No device selected..." " INFO" -ForegroundColor Red

            }

        Write-Host

        }

    }



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================