<#
.SYNOPSIS
    Manageddevices Deviceownership Set

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
    We Enhanced Manageddevices Deviceownership Set

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



Function Get-ManagedDevices(){

<#
.SYNOPSIS
This function is used to get Intune Managed Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Intune Managed Device
.EXAMPLE
Get-ManagedDevices -ErrorAction Stop
Returns all managed devices but excludes EAS devices registered within the Intune Service
.EXAMPLE
Get-ManagedDevices -IncludeEAS
Returns all managed devices including EAS devices registered within the Intune Service
.NOTES
NAME: Get-ManagedDevices -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [switch]$WEIncludeEAS,
    [switch]$WEExcludeMDM
)


$graphApiVersion = " beta"
$WEResource = " deviceManagement/managedDevices"

try {

    $WECount_Params = 0

    if($WEIncludeEAS.IsPresent){ $WECount_Params++ }
    if($WEExcludeMDM.IsPresent){ $WECount_Params++ }
        
        if($WECount_Params -gt 1){

        write-warning " Multiple parameters set, specify a single parameter -IncludeEAS, -ExcludeMDM or no parameter against the function"
        Write-Information break

        }
        
        elseif($WEIncludeEAS){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource"

        }

        elseif($WEExcludeMDM){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource`?`$filter=managementAgent eq 'eas'"

        }
        
        else {
    
        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource`?`$filter=managementAgent eq 'mdm' and managementAgent eq 'easmdm'"
        Write-Warning " EAS Devices are excluded by default, please use -IncludeEAS if you want to include those devices"
        Write-Information }

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



Function Set-ManagedDevice(){

<#
.SYNOPSIS
This function is used to set Managed Device property from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets a Managed Device property
.EXAMPLE
Set-ManagedDevice -id $id -ownerType company
Returns Managed Devices configured in Intune
.NOTES
NAME: Set-ManagedDevice -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $id,
    $ownertype
)


$graphApiVersion = " Beta"
$WEResource = " deviceManagement/managedDevices"

    try {

        if($id -eq "" -or $null -eq $id){

        Write-Information " No Device id specified, please provide a device id..." -f Red
        break

        }
        
        if($ownerType -eq "" -or $null -eq $ownerType){

            Write-Information " No ownerType parameter specified, please provide an ownerType. Supported value personal or company..." -f Red
            Write-Information break

            }

        elseif($ownerType -eq " company" ){

$WEJSON = @"

{
    ownerType:" company"
}

" @

                Write-Information Write-Information " Are you sure you want to change the device ownership to 'company' on this device? Y or N?"
                $WEConfirm = read-host

                if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){
            
                # Send Patch command to Graph to change the ownertype
                $uri = " https://graph.microsoft.com/beta/deviceManagement/managedDevices('$WEID')"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $WEJson -ContentType " application/json"

                }

                else {

                Write-WELog " Change of Device Ownership for the device $WEID was cancelled..." " INFO" -ForegroundColor Yellow
                Write-Information }
            
            }

        elseif($ownerType -eq " personal" ){

$WEJSON = @"

{
    ownerType:" personal"
}

" @

                Write-Information Write-Information " Are you sure you want to change the device ownership to 'personal' on this device? Y or N?"
                $WEConfirm = read-host

                if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){
            
                # Send Patch command to Graph to change the ownertype
                $uri = " https://graph.microsoft.com/beta/deviceManagement/managedDevices('$WEID')"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $WEJson -ContentType " application/json"

                }

                else {

                Write-WELog " Change of Device Ownership for the device $WEID was cancelled..." " INFO" -ForegroundColor Yellow
                Write-Information }

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

   ;  $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Information }


$script:authToken = Get-AuthToken -User $WEUser

}





; 
$WEManagedDevice = Get-ManagedDevices -ErrorAction Stop | Where-Object { $_.deviceName -eq " IPADMINI4" }

if($WEManagedDevice){

    if(@($WEManagedDevice.count) -gt 1){

    Write-WELog " More than 1 device was found, script supports single deviceID..." " INFO" -ForegroundColor Red
    Write-Information break

    }

    else {

    Write-Information " Device Name:" $WEManagedDevice.deviceName -ForegroundColor Cyan
    Write-Information " Management State:" $WEManagedDevice.managementState
    Write-Information " Operating System:" $WEManagedDevice.operatingSystem
    Write-Information " Device Type:" $WEManagedDevice.deviceType
    Write-Information " Last Sync Date Time:" $WEManagedDevice.lastSyncDateTime
    Write-Information " Jail Broken:" $WEManagedDevice.jailBroken
    Write-Information " Compliance State:" $WEManagedDevice.complianceState
    Write-Information " Enrollment Type:" $WEManagedDevice.enrollmentType
    Write-Information " AAD Registered:" $WEManagedDevice.aadRegistered
    Write-Information " Management Agent:" $WEManagedDevice.managementAgent
    Write-WELog " User Principal Name:" " INFO" $WEManagedDevice.userPrincipalName
    Write-WELog " Owner Type:" " INFO" $WEManagedDevice.ownerType -ForegroundColor Yellow

    Set-ManagedDevice -id $WEManagedDevice.id -ownertype personal

    }

}

else {

Write-WELog " No Managed Device found..." " INFO" -ForegroundColor Red
Write-Information }



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================