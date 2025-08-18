<#
.SYNOPSIS
    Win10 Primaryuser Get

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
    We Enhanced Win10 Primaryuser Get

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
[parameter(Mandatory=$false)]
$WEDeviceName

)



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



[CmdletBinding()]
function WE-Get-Win10IntuneManagedDevice -ErrorAction Stop {

<#
.SYNOPSIS
This gets information on Intune managed device
.DESCRIPTION
This gets information on Intune managed device
.EXAMPLE
Get-Win10IntuneManagedDevice -ErrorAction Stop
.NOTES
NAME: Get-Win10IntuneManagedDevice -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
[parameter(Mandatory=$false)]
[ValidateNotNullOrEmpty()]
[string]$deviceName
)
    
    $graphApiVersion = " beta"

    try {

        if($deviceName){

            $WEResource = " deviceManagement/managedDevices?`$filter=deviceName eq '$deviceName'"
	        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)" 

            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value

        }

        else {

            $WEResource = " deviceManagement/managedDevices?`$filter=(((deviceType%20eq%20%27desktop%27)%20or%20(deviceType%20eq%20%27windowsRT%27)%20or%20(deviceType%20eq%20%27winEmbedded%27)%20or%20(deviceType%20eq%20%27surfaceHub%27)))"
	        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value

        }

	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
	; 	$reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
	; 	$responseBody = $reader.ReadToEnd();
		Write-WELog " Response content:`n$responseBody" " INFO" -f Red
		Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw " Get-IntuneManagedDevices -ErrorAction Stop error"
	}

}



[CmdletBinding()]
function WE-Get-AADDeviceId -ErrorAction Stop {

<#
.SYNOPSIS
This gets an AAD device object id from the Intune AAD device id
.DESCRIPTION
This gets an AAD device object id from the Intune AAD device id
.EXAMPLE
Get-AADDeviceId -ErrorAction Stop
.NOTES
NAME: Get-AADDeviceId -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    [string] $deviceId
)
    $graphApiVersion = " beta"
    $WEResource = " devices"
	$uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)?`$filter=deviceId eq '$deviceId'"

    try {
        $device = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        return $device.value." id"

	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
	; 	$reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
	; 	$responseBody = $reader.ReadToEnd();
		Write-WELog " Response content:`n$responseBody" " INFO" -f Red
		Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw " Get-AADDeviceId -ErrorAction Stop error"
	}
}



[CmdletBinding()]
function WE-Get-IntuneDevicePrimaryUser -ErrorAction Stop {

<#
.SYNOPSIS
This lists the Intune device primary user
.DESCRIPTION
This lists the Intune device primary user
.EXAMPLE
Get-IntuneDevicePrimaryUser -ErrorAction Stop
.NOTES
NAME: Get-IntuneDevicePrimaryUser -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    [string] $deviceId
)
    
    $graphApiVersion = " beta"
    $WEResource = " deviceManagement/managedDevices"
	$uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)" + " /" + $deviceId + " /users"

    try {
        
        $primaryUser = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        return $primaryUser.value." id"
        
	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
	; 	$reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
	; 	$responseBody = $reader.ReadToEnd();
		Write-WELog " Response content:`n$responseBody" " INFO" -f Red
		Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw " Get-IntuneDevicePrimaryUser -ErrorAction Stop error"
	}
}



[CmdletBinding()]
function WE-Get-AADDevicesRegisteredOwners -ErrorAction Stop {

<#
.SYNOPSIS
This lists the AAD devices registered owners
.DESCRIPTION
List of AAD device registered owners
.EXAMPLE
Get-AADDevicesRegisteredOwners -ErrorAction Stop
.NOTES
NAME: Get-AADDevicesRegisteredOwners -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    [string] $deviceId
)
    $graphApiVersion = " beta"
    $WEResource = " devices"
; 	$uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)/$deviceId/registeredOwners"

    try {
        
       ;  $registeredOwners = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        Write-WELog " AAD Registered Owner:" " INFO" -ForegroundColor Yellow

        if(@($registeredOwners.value).count -ge 1){

            for($i=0; $i -lt $registeredOwners.value.Count; $i++){
            
                Write-WELog " Id:" " INFO" $registeredOwners.value[$i]." id"
                Write-WELog " Name:" " INFO" $registeredOwners.value[$i]." displayName"
            
            }

        }

        else {

            Write-WELog " No registered Owner found in Azure Active Directory..." " INFO" -ForegroundColor Red
        
        }

	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
	; 	$reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
	; 	$responseBody = $reader.ReadToEnd();
		Write-WELog " Response content:`n$responseBody" " INFO" -f Red
		Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw " Get-AADDevicesRegisteredOwners -ErrorAction Stop error"
	}
}



[CmdletBinding()]
function WE-Get-AADDevicesRegisteredUsers -ErrorAction Stop {

<#
.SYNOPSIS
This lists the AAD devices registered users
.DESCRIPTION
List of AAD device registered users
.EXAMPLE
Get-AADDevicesRegisteredUsers -ErrorAction Stop
.NOTES
NAME: Get-AADDevicesRegisteredUsers -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    [string] $deviceId
)
    $graphApiVersion = " beta"
    $WEResource = " devices"
; 	$uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)" + " /$deviceId/registeredUsers"

    try {
       ;  $registeredUsers = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        Write-WELog " RegisteredUsers:" " INFO" -ForegroundColor Yellow

        if(@($registeredUsers.value).count -ge 1){

            for($i=0; $i -lt $registeredUsers.value.Count; $i++)
            {

                Write-WELog " Id:" " INFO" $registeredUsers.value[$i]." id"
                Write-WELog " Name:" " INFO" $registeredUsers.value[$i]." displayName"
            }

        }

        else {

            Write-WELog " No registered User found in Azure Active Directory..." " INFO" -ForegroundColor Red
        
        }

	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
	; 	$reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
	; 	$responseBody = $reader.ReadToEnd();
		Write-WELog " Response content:`n$responseBody" " INFO" -f Red
		Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw " Get-AADDevicesRegisteredUsers -ErrorAction Stop error"
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

    if($null -eq $WEUser -or $WEUser -eq "" ) {
        $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
        Write-Information }

    # Getting the authorization token
    $script:authToken = Get-AuthToken -User $WEUser
}





if($WEDeviceName){

    $WEDevices = Get-Win10IntuneManagedDevice -deviceName $WEDeviceName

}

else {

    $WEDevices = Get-Win10IntuneManagedDevice -ErrorAction Stop

}



if($WEDevices){

    foreach($device in $WEDevices){

            Write-Information Write-WELog " Device name:" " INFO" $device." deviceName"
            Write-WELog " Intune device id:" " INFO" $device." id"
            
           ;  $WEIntuneDevicePrimaryUser = Get-IntuneDevicePrimaryUser -deviceId $device.id

            if($null -eq $WEIntuneDevicePrimaryUser){

                Write-WELog " No Intune Primary User Id set for Intune Managed Device" " INFO" $WEDevice." deviceName" -f Red 

            }

            else {

                Write-WELog " Intune Primary user id:" " INFO" $WEIntuneDevicePrimaryUser

            }

           ;  $aadDeviceId = Get-AADDeviceId -deviceId $device." azureActiveDirectoryDeviceId"
            Write-Information Get-AADDevicesRegisteredOwners -deviceId $aadDeviceId
            Write-Information Get-AADDevicesRegisteredUsers -deviceId $aadDeviceId

            Write-Information Write-WELog " -------------------------------------------------------------------" " INFO"
    
    }

}

else {

    Write-WELog " No Windows 10 devices found..." " INFO" -ForegroundColor Red

}

Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================