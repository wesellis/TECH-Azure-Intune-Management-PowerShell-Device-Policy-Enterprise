<#
.SYNOPSIS
    Win10 Primaryuser Delete

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
    We Enhanced Win10 Primaryuser Delete

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



function WE-Get-Win10IntuneManagedDevices {

<#
.SYNOPSIS
This gets information on Intune managed devices
.DESCRIPTION
This gets information on Intune managed devices
.EXAMPLE
Get-Win10IntuneManagedDevices
.NOTES
NAME: Get-Win10IntuneManagedDevices


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
	; 	$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
	; 	$responseBody = $reader.ReadToEnd();
		Write-WELog " Response content:`n$responseBody" " INFO" -f Red
		Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw " Get-IntuneManagedDevices error"
	}

}



function WE-Get-IntuneDevicePrimaryUser {

<#
.SYNOPSIS
This lists the Intune device primary user
.DESCRIPTION
This lists the Intune device primary user
.EXAMPLE
Get-IntuneDevicePrimaryUser
.NOTES
NAME: Get-IntuneDevicePrimaryUser


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
	; 	$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
	; 	$responseBody = $reader.ReadToEnd();
		Write-WELog " Response content:`n$responseBody" " INFO" -f Red
		Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw " Get-IntuneDevicePrimaryUser error"
	}
}



function WE-Delete-IntuneDevicePrimaryUser {

<#
.SYNOPSIS
This deletes the Intune device primary user
.DESCRIPTION
This deletes the Intune device primary user
.EXAMPLE
Delete-IntuneDevicePrimaryUser
.NOTES
NAME: Delete-IntuneDevicePrimaryUser


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
$WEIntuneDeviceId
)
    
    $graphApiVersion = " beta"
    $WEResource = " deviceManagement/managedDevices('$WEIntuneDeviceId')/users/`$ref"

    try {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"

        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete

	}

    catch {

		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
	; 	$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
	; 	$responseBody = $reader.ReadToEnd();
		Write-WELog " Response content:`n$responseBody" " INFO" -f Red
		Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw " Delete-IntuneDevicePrimaryUser error"
	
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

    if($WEUser -eq $null -or $WEUser -eq "" ) {
        $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
        Write-Host
    }

    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $WEUser
}





if(!$WEDeviceName){

    Write-Host
    write-host " Intune Device Name:" -f Yellow
    $WEDeviceName = Read-Host

}

$WEDevice = Get-Win10IntuneManagedDevices -deviceName " $WEDeviceName"

if($WEDevice){

    Write-Host
    Write-WELog " Device name:" " INFO" $device." deviceName" -ForegroundColor Cyan
   ;  $WEIntuneDevicePrimaryUser = Get-IntuneDevicePrimaryUser -deviceId $WEDevice.id

    Write-WELog " Intune Device Primary User:" " INFO" $WEIntuneDevicePrimaryUser

   ;  $WEDeleteIntuneDevicePrimaryUser = Delete-IntuneDevicePrimaryUser -IntuneDeviceId $WEDevice.id

    if($WEDeleteIntuneDevicePrimaryUser -eq "" ){

        Write-WELog " User deleted as Primary User from the device '$WEDeviceName'..." " INFO" -ForegroundColor Green

    }

}

else {

    Write-WELog " Intune Device '$WEDeviceName' can't be found..." " INFO" -ForegroundColor Red

}

Write-Host



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================