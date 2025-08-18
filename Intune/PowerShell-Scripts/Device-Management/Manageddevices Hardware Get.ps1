<#
.SYNOPSIS
    Manageddevices Hardware Get

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
    We Enhanced Manageddevices Hardware Get

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

        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource`?`$filter=managementAgent eq 'mdm' and managementAgent eq 'easmdm' and managementAgent eq 'googleCloudDevicePolicyController'"
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





$WEExportPath = Read-Host -Prompt " Please specify a path to export Managed Devices hardware data to e.g. C:\IntuneOutput"

    # If the directory path doesn't exist prompt user to create the directory

    if(!(Test-Path " $WEExportPath" )){

    Write-Information Write-WELog " Path '$WEExportPath' doesn't exist, do you want to create this directory? Y or N?" " INFO"

    $WEConfirm = read-host

        if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

        new-item -ItemType Directory -Path " $WEExportPath" | Out-Null
        Write-Information }

        else {

        Write-WELog " Creation of directory path was cancelled..." " INFO" -ForegroundColor Red
        Write-Information break

        }

    }

Write-Information $WEDevices = Get-ManagedDevices -ErrorAction Stop

if($WEDevices){

    $WEResults = @()

    foreach($WEDevice in $WEDevices){

    $WEDeviceID = $WEDevice.id

    Write-WELog " Device found:" " INFO" $WEDevice.deviceName -ForegroundColor Yellow
    Write-Information $uri = " https://graph.microsoft.com/beta/deviceManagement/manageddevices('$WEDeviceID')?`$select=hardwareinformation,iccid,udid,ethernetMacAddress"

    $WEDeviceInfo = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)

    $WEDeviceNoHardware = $WEDevice | select * -ExcludeProperty hardwareInformation,deviceActionResults,userId,imei,manufacturer,model,isSupervised,isEncrypted,serialNumber,meid,subscriberCarrier,iccid,udid,ethernetMacAddress
    $WEHardwareExcludes = $WEDeviceInfo.hardwareInformation | select * -ExcludeProperty sharedDeviceCachedUsers,phoneNumber
    $WEOtherDeviceInfo = $WEDeviceInfo | select iccid,udid,ethernetMacAddress

        $WEObject = New-Object -ErrorAction Stop System.Object

            foreach($WEProperty in $WEDeviceNoHardware.psobject.Properties){

                $WEObject | Add-Member -MemberType NoteProperty -Name $WEProperty.Name -Value $WEProperty.Value

            }

            foreach($WEProperty in $WEHardwareExcludes.psobject.Properties){

                $WEObject | Add-Member -MemberType NoteProperty -Name $WEProperty.Name -Value $WEProperty.Value

            }

            foreach($WEProperty in $WEOtherDeviceInfo.psobject.Properties){

                $WEObject | Add-Member -MemberType NoteProperty -Name $WEProperty.Name -Value $WEProperty.Value

            }

        $WEResults = $WEResults + $WEObject

        $WEObject

    }

   ;  $WEDate = get-date -ErrorAction Stop

   ;  $WEOutput = " ManagedDeviceHardwareInfo_" + $WEDate.Day + " -" + $WEDate.Month + " -" + $WEDate.Year + " _" + $WEDate.Hour + " -" + $WEDate.Minute

    # Exporting Data to CSV file in provided directory
    $WEResults | Export-Csv " $WEExportPath\$WEOutput.csv" -NoTypeInformation
    Write-Information " CSV created in $WEExportPath\$WEOutput.csv..." -f cyan

}

else {

Write-Information " No Intune Managed Devices found..." -f green
Write-Information }



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================