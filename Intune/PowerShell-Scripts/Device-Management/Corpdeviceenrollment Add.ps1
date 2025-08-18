<#
.SYNOPSIS
    Corpdeviceenrollment Add

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
    We Enhanced Corpdeviceenrollment Add

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



Function Add-CorporateDeviceIdentifiers(){

<#
.SYNOPSIS
This function is used to add a Corporate Device Identifier from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a Corporate Device Identifier
.EXAMPLE
Add-CorporateDeviceIdentifiers -IdentifierType imei -OverwriteImportedDeviceIdentities false -Identifier " 12345678901234" -Description " Device Information"
Adds a Corporate Device Identifier to Intune
.NOTES
NAME: Add-CorporateDeviceIdentifiers


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet(" imei" ," serialNumber" )]
    $WEIdentifierType,
    [Parameter(Mandatory=$true)]
    [ValidateSet(" false" ," true" )]
    $WEOverwriteImportedDeviceIdentities,
    [Parameter(Mandatory=$true)]
    $WEIdentifier,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WEDescription
)


$graphApiVersion = " beta"
$WEResource = " deviceManagement/importedDeviceIdentities/importDeviceIdentityList"

    try {

$WEJSON = @"

{
" overwriteImportedDeviceIdentities" : $WEOverwriteImportedDeviceIdentities,
" importedDeviceIdentities" : [ { 
" importedDeviceIdentifier" : " $WEIdentifier" ,
" importedDeviceIdentityType" : " $WEIdentifierType" ,
" description" : " $WEDescription" }
]
}

" @

        if($WEIdentifierType -eq " imei" ){

            if(($WEIdentifier -match " ^[0-9]+$" ) -and ($WEIdentifier.length -ge 15)){

                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
                (Invoke-RestMethod -Uri $uri -Method Post -ContentType " application/json" -Body $WEJSON -Headers $authToken).value

            }

            elseif($WEIdentifier -notmatch " ^[0-9]+$" -or ($WEIdentifier.length -lt 15)) {

                Write-WELog " Invalid Device Identifier '$WEIdentifier' parameter found for $WEIdentifierType Identity Type..." " INFO" -ForegroundColor Red

            }

        }

        if($WEIdentifierType -eq " serialNumber" ){

            if(($WEIdentifier -match " ^[a-zA-Z0-9]+$" ) -and (@($WEDescription).length -le 128)){

                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
                (Invoke-RestMethod -Uri $uri -Method Post -ContentType " application/json" -Body $WEJSON -Headers $authToken).value

            }

            elseif($WEIdentifier -notmatch " ^[a-zA-Z0-9]+$" ){

                Write-WELog " Invalid Device Identifier '$WEIdentifier' parameter found for $WEIdentifierType Identity Type..." " INFO" -ForegroundColor Red

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
    $line = $_.InvocationInfo.ScriptLineNumber
    $msg = $ex.message
    $WEErrorMessage = $WEErrorMessage + " $responseBody`n"
    $WEErrorMessage = $WEErrorMessage + " Exception: $msg on line $line"
    Write-Error $WEErrorMessage
    break

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

   ;  $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Information }


$script:authToken = Get-AuthToken -User $WEUser

}




; 
$WEStatus = Add-CorporateDeviceIdentifiers -IdentifierType imei -OverwriteImportedDeviceIdentities false -Identifier " 123456789012345" -Description " Test Device"

if($WEStatus.status -eq $true) {

    Write-WELog " Device" " INFO" $status.importedDeviceIdentifier " added to the Intune Service..." -ForegroundColor Green
    $WEStatus

}

elseif($WEStatus.status -eq $false) {

    Write-WELog " Device" " INFO" $status.importedDeviceIdentifier " import failed, the device identifier could have already been added to the service..." -ForegroundColor Red

}

Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================