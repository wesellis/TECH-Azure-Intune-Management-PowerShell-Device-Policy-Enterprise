<#
.SYNOPSIS
    Managedapppolicy Mobileappidentifier Get

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
    We Enhanced Managedapppolicy Mobileappidentifier Get

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



Function Get-IntuneMAMApplication(){

<#
.SYNOPSIS
This function is used to get MAM applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any MAM applications
.EXAMPLE
Get-IntuneMAMApplication -Android
Returns any Android MAM applications configured in Intune
Get-IntuneMAMApplication -iOS
Returns any iOS MAM applications configured in Intune
Get-IntuneMAMApplication -ErrorAction Stop
Returns all MAM applications configured in Intune
.NOTES
NAME: Get-IntuneMAMApplication -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
[switch]$WEAndroid,
[switch]$iOS
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileApps"

    try {

        $WECount_Params = 0

        if($WEAndroid.IsPresent){ $WECount_Params++ }
        if($iOS.IsPresent){ $WECount_Params++ }

        if($WECount_Params -gt 1){

        Write-Information " Multiple parameters set, specify a single parameter -Android or -iOS against the function" -f Red
        Write-Information }
        
        elseif($WEAndroid){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains(" managedAndroidStoreApp" ) }

        }

        elseif($iOS){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains(" managedIOSStoreApp" ) }

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains(" managed" ) }

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




; 
$WEAPP_iOS = Get-IntuneMAMApplication -iOS | Sort-Object displayName
; 
$WEAPP_Android = Get-IntuneMAMApplication -Android | Sort-Object displayName

Write-WELog " Managed iOS Store Applications" " INFO" -f Yellow
Write-Information $WEAPP_iOS | ForEach-Object {

    Write-WELog " DisplayName:" " INFO" $_.displayName -ForegroundColor Cyan
    $_.'@odata.type'
    $_.bundleId
    Write-Information }



Write-WELog " Managed Android Store Applications" " INFO" -f Yellow
Write-Information $WEAPP_Android | ForEach-Object {

    Write-WELog " DisplayName:" " INFO" $_.displayName -ForegroundColor Cyan
    $_.'@odata.type'
    $_.packageId
    Write-Information }

Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================