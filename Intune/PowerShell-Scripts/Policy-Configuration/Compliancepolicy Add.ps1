<#
.SYNOPSIS
    Compliancepolicy Add

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
    We Enhanced Compliancepolicy Add

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



Function Test-JSON(){

<#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $WEJSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-JSON




[CmdletBinding()]
function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
        [ValidateSet(" INFO" , " WARN" , " ERROR" , " SUCCESS" )]
        [string]$Level = " INFO"
    )
    
   ;  $timestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
   ;  $colorMap = @{
        " INFO" = " Cyan" ; " WARN" = " Yellow" ; " ERROR" = " Red" ; " SUCCESS" = " Green"
    }
    
    $logEntry = " $timestamp [WE-Enhanced] [$Level] $Message"
    Write-Information $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
$WEJSON

)

    try {

    $WETestJSON = ConvertFrom-Json $WEJSON -ErrorAction Stop
    $validJson = $true

    }

    catch {

    $validJson = $false
    $_.Exception

    }

    if (!$validJson){

    Write-WELog " Provided JSON isn't in valid JSON format" " INFO" -f Red
    break

    }

}



Function Add-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to add a device compliance policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device compliance policy
.EXAMPLE
Add-DeviceCompliancePolicy -JSON $WEJSON
Adds an Android device compliance policy in Intune
.NOTES
NAME: Add-DeviceCompliancePolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEJSON
)

$graphApiVersion = " v1.0"
$WEResource = " deviceManagement/deviceCompliancePolicies"

    try {

        if($WEJSON -eq "" -or $null -eq $WEJSON){

        Write-Information " No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $WEJSON

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"

        }

    }

    catch {

    Write-Information $ex = $_.Exception
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
$WEJSON_Android = @"

    {
    " passwordExpirationDays" : null,
    " requireAppVerify" :  true,
    " securityPreventInstallAppsFromUnknownSources" :  true,
    " @odata.type" :  " microsoft.graph.androidCompliancePolicy" ,
    " scheduledActionsForRule" :[{" ruleName" :" PasswordRequired" ," scheduledActionConfigurations" :[{" actionType" :" block" ," gracePeriodHours" :0," notificationTemplateId" :"" }]}],
    " passwordRequiredType" :  " numeric" ,
    " storageRequireEncryption" :  true,
    " storageRequireRemovableStorageEncryption" :  true,
    " passwordMinutesOfInactivityBeforeLock" :  15,
    " passwordPreviousPasswordBlockCount" :  null,
    " passwordRequired" :  true,
    " description" :  " Android Compliance Policy" ,
    " passwordMinimumLength" :  4,
    " displayName" :  " Android Compliance Policy" ,
    " securityBlockJailbrokenDevices" :  true,
    " deviceThreatProtectionRequiredSecurityLevel" :  " low" ,
    " deviceThreatProtectionEnabled" :  true,
    " securityDisableUsbDebugging" :  true
    }

" @


; 
$WEJSON_iOS = @"

  {
  " @odata.type" : " microsoft.graph.iosCompliancePolicy" ,
  " description" : " iOS Compliance Policy" ,
  " displayName" : " iOS Compliance Policy" ,
  " scheduledActionsForRule" :[{" ruleName" :" PasswordRequired" ," scheduledActionConfigurations" :[{" actionType" :" block" ," gracePeriodHours" :0," notificationTemplateId" :"" }]}],
  " passcodeBlockSimple" : true,
  " passcodeExpirationDays" : null,
  " passcodeMinimumLength" : 4,
  " passcodeMinutesOfInactivityBeforeLock" : 15,
  " passcodePreviousPasscodeBlockCount" : null,
  " passcodeMinimumCharacterSetCount" : null,
  " passcodeRequiredType" : " numeric" ,
  " passcodeRequired" : true,
  " securityBlockJailbrokenDevices" : true,
  " deviceThreatProtectionEnabled" : true,
  " deviceThreatProtectionRequiredSecurityLevel" : " low"
  }

" @



Write-WELog " Adding Android Compliance Policy from JSON..." " INFO" -ForegroundColor Yellow

Add-DeviceCompliancePolicy -JSON $WEJSON_Android

Write-WELog " Adding iOS Compliance Policy from JSON..." " INFO" -ForegroundColor Yellow
Write-Information Add-DeviceCompliancePolicy -JSON $WEJSON_iOS



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================