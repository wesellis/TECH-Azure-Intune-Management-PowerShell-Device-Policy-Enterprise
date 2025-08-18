<#
.SYNOPSIS
    Appledepprofile Assign

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
    We Enhanced Appledepprofile Assign

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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
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



Function Get-DEPOnboardingSettings {

<#
.SYNOPSIS
This function retrieves the DEP onboarding settings for your tenant. DEP Onboarding settings contain information such as Token ID, which is used to sync DEP and VPP
.DESCRIPTION
The function connects to the Graph API Interface and gets a retrieves the DEP onboarding settings.
.EXAMPLE
Get-DEPOnboardingSettings
Gets all DEP Onboarding Settings for each DEP token present in the tenant
.NOTES
NAME: Get-DEPOnboardingSettings

    
[cmdletbinding()]
    
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
[parameter(Mandatory=$false)]
[string]$tokenid
)
    
    $graphApiVersion = " beta"
    
        try {
    
                if ($tokenid){
                
                $WEResource = " deviceManagement/depOnboardingSettings/$tokenid/"
                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
                (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get)
                     
                }
    
                else {
                
                $WEResource = " deviceManagement/depOnboardingSettings/"
                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
                (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).value
                
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



Function Get-DEPProfiles(){

<#
.SYNOPSIS
This function is used to get a list of DEP profiles by DEP Token
.DESCRIPTION
The function connects to the Graph API Interface and gets a list of DEP profiles based on DEP token
.EXAMPLE
Get-DEPProfiles
Gets all DEP profiles
.NOTES
NAME: Get-DEPProfiles


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    $id
)

$graphApiVersion = " beta"
$WEResource = " deviceManagement/depOnboardingSettings/$id/enrollmentProfiles"

    try {

        $WESyncURI = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
        Invoke-RestMethod -Uri $WESyncURI -Headers $authToken -Method GET

    }

    catch {

    Write-Host
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



Function Assign-ProfileToDevice(){

<#
.SYNOPSIS
This function is used to assign a profile to given devices using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and assigns a profile to given devices
.EXAMPLE
Assign-ProfileToDevice
Assigns a profile to given devices in Intune
.NOTES
NAME: Assign-ProfileToDevice


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    $id,
    [Parameter(Mandatory=$true)]
    $WEDeviceSerialNumber,
    [Parameter(Mandatory=$true)]
    $WEProfileId
)

$graphApiVersion = " beta"
$WEResource = " deviceManagement/depOnboardingSettings/$id/enrollmentProfiles('$WEProfileId')/updateDeviceProfileAssignment"

    try {

        $WEDevicesArray = $WEDeviceSerialNumber -split " ,"

        $WEJSON = @{ " deviceIds" = $WEDevicesArray } | ConvertTo-Json

        Test-JSON -JSON $WEJSON

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"

        Write-WELog " Success: " " INFO" -f Green -NoNewline
        Write-WELog " Device assigned!" " INFO"
        Write-Host

    }

    catch {

        Write-Host
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







$tokens = (Get-DEPOnboardingSettings)

if($tokens){

$tokencount = @($tokens).count

Write-WELog " DEP tokens found: $tokencount" " INFO"
Write-Host

    if ($tokencount -gt 1){

    write-host " Listing DEP tokens..." -ForegroundColor Yellow
    Write-Host
   ;  $WEDEP_Tokens = $tokens.tokenName | Sort-Object -Unique

   ;  $menu = @{}

    for ($i=1;$i -le $WEDEP_Tokens.count; $i++) 
    { Write-WELog " $i. $($WEDEP_Tokens[$i-1])" " INFO" 
    $menu.Add($i,($WEDEP_Tokens[$i-1]))}

    Write-Host
    [int]$ans = Read-Host 'Select the token you wish you to use (numerical value)'
    $selection = $menu.Item($ans)
    Write-Host

        if ($selection){

        $WESelectedToken = $tokens | Where-Object { $_.TokenName -eq " $WESelection" }

        $WESelectedTokenId = $WESelectedToken | Select-Object -ExpandProperty id
        $id = $WESelectedTokenId

        }

    }

    elseif ($tokencount -eq 1) {

        $id = (Get-DEPOnboardingSettings).id
    
    }

}

else {
    
    Write-Warning " No DEP tokens found!"
    Write-Host
    break

}





$WEDeviceSerialNumber = Read-Host " Please enter device serial number"


$WEDeviceSerialNumber = $WEDeviceSerialNumber.replace(" " ,"" )

if(!($WEDeviceSerialNumber)){
    
    Write-WELog " Error: No serial number entered!" " INFO" -ForegroundColor Red
    Write-Host
    break
    
}

$graphApiVersion = " beta"
$WEResource = " deviceManagement/depOnboardingSettings/$($id)/importedAppleDeviceIdentities?`$filter=discoverySource eq 'deviceEnrollmentProgram' and contains(serialNumber,'$WEDeviceSerialNumber')"

$uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
$WESearchResult = (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).value

if (!($WESearchResult)){

    Write-warning " Can't find device $WEDeviceSerialNumber."
    Write-Host
    break

}



$WEProfiles = (Get-DEPProfiles -id $id).value

if($WEProfiles){
                
Write-Host
Write-WELog " Listing DEP Profiles..." " INFO" -ForegroundColor Yellow
Write-Host
; 
$enrollmentProfiles = $WEProfiles.displayname | Sort-Object -Unique
; 
$menu = @{}

for ($i=1;$i -le $enrollmentProfiles.count; $i++) 
{ Write-WELog " $i. $($enrollmentProfiles[$i-1])" " INFO" 
$menu.Add($i,($enrollmentProfiles[$i-1]))}

Write-Host
$ans = Read-Host 'Select the profile you wish to assign (numerical value)'

    # Checking if read-host of DEP Profile is an integer
    if(($ans -match " ^[\d\.]+$" ) -eq $true){

        $selection = $menu.Item([int]$ans)

    }

    if ($selection){
   
        $WESelectedProfile = $WEProfiles | Where-Object { $_.DisplayName -eq " $WESelection" }
       ;  $WESelectedProfileId = $WESelectedProfile | Select-Object -ExpandProperty id
       ;  $WEProfileID = $WESelectedProfileId

    }

    else {

        Write-Host
        Write-Warning " DEP Profile selection invalid. Exiting..."
        Write-Host
        break

    }

}

else {
    
    Write-Host
    Write-Warning " No DEP profiles found!"
    break

}



Assign-ProfileToDevice -id $id -DeviceSerialNumber $WEDeviceSerialNumber -ProfileId $WEProfileID



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================