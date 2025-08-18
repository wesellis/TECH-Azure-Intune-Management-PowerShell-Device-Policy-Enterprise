<#
.SYNOPSIS
    Get Androiddedicateddeviceqrcode

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
    We Enhanced Get Androiddedicateddeviceqrcode

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



[CmdletBinding()]
Function Get-AndroidEnrollmentProfile -ErrorAction Stop {

<#
.SYNOPSIS
Gets Android Enterprise Enrollment Profile
.DESCRIPTION
Gets Android Enterprise Enrollment Profile
.EXAMPLE
Get-AndroidEnrollmentProfile -ErrorAction Stop
.NOTES
NAME: Get-AndroidEnrollmentProfile -ErrorAction Stop


$graphApiVersion = " Beta"
$WEResource = " deviceManagement/androidDeviceOwnerEnrollmentProfiles"
    
    try {
        
        $now = (Get-Date -Format s)    
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)?`$filter=tokenExpirationDateTime gt $($now)z"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).value
    
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



[CmdletBinding()]
Function Get-AndroidQRCode{

<#
.SYNOPSIS
Gets Android Device Owner Enrollment Profile QRCode Image
.DESCRIPTION
Gets Android Device Owner Enrollment Profile QRCode Image
.EXAMPLE
Get-AndroidQRCode -ErrorAction Stop
.NOTES
NAME: Get-AndroidQRCode -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
[parameter(Mandatory=$true)]
[string]$WEProfileid
)

$graphApiVersion = " Beta"

    try {
            
        $WEResource = " deviceManagement/androidDeviceOwnerEnrollmentProfiles/$($WEProfileid)?`$select=qrCodeImage"
        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get)
                    
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





$parent = [System.IO.Path]::GetTempPath()
[string] $name = [System.Guid]::NewGuid()
New-Item -ItemType Directory -Path (Join-Path $parent $name) | Out-Null
$WETempDirPath = " $parent$name"



$WEProfiles = Get-AndroidEnrollmentProfile -ErrorAction Stop

if($profiles){

$profilecount = @($profiles).count

    if(@($profiles).count -gt 1){

    Write-WELog " Corporate-owned dedicated device profiles found: $profilecount" " INFO"
    Write-Information ;  $WECOSUprofiles = $profiles.Displayname | Sort-Object -Unique

   ;  $menu = @{}

    for ($i=1;$i -le $WECOSUprofiles.count; $i++) 
    { Write-WELog " $i. $($WECOSUprofiles[$i-1])" " INFO" 
    $menu.Add($i,($WECOSUprofiles[$i-1]))}

    Write-Information $ans = Read-Host 'Choose a profile (numerical value)'

    if($ans -eq "" -or $null -eq $ans){

        Write-WELog " Corporate-owned dedicated device profile can't be null, please specify a valid Profile..." " INFO" -ForegroundColor Red
        Write-Information break

    }

    elseif(($ans -match " ^[\d\.]+$" ) -eq $true){

    $selection = $menu.Item([int]$ans)

    Write-Information if($selection){

            $WESelectedProfile = $profiles | ? { $_.DisplayName -eq " $WESelection" }

            $WESelectedProfileID = $WESelectedProfile | select -ExpandProperty id

            $WEProfileID = $WESelectedProfileID

            $WEProfileDisplayName = $WESelectedProfile.displayName

        }

        else {

            Write-WELog " Corporate-owned dedicated device profile selection invalid, please specify a valid Profile..." " INFO" -ForegroundColor Red
            Write-Information break

        }

    }

    else {

        Write-WELog " Corporate-owned dedicated device profile selection invalid, please specify a valid Profile..." " INFO" -ForegroundColor Red
        Write-Information break

    }

}

    elseif(@($profiles).count -eq 1){

        $WEProfileid = (Get-AndroidEnrollmentProfile).id
        $WEProfileDisplayName = (Get-AndroidEnrollmentProfile).displayname
    
        Write-WELog " Found a Corporate-owned dedicated devices profile '$WEProfileDisplayName'..." " INFO"
        Write-Information }

    else {

        Write-Information write-host " No enrollment profiles found!" -f Yellow
        break

    }

Write-Warning " You are about to export the QR code for the Dedicated Device Enrollment Profile '$WEProfileDisplayName'"
Write-Warning " Anyone with this QR code can Enrol a device into your tenant. Please ensure it is kept secure."
Write-Warning " If you accidentally share the QR code, you can immediately expire it in the Intune UI."
write-warning " Devices already enrolled will be unaffected."
Write-Information Write-WELog " Show token? [Y]es, [N]o" " INFO"

$WEFinalConfirmation = Read-Host

    if ($WEFinalConfirmation -ne " y" ){
    
        Write-WELog " Exiting..." " INFO"
        Write-Information break

    }

    else {

    Write-Information $WEQR = (Get-AndroidQRCode -Profileid $WEProfileID)
    
    $WEQRType = $WEQR.qrCodeImage.type
    $WEQRValue = $WEQR.qrCodeImage.value
 
    $imageType = $WEQRType.split(" /" )[1]
 
   ;  $filename = " $WETempDirPath\$WEProfileDisplayName.$imageType"

   ;  $bytes = [Convert]::FromBase64String($WEQRValue)
    [IO.File]::WriteAllBytes($filename, $bytes)

        if (Test-Path $filename){

            Write-WELog " Success: " " INFO" -NoNewline -ForegroundColor Green
            Write-Information " QR code exported to " -NoNewline
            Write-WELog " $filename" " INFO" -ForegroundColor Yellow
            Write-Information }

        else {
        
            Write-Information " Oops! Something went wrong!"
        
        }
       
    }

}

else {

    Write-WELog " No Corporate-owned dedicated device Profiles found..." " INFO" -ForegroundColor Yellow
    Write-Information }



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================