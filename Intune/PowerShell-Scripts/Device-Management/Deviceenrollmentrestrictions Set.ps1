<#
.SYNOPSIS
    Deviceenrollmentrestrictions Set

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
    We Enhanced Deviceenrollmentrestrictions Set

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



Function Get-DeviceEnrollmentConfigurations(){
    
<#
.SYNOPSIS
This function is used to get Deivce Enrollment Configurations from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets Device Enrollment Configurations
.EXAMPLE
Get-DeviceEnrollmentConfigurations
Returns Device Enrollment Configurations configured in Intune
.NOTES
NAME: Get-DeviceEnrollmentConfigurations

    
[cmdletbinding()]
    
$graphApiVersion = " Beta"
$WEResource = " deviceManagement/deviceEnrollmentConfigurations"
        
    try {
            
    $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
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


    
Function Set-DeviceEnrollmentConfiguration(){
    
<#
.SYNOPSIS
This function is used to set the Device Enrollment Configuration resource using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets the Device Enrollment Configuration Resource
.EXAMPLE
Set-DeviceEnrollmentConfiguration -DEC_Id $WEDEC_Id -JSON $WEJSON
Sets the Device Enrollment Configuration using Graph API
.NOTES
NAME: Set-DeviceEnrollmentConfiguration

    
[cmdletbinding()]
    
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEJSON,
    $WEDEC_Id
)
    
$graphApiVersion = " Beta"
$WEApp_resource = " deviceManagement/deviceEnrollmentConfigurations"
        
    try {
    
        if(!$WEJSON){
    
        write-host " No JSON was passed to the function, provide a JSON variable" -f Red
        break
    
        }
    
        elseif(!$WEDEC_Id){
    
        write-host " No Device Enrollment Configuration ID was passed to the function, provide a Device Enrollment Configuration ID" -f Red
        break
    
        }
    
        else {
    
        Test-JSON -JSON $WEJSON
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEApp_resource)/$WEDEC_Id"
        Invoke-RestMethod -Uri $uri -Method Patch -ContentType " application/json" -Body $WEJSON -Headers $authToken
    
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
NAME: Test-AuthHeader




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





$WEJSON = @"

{
    " @odata.type" :" #microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration" ,
    " displayName" :" All Users" ,
    " description" :" This is the default Device Type Restriction applied with the lowest priority to all users regardless of group membership." ,

    " androidRestriction" :{
    " platformBlocked" :false,
    " personalDeviceEnrollmentBlocked" :false,
    " osMinimumVersion" :"" ,
    " osMaximumVersion" :""
    },
    " androidForWorkRestriction" :{
    " platformBlocked" :false,
    " personalDeviceEnrollmentBlocked" :false,
    " osMinimumVersion" :null,
    " osMaximumVersion" :null
    },
    " iosRestriction" :{
    " platformBlocked" :false,
    " personalDeviceEnrollmentBlocked" :false,
    " osMinimumVersion" :"" ,
    " osMaximumVersion" :""
    },
    " macRestriction" :{
    " platformBlocked" :false,
    " personalDeviceEnrollmentBlocked" :false,
    " osMinimumVersion" :null,
    " osMaximumVersion" :null
    },
    " windowsRestriction" :{
    " platformBlocked" :false,
    " personalDeviceEnrollmentBlocked" :false,
    " osMinimumVersion" :"" ,
    " osMaximumVersion" :""
    },
    " windowsMobileRestriction" :{
    " platformBlocked" :false,
    " personalDeviceEnrollmentBlocked" :false,
    " osMinimumVersion" :"" ,
    " osMaximumVersion" :""
    }

}

" @


; 
$WEDeviceEnrollmentConfigurations = Get-DeviceEnrollmentConfigurations
; 
$WEPlatformRestrictions = ($WEDeviceEnrollmentConfigurations | Where-Object { ($_.id).contains(" DefaultPlatformRestrictions" ) }).id

Set-DeviceEnrollmentConfiguration -DEC_Id $WEPlatformRestrictions -JSON $WEJSON



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================