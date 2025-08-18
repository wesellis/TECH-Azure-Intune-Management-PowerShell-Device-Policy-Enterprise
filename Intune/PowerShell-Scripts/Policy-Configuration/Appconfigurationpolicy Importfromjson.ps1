<#
.SYNOPSIS
    Appconfigurationpolicy Importfromjson

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
    We Enhanced Appconfigurationpolicy Importfromjson

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
        Write-Host
        Write-WELog " AzureAD Powershell module not installed..." " INFO" -f Red
        Write-WELog " Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" " INFO" -f Yellow
        Write-WELog " Script can't continue..." " INFO" -f Red
        Write-Host
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

    Write-Host $_.Exception.Message -f Red
    Write-Host $_.Exception.ItemName -f Red
    Write-Host
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



Function Test-AppBundleId(){

<#
.SYNOPSIS
This function is used to test whether an app bundle ID is present in the client apps from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and checks whether the app bundle ID has been added to the client apps
.EXAMPLE
Test-AppBundleId -bundleId 
Returns the targetedMobileApp GUID for the specified app GUID in Intune
.NOTES
NAME: Test-AppBundleId




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
$bundleId

)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileApps?`$filter=(microsoft.graph.managedApp/appAvailability eq null or microsoft.graph.managedApp/appAvailability eq 'lineOfBusiness' or isAssigned eq true) and (isof('microsoft.graph.iosLobApp') or isof('microsoft.graph.iosStoreApp') or isof('microsoft.graph.iosVppApp') or isof('microsoft.graph.managedIOSStoreApp') or isof('microsoft.graph.managedIOSLobApp'))"

   try {
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        $mobileApps = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
             
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
    Write-Host
    break

    }

    $app = $mobileApps.value | where {$_.bundleId -eq $bundleId}
    
    If($app){
    
        return $app.id

    }
    
    Else{

        return $false

    }
       
}



Function Test-AppPackageId(){

<#
.SYNOPSIS
This function is used to test whether an app package ID is present in the client apps from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and checks whether the app package ID has been added to the client apps
.EXAMPLE
Test-AppPackageId -packageId 
Returns the targetedMobileApp GUID for the specified app GUID in Intune
.NOTES
NAME: Test-AppPackageId




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
$packageId

)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.androidForWorkApp') or microsoft.graph.androidManagedStoreApp/supportsOemConfig eq false)"

   try {
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        $mobileApps = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        
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
    Write-Host
    break

    }

    $app = $mobileApps.value | where {$_.packageId -eq $packageId}
    
    If($app){
    
        return $app.id

    }
    
    Else{

        return $false

    }

}



Function Add-ManagedAppAppConfigPolicy(){

<#
.SYNOPSIS
This function is used to add an app configuration policy for managed apps using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an app configuration policy for managed apps
.EXAMPLE
Add-ManagedAppAppConfiguPolicy -JSON $WEJSON
.NOTES
NAME: Add-ManagedAppAppConfigPolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEJSON
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/targetedManagedAppConfigurations"
    
    try {

        if($WEJSON -eq "" -or $WEJSON -eq $null){

        Write-WELog " No JSON specified, please specify valid JSON for the App Configuration Policy..." " INFO" -f Red

        }

        else {

        Test-JSON -JSON $WEJSON

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"

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
    Write-Host
    break

    }

}



Function Add-ManagedDeviceAppConfigPolicy(){

<#
.SYNOPSIS
This function is used to add an app configuration policy for managed devices using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an app configuration policy for managed devices
.EXAMPLE
Add-ManagedDeviceAppConfiguPolicy -JSON $WEJSON
.NOTES
NAME: Add-ManagedDeviceAppConfigPolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEJSON
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileAppConfigurations"
    
    try {

        if($WEJSON -eq "" -or $WEJSON -eq $null){

        Write-WELog " No JSON specified, please specify valid JSON for the App Configuration Policy..." " INFO" -f Red

        }

        else {

        Test-JSON -JSON $WEJSON

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"

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
    Write-Host
    break

    }

}





Write-Host


if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        Write-WELog " Authentication Token expired" " INFO" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        Write-Host

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





$WEImportPath = Read-Host -Prompt " Please specify a path to a JSON file to import data from e.g. C:\IntuneOutput\Policies\policy.json"


$WEImportPath = $WEImportPath.replace('" ','')

if(!(Test-Path " $WEImportPath" )){

Write-WELog " Import Path for JSON file doesn't exist..." " INFO" -ForegroundColor Red
Write-WELog " Script can't continue..." " INFO" -ForegroundColor Red
Write-Host
break

}

$WEJSON_Data = gc " $WEImportPath"


$WEJSON_Convert = $WEJSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,isAssigned,roleScopeTagIds

$WEDisplayName = $WEJSON_Convert.displayName

Write-Host
Write-WELog " App Configuration Policy '$WEDisplayName' Found..." " INFO" -ForegroundColor Yellow



If(($WEJSON_Convert.'@odata.type' -eq " #microsoft.graph.iosMobileAppConfiguration" ) -or ($WEJSON_Convert.'@odata.type' -eq " #microsoft.graph.androidManagedStoreAppConfiguration" )){

    Write-WELog " App Configuration JSON is for Managed Devices" " INFO" -ForegroundColor Yellow

    If($WEJSON_Convert.'@odata.type' -eq " #microsoft.graph.iosMobileAppConfiguration" ){

        # Check if the client app is present 
        $targetedMobileApp = Test-AppBundleId -bundleId $WEJSON_Convert.bundleId
           
        If($targetedMobileApp){

            Write-Host
            Write-WELog " Targeted app $($WEJSON_Convert.bundleId) has already been added from the App Store" " INFO" -ForegroundColor Yellow
            Write-WELog " The App Configuration Policy will be created" " INFO" -ForegroundColor Yellow
            Write-Host

            # Update the targetedMobileApps GUID if required
            If(!($targetedMobileApp -eq $WEJSON_Convert.targetedMobileApps)){

                $WEJSON_Convert.targetedMobileApps.SetValue($targetedMobileApp,0)

            }

            $WEJSON_Output = $WEJSON_Convert | ConvertTo-Json -Depth 5
            $WEJSON_Output
            Write-Host
            Write-WELog " Adding App Configuration Policy '$WEDisplayName'" " INFO" -ForegroundColor Yellow
            Add-ManagedDeviceAppConfigPolicy -JSON $WEJSON_Output

        }

        Else
        {

            Write-Host
            Write-WELog " Targeted app bundle id '$($WEJSON_Convert.bundleId)' has not been added from the App Store" " INFO" -ForegroundColor Red
            Write-WELog " The App Configuration Policy can't be created" " INFO" -ForegroundColor Red

        }


    }

    ElseIf($WEJSON_Convert.'@odata.type' -eq " #microsoft.graph.androidManagedStoreAppConfiguration" ){

        # Check if the client app is present 
        $targetedMobileApp = Test-AppPackageId -packageId $WEJSON_Convert.packageId
        
        If($targetedMobileApp){

            Write-Host
            Write-WELog " Targeted app $($WEJSON_Convert.packageId) has already been added from Managed Google Play" " INFO" -ForegroundColor Yellow
            Write-WELog " The App Configuration Policy will be created" " INFO" -ForegroundColor Yellow
            Write-Host
            
            # Update the targetedMobileApps GUID if required           
            If(!($targetedMobileApp -eq $WEJSON_Convert.targetedMobileApps)){
               
                $WEJSON_Convert.targetedMobileApps.SetValue($targetedMobileApp,0)

            }

           ;  $WEJSON_Output = $WEJSON_Convert | ConvertTo-Json -Depth 5
            $WEJSON_Output
            Write-Host   
            Write-WELog " Adding App Configuration Policy '$WEDisplayName'" " INFO" -ForegroundColor Yellow                                                      
            Add-ManagedDeviceAppConfigPolicy -JSON $WEJSON_Output

        }

        Else
        {

            Write-Host
            Write-WELog " Targeted app package id '$($WEJSON_Convert.packageId)' has not been added from Managed Google Play" " INFO" -ForegroundColor Red
            Write-WELog " The App Configuration Policy can't be created" " INFO" -ForegroundColor Red

        }
    
    }

}

Else
{

    Write-WELog " App Configuration JSON is for Managed Apps" " INFO" -ForegroundColor Yellow
   ;  $WEJSON_Output = $WEJSON_Convert | ConvertTo-Json -Depth 5
    $WEJSON_Output
    Write-Host
    Write-WELog " Adding App Configuration Policy '$WEDisplayName'" " INFO" -ForegroundColor Yellow
    Add-ManagedAppAppConfigPolicy -JSON $WEJSON_Output   

}
 







# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================