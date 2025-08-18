<#
.SYNOPSIS
    Rbac Scopetags Deviceassign

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
    We Enhanced Rbac Scopetags Deviceassign

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



Function Get-RBACScopeTag(){

<#
.SYNOPSIS
This function is used to get scope tags using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets scope tags
.EXAMPLE
Get-RBACScopeTag -DisplayName " Test"
Gets a scope tag with display Name 'Test'
.NOTES
NAME: Get-RBACScopeTag -ErrorAction Stop


[cmdletbinding()]
    
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$false)]
    $WEDisplayName
)


$graphApiVersion = " beta"
$WEResource = " deviceManagement/roleScopeTags"

    try {

        if($WEDisplayName){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource`?`$filter=displayName eq '$WEDisplayName'"
            $WEResult = (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken).Value

        }

        else {

            $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource"
            $WEResult = (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken).Value

        }

    return $WEResult

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
    Write-Information throw
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
    [switch]$WEExcludeMDM,
    $WEDeviceName,
    $id
)


$graphApiVersion = " beta"
$WEResource = " deviceManagement/managedDevices"

try {

    $WECount_Params = 0

    if($WEIncludeEAS.IsPresent){ $WECount_Params++ }
    if($WEExcludeMDM.IsPresent){ $WECount_Params++ }
    if($WEDeviceName.IsPresent){ $WECount_Params++ }
    if($id.IsPresent){ $WECount_Params++ }
        
        if($WECount_Params -gt 1){

            write-warning " Multiple parameters set, specify a single parameter -IncludeEAS, -ExcludeMDM, -deviceName, -id or no parameter against the function"
            Write-Information break

        }
        
        elseif($WEIncludeEAS){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }

        elseif($WEExcludeMDM){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource`?`$filter=managementAgent eq 'eas'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }

        elseif($id){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource('$id')"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)

        }

        elseif($WEDeviceName){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource`?`$filter=deviceName eq '$WEDeviceName'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }
        
        else {
    
            $uri = " https://graph.microsoft.com/$graphApiVersion/$WEResource`?`$filter=managementAgent eq 'mdm' and managementAgent eq 'easmdm'"
            Write-Warning " EAS Devices are excluded by default, please use -IncludeEAS if you want to include those devices"
            Write-Information (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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



Function Update-ManagedDevices(){

<#
.SYNOPSIS
This function is used to add a device compliance policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device compliance policy
.EXAMPLE
Update-ManagedDevices -JSON $WEJSON
Adds an Android device compliance policy in Intune
.NOTES
NAME: Update-ManagedDevices


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $id,
    $WEScopeTags
)

$graphApiVersion = " beta"
$WEResource = " deviceManagement/managedDevices('$id')"

    try {

        if($WEScopeTags -eq "" -or $null -eq $WEScopeTags){

$WEJSON = @"

{
  " roleScopeTagIds" : []
}

" @
        }

        else {

            $object = New-Object -ErrorAction Stop –TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name 'roleScopeTagIds' -Value @($WEScopeTags)
            $WEJSON = $object | ConvertTo-Json

        }

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $WEJSON -ContentType " application/json"

        Start-Sleep -Milliseconds 100

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






if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        Write-Information " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        Write-Information # Defining User Principal Name if not present

            if($null -eq $WEUser -or $WEUser -eq "" ){

            $WEGlobal:User = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
            Write-Information }

        $script:authToken = Get-AuthToken -User $WEUser

        }
}



else {

    if($null -eq $WEUser -or $WEUser -eq "" ){

    Write-Information $WEGlobal:User = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Information }


$script:authToken = Get-AuthToken -User $WEUser

}







Write-Information ; 
$WEScopeTags = (Get-RBACScopeTag).displayName | sort

if($WEScopeTags){

Write-WELog " Please specify Scope Tag you want to assign:" " INFO" -ForegroundColor Yellow
; 
$menu = @{}

for ($i=1;$i -le $WEScopeTags.count; $i++) 
{ Write-WELog " $i. $($WEScopeTags[$i-1])" " INFO" 
$menu.Add($i,($WEScopeTags[$i-1]))}

Write-Information $ans = Read-Host 'Enter Scope Tag id (Numerical value)'

if($ans -eq "" -or $null -eq $ans){

    Write-WELog " Scope Tag can't be null, please specify a valid Scope Tag..." " INFO" -ForegroundColor Red
    Write-Information break

}

elseif(($ans -match " ^[\d\.]+$" ) -eq $true){

$selection = $menu.Item([int]$ans)

    if($selection){

        $WEScopeTagId = (Get-RBACScopeTag -ErrorAction Stop | ? { $_.displayName -eq " $selection" }).id

    }

    else {

        Write-WELog " Scope Tag selection invalid, please specify a valid Scope Tag..." " INFO" -ForegroundColor Red
        Write-Information break

    }

}

else {

    Write-WELog " Scope Tag not an integer, please specify a valid scope tag..." " INFO" -ForegroundColor Red
    Write-Information break

}

Write-Information }

else {

    Write-WELog " No Scope Tags created, script can't continue..." " INFO" -ForegroundColor Red
    Write-Information break

}





$WEDeviceName = " Intune Device Name"

$WEIntuneDevice = Get-ManagedDevices -DeviceName " $WEDeviceName"

if($WEIntuneDevice){

    if(@($WEIntuneDevice).count -eq 1){

    $WEMD = Get-ManagedDevices -id $WEIntuneDevice.id

    Write-Information " Are you sure you want to add scope tag '$selection' to '$WEDeviceName' (Y or N?)"
    $WEConfirm = read-host

        if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

        if($WEMD.roleScopeTagIds){

            if(!($WEMD.roleScopeTagIds).contains(" $WEScopeTagId" )){

                $WEST = @($WEMD.roleScopeTagIds) + @(" $WEScopeTagId" )

                $WEResult = Update-ManagedDevices -id $WEMD.id -ScopeTags $WEST

                if($WEResult -eq "" ){

                    Write-WELog " Managed Device '$WEDeviceName' patched with ScopeTag '$selection'..." " INFO" -ForegroundColor Green
                            
                }

            }

            else {

                Write-WELog " Scope Tag '$selection' already assigned to '$WEDeviceName'..." " INFO" -ForegroundColor Magenta

            }

        }

        else {

           ;  $WEST = @(" $WEScopeTagId" )

           ;  $WEResult = Update-ManagedDevices -id $WEMD.id -ScopeTags $WEST

            if($WEResult -eq "" ){

                Write-WELog " Managed Device '$WEDeviceName' patched with ScopeTag '$selection'..." " INFO" -ForegroundColor Green

            }

        }

        }

        else {

            Write-WELog " Addition of Scope Tag '$selection' to '$WEDeviceName' was cancelled..." " INFO"

        }

    }

    elseif(@($WEIntuneManagedDevice).count -gt 1){

        Write-WELog " More than one device found with name '$deviceName'..." " INFO" -ForegroundColor Red

    }

}

else {

    Write-WELog " No Intune Managed Device found with name '$deviceName'..." " INFO" -ForegroundColor Red

}

Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================