<#
.SYNOPSIS
    Rbac Scopetags Policyunassign

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
    We Enhanced Rbac Scopetags Policyunassign

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
    


Function Get-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to get device compliance policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device compliance policies
.EXAMPLE
Get-DeviceCompliancePolicy
Returns any device compliance policies configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -Android
Returns any device compliance policies for Android configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -iOS
Returns any device compliance policies for iOS configured in Intune
.NOTES
NAME: Get-DeviceCompliancePolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEName,
    [switch]$WEAndroid,
    [switch]$iOS,
    [switch]$WEWin10,
    $id
)

$graphApiVersion = " Beta"
$WEResource = " deviceManagement/deviceCompliancePolicies"

    try {

        $WECount_Params = 0

        if($WEAndroid.IsPresent){ $WECount_Params++ }
        if($iOS.IsPresent){ $WECount_Params++ }
        if($WEWin10.IsPresent){ $WECount_Params++ }
        if($WEName.IsPresent){ $WECount_Params++ }

        if($WECount_Params -gt 1){

        write-host " Multiple parameters set, specify a single parameter -Android -iOS or -Win10 against the function" -f Red

        }

        elseif($WEAndroid){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" android" ) }

        }

        elseif($iOS){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" ios" ) }

        }

        elseif($WEWin10){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" windows10CompliancePolicy" ) }

        }

        elseif($WEName){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains(" $WEName" ) }

        }

        elseif($id){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)/$id`?`$expand=assignments,scheduledActionsForRule(`$expand=scheduledActionConfigurations)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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



Function Get-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to get device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device configuration policies
.EXAMPLE
Get-DeviceConfigurationPolicy
Returns any device configuration policies configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $name,
    $id
)

$graphApiVersion = " Beta"
$WEDCP_resource = " deviceManagement/deviceConfigurations"

    try {

        if($WEName){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains(" $WEName" ) }

        }

        elseif($id){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)/$id"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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



Function Update-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to update a device compliance policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and updates a device compliance policy
.EXAMPLE
Update-DeviceCompliancePolicy -id $WEPolicy.id -Type $WEType -ScopeTags " 1"
Updates a device configuration policy in Intune
.NOTES
NAME: Update-DeviceCompliancePolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    $id,
    [Parameter(Mandatory=$true)]
    $WEType,
    [Parameter(Mandatory=$true)]
    $WEScopeTags
)

$graphApiVersion = " beta"
$WEResource = " deviceManagement/deviceCompliancePolicies/$id"

    try {
     
        if($WEScopeTags -eq "" -or $WEScopeTags -eq $null){

$WEJSON = @"

{
  " @odata.type" : " $WEType" ,
  " roleScopeTagIds" : []
}

" @
        }

        else {

            $object = New-Object –TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value " $WEType"
            $object | Add-Member -MemberType NoteProperty -Name 'roleScopeTagIds' -Value @($WEScopeTags)
            $WEJSON = $object | ConvertTo-Json

        }

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $WEJSON -ContentType " application/json"

        Start-Sleep -Milliseconds 100

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



Function Update-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to update a device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and updates a device configuration policy
.EXAMPLE
Update-DeviceConfigurationPolicy -id $WEPolicy.id -Type $WEType -ScopeTags " 1"
Updates an device configuration policy in Intune
.NOTES
NAME: Update-DeviceConfigurationPolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    $id,
    [Parameter(Mandatory=$true)]
    $WEType,
    [Parameter(Mandatory=$true)]
    $WEScopeTags
)

$graphApiVersion = " beta"
$WEResource = " deviceManagement/deviceConfigurations/$id"

    try {
     
        if($WEScopeTags -eq "" -or $WEScopeTags -eq $null){

$WEJSON = @"

{
  " @odata.type" : " $WEType" ,
  " roleScopeTagIds" : []
}

" @
        }

        else {

            $object = New-Object –TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value " $WEType"
            $object | Add-Member -MemberType NoteProperty -Name 'roleScopeTagIds' -Value @($WEScopeTags)
            $WEJSON = $object | ConvertTo-Json

        }

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $WEJSON -ContentType " application/json"

        Start-Sleep -Milliseconds 100

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

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

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





Write-WELog " Are you sure you want to remove all Scope Tags from all Configuration and Compliance Policies? Y or N?" " INFO"
$WEConfirm = read-host

if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

    Write-Host
    Write-WELog " Device Compliance Policies" " INFO" -ForegroundColor Cyan
    Write-WELog " Setting all Device Compliance Policies back to no Scope Tag..." " INFO"

    $WECPs = Get-DeviceCompliancePolicy | Sort-Object displayName

    if($WECPs){

        foreach($WEPolicy in $WECPs){

            $WEPolicyDN = $WEPolicy.displayName

            $WEResult = Update-DeviceCompliancePolicy -id $WEPolicy.id -Type $WEPolicy.'@odata.type' -ScopeTags ""

            if($WEResult -eq "" ){

                Write-WELog " Compliance Policy '$WEPolicyDN' patched..." " INFO" -ForegroundColor Gray

            }

        }

    }

    Write-Host

    ####################################################

    Write-WELog " Device Configuration Policies" " INFO" -ForegroundColor Cyan
    Write-WELog " Setting all Device Configuration Policies back to no Scope Tag..." " INFO"

    $WEDCPs = Get-DeviceConfigurationPolicy | ? { $_.'@odata.type' -ne " #microsoft.graph.unsupportedDeviceConfiguration" } | sort displayName

    if($WEDCPs){

        foreach($WEPolicy in $WEDCPs){

           ;  $WEPolicyDN = $WEPolicy.displayName
            
               ;  $WEResult = Update-DeviceConfigurationPolicy -id $WEPolicy.id -Type $WEPolicy.'@odata.type' -ScopeTags ""

                if($WEResult -eq "" ){

                    Write-WELog " Configuration Policy '$WEPolicyDN' patched..." " INFO" -ForegroundColor Gray

                }

            }

        }

    }

else {

    Write-WELog " Removal of all Scope Tags from all Configuration and Compliance Policies was cancelled..." " INFO" -ForegroundColor Yellow

}

Write-Host



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================