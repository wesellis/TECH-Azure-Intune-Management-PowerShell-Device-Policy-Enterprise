<#
.SYNOPSIS
    Settingscatalog Get

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
    We Enhanced Settingscatalog Get

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



Function Get-SettingsCatalogPolicy(){

<#
.SYNOPSIS
This function is used to get Settings Catalog policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Settings Catalog policies
.EXAMPLE
Get-SettingsCatalogPolicy
Returns any Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform windows10
Returns any Windows 10 Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform macOS
Returns any MacOS Settings Catalog policies configured in Intune
.NOTES
NAME: Get-SettingsCatalogPolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory=$false)]
    [ValidateSet(" windows10" ," macOS" )]
    [ValidateNotNullOrEmpty()]
    [string]$WEPlatform
)

$graphApiVersion = " beta"

    if($WEPlatform){
        
        $WEResource = " deviceManagement/configurationPolicies?`$filter=platforms has '$WEPlatform' and technologies has 'mdm'"

    }

    else {

        $WEResource = " deviceManagement/configurationPolicies?`$filter=technologies has 'mdm'"

    }

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



Function Get-SettingsCatalogPolicySettings(){

<#
.SYNOPSIS
This function is used to get Settings Catalog policy Settings from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Settings Catalog policy Settings
.EXAMPLE
Get-SettingsCatalogPolicySettings -policyid policyid
Returns any Settings Catalog policy Settings configured in Intune
.NOTES
NAME: Get-SettingsCatalogPolicySettings


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $policyid
)

$graphApiVersion = " beta"
$WEResource = " deviceManagement/configurationPolicies('$policyid')/settings?`$expand=settingDefinitions"

    try {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"

        $WEResponse = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)

        $WEAllResponses = $WEResponse.value
     
        $WEResponseNextLink = $WEResponse." @odata.nextLink"

        while ($WEResponseNextLink -ne $null){

            $WEResponse = (Invoke-RestMethod -Uri $WEResponseNextLink -Headers $authToken -Method Get)
            $WEResponseNextLink = $WEResponse." @odata.nextLink"
            $WEAllResponses = $WEAllResponses + $WEResponse.value

        }

        return $WEAllResponses

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





$WEPolicies = Get-SettingsCatalogPolicy

if($WEPolicies){

    foreach($policy in $WEPolicies){

        Write-Host $policy.name -ForegroundColor Yellow

        $WEAllSettingsInstances = @()

        $policyid = $policy.id
        $WEPolicy_Technologies = $policy.technologies
        $WEPolicy_Platforms = $WEPolicy.platforms
        $WEPolicy_Name = $WEPolicy.name
        $WEPolicy_Description = $policy.description

        $WEPolicyBody = New-Object -TypeName PSObject

        Add-Member -InputObject $WEPolicyBody -MemberType 'NoteProperty' -Name 'name' -Value " $WEPolicy_Name"
        Add-Member -InputObject $WEPolicyBody -MemberType 'NoteProperty' -Name 'description' -Value " $WEPolicy_Description"
        Add-Member -InputObject $WEPolicyBody -MemberType 'NoteProperty' -Name 'platforms' -Value " $WEPolicy_Platforms"
        Add-Member -InputObject $WEPolicyBody -MemberType 'NoteProperty' -Name 'technologies' -Value " $WEPolicy_Technologies"

        # Checking if policy has a templateId associated
        if($policy.templateReference.templateId){

            Write-WELog " Found template reference" " INFO" -f Cyan
            $templateId = $policy.templateReference.templateId

            $WEPolicyTemplateReference = New-Object -TypeName PSObject

            Add-Member -InputObject $WEPolicyTemplateReference -MemberType 'NoteProperty' -Name 'templateId' -Value $templateId

            Add-Member -InputObject $WEPolicyBody -MemberType 'NoteProperty' -Name 'templateReference' -Value $WEPolicyTemplateReference

        }

        $WESettingInstances = Get-SettingsCatalogPolicySettings -policyid $policyid

       ;  $WEInstances = $WESettingInstances.settingInstance

        foreach($object in $WEInstances){

           ;  $WEInstance = New-Object -TypeName PSObject

            Add-Member -InputObject $WEInstance -MemberType 'NoteProperty' -Name 'settingInstance' -Value $object
           ;  $WEAllSettingsInstances = $WEAllSettingsInstances + $WEInstance

        }

        Add-Member -InputObject $WEPolicyBody -MemberType 'NoteProperty' -Name 'settings' -Value @($WEAllSettingsInstances)

        $WEPolicyBody | ConvertTo-Json -Depth 10

        Write-Host

    }

}

else {

    Write-WELog " No Settings Catalog policies found..." " INFO" -ForegroundColor Red
    Write-Host

}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================