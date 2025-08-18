<#
.SYNOPSIS
    Termsandconditions Remove

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
    We Enhanced Termsandconditions Remove

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



Function Get-TermsAndConditions(){

<#
.SYNOPSIS
This function is used to get the Get Terms And Conditions intune resource from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets the Terms and Conditions Intune Resource
.EXAMPLE
Get-TermsAndConditions -ErrorAction Stop
Returns the Organization resource configured in Intune
.NOTES
NAME: Get-TermsAndConditions -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEName
)

$graphApiVersion = " Beta"
$resource = " deviceManagement/termsAndConditions"

    try {

        if($WEName){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains(" $WEName" ) }

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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



Function Remove-TermsAndCondition(){

<#
.SYNOPSIS
This function is used to delete a Terms and Condition Definition from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and deletes a Terms and Condition Definition
.EXAMPLE
Remove-TermsAndCondition -termsAndConditionsId $termsAndConditionsId
Removes a Terms and Condition Definition configured in Intune
.NOTES
NAME: Remove-TermsAndCondition -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $termsAndConditionId
)

$graphApiVersion = " Beta"
$WEResource = " deviceManagement/termsAndConditions/$termsAndConditionId"

    try {

        if($termsAndConditionId -eq "" -or $null -eq $termsAndConditionId){

        Write-WELog " termsAndConditionId hasn't been passed as a paramater to the function..." " INFO" -ForegroundColor Red
        Write-Information " Please specify a valid termsAndConditionsId..."
        break

        }

        else {

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete

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

   ;  $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Information }


$script:authToken = Get-AuthToken -User $WEUser

}




; 
$WETC = Get-TermsAndConditions -Name " Customer"

    if($WETC){

        if(@($WETC).count -gt 1){

        Write-WELog " More than one terms and conditions has been found, please specify a single terms and conditions..." " INFO" -ForegroundColor Red
        Write-Information }

        elseif(@($WETC).count -eq 1){

        Write-WELog " Removing Terms and Conditions:" " INFO" $WETC.displayName -ForegroundColor Yellow
        Remove-TermsAndCondition -termsAndConditionId $WETC.id
        Write-Information }

    }



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================