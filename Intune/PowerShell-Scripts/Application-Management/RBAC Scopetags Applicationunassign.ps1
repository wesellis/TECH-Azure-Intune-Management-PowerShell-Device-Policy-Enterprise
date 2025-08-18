<#
.SYNOPSIS
    Rbac Scopetags Applicationunassign

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
    We Enhanced Rbac Scopetags Applicationunassign

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



Function Get-IntuneApplication(){

<#
.SYNOPSIS
This function is used to get applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any applications added
.EXAMPLE
Get-IntuneApplication -ErrorAction Stop
Returns any applications configured in Intune
.NOTES
NAME: Get-IntuneApplication -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $displayName,
    $id
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/mobileApps"
    
    try {
        
        if($displayName){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)?`$filter=displayName eq '$displayName'"
            (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).value

        }
        
        elseif($id){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)/$id"
            (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get)

        }

        else {

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value | ? { (!($_.'@odata.type').Contains(" managed" )) }
        
        }
    }
    
    catch {

    $ex = $_.Exception
    Write-WELog " Request to $WEUri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" " INFO" -f Red
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



Function Update-IntuneApplication(){

<#
.SYNOPSIS
This function is used to update an Intune Application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and updates an Intune Application
.EXAMPLE
Update-IntuneApplication -id $id -Type " #microsoft.graph.WebApp" -ScopeTags " 1,2,3"
Updates an Intune Application with selected scope tags
.NOTES
NAME: Update-IntuneApplication


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $id,
    $WEType,
    $WEScopeTags
)

$graphApiVersion = " beta"
$WEResource = " deviceAppManagement/mobileApps/$id"

    try {

        if(($WEType -eq " #microsoft.graph.androidManagedStoreApp" ) -or ($WEType -eq " #microsoft.graph.microsoftStoreForBusinessApp" ) -or ($WEType -eq " #microsoft.graph.iosVppApp" )){

            Write-Warning " Scope Tags aren't available on '$WEType' application Type..."

        }
        
        else {
        
        if($WEScopeTags -eq "" -or $null -eq $WEScopeTags){

$WEJSON = @"

{
  " @odata.type" : " $WEType" ,
  " roleScopeTagIds" : []
}

" @
        }

        else {

            $object = New-Object -ErrorAction Stop –TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value " $WEType"
            $object | Add-Member -MemberType NoteProperty -Name 'roleScopeTagIds' -Value @($WEScopeTags)
            $WEJSON = $object | ConvertTo-Json

        }

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $WEJSON -ContentType " application/json"

        Start-Sleep -Milliseconds 100

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

    Write-Information $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Information }


$script:authToken = Get-AuthToken -User $WEUser

}





Write-Information $displayName = " Bing Web App"

$WEApplication = Get-IntuneApplication -displayName " $displayName"

if(@($WEApplication).count -eq 1){

    $WEADN = $WEApplication.displayName
    $WEAT = $WEApplication.'@odata.type'

    Write-WELog " Intune Application '$WEADN' with type '$WEAT' found..." " INFO"

   ;  $WEIA = Get-IntuneApplication -id $WEApplication.id

   ;  $WEResult = Update-IntuneApplication -id $WEIA.id -Type $WEIA.'@odata.type' -ScopeTags ""

        if($WEResult -eq "" ){

            Write-WELog " Intune Application '$WEADN' patched..." " INFO" -ForegroundColor Gray
                            
        }

    Write-Information }

elseif(@($WEApplication).count -gt 1){

    Write-WELog " More than one Intune Application found with name '$displayName'..." " INFO" -ForegroundColor Red

}

else {

    Write-WELog " No Intune Applications found..." " INFO" -ForegroundColor Red

}





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================