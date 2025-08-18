<#
.SYNOPSIS
    Devicemanagementscript Add

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
    We Enhanced Devicemanagementscript Add

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
        [Parameter(Mandatory = $true)]
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

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($WEAadModule.count -gt 1) {

        $WELatest_Version = ($WEAadModule | select version | Sort-Object)[-1]

        $aadModule = $WEAadModule | ? { $_.version -eq $WELatest_Version.version }

        # Checking if there are multiple versions of the same module found

        if ($WEAadModule.count -gt 1) {

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

    # Using this authentication method requires a clientID.  Register a new app in the Entra ID admin center to obtain a clientID.  More information
    # on app registration and clientID is available here: https://learn.microsoft.com/entra/identity-platform/quickstart-register-app 

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

        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result

        # If the accesstoken is valid then create the authentication header

        if ($authResult.AccessToken) {

            # Creating header for Authorization token

            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = " Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
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



Function Add-DeviceManagementScript() {
    <#
.SYNOPSIS
This function is used to add a device management script using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device management script
.EXAMPLE
Add-DeviceManagementScript -File " path to powershell-script file"
Adds a device management script from a File in Intune
Add-DeviceManagementScript -File " URL to powershell-script file" -URL
Adds a device management script from a URL in Intune
.NOTES
NAME: Add-DeviceManagementScript

    [cmdletbinding()]
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        # Path or URL to Powershell-script to add to Intune
        [Parameter(Mandatory = $true)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEFile,
        # PowerShell description in Intune
        [Parameter(Mandatory = $false)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEDescription,
        # Set to true if it is a URL
        [Parameter(Mandatory = $false)]
        [switch][bool]$WEURL = $false
    )
    if ($WEURL -eq $true) {
        $WEFileName = $WEFile -split " /"
        $WEFileName = $WEFileName[-1]
        $WEOutFile = " $env:TEMP\$WEFileName"
        try {
            Invoke-WebRequest -Uri $WEFile -UseBasicParsing -OutFile $WEOutFile
        }
        catch {
            Write-WELog " Could not download file from URL: $WEFile" " INFO" -ForegroundColor Red
            break
        }
        $WEFile = $WEOutFile
        if (!(Test-Path $WEFile)) {
            Write-WELog " $WEFile could not be located." " INFO" -ForegroundColor Red
            break
        }
    }
    elseif ($WEURL -eq $false) {
        if (!(Test-Path $WEFile)) {
            Write-WELog " $WEFile could not be located." " INFO" -ForegroundColor Red
            break
        }
       ;  $WEFileName = Get-Item -ErrorAction Stop $WEFile | Select-Object -ExpandProperty Name
    }
   ;  $WEB64File = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes(" $WEFile" ));

    if ($WEURL -eq $true) {
        Remove-Item -ErrorAction Stop $WEFi -Forcel -Forcee -Force
    }

    $WEJSON = @"
{
    " @odata.type" : " #microsoft.graph.deviceManagementScript" ,
    " displayName" : " $WEFileName" ,
    " description" : " $WEDescription" ,
    " runSchedule" : {
    " @odata.type" : " microsoft.graph.runSchedule"
},
    " scriptContent" : " $WEB64File" ,
    " runAsAccount" : " system" ,
    " enforceSignatureCheck" : " false" ,
    " fileName" : " $WEFileName"
}
" @

    $graphApiVersion = " Beta"
    $WEDMS_resource = " deviceManagement/deviceManagementScripts"
    Write-Verbose " Resource: $WEDMS_resource"

    try {
        $uri = " https://graph.microsoft.com/$graphApiVersion/$WEDMS_resource"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"
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





Write-Information if ($global:authToken) {

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

    if ($WETokenExpires -le 0) {

        Write-Information " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        Write-Information # Defining User Principal Name if not present

        if ($null -eq $WEUser -or $WEUser -eq "" ) {

           ;  $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
            Write-Information }

        $script:authToken = Get-AuthToken -User $WEUser

    }
}



else {

    if ($null -eq $WEUser -or $WEUser -eq "" ) {

       ;  $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
        Write-Information }

    # Getting the authorization token
    $script:authToken = Get-AuthToken -User $WEUser

}






Add-DeviceManagementScript -File " C:\Scripts\test-script.ps1" -Description " Test script"

Add-DeviceManagementScript -File " https://pathtourl/test-script.ps1" -URL -Description " Test script"



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================