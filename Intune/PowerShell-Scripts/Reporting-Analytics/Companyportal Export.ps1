<#
.SYNOPSIS
    Companyportal Export

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
    We Enhanced Companyportal Export

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



Function Get-IntuneBrand(){

<#
.SYNOPSIS
This function is used to get the Company Intune Branding resources from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets the Intune Branding Resource
.EXAMPLE
Get-IntuneBrand -ErrorAction Stop
Returns the Company Intune Branding configured in Intune
.NOTES
NAME: Get-IntuneBrand -ErrorAction Stop


[cmdletbinding()]

$graphApiVersion = " Beta"
$WEResource = " deviceManagement/intuneBrand"

    try {

    $uri = " https://graph.microsoft.com/$graphApiVersion/$($resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

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



Function Export-JSONData(){

<#
.SYNOPSIS
This function is used to export JSON data returned from Graph
.DESCRIPTION
This function is used to export JSON data returned from Graph
.EXAMPLE
Export-JSONData -JSON $WEJSON
Export the JSON inputted on the function
.NOTES
NAME: Export-JSONData




[CmdletBinding()]
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
    Write-Information $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
$WEJSON,
$WEExportPath

)

    try {

        if($WEJSON -eq "" -or $null -eq $WEJSON){

        Write-Information " No JSON specified, please specify valid JSON..." -f Red

        }

        elseif(!$WEExportPath){

        Write-Information " No export path parameter set, please provide a path to export the file" -f Red

        }

        elseif(!(Test-Path $WEExportPath)){

        Write-Information " $WEExportPath doesn't exist, can't export JSON Data" -f Red

        }

        else {

        $WEJSON1 = ConvertTo-Json $WEJSON -Depth 5

        $WEJSON_Convert = $WEJSON1 | ConvertFrom-Json

        $displayName = $WEJSON_Convert.displayName

        # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
        $WEDisplayName = $WEDisplayName -replace '\<|\>|:|" |/|\\|\||\?|\*', " _"

        $WEProperties = ($WEJSON_Convert | Get-Member -ErrorAction Stop | ? { $_.MemberType -eq " NoteProperty" }).Name

            $WEFileName_JSON = " $WEDisplayName" + " _" + $(get-date -f dd-MM-yyyy-H-mm-ss) + " .json"

            $WEObject = New-Object -ErrorAction Stop System.Object

                foreach($WEProperty in $WEProperties){

                $WEObject | Add-Member -MemberType NoteProperty -Name $WEProperty -Value $WEJSON_Convert.$WEProperty

                }

            Write-Information " Export Path:" " $WEExportPath"

            $WEJSON1 | Set-Content -LiteralPath " $WEExportPath\$WEFileName_JSON"
            Write-Information " JSON created in $WEExportPath\$WEFileName_JSON..." -f cyan
            
        }

    }

    catch {

    $_.Exception

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





$WEExportPath = Read-Host -Prompt " Please specify a path to export Company Portal Branding data to e.g. C:\IntuneOutput"

    # If the directory path doesn't exist prompt user to create the directory
    $WEExportPath = $WEExportPath.replace('" ','')

    if(!(Test-Path " $WEExportPath" )){

    Write-Information Write-WELog " Path '$WEExportPath' doesn't exist, do you want to create this directory? Y or N?" " INFO"

   ;  $WEConfirm = read-host

        if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

        new-item -ItemType Directory -Path " $WEExportPath" | Out-Null
        Write-Information }

        else {

        Write-WELog " Creation of directory path was cancelled..." " INFO" -ForegroundColor Red
        Write-Information break

        }

    }

Write-Information ; 
$WEIntuneBrand = Get-IntuneBrand -ErrorAction Stop

if($WEIntuneBrand.displayName){

    Write-Information " Exporting Company Portal Branding" -f Yellow
    Export-JSONData -JSON $WEIntuneBrand -ExportPath " $WEExportPath"
    Write-Information }

else {

    Write-WELog " Company Portal Branding is set as default..." " INFO" -ForegroundColor Red
    Write-Information " Company Name property is required at a minimum..."
    Write-Information }





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================