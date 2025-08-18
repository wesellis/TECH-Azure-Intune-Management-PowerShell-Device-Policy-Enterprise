<#
.SYNOPSIS
    Softwareupdates Export

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
    We Enhanced Softwareupdates Export

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



Function Get-SoftwareUpdatePolicy(){

<#
.SYNOPSIS
This function is used to get Software Update policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Software Update policies
.EXAMPLE
Get-SoftwareUpdatePolicy -Windows10
Returns Windows 10 Software Update policies configured in Intune
.EXAMPLE
Get-SoftwareUpdatePolicy -iOS
Returns iOS update policies configured in Intune
.NOTES
NAME: Get-SoftwareUpdatePolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [switch]$WEWindows10,
    [switch]$iOS
)

$graphApiVersion = " Beta"

    try {

        $WECount_Params = 0

        if($iOS.IsPresent){ $WECount_Params++ }
        if($WEWindows10.IsPresent){ $WECount_Params++ }

        if($WECount_Params -gt 1){

        write-host " Multiple parameters set, specify a single parameter -iOS or -Windows10 against the function" -f Red

        }

        elseif($WECount_Params -eq 0){

        Write-WELog " Parameter -iOS or -Windows10 required against the function..." " INFO" -ForegroundColor Red
        Write-Host
        break

        }

        elseif($WEWindows10){

        $WEResource = " deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=groupAssignments"

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value

        }

        elseif($iOS){

        $WEResource = " deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.iosUpdateConfiguration')&`$expand=groupAssignments"

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
$WEJSON,
$WEExportPath

)

    try {

        if($WEJSON -eq "" -or $WEJSON -eq $null){

        write-host " No JSON specified, please specify valid JSON..." -f Red

        }

        elseif(!$WEExportPath){

        write-host " No export path parameter set, please provide a path to export the file" -f Red

        }

        elseif(!(Test-Path $WEExportPath)){

        write-host " $WEExportPath doesn't exist, can't export JSON Data" -f Red

        }

        else {

        $WEJSON1 = ConvertTo-Json $WEJSON

        $WEJSON_Convert = $WEJSON1 | ConvertFrom-Json

        $displayName = $WEJSON_Convert.displayName

        # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
        $WEDisplayName = $WEDisplayName -replace '\<|\>|:|" |/|\\|\||\?|\*', " _"

        $WEProperties = ($WEJSON_Convert | Get-Member | ? { $_.MemberType -eq " NoteProperty" }).Name

            $WEFileName_CSV = " $WEDisplayName" + " _" + $(get-date -f dd-MM-yyyy-H-mm-ss) + " .csv"
            $WEFileName_JSON = " $WEDisplayName" + " _" + $(get-date -f dd-MM-yyyy-H-mm-ss) + " .json"

            $WEObject = New-Object System.Object

                foreach($WEProperty in $WEProperties){

                $WEObject | Add-Member -MemberType NoteProperty -Name $WEProperty -Value $WEJSON_Convert.$WEProperty

                }

            write-host " Export Path:" " $WEExportPath"

            $WEObject | Export-Csv -LiteralPath " $WEExportPath\$WEFileName_CSV" -Delimiter " ," -NoTypeInformation -Append
            $WEJSON1 | Set-Content -LiteralPath " $WEExportPath\$WEFileName_JSON"
            write-host " CSV created in $WEExportPath\$WEFileName_CSV..." -f cyan
            write-host " JSON created in $WEExportPath\$WEFileName_JSON..." -f cyan
            
        }

    }

    catch {

    $_.Exception

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





$WEExportPath = Read-Host -Prompt " Please specify a path to export the policy data to e.g. C:\IntuneOutput"

    # If the directory path doesn't exist prompt user to create the directory
    $WEExportPath = $WEExportPath.replace('" ','')

    if(!(Test-Path " $WEExportPath" )){

    Write-Host
    Write-WELog " Path '$WEExportPath' doesn't exist, do you want to create this directory? Y or N?" " INFO" -ForegroundColor Yellow

    $WEConfirm = read-host

        if($WEConfirm -eq " y" -or $WEConfirm -eq " Y" ){

        new-item -ItemType Directory -Path " $WEExportPath" | Out-Null
        Write-Host

        }

        else {

        Write-WELog " Creation of directory path was cancelled..." " INFO" -ForegroundColor Red
        Write-Host
        break

        }

    }


; 
$WEWSUPs = Get-SoftwareUpdatePolicy -Windows10

if($WEWSUPs){

    foreach($WEWSUP in $WEWSUPs){

        write-host " Software Update Policy:" $WEWSUP.displayName -f Yellow
        Export-JSONData -JSON $WEWSUP -ExportPath " $WEExportPath"
        Write-Host

    }

}

else {

    Write-WELog " No Software Update Policies for Windows 10 Created..." " INFO" -ForegroundColor Red
    Write-Host

}


; 
$WEISUPs = Get-SoftwareUpdatePolicy -iOS

if($WEISUPs){

    foreach($WEISUP in $WEISUPs){

        write-host " Software Update Policy:" $WEISUP.displayName -f Yellow
        Export-JSONData -JSON $WEISUP -ExportPath " $WEExportPath"
        Write-Host

    }

}

else {

    Write-WELog " No Software Update Policies for iOS Created..." " INFO" -ForegroundColor Red
    Write-Host

}




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================