<#
.SYNOPSIS
    Iosappprovisioningprofile Analysis

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
    We Enhanced Iosappprovisioningprofile Analysis

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


[CmdletBinding()]
function WE-Test-RequiredPath {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param([Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath)
    if (!(Test-Path $WEPath)) {
        Write-Warning " Required path not found: $WEPath"
        return $false
    }
    return $true
}

<#



$WEErrorActionPreference = " Stop"
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



Function Get-AADGroup(){

<#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup -ErrorAction Stop
Returns an AAD group
.NOTES
NAME: Get-AADGroup -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEGroupName,
    $id,
    [switch]$WEMembers
)


$graphApiVersion = " v1.0"
$WEGroup_resource = " groups"
    
    try {

        if($id){

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)?`$filter=id eq '$id'"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }
        
        elseif($WEGroupName -eq "" -or $null -eq $WEGroupName){
        
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if(!$WEMembers){

            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)?`$filter=displayname eq '$WEGroupName'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
            }
            
            elseif($WEMembers){
            
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)?`$filter=displayname eq '$WEGroupName'"
            $WEGroup = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
                if($WEGroup){

                $WEGID = $WEGroup.id

                $WEGroup.displayName
                Write-Information $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)/$WEGID/Members"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                }

            }
        
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



[CmdletBinding()]
Function Get-iOSProvisioningProfile{

<#
.SYNOPSIS
This function is used to get iOS Provisioning Profile uploaded to Intune.
.DESCRIPTION
The function connects to the Graph API Interface and gets an iOS App Provisioning Profile.
.EXAMPLE
Get-iOSProvisioningProfile -ErrorAction Stop
Gets all iOS Provisioning Profiles
.NOTES
NAME: Get-iOSProvisioningProfile -ErrorAction Stop


[cmdletbinding()]

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/iosLobAppProvisioningConfigurations?`$expand=assignments"
    
    try {
                
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).value

            
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

    $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Information }


$script:authToken = Get-AuthToken -User $WEUser

}





Write-Information Write-Information " -------------------------------------------------------------------"
Write-Information Write-Information " Analysing iOS App Provisioning Profiles..."
Write-Information Write-Information " -------------------------------------------------------------------"
Write-Information $WEProfiles = (Get-iOSProvisioningProfile)
$WEDays = 30
$WECSV = @()
$WECSV = $WECSV + " iOSAppProvisioningProfileName,GroupAssignedName,ExpiryDate"
$WEGroupsOutput = @()

    foreach ($WEProfile in $WEProfiles) {
    
        $WEPayload = $WEProfile.payload
        $payloadFileName = $WEProfile.payloadFileName
        $WEPayloadRaw = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($WEPayload))
        $WEExp = ($WEPayloadRaw | C:\windows\System32\findstr.exe /i " date" ).trim()[3]
        [datetime]$WEProfileExpirationDate = $WEExp.TrimStart('<date>').trimend('</date>')
        $displayName = $WEProfile.displayName
        $WEGroupID = ($WEProfile.assignments.target.groupId)
        $WECurrentTime = [System.DateTimeOffset]::Now
        $WETimeDifference = ($WECurrentTime - $WEProfileExpirationDate)
        $WETotalDays = ($WETimeDifference.Days)

        Write-Information " iOS App Provisioning Profile Name: $($displayName)"
            
            
                if ($WEGroupID) {
               
                    foreach ($id in $WEGroupID) {
                
                            $WEGroupName = (Get-AADGroup -id $id).DisplayName
                            Write-Information " Group assigned: $($WEGroupName)"
                            $WECSV = $WECSV + " $($displayName),$($WEGroupName),$($WEProfileExpirationDate)"

                        }

                }

                else {
                
                Write-Information " Group assigned: " -NoNewline 
                Write-WELog " Unassigned" " INFO"
                $WECSV = $WECSV + " $($displayName),,$($WEProfileExpirationDate)"
                
                }
            
            if ($WETotalDays -gt " 0" ) {
           
                Write-WELog " iOS App Provisioning Profile Expiration Date: " " INFO" -NoNewline
                Write-Information " $($WEProfileExpirationDate)"

            }

            elseif ($WETotalDays -gt " -30" ) {
            
                    Write-WELog " iOS App Provisioning Profile Expiration Date: " " INFO" -NoNewline
                    Write-Information " $($WEProfileExpirationDate)" 

            }

            else {
            
                    Write-WELog " iOS App Provisioning Profile: $($WEProfileExpirationDate)" " INFO"

            }

        
        Write-Information Write-Information " -------------------------------------------------------------------"
        Write-Information }

    if (!($WEProfiles.count -eq 0)) {

    Write-WELog " Export results? [Y]es, [N]o" " INFO"
    $conf = Read-Host
 
        if ($conf -eq " Y" ){

        $parent = [System.IO.Path]::GetTempPath()
        [string] $name = [System.Guid]::NewGuid()
        New-Item -ItemType Directory -Path (Join-Path $parent $name) | Out-Null
       ;  $WETempDirPath = " $parent$name" 
       ;  $WETempExportFilePath = " $($WETempDirPath)\iOSAppProvisioningProfileExport.txt"
        $WECSV | Add-Content $WETempExportFilePath -Force
        Write-Information Write-WELog " $($WETempExportFilePath)" " INFO"
        Write-Information }

    }

    else {
    
        Write-Information " No iOS App Provisioning Profiles found."
        Write-Information }



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================