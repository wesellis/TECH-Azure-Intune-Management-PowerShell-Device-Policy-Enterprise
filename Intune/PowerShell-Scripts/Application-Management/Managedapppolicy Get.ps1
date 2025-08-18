<#
.SYNOPSIS
    Managedapppolicy Get

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
    We Enhanced Managedapppolicy Get

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

    $WEMethodArguments = [Type[]]@(" System.String" , " System.String" , " System.Uri" , " Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior" , " Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" )
    $WENonAsync = $WEAuthContext.GetType().GetMethod(" AcquireToken" , $WEMethodArguments)

        if ($WENonAsync -ne $null){

            $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, [Uri]$redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto, $userId)
        
        }
        
        else {

            $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, [Uri]$redirectUri, $platformParameters, $userId).Result 
        
        }

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



Function Get-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to get managed app policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app policies
.EXAMPLE
Get-ManagedAppPolicy
Returns any managed app policies configured in Intune
.NOTES
NAME: Get-ManagedAppPolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEName
)

$graphApiVersion = " Beta"
$WEResource = " deviceAppManagement/managedAppPolicies"

    try {
    
        if($WEName){
    
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains(" $WEName" ) }
    
        }
    
        else {
    
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains(" ManagedAppProtection" ) -or ($_.'@odata.type').contains(" InformationProtectionPolicy" ) }
    
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



Function Get-ManagedAppProtection(){

<#
.SYNOPSIS
This function is used to get managed app protection configuration from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app protection policy
.EXAMPLE
Get-ManagedAppProtection -id $id -OS " Android"
Returns a managed app protection policy for Android configured in Intune
Get-ManagedAppProtection -id $id -OS " iOS"
Returns a managed app protection policy for iOS configured in Intune
Get-ManagedAppProtection -id $id -OS " WIP_WE"
Returns a managed app protection policy for Windows 10 without enrollment configured in Intune
.NOTES
NAME: Get-ManagedAppProtection


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $id,
    $WEOS    
)

$graphApiVersion = " Beta"

    try {
    
        if($id -eq "" -or $id -eq $null){
    
        write-host " No Managed App Policy id specified, please provide a policy id..." -f Red
        break
    
        }
    
        else {
    
            if($WEOS -eq "" -or $WEOS -eq $null){
    
            write-host " No OS parameter specified, please provide an OS. Supported value are Android,iOS,WIP_WE,WIP_MDM..." -f Red
            Write-Host
            break
    
            }
    
            elseif($WEOS -eq " Android" ){
    
            $WEResource = " deviceAppManagement/androidManagedAppProtections('$id')/?`$expand=deploymentSummary,apps,assignments"
    
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }
    
            elseif($WEOS -eq " iOS" ){
    
            $WEResource = " deviceAppManagement/iosManagedAppProtections('$id')/?`$expand=deploymentSummary,apps,assignments"
    
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }

            elseif($WEOS -eq " WIP_WE" ){
    
            $WEResource = " deviceAppManagement/windowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }

            elseif($WEOS -eq " WIP_MDM" ){
    
            $WEResource = " deviceAppManagement/mdmWindowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    
            $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

            }
    
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



Function Get-AADGroup(){

<#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup


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
    
        elseif($WEGroupName -eq "" -or $WEGroupName -eq $null){
    
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
                write-host
    
                $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEGroup_resource)/$WEGID/Members"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
                }
    
            }
    
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





write-host " Running query against Microsoft Graph for App Protection Policies" -f Yellow

$WEManagedAppPolicies = Get-ManagedAppPolicy

write-host

foreach($WEManagedAppPolicy in $WEManagedAppPolicies){

write-host " Managed App Policy:" $WEManagedAppPolicy.displayName -f Yellow

$WEManagedAppPolicy

    # If Android Managed App Policy
    
    if($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.androidManagedAppProtection" ){
    
        $WEAndroidManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " Android"
    
        write-host " Managed App Policy - Assignments" -f Cyan
    
        $WEAndroidAssignments = ($WEAndroidManagedAppProtection | select assignments).assignments
    
            if($WEAndroidAssignments){
    
                foreach($WEGroup in $WEAndroidAssignments.target.groupId){
    
                (Get-AADGroup -id $WEGroup).displayName
    
                }
    
                Write-Host
    
            }
    
            else {
    
            Write-WELog " No assignments set for this policy..." " INFO" -ForegroundColor Red
            Write-Host
    
            }
    
        write-host " Managed App Policy - Mobile Apps" -f Cyan
            
        if($WEManagedAppPolicy.deployedAppCount -ge 1){
    
        ($WEAndroidManagedAppProtection | select apps).apps.mobileAppIdentifier
    
        }
    
        else {
    
        Write-WELog " No Managed Apps targeted..." " INFO" -ForegroundColor Red
        Write-Host
    
        }
    
    }

    # If iOS Managed App Policy
    
    elseif($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.iosManagedAppProtection" ){
    
        $iOSManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " iOS"
    
        write-host " Managed App Policy - Assignments" -f Cyan
    
        $iOSAssignments = ($iOSManagedAppProtection | select assignments).assignments
    
            if($iOSAssignments){
    
                foreach($WEGroup in $iOSAssignments.target.groupId){
    
                (Get-AADGroup -id $WEGroup).displayName
    
                }
    
                Write-Host
    
            }
    
            else {
    
            Write-WELog " No assignments set for this policy..." " INFO" -ForegroundColor Red
            Write-Host
    
            }
    
        write-host " Managed App Policy - Mobile Apps" -f Cyan
            
        if($WEManagedAppPolicy.deployedAppCount -ge 1){
    
        ($iOSManagedAppProtection | select apps).apps.mobileAppIdentifier
    
        }
    
        else {
    
        Write-WELog " No Managed Apps targeted..." " INFO" -ForegroundColor Red
        Write-Host
    
        }
    
    }

    # If WIP Without Enrollment Managed App Policy
    
    elseif($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.windowsInformationProtectionPolicy" ){
    
        $WEWin10ManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " WIP_WE"
    
        write-host " Managed App Policy - Assignments" -f Cyan
    
        $WEWin10Assignments = ($WEWin10ManagedAppProtection | select assignments).assignments
    
            if($WEWin10Assignments){
    
                foreach($WEGroup in $WEWin10Assignments.target.groupId){
    
                (Get-AADGroup -id $WEGroup).displayName
    
                }
    
                Write-Host
    
            }
    
            else {
    
            Write-WELog " No assignments set for this policy..." " INFO" -ForegroundColor Red
            Write-Host
    
            }
    
        write-host " Protected Apps" -f Cyan
            
        if($WEWin10ManagedAppProtection.protectedApps){
    
        $WEWin10ManagedAppProtection.protectedApps.displayName
    
        Write-Host

        }
    
        else {
    
        Write-WELog " No Protected Apps targeted..." " INFO" -ForegroundColor Red
        Write-Host
    
        }

        
        write-host " Protected AppLocker Files" -ForegroundColor Cyan

        if($WEWin10ManagedAppProtection.protectedAppLockerFiles){
    
        $WEWin10ManagedAppProtection.protectedAppLockerFiles.displayName

        Write-Host
    
        }
    
        else {
    
        Write-WELog " No Protected Applocker Files targeted..." " INFO" -ForegroundColor Red
        Write-Host
    
        }
    
    }

    # If WIP with Enrollment (MDM) Managed App Policy
    
    elseif($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.mdmWindowsInformationProtectionPolicy" ){
    
       ;  $WEWin10ManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " WIP_MDM"
    
        write-host " Managed App Policy - Assignments" -f Cyan
    
       ;  $WEWin10Assignments = ($WEWin10ManagedAppProtection | select assignments).assignments
    
            if($WEWin10Assignments){
    
                foreach($WEGroup in $WEWin10Assignments.target.groupId){
    
                (Get-AADGroup -id $WEGroup).displayName
    
                }
    
                Write-Host
    
            }
    
            else {
    
            Write-WELog " No assignments set for this policy..." " INFO" -ForegroundColor Red
            Write-Host
    
            }
    
        write-host " Protected Apps" -f Cyan
            
        if($WEWin10ManagedAppProtection.protectedApps){
    
        $WEWin10ManagedAppProtection.protectedApps.displayName
    
        Write-Host

        }
    
        else {
    
        Write-WELog " No Protected Apps targeted..." " INFO" -ForegroundColor Red
        Write-Host
    
        }

        
        write-host " Protected AppLocker Files" -ForegroundColor Cyan

        if($WEWin10ManagedAppProtection.protectedAppLockerFiles){
    
        $WEWin10ManagedAppProtection.protectedAppLockerFiles.displayName

        Write-Host
    
        }
    
        else {
    
        Write-WELog " No Protected Applocker Files targeted..." " INFO" -ForegroundColor Red
        Write-Host
    
        }
    
    }

}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================