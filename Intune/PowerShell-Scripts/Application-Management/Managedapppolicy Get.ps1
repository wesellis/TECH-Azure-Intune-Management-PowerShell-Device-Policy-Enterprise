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

    $WEMethodArguments = [Type[]]@(" System.String" , " System.String" , " System.Uri" , " Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior" , " Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" )
    $WENonAsync = $WEAuthContext.GetType().GetMethod(" AcquireToken" , $WEMethodArguments)

        if ($null -ne $WENonAsync){

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



Function Get-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to get managed app policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app policies
.EXAMPLE
Get-ManagedAppPolicy -ErrorAction Stop
Returns any managed app policies configured in Intune
.NOTES
NAME: Get-ManagedAppPolicy -ErrorAction Stop


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
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    Write-Information break
    
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
NAME: Get-ManagedAppProtection -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $id,
    $WEOS    
)

$graphApiVersion = " Beta"

    try {
    
        if($id -eq "" -or $null -eq $id){
    
        Write-Information " No Managed App Policy id specified, please provide a policy id..." -f Red
        break
    
        }
    
        else {
    
            if($WEOS -eq "" -or $null -eq $WEOS){
    
            Write-Information " No OS parameter specified, please provide an OS. Supported value are Android,iOS,WIP_WE,WIP_MDM..." -f Red
            Write-Information break
    
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
   ;  $reader = New-Object -ErrorAction Stop System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
   ;  $responseBody = $reader.ReadToEnd();
    Write-WELog " Response content:`n$responseBody" " INFO" -f Red
    Write-Error " Request to $WEUri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
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
Returns all users registered with Azure AD
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





Write-Information " Running query against Microsoft Graph for App Protection Policies" -f Yellow

$WEManagedAppPolicies = Get-ManagedAppPolicy -ErrorAction Stop

Write-Information foreach($WEManagedAppPolicy in $WEManagedAppPolicies){

Write-Information " Managed App Policy:" $WEManagedAppPolicy.displayName -f Yellow

$WEManagedAppPolicy

    # If Android Managed App Policy
    
    if($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.androidManagedAppProtection" ){
    
        $WEAndroidManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " Android"
    
        Write-Information " Managed App Policy - Assignments" -f Cyan
    
        $WEAndroidAssignments = ($WEAndroidManagedAppProtection | select assignments).assignments
    
            if($WEAndroidAssignments){
    
                foreach($WEGroup in $WEAndroidAssignments.target.groupId){
    
                (Get-AADGroup -id $WEGroup).displayName
    
                }
    
                Write-Information }
    
            else {
    
            Write-WELog " No assignments set for this policy..." " INFO" -ForegroundColor Red
            Write-Information }
    
        Write-Information " Managed App Policy - Mobile Apps" -f Cyan
            
        if($WEManagedAppPolicy.deployedAppCount -ge 1){
    
        ($WEAndroidManagedAppProtection | select apps).apps.mobileAppIdentifier
    
        }
    
        else {
    
        Write-WELog " No Managed Apps targeted..." " INFO" -ForegroundColor Red
        Write-Information }
    
    }

    # If iOS Managed App Policy
    
    elseif($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.iosManagedAppProtection" ){
    
        $iOSManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " iOS"
    
        Write-Information " Managed App Policy - Assignments" -f Cyan
    
        $iOSAssignments = ($iOSManagedAppProtection | select assignments).assignments
    
            if($iOSAssignments){
    
                foreach($WEGroup in $iOSAssignments.target.groupId){
    
                (Get-AADGroup -id $WEGroup).displayName
    
                }
    
                Write-Information }
    
            else {
    
            Write-WELog " No assignments set for this policy..." " INFO" -ForegroundColor Red
            Write-Information }
    
        Write-Information " Managed App Policy - Mobile Apps" -f Cyan
            
        if($WEManagedAppPolicy.deployedAppCount -ge 1){
    
        ($iOSManagedAppProtection | select apps).apps.mobileAppIdentifier
    
        }
    
        else {
    
        Write-WELog " No Managed Apps targeted..." " INFO" -ForegroundColor Red
        Write-Information }
    
    }

    # If WIP Without Enrollment Managed App Policy
    
    elseif($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.windowsInformationProtectionPolicy" ){
    
        $WEWin10ManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " WIP_WE"
    
        Write-Information " Managed App Policy - Assignments" -f Cyan
    
        $WEWin10Assignments = ($WEWin10ManagedAppProtection | select assignments).assignments
    
            if($WEWin10Assignments){
    
                foreach($WEGroup in $WEWin10Assignments.target.groupId){
    
                (Get-AADGroup -id $WEGroup).displayName
    
                }
    
                Write-Information }
    
            else {
    
            Write-WELog " No assignments set for this policy..." " INFO" -ForegroundColor Red
            Write-Information }
    
        Write-Information " Protected Apps" -f Cyan
            
        if($WEWin10ManagedAppProtection.protectedApps){
    
        $WEWin10ManagedAppProtection.protectedApps.displayName
    
        Write-Information }
    
        else {
    
        Write-WELog " No Protected Apps targeted..." " INFO" -ForegroundColor Red
        Write-Information }

        
        Write-Information " Protected AppLocker Files"

        if($WEWin10ManagedAppProtection.protectedAppLockerFiles){
    
        $WEWin10ManagedAppProtection.protectedAppLockerFiles.displayName

        Write-Information }
    
        else {
    
        Write-WELog " No Protected Applocker Files targeted..." " INFO" -ForegroundColor Red
        Write-Information }
    
    }

    # If WIP with Enrollment (MDM) Managed App Policy
    
    elseif($WEManagedAppPolicy.'@odata.type' -eq " #microsoft.graph.mdmWindowsInformationProtectionPolicy" ){
    
       ;  $WEWin10ManagedAppProtection = Get-ManagedAppProtection -id $WEManagedAppPolicy.id -OS " WIP_MDM"
    
        Write-Information " Managed App Policy - Assignments" -f Cyan
    
       ;  $WEWin10Assignments = ($WEWin10ManagedAppProtection | select assignments).assignments
    
            if($WEWin10Assignments){
    
                foreach($WEGroup in $WEWin10Assignments.target.groupId){
    
                (Get-AADGroup -id $WEGroup).displayName
    
                }
    
                Write-Information }
    
            else {
    
            Write-WELog " No assignments set for this policy..." " INFO" -ForegroundColor Red
            Write-Information }
    
        Write-Information " Protected Apps" -f Cyan
            
        if($WEWin10ManagedAppProtection.protectedApps){
    
        $WEWin10ManagedAppProtection.protectedApps.displayName
    
        Write-Information }
    
        else {
    
        Write-WELog " No Protected Apps targeted..." " INFO" -ForegroundColor Red
        Write-Information }

        
        Write-Information " Protected AppLocker Files"

        if($WEWin10ManagedAppProtection.protectedAppLockerFiles){
    
        $WEWin10ManagedAppProtection.protectedAppLockerFiles.displayName

        Write-Information }
    
        else {
    
        Write-WELog " No Protected Applocker Files targeted..." " INFO" -ForegroundColor Red
        Write-Information }
    
    }

}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================