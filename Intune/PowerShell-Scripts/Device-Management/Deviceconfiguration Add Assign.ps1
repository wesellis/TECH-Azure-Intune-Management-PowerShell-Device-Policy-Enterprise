<#
.SYNOPSIS
    Deviceconfiguration Add Assign

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
    We Enhanced Deviceconfiguration Add Assign

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



Function Add-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to add an device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy
.EXAMPLE
Add-DeviceConfigurationPolicy -JSON $WEJSON
Adds a device configuration policy in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicy


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    $WEJSON
)

$graphApiVersion = " Beta"
$WEDCP_resource = " deviceManagement/deviceConfigurations"
Write-Verbose " Resource: $WEDCP_resource"

    try {

        if($WEJSON -eq "" -or $WEJSON -eq $null){

        write-host " No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $WEJSON

        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"

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



Function Add-DeviceConfigurationPolicyAssignment(){

    <#
    .SYNOPSIS
    This function is used to add a device configuration policy assignment using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy assignment
    .EXAMPLE
    Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $WEConfigurationPolicyId -TargetGroupId $WETargetGroupId -AssignmentType Included
    Adds a device configuration policy assignment in Intune
    .NOTES
    NAME: Add-DeviceConfigurationPolicyAssignment
    #>
    
    [cmdletbinding()]
    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $WEConfigurationPolicyId,
    
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $WETargetGroupId,
    
        [parameter(Mandatory=$true)]
        [ValidateSet(" Included" ," Excluded" )]
        [ValidateNotNullOrEmpty()]
        [string]$WEAssignmentType
    )
    
    $graphApiVersion = " Beta"
    $WEResource = " deviceManagement/deviceConfigurations/$WEConfigurationPolicyId/assign"
        
        try {
    
            if(!$WEConfigurationPolicyId){
    
                write-host " No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
                break
    
            }
    
            if(!$WETargetGroupId){
    
                write-host " No Target Group Id specified, specify a valid Target Group Id" -f Red
                break
    
            }
    
            # Checking if there are Assignments already configured in the Policy
            $WEDCPA = Get-DeviceConfigurationPolicyAssignment -id $WEConfigurationPolicyId
    
            $WETargetGroups = @()
    
            if(@($WEDCPA).count -ge 1){
                
                if($WEDCPA.targetGroupId -contains $WETargetGroupId){
    
                Write-WELog " Group with Id '$WETargetGroupId' already assigned to Policy..." " INFO" -ForegroundColor Red
                Write-Host
                break
    
                }
    
                # Looping through previously configured assignements
    
                $WEDCPA | foreach {
    
                $WETargetGroup = New-Object -TypeName psobject
         
                    if($_.excludeGroup -eq $true){
    
                        $WETargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                    }
         
                    else {
         
                        $WETargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
                    }
    
                $WETargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $_.targetGroupId
    
                $WETarget = New-Object -TypeName psobject
                $WETarget | Add-Member -MemberType NoteProperty -Name 'target' -Value $WETargetGroup
    
                $WETargetGroups = $WETargetGroups + $WETarget
    
                }
    
                # Adding new group to psobject
                $WETargetGroup = New-Object -TypeName psobject
    
                    if($WEAssignmentType -eq " Excluded" ){
    
                        $WETargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                    }
         
                    elseif($WEAssignmentType -eq " Included" ) {
         
                        $WETargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
                    }
         
                $WETargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value " $WETargetGroupId"
    
                $WETarget = New-Object -TypeName psobject
                $WETarget | Add-Member -MemberType NoteProperty -Name 'target' -Value $WETargetGroup
    
                $WETargetGroups = $WETargetGroups + $WETarget
    
            }
    
            else {
    
                # No assignments configured creating new JSON object of group assigned
                
                $WETargetGroup = New-Object -TypeName psobject
    
                    if($WEAssignmentType -eq " Excluded" ){
    
                        $WETargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                    }
         
                    elseif($WEAssignmentType -eq " Included" ) {
         
                        $WETargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
                    }
         
                $WETargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value " $WETargetGroupId"
    
                $WETarget = New-Object -TypeName psobject
                $WETarget | Add-Member -MemberType NoteProperty -Name 'target' -Value $WETargetGroup
    
                $WETargetGroups = $WETarget
    
            }
    
        # Creating JSON object to pass to Graph
        $WEOutput = New-Object -TypeName psobject
    
        $WEOutput | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($WETargetGroups)
    
        $WEJSON = $WEOutput | ConvertTo-Json -Depth 3
    
        # POST to Graph Service
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEResource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $WEJSON -ContentType " application/json"
    
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



Function Get-DeviceConfigurationPolicyAssignment(){

    <#
    .SYNOPSIS
    This function is used to get device configuration policy assignment from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets a device configuration policy assignment
    .EXAMPLE
    Get-DeviceConfigurationPolicyAssignment $id guid
    Returns any device configuration policy assignment configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicyAssignment
    #>
    
    [cmdletbinding()]
    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$true,HelpMessage=" Enter id (guid) for the Device Configuration Policy you want to check assignment" )]
        $id
    )
    
    $graphApiVersion = " Beta"
    $WEDCP_resource = " deviceManagement/deviceConfigurations"
    
        try {
    
        $uri = " https://graph.microsoft.com/$graphApiVersion/$($WEDCP_resource)/$id/groupAssignments"
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
    
    ####################################################

Function Test-JSON(){

<#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $WEJSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-AuthHeader




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
$WEJSON

)

    try {

    $WETestJSON = ConvertFrom-Json $WEJSON -ErrorAction Stop
    $validJson = $true

    }

    catch {

    $validJson = $false
    $_.Exception

    }

    if (!$validJson){
    
    Write-WELog " Provided JSON isn't in valid JSON format" " INFO" -f Red
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





$iOS = @"

{
    " @odata.type" : " #microsoft.graph.iosGeneralDeviceConfiguration" ,
    " description" : "" ,
    " displayName" : " iOS Device Restriction Policy" ,
    " accountBlockModification" : false,
    " activationLockAllowWhenSupervised" : false,
    " airDropBlocked" : false,
    " airDropForceUnmanagedDropTarget" : false,
    " airPlayForcePairingPasswordForOutgoingRequests" : false,
    " appleWatchBlockPairing" : false,
    " appleWatchForceWristDetection" : false,
    " appleNewsBlocked" : false,
    " appsSingleAppModeBundleIds" : [],
    " appsVisibilityList" : [],
    " appsVisibilityListType" : " none" ,
    " appStoreBlockAutomaticDownloads" : false,
    " appStoreBlocked" : false,
    " appStoreBlockInAppPurchases" : false,
    " appStoreBlockUIAppInstallation" : false,
    " appStoreRequirePassword" : false,
    " bluetoothBlockModification" : false,
    " cameraBlocked" : false,
    " cellularBlockDataRoaming" : false,
    " cellularBlockGlobalBackgroundFetchWhileRoaming" : false,
    " cellularBlockPerAppDataModification" : false,
    " cellularBlockVoiceRoaming" : false,
    " certificatesBlockUntrustedTlsCertificates" : false,
    " classroomAppBlockRemoteScreenObservation" : false,
    " compliantAppsList" : [],
    " compliantAppListType" : " none" ,
    " configurationProfileBlockChanges" : false,
    " definitionLookupBlocked" : false,
    " deviceBlockEnableRestrictions" : false,
    " deviceBlockEraseContentAndSettings" : false,
    " deviceBlockNameModification" : false,
    " diagnosticDataBlockSubmission" : false,
    " diagnosticDataBlockSubmissionModification" : false,
    " documentsBlockManagedDocumentsInUnmanagedApps" : false,
    " documentsBlockUnmanagedDocumentsInManagedApps" : false,
    " emailInDomainSuffixes" : [],
    " enterpriseAppBlockTrust" : false,
    " enterpriseAppBlockTrustModification" : false,
    " faceTimeBlocked" : false,
    " findMyFriendsBlocked" : false,
    " gamingBlockGameCenterFriends" : true,
    " gamingBlockMultiplayer" : false,
    " gameCenterBlocked" : false,
    " hostPairingBlocked" : false,
    " iBooksStoreBlocked" : false,
    " iBooksStoreBlockErotica" : false,
    " iCloudBlockActivityContinuation" : false,
    " iCloudBlockBackup" : true,
    " iCloudBlockDocumentSync" : true,
    " iCloudBlockManagedAppsSync" : false,
    " iCloudBlockPhotoLibrary" : false,
    " iCloudBlockPhotoStreamSync" : true,
    " iCloudBlockSharedPhotoStream" : false,
    " iCloudRequireEncryptedBackup" : false,
    " iTunesBlockExplicitContent" : false,
    " iTunesBlockMusicService" : false,
    " iTunesBlockRadio" : false,
    " keyboardBlockAutoCorrect" : false,
    " keyboardBlockPredictive" : false,
    " keyboardBlockShortcuts" : false,
    " keyboardBlockSpellCheck" : false,
    " kioskModeAllowAssistiveSpeak" : false,
    " kioskModeAllowAssistiveTouchSettings" : false,
    " kioskModeAllowAutoLock" : false,
    " kioskModeAllowColorInversionSettings" : false,
    " kioskModeAllowRingerSwitch" : false,
    " kioskModeAllowScreenRotation" : false,
    " kioskModeAllowSleepButton" : false,
    " kioskModeAllowTouchscreen" : false,
    " kioskModeAllowVoiceOverSettings" : false,
    " kioskModeAllowVolumeButtons" : false,
    " kioskModeAllowZoomSettings" : false,
    " kioskModeAppStoreUrl" : null,
    " kioskModeRequireAssistiveTouch" : false,
    " kioskModeRequireColorInversion" : false,
    " kioskModeRequireMonoAudio" : false,
    " kioskModeRequireVoiceOver" : false,
    " kioskModeRequireZoom" : false,
    " kioskModeManagedAppId" : null,
    " lockScreenBlockControlCenter" : false,
    " lockScreenBlockNotificationView" : false,
    " lockScreenBlockPassbook" : false,
    " lockScreenBlockTodayView" : false,
    " mediaContentRatingAustralia" : null,
    " mediaContentRatingCanada" : null,
    " mediaContentRatingFrance" : null,
    " mediaContentRatingGermany" : null,
    " mediaContentRatingIreland" : null,
    " mediaContentRatingJapan" : null,
    " mediaContentRatingNewZealand" : null,
    " mediaContentRatingUnitedKingdom" : null,
    " mediaContentRatingUnitedStates" : null,
    " mediaContentRatingApps" : " allAllowed" ,
    " messagesBlocked" : false,
    " notificationsBlockSettingsModification" : false,
    " passcodeBlockFingerprintUnlock" : false,
    " passcodeBlockModification" : false,
    " passcodeBlockSimple" : true,
    " passcodeExpirationDays" : null,
    " passcodeMinimumLength" : 4,
    " passcodeMinutesOfInactivityBeforeLock" : null,
    " passcodeMinutesOfInactivityBeforeScreenTimeout" : null,
    " passcodeMinimumCharacterSetCount" : null,
    " passcodePreviousPasscodeBlockCount" : null,
    " passcodeSignInFailureCountBeforeWipe" : null,
    " passcodeRequiredType" : " deviceDefault" ,
    " passcodeRequired" : true,
    " podcastsBlocked" : false,
    " safariBlockAutofill" : false,
    " safariBlockJavaScript" : false,
    " safariBlockPopups" : false,
    " safariBlocked" : false,
    " safariCookieSettings" : " browserDefault" ,
    " safariManagedDomains" : [],
    " safariPasswordAutoFillDomains" : [],
    " safariRequireFraudWarning" : false,
    " screenCaptureBlocked" : false,
    " siriBlocked" : false,
    " siriBlockedWhenLocked" : false,
    " siriBlockUserGeneratedContent" : false,
    " siriRequireProfanityFilter" : false,
    " spotlightBlockInternetResults" : false,
    " voiceDialingBlocked" : false,
    " wallpaperBlockModification" : false
}

" @



$WEAndroid = @"

{
    " @odata.type" : " #microsoft.graph.androidGeneralDeviceConfiguration" ,
    " description" : "" ,
    " displayName" : " Android Device Restriction Policy" ,
    " appsBlockClipboardSharing" : false,
    " appsBlockCopyPaste" : false,
    " appsBlockYouTube" : false,
    " bluetoothBlocked" : false,
    " cameraBlocked" : false,
    " cellularBlockDataRoaming" : true,
    " cellularBlockMessaging" : false,
    " cellularBlockVoiceRoaming" : false,
    " cellularBlockWiFiTethering" : false,
    " compliantAppsList" : [],
    " compliantAppListType" : " none" ,
    " diagnosticDataBlockSubmission" : false,
    " locationServicesBlocked" : false,
    " googleAccountBlockAutoSync" : false,
    " googlePlayStoreBlocked" : false,
    " kioskModeBlockSleepButton" : false,
    " kioskModeBlockVolumeButtons" : false,
    " kioskModeManagedAppId" : null,
    " nfcBlocked" : false,
    " passwordBlockFingerprintUnlock" : true,
    " passwordBlockTrustAgents" : false,
    " passwordExpirationDays" : null,
    " passwordMinimumLength" : 4,
    " passwordMinutesOfInactivityBeforeScreenTimeout" : null,
    " passwordPreviousPasswordBlockCount" : null,
    " passwordSignInFailureCountBeforeFactoryReset" : null,
    " passwordRequiredType" : " deviceDefault" ,
    " passwordRequired" : true,
    " powerOffBlocked" : false,
    " factoryResetBlocked" : false,
    " screenCaptureBlocked" : false,
    " deviceSharingBlocked" : false,
    " storageBlockGoogleBackup" : true,
    " storageBlockRemovableStorage" : false,
    " storageRequireDeviceEncryption" : true,
    " storageRequireRemovableStorageEncryption" : true,
    " voiceAssistantBlocked" : false,
    " voiceDialingBlocked" : false,
    " webBrowserAllowPopups" : false,
    " webBrowserBlockAutofill" : false,
    " webBrowserBlockJavaScript" : false,
    " webBrowserBlocked" : false,
    " webBrowserCookieSettings" : " browserDefault" ,
    " wiFiBlocked" : false
}

" @





$WEAADGroup = Read-Host -Prompt " Enter the Azure AD Group name where policies will be assigned"

$WETargetGroupId = (get-AADGroup -GroupName " $WEAADGroup" ).id

    if($WETargetGroupId -eq $null -or $WETargetGroupId -eq "" ){

    Write-WELog " AAD Group - '$WEAADGroup' doesn't exist, please specify a valid AAD Group..." " INFO" -ForegroundColor Red
    Write-Host
    exit

    }



Write-WELog " Adding Android Device Restriction Policy from JSON..." " INFO" -ForegroundColor Yellow

$WECreateResult_Android = Add-DeviceConfigurationPolicy -JSON $WEAndroid

Write-WELog " Device Restriction Policy created as" " INFO" $WECreateResult_Android.id
write-host
write-host " Assigning Device Restriction Policy to AAD Group '$WEAADGroup'" -f Cyan

$WEAssign_Android = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $WECreateResult_Android.id -TargetGroupId $WETargetGroupId -AssignmentType Included

Write-WELog " Assigned '$WEAADGroup' to $($WECreateResult_Android.displayName)/$($WECreateResult_Android.id)" " INFO"
Write-Host



Write-WELog " Adding iOS Device Restriction Policy from JSON..." " INFO" -ForegroundColor Yellow
Write-Host
; 
$WECreateResult_iOS = Add-DeviceConfigurationPolicy -JSON $iOS

Write-WELog " Device Restriction Policy created as" " INFO" $WECreateResult_iOS.id
write-host
write-host " Assigning Device Restriction Policy to AAD Group '$WEAADGroup'" -f Cyan
; 
$WEAssign_iOS = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $WECreateResult_iOS.id -TargetGroupId $WETargetGroupId -AssignmentType Included

Write-WELog " Assigned '$WEAADGroup' to $($WECreateResult_iOS.displayName)/$($WECreateResult_iOS.id)" " INFO"
Write-Host



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================