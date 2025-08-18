<#
.SYNOPSIS
    Intunegraph Winreporting Script

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
    We Enhanced Intunegraph Winreporting Script

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#NOTES:


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

This script has been compiled over time based on various reporting needs for Intune-managed devices - 
it has a lot of repeated stuff due to development for different needs over time. Please be nice :)

Once the CSV is exported, you can optionally import the file into an excel template for filtering and conditional formatting.
Like any public script off the interwebs, there are no guarantees expressed or implied for all functions to work properly.



Write-WELog "" " INFO"
$targetDeviceGroupName = Read-Host 'Enter the name of the desired group you would like to target for reporting. You may type " All" to target all devices'
Write-WELog "" " INFO"


$WETARGET_UPDATE_PROFILE = Read-Host " Please enter the display name of your Feature Update profile. You may enter 'All' to get device statuses from all profiles"
Write-WELog " `n" " INFO"


[CmdletBinding()]
function WE-Get-GraphPagedResult -ErrorAction Stop
{
    

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

param ([parameter(Mandatory = $true)]$WEHeaders,[parameter(Mandatory = $true)]$WEUri,[Parameter(Mandatory=$false)][switch]$WEVerb)
    $amalgam = @()
    $pages = 0
    do
    {
        $results = Invoke-RestMethod $WEUri -Method " GET" -Headers $WEHeaders
        if ($results.value)
            {$amalgam = $amalgam + $results.value}
        else
            {$amalgam = $amalgam + $results}
        $pages = $pages + 1

        if($WEVerb)
        {Write-WELog " Completed page $pages for url $WEUri" " INFO" }

        $WEUri = $results.'@odata.nextlink'

    } until (!($WEUri))

    $amalgam
}



[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Web



[CmdletBinding()]
function WE-Connect_To_Graph {
    #App registration
    $tenant = " primary-or-federated-domain"
    $clientId = " APPLICATION-ID"
    $clientSecret = " SECRET-VALUE"
    $clientSecret = [System.Web.HttpUtility]::UrlEncode($clientSecret)

    #Header and body request variables
    $headers = New-Object -ErrorAction Stop " System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add(" Content-Type" , " application/x-www-form-urlencoded" )
    $body = " grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
    $body = $body + -join(" &client_id=" , $clientId, " &client_secret=" , $clientSecret)
    $response = Invoke-RestMethod " https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $header -Body $body
    $token = -join(" Bearer " , $response.access_token)
    #Reinstantiate headers
    $headers = New-Object -ErrorAction Stop " System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add(" Authorization" , $token)
    $headers.Add(" Content-Type" , " application/json" )

    $headers
    Start-Sleep -Seconds 3
}

$headers = Connect_To_Graph


<#
$tenant = " primary-or-federated-domain"
$clientId = " APPLICATION-ID"

$WEAccessToken = Get-MsalToken -TenantId $tenant -ClientId $clientId -ForceRefresh
$authHeader = $WEAccessToken.CreateAuthorizationHeader()

$headers = New-Object -ErrorAction Stop " System.Collections.Generic.Dictionary[[String],[String]]"

$headers.Add(" Content-Type" , " application/json" )
$headers.Add(" Authorization" , " $($authHeader)" )
$headers.Add(" Accept" , " application/json" )






$intuneDevices = Get-GraphPagedResult -Uri " https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'" -Headers $headers -Verb



if($targetDeviceGroupName -ne " All" )
{
    Write-WELog " Querying Azure group by display name..." " INFO"
    $groupPayload = Invoke-RestMethod " https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$($targetDeviceGroupName)'" -Method " GET" -Headers $headers
    if ($groupPayload.value.Length -eq 0)
    {
        Write-Error " Group with name $targetDeviceGroupName does not exist. Closing Script..."
        exit -1
    }

    $theGroup = $groupPayload.value[0]
    $groupDeviceIds = @()
    Write-WELog " Querying members of retrieved Azure group..." " INFO"
    $groupDevices = Get-GraphPagedResult -Uri " https://graph.microsoft.com/beta/groups/$($theGroup.id)/members" -Headers $headers -Verb

    foreach($dev in $groupDevices)
    {
        $groupDeviceIds = $groupDeviceIds + $dev.deviceId
    }
}



$updateRingsStatus = @()

$updateRings = Get-GraphPagedResult -Uri " https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=(isof('microsoft.graph.windowsUpdateForBusinessConfiguration'))" -Headers $headers -Verb
$ringCount = 1

foreach($ring in $updateRings)
{
    Write-WELog " Getting device details from Ring $ringCount ($($ring.displayName))..." " INFO"
   ;  $ringDeviceStatusAll = Get-GraphPagedResult -Uri " https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($ring.id)/deviceStatuses" -Headers $headers -Verb
    #Filter to System account, omit UPN entries
   ;  $ringDeviceStatus = $ringDeviceStatusAll | Where-Object {$_.UserPrincipalName -eq " System account" }
    
    Write-WELog " Updating status array for ring $ringCount..." " INFO"

    foreach($device in $ringDeviceStatus)
    {
       ;  $updateRingsStatus = $updateRingsStatus + New-Object -TypeName PSObject -Property @{
            " Ring" = $($ring.displayName); 
            " Device" = $($device.deviceDisplayName); 
            " Status" = $($device.status);
        }
    }
    $ringCount = $ringCount + 1
}

Start-Sleep -Seconds 5



$headers = Connect_To_Graph



Write-WELog " Getting Device Health Attestation Report..." " INFO"
$deviceHealthAttestationReport = Get-GraphPagedResult -Uri " https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=isof('microsoft.graph.windowsManagedDevice')&`$select=deviceHealthAttestationState,deviceName,operatingSystem,id" -Headers $headers -Verb


Write-WELog " Getting Device Encryption Report..." " INFO"
$encryptionReport = Get-GraphPagedResult -Uri " https://graph.microsoft.com/beta/deviceManagement/managedDeviceEncryptionStates?`$select=advancedBitLockerStates,deviceName,encryptionReadinessState" -Headers $headers -Verb

<# This call seems to often timeout when paired with the previous calls. Re-running might work, but repeated authentication on line 160 instead.
if(!($encryptionReport))
{
    Write-WELog " Gateway timeout likely occured - re-running call..." " INFO"
    $encryptionReport = Get-GraphPagedResult -Uri " https://graph.microsoft.com/beta/deviceManagement/managedDeviceEncryptionStates?`$select=advancedBitLockerStates,deviceName,encryptionReadinessState" -Headers $headers -Verb
}







$profiles = Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles" -Method " GET" -Headers $headers

if($WETARGET_UPDATE_PROFILE -eq 'All')
{
    $featureUpdateReport = @()
    Write-WELog " Please wait - this make take a bit to export all $($profiles.value.count) Feature Update profiles..." " INFO"

    foreach($profile in $profiles.value)
    {
        $profileName = $profile.displayName
       ;  $profileId = $profile.id

        Write-Output " Now assessing profile $profileName"
       ;  $payload = @{
            reportName = " FeatureUpdateDeviceState" ;
            filter = " (PolicyId eq '$($profileId)')" ;
            localizationType = " LocalizedValuesAsAdditionalColumn" ;
            select = @(
                " PolicyId" ,
                " PolicyName" ,
                " FeatureUpdateVersion" ,
                " DeviceId" ,
                " AADDeviceId" ,
                " PartnerPolicyId" ,
                " EventDateTimeUTC" ,
                " LastSuccessfulDeviceUpdateStatus" ,
                " LastSuccessfulDeviceUpdateSubstatus" ,
                " LastSuccessfulDeviceUpdateStatusEventDateTimeUTC" ,
                " CurrentDeviceUpdateStatus" ,
                " CurrentDeviceUpdateSubstatus" ,
                " CurrentDeviceUpdateStatusEventDateTimeUTC" ,
                " LatestAlertMessage" ,
                " LatestAlertMessageDescription" ,
                " LatestAlertRecommendedAction" ,
                " LatestAlertExtendedRecommendedAction" ,
                " UpdateCategory" ,
                " WindowsUpdateVersion" ,
                " LastWUScanTimeUTC" ,
                " Build" ,
                " DeviceName" ,
                " OwnerType" ,
                " UPN" ,
                " AggregateState"        
            );
        }

        $payload = $payload | ConvertTo-Json

        #Generate job to export report
        $jobGenResult = Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs" -Method " POST" -Headers $headers -Body $payload
        Write-Output $jobGenResult

        #Keep polling til the blob link appears
        Write-Output " Now starting extraction of report for profile $profileName"
        $reportUrl = ""

        while($true)
        {
            Start-Sleep -Seconds 10
            $report = Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$($jobGenResult.id)')" -Method " GET" -Headers $headers
            if($null -ne $report.url)
            {
                Write-Output " Report extraction successful. Url loaded. Now pulling report..."
                $reportUrl = $report.url
                break
            }
            Write-Output " Report unavailable. Trying again in 10 seconds..."
        }

        #In case there are special characters, which screws up downloading and creating directory/zip
        $trimmedProfileName = $profileName -replace '[^A-Za-z0-9\s]',''

        if(Test-Path " $psscriptroot\data\$trimmedProfileName" )
        {
            Remove-Item -ErrorAction Stop " -Force $psscriptroot\data\$trimmedProfileName" -Force -Recurse
        }

        New-Item -Path " $psscriptroot\data" -Name " $trimmedProfileName" -ItemType " directory"
        Invoke-WebRequest -Uri $reportUrl -OutFile " $psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName.zip"
        Write-Output " Report downloaded for profile $profileName"

        Expand-Archive " $psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName.zip" -DestinationPath " $psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName"

        $theFileName = Get-ChildItem -Path " $psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName" | Select -ExpandProperty FullName | Select-Object -first 1
        $featureUpdateReport = $featureUpdateReport + Import-Csv -Path $theFileName
    }
}

else
{
    $theProfile = @()
    foreach($p in $profiles.value){
        if ($p.displayName -eq $($WETARGET_UPDATE_PROFILE)){
            $theProfile = $p
            break
        }
    }

   ;  $profileName = $theProfile.displayName
    Write-Output " Now assessing profile $profileName"

   ;  $payload = @{
        reportName = " FeatureUpdateDeviceState" ;
        filter = " (PolicyId eq '$($theProfile.id)')" ;
        localizationType = " LocalizedValuesAsAdditionalColumn" ;
        select = @(
            " PolicyId" ,
            " PolicyName" ,
            " FeatureUpdateVersion" ,
            " DeviceId" ,
            " AADDeviceId" ,
            " PartnerPolicyId" ,
            " EventDateTimeUTC" ,
            " LastSuccessfulDeviceUpdateStatus" ,
            " LastSuccessfulDeviceUpdateSubstatus" ,
            " LastSuccessfulDeviceUpdateStatusEventDateTimeUTC" ,
            " CurrentDeviceUpdateStatus" ,
            " CurrentDeviceUpdateSubstatus" ,
            " CurrentDeviceUpdateStatusEventDateTimeUTC" ,
            " LatestAlertMessage" ,
            " LatestAlertMessageDescription" ,
            " LatestAlertRecommendedAction" ,
            " LatestAlertExtendedRecommendedAction" ,
            " UpdateCategory" ,
            " WindowsUpdateVersion" ,
            " LastWUScanTimeUTC" ,
            " Build" ,
            " DeviceName" ,
            " OwnerType" ,
            " UPN" ,
            " AggregateState"        
        );
    }

    $payload = $payload | ConvertTo-Json

    #Generate job to export report
    $jobGenResult = Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs" -Method " POST" -Headers $headers -Body $payload
    Write-Output $jobGenResult

    #Keep polling til the blob link appears
    Write-Output " Now starting extraction of report for profile $profileName"
    $reportUrl = ""

    while($true)
    {
            Start-Sleep -Seconds 10
            $report = Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$($jobGenResult.id)')" -Method " GET" -Headers $headers
            if($null -ne $report.url)
            {
                Write-Output " Report extraction successful. Url loaded. Now pulling report..."
                $reportUrl = $report.url
                break
            }
            Write-Output " Report unavailable. Trying again in 10 seconds..."
    }

    #In case there are special characters, which screws up downloading and creating directory/zip
    $trimmedProfileName = $profileName -replace '[^A-Za-z0-9\s]',''

    if(Test-Path " $psscriptroot\data\$trimmedProfileName" )
    {
            Remove-Item -ErrorAction Stop " -Force $psscriptroot\data\$trimmedProfileName" -Force -Recurse
    }

    New-Item -Path " $psscriptroot\data" -Name " $trimmedProfileName" -ItemType " directory"
    Invoke-WebRequest -Uri $reportUrl -OutFile " $psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName.zip"
    Write-Output " Report downloaded for profile $profileName"

    Expand-Archive " $psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName.zip" -DestinationPath " $psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName"

    $theFileName = Get-ChildItem -Path " $psscriptroot\data\$trimmedProfileName\report_$trimmedProfileName" | Select -ExpandProperty FullName | Select-Object -first 1
    $featureUpdateReport = Import-Csv -Path $theFileName
}



$headers = Connect_To_Graph




$outarray = @()
$deviceCount = 0

foreach($device in $intuneDevices)
{

    if($targetDeviceGroupName -ne " All" -and $groupDeviceIds -notcontains $device.azureActiveDirectoryDeviceId)
    {
        continue
    }
    $deviceCount = $deviceCount + 1
    

    $deviceId = $device.id
    $deviceAADid = $device.azureActiveDirectoryDeviceId
    $deviceName = $device.deviceName
    $deviceLastSync = $device.lastSyncDateTime
    $deviceSync = $deviceLastSync.split(" T" )[0]         #This will be in UTC
    #$deviceSync = [datetime]::Parse($deviceLastSync).ToString('MM-dd-yyyy')
    $deviceUPN = $device.userPrincipalName
    $deviceCompliance = $device.complianceState
    $deviceJoinType = $device.joinType
    $deviceAutopilotEnrolled = $device.autopilotEnrolled
    $deviceEnrollmentProfileName = $device.enrollmentProfileName

    #Additional call for hardware details...
    $deviceAdditionalInfo = Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($deviceId)?`$select=chassisType,ethernetMacAddress,hardwareInformation,physicalMemoryInBytes,processorArchitecture,roleScopeTagIds" -Method " GET" -Headers $headers
    $deviceHardwareInfo = $deviceAdditionalInfo.hardwareInformation
    [string]$deviceScopeTags = $deviceAdditionalInfo.roleScopeTagIds
    $deviceSerial = $device.serialNumber
    $deviceChassis = $deviceAdditionalInfo.chassisType
    $deviceManufacturer = $deviceHardwareInfo.manufacturer
    $deviceModel = $deviceHardwareInfo.model
    $deviceBiosVersion = $deviceHardwareInfo.systemManagementBIOSVersion
    $deviceOsVersion = $device.osVersion
    $deviceOsEdition = $deviceHardwareInfo.operatingSystemEdition
    $deviceArchitecture = $deviceAdditionalInfo.processorArchitecture
    $deviceTpmSpecVersion = $deviceHardwareInfo.tpmSpecificationVersion
    $deviceTpmManufacturer = $deviceHardwareInfo.tpmManufacturer
    $deviceTpmMfrVersion = $deviceHardwareInfo.tpmVersion
    $deviceIpAddress = $deviceHardwareInfo.ipAddressV4
    $deviceIpSubnet = $deviceHardwareInfo.subnetAddress
    [string]$deviceWiredIpAddress = $deviceHardwareInfo.wiredIPv4Addresses
    $deviceEthernetMacAddress = $deviceAdditionalInfo.ethernetMacAddress
    $deviceTotalStorage = $deviceHardwareInfo.totalStorageSpace
    $deviceFreeStorage = $deviceHardwareInfo.freeStorageSpace
    $deviceLicenseStatus = $deviceHardwareInfo.deviceLicensingStatus

    #additional call for Defender info...
    $deviceWinSecurity = Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($deviceId)/windowsProtectionState" -Method " GET" -Headers $headers
    $deviceMalwareProtection = $deviceWinSecurity.malwareProtectionEnabled
    $deviceWinSecurityState = $deviceWinSecurity.deviceStatuses
    $deviceRealTimeProtection = $deviceWinSecurity.realTimeProtectionEnabled
    $deviceNetworkInspectionEnabled = $deviceWinSecurity.networkInspectionSystemEnabled
    $deviceQuickScanOverdue = $deviceWinSecurity.quickScanOverdue
    $deviceFullScanOverdue = $deviceWinSecurity.fullScanOverdue
    $deviceSignatureUpdateRequired = $deviceWinSecurity.signatureUpdateOverdue
    $deviceRebootRequired = $deviceWinSecurity.rebootRequired
    $deviceFullScanRequired = $deviceWinSecurity.fullScanRequired
    $deviceSecurityEngineVersion = $deviceWinSecurity.engineVersion
    $deviceSecuritySignatureVersion = $deviceWinSecurity.signatureVersion
    $deviceSecurityAntiMalwareVersion = $deviceWinSecurity.antiMalwareVersion
    if($deviceWinSecurity.lastQuickScanDateTime){$deviceSecuritylastQuickScan = ($deviceWinSecurity.lastQuickScanDateTime).split(" T" )[0]} else {$deviceSecuritylastQuickScan = " unknown" }
    if($deviceWinSecurity.lastFullScanDateTime){$deviceSecuritylastFullScan = ($deviceWinSecurity.lastFullScanDateTime).split(" T" )[0]} else {$deviceSecuritylastFullScan = " unknown" }
    $deviceSecuritylastQuickScanSignatureVersion = $deviceWinSecurity.lastQuickScanSignatureVersion
    $deviceSecuritylastFullScanSignatureVersion = $deviceWinSecurity.lastFullScanSignatureVersion
    if($deviceWinSecurity.lastReportedDateTime){$deviceSecuritylastReported = ($deviceWinSecurity.lastReportedDateTime).split(" T" )[0]} else {$deviceSecuritylastReported = " unknown" }
    $deviceSecurityproductStatus = $deviceWinSecurity.productStatus
    $deviceSecurityisVirtualMachine = $deviceWinSecurity.isVirtualMachine
    $deviceSecuritytamperProtectionEnabled = $deviceWinSecurity.tamperProtectionEnabled

    #device health attestation info...
    $deviceHealthAttestation = $null
    foreach($report in $deviceHealthAttestationReport)
    {
        if($report.deviceName -eq $deviceName)
        {
            $deviceHealthAttestation = $report.deviceHealthAttestationState
            $deviceHealthAttestationStatus = $deviceHealthAttestation.deviceHealthAttestationStatus
            $deviceHealthAttestationSupportStatus = $deviceHealthAttestation.healthAttestationSupportStatus
            $deviceHealthAttestationKey = $deviceHealthAttestation.attestationIdentityKey
            $deviceBitLockerStatus = $deviceHealthAttestation.bitLockerStatus
            $deviceSecureBoot = $deviceHealthAttestation.secureBoot
            $deviceBootDebugging = $deviceHealthAttestation.bootDebugging
            $deviceOsKernelDebugging = $deviceHealthAttestation.operatingSystemKernelDebugging
            $deviceCodeIntegrity = $deviceHealthAttestation.codeIntegrity
            $deviceTestSigning = $deviceHealthAttestation.testSigning
            $deviceSafeMode = $deviceHealthAttestation.safeMode
            $devicesWindowsPE = $deviceHealthAttestation.windowsPE
            $deviceEarlyLaunchAntiMalwareDriverProtection = $deviceHealthAttestation.earlyLaunchAntiMalwareDriverProtection
            $deviceVirtualSecureMode = $deviceHealthAttestation.virtualSecureMode
            $deviceAttestationTpmVer = $deviceHealthAttestation.tpmVersion
            $deviceMemoryIntegrityProtection = $deviceHealthAttestation.memoryIntegrityProtection
            $deviceMemoryAccessProtection = $deviceHealthAttestation.memoryAccessProtection
            $deviceVirtualizationBasedSecurity = $deviceHealthAttestation.virtualizationBasedSecurity
            $deviceFirmwareProtection = $deviceHealthAttestation.firmwareProtection
            $deviceSystemManagementMode = $deviceHealthAttestation.systemManagementMode
            $deviceSecuredCorePC = $deviceHealthAttestation.securedCorePC
            break
        }
    }
    if(!($deviceHealthAttestation))
    {
        $deviceHealthAttestationStatus = " Unknown"
        $deviceHealthAttestationSupportStatus = " Unknown"
        $deviceHealthAttestationKey = " Unknown"
        $deviceBitLockerStatus = " Unknown"
        $deviceSecureBoot = " Unknown"
        $deviceBootDebugging = " Unknown"
        $deviceOsKernelDebugging = " Unknown"
        $deviceCodeIntegrity = " Unknown"
        $deviceTestSigning = " Unknown"
        $deviceSafeMode = " Unknown"
        $devicesWindowsPE = " Unknown"
        $deviceEarlyLaunchAntiMalwareDriverProtection = " Unknown"
        $deviceVirtualSecureMode = " Unknown"
        $deviceAttestationTpmVer = " Unknown"
        $deviceMemoryIntegrityProtection = " Unknown"
        $deviceMemoryAccessProtection = " Unknown"
        $deviceVirtualizationBasedSecurity = " Unknown"
        $deviceFirmwareProtection = " Unknown"
        $deviceSystemManagementMode = " Unknown"
        $deviceSecuredCorePC = " Unknown"
    }

    #MDM over GPO status, if applied
    $deviceMDMoverGPO = $device.preferMdmOverGroupPolicyAppliedDateTime
    if($deviceMDMoverGPO = " 0001-01-01T00:00:00Z" ){
        $deviceMDMoverGPOstring = " Not applied."
    }
    else
    {
        $deviceMDMoverGPOstring = $deviceMDMoverGPO
    }

    #managed by state (Intune devices query doesn't appear to pull configMgr-only/cloud-attached devices, but including if statement to be safe)
    if($device.managementAgent -eq " configurationManagerClientMdm" ){
        $deviceManagement = " Co-Managed"
    }
    elseif($device.managementAgent -eq " mdm" )
    {
        $deviceManagement = " Intune"
    }
    elseif($device.managementAgent -eq " configurationManagerClient" )
    {
        $deviceManagement = " ConfigMgr"
    }
    else
    {
        $deviceManagement = $device.managementAgent
    }

    #encryption state
    if(($device.isEncrypted) -eq " True" ){
        $deviceEncryptionStatus = " Encrypted"
    }
    else
    {
        $deviceEncryptionStatus = " Not encrypted"
    }

    #Search encryption report for matching device
    foreach($erRecord in $encryptionReport)
    {
        if($erRecord.deviceName -eq $deviceName)
        {
            $deviceEncryptionReport_ReadinessState = $erRecord.encryptionReadinessState
            $deviceEncryptionReport_TPMSpecificationVersion = $erRecord.tpmSpecificationVersion
            $deviceEncryptionReport_AdvancedBitLockerStates = $erRecord.advancedBitLockerStates
            break
        }
    }

    #SCCM information for co-managed devices, where applicable
    $deviceSCCMclientHealth = $device.configurationManagerClientHealthState.state
    $deviceSCCMclientLastSync = $device.configurationManagerClientHealthState.lastSyncDateTime
    if($deviceManagement -eq " Intune" ){
        $deviceSCCMclientHealth = " Intune-only"
        $deviceSCCMclientSync = " N/A"
    }
    else
    {
        $deviceSCCMclientSync = $deviceSCCMclientLastSync.split(" T" )[0]     #Will display in UTC
        #$deviceSCCMclientSync = [datetime]::Parse($deviceSCCMclientLastSync).ToString('MM-dd-yyyy')
    }
    $deviceComanagementSettings = $device.configurationManagerClientEnabledFeatures
    $deviceComanagementApps = " N/A"
    $deviceComanagementResourceAccess = " N/A"
    $deviceComanagementDeviceConfig = " N/A"
    $deviceComanagementCompliance = " N/A"
    $deviceComanagementWindowsUpdate = " N/A"
    $deviceComanagementEndpointProtection = " N/A"
    $deviceComanagementOfficeApps = " N/A"
    
    if($deviceManagement -eq " Co-Managed" ){
        if($deviceComanagementSettings.ModernApps -eq " True" ) {$deviceComanagementApps = " Intune" } else {$deviceComanagementApps = " SCCM" }
        if($deviceComanagementSettings.resourceAccess -eq " True" ) {$deviceComanagementResourceAccess = " Intune" } else {$deviceComanagementResourceAccess = " SCCM" }
        if($deviceComanagementSettings.deviceConfiguration -eq " True" ) {$deviceComanagementDeviceConfig = " Intune" } else {$deviceComanagementDeviceConfig = " SCCM" }
        if($deviceComanagementSettings.compliancePolicy -eq " True" ) {$deviceComanagementCompliance = " Intune" } else {$deviceComanagementCompliance = " SCCM" }
        if($deviceComanagementSettings.windowsUpdateForBusiness -eq " True" ) {$deviceComanagementWindowsUpdate = " Intune" } else {$deviceComanagementWindowsUpdate = " SCCM" }
        if($deviceComanagementSettings.endpointProtection -eq " True" ) {$deviceComanagementEndpointProtection = " Intune" } else {$deviceComanagementEndpointProtection = " SCCM" }
        if($deviceComanagementSettings.officeApps -eq " True" ) {$deviceComanagementOfficeApps = " Intune" } else {$deviceComanagementOfficeApps = " SCCM" }
    }

    #logged on users
    $usersLoggedOn = $device.usersLoggedOn.userId

    #Group memberships of device
    Write-Information " Getting generic device profile of $deviceSerial..."
    $deviceNormalProfile = (Invoke-RestMethod " https://graph.microsoft.com/beta/devices?`$filter=displayName eq '$($deviceName)'" -Method " GET" -Headers $headers).value

    if($null -eq $deviceNormalProfile){
        Write-Warning " Azure device object could not be found."
    }
    elseif($deviceNormalProfile.length -gt 1){

        foreach($object in $deviceNormalProfile){
            if($object.deviceId -eq $device.azureActiveDirectoryDeviceId){
                $deviceAzureId = $object.deviceId
                $deviceAzureObjId = $object.id
                break
            }
        }
    }

    else
    {
        $deviceAzureId = $deviceNormalProfile.deviceId
        $deviceAzureObjId = $deviceNormalProfile.id
    }

    Write-Information " Getting group memberships of device $deviceSerial..."
    $deviceGroupSearch = Invoke-RestMethod " https://graph.microsoft.com/beta/devices/$($deviceAzureObjId)/memberOf" -Method " GET" -Headers $headers
    $deviceGroupValue = $deviceGroupSearch.value
    $deviceGroups = @()
    $deviceGroupsString = $null

    foreach($group in $deviceGroupValue){
       ;  $deviceGroups = $deviceGroups + $group.displayName
       ;  $deviceGroupsString = $deviceGroups -join " ; "
    }


    #Feature Update Status
    $deviceFeatureUpdateStatus = $null
    foreach($entry in $featureUpdateReport){
        $featUpdate_Status = $entry.CurrentDeviceUpdateSubstatus_loc
        $featUpdate_deviceName = $entry.DeviceName

        if($featUpdate_deviceName -eq $deviceName){
            $deviceFeatureUpdateStatus = $featUpdate_Status
            break
        }
    }

    # get list of all compliance policies of this particular device
    Write-Information " Getting compliance policy for device $deviceSerial ..."
    $deviceCompliancePolicy = (Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceId')/deviceCompliancePolicyStates" -Method " GET" -Headers $headers).value
    $deviceComplianceStatus_Detailed = $null
    $settingArray = @()
    $complianceArray = @()
    $windowsPolicyFound = $WEFalse
    $defaultPolicyFound = $WETrue

    # Compliance policy details (please update line 382 below - this way Intune's default compliance state is not reported)
    foreach($policy in $deviceCompliancePolicy){
        if($policy.platformType -like " *windows*" ){

            $windowsPolicyFound = $WETrue
           ;  $deviceComplianceId = $policy.id
            Write-Information " Getting compliance settings states for device $deviceName..."
           ;  $deviceComplianceStatus_Detailed = (Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceId')/deviceCompliancePolicyStates('$deviceComplianceId')/settingStates" -Method " GET" -Headers $headers).value
            $deviceComplianceStatus_Detailed | Select @{n = 'deviceName'; e = { $deviceName } }, state, setting

            if($deviceComplianceStatus_Detailed.Length -eq 0){
                $complianceArray = $complianceArray + " Targeted Compliance Policy not evaluated."
            }

            else
            {
                foreach($setting in $deviceComplianceStatus_Detailed)
                {
                    $settingName = $setting.setting
                    $settingName = $settingName.Split(" ." ) | Select -Index 1
                    $settingState = $setting.state
                    $settingUPN = $setting.userPrincipalName

                    if($settingArray -notcontains " ($settingUPN) $settingName = $settingState" ){
                        $settingArray = $settingArray + " ($settingUPN) $settingName = $settingState"
                    }
                }

                #Only include UPN based states if system and UPN states are present 
                foreach($result in $settingArray){
                    if($result -like " *System account*" -and $settingArray -like " *@*" ){
                        continue
                    }
                    elseif($complianceArray -contains $result){
                        continue
                    }
                    else
                    {
                        $complianceArray = $complianceArray + $result
                    }
                }

            }
        }
        elseif($policy.displayName -like " Default Device Compliance Policy" )
        {
            $defaultPolicyFound = $true
           ;  $deviceComplianceId = $policy.id
            Write-Information " Getting compliance settings states for device $deviceName..."
           ;  $deviceComplianceStatus_Detailed = (Invoke-RestMethod " https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceId')/deviceCompliancePolicyStates('$deviceComplianceId')/settingStates" -Method " GET" -Headers $headers).value
            $deviceComplianceStatus_Detailed | Select @{n = 'deviceName'; e = { $deviceName } }, state, setting

            if($deviceComplianceStatus_Detailed.Length -eq 0){
                $complianceArray = $complianceArray + " Default Compliance Policy not evaluated."
            }

            else
            {
                foreach($setting in $deviceComplianceStatus_Detailed)
                {
                    $settingName = $setting.setting
                    $settingName = $settingName.Split(" ." ) | Select -Index 1
                    $settingState = $setting.state
                    $settingUPN = $setting.userPrincipalName

                    if($settingArray -notcontains " ($settingUPN) $settingName = $settingState" ){
                        $settingArray = $settingArray + " ($settingUPN) $settingName = $settingState"
                    }
                }

                #Only include UPN based states if system and UPN states are present 
                foreach($result in $settingArray){
                    if($result -like " *System account*" -and $settingArray -like " *@*" ){
                        continue
                    }
                    elseif($complianceArray -contains $result){
                        continue
                    }
                    else
                    {
                       ;  $complianceArray = $complianceArray + $result
                    }
                }

            }
        }

        #Combine compliance results into single string
       ;  $deviceComplianceStatus_DetailedString = $complianceArray -join " ; "
    }

    if($windowsPolicyFound -eq $WEFalse){
        $deviceComplianceStatus_DetailedString = 'Windows-based Compliance Policy not assigned.'
    }

    #Device Update Ring Status
    foreach($ring in $updateRingsStatus)
    {
        if($($ring.Device) -eq $deviceName)
        {
            $deviceUpdateRing = $($ring.Ring)
            $deviceUpdateRingStatus = $($ring.Status)
            break
        }
    }

    #############################################################

    #Add desired labels and variables to array for csv export
    $record = [ordered] @{
        'Name' = $deviceName
        'Serial' = $deviceSerial
        'Associate UPN' = $deviceUPN
        'Last Device Sync Time' = $deviceSync
        'Managed By' = $deviceManagement
        'OS Version' = $deviceOsVersion
        'OS Edition' = $deviceOsEdition
        'Feature Update Status' = $deviceFeatureUpdateStatus
        'Update Ring' = $deviceUpdateRing
        'Update Ring Status' = $deviceUpdateRingStatus
        'Encryption Status' = $deviceEncryptionStatus
        'BitLocker Status' = $deviceBitLockerStatus
        'Encryption Readiness State' = $deviceEncryptionReport_ReadinessState
        'Encryption Advanced State' = $deviceEncryptionReport_AdvancedBitLockerStates
        'TPM SpecVersion' = $deviceTpmSpecVersion
        'TPM SpecVersion (H.A.)' = $deviceAttestationTpmVer
        'TPM Manufacturer' = $deviceTpmManufacturer
        'TPM Mfr Version' = $deviceTpmMfrVersion
        'BIOS Version' = $deviceBiosVersion
        'Secure Boot' = $deviceSecureBoot
        'Model' = $deviceModel
        'Manufacturer' = $deviceManufacturer
        'Is Virtual Machine' = $deviceSecurityisVirtualMachine
        'Chassis Type' = $deviceChassis
        'Processor Architecture' = $deviceArchitecture
        'Compliance Status' = $deviceCompliance
        'Detailed Compliance Settings' = $deviceComplianceStatus_DetailedString
        'SCCM Client Health' = $deviceSCCMclientHealth
        'SCCM Client Last Sync' = $deviceSCCMclientSync
        'Co-Management: Compliance' = $deviceComanagementCompliance
        'Co-Management: Device Configuration' = $deviceComanagementDeviceConfig
        'Co-Management: Endpoint Protection' = $deviceComanagementEndpointProtection
        'Co-Management: Resource Access' = $deviceComanagementResourceAccess
        'Co-Management: Client Apps' = $deviceComanagementApps
        'Co-Management: Office C2R Apps' = $deviceComanagementOfficeApps
        'Co-Management: Windows Updates' = $deviceComanagementWindowsUpdate
        'MDM over GPO Applied' = $deviceMDMoverGPOstring
        'Intune Device ID' = $deviceId
        'Azure Device ID' = $deviceAzureId
        'Scope Tags' = $deviceScopeTags
        'Group Memberships' = $deviceGroupsString
        'Users Logged On' = $usersLoggedOn
        'IP Address' = $deviceIpAddress
        'IP Subnet' = $deviceIpSubnet
        'Wired IP Address' = $deviceWiredIpAddress
        'Ethernet Mac Address' = $deviceEthernetMacAddress
        'Total Storage' = $deviceTotalStorage
        'Free Storage' = $deviceFreeStorage
        'Health Attestation Status' = $deviceHealthAttestationStatus
        'Health Attestation Support' = $deviceHealthAttestationSupportStatus
    }

    $outarray = $outarray + New-Object -ErrorAction Stop PsObject -property $record

    #Each device sets off 6 calls.  1500 devices is 9000 calls.  Rest for 10 seconds.  Process time for one device is estimated at 1-2 seconds.
    #This means 1500 devices take approximately 1500 seconds, or 25 minutes.  Graph limit window is 10,000 calls per 10 minutes.  Resting is to make the window absolute and to not interfere in company business.
    #
    if($deviceCount % 1500 -eq 0)
    {
        Write-Output " $deviceCount devices have been processed so far.  Now sleeping for 10 seconds to avoid graph limiting..."
        Start-Sleep -Seconds 10
        Write-WELog " Re-authenticating with app registration..." " INFO"
       ;  $headers = Connect_To_Graph


        #NOTE: This if statement can be used if you need to re-authenticate after a larger number of devices (needs to be a multiple of the number above)
        <#if($deviceCount % 3000 -eq 0)
        {
            Write-WELog " Re-authenticating with app registration..." " INFO"
           ;  $headers = Connect_To_Graph
        }
        #>
    }

}



Write-WELog " Reporting Complete. Exporting the final csv..." " INFO"
$outarray | export-csv " C:\Users\Public\Desktop\Intune_WindowsPCs_$($targetDeviceGroupName)_Report.csv" -NoTypeInformation -Force 




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
