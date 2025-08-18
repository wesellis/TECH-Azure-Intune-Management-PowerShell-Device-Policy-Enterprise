<#
.SYNOPSIS
    Bitlockerremedy

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
    We Enhanced Bitlockerremedy

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


Disable-AzContextAutosave –Scope Process



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

Disable-AzContextAutosave –Scope Process
$connection = Get-AutomationConnection -Name AzureRunAsConnection
$certificate = Get-AutomationCertificate -Name AzureRunAsCertificate
$connectionResult = Connect-AzAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationId $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint


$WEGraphConnection = Get-MsalToken -ClientCertificate $certificate -ClientId $connection.ApplicationID -TenantId  $connection.TenantID 
$WEHeader =  @{Authorization = " Bearer $($WEGraphConnection.AccessToken)" }



[string]$WEWorkspaceID = Get-AutomationVariable -Name 'BitlockerRemedyWorkspaceID'


$WEExposedKeysQuery = @'
AuditLogs
| where OperationName == " Read BitLocker key" and TimeGenerated > ago(65m) 
| extend MyDetails = tostring(AdditionalDetails[0].value)
| extend userPrincipalName_ = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| parse MyDetails with * " key ID: '" MyRecoveryKeyID  " '. Backed up from device: '" MyDevice " '" *
| project MyDevice, MyRecoveryKeyID, userPrincipalName_, TimeGenerated
'@

$WEDeletedKeysQuery = @'
AuditLogs
| where OperationName == " Delete BitLocker key" and TimeGenerated > ago(65m) 
| extend MyRecoveryKeyID = tostring(TargetResources[0].displayName)
| project MyRecoveryKeyID, ActivityDateTime
'@

$WEIntuneKeyRolloverQuery = @'
IntuneAuditLogs 
| where OperationName == " rotateBitLockerKeys ManagedDevice" and TimeGenerated > ago(65m)  
| extend DeviceID = tostring(parse_json(tostring(parse_json(Properties).TargetObjectIds))[0])
| project DeviceID, ResultType
'@


$WEAllKeyExposures = Invoke-AZOperationalInsightsQuery -WorkspaceId $WEWorkspaceID -Query $WEExposedKeysQuery
$WEMyAutoKeyDeletion = Invoke-AZOperationalInsightsQuery -WorkspaceId $WEWorkspaceID -Query $WEDeletedKeysQuery
$WEMyIntuneRolloverActions = Invoke-AZOperationalInsightsQuery -WorkspaceId $WEWorkspaceID -Query $WEIntuneKeyRolloverQuery

$WEDeviceToRolloverIDs = @()
foreach($WEKeyExposure in $WEAllKeyExposures.Results){
    if ($WEKeyExposure.MyRecoveryKeyID -in $WEMyAutoKeyDeletion.Results.MyRecoveryKeyID){
        #Write-Output " Device $($WEKeyExposure.MyDevice) with key $($WEKeyExposure.MyRecoveryKeyID) has been replaced OK"
    }elseif ($WEKeyExposure -notin $WEMyAutoKeyDeletion.Results.MyRecoveryKeyID) {
        #Write-Output " Device $($WEKeyExposure.MyDevice) with key $($WEKeyExposure.MyRecoveryKeyID) needs a rollover"
        $WEDeviceToRolloverIDs = $WEDeviceToRolloverIDs + $WEKeyExposure.MyDevice
    }
}

if ([string]::IsNullOrEmpty($WEDeviceToRolloverIDs)){
    Write-Output " Query returned empty. Possibly issues with delay in query"
    } else {
    #Write-Output " Device to rollover IDs $WEDeviceToRolloverIDs"
    foreach($WEDeviceToRolloverID in $WEDeviceToRolloverIDs){
        #write-output $WEDeviceToRolloverID
        $WEGetManagedDeviceIDUri = " https://graph.microsoft.com/beta/deviceManagement/managedDevices?filter=azureADDeviceID eq '$WEDeviceToRolloverID'"
        #Write-Output $WEGetManagedDeviceIDUri
        $WEManagedDeviceResult = Invoke-RestMethod -Method GET -Uri $WEGetManagedDeviceIDUri -ContentType " application/json" -Headers $WEHeader -ErrorAction Stop
        write-output " Evaluating $($WEManagedDeviceResult.value.deviceName)"
        $WEManagedDeviceID = $WEManagedDeviceResult.value.id 
        if ($WEManagedDeviceID -notin $WEMyIntuneRolloverActions.Results.DeviceID){
           ;  $WERolloverKeyUri = " https://graph.microsoft.com/beta/deviceManagement/managedDevices/$WEManagedDeviceID/rotateBitLockerKeys"
           ;  $WERolloverKeyResult = Invoke-RestMethod -Method POST -Uri $WERolloverKeyUri -ContentType " application/json" -Headers $WEHeader -ErrorAction Stop
            write-output " Recovery Key Rollover invoked on $($WEManagedDeviceResult.value.deviceName)"
            } else {
            Write-Output " Intune Rollover has already been performed on $($WEManagedDeviceResult.value.deviceName), no action needed"
        }
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================