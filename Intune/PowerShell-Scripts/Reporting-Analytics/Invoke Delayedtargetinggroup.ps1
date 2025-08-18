<#
.SYNOPSIS
    Invoke Delayedtargetinggroup

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
    We Enhanced Invoke Delayedtargetinggroup

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
    .SYNOPSIS
    Automated script for delayed targeting based on a set timerange. 
    .DESCRIPTION
    Add devices to group X hours after enrolled to Intune to avoid certain scripts and packages to be targeted during provisioning. 
     .PARAMETERS
    TargetingGroupID: The ObjectID of the group you are maintainging in Azure AD
    .NOTES
        Author:      Jan Ketil Skanke 
        Contact:     @JankeSkanke
        Created:     2021-06-14 
        Updated:     2021-06-14
        Version history:
        1.0.0 - (2021-09-22 ) Production Ready version




$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
function WE-Get-MSIAccessTokenGraph{
   ;  $resourceURL = " https://graph.microsoft.com/" 
   ;  $response = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -UseBasicParsing -Uri " $($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method 'GET' -Headers @{'X-IDENTITY-HEADER' = " $env:IDENTITY_HEADER" ; 'Metadata' = 'True'}).RawContentStream.ToArray()) | ConvertFrom-Json 
    $accessToken = $response.access_token

    #Create Global Authentication Header
    $WEGlobal:AuthenticationHeader = @{
    " Content-Type" = " application/json"
    " Authorization" = " Bearer " + $accessToken
    }
return $WEAuthenticationHeader
}

$WETargetingGroupID = " <ENTER YOUR GROUPS OBJECTID FROM AZURE AD>" # Or use a Automation Account Variable 

$WEConnecting = Connect-AzAccount -Identity 


$WEResponse = Get-MSIAccessTokenGraph -ErrorAction Stop


$starttime = Get-Date((Get-Date).AddHours(-28)) -Format " yyyy-MM-ddTHH:mm:ssZ"
$endtime = Get-Date((Get-Date).AddHours(-4)) -Format " yyyy-MM-ddTHH:mm:ssZ"


$WEDevices = Invoke-MSGraphOperation -APIVersion Beta -Get -Resource " deviceManagement/manageddevices?filter=startswith(deviceName, 'MTR-') and ((enrolleddatetime+lt+$($endtime)) and (enrolleddatetime+gt+$($starttime)))"



$WEDeviceIDsInGroup = (Get-AzADGroupMember -GroupObjectId $WETargetingGroupID).Id
if (-not([string]::IsNullOrEmpty($WEDevices))){
  foreach($device in $devices){
   ;  $WEDeviceID = $device.azureADDeviceId
   ;  $WEDirectoryObjectID = (Invoke-MSGraphOperation -APIVersion Beta -Get -Resource " devices?filter=deviceId+eq+`'$WEDeviceID`'" ).id
    if (-not ($WEDirectoryObjectID -in $WEDeviceIDsInGroup)){            
      try {
        Add-AzADGroupMember -MemberObjectId $WEDirectoryObjectID -TargetGroupObjectId $WETargetingGroupID -ErrorAction Stop
        Write-Output " Added $($device.deviceName) with ID $($WEDirectoryObjectID) to group"
      } catch {
        Write-Output " Failed to add $($device.deviceName) to group. Message: $($_.Exception.Message)"
        }
        } else {
          Write-Output " $($device.deviceName) with ID $($WEDirectoryObjectID) already in group"
        }
    }
} else {
  Write-Output " No new devices to process this time, exiting script"
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================