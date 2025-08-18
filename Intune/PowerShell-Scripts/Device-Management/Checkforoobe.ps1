<#
.SYNOPSIS
    Checkforoobe

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
    We Enhanced Checkforoobe

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


[string]$WEAutoPilotSettingsKey = 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[string]$WEAutoPilotSettingsKey = 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'
[string]$WEDevicePrepName = 'DevicePreparationCategory.Status'
[string]$WEDeviceSetupName = 'DeviceSetupCategory.Status'
[bool]$WEDevicePrepNotRunning = $false
[bool]$WEDeviceSetupNotRunning = $false
        
$WEDevicePrepDetails = (Get-ItemProperty -Path $WEAutoPilotSettingsKey -Name $WEDevicePrepName -ErrorAction 'Ignore').$WEDevicePrepName; 
$WEDeviceSetupDetails = (Get-ItemProperty -Path $WEAutoPilotSettingsKey -Name $WEDeviceSetupName -ErrorAction 'Ignore').$WEDeviceSetupName
 
if (-not [string]::IsNullOrEmpty($WEDevicePrepDetails)) {
   ;  $WEDeviceSetupDetails = $WEDeviceSetupDetails | ConvertFrom-Json
}
else {
    Write-Output " No_Autopilot_Config"
    Exit
}
 
 
if ($WEDeviceSetupDetails.categoryState -eq " inProgress" ) {
    Write-Output " ESP_Running"
    Exit
}
else {
    Write-Output " ESP_NotRunning"
    Exit
}
 



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================