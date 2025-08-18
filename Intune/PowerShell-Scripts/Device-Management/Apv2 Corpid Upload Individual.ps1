<#
.SYNOPSIS
    Apv2 Corpid Upload Individual

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
    We Enhanced Apv2 Corpid Upload Individual

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

Install-Module Microsoft.Graph.Beta.DeviceManagement -confirm:$false -Force -AllowClobber
Import-Module Microsoft.Graph.Beta.DeviceManagement


Connect-MgGraph


$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem; 
$bios = Get-CimInstance -ClassName Win32_BIOS

; 
$params = @{
    overwriteImportedDeviceIdentities = $false
	importedDeviceIdentities = @(
		@{
			importedDeviceIdentityType = " manufacturerModelSerial"
			importedDeviceIdentifier = " $($computerSystem.Manufacturer),$($computerSystem.Model),$($bios.SerialNumber)"
		}
	)
} | ConvertTo-Json


Invoke-MgGraphRequest -Method POST -Uri " https://graph.microsoft.com/beta/deviceManagement/importedDeviceIdentities/importDeviceIdentityList" -Body $params


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================