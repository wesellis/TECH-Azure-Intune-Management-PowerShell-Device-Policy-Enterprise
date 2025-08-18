<#
.SYNOPSIS
    Intune Compliance Sensor Dcm Warranty Expire

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
    We Enhanced Intune Compliance Sensor Dcm Warranty Expire

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


$WEErrorActionPreference = "Stop" ; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

_author_ = Sven Riebe <sven_riebe@Dell.com>
_version_ = 1.0.0
_Dev_Status_ = Test
Copyright © 2023 Dell Inc. or its subsidiaries. All Rights Reserved.

No implied support and test in test environment/device before using in any production environment.

Licensed under the Apache License, Version 2.0 (the " License" );
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an " AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


<#Version Changes

1.0.0   inital version




<#
.Synopsis
   This PowerShell is for custom compliance scans and is checking the support contract time of this device by Dell Command Monitor (DCM)
   IMPORTANT: This script need a client installation of Dell Command Monitor https://www.dell.com/support/kbdoc/en-us/000177080/dell-command-monitor
   IMPORTANT: This script does not reboot the system to apply or query system.
.DESCRIPTION
   Powershell using Dell Command Monitor WMI to check the support contract time of the device. This script need to be upload in Intune Compliance / Script and need a JSON file additional for reporting this value.
   NOTE: This script looks only for the last ending warranty and checks if this warranty is currently active. This script does not look for multiple warranties with different expiry dates.
   NOTE: This script verifies if the system is compliant or not as per the rules mentioned in the JSON file. 





$WEWarrantyEnd = Get-CimInstance -Namespace root\dcim\sysman -ClassName DCIM_AssetWarrantyInformation | Sort-Object WarrantyEndDate -Descending | select -ExpandProperty WarrantyEndDate 
$WEWarrantyEndSelect = $WEWarrantyEnd[0] -split " ,"
$WEWarrantyDate = $WEWarrantyEndSelect -split " "
[datetime]$WEFinalDate = $WEWarrantyDate.GetValue(0)


$WEToday = Get-Date
$WEDuration = New-TimeSpan -Start $WEToday -End $WEFinalDate; 
$last30Days = New-TimeSpan -Start $WEToday -End $WEFinalDate.AddDays(-30)

; 
$hash = @{ Support = $WEDuration.Days; Last30Days = $last30Days.Days }


return $hash | ConvertTo-Json -Compress


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================