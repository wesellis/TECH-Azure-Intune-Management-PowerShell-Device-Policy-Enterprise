<#
.SYNOPSIS
    Intune Retreive Cpuinfo

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
    We Enhanced Intune Retreive Cpuinfo

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

_author_ = Kathpalia, Nitin <N_Kathpalia@dell.com>
_version_ = 1.0.0

Copyright � 2023 Dell Inc. or its subsidiaries. All Rights Reserved.

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

1.0.0   initial version




<#
.Synopsis
   This PowerShell script retrieves the CPU Information of the system.
   IMPORTANT: This script needs a client installation of Dell Command Monitor https://www.dell.com/support/kbdoc/en-us/000177080/dell-command-monitor
   IMPORTANT: WMI BIOS is supported only on devices which developed after 2018, older devices do not supported by this powershell script
   IMPORTANT: This script does not reboot the system to apply or query system.
.DESCRIPTION
   This Powershell script uses WMI call to retrieve the CPU information in JSON format.
.EXAMPLE
	An example of the CPU Information retrived in JSON format:
	{" Version" :" 1.2.2" }


$WEProcessor = Get-CimInstance -Namespace root\dcim\sysman -ClassName DCIM_Processor
if($null -ne $WEProcessor)
{
    $WEProcessorName = $WEProcessor | Select -ExpandProperty ElementName
    $WEEnabledState = Switch ($WEProcessor | Select -ExpandProperty EnabledState)
    {
        2 {" Enabled" }
        3 {" Disabled" }
        5 {" Not Applicable" }
        6 {" Enabled but Offline" }
        7 {" No Default" }
        9 {" Quiesce" }
    }
    $WEEnabledDefault = Switch ($WEProcessor | Select -ExpandProperty EnabledDefault)
    {
        2 {" Enabled" }
        3 {" Disabled" }
        5 {" Not Applicable" }
        6 {" Enabled but Offline" }
        7 {" No Default" }
        9 {" Quiesce" }
    }
    $WECPUStatus = Switch ($WEProcessor | Select -ExpandProperty CPUStatus)
    {
        0 {" Unknown" }
        1 {" CPU Enabled" }
        2 {" CPU Disabled by User" }
        3 {" CPU Disabled By BIOS (POST Error)" }
        4 {" CPU Is Idle" }
        7 {" Other" }
    }
    $WECurrentClockSpeed = $WEProcessor | Select -ExpandProperty CurrentClockSpeed 
    $WEExternalBusClockSpeed = $WEProcessor | Select -ExpandProperty ExternalBusClockSpeed
    $WEHealthState = Switch ($WEProcessor | Select -ExpandProperty HealthState)
    {
        0  {" Unknown" }
        5  {" OK" }
        10 {" Degraded/Warning" }
        15 {" Minor Failure" }
        20 {" Major Failure" }
        25 {" Critical Failure" }
        30 {" Non-recoverable Error" }
    }
    $WEMaxClockSpeed = $WEProcessor | Select -ExpandProperty MaxClockSpeed
    $WENumberOfEnabledCores = $WEProcessor | Select -ExpandProperty NumberOfEnabledCores
    $WEOperationalStatus = Switch ($WEProcessor | Select -ExpandProperty OperationalStatus)
    {
        0  {" Unknown" }
        1  {" Other" }
        2  {" OK" }
        3  {" Degraded" }
        4  {" Stressed" }
        5  {" Predictive Failure" }
        6  {" Error" }
        7  {" Non-Recoverable Error" }
        8  {" Starting" }
        9  {" Stopping" }
        10 {" Stopped" }
        11 {" In Service" }
        12 {" No Contact" }
        13 {" Lost Communication" }
        14 {" Aborted" }
        15 {" Dormant" }
        16 {" Supporting Entity in Error" }
        17 {" Completed" }
        18 {" Power Mode" }
    }
    $WEPrimaryStatus = Switch ($WEProcessor | Select -ExpandProperty PrimaryStatus)
    {
        0 {" Unknown" }
        1 {" OK" }
        2 {" Degraded" }
        3 {" Error" }
    }
    $WERequestedState = Switch ($WEProcessor | Select -ExpandProperty RequestedState)
    {
        0  {" Unknown" }
        2  {" Enabled" }
        3  {" Disabled" }
        4  {" Shut Down" }
        5  {" No Change" }
        6  {" Offline" }
        7  {" Test" }
        8  {" Deferred" }
        9  {" Quiesce" }
        10 {" Reboot" }
        11 {" Reset" }
        12 {" Not Applicable" }
    }
    $WEStepping = $WEProcessor | Select -ExpandProperty Stepping
    $WESystemName = $WEProcessor | Select -ExpandProperty SystemName
    $WEFamily = $WEProcessor | Select -ExpandProperty Family
    $WEUpgradeMethod = $WEProcessor | Select -ExpandProperty UpgradeMethod
    $WETransitioningToState =  Switch ($WEProcessor | Select -ExpandProperty TransitioningToState)
    {
        0  {" Unknown" }
        2  {" Enabled" }
        3  {" Disabled" }
        4  {" Shut Down" }
        5  {" No Change" }
        6  {" Offline" }
        7  {" Test" }
        8  {" Deferred" }
        9  {" Quiesce" }
        10 {" Reboot" }
        11 {" Reset" }
        12 {" Not Applicable" }
    }
   ;  $WEUniqueID = $WEProcessor | Select -ExpandProperty UniqueID
   ;  $hash = @{ProcessorName=$WEProcessorName;EnabledDefault=$WEEnabledDefault;EnabledState=$WEEnabledState;CPUStatus=$WECPUStatus;CurrentClockSpeed=$WECurrentClockSpeed;ExternalBusClockSpeed=$WEExternalBusClockSpeed;HealthState=$WEHealthState;MaxClockSpeed=$WEMaxClockSpeed;NumberOfEnabledCores=$WENumberOfEnabledCores;OperationalStatus=$WEOperationalStatus;PrimaryStatus=$WEPrimaryStatus;RequestedState=$WERequestedState;Stepping=$WEStepping;SystemName=$WESystemName;TransitioningToState=$WETransitioningToState;UniqueID=$WEUniqueID;Family=$WEFamily;UpgradeMethod=$WEUpgradeMethod} | ConvertTo-Json -Compress

    return $hash
    Write-Information $hash
}
 
else
{
    Write-Error -Category ResourceUnavailable -CategoryTargetName " root/dcim/sysman" -CategoryTargetType " DCIM_Processor" -Message " Unable to enumerate the class 'DCIM_Processor' in the namespace 'root/dcim/sysman'" 	
    exit 1
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================