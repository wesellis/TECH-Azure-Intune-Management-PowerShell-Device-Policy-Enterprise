<#
.SYNOPSIS
    Intune Detection Bios Adminpw Change

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
    We Enhanced Intune Detection Bios Adminpw Change

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
_version_ = 1.0.1
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

1.0.1   Added registry key check before updating the BIOS admin password.


<#
.Synopsis
   This PowerShell script checks if the BIOS AdminPW is older than 180 days and needs to be changed.
   IMPORTANT: Works only if you are using the " Intune_1_and_2_Remediation_BIOS_AdminPW_Setting.ps1" script to set BIOS AdminPW.
   IMPORTANT: This script needs a client which supports the WMI Namespace " root/dcim/sysman/wmisecurity" and the WMI class " PasswordObject" .
   IMPORTANT: WMI BIOS is supported only on devices which developed after 2018, older devices do not supported by this powershell script.
   IMPORTANT: This script does not reboot the system to apply or query system.

.DESCRIPTION
   PowerShell to import as Dection Script for Microsoft Endpoint Manager. This Script need to be imported in Reports/Endpoint Analytics/Proactive remediation. This File is for detection only and need a seperate script for remediation additional.
   NOTE: The pre-remediation detection script output is available in Intune reports in the " Pre-remediation detection output" column.
   NOTE: The post-remediation detection script output is available in Intune reports in the " Post-remediation detection output" column.
   NOTE: The remediation script log message are available on the endpoint at this path: " C:\Temp\BIOS_Profile.txt"
   

try{

    #Check if AdminPW is set on the machine
    $WEBIOSAdminPW = Get-CimInstance -Namespace root/dcim/sysman/wmisecurity -ClassName PasswordObject -Filter " NameId='Admin'" | Select-Object -ExpandProperty IsPasswordSet
    $WERegKeyexist = Test-Path 'HKLM:\SOFTWARE\Dell\BIOS'
	Write-Output " Checking if BIOS admin password is set on the machine."

	if($WEBIOSAdminPW -eq $null)
	{
		Write-Error -Category ResourceUnavailable -CategoryTargetName " root/dcim/sysman/wmisecurity" -CategoryTargetType " PasswordObject" -Message " Unable to get the 'Admin' object in class 'PasswordObject' in the Namespace 'root/dcim/sysman/wmisecurity'" 
		exit 1
	}
    elseif($WEBIOSAdminPW -match " 1" )
    {
		Write-Output " BIOS password is already set on the machine."
		if($WERegKeyexist -eq " True" )
		{
			# Registry key exists, password is known.
			# check if BIOS password older that 180 days
		; 	$WEDateExpire = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Dell\BIOS\' -Name Update | Select-Object -ExpandProperty Update
			if ((Get-Date -Format yyyyMMdd) -le (Get-Date $WEDateExpire -Format yyyyMMdd))
			{
				write-host " BIOS Admin password is not older than 180 days. No need to update the password."
				exit 0 
			}
			else
			{
				Write-WELog " BIOS Admin password is older than 180 days. Need to update the password." " INFO"
				exit 1
			}
		}
		else
		{
			# BIOS password set but registry does not exist.
			# BIOS password set but unknown, need to verify if password can be changed. Run remediation.
			Write-WELog " An unknown BIOS password is set on this machine. Need to verify if the password can be changed. Running the remediation script.." " INFO"
			exit 1
		}
    }            
    else
        {
			Write-WELog " No BIOS Admin password is set. No need to set/update the password." " INFO"
			exit 0
        }
    }
catch
{
   ;  $errMsg = $_.Exception.Message
    write-Error $errMsg
    exit 1
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================