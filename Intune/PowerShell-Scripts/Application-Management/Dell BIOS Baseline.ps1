<#
.SYNOPSIS
    Dell Bios Baseline

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
    We Enhanced Dell Bios Baseline

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

_author_ = Prateek Vishwakarma <Prateek_Vishwakarma@Dell.com>
_version_ = 1.0

Copyright � 2021 Dell Inc. or its subsidiaries. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the " License" );
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an " AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


<#
.Synopsis
   Set-DellBIOSDefaults cmdlet used to set Dell BIOS to default settings using Dell BIOS DirectWMI capabilities.
   IMPORTANT: Make sure you are using latest Powershell version 5 or newer to execute this cmdlet. Execute " Get-Host" to check the version.
   IMPORTANT: Make sure direct WMI capabilities are supported on the system. 
   IMPORTANT: This script does not reboots the system to apply the settings. In order to bring the settings into effect, reboot the system.
.DESCRIPTION
   Cmdlet used to set BIOS to default settings (all BIOS settings to a default value as per selected baseline) on the next reboot. 
   IMPORTANT: Please note that many settings will not be applied until the system is rebooted.
   
   - DefaultType, REQUIRED, pass in the BIOS Baseline profile name. Accepted Values are " BuiltInSafeDefaults" , " LastKnownGood" , " Factory" , " UserConf1" , " UserConf2" .
   - AdminPwd, OPTIONAL, Dell BIOS Admin password, if set on the client

.EXAMPLE
	This example shows how to reset Dell BIOS to 'BuiltInSafeDefaults' profile, when BIOS Admin password is not set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " BuiltInSafeDefaults"
.EXAMPLE
	This example shows how to reset Dell BIOS to 'LastKnownGood' profile, when BIOS Admin password is not set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " LastKnownGood"
.EXAMPLE
	This example shows how to reset Dell BIOS to 'Factory' profile, when BIOS Admin password is not set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " Factory"
.EXAMPLE
	This example shows how to reset Dell BIOS to 'UserConf1' profile, when BIOS Admin password is not set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " UserConf1"
.EXAMPLE
	This example shows how to reset Dell BIOS to 'UserConf2' profile, when BIOS Admin password is not set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " UserConf2"
	
.EXAMPLE
	This example shows how to reset Dell BIOS to 'BuiltInSafeDefaults' profile, when BIOS Admin password is set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " BuiltInSafeDefaults" -AdminPwd " P@ssword"
.EXAMPLE
	This example shows how to reset Dell BIOS to 'LastKnownGood' profile, when BIOS Admin password is set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " LastKnownGood" -AdminPwd " P@ssword"	
.EXAMPLE
	This example shows how to reset Dell BIOS to 'Factory' profile, when BIOS Admin password is set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " Factory" -AdminPwd " P@ssword"
.EXAMPLE
	This example shows how to reset Dell BIOS to 'UserConf1' profile, when BIOS Admin password is set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " UserConf1" -AdminPwd " P@ssword"
.EXAMPLE
	This example shows how to reset Dell BIOS to 'UserConf2' profile, when BIOS Admin password is set on the system. Settings will not be applied until next system reboot.
    Set-DellBIOSDefaults -DefaultType " UserConf2" -AdminPwd " P@ssword"




Function Is-DellBIOSPasswordSet
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory=$true, 
			HelpMessage=" Enter Password Type. e.g. Admin" )]
        [ValidateNotNullOrEmpty()]
		[ValidateSet(" Admin" , " System" )]
        [string]$WEPwdType
    )
	
	try
	{
		$WEIsPasswordSet = Get-CimInstance -Namespace root/dcim/sysman/wmisecurity -ClassName PasswordObject | Where-Object NameId -EQ $WEPwdType | Select-Object -ExpandProperty IsPasswordSet -ErrorAction stop
		if(1 -eq $WEIsPasswordSet) { Write-Host  $WEPwdType " password is set on the system" }
		else { Write-Host  $WEPwdType " password is not set on the system" }
		return $WEIsPasswordSet
	}
	Catch
	{
		$WEException = $_
		Write-Error " Exception:" $WEException
	}
	Finally
	{
		Write-WELog " Function Is-PasswordSet Executed" " INFO" 
	}
}


Function Set-DellBIOSDefaults
{
	[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
		[parameter(Mandatory=$true, HelpMessage=" Enter BIOS Baseline profile name. e.g. LastKnownGood " )]
		[ValidateSet(" BuiltInSafeDefaults" ," LastKnownGood" ," Factory" ," UserConf1" ," UserConf2" )]
		[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEDefaultType,
		
		[parameter(Mandatory=$false, HelpMessage=" Enter BIOS Admin Password if applicable. e.g. dell_admin " )]
        [ValidateNotNullOrEmpty()]
        [string]$WEAdminPwd
    )
	
	# Resets Dell BIOS to the given Baseline profile
	
	try
	{		
		
		<#
			Convert the DefaultType parameter to enumeration mapping as follows

				0 - BuiltInSafeDefaults
				1 - LastKnownGood
				2 - Factory
				3 - UserConf1
				4 - UserConf2
		#>
		
			
		switch($WEDefaultType)
		{
			BuiltInSafeDefaults {[byte]$WEDefaultValue =  0
                                break
                                }
			LastKnownGood {[byte]$WEDefaultValue = 1
                                break
                                }
			Factory {[byte]$WEDefaultValue =  2
                                break
                                }
			UserConf1 {[byte]$WEDefaultValue =  3
                                break
                                }
			UserConf2 {[byte]$WEDefaultValue =  4
                                break
                                }
			default
			{
				#Flow should not reach here as we have ValidateSet in effect
				throw " Use one of the following arguments - BuiltInSafeDefaults, LastKnownGood, Factory, UserConf1, UserConf2"
			}
		}
		
		#Get BIOSAttributeInterface Class Object
	    $WEBAI = Get-CimInstance -Namespace root/dcim/sysman/biosattributes -ClassName BIOSAttributeInterface -EA stop
		
		#check if Admin password is set on the box
	    $WEIsBIOSAdminPasswordSet = Is-DellBIOSPasswordSet -PwdType " Admin" -EA stop
		
		if($WEIsBIOSAdminPasswordSet)
        {
            if(!([String]::IsNullOrEmpty($WEAdminPwd)))
			{
				#Get encoder for encoding password
	            $encoder = New-Object System.Text.UTF8Encoding
   
                #encode the password
               ;  $WEAdminBytes = $encoder.GetBytes($WEAdminPwd)

                #Set BIOS Baseline
               ;  $status = $WEBAI | Invoke-CimMethod -MethodName SetBIOSDefaults -Arguments @{DefaultType=$WEDefaultValue; SecType=1; SecHndCount=$WEAdminBytes.Length; SecHandle=$WEAdminBytes;} | Select-Object -ExpandProperty Status -EA stop
			}
			else
			{
				throw " Admin Password is required for this operation"
                    
			}                
        }
        else
        {
            #Configure BIOS Attribute
			$status = $WEBAI | Invoke-CimMethod -MethodName SetBIOSDefaults -Arguments @{DefaultType=$WEDefaultValue; SecType=0; SecHndCount=0; SecHandle=@();} | Select-Object -ExpandProperty Status -EA stop
        }
           
        switch ( $status )
		{
			0 { $result = 'Success'
				break
				}
			1 { $result = 'Failed'    
				break
				}
			2 { $result = 'Invalid Parameter'   
				break
				}
			3 { $result = 'Access Denied, Provide Correct Admin Password' 
				break
				}
			4 { $result = 'Not Supported'  
				break
				}
			5 { $result = 'Memory Error'    
				break
				}
			6 { $result = 'Protocol Error'  
				break
				}
			default {;  $result ='Unknown' 
				break
				}
		}
	}
	catch
	{
	; 	$WEException = $_
		Write-Host $WEException
	}
	finally
	{
		Write-Host $result
		Write-WELog " Function Set-DellBIOSDefaults Executed" " INFO"	
	}
	
}





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================