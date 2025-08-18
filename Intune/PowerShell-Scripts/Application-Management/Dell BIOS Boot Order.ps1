<#
.SYNOPSIS
    Dell Bios Boot Order

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
    We Enhanced Dell Bios Boot Order

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
   Set-DellBIOSBootOrder -ErrorAction Stop cmdlet used to configure Boot order
.DESCRIPTION
   NOTE: Configuring boot order is supported for LEGACY and UEFI boot sequences.
   - NewBootOrder: REQUIRED, pass in the New Boot order to set e.g. Windows Boot Manager, UEFI Hard Drive, UEFI HTTPs Boot, USB NIC (IPV6)" 
   - BootListType: REQUIRED, pass in the BootListType e.g. 'LEGACY' or 'UEFI' 
   - AdminPwd, OPTIONAL, Dell BIOS Admin password, if set on the client
   IMPORTANT: You must execute and view the current boot order at least once using Get-DellBIOSBootOrder -ErrorAction Stop before trying to configure Boot Order.
   IMPORTANT: make sure to pass correct list for " NewBootOrder" argument otherwise INCORRECT PARAMETER error will be thrown.
   IMPORTANT: Make sure direct WMI capabilities are supported on the system.
   
.EXAMPLE
   This example shows how to configure configure UEFI BootOrder, when Dell BIOS Admin Password is not set
   Get-DellBIOSBootOrder -BootListType UEFI
   [string[]]$WENewBO = @(" Windows Boot Manager" , " USB NIC (IPV4)" , " USB NIC (IPV6)" , " UEFI HTTPs Boot" )
   Set-DellBIOSBootOrder -NewBootOrder $WENewBO -BootListType UEFI 
.EXAMPLE
   This example shows how to configure configure UEFI BootOrder, when Dell BIOS Admin Password is set
   Get-DellBIOSBootOrder -BootListType UEFI
   [string[]]$WENewBO = @(" Windows Boot Manager" , " USB NIC (IPV6)" , " USB NIC (IPV4)" , " UEFI HTTPs Boot" )
   Set-DellBIOSBootOrder -NewBootOrder $WENewBO -BootListType UEFI -AdminPwd " P@ssword"



[CmdletBinding()]
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
		if(1 -eq $WEIsPasswordSet) { Write-Information $WEPwdType " password is set on the system" }
		else { Write-Information $WEPwdType " password is not set on the system" }
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


[CmdletBinding()]
Function Get-DellBIOSBootOrder -ErrorAction Stop
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
	[parameter(Mandatory=$true, HelpMessage=" Enter BootListType e.g. 'LEGACY' or 'UEFI' " )]
	[ValidateSet(" UEFI" ," LEGACY" )]
	[string]$WEBootListType
    )

    try
    {
        $WEBootOrder = Get-CimInstance -Namespace root\dcim\sysman\biosattributes -ClassName BootOrder | Where-Object BootListType -eq $WEBootListType -EA Stop
		Write-Information $WEBootListType " BootOrder count:" $WEBootOrder.BOCount
		Write-Information $WEBootListType " BootOrder isActive:" $WEBootOrder.IsActive
        return $WEBootOrder
    }
    catch
    {
        $WEException = $_
		Write-Error " Exception:" $WEException
    }
    Finally
    {
        Write-WELog " Function Get-DellBIOSBootOrder -ErrorAction Stop Executed" " INFO"
    }
}


[CmdletBinding()]
Function Set-DellBIOSBootOrder -ErrorAction Stop
{
    #Set BootOrder

    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory=$true, HelpMessage=" Enter New Boot order to set e.g. Windows Boot Manager, UEFI Hard Drive, UEFI HTTPs Boot, USB NIC (IPV6)" )]
		[ValidateNotNullOrEmpty()]
		[string[]]$WENewBootOrder,
		
        [parameter(Mandatory=$true, HelpMessage=" Enter BootListType e.g. 'LEGACY' or 'UEFI' " )]
		[ValidateSet(" UEFI" ," LEGACY" )]
		[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEBootListType,
		
		[parameter(Mandatory=$false, HelpMessage=" Enter BIOS Admin Password if applicable. e.g. dell_admin " )]
        [ValidateNotNullOrEmpty()]
        [string]$WEAdminPwd

    )
	try
	{
			
		$WEBOI = Get-CimInstance -Namespace root\dcim\sysman\biosattributes -ClassName SetBootOrder -EA stop	
		
		$WEBootOrder = Get-DellBIOSBootOrder -BootListType $WEBootListType -EA stop
		
		#check if Admin password is set on the box
	    $WEIsBIOSAdminPasswordSet = Is-DellBIOSPasswordSet -PwdType " Admin" -EA stop
			
		#Proceed Boot order operation only if BOCount member is greater than one
		if($WEBootOrder.BOCount -gt 1)
		{	
			[String]$WECurrentBootOrder = $WEBootOrder | Select-Object -ExpandProperty BootOrder -EA stop
            Write-WELog " Current Boot Order for" " INFO" $WEBootListType " BootListType is" $WECurrentBootOrder

			if($WECurrentBootOrder -eq $WENewBootOrder)
			{
				throw " Given Boot Order is already set"
			}
			
			if($WEIsBIOSAdminPasswordSet)
			{
				if(!([String]::IsNullOrEmpty($WEAdminPwd)))
				{
					#Get encoder for encoding password
					$encoder = New-Object -ErrorAction Stop System.Text.UTF8Encoding
   
					#encode the password
				; 	$WEAdminBytes = $encoder.GetBytes($WEAdminPwd)
					
				; 	$status = $WEBOI | Invoke-CimMethod -MethodName Set -Arguments @{BootListType=$WEBootListType; BootOrder=$WENewBootOrder; BOCount=$WENewBootOrder.Count; SecType=1; SecHndCount=$WEAdminBytes.Length; SecHandle=$WEAdminBytes;} | Select-Object -ExpandProperty Status -EA stop
				}
				else
				{
					throw " Admin Password is required for this operation"
				}
			}	
			else
			{
				$status = $WEBOI | Invoke-CimMethod -MethodName Set -Arguments @{BootListType=$WEBootListType; BootOrder=$WENewBootOrder; BOCount=$WENewBootOrder.Count; SecType=0; SecHndCount=0; SecHandle=@();} | Select-Object -ExpandProperty Status -EA stop
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
		else
		{
			throw " Cannot Configure BootOrder with Single Bootable device"
		}
    }
	catch
	{
	; 	$WEException = $_
		Write-WELog " Exception: $WEException " " INFO"
	}
	finally
	{
        Write-Information $result
		Write-WELog " Function Set-DellBIOSBootOrder -ErrorAction Stop Executed" " INFO"		
	}
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================