<#
.SYNOPSIS
    Dell Bios Password

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
    We Enhanced Dell Bios Password

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
   Set-DellBIOSPassword -ErrorAction Stop cmdlet used to set, change or clear BIOS passwords (system or setup(admin))
   IMPORTANT: Make sure you are using latest Powershell version 5 or newer to execute this cmdlet. Execute " Get-Host" to check the version.
   IMPORTANT: Make sure direct WMI capabilities are supported on the system.
.DESCRIPTION
   Cmdlet used to either set, change or clear BIOS passwords (system or setup) using Dell BIOS direct WMI capabilities 
   - PwdType, REQUIRED, Set, Change or clear BIOS password, pass in the type of password you want to change. Supported values are: Admin or System. NOTE: Make sure to pass in exact string value as listed (case sensitive values)
   - NewPwd, REQUIRED, Change BIOS password, pass in the new password. If you are clearing the password, pass in "" for value
   - OldPwd, OPTIONAL, Change BIOS password, pass in the old password. If you are setting new password, pass in "" for value
   - AdminPwd, OPTIONAL, Change BIOS System password, pass in the AdminPwd, if set on the client
   
.DESCRIPTION
   - Supported PwdType can be retrieved using 
   - $WESupported_password_types = Get-CimInstance -Namespace root/DCIM/SYSMAN/wmisecurity -ClassName PasswordObject | Select NameId
   
.EXAMPLE
	This example shows how to freshly set BIOS Admin password
	Set-DellBIOSPassword -PwdType " Admin" -NewPwd " admin_p@ssw0rd" -OldPwd ""
.EXAMPLE
	This example shows how to change BIOS Admin password
	Set-DellBIOSPassword -PwdType " Admin" -NewPwd " new_admin_p@ssW0rd" -OldPwd " admin_p@ssw0rd"
.EXAMPLE
	This example shows how to clear BIOS Admin password
    Set-DellBIOSPassword -PwdType " Admin" -NewPwd "" -OldPwd " admin_p@ssw0rd"

.EXAMPLE
	This example shows how to set BIOS System password when BIOS Admin password is set
	Set-DellBIOSPassword -PwdType " System" -NewPwd " system_p@ssw0rd" -OldPwd "" -AdminPwd " admin_p@ssw0rd" 
.EXAMPLE
    This example shows how to change BIOS System password when BIOS Admin password is set
	Set-DellBIOSPassword -PwdType " System" -NewPwd " new_system_p@ssW0rd" -OldPwd " system_p@ssw0rd" -AdminPwd " admin_p@ssw0rd"
.EXAMPLE
	This example shows how to clear BIOS System password when BIOS Admin password is set
    Set-DellBIOSPassword -PwdType " System" -NewPwd "" -OldPwd " system_p@ssw0rd" -AdminPwd " admin_p@ssw0rd"

.EXAMPLE
	This example shows how to set BIOS System password when BIOS Admin password is not set
	Set-DellBIOSPassword -PwdType " System" -NewPwd " system_p@ssw0rd" -OldPwd ""
.EXAMPLE
	This example shows how to change BIOS System password
	Set-DellBIOSPassword -PwdType " System" -NewPwd " new_system_p@ssW0rd" -OldPwd " system_p@ssw0rd"
.EXAMPLE
	This example shows how to clear BIOS System password
    Set-DellBIOSPassword -PwdType " System" -NewPwd "" -OldPwd " system_p@ssw0rd"




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
Function Set-DellBIOSPassword -ErrorAction Stop
{
    [CmdletBinding()]; 
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory=$true, HelpMessage=" Enter Password Type. e.g. Admin " )]
        [ValidateNotNullOrEmpty()]
		[ValidateSet(" Admin" , " System" )]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPwdType,
		
		[parameter(Mandatory=$true, HelpMessage=" Enter New Password for given PwdType. e.g dell_new " )]
        [AllowEmptyString()]
        [ValidateNotNull()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WENewPwd,
		
		[parameter(Mandatory=$false, HelpMessage=" Enter Old Password for given PwdType. e.g. dell_old " )]
        [ValidateNotNull()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEOldPwd,
		
		[parameter(Mandatory=$false, HelpMessage=" Enter BIOS Admin Password if it is applied already. e.g. dell_admin 
		It is required when user wants to set System password, when Admin password is set " )]
        [ValidateNotNull()]
        [string]$WEAdminPwd
	)
	
	try
	{
	; 	$status = 1;
		
		#check if Admin password is set on the box
		$WEIsBIOSAdminPasswordSet = Is-DellBIOSPasswordSet -PwdType " Admin" -EA stop
		
		#Get encoder for encoding password
		$encoder = New-Object -ErrorAction Stop System.Text.UTF8Encoding
		
		#Get SecurityInterface Class Object
		$WESI = Get-CimInstance -Namespace root/dcim/sysman/wmisecurity -ClassName SecurityInterface -EA stop
		
		
		if($WEPwdType -EQ " Admin" )
		{
			if($WEIsBIOSAdminPasswordSet)
			{
				#Modify or Clear
				
				#In case of Admin password modification, $WEAdminPwd and $WEOldPwd will have same value
			; 	$WEAdminBytes = $encoder.GetBytes($WEOldPwd)
			 
			; 	$status = $WESI | Invoke-CimMethod -MethodName SetnewPassword -Arguments @{NameId=$WEPwdType; NewPassword=$WENewPwd; OldPassword=$WEOldPwd; SecType=1; SecHndCount=$WEAdminBytes.Length; SecHandle=$WEAdminBytes;} | Select-Object -ExpandProperty Status -EA stop
			
			}
			else
			{
				#Set or Modify
							
				$status = $WESI | Invoke-CimMethod -MethodName SetnewPassword -Arguments @{NameId=$WEPwdType; NewPassword=$WENewPwd; OldPassword="" ; SecType=0; SecHndCount=0; SecHandle=@();} | Select-Object -ExpandProperty Status -EA stop

			}
		}
		
		elseif($WEPwdType -EQ " System" )
		{
			#check if system password is set on the box
			$WEIsBIOSSystemPasswordSet = Is-DellBIOSPasswordSet -PwdType " System"
			
			#If the BIOS Admin password is set, It will be required to System password operation 
			
            if($WEIsBIOSAdminPasswordSet)
			{	
				# Set BIOS System Password when BIOS Admin Password is already set
				
				#validate that $WEAdminPwd is not empty
					
				#parameter validation
				if(!($WEAdminPwd))
				{
					throw " Admin Password is required for this operation"
				}
			
			; 	$WEAdminBytes = $encoder.GetBytes($WEAdminPwd)

                if($WEIsBIOSSystemPasswordSet)
			    {
				    #Modify or Clear
				
				    #parameter validation
				    if(!($WEOldPwd))
				    {
					    throw " Old System Password is required for this operation"
				    }
				
				   ;  $status = $WESI | Invoke-CimMethod -MethodName SetnewPassword -Arguments @{NameId=$WEPwdType; NewPassword=$WENewPwd; OldPassword=$WEOldPwd; SecType=1; SecHndCount=$WEAdminBytes.Length; SecHandle=$WEAdminBytes;} | Select-Object -ExpandProperty Status -EA stop
			    }
			
			    else
			    {
                    #Set
				    $status = $WESI | Invoke-CimMethod -MethodName SetNewPassword -Arguments @{NameId=$WEPwdType; NewPassword=$WENewPwd; OldPassword="" ; SecType=1; SecHndCount=$WEAdminBytes.Length; SecHandle=$WEAdminBytes;} | Select-Object -ExpandProperty Status -EA stop    
						
			    }
				
			}
			else
			{
				if($WEIsBIOSSystemPasswordSet)
			    {
				    #Modify or Clear
				
				    #parameter validation
				    if(!($WEOldPwd))
				    {
					    throw " Old System Password is required for this operation"
				    }
				
				    $status = $WESI | Invoke-CimMethod -MethodName SetnewPassword -Arguments @{NameId=$WEPwdType; NewPassword=$WENewPwd; OldPassword=$WEOldPwd; SecType=0; SecHndCount=0; SecHandle=@();} | Select-Object -ExpandProperty Status -EA stop
			    }
			
			    else
			    {
                    #Set
				    $status = $WESI | Invoke-CimMethod -MethodName SetNewPassword -Arguments @{NameId=$WEPwdType; NewPassword=$WENewPwd; OldPassword="" ; SecType=0; SecHndCount=0; SecHandle=@();} | Select-Object -ExpandProperty Status -EA stop    
						
			    }
						
			}    
            
		}			
		
		else
		{
			#flow should not come here as we have parameter validation in place
			#this case can be extended for HDD passwords when supported
			throw " This Passwordtype is not supported."
			
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
			3 { $result = 'Access Denied, Please Provide Correct Old Password/Admin Password and also adhere to Strong Password parameters applied on the system for New Password 
                            (StrongPassword, PwdUpperCaseRqd, PwdLowerCaseRqd, PwdDigitRqd, PwdSpecialCharRqd, PwdMinLen, PwdMaxLen)' 
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
		Write-Information $WEException
	}
	Finally
	{
		
		Write-Information $result
		Write-WELog " Function Set-Password -ErrorAction Stop Executed" " INFO"
	}
}




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================