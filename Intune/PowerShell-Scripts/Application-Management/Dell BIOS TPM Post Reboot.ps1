<#
.SYNOPSIS
    Dell Bios Tpm Post Reboot

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
    We Enhanced Dell Bios Tpm Post Reboot

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
   Activate-DellBIOSTPM Cmdlet used to Enable TpmActivation BIOS attribute using Dell BIOS DirectWMI capabilities.
   IMPORTANT: Configuring TPM is handled using two scripts as Local System Restart is involved. These scripts in their order of execution are
				1. 4_1_Dell_BIOS_TPM.ps1 - enables TPMSecurity and Restarts the local system (optional)
				2. 4_2_Dell_BIOS_TPM.ps1 - activates TPM (TpmActivation) and Restarts the local system (optional)
	For more information on TPM, refer to the following Dell Whitepaper -
	http://downloads.dell.com/solutions/general-solution-resources/White%20Papers/Securing%20Dell%20Commercial%20Systems%20with%20Trusted%20Platform%20Module%20(TPM).pdf 
	
   IMPORTANT: Make sure you are using latest Powershell version 5 or newer to execute this cmdlet. Execute " Get-Host" to check the version.
   IMPORTANT: Make sure direct WMI capabilities are supported on the system.
   IMPORTANT: Scope of this Script is to configure TpmActivation BIOS attribute and restart local machine (optional)
   IMPORTANT: TPM cannot be disabled or deactivated using Dell BIOS DirectWMI Capabilities. Disabling or deactivation
			  of the TPM can only be performed using the BIOS Setup.
	IMPORTANT: TPM can be activated or enabled in the following scenarios:
				- Administrator password is set on system.
				- TPM is not owned.
				- TPM is disabled or deactivated.
.DESCRIPTION
	Cmdlet used to Enable TpmActivation BIOS attribute. 
   - AdminPwd, REQUIRED, Dell BIOS Admin password. if set on the client
   - Restart, OPTIONAL, pass in -Restart switch if local system restart needs to be performed (recommended)
.EXAMPLE
	This example shows how to enable TpmActivation. ( note - local system restart is required (manually or through Intune MDM) for the changes to take effect )
	Activate-DellBIOSTPM -AdminPwd " P@ssword"
.EXAMPLE
    This example shows how to enable TpmActivation and Restart the local system. 
	Activate-DellBIOSTPM -AdminPwd " P@ssword" -Restart



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
Function Get-DellBIOSAttributes -ErrorAction Stop
{
    try
	{
        #Fetch all Enumeration type Dell BIOS Attributes
        $WEEnumerationAttributes = Get-CimInstance -Namespace root\dcim\sysman\biosattributes -ClassName EnumerationAttribute -Select " AttributeName" ," CurrentValue" ," PossibleValue" -EA Stop

        #Fetch all Integer type Dell BIOS Attributes
        $WEIntegerAttributes = Get-CimInstance -Namespace root\dcim\sysman\biosattributes -ClassName IntegerAttribute -Select " AttributeName" ," CurrentValue" ," LowerBound" ," UpperBound" -EA Stop

        #Fetch all String type Dell BIOS Attributes
        $WEStringAttributes = Get-CimInstance -Namespace root\dcim\sysman\biosattributes -ClassName StringAttribute -Select " AttributeName" ," CurrentValue" ," MinLength" ," MaxLength" -EA Stop

        #Create a single list object
        $WEBIOSAttributes = $WEEnumerationAttributes + $WEIntegerAttributes + $WEStringAttributes | Sort-Object AttributeName

        return $WEBIOSAttributes
    }
    catch
    {
        $WEException = $_
		Write-Error " Exception:" $WEException
    }
    Finally
    {
        Write-WELog " Function Get-DellBIOSAttribute -ErrorAction Stop Executed" " INFO"
    }
}


[CmdletBinding()]
Function Set-DellBIOSAttribute -ErrorAction Stop
{
    #Sets a Dell BIOS Attribute

    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$true, HelpMessage=" Enter Dell BIOS AttributeName. e.g. UefiNwStack" )]
		[ValidateNotNullOrEmpty()]
        [String]$WEAttributeName,
        [Parameter(Mandatory=$true, HelpMessage=" Enter Dell BIOS AttributeValueName. e.g. Disabled" )]
		[ValidateNotNull()]
        [AllowEmptyString()]
        [String]$WEAttributeValueName,
        [Parameter(Mandatory=$false, HelpMessage=" Enter Dell BIOS Admin Password (if applicable)" )]
		[ValidateNotNullOrEmpty()]
        [String]$WEAdminPwd
    )
    
    try
    {
        #Get BIOSAttributeInterface Class Object
	    $WEBAI = Get-CimInstance -Namespace root/dcim/sysman/biosattributes -ClassName BIOSAttributeInterface -EA stop

        #check if Admin password is set on the box
	    $WEIsBIOSAdminPasswordSet = Is-DellBIOSPasswordSet -PwdType " Admin" -EA stop
		
	    #Perform a Get Operation to ensure that the given BIOS Attribute is applicable on the SUT and fetch the possible values
	    $WEBIOSAttributes = Get-DellBIOSAttributes -ErrorAction Stop

	    $WECurrentValue = $WEBIOSAttributes | Where-Object AttributeName -eq $WEAttributeName | Select-Object -ExpandProperty CurrentValue -EA Stop

	    if($WENULL -ne $WECurrentValue)
	    {
		    #Check if Attribute is already set to given value
		    if($WECurrentValue -eq $WEAttributeValueName)
		    {
			    Write-WELog " Attribute " " INFO" $WEAttributeName" is already set to " $WEAttributeValueName""
		    }

		    #Attribute is not set to given value
		    else
		    {
                if($WEIsBIOSAdminPasswordSet)
                {
                    if(!([String]::IsNullOrEmpty($WEAdminPwd)))
			        {
				        #Get encoder for encoding password
	                    $encoder = New-Object -ErrorAction Stop System.Text.UTF8Encoding
   
                        #encode the password
                       ;  $WEAdminBytes = $encoder.GetBytes($WEAdminPwd)

                        #Configure BIOS Attribute
                       ;  $status = $WEBAI | Invoke-CimMethod -MethodName SetAttribute -Arguments @{AttributeName=$WEAttributeName; AttributeValue=$WEAttributeValueName; SecType=1; SecHndCount=$WEAdminBytes.Length; SecHandle=$WEAdminBytes;} | Select-Object -ExpandProperty Status -EA stop
			        }
			        else
			        {
				        throw " Admin Password is required for this operation"
                    
			        }                
                }
                else
                {
                    #Configure BIOS Attribute
                    $status = $WEBAI | Invoke-CimMethod -MethodName SetAttribute -Arguments @{AttributeName=$WEAttributeName; AttributeValue=$WEAttributeValueName; SecType=0; SecHndCount=0; SecHandle=@()} | Select-Object -ExpandProperty Status -EA stop 
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
			        default { $result ='Unknown' 
				        break
				        }
		        }
          	
		    }
	    }
	    #BIOS Attribute not present
	    else
	    {
		    Write-WELog " Attribute:" " INFO" $WEAttributeName " not present on the system" 
	    }
    }
    catch
    {
        $WEException = $_
		Write-Information $WEException
    }
    finally
    {
        Write-Information $result
		Write-WELog " Function Set-DellBIOSAttribute -ErrorAction Stop Executed" " INFO"
    }
}


[CmdletBinding()]
Function Restart-DellComputer
{	
	[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
		[parameter(Mandatory=$true, HelpMessage=" Enter time in seconds" )]
		[ValidateNotNullOrEmpty()]
		[int]$WESeconds
	)
	try
	{
	Write-WELog " Following will happen during restart" " INFO"
	$WEWhatIf = Restart-Computer -WhatIf	
	Write-Information $WEWhatIf
	
	Write-WELog " Waiting for" " INFO" $WESeconds " before restart"
	Start-Sleep -Seconds $WESeconds
	Write-WELog " Attempting system restart at " " INFO" $(Get-Date) -EA stop
	
	Restart-Computer -ComputerName . -Force -EA stop
	}
	catch
	{
		$WEException = $_
		Write-Information $WEException
	}
	finally
	{
		Write-WELog " Restart-DellComputer Executed" " INFO"
	}	
}


[CmdletBinding()]
Function Activate-DellBIOSTPM
{
		[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
			[parameter(Mandatory=$true, HelpMessage=" Enter BIOS Admin Password. e.g. dell_admin " )]
			[ValidateNotNullOrEmpty()]
			[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAdminPwd,

			[parameter(Mandatory=$false, HelpMessage=" use -Restart switch if system Restart needs to be performed" )]
			[switch]$WERestart
		)
		try{
			
			#check if Admin password is set on the box
		; 	$WEIsBIOSAdminPasswordSet = Is-DellBIOSPasswordSet -PwdType " Admin" -EA stop
			
			if(!($WEIsBIOSAdminPasswordSet))
			{
				throw " Admin Password should be set to activate TPM"
			}
			
			#Activate TPM
			Set-DellBIOSAttribute -AttributeName " TpmActivation" -AttributeValueName " Enabled" -AdminPwd $WEAdminPwd -EA stop
			
			#After that restart the device, using Intune MDM or using PowerShell script.
			#restart the system if required, using Powershell Script
            if($WERestart)
            {
				#CAUTION: USER MIGHT LOSE UNSAVED WORK
			    Restart-DellComputer -Seconds 10
			}			
		}	
		catch
		{
		; 	$WEException = $_
			Write-Information $WEException
		}
		finally
		{
			Write-Information $result
			Write-WELog " Function Activate-DellBIOSTPM Executed" " INFO"	
		}
}






# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================