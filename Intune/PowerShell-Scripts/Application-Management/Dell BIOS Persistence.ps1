<#
.SYNOPSIS
    Dell Bios Persistence

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
    We Enhanced Dell Bios Persistence

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
   Set-DellBIOSAttributeAbsolute cmdlet used to configure Absolute Dell BIOS Attribute.
   IMPORTANT: Make sure you are using latest Powershell version 5 or newer to execute this cmdlet. Execute " Get-Host" to check the version.
   IMPORTANT: Make sure direct WMI capabilities are supported on the system.
.DESCRIPTION
   Make sure you pass in exact name of the attribute and value since these are case sensitive. 
   Example: For attribute 'Absolute', you must pass in " Absolute" . Passing in " absolute" will fail.
   
   - AttributeValueName, REQUIRED, Possible Values for Absolute are 'Enabled', 'Disabled' and 'PermanentlyDisabled' (case sensitive values)
   - AdminPwd, OPTIONAL, Dell BIOS Admin password, if set on the client
   
.EXAMPLE
    This example shows how to configure 'Absolute' Dell BIOS Attribute, when Dell BIOS Admin Password is not set
	Set-DellBIOSAttributeAbsolute -AttributeValueName " Disabled"
.EXAMPLE
	This example shows how to configure 'Absolute' Dell BIOS Attribute, when Dell BIOS Admin Password is set
	Set-DellBIOSAttributeAbsolute -AttributeValueName " Enabled" -AdminPwd " P@ssword"





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


Function Get-DellBIOSAttributes
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
        Write-WELog " Function Get-DellBIOSAttribute Executed" " INFO"
    }
}


Function Set-DellBIOSAttributeAbsolute
{
    #Configures Absolute

    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
		[Parameter(Mandatory=$true, HelpMessage=" Enter Dell BIOS AttributeValueName. e.g. Possible Values for Absolute are Enabled, Disabled and PermanentlyDisabled" )]
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
	    $WEBIOSAttributes = Get-DellBIOSAttributes -EA stop

	    $WECurrentValue = $WEBIOSAttributes | Where-Object AttributeName -eq " Absolute" | Select-Object -ExpandProperty CurrentValue -EA Stop

	    if($WENULL -ne $WECurrentValue)
	    {
		    #Check if Absolute is already set to given value
		    if($WECurrentValue -eq $WEAttributeValueName)
		    {
			    Write-WELog " Attribute Absolute is already set to " " INFO" $WEAttributeValueName""
		    }
			
			#Check if Absolute is set to PermanentlyDisabled
		    if($WECurrentValue -eq " PermanentlyDisabled" )
		    {
			    Write-WELog " Attribute Absolute is set to 'PermanentlyDisabled', it cannot be modified. " " INFO" 
		    }

		    #Absolute is not set to given value
		    else
		    {
                if($WEIsBIOSAdminPasswordSet)
                {
                    if(!([String]::IsNullOrEmpty($WEAdminPwd)))
			        {
				        #Get encoder for encoding password
	                    $encoder = New-Object System.Text.UTF8Encoding
   
                        #encode the password
                       ;  $WEAdminBytes = $encoder.GetBytes($WEAdminPwd)

                        #Configure BIOS Attribute
                       ;  $status = $WEBAI | Invoke-CimMethod -MethodName SetAttribute -Arguments @{AttributeName=" Absolute" ; AttributeValue=$WEAttributeValueName; SecType=1; SecHndCount=$WEAdminBytes.Length; SecHandle=$WEAdminBytes;} | Select-Object -ExpandProperty Status -EA stop
			        }
			        else
			        {
				        throw " Admin Password is required for this operation"
                    
			        }                
                }
                else
                {
                    #Configure Absolute
                    $status = $WEBAI | Invoke-CimMethod -MethodName SetAttribute -Arguments @{AttributeName=" Absolute" ; AttributeValue=$WEAttributeValueName; SecType=0; SecHndCount=0; SecHandle=@()} | Select-Object -ExpandProperty Status -EA stop 
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
	    }
	    #BIOS Attribute not present
	    else
	    {
		    Write-WELog " Attribute: Absolute not present on the system" " INFO" 
	    }
    }
    catch
    {
       ;  $WEException = $_
		Write-Host $WEException
    }
    finally
    {
        Write-Host $result
		Write-WELog " Function Set-DellBIOSAttributeAbsolute Executed" " INFO"
    }
}




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================