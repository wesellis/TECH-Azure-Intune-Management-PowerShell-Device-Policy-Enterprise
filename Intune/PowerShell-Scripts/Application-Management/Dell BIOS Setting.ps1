<#
.SYNOPSIS
    Dell Bios Setting

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
    We Enhanced Dell Bios Setting

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
   Set-DellBIOSAttribute -ErrorAction Stop cmdlet used to set single Dell BIOS attribute at a time.
   Set-DellBIOSAttributes -ErrorAction Stop cmdlet used to set multiple Dell BIOS attributes at a time.
   IMPORTANT: Make sure you are using latest Powershell version 5 or newer to execute this cmdlet. Execute " Get-Host" to check the version.
   IMPORTANT: Make sure direct WMI capabilities are supported on the system.
.DESCRIPTION
   Cmdlets used to either set single or multiple Dell BIOS attributes at a time, using Dell BIOS direct WMI capabilities. 
   Make sure you pass in exact name of the attribute and value since these are case sensitive. 
   Example: For attribute 'Camera', you must pass in " Camera" . Passing in " camera" will fail.
   
   - AttributeName or AttributeNames[] , REQUIRED, single or list of Dell BIOS Attribute names to be configured (case sensitive values)
   - AttributeValueName or AttributeValueNames[], REQUIRED, corresponding single or list of Dell BIOS AttributeValue names to be configured into (case sensitive values)
   - AdminPwd, OPTIONAL, Dell BIOS Admin password, if set on the client
   
.EXAMPLE
    This example shows how to configure a single Dell BIOS attribute (EnumerationAttribute) at a time, when Dell BIOS Admin Password is not set
	Set-DellBIOSAttribute -AttributeName " Camera" -AttributeValueName " Disabled"
.EXAMPLE
	This example shows how to configure a single Dell BIOS attribute (IntegerAttribute) at a time, when Dell BIOS Admin Password is not set
	Set-DellBIOSAttribute -AttributeName " AutoOnHr" -AttributeValueName " 10"
.EXAMPLE
	This example shows how to configure a single Dell BIOS attribute (StringAttribute) at a time, when Dell BIOS Admin Password is not set
	Set-DellBIOSAttribute -AttributeName " Asset" -AttributeValueName " DellProperty"
.EXAMPLE
	This example shows how to configure a single Dell BIOS attribute (EnumerationAttribute) at a time, when Dell BIOS Admin Password is set
	Set-DellBIOSAttribute -AttributeName " Camera" -AttributeValueName " Enabled" -AdminPwd " P@ssword"
.EXAMPLE
	This example shows how to configure a single Dell BIOS attribute (IntegerAttribute) at a time, when Dell BIOS Admin Password is set
	Set-DellBIOSAttribute -AttributeName " AutoOnHr" -AttributeValueName " 0" -AdminPwd " P@ssword"
.EXAMPLE
	This example shows how to configure a single Dell BIOS attribute (StringAttribute) at a time, when Dell BIOS Admin Password is set
	Set-DellBIOSAttribute -AttributeName " Asset" -AttributeValueName " " -AdminPwd " P@ssword"
	
.EXAMPLE
	This example shows how to configure multiple Dell BIOS attributes at a time, when Dell BIOS Admin Password is not set
	Set-DellBIOSAttributes -AttributeNames @(" Camera" , " AutoOnHr" , " Asset" ) -AttributeValueNames @(" Enabled" , " 1" , " DellProperty" )
.EXAMPLE
	This example shows how to configure multiple Dell BIOS attributes at a time, when Dell BIOS Admin Password is set
	Set-DellBIOSAttributes -AttributeNames @(" Camera" , " AutoOnHr" , " Asset" ) -AttributeValueNames @(" Enabled" , " 1" , " DellProperty" ) -AdminPwd " P@ssword"




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
    #Sets a single Dell BIOS Attribute at a time

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
	    $WEBIOSAttributes = Get-DellBIOSAttributes -EA stop

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
Function Set-DellBIOSAttributes -ErrorAction Stop
{
    #Sets multiple Dell BIOS Attributes at a time

    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$true, HelpMessage=" Enter a list of Dell BIOS AttributeNames. e.g. Camera, AutoOnHr, Asset " )]
		[ValidateNotNullOrEmpty()]
        [String[]]$WEAttributeNames,
        [Parameter(Mandatory=$true, HelpMessage=" Enter a list of Dell BIOS AttributeValueNames. e.g. Disabled, 1, DellProperty " )]
		[ValidateNotNull()]
        [AllowEmptyString()]
        [String[]]$WEAttributeValueNames,
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
	    
        $WEAttributeCount = $WEAttributeNames.Count

        if($WEIsBIOSAdminPasswordSet)
        {
            if(!([String]::IsNullOrEmpty($WEAdminPwd)))
			{
				#Get encoder for encoding password
	            $encoder = New-Object -ErrorAction Stop System.Text.UTF8Encoding
   
                #encode the password
               ;  $WEAdminBytes = $encoder.GetBytes($WEAdminPwd)

                #Configure BIOS Attribute
               ;  $status = $WEBAI | Invoke-CimMethod -MethodName SetAttributes -Arguments @{AttributeCount=$WEAttributeCount; AttributeNames=$WEAttributeNames; AttributeValueNames=$WEAttributeValueNames; SecType=1; SecHndCount=$WEAdminBytes.Length; SecHandle=$WEAdminBytes;} | Select-Object -ExpandProperty Status -EA stop
			}
			else
			{
				throw " Admin Password is required for this operation"
                    
			}                
        }
        else
        {
            #Configure BIOS Attribute
            $status = $WEBAI | Invoke-CimMethod -MethodName SetAttributes -Arguments @{AttributeCount=$WEAttributeCount; AttributeNames=$WEAttributeNames; AttributeValueNames=$WEAttributeValueNames; SecType=0; SecHndCount=0; SecHandle=@()} | Select-Object -ExpandProperty Status -EA stop 
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
       ;  $WEException = $_
		Write-Information $WEException
    }
    finally
    {
        Write-Information $result
		Write-WELog " Function Set-DellBIOSAttributes -ErrorAction Stop Executed" " INFO"
    }
}




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================