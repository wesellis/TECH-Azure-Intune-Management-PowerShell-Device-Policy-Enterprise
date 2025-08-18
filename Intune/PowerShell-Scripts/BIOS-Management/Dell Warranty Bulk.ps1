<#
.SYNOPSIS
    Dell Warranty Bulk

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
    We Enhanced Dell Warranty Bulk

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
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

_author_ = Prateek Vishwakarma <Prateek_Vishwakarma@Dell.com>
_version_ = 1.0

Copyright © 2023 Dell Inc. or its subsidiaries. All Rights Reserved.

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
	IT Administrators need a way to retrieve the warranty entitlement information of 
	list of client systems.
	For example - A list of client systems for which warranty expires in next 30 days.
	This helps with proactive plans of warranty renewal and inventory/audits.

.DESCRIPTION
	Get-DellWarrantyInBulk -ErrorAction Stop cmdlet can be used to fetch warranty entitlement information 
	of list of client systems.
	This cmdlet can be executed on a single windows endpoint, and need not deployed to 
	all the client systems.

	Scenario A : Using Get-DellWarrantyInBulk -ErrorAction Stop cmdlet, An Intune based IT Administrative 
	user can just use their Intune UPN and Password to fetch a list of service tags
	of their Dell IntuneManagedDevices and then bulk query the warranty entitlement 
	status using Dell Command | Warranty. 

	Scenario B : Using Get-DellWarrantyInBulk -ErrorAction Stop cmdlet, A Microsoft Endpoint Manager / 
	Configuration Manager (MEMCM) based IT Administrative user can fetch the list
	of service tags from the MEMCM Database in a CSV format and then pass the same 
	as input to Get-DellWarrantyInBulk -ErrorAction Stop cmdlet.

   	IMPORTANT: 
		1. Make sure you are using latest Powershell version 5 or newer to execute 
			this cmdlet. Execute " Get-Host" to check the version.
		2. Make sure Dell Command | Warranty application is installed on the endpoint.
			https://www.dell.com/support/kbdoc/en-us/000146749/dell-command-warranty
		3. Make sure you have working internet connection to query warranty information.
		4. This script installs " Microsoft.Graph.Intune" powershell module from 
			PSGallery, if user wishes to fetch Dell service tags from Intune environment.
   
	Following is description of Get-DellWarrantyInBulk -ErrorAction Stop cmdlet parameters -

	- AdminUPN, 	[string],       REQUIRED (Scenario A),  
		User Principal Name of Intune Administrative user.

	- AdminPwd, 	[SecureString], REQUIRED (Scenario A),  
		Password of adminUPN user (in a SecureString format).

	- InputCSV, 	[string],       REQUIRED (Scenario B),  
		Full path to CSV file (containing list of Dell service tags).

	- OutputDir,	[string],       OPTIONAL,				
		Path of Output directory (where warranty details will be exported).
		The cmdlet generates output in $WEPSScriptRoot path, in case user does not sets 
		OutputDir.

	- Filter,		[string],       OPTIONAL,				
		Optional filters that can be used while querying warranty information.
		 e.g. 
		 - ActiveWarranty - Exports active warranty entitlement information.
		 - WarrantyExpiringIn30Days - Exports warranty entitlement information where 
		 								entitlement expires in 30 days.
		 - ExpiredWarranty - Exports expired warranty entitlement information. 
		Default: AnyWarranty - Exports all warranty entitlement information. 

	- ProxyServer,	[string],       OPTIONAL,				
		Proxy server URL without port e.g., https://<proxy_url>.

	- ProxyPort,	[string],       OPTIONAL,				
		Proxy server port e.g., 80.

	- ProxyUser,	[string],       OPTIONAL,				
		Proxy user name.

	- ProxyPassword,[SecureString],	OPTIONAL,				
		Proxy user password (in a SecureString format).

	
	NOTE: 
		Following commands can be used to convert plaintext password to SecureString:

		$password = " <your_password>"
		[Security.SecureString]$securePassword = ConvertTo-SecureString $password `
		-AsPlainText -Force	

.EXAMPLE
	This example shows how to fetch bulk warranty in an intune environment (Scenario A).
    Get-DellWarrantyInBulk -AdminUPN " user@company.com" -AdminPwd $securePassword

.EXAMPLE
	This example shows how to fetch bulk warranty (Scenario A) WarrantyExpiringIn30Days
	 entitlements.
    Get-DellWarrantyInBulk -AdminUPN " user@company.com" -AdminPwd $securePassword `
	-Filter WarrantyExpiringIn30Days

.EXAMPLE
	This example shows how to fetch bulk warranty (Scenario A) behind Proxy.
    Get-DellWarrantyInBulk -AdminUPN " user@company.com" -AdminPwd $securePassword `
	-ProxyServer https://<proxy_url> -ProxyPort 80 -ProxyUser " proxy_user_name" `
	-ProxyPassword $secureProxyUserPassword

.EXAMPLE
	This example shows how to fetch bulk warranty in a MEMCM envronment (Scenario B).
    Get-DellWarrantyInBulk -InputCSV <Full path to input csv file `
	containing dell service tags>

.EXAMPLE
	This example shows how to fetch bulk warranty (Scenario B) ExpiredWarranty. 
	entitlements
    Get-DellWarrantyInBulk -InputCSV <Full path to input csv file `
	containing dell service tags> -Filter ExpiredWarranty

.EXAMPLE
	This example shows how to fetch bulk warranty (Scenario B) behind proxy.
    Get-DellWarrantyInBulk -InputCSV <Full path to input csv file `
	containing dell service tags> `
	-ProxyServer https://<proxy_url> -ProxyPort 80 -ProxyUser " proxy_user_name" `
	-ProxyPassword $secureProxyUserPassword



[CmdletBinding()]
Function Get-DellWarrantyInBulk -ErrorAction Stop
{	
	[CmdletBinding(DefaultParameterSetName = 'UsingGraph')]
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
		[parameter(Mandatory=$true,
					ParameterSetName = 'UsingGraph',
		 			HelpMessage=" Enter User Principal Name of Intune Administrative user " )]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAdminUPN,
		
		[parameter(Mandatory=$true,
					ParameterSetName = 'UsingGraph', 
					HelpMessage=" Enter password for adminUPN in a SecureString format " )]
        [ValidateNotNullOrEmpty()]
		[Security.SecureString]$WEAdminPwd,

		[parameter(Mandatory=$true,
					ParameterSetName = 'UsingCSV', 
					HelpMessage=" Enter full path to CSV file with list of Dell service tags " )]	
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEInputCSV,

		[parameter(Mandatory=$false, 
					HelpMessage=" Enter output directory for warranty details " )]
        [ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEOutputDir,

		[parameter(Mandatory=$false, 
					HelpMessage=" Enter optional filter e.g. WarrantyExpiringIn30Days. `
					Default: AnyWarranty " )]
        [ValidateNotNullOrEmpty()]
		[ValidateSet(" ActiveWarranty" , " ExpiredWarranty" , " WarrantyExpiringIn30Days" )]
		[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEFilter,

		[parameter(Mandatory=$false, 
					HelpMessage=" Enter the Proxy Server to use custom proxy settings. `
					/<proxy_url> " )]
        [ValidateNotNullOrEmpty()]		
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEProxyServer,
        
        [parameter(Mandatory=$false, 
					HelpMessage=" Enter the Proxy Port. e.g. 80 " )]
        [ValidateNotNullOrEmpty()]		
        [int]$WEProxyPort,
        
        [parameter(Mandatory=$false, 
					HelpMessage=" Enter the Proxy User Name. " )]
        [ValidateNotNullOrEmpty()]		
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEProxyUser,
        
        [parameter(Mandatory=$false, 
					HelpMessage=" Enter the Proxy Password in a SecureString format. " )]
        [ValidateNotNullOrEmpty()]		
        [SecureString]$WEProxyPassword
    )
	
	try
	{	
		# ** Pre-requisite validation. ***
		
		$WEProgramFilesx86Path = [Environment]::GetEnvironmentVariable(" ProgramFiles(x86)" ) 
		$WEDCWPath = Join-Path $WEProgramFilesx86Path -ChildPath " Dell" `
					| Join-Path -ChildPath " CommandIntegrationSuite" `
					| Join-Path -ChildPath " DellWarranty-CLI.exe"
		
		if (-not(Test-Path $WEDCWPath))
		{
			Write-Error " Dell Command | Warranty is not installed. `
						Please retry after installation."
			exit $1
		}

		# ** Input validation. ***

        If (-not((-not($WEProxyServer) -and -not($WEProxyPort) -and -not($WEProxyUser) -and -not($WEProxyPassword)) -or 
			  ($WEProxyServer -and $WEProxyPort -and -not($WEProxyUser) -and -not($WEProxyPassword)) -or 
			  ($WEProxyServer -and $WEProxyPort -and $WEProxyUser -and $WEProxyPassword)
			))        
			{
				Write-Error " Mandatory proxy arguments missing"
				exit $1
			} 
		
		If(-not($WEOutputDir))
		{
			$WEOutputDir = $WEPSScriptRoot
		}
		
		If(-not(Test-Path -Path $WEOutputDir))
        {           
            Try
		    {
                Write-Information Creating output directory: $WEOutputDir `n
			    New-Item -Path $WEOutputDir -ItemType Directory -Force | Out-Null
				
				# Apply ACL

				Write-Information Applying ACL to Folder: $WEOutputDir `n
				$WEACL = Get-Item -ErrorAction Stop $WEOutputDir | get-acl -ErrorAction Stop
				# Remove inheritance
				$WEACL.SetAccessRuleProtection($true,$true)
				$WEACL | Set-Acl -ErrorAction Stop
				# Remove Users
				$accessrule = New-Object -ErrorAction Stop system.security.AccessControl.FileSystemAccessRule(" users" ," Read" ,,," Allow" )
				$WEACL.RemoveAccessRuleAll($accessrule)
				Set-Acl -Path $WEOutputDir -AclObject $WEACL                
		    }
		    Catch
		    {
                Write-Information Error creating output directory $WEOutputDir `n
			    Write-Error " $($_.Exception)"
                exit $1
		    }
        }
        else
        {            
            $WEOutputDirObj = Get-Item -ErrorAction Stop $WEOutputDir -Force -ea SilentlyContinue
            if([bool]($WEOutputDirObj.Attributes -band [IO.FileAttributes]::ReparsePoint))
            { 
                Write-Error " Directory reparse point exists for $WEOutputDir. `
				 Select another directory and retry... "
                exit $1
            }
        }

		$WEInputCSVFilePath = $WEInputCSV

		If($WEInputCSVFilePath)
		{
			if(-not(Test-Path -Path $WEInputCSVFilePath -PathType Leaf))
			{
				Write-Error " Input CSV file not found"
				exit $1
			}
		}
		else
		{
			$WERemoveModule = $false
			
			# Prepare the input filename

			$WEFileName = " Input.csv"
			$WEFileTimeStamp = (get-date -format yyyyMMdd_HHmmss) + " _" + $WEFileName
			$WEFilePath = Join-Path $WEPSScriptRoot -ChildPath $WEFileTimeStamp
			Write-WELog " FilePath: $WEFilePath" " INFO"

			# Install the PowerShell module for Microsoft Graph from PS gallery.

			if (Get-Module -ListAvailable -Name " Microsoft.Graph.Intune" ) 
			{
				Write-WELog " Microsoft.Graph.Intune PowerShell module exists" " INFO"
			} 
			else 
			{
				# MIT License 
				# https://www.powershellgallery.com/packages/Microsoft.Graph.Intune/6.1907.1.0/Content/LICENSE.txt
				Install-Module -Name Microsoft.Graph.Intune `
								-Repository PSGallery `
								-AllowClobber `
								-Scope CurrentUser `
								-Force `
								-ErrorAction stop
			
				$WERemoveModule = $true
			}

			# Verify Installation

			If (-not(Get-InstalledModule -ErrorAction Stop Microsoft.Graph.Intune -ErrorAction SilentlyContinue)) 
			{
				Write-Error " Microsoft.Graph.Intune PowerShell module installation failed"
				exit $1
			}
			
			# Import the Microsoft.Graph.Intune module
			Import-Module Microsoft.Graph.Intune -ErrorAction SilentlyContinue	

			# Authenticate with Microsoft Graph.
			# Create the PSCredential object.
			
			$WEAdminCred = New-Object -ErrorAction Stop System.Management.Automation.PSCredential ($adminUPN, $adminPwd)

			# Log in with these credentials
			Connect-MSGraph -PSCredential $WEAdminCred | Out-Null


			# Retrieve list of device serial number.

			#$WEServiceTags = Get-IntuneManagedDevice -Filter " startswith(deviceName,'DELL_')" | | Select-Object -Property serialNumber
			$WEServiceTags = Get-IntuneManagedDevice -ErrorAction Stop | Select-Object -Property serialNumber

			if($WERemoveModule -eq $true)
			{
				Write-WELog " Removing Microsoft.Graph.Intune module" " INFO"
                Remove-Module -Name Microsoft.Graph.Intune -Force
			}

			[System.Collections.ArrayList]$WEValidServiceTags = @()
			foreach ($serviceTag in $WEServiceTags)
			{
				if (($serviceTag.serialNumber -ne "" ) `
					-and ($null -ne $serviceTag.serialNumber) `
					-and ($serviceTag.serialNumber -match '.*\b[A-Z\d]{7}\b.*'))
				{
					[void]$WEValidServiceTags.Add($serviceTag.serialNumber)
				}
			}

			$WEValidServiceTags | Out-File $WEFilePath
			$WEInputCSVFilePath = $WEFilePath
        }


		# Prepare the output filename

		$WEOutputCSVFileName = " WarrantyOutput.csv"
		$WEFileTimeStamp = (get-date -format yyyyMMdd_HHmmss) + " _" + $WEOutputCSVFileName
		$WEOutputCSVFilePath = Join-Path $WEOutputDir -ChildPath $WEFileTimeStamp


		
		# Create the list of arguments to invoke Dell Command | Warranty

		$WEOptionalArguments = " "
		
		if($WEFilter)
		{
			$WEOptionalArguments = $WEOptionalArguments + " /F=" + $WEFilter
		}

		if($WEProxyServer -and $WEProxyPort)
		{
			$WEProxyServerPort = $WEProxyServer.Trim() + " :" + $WEProxyPort
			$WEOptionalArguments = $WEOptionalArguments + " /Ps=" + $WEProxyServerPort
		}

		if($WEProxyUser -and $WEProxyPassword)
		{
			$WEUnsecureProxyPassword = [System.Net.NetworkCredential]::new("" , $WEProxyPassword).Password
			$WEOptionalArguments = $WEOptionalArguments + " /Pu=" + $WEProxyUser + " /Pd=" + $WEUnsecureProxyPassword
		}

       ;  $arglist = @((" /I=" + $WEInputCSVFilePath + " /E=" + $WEOutputCSVFilePath + $WEOptionalArguments ))
	
		# Invoke Dell Command | Warranty

		Start-Process -FilePath $WEDCWPath -ArgumentList $arglist -WindowStyle Hidden 
		
	}
	Catch
	{
	; 	$WEException = $_
		Write-Error " Exception:" $WEException
	}
	Finally
	{
		Write-WELog " Function Get-DellWarrantyInBulk -ErrorAction Stop Executed" " INFO"
		Write-WELog " Observe Dell | Command Warranty log files for more information" " INFO" 
	}
}








} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
