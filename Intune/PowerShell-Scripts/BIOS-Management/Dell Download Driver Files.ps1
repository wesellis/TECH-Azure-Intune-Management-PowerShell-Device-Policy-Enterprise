<#
.SYNOPSIS
    Dell Download Driver Files

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
    We Enhanced Dell Download Driver Files

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

_author_ = Supreeth Dayananda <Supreeth_D1@Dell.com>
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
   Get-DellDriverPack cmdlet used to retrieve the driver pack for the individual system.
   This script can be used by an administrative user to download all the drivers for a particular system that can be later deployed to that system.
   IMPORTANT: Make sure you are using latest PowerShell version 5 or newer to execute this cmdlet. Execute " Get-Host" to check the version.   
.DESCRIPTION
   Cmdlet used to retrieve driver pack for the individual system that is applicable and can installed for that particular system. 
   - SystemID, REQUIRED, the Platform System ID or BIOS ID of the system for which the drivers must be downloaded.
     Note: System ID can be found under System Information -> System Summary -> System SKU (System ID or BIOS ID)
           win + R, type msinfo32 to get the System Information. Under System Information look for System SKU. 
           PowerShell Command to get the Platform System ID or BIOS ID of the system -
                   (Get-CimInstance Win32_ComputerSystem).SystemSKUNumber
   - SystemOS, REQUIRED, the target Operating System on which the drivers will be installed.
   - DownloadDir, REQUIRED, the download path where all the driver files will be downloaded.
   - ProxyServer, OPTIONAL, the custom proxy server address.
   - ProxyPort, OPTIONAL, the custom proxy server port.
   - ProxyUser, OPTIONAL, the custom proxy Username.
   - ProxyPassword, OPTIONAL, the custom Proxy Password
     The ProxyPassword is a SecureString parameter, user must convert to SecureString before passing the ProxyPassword parameter to 
     Get-DellDriverPack cmdlet.
     e.g. $WEProxyPass = " Password"
          $WESecureProxyPassword = ConvertTo-SecureString $WEProxyPass -AsPlainText -Force

.EXAMPLE
	This example shows how to download the Driver packages using SystemID, System-OS and Download-Directory
	Get-DellDriverFiles -SystemID " 0A40" -SystemOS " Windows 10 x64" -DownloadDir " LocalPath"
.EXAMPLE
	This example shows how to download the Driver packages using the custom proxy settings
	Get-DellDriverFiles -SystemID " 0A40" -SystemOS " Win 10 x64" -DownloadDir " LocalPath" -ProxyServer " http://<proxy_url>" -ProxyPort " 80"
.EXAMPLE
	This example shows how to download the Driver packages using the custom proxy settings using user credentials
	$WEProxyPass = " Password"
    $WESecureProxyPassword = ConvertTo-SecureString $WEProxyPass -AsPlainText -Force
    Get-DellDriverFiles -SystemID " 0A40" -SystemOS " Win 10 x64" -DownloadDir " LocalPath" -ProxyServer " http://<proxy_url>" -ProxyPort " 80" -ProxyUser " Username" -ProxyPassword $WESecureProxyPassword


Function Get-DellDriverFiles
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory=$true, HelpMessage=" Enter target System ID or BIOS ID for which the drivers must be downloaded. e.g. 0A40 " )]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESystemID,	

        [parameter(Mandatory=$true, HelpMessage=" Enter the target Operating System on which the drivers will be installed. e.g. Windows 11 x64" )]
        [ValidateNotNullOrEmpty()]
		[ValidateSet(" Windows 10 x64" , " Windows 11 x64" )]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESystemOS,
        
        [parameter(Mandatory=$true, HelpMessage=" Enter the download folder location where the files will be downloaded. " )]
        [ValidateNotNullOrEmpty()]		
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEDownloadDir,
        
        [parameter(Mandatory=$false, HelpMessage=" Enter the Proxy Server to use custom proxy settings. e.g. http://<proxy_url> " )]
        [ValidateNotNullOrEmpty()]		
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEProxyServer,
        
        [parameter(Mandatory=$false, HelpMessage=" Enter the Proxy Port. e.g. 80 " )]
        [ValidateNotNullOrEmpty()]		
        [int]$WEProxyPort,
        
        [parameter(Mandatory=$false, HelpMessage=" Enter the Proxy User Name. " )]
        [ValidateNotNullOrEmpty()]		
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEProxyUser,
        
        [parameter(Mandatory=$false, HelpMessage=" Enter the Proxy Password. " )]
        [ValidateNotNullOrEmpty()]		
        [SecureString]$WEProxyPassword	
		
	)
	
	try
	{

        # ** Mandatory Proxy Arguments Validation. ***
        
        If(!((!$WEProxyServer -and !$WEProxyPort -and !$WEProxyUser -and !$WEProxyPassword) -or 
           ($WEProxyServer -and $WEProxyPort -and !$WEProxyUser -and !$WEProxyPassword) -or 
           ($WEProxyServer -and $WEProxyPort -and $WEProxyUser -and $WEProxyPassword)))        
        {
            Write-Host Error: Missing Mandatory Proxy Arguments `n -BackgroundColor Red
            exit $1
        }           
        
        # DriverCabCatalog File Name
        $WEDriverCabCatalogFileName = " DriverPackCatalog.cab"
        # DriverCabCatalog XML File Name
        $WEDriverCabCatalogXMLFileName = " DriverPackCatalog.xml"
        # DriverPackCatalog.cab file URL
		$WEDriverCabCatalog = " https://downloads.dell.com/catalog/DriverPackCatalog.cab"          
        # Download directory name (System_ID_System_OS)
        $WEDownloadDirName = $WESystemID.Trim() + " " + $WESystemOS.Trim()                                        
        $WEDownloadDirName = $WEDownloadDirName.Replace(" " ," _" )
        # Download folder path                                    
        $WEDriverDownloadFolder = Join-Path -Path $WEDownloadDir -ChildPath $WEDownloadDirName 
        # DriverPackCatalog.cab download path                       
        $WEDriverCabCatalogFile = Join-Path -Path $WEDriverDownloadFolder -ChildPath $WEDriverCabCatalogFileName 
        # DriverPackCatalog.xml extraction path
        $WEDriverCatalogXMLFile = Join-Path -Path $WEDriverDownloadFolder -ChildPath $WEDriverCabCatalogXMLFileName                             
        
        # *** Check if download directory exists, if it does not exist create download directory ***
        Try
        {
            $WEDownloadDir = Resolve-Path -Path $WEDownloadDir
        }
        Catch
		{
            Write-Host Error resolving path $WEDownloadDir `n
			Write-Error " $($_.Exception)"            
            Try
		    {
                Write-Host Creating Download Directory: $WEDownloadDir `n
			    New-Item -Path $WEDownloadDir -ItemType Directory -Force | Out-Null                
		    }
		    Catch
		    {
                Write-Host Error creating download directory $WEDownloadDir `n
			    Write-Error " $($_.Exception)"
                exit $1
		    }            
		}
        If(!(Test-Path -Path $WEDownloadDir))
        {           
            Try
		    {
                Write-Host Creating Download Directory: $WEDownloadDir `n
			    New-Item -Path $WEDownloadDir -ItemType Directory -Force | Out-Null                
		    }
		    Catch
		    {
                Write-Host Error creating download directory $WEDownloadDir `n
			    Write-Error " $($_.Exception)"
                exit $1
		    }
        }
        else
        {            
            $WEDownloadDirFile = Get-Item $WEDownloadDir -Force -ea SilentlyContinue
            if([bool]($WEDownloadDirFile.Attributes -band [IO.FileAttributes]::ReparsePoint))
            { 
                Write-WELog " Directory Reparse Point Exists for $WEDownloadDir. Select another directory and re-run script..." " INFO" `n -BackgroundColor Red
                exit $1
            }
        }

        # *** If the System_Model_System_OS folder exists in the Download directory, delete the folder. ***

        If(Test-Path -Path $WEDriverDownloadFolder)
        {           
            Try
		    {
                Write-Host Deleting Folder: $WEDriverDownloadFolder `n
			    Remove-Item -Path $WEDriverDownloadFolder -Recurse -Force | Out-Null                
		    }
		    Catch
		    {
                Write-Host Error deleting directory $WEDriverDownloadFolder `n
			    Write-Error " $($_.Exception)"
                exit $1
		    }
        }
         
        # *** Create System_Model_System_OS folder under Download directory. ***   
               
        Try
		{
            Write-Host Creating Folder: $WEDriverDownloadFolder `n
			
            New-Item -Path $WEDriverDownloadFolder -ItemType Directory -Force | Out-Null
            
            # Apply ACL
            
            Write-Host Applying ACL to Folder: $WEDriverDownloadFolder `n
            
            $WEACL = Get-Item $WEDriverDownloadFolder | get-acl
            # Remove inheritance
            $WEACL.SetAccessRuleProtection($true,$true)
            $WEACL | Set-Acl
            # Remove Users
            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule(" users" ," Read" ,,," Allow" )
            $WEACL.RemoveAccessRuleAll($accessrule)
            Set-Acl -Path $WEDriverDownloadFolder -AclObject $WEACL                
		}
		Catch
		{
            Write-Host Error creating directory $WEDriverDownloadFolder `n
			Write-Error " $($_.Exception)"
            exit $1
		}
        
        
        # *** To Download the Driver Cab Catalog. ***

        try {
              Write-Host Downloading DriverPackCatalog file... `n          
              $WEWebClient = New-Object -TypeName System.Net.WebClient
              # *** Check if Custom Proxy Settings is passed and set the custom proxy settings. ***
              if($WEProxyServer -and $WEProxyPort -and $WEProxyUser -and $WEProxyPassword)
              {
                $WEProxyServerAddress = $WEProxyServer.Trim() + " :" + $WEProxyPort.ToString()
                Write-Host Downloading DriverPackCatalog File using Custom Proxy Settings using Proxy Credentials. `n
                $WEWebProxy = New-Object System.Net.WebProxy($WEProxyServerAddress,$true)           
                $WEWebProxyCredentials = (New-Object Net.NetworkCredential($WEProxyUser.Trim(),$WEProxyPassword)).GetCredential($WEProxyServer.Trim(),$WEProxyPort," KERBEROS" ) 
                $WEWebProxy.Credentials = $WEWebProxyCredentials            
                $WEWebClient.Proxy = $WEWebProxy                 
              }
              elseif($WEProxyServer -and $WEProxyPort)
              {
                $WEProxyServerAddress = $WEProxyServer.Trim() + " :" + $WEProxyPort.ToString()
                Write-Host Downloading DriverPackCatalog File using Custom Proxy Settings. `n
                $WEWebProxy = New-Object System.Net.WebProxy($WEProxyServerAddress,$true)         
                $WEWebClient.Proxy = $WEWebProxy                         
              }

              $WEWebClient.DownloadFile($WEDriverCabCatalog, " $WEDriverCabCatalogFile" )
              
              if (Test-Path " $WEDriverCabCatalogFile" )
			  {                   
                 Write-Host DriverPackCatalog file downloaded successful. `n
              }
              else
              {
                    Write-Host DriverPackCatalog file is not downloaded! `n -BackgroundColor Red 
                    exit $1
              }              
            }
        catch [System.Net.WebException]
            {
                Write-Error " $($_.Exception)"
                exit $1
            }


        # *** To Extract the DriverPackCatalog file. ***
        
        try {
                Write-Host Extracting DriverPackCatalog file... `n  
                expand -r $WEDriverCabCatalogFile $WEDriverDownloadFolder
                if (Test-Path " $WEDriverCatalogXMLFile" )
			    {
                   Write-Host DriverPackCatalog file extraction successful. `n
                }
                else
                {
                    Write-Host DriverPackCatalog XML file extraction failed! `n -BackgroundColor Red 
                    exit $1
                }               	                        
            }
        catch [Exception] 
            {
                Write-Error " $($_.Exception)"
                exit $1
            }

        try {
            [xml]$WECatalogXML = Get-Content -Path $WEDriverCatalogXMLFile -ErrorAction Ignore
            [array]$WEDriverPackages = $WECatalogXML.DriverPackManifest.DriverPackage
            $urlBase = " https://downloads.dell.com/"
            $WENoDriverMatchFound = $true
            foreach ($WEDriverPackage in $WEDriverPackages)
	        {
                # Driver Package Name
                $WEDriverPackageName = $WEDriverPackage.Name.Display.'#cdata-section'.Trim()           
                # Driver Match Found Flag
                $WEDriverMatchFound = $false                                                         
                # Driver Download url
                $WEDriverDownloadPath = -join($urlBase, $WEDriverPackage.path)                         
                # Driver Download Path
                $WEDriverDownloadDestPath = -join($WEDriverDownloadFolder," \$WEDriverPackageName" )       

                foreach ($WESupportedSystems in $WEDriverPackage.SupportedSystems.Brand)
			    {
                    $WESystemIDFromCatalog = $WESupportedSystems.Model.systemID
			        
                    # Check for System ID Match
				    if ($WESystemIDFromCatalog -eq $WESystemID)
				    {                            
                        # Check for System OS Match
                        foreach ($WESupportedOS in $WEDriverPackage.SupportedOperatingSystems)
			            {
				            if ($WESupportedOS.OperatingSystem.Display.'#cdata-section'.Trim() -match $WESystemOS)
				            {  
                                $WENoDriverMatchFound = $false                                  
					            $WEDriverMatchFound = $true
				            }				
			            }
				    }				
			    }           		           
   
		        # *** Download the driver if both System ID and System OS match found. ***
		            
		        if ($WEDriverMatchFound)
		        {     
                    Write-Host Downloading driver file! `n The download might take some time... `n Make sure the internet is not disconnected! `n -BackgroundColor Gray
                    # Adding stopwatch to get the total time taken to download the driver.
                    $WEStopWatch = [system.diagnostics.stopwatch]::StartNew() 
                    $WEWebClient = New-Object -TypeName System.Net.WebClient

                    # *** Check if Custom Proxy Settings is passed and set the custom proxy settings. ***
                    if($WEProxyServer -and $WEProxyPort -and $WEProxyUser -and $WEProxyPassword)
                    {
                        $WEProxyServerAddress = $WEProxyServer.Trim() + " :" + $WEProxyPort.ToString()
                        Write-Host Downloading Driver using Custom Proxy Settings using Proxy Credentials. `n
                        $WEWebProxy = New-Object System.Net.WebProxy($WEProxyServerAddress,$true)           
                        $WEWebProxyCredentials = (New-Object Net.NetworkCredential($WEProxyUser.Trim(),$WEProxyPassword)).GetCredential($WEProxyServer.Trim(),$WEProxyPort," KERBEROS" ) 
                        $WEWebProxy.Credentials = $WEWebProxyCredentials            
                        $WEWebClient.Proxy = $WEWebProxy                 
                    }
                    elseif($WEProxyServer -and $WEProxyPort)
                    {
                        $WEProxyServerAddress = $WEProxyServer.Trim() + " :" + $WEProxyPort.ToString()
                        Write-Host Downloading Driver using Custom Proxy Settings. `n
                        $WEWebProxy = New-Object System.Net.WebProxy($WEProxyServerAddress,$true)         
                        $WEWebClient.Proxy = $WEWebProxy                         
                    }

                    $WEWebClient.DownloadFile($WEDriverDownloadPath, $WEDriverDownloadDestPath)
                    $WEStopWatch.Stop()
                    $WETotalDriverDownloadTime = $WEStopWatch.Elapsed    
                    
                    # *** Once Driver Download is completed Check if the SHA256 hash matches with the downloaded driver. ***
                    if (Test-Path " $WEDriverDownloadDestPath" )
					{   
                        Write-WELog " Driver download successful: $WEDriverPackageName `n" " INFO"
                        Write-WELog " Total time taken to download driver $WEDriverPackageName (hh:mm:ss.ms): $WETotalDriverDownloadTime `n" " INFO"    
                        # MD5 hash from the xml file           		
		               ;  $WEMD5Hash = $WEDriverPackage.Cryptography.Hash | Where-Object { $_.algorithm -eq 'SHA256' } | Select-Object -ExpandProperty " #text"       
                        # MD5 hash of the downloaded driver file
                       ;  $WEDriverFileMD5Hash = Get-FileHash $WEDriverDownloadDestPath -Algorithm SHA256                                                        
		                if($WEMD5Hash -eq $WEDriverFileMD5Hash.Hash)
                        {
                            Write-WELog " MD5 hash match successful - $WEDriverPackageName. `n" " INFO"
                        }
                        else
                        {
                            Write-WELog " MD5 has match failed. Hence, deleting the driver file $WEDriverPackageName. `n" " INFO"
                            Remove-Item -Path $WEDriverDownloadDestPath -Recurse -Force | Out-Null
                        }
                    }
                    else
                    {
                        Write-WELog " Driver download failed: $WEDriverPackageName `n" " INFO"
                    }                  
			                                  
		        }		            
		
	        }
            
            if($WENoDriverMatchFound -eq $true)
            {
                Write-WELog " No Driver Match found for the SystemID: $WESystemID, OS: $WESystemOS. `n" " INFO"
                Write-WELog " Contact Dell Support. `n" " INFO"
            }	

            }
        catch [Exception] 
            {
                Write-Error " $($_.Exception)"
            }
		
	}	
	catch
	{
		Write-Error " $($_.Exception)"
	}
	Finally
	{
        # Delete DriverPackCatalog.cab file	
        if($WEDriverCabCatalogFile)
        {	
            if(Test-Path $WEDriverCabCatalogFile) 
            {
                Remove-Item -Path $WEDriverCabCatalogFile -Recurse -Force | Out-Null
            }
        }
        # Delete DriverPackCatalog.xml file
        if($WEDriverCatalogXMLFile)
        {
            if(Test-Path $WEDriverCatalogXMLFile)
            {
                Remove-Item -Path $WEDriverCatalogXMLFile -Recurse -Force | Out-Null
            }
        }
		Write-WELog " Function Get-DellDriverFiles Executed" " INFO"
	}
}




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================