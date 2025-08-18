<#
.SYNOPSIS
    Dell Install Driver Files

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
    We Enhanced Dell Install Driver Files

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
   Install-DellDriverFiles cmdlet used to download and install the driver pack for the individual system.
   This script can be used by an administrative user to download and install all the drivers for a particular system.
   IMPORTANT: Make sure you are using latest PowerShell version 5 or newer to execute this cmdlet. Execute " Get-Host" to check the version.
   IMPORTANT: Make sure to run this script in 64-bit PowerShell Host only. As PNPUtil command to install drivers is supported only on 64-bit. 
              While deploying the script via Intune, make sure to select " Yes" - " Run Script in 64-bit PowerShell Host" .    
.DESCRIPTION
   Cmdlet used to download and install driver pack for the individual system. 
   - DownloadDir, REQUIRED, the download path where all the driver files will be downloaded and installed from.
   - Restart, OPTIONAL, pass in -Restart switch if local system restart needs to be performed after driver installation (recommended)
   - ProxyServer, OPTIONAL, the custom proxy server address.
   - ProxyPort, OPTIONAL, the custom proxy server port.
   - ProxyUser, OPTIONAL, the custom proxy Username.
   - ProxyPassword, OPTIONAL, the custom Proxy Password
     The ProxyPassword is a SecureString parameter, user must convert to SecureString before passing the ProxyPassword parameter to 
     Install-DellDriverFiles cmdlet.
     e.g. $WEProxyPass = " Password"
          $WESecureProxyPassword = ConvertTo-SecureString $WEProxyPass -AsPlainText -Force
     NOTE:
     1. This Script will create a Log File - " DellDriverInstaller_Log.txt" under the DownloadDir to track the driver installation data.
     
.EXAMPLE
	This example shows how to download and install the Driver packages using Download-Directory
	Install-DellDriverFiles -DownloadDir " LocalPath"
.EXAMPLE
	This example shows how to download and install the Driver packages using Download-Directory and restart switch
	Install-DellDriverFiles -DownloadDir " LocalPath" -Restart
.EXAMPLE
	This example shows how to download and install the Driver packages using the custom proxy settings
	Install-DellDriverFiles -DownloadDir " LocalPath" -ProxyServer " http://<proxy_url>" -ProxyPort " 80"
.EXAMPLE
	This example shows how to download and install the Driver packages using the custom proxy settings using user credentials
	$WEProxyPass = " Password"
    $WESecureProxyPassword = ConvertTo-SecureString $WEProxyPass -AsPlainText -Force
    Install-DellDriverFiles -DownloadDir " LocalPath" -ProxyServer " http://<proxy_url>" -ProxyPort " 80" -ProxyUser " Username" -ProxyPassword $WESecureProxyPassword


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
	Write-Host $WEWhatIf
	
	Write-WELog " Waiting for" " INFO" $WESeconds " before restart"
	Start-Sleep -Seconds $WESeconds
	Write-WELog " Attempting system restart at " " INFO" $(Get-Date) -EA stop
	
	Restart-Computer -ComputerName . -Force -EA stop
	}
	catch [Exception]
	{		
		Write-Error " $($_.Exception)"
	}
	finally
	{
		Write-WELog " Restart-DellComputer Executed" " INFO"
	}	
}

Function Install-DellDriverFiles
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory=$true, HelpMessage=" Enter the download folder location where the files will be downloaded. " )]
        [ValidateNotNullOrEmpty()]		
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEDownloadDir,

        [parameter(Mandatory=$false, HelpMessage=" use -Restart switch if system Restart needs to be performed" )]
	    [switch]$WERestart,
        
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
        # ** If PowerShell process is running as 32-bit process exit the script, as PNPUtil is supported only as 64-bit process.
        
        if(![Environment]::Is64BitProcess)
        {
            Write-Host Error: Script is not supported in 32-bit PowerShell Host `n -BackgroundColor Red
            Write-Host Run Script in 64-bit PowerShell Host `n -BackgroundColor Red
            exit $1
        }
            
        # ** Mandatory Proxy Arguments Validation. ***
        
        If(!((!$WEProxyServer -and !$WEProxyPort -and !$WEProxyUser -and !$WEProxyPassword) -or 
           ($WEProxyServer -and $WEProxyPort -and !$WEProxyUser -and !$WEProxyPassword) -or 
           ($WEProxyServer -and $WEProxyPort -and $WEProxyUser -and $WEProxyPassword)))        
        {
            Write-Host Error: Missing Mandatory Proxy Arguments `n -BackgroundColor Red
            exit $1
        }
        # Driver installation status flag
        $WEDriverInstallSuccess = $false 
        # To get the current date and time to write onto log-file.      
        $WEDate = Get-Date
        # DriverCabCatalog File Name
        $WEDriverCabCatalogFileName = " DriverPackCatalog.cab"
        # DriverCabCatalog XML File Name
        $WEDriverCabCatalogXMLFileName = " DriverPackCatalog.xml"
        # DriverPackCatalog.cab file URL
		$WEDriverCabCatalog = " https://downloads.dell.com/catalog/DriverPackCatalog.cab"      
        # Platform System ID or BIOS ID
        $WESystemID = (Get-CimInstance Win32_ComputerSystem).SystemSKUNumber
        # Platform System OS
        $WEPlatformSystemOS = (Get-CimInstance Win32_OperatingSystem).Caption
        #Platform OS Architecture
        $WEPlatformSystemOSArch = [Environment]::Is64BitOperatingSystem
        # Check OS architecture, supports only 64-bit architecture 
        if($WEPlatformSystemOSArch -ne " True" )
        {
            Write-Host Error: Supports only 64-bit architecture! `n -BackgroundColor Red
            exit $1
        }

        # Supported for only Windows 10 and Windows 11 OS
        if($WEPlatformSystemOS -match " Windows 10" )
        {
            $WESystemOS = " Windows 10 x64"
        }
        elseif($WEPlatformSystemOS -match " Windows 11" )
        {
            $WESystemOS = " Windows 11 x64"
        }
        else
        {
            Write-Host Error: Supports only Windows 10 and Windows 11 platforms `n -BackgroundColor Red            
            exit $1
        }

        # Download directory name (System_ID_System_OS)
        $WEDownloadDirName = $WESystemID.Trim() + " " + $WESystemOS.Trim()                                        
        $WEDownloadDirName = $WEDownloadDirName.Replace(" " ," _" )
        # Download folder path                                    
        $WEDriverDownloadFolder = Join-Path -Path $WEDownloadDir -ChildPath $WEDownloadDirName 
        # DriverPackCatalog.cab download path                       
        $WEDriverCabCatalogFile = Join-Path -Path $WEDriverDownloadFolder -ChildPath $WEDriverCabCatalogFileName 
        # DriverPackCatalog.xml extraction path
        $WEDriverCatalogXMLFile = Join-Path -Path $WEDriverDownloadFolder -ChildPath $WEDriverCabCatalogXMLFileName    
        # Log-File Path
        $WELogFileName = " DellDriverInstaller_Log.txt"
        $WELogFilePath = Join-Path -Path $WEDriverDownloadFolder -ChildPath $WELogFileName
                    
        # *** Check if download directory exists, if it does not exist create download directory ***
        Try
        {
            $WEDownloadDir = Resolve-Path -Path $WEDownloadDir
        }
        Catch [Exception]
		{
            Write-Host Error resolving path $WEDownloadDir `n
			Write-Error " $($_.Exception)"
            Try
		    {
                Write-Host Creating Download Directory: $WEDownloadDir `n
			    New-Item -Path $WEDownloadDir -ItemType Directory -Force | Out-Null                
		    }
		    Catch [Exception]
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
		    Catch [Exception]
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
		    Catch [Exception]
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
            # Create Log File
            New-Item -ItemType File -Path $WELogFilePath -Force                
		}
		Catch [Exception]
		{
            Write-Host Error creating directory $WEDriverDownloadFolder `n
			Write-Error " $($_.Exception)"            
            exit $1
		}

        # *** Adding contents into Log-File. ***

        Add-Content -Path $WELogFilePath -Value " ===================================="

        Add-Content -Path $WELogFilePath -Value " Script - Dell_Install_Driver_Files.ps1 "

        Add-Content -Path $WELogFilePath -Value " $WEDate "

        Add-Content -Path $WELogFilePath -Value " System ID - $WESystemID "

        Add-Content -Path $WELogFilePath -Value " System OS - $WESystemOS "

        Add-Content -Path $WELogFilePath -Value " ===================================="
        
        
        # *** To Download the Driver Cab Catalog. ***

        try {
              Write-Host Downloading DriverPackCatalog file... `n 
              Add-Content -Path $WELogFilePath -Value " Downloading DriverPackCatalog file..."         
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
                 Add-Content -Path $WELogFilePath -Value " DriverPackCatalog file downloaded successful."
              }
              else
              {
                    Write-Host DriverPackCatalog file is not downloaded! `n -BackgroundColor Red 
                    Add-Content -Path $WELogFilePath -Value " DriverPackCatalog file download failed!"
                    exit $1
              }              
            }
        catch [System.Net.WebException]
            {
                Write-Error " $($_.Exception)"
                Add-Content -Path $WELogFilePath -Value " $($_.Exception)"
                exit $1
            }


        # *** To Extract the DriverPackCatalog file. ***
        
        try {
                Write-Host Extracting DriverPackCatalog file... `n 
                Add-Content -Path $WELogFilePath -Value " Extracting DriverPackCatalog file..."  
                expand -r $WEDriverCabCatalogFile $WEDriverDownloadFolder
                if (Test-Path " $WEDriverCatalogXMLFile" )
			    {
                   Write-Host DriverPackCatalog file extraction successful. `n
                   Add-Content -Path $WELogFilePath -Value " DriverPackCatalog file extraction successful."
                }
                else
                {
                    Write-Host DriverPackCatalog XML file extraction failed! `n -BackgroundColor Red 
                    Add-Content -Path $WELogFilePath -Value " DriverPackCatalog XML file extraction failed!"
                    exit $1
                }               	                        
            }
        catch [Exception] 
            {
                Write-Error " $($_.Exception)"
                Add-Content -Path $WELogFilePath -Value " $($_.Exception)"
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
                    Add-Content -Path $WELogFilePath -Value " Downloading driver file..."
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
                        Add-Content -Path $WELogFilePath -Value " Driver download successful: $WEDriverPackageName"
                        Write-WELog " Total time taken to download driver $WEDriverPackageName (hh:mm:ss.ms): $WETotalDriverDownloadTime `n" " INFO"
                        Add-Content -Path $WELogFilePath -Value " Total time taken to download driver $WEDriverPackageName (hh:mm:ss.ms): $WETotalDriverDownloadTime"    
                        # MD5 hash from the xml file           		
		                $WEMD5Hash = $WEDriverPackage.Cryptography.Hash | Where-Object { $_.algorithm -eq 'SHA256' } | Select-Object -ExpandProperty " #text"       
                        # MD5 hash of the downloaded driver file
                        $WEDriverFileMD5Hash = Get-FileHash $WEDriverDownloadDestPath -Algorithm SHA256                                                        
		                if($WEMD5Hash -eq $WEDriverFileMD5Hash.Hash)
                        {
                            Write-WELog " MD5 hash match successful - $WEDriverPackageName. `n" " INFO"
                            Add-Content -Path $WELogFilePath -Value " MD5 hash match successful - $WEDriverPackageName."
                            # Extract downloaded driver file
                            Write-WELog " Extracting driver file - $WEDriverPackageName. `n" " INFO"
                            Add-Content -Path $WELogFilePath -Value " Extracting driver file - $WEDriverPackageName."
                            Write-WELog " The extraction might take some time... `n Please wait for the extraction to complete... " " INFO" -BackgroundColor Gray
                            $WEDriverPackageLocation = Join-Path -Path $WEDriverDownloadFolder -ChildPath $WEDriverPackageName
                            $WEDriverPackageExtractFolderName = [System.IO.Path]::GetFileNameWithoutExtension($WEDriverPackageName)
                            $WEDriverPackExtractLocation = Join-Path -Path $WEDriverDownloadFolder -ChildPath $WEDriverPackageExtractFolderName
                            try 
                            {
                                if($WEDriverPackageName -match " .exe" )
                                {
                                    Start-Process -FilePath $WEDriverPackageLocation -ArgumentList " /s /e=$WEDriverPackExtractLocation" -Wait -NoNewWindow -PassThru
                                }
                                else
                                {
                                    # Create extraction folder for .cab extraction
                                    New-Item -Path $WEDriverPackExtractLocation -ItemType Directory -Force | Out-Null
                                    # Extract all contents into the extraction folder
                                    expand -r -F:* $WEDriverPackageLocation $WEDriverPackExtractLocation | Out-Null
                                }
                            }
                            catch [Exception] 
                            {
                                Write-WELog " Extraction of DriverPack $WEDriverPackageName failed! `n" " INFO"
                                Add-Content -Path $WELogFilePath -Value " Extraction of DriverPack $WEDriverPackageName failed!"
                                Write-Error " $($_.Exception)"
                                Add-Content -Path $WELogFilePath -Value " $($_.Exception)"
                                exit $1
                            }
                            Write-WELog " Driver extraction successful - $WEDriverPackageName. `n" " INFO"
                            Add-Content -Path $WELogFilePath -Value " Driver extraction successful - $WEDriverPackageName." 
                            # Install the Driver using PNPUTIL command
                            $WEDriverFilestoInstall = Join-Path -Path $WEDriverPackExtractLocation -ChildPath " *.inf"
                            Write-WELog " Installing driver - $WEDriverPackageName. `n" " INFO"
                            Add-Content -Path $WELogFilePath -Value " Installing driver - $WEDriverPackageName."
                            Write-WELog " The installation might take some time... `n Please wait for the installation to complete... " " INFO" -BackgroundColor Gray
                            try
                            {
                                PNPUtil.exe /add-driver $WEDriverFilestoInstall /subdirs /install | Tee-Object -Append -File $WELogFilePath
                            }
                            catch [Exception] 
                            {
                                Write-WELog " $WEDriverPackageName Installation failed! `n" " INFO"
                                Add-Content -Path $WELogFilePath -Value " $WEDriverPackageName Installation failed!"
                                Write-Error " $($_.Exception)"
                                Add-Content -Path $WELogFilePath -Value " $($_.Exception)"
                                exit $1
                            }
                            Write-WELog " $WEDriverPackageName Installation Completed. `n" " INFO"
                            Add-Content -Path $WELogFilePath -Value " $WEDriverPackageName Installation Completed."
                           ;  $WEDriverInstallSuccess = $true                     
                        }
                        else
                        {
                            Write-WELog " MD5 has match failed. Hence, deleting the driver file $WEDriverPackageName. `n" " INFO"
                            Add-Content -Path $WELogFilePath -Value " MD5 has match failed. Hence, deleting the driver file $WEDriverPackageName."
                            Write-WELog " Driver installation was not successful! `n" " INFO"
                            Add-Content -Path $WELogFilePath -Value " Driver installation was not successful!"
                            Remove-Item -Path $WEDriverDownloadDestPath -Recurse -Force | Out-Null
                        }
                    }
                    else
                    {
                        Write-WELog " Driver download failed: $WEDriverPackageName `n" " INFO"
                        Add-Content -Path $WELogFilePath -Value " Driver download failed: $WEDriverPackageName"
                    }                  
			                                  
		        }		            
		
	        }
            
            if($WENoDriverMatchFound -eq $true)
            {
                Write-WELog " No Driver Match found for the SystemID: $WESystemID, OS: $WESystemOS. `n" " INFO"
                Write-WELog " Contact Dell Support. `n" " INFO"
                Add-Content -Path $WELogFilePath -Value " No Driver Match found for the SystemID: $WESystemID, OS: $WESystemOS."
                Add-Content -Path $WELogFilePath -Value " Contact Dell Support."
            }	

            }
        catch [Exception] 
            {
                Write-Error " $($_.Exception)"
                Add-Content -Path $WELogFilePath -Value " $($_.Exception)"
            }
		
	}	
	catch [Exception]
	{
		Write-Error " $($_.Exception)"
        Add-Content -Path $WELogFilePath -Value " $($_.Exception)"
	}
	Finally
	{
        # Delete all contents from DownloadFolder except Log file
        if($WELogFilePath)
        {
            if($WEDriverDownloadFolder)
            {
                try
                {
                    Get-ChildItem -Path  $WEDriverDownloadFolder -Recurse -exclude $WELogFileName |
                    Select -ExpandProperty FullName |
                    Where {$_ -notlike $WELogFilePath} |
                    sort length -Descending |
                    Remove-Item -Recurse -Force | Out-Null
                }
                catch [Exception]
	            {
                    Write-WELog " Deleting files from $WEDriverDownloadFolder failed! Manual clean-up is required!" " INFO"
		            Write-Error " $($_.Exception)"
                    Add-Content -Path $WELogFilePath -Value " Deleting files from $WEDriverDownloadFolder failed! Manual clean-up is required!"
                    Add-Content -Path $WELogFilePath -Value " $($_.Exception)"
	            }
            }
		    Write-WELog " Function Install-DellDriverFiles Executed" " INFO"        
           ;  $WEFinishTime = Get-Date
            Add-Content -Path $WELogFilePath -Value " ------------------------------------"

            Add-Content -Path $WELogFilePath -Value " Function Install-DellDriverFiles Executed"

            Add-Content -Path $WELogFilePath -Value " $WEFinishTime "
                
            Add-Content -Path $WELogFilePath -Value " ------------------------------------"
            #restart the system if required, using Powershell Script
            if($WERestart -and $WEDriverInstallSuccess)
            {
                Write-WELog " Restarting System... `n" " INFO"
                Add-Content -Path $WELogFilePath -Value " Restarting System..."
			    #CAUTION: USER MIGHT LOSE UNSAVED WORK
			    Restart-DellComputer -Seconds 10
		    }
        }
	}
}




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================