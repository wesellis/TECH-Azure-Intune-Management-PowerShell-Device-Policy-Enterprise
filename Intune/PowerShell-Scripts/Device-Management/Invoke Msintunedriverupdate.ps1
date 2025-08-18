<#
.SYNOPSIS
    Invoke Msintunedriverupdate

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
    We Enhanced Invoke Msintunedriverupdate

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


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS

    The purpose of this script is to automate the driver update process when enrolling devices through
    Microsoft Intune.

.DESCRIPTION

    This script will determine the model of the computer, manufacturer and operating system used then download,
    extract & install the latest driver package from the manufacturer. At present Dell, HP and Lenovo devices
    are supported.
	
.NOTES

    FileName:    Invoke-MSIntuneDriverUpdate.ps1

    Author:      Maurice Daly
    Contact:     @MoDaly_IT
    Created:     2017-12-03
    Updated:     2017-12-05

    Version history:

    1.0.0 - (2017-12-03) Script created
	1.0.1 - (2017-12-05) Updated Lenovo matching SKU value and added regex matching for Computer Model values. 
	1.0.2 - (2017-12-05) Updated to cater for language differences in OS architecture returned




$WETempLocation = Join-Path $env:SystemDrive " Temp\SCConfigMgr"


[string]$WETempDirectory = Join-Path $WETempLocation " \Temp"
[string]$WELogDirectory = Join-Path $WETempLocation " \Logs"


if ((Test-Path -Path $WETempDirectory) -eq $false) {
	New-Item -Path $WETempDirectory -ItemType Dir
}


if ((Test-Path -Path $WELogDirectory) -eq $false) {
	New-Item -Path $WELogDirectory -ItemType Dir
}


function global:Write-CMLogEntry {
	[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
		[parameter(Mandatory = $true, HelpMessage = " Value added to the log file." )]
		[ValidateNotNullOrEmpty()]
		[string]
		$WEValue,
		[parameter(Mandatory = $true, HelpMessage = " Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error." )]
		[ValidateNotNullOrEmpty()]
		[ValidateSet(" 1" , " 2" , " 3" )]
		[string]
		$WESeverity,
		[parameter(Mandatory = $false, HelpMessage = " Name of the log file that the entry will written to." )]
		[ValidateNotNullOrEmpty()]
		[string]
		$WEFileName = " Invoke-MSIntuneDriverUpdate.log"
	)
	# Determine log file location
	$WELogFilePath = Join-Path -Path $WELogDirectory -ChildPath $WEFileName
	# Construct time stamp for log entry
	$WETime = -join @((Get-Date -Format " HH:mm:ss.fff" ), " +" , (Get-CimInstance -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
	# Construct date for log entry
	$WEDate = (Get-Date -Format " MM-dd-yyyy" )
	# Construct context for log entry
	$WEContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	# Construct final log entry
	$WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" DriverAutomationScript"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
	# Add value to log file
	try {
		Add-Content -Value $WELogText -LiteralPath $WELogFilePath -ErrorAction Stop
	}
	catch [System.Exception] {
		Write-Warning -Message " Unable to append log entry to Invoke-DriverUpdate.log file. Error message: $($_.Exception.Message)"
	}
}




$WEDellDownloadList = " http://downloads.dell.com/published/Pages/index.html"
$WEDellDownloadBase = " http://downloads.dell.com"
$WEDellDriverListURL = " http://en.community.dell.com/techcenter/enterprise-client/w/wiki/2065.dell-command-deploy-driver-packs-for-enterprise-client-os-deployment"
$WEDellBaseURL = " http://en.community.dell.com"


$WEDellXMLCabinetSource = " http://downloads.dell.com/catalog/DriverPackCatalog.cab"
$WEDellCatalogSource = " http://downloads.dell.com/catalog/CatalogPC.cab"


$WEDellCabFile = [string]($WEDellXMLCabinetSource | Split-Path -Leaf)
$WEDellCatalogFile = [string]($WEDellCatalogSource | Split-Path -Leaf)
$WEDellXMLFile = $WEDellCabFile.Trim(" .cab" )
$WEDellXMLFile = $WEDellXMLFile + " .xml"
$WEDellCatalogXMLFile = $WEDellCatalogFile.Trim(" .cab" ) + " .xml"


$WEDellCatalogXML = $null
$WEDellModelXML = $null
$WEDellModelCabFiles = $null




$WEHPXMLCabinetSource = " http://ftp.hp.com/pub/caps-softpaq/cmit/HPClientDriverPackCatalog.cab"
$WEHPSoftPaqSource = " http://ftp.hp.com/pub/softpaq/"
$WEHPPlatFormList = " http://ftp.hp.com/pub/caps-softpaq/cmit/imagepal/ref/platformList.cab"


$WEHPCabFile = [string]($WEHPXMLCabinetSource | Split-Path -Leaf)
$WEHPXMLFile = $WEHPCabFile.Trim(" .cab" )
$WEHPXMLFile = $WEHPXMLFile + " .xml"
$WEHPPlatformCabFile = [string]($WEHPPlatFormList | Split-Path -Leaf)
$WEHPPlatformXMLFile = $WEHPPlatformCabFile.Trim(" .cab" )
$WEHPPlatformXMLFile = $WEHPPlatformXMLFile + " .xml"


$global:HPModelSoftPaqs = $null
$global:HPModelXML = $null
$global:HPPlatformXML = $null




$global:LenovoXMLSource = " https://download.lenovo.com/cdrt/td/catalog.xml"


$global:LenovoXMLFile = [string]($global:LenovoXMLSource | Split-Path -Leaf)


$global:LenovoModelDrivers = $null
$global:LenovoModelXML = $null
$global:LenovoModelType = $null
$global:LenovoSystemSKU = $null




$WEComputerManufacturer = (Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer).Trim()
Write-CMLogEntry -Value " Manufacturer determined as: $($WEComputerManufacturer)" -Severity 1


switch -Wildcard ($WEComputerManufacturer) {
	" *HP*" {
		$WEComputerManufacturer = " Hewlett-Packard"
		$WEComputerModel = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
		$WESystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).BaseBoardProduct
	}
	" *Hewlett-Packard*" {
		$WEComputerManufacturer = " Hewlett-Packard"
		$WEComputerModel = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
		$WESystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).BaseBoardProduct
	}
	" *Dell*" {
		$WEComputerManufacturer = " Dell"
		$WEComputerModel = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
		$WESystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku
	}
	" *Lenovo*" {
		$WEComputerManufacturer = " Lenovo"
		$WEComputerModel = Get-CimInstance -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version
		$WESystemSKU = ((Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI | Select-Object -ExpandProperty BIOSVersion).SubString(0, 4)).Trim()
	}
}
Write-CMLogEntry -Value " Computer model determined as: $($WEComputerModel)" -Severity 1

if (-not [string]::IsNullOrEmpty($WESystemSKU)) {
	Write-CMLogEntry -Value " Computer SKU determined as: $($WESystemSKU)" -Severity 1
}


switch -wildcard (Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty Version) {
	" 10.0*" {
		$WEOSName = " Windows 10"
	}
	" 6.3*" {
		$WEOSName = " Windows 8.1"
	}
	" 6.1*" {
		$WEOSName = " Windows 7"
	}
}
Write-CMLogEntry -Value " Operating system determined as: $WEOSName" -Severity 1


switch -wildcard ((Get-CimInstance Win32_operatingsystem).OSArchitecture) {
	" 64-*" {
		$WEOSArchitecture = " 64-Bit"
	}
	" 32-*" {
		$WEOSArchitecture = " 32-Bit"
	}
}

Write-CMLogEntry -Value " Architecture determined as: $WEOSArchitecture" -Severity 1

$WEWindowsVersion = ($WEOSName).Split(" " )[1]

function WE-DownloadDriverList {
	global:Write-CMLogEntry -Value " ======== Download Model Link Information ========" -Severity 1
	if ($WEComputerManufacturer -eq " Hewlett-Packard" ) {
		if ((Test-Path -Path $WETempDirectory\$WEHPCabFile) -eq $false) {
			global:Write-CMLogEntry -Value " ======== Downloading HP Product List ========" -Severity 1
			# Download HP Model Cabinet File
			global:Write-CMLogEntry -Value " Info: Downloading HP driver pack cabinet file from $WEHPXMLCabinetSource" -Severity 1
			try {
				Start-BitsTransfer -Source $WEHPXMLCabinetSource -Destination $WETempDirectory
				# Expand Cabinet File
				global:Write-CMLogEntry -Value " Info: Expanding HP driver pack cabinet file: $WEHPXMLFile" -Severity 1
				Expand " $WETempDirectory\$WEHPCabFile" -F:* " $WETempDirectory\$WEHPXMLFile"
			}
			catch {
				global:Write-CMLogEntry -Value " Error: $($_.Exception.Message)" -Severity 3
			}
		}
		# Read XML File
		if ($global:HPModelSoftPaqs -eq $null) {
			global:Write-CMLogEntry -Value " Info: Reading driver pack XML file - $WETempDirectory\$WEHPXMLFile" -Severity 1
			[xml]$global:HPModelXML = Get-Content -Path $WETempDirectory\$WEHPXMLFile
			# Set XML Object
			$global:HPModelXML.GetType().FullName | Out-Null
			$global:HPModelSoftPaqs = $WEHPModelXML.NewDataSet.HPClientDriverPackCatalog.ProductOSDriverPackList.ProductOSDriverPack
		}
	}
	if ($WEComputerManufacturer -eq " Dell" ) {
		if ((Test-Path -Path $WETempDirectory\$WEDellCabFile) -eq $false) {
			global:Write-CMLogEntry -Value " Info: Downloading Dell product list" -Severity 1
			global:Write-CMLogEntry -Value " Info: Downloading Dell driver pack cabinet file from $WEDellXMLCabinetSource" -Severity 1
			# Download Dell Model Cabinet File
			try {
				Start-BitsTransfer -Source $WEDellXMLCabinetSource -Destination $WETempDirectory
				# Expand Cabinet File
				global:Write-CMLogEntry -Value " Info: Expanding Dell driver pack cabinet file: $WEDellXMLFile" -Severity 1
				Expand " $WETempDirectory\$WEDellCabFile" -F:* " $WETempDirectory\$WEDellXMLFile"
			}
			catch {
				global:Write-CMLogEntry -Value " Error: $($_.Exception.Message)" -Severity 3
			}
		}
		if ($WEDellModelXML -eq $null) {
			# Read XML File
			global:Write-CMLogEntry -Value " Info: Reading driver pack XML file - $WETempDirectory\$WEDellXMLFile" -Severity 1
			[xml]$WEDellModelXML = (Get-Content -Path $WETempDirectory\$WEDellXMLFile)
			# Set XML Object
			$WEDellModelXML.GetType().FullName | Out-Null
		}
		$WEDellModelCabFiles = $WEDellModelXML.driverpackmanifest.driverpackage
		
	}
	if ($WEComputerManufacturer -eq " Lenovo" ) {
		if ($global:LenovoModelDrivers -eq $null) {
			try {
				[xml]$global:LenovoModelXML = Invoke-WebRequest -Uri $global:LenovoXMLSource
			}
			catch {
				global:Write-CMLogEntry -Value " Error: $($_.Exception.Message)" -Severity 3
			}
			
			# Read Web Site
			global:Write-CMLogEntry -Value " Info: Reading driver pack URL - $global:LenovoXMLSource" -Severity 1
			
			# Set XML Object 
			$global:LenovoModelXML.GetType().FullName | Out-Null
			$global:LenovoModelDrivers = $global:LenovoModelXML.Products
		}
	}
}

function WE-FindLenovoDriver {
	
<#
 # This powershell file will extract the link for the specified driver pack or application
 # param $WEURI The string version of the URL
 # param $64bit A boolean to determine what version to pick if there are multiple
 # param $os A string containing 7, 8, or 10 depending on the os we are deploying 
 #           i.e. 7, Win7, Windows 7 etc are all valid os strings
 #>
	[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
		[parameter(Mandatory = $true, HelpMessage = " Provide the URL to parse." )]
		[ValidateNotNullOrEmpty()]
		[string]
		$WEURI,
		[parameter(Mandatory = $true, HelpMessage = " Specify the operating system." )]
		[ValidateNotNullOrEmpty()]
		[string]
		$WEOS,
		[string]
		$WEArchitecture
	)
	
	#Case for direct link to a zip file
	if ($WEURI.EndsWith(" .zip" )) {
		return $WEURI
	}
	
	$err = @()
	
	#Get the content of the website
	try {
		$html = Invoke-WebRequest –Uri $WEURI
	}
	catch {
		global:Write-CMLogEntry -Value " Error: $($_.Exception.Message)" -Severity 3
	}
	
	#Create an array to hold all the links to exe files
	$WELinks = @()
	$WELinks.Clear()
	
	#determine if the URL resolves to the old download location
	if ($WEURI -like " *olddownloads*" ) {
		#Quickly grab the links that end with exe
		$WELinks = (($html.Links | Where-Object {
					$_.href -like " *exe"
				}) | Where class -eq " downloadBtn" ).href
	}
	
	$WELinks = ((Select-string '(http[s]?)(:\/\/)([^\s,]+.exe)(?=" )' -InputObject ($html).Rawcontent -AllMatches).Matches.Value)
	
	if ($WELinks.Count -eq 0) {
		return $null
	}
	
	# Switch OS architecture
	switch -wildcard ($WEArchitecture) {
		" *64*" {
			$WEArchitecture = " 64"
		}
		" *86*" {
			$WEArchitecture = " 32"
		}
	}
	
	#if there are multiple links then narrow down to the proper arc and os (if needed)
	if ($WELinks.Count -gt 0) {
		#Second array of links to hold only the ones we want to target
		$WEMatchingLink = @()
		$WEMatchingLink.clear()
		foreach ($WELink in $WELinks) {
			if ($WELink -like " *w$($WEOS)$($WEArchitecture)_*" -or $WELink -like " *w$($WEOS)_$($WEArchitecture)*" ) {
				$WEMatchingLink = $WEMatchingLink + $WELink
			}
		}
	}
	
	if ($WEMatchingLink -ne $null) {
		return $WEMatchingLink
	}
	else {
		return " badLink"
	}
}

function WE-Get-RedirectedUrl {
	[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
		[Parameter(Mandatory = $true)]
		[String]
		$WEURL
	)
	
	$WERequest = [System.Net.WebRequest]::Create($WEURL)
	$WERequest.AllowAutoRedirect = $false
	$WERequest.Timeout = 3000
	$WEResponse = $WERequest.GetResponse()
	
	if ($WEResponse.ResponseUri) {
		$WEResponse.GetResponseHeader(" Location" )
	}
	$WEResponse.Close()
}

function WE-LenovoModelTypeFinder {
	[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
		[parameter(Mandatory = $false, HelpMessage = " Enter Lenovo model to query" )]
		[string]
		$WEComputerModel,
		[parameter(Mandatory = $false, HelpMessage = " Enter Operating System" )]
		[string]
		$WEOS,
		[parameter(Mandatory = $false, HelpMessage = " Enter Lenovo model type to query" )]
		[string]
		$WEComputerModelType
	)
	try {
		if ($global:LenovoModelDrivers -eq $null) {
			[xml]$global:LenovoModelXML = Invoke-WebRequest -Uri $global:LenovoXMLSource
			# Read Web Site
			global:Write-CMLogEntry -Value " Info: Reading driver pack URL - $global:LenovoXMLSource" -Severity 1
			
			# Set XML Object
			$global:LenovoModelXML.GetType().FullName | Out-Null
			$global:LenovoModelDrivers = $global:LenovoModelXML.Products
		}
	}
	catch {
		global:Write-CMLogEntry -Value " Error: $($_.Exception.Message)" -Severity 3
	}
	
	if ($WEComputerModel.Length -gt 0) {
		$global:LenovoModelType = ($global:LenovoModelDrivers.Product | Where-Object {
				$_.Queries.Version -match " $WEComputerModel"
			}).Queries.Types | Select -ExpandProperty Type | Select -first 1
		$global:LenovoSystemSKU = ($global:LenovoModelDrivers.Product | Where-Object {
				$_.Queries.Version -match " $WEComputerModel"
			}).Queries.Types | select -ExpandProperty Type | Get-Unique
	}
	
	if ($WEComputerModelType.Length -gt 0) {
		$global:LenovoModelType = (($global:LenovoModelDrivers.Product.Queries) | Where-Object {
				($_.Types | Select -ExpandProperty Type) -match $WEComputerModelType
			}).Version | Select -first 1
	}
	Return $global:LenovoModelType
}

function WE-InitiateDownloads {
	
	$WEProduct = " Intune Driver Automation"
	
	# Driver Download ScriptBlock
	$WEDriverDownloadJob = {
		Param ([string]
			$WETempDirectory,
			[string]
			$WEComputerModel,
			[string]
			$WEDriverCab,
			[string]
			$WEDriverDownloadURL
		)
		
		try {
			# Start Driver Download	
			Start-BitsTransfer -DisplayName " $WEComputerModel-DriverDownload" -Source $WEDriverDownloadURL -Destination " $($WETempDirectory + '\Driver Cab\' + $WEDriverCab)"
		}
		catch [System.Exception] {
			global:Write-CMLogEntry -Value " Error: $($_.Exception.Message)" -Severity 3
		}
	}
	
	global:Write-CMLogEntry -Value " ======== Starting Download Processes ========" -Severity 1
	global:Write-CMLogEntry -Value " Info: Operating System specified: Windows $($WEWindowsVersion)" -Severity 1
	global:Write-CMLogEntry -Value " Info: Operating System architecture specified: $($WEOSArchitecture)" -Severity 1
	
	# Operating System Version
	$WEOperatingSystem = (" Windows " + $($WEWindowsVersion))
	
	# Vendor Make
	$WEComputerModel = $WEComputerModel.Trim()
	
	# Get Windows Version Number
	switch -Wildcard ((Get-CimInstance -Class Win32_OperatingSystem).Version) {
		" *10.0.16*" {
			$WEOSBuild = " 1709"
		}
		" *10.0.15*" {
			$WEOSBuild = " 1703"
		}
		" *10.0.14*" {
			$WEOSBuild = " 1607"
		}
	}
	global:Write-CMLogEntry -Value " Info: Windows 10 build $WEOSBuild identified for driver match" -Severity 1
	
	# Start driver import processes
	global:Write-CMLogEntry -Value " Info: Starting Download,Extract And Import Processes For $WEComputerManufacturer Model: $($WEComputerModel)" -Severity 1
	
	# =================== DEFINE VARIABLES =====================
	
	if ($WEComputerManufacturer -eq " Dell" ) {
		global:Write-CMLogEntry -Value " Info: Setting Dell variables" -Severity 1
		if ($WEDellModelCabFiles -eq $null) {
			[xml]$WEDellModelXML = Get-Content -Path $WETempDirectory\$WEDellXMLFile
			# Set XML Object
			$WEDellModelXML.GetType().FullName | Out-Null
			$WEDellModelCabFiles = $WEDellModelXML.driverpackmanifest.driverpackage
		}
		if ($WESystemSKU -ne $null) {
			global:Write-CMLogEntry -Value " Info: SystemSKU value is present, attempting match based on SKU - $WESystemSKU)" -Severity 1
			
			$WEComputerModelURL = $WEDellDownloadBase + " /" + ($WEDellModelCabFiles | Where-Object {
					((($_.SupportedOperatingSystems).OperatingSystem).osCode -like " *$WEWindowsVersion*" ) -and ($_.SupportedSystems.Brand.Model.SystemID -eq $WESystemSKU)
				}).delta
			$WEComputerModelURL = $WEComputerModelURL.Replace(" \" , " /" )
			$WEDriverDownload = $WEDellDownloadBase + " /" + ($WEDellModelCabFiles | Where-Object {
					((($_.SupportedOperatingSystems).OperatingSystem).osCode -like " *$WEWindowsVersion*" ) -and ($_.SupportedSystems.Brand.Model.SystemID -eq $WESystemSKU)
				}).path
			$WEDriverCab = (($WEDellModelCabFiles | Where-Object {
						((($_.SupportedOperatingSystems).OperatingSystem).osCode -like " *$WEWindowsVersion*" ) -and ($_.SupportedSystems.Brand.Model.SystemID -eq $WESystemSKU)
					}).path).Split(" /" ) | select -Last 1
		}
		elseif ($WESystemSKU -eq $null -or $WEDriverCab -eq $null) {
			global:Write-CMLogEntry -Value " Info: Falling back to matching based on model name" -Severity 1
			
			$WEComputerModelURL = $WEDellDownloadBase + " /" + ($WEDellModelCabFiles | Where-Object {
					((($_.SupportedOperatingSystems).OperatingSystem).osCode -like " *$WEWindowsVersion*" ) -and ($_.SupportedSystems.Brand.Model.Name -like " *$WEComputerModel*" )
				}).delta
			$WEComputerModelURL = $WEComputerModelURL.Replace(" \" , " /" )
			$WEDriverDownload = $WEDellDownloadBase + " /" + ($WEDellModelCabFiles | Where-Object {
					((($_.SupportedOperatingSystems).OperatingSystem).osCode -like " *$WEWindowsVersion*" ) -and ($_.SupportedSystems.Brand.Model.Name -like " *$WEComputerModel" )
				}).path
			$WEDriverCab = (($WEDellModelCabFiles | Where-Object {
						((($_.SupportedOperatingSystems).OperatingSystem).osCode -like " *$WEWindowsVersion*" ) -and ($_.SupportedSystems.Brand.Model.Name -like " *$WEComputerModel" )
					}).path).Split(" /" ) | select -Last 1
		}
		$WEDriverRevision = (($WEDriverCab).Split(" -" )[2]).Trim(" .cab" )
	; 	$WEDellSystemSKU = ($WEDellModelCabFiles.supportedsystems.brand.model | Where-Object {
				$_.Name -match (" ^" + $WEComputerModel + " $" )
			} | Get-Unique).systemID
		if ($WEDellSystemSKU.count -gt 1) {
		; 	$WEDellSystemSKU = [string]($WEDellSystemSKU -join " ;" )
		}
		global:Write-CMLogEntry -Value " Info: Dell System Model ID is : $WEDellSystemSKU" -Severity 1
	}
	if ($WEComputerManufacturer -eq " Hewlett-Packard" ) {
		global:Write-CMLogEntry -Value " Info: Setting HP variables" -Severity 1
		if ($global:HPModelSoftPaqs -eq $null) {
			[xml]$global:HPModelXML = Get-Content -Path $WETempDirectory\$WEHPXMLFile
			# Set XML Object
			$global:HPModelXML.GetType().FullName | Out-Null
			$global:HPModelSoftPaqs = $global:HPModelXML.NewDataSet.HPClientDriverPackCatalog.ProductOSDriverPackList.ProductOSDriverPack
		}
		if ($WESystemSKU -ne $null) {
			$WEHPSoftPaqSummary = $global:HPModelSoftPaqs | Where-Object {
				($_.SystemID -match $WESystemSKU) -and ($_.OSName -like " $WEOSName*$WEOSArchitecture*$WEOSBuild*" )
			} | Sort-Object -Descending | select -First 1
		}
		else {
			$WEHPSoftPaqSummary = $global:HPModelSoftPaqs | Where-Object {
				($_.SystemName -match $WEComputerModel) -and ($_.OSName -like " $WEOSName*$WEOSArchitecture*$WEOSBuild*" )
			} | Sort-Object -Descending | select -First 1
		}
		if ($WEHPSoftPaqSummary -ne $null) {
			$WEHPSoftPaq = $WEHPSoftPaqSummary.SoftPaqID
			$WEHPSoftPaqDetails = $global:HPModelXML.newdataset.hpclientdriverpackcatalog.softpaqlist.softpaq | Where-Object {
				$_.ID -eq " $WEHPSoftPaq"
			}
			$WEComputerModelURL = $WEHPSoftPaqDetails.URL
			# Replace FTP for HTTP for Bits Transfer Job
			$WEDriverDownload = ($WEHPSoftPaqDetails.URL).TrimStart(" ftp:" )
		; 	$WEDriverCab = $WEComputerModelURL | Split-Path -Leaf
		; 	$WEDriverRevision = " $($WEHPSoftPaqDetails.Version)"
		}
		else{
			Write-CMLogEntry -Value " Unsupported model / operating system combination found. Exiting." -Severity 3; exit 1
		}
	}
	if ($WEComputerManufacturer -eq " Lenovo" ) {
		global:Write-CMLogEntry -Value " Info: Setting Lenovo variables" -Severity 1
		$global:LenovoModelType = LenovoModelTypeFinder -ComputerModel $WEComputerModel -OS $WEWindowsVersion
		global:Write-CMLogEntry -Value " Info: $WEComputerManufacturer $WEComputerModel matching model type: $global:LenovoModelType" -Severity 1
		
		if ($global:LenovoModelDrivers -ne $null) {
			[xml]$global:LenovoModelXML = (New-Object System.Net.WebClient).DownloadString(" $global:LenovoXMLSource" )
			# Set XML Object
			$global:LenovoModelXML.GetType().FullName | Out-Null
			$global:LenovoModelDrivers = $global:LenovoModelXML.Products
			if ($WESystemSKU -ne $null) {
				$WEComputerModelURL = (($global:LenovoModelDrivers.Product | Where-Object {
							($_.Queries.smbios -match $WESystemSKU -and $_.OS -match $WEWindowsVersion)
						}).driverPack | Where-Object {
						$_.id -eq " SCCM"
					})." #text"
			}
			else {
				$WEComputerModelURL = (($global:LenovoModelDrivers.Product | Where-Object {
							($_.Queries.Version -match (" ^" + $WEComputerModel + " $" ) -and $_.OS -match $WEWindowsVersion)
						}).driverPack | Where-Object {
						$_.id -eq " SCCM"
					})." #text"
			}
			global:Write-CMLogEntry -Value " Info: Model URL determined as $WEComputerModelURL" -Severity 1
			$WEDriverDownload = FindLenovoDriver -URI $WEComputerModelURL -os $WEWindowsVersion -Architecture $WEOSArchitecture
			If ($WEDriverDownload -ne $null) {
				$WEDriverCab = $WEDriverDownload | Split-Path -Leaf
				$WEDriverRevision = ($WEDriverCab.Split(" _" ) | Select -Last 1).Trim(" .exe" )
				global:Write-CMLogEntry -Value " Info: Driver cabinet download determined as $WEDriverDownload" -Severity 1
			}
			else {
				global:Write-CMLogEntry -Value " Error: Unable to find driver for $WEMake $WEModel" -Severity 1
			}
		}
	}
	
	# Driver location variables
	$WEDriverSourceCab = ($WETempDirectory + " \Driver Cab\" + $WEDriverCab)
	$WEDriverExtractDest = (" $WETempDirectory" + " \Driver Files" )
	global:Write-CMLogEntry -Value " Info: Driver extract location set - $WEDriverExtractDest" -Severity 1
	
	# =================== INITIATE DOWNLOADS ===================			
	
	global:Write-CMLogEntry -Value " ======== $WEProduct - $WEComputerManufacturer $WEComputerModel DRIVER PROCESSING STARTED ========" -Severity 1
	
	# =============== ConfigMgr Driver Cab Download =================				
	global:Write-CMLogEntry -Value " $($WEProduct): Retrieving ConfigMgr driver pack site For $WEComputerManufacturer $WEComputerModel" -Severity 1
	global:Write-CMLogEntry -Value " $($WEProduct): URL found: $WEComputerModelURL" -Severity 1
	
	if (($WEComputerModelURL -ne $null) -and ($WEDriverDownload -ne " badLink" )) {
		# Cater for HP / Model Issue
		$WEComputerModel = $WEComputerModel -replace '/', '-'
		$WEComputerModel = $WEComputerModel.Trim()
		Set-Location -Path $WETempDirectory
		# Check for destination directory, create if required and download the driver cab
		if ((Test-Path -Path $($WETempDirectory + " \Driver Cab\" + $WEDriverCab)) -eq $false) {
			if ((Test-Path -Path $($WETempDirectory + " \Driver Cab" )) -eq $false) {
				New-Item -ItemType Directory -Path $($WETempDirectory + " \Driver Cab" )
			}
			global:Write-CMLogEntry -Value " $($WEProduct): Downloading $WEDriverCab driver cab file" -Severity 1
			global:Write-CMLogEntry -Value " $($WEProduct): Downloading from URL: $WEDriverDownload" -Severity 1
			Start-Job -Name " $WEComputerModel-DriverDownload" -ScriptBlock $WEDriverDownloadJob -ArgumentList ($WETempDirectory, $WEComputerModel, $WEDriverCab, $WEDriverDownload)
			sleep -Seconds 5
		; 	$WEBitsJob = Get-BitsTransfer | Where-Object {
				$_.DisplayName -match " $WEComputerModel-DriverDownload"
			}
			while (($WEBitsJob).JobState -eq " Connecting" ) {
				global:Write-CMLogEntry -Value " $($WEProduct): Establishing connection to $WEDriverDownload" -Severity 1
				sleep -seconds 30
			}
			while (($WEBitsJob).JobState -eq " Transferring" ) {
				if ($WEBitsJob.BytesTotal -ne $null) {
				; 	$WEPercentComplete = [int](($WEBitsJob.BytesTransferred * 100)/$WEBitsJob.BytesTotal);
					global:Write-CMLogEntry -Value " $($WEProduct): Downloaded $([int]((($WEBitsJob).BytesTransferred)/ 1MB)) MB of $([int]((($WEBitsJob).BytesTotal)/ 1MB)) MB ($WEPercentComplete%). Next update in 30 seconds." -Severity 1
					sleep -seconds 30
				}
				else {
					global:Write-CMLogEntry -Value " $($WEProduct): Download issues detected. Cancelling download process" -Severity 2
					Get-BitsTransfer | Where-Object {
						$_.DisplayName -eq " $WEComputerModel-DriverDownload"
					} | Remove-BitsTransfer
				}
			}
			Get-BitsTransfer | Where-Object {
				$_.DisplayName -eq " $WEComputerModel-DriverDownload"
			} | Complete-BitsTransfer
			global:Write-CMLogEntry -Value " $($WEProduct): Driver revision: $WEDriverRevision" -Severity 1
		}
		else {
			global:Write-CMLogEntry -Value " $($WEProduct): Skipping $WEDriverCab. Driver pack already downloaded." -Severity 1
		}
		
		# Cater for HP / Model Issue
		$WEComputerModel = $WEComputerModel -replace '/', '-'
		
		if (((Test-Path -Path " $($WETempDirectory + '\Driver Cab\' + $WEDriverCab)" ) -eq $true) -and ($WEDriverCab -ne $null)) {
			global:Write-CMLogEntry -Value " $($WEProduct): $WEDriverCab File exists - Starting driver update process" -Severity 1
			# =============== Extract Drivers =================
			
			if ((Test-Path -Path " $WEDriverExtractDest" ) -eq $false) {
				New-Item -ItemType Directory -Path " $($WEDriverExtractDest)"
			}
			if ((Get-ChildItem -Path " $WEDriverExtractDest" -Recurse -Filter *.inf -File).Count -eq 0) {
				global:Write-CMLogEntry -Value " ==================== $WEPRODUCT DRIVER EXTRACT ====================" -Severity 1
				global:Write-CMLogEntry -Value " $($WEProduct): Expanding driver CAB source file: $WEDriverCab" -Severity 1
				global:Write-CMLogEntry -Value " $($WEProduct): Driver CAB destination directory: $WEDriverExtractDest" -Severity 1
				if ($WEComputerManufacturer -eq " Dell" ) {
					global:Write-CMLogEntry -Value " $($WEProduct): Extracting $WEComputerManufacturer drivers to $WEDriverExtractDest" -Severity 1
					Expand " $WEDriverSourceCab" -F:* " $WEDriverExtractDest"
				}
				if ($WEComputerManufacturer -eq " Hewlett-Packard" ) {
					global:Write-CMLogEntry -Value " $($WEProduct): Extracting $WEComputerManufacturer drivers to $WEHPTemp" -Severity 1
					# Driver Silent Extract Switches
					$WEHPSilentSwitches = " -PDF -F" + " $WEDriverExtractDest" + " -S -E"
					global:Write-CMLogEntry -Value " $($WEProduct): Using $WEComputerManufacturer silent switches: $WEHPSilentSwitches" -Severity 1
					Start-Process -FilePath " $($WETempDirectory + '\Driver Cab\' + $WEDriverCab)" -ArgumentList $WEHPSilentSwitches -Verb RunAs
					$WEDriverProcess = ($WEDriverCab).Substring(0, $WEDriverCab.length - 4)
					
					# Wait for HP SoftPaq Process To Finish
					While ((Get-Process).name -contains $WEDriverProcess) {
						global:Write-CMLogEntry -Value " $($WEProduct): Waiting for extract process (Process: $WEDriverProcess) to complete..  Next check in 30 seconds" -Severity 1
						sleep -Seconds 30
					}
				}
				if ($WEComputerManufacturer -eq " Lenovo" ) {
					# Driver Silent Extract Switches
					$global:LenovoSilentSwitches = " /VERYSILENT /DIR=" + '" ' + $WEDriverExtractDest + '" ' + ' /Extract=" Yes" '
					global:Write-CMLogEntry -Value " $($WEProduct): Using $WEComputerManufacturer silent switches: $global:LenovoSilentSwitches" -Severity 1
					global:Write-CMLogEntry -Value " $($WEProduct): Extracting $WEComputerManufacturer drivers to $WEDriverExtractDest" -Severity 1
					Unblock-File -Path $($WETempDirectory + '\Driver Cab\' + $WEDriverCab)
					Start-Process -FilePath " $($WETempDirectory + '\Driver Cab\' + $WEDriverCab)" -ArgumentList $global:LenovoSilentSwitches -Verb RunAs
				; 	$WEDriverProcess = ($WEDriverCab).Substring(0, $WEDriverCab.length - 4)
					# Wait for Lenovo Driver Process To Finish
					While ((Get-Process).name -contains $WEDriverProcess) {
						global:Write-CMLogEntry -Value " $($WEProduct): Waiting for extract process (Process: $WEDriverProcess) to complete..  Next check in 30 seconds" -Severity 1
						sleep -seconds 30
					}
				}
			}
			else {
				global:Write-CMLogEntry -Value " Skipping. Drivers already extracted." -Severity 1
			}
		}
		else {
			global:Write-CMLogEntry -Value " $($WEProduct): $WEDriverCab file download failed" -Severity 3
		}
	}
	elseif ($WEDriverDownload -eq " badLink" ) {
		global:Write-CMLogEntry -Value " $($WEProduct): Operating system driver package download path not found.. Skipping $WEComputerModel" -Severity 3
	}
	else {
		global:Write-CMLogEntry -Value " $($WEProduct): Driver package not found for $WEComputerModel running Windows $WEWindowsVersion $WEArchitecture. Skipping $WEComputerModel" -Severity 2
	}
	global:Write-CMLogEntry -Value " ======== $WEPRODUCT - $WEComputerManufacturer $WEComputerModel DRIVER PROCESSING FINISHED ========" -Severity 1
	
	
	if ($WEValidationErrors -eq 0) {
		
	}
}

function WE-Update-Drivers {
; 	$WEDriverPackagePath = Join-Path $WETempDirectory " Driver Files"
	Write-CMLogEntry -Value " Driver package location is $WEDriverPackagePath" -Severity 1
	Write-CMLogEntry -Value " Starting driver installation process" -Severity 1
	Write-CMLogEntry -Value " Reading drivers from $WEDriverPackagePath" -Severity 1
	# Apply driver maintenance package
	try {
		if ((Get-ChildItem -Path $WEDriverPackagePath -Filter *.inf -Recurse).count -gt 0) {
			try {
				Start-Process " $env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -WorkingDirectory $WEDriverPackagePath -ArgumentList " pnputil /add-driver *.inf /subdirs /install | Out-File -FilePath (Join-Path $WELogDirectory '\Install-Drivers.txt') -Append" -NoNewWindow -Wait
				Write-CMLogEntry -Value " Driver installation complete. Restart required" -Severity 1
			}
			catch [System.Exception]
			{
				Write-CMLogEntry -Value " An error occurred while attempting to apply the driver maintenance package. Error message: $($_.Exception.Message)" -Severity 3; exit 1
			}
		}
		else {
			Write-CMLogEntry -Value " No driver inf files found in $WEDriverPackagePath." -Severity 3; exit 1
		}
	}
	catch [System.Exception] {
		Write-CMLogEntry -Value " An error occurred while attempting to apply the driver maintenance package. Error message: $($_.Exception.Message)" -Severity 3; exit 1
	}
	Write-CMLogEntry -Value " Finished driver maintenance." -Severity 1
	Return $WELastExitCode
}

if ($WEOSName -eq " Windows 10" ) {
	# Download manufacturer lists for driver matching
	DownloadDriverList
	# Initiate matched downloads
	InitiateDownloads
	# Update driver repository and install drivers
	Update-Drivers
}
else {
	Write-CMLogEntry -Value " An upsupported OS was detected. This script only supports Windows 10." -Severity 3; exit 1
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================