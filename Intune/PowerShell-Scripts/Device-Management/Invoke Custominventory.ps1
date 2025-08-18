<#
.SYNOPSIS
    Invoke Custominventory

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
    We Enhanced Invoke Custominventory

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
    Collect custom device inventory and upload to Log Analytics for further processing. 

.DESCRIPTION
    This script will collect device hardware and / or app inventory and upload this to a Log Analytics Workspace. This allows you to easily search in device hardware and installed apps inventory. 
    The script is meant to be runned on a daily schedule either via Proactive Remediations (RECOMMENDED) in Intune or manually added as local schedule task on your Windows 10 Computer. 

.EXAMPLE
    Invoke-CustomInventory.ps1 (Required to run as System or Administrator)      

.NOTES
    FileName:    Invoke-CustomInventory.ps1
    Author:      Jan Ketil Skanke
    Contributor: Sandy Zeng / Maurice Daly
    Contact:     @JankeSkanke
    Created:     2021-01-Feb
    Updated:     2021-Nov-07

    Version history:
    0.9.0 - (2021-01-02) Script created
    1.0.0 - (2021-01-02) Script polished cleaned up. 
    1.0.1 - (2021-04-05) Added NetworkAdapter array and fixed typo
    2.0.1 (2021-09-01) Removed all location information for privacy reasons 
    2.1 - (2021-09-08) Added section to cater for BIOS release version information, for HP, Dell and Lenovo and general bugfixes
    2.1.1 - (2021-21-10) Added MACAddress to the inventory for each NIC. 
	2.1.2 - (2021-24-11) Added SMBIOSAssetTag and cleaned up ununsed function WE-Start-FileDownload

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$WECustomerId = ""  


$WESharedKey = ""


$WECollectAppInventory = $true
$WECollectDeviceInventory = $true

$WEAppLogName = " AppInventory"
$WEDeviceLogName = " DeviceInventory"
$WEDate = (Get-Date)


$WETimeStampField = ""




function WE-Get-AzureADDeviceID {
    <#
    .SYNOPSIS
        Get the Azure AD device ID from the local device.
    
    .DESCRIPTION
        Get the Azure AD device ID from the local device.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-05-26
        Updated:     2021-05-26
    
        Version history:
        1.0.0 - (2021-05-26) Function created
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$WEAzureADJoinInfoRegistryKeyPath = " HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$WEAzureADJoinInfoThumbprint = Get-ChildItem -Path $WEAzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty " PSChildName"
		if ($WEAzureADJoinInfoThumbprint -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
			$WEAzureADJoinCertificate = Get-ChildItem -Path " Cert:\LocalMachine\My" -Recurse | Where-Object { $WEPSItem.Thumbprint -eq $WEAzureADJoinInfoThumbprint }
			if ($WEAzureADJoinCertificate -ne $null) {
				# Determine the device identifier from the subject name
				$WEAzureADDeviceID = ($WEAzureADJoinCertificate | Select-Object -ExpandProperty " Subject" ) -replace " CN=" , ""
				# Handle return value
				return $WEAzureADDeviceID
			}
		}
	}
} #endfunction 

function WE-Get-AzureADJoinDate {
    <#
    .SYNOPSIS
        Get the Azure AD device join date 
    
    .DESCRIPTION
        Get the Azure AD device join date 
    
    .NOTES
        Author:      Jan Ketil Skanke
        Contact:     @JankeSkanke
        Created:     2021-11-11
        Updated:     2021-11-11
    
        Version history:
        1.0.0 - (2021-11-11) Function created
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$WEAzureADJoinInfoRegistryKeyPath = " HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$WEAzureADJoinInfoThumbprint = Get-ChildItem -Path $WEAzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty " PSChildName"
		if ($WEAzureADJoinInfoThumbprint -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
			$WEAzureADJoinCertificate = Get-ChildItem -Path " Cert:\LocalMachine\My" -Recurse | Where-Object { $WEPSItem.Thumbprint -eq $WEAzureADJoinInfoThumbprint }
			if ($WEAzureADJoinCertificate -ne $null) {
				# Determine the device identifier from the subject name
				$WEAzureADJoinDate = ($WEAzureADJoinCertificate | Select-Object -ExpandProperty " NotBefore" ) 
				# Handle return value
				return $WEAzureADJoinDate
			}
		}
	}
} #endfunction 

function WE-Get-InstalledApplications() {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
        [string]$WEUserSid
    )
    
    New-PSDrive -PSProvider Registry -Name " HKU" -Root HKEY_USERS | Out-Null
    $regpath = @(" HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" )
    $regpath = $regpath + " HKU:\$WEUserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    if (-not ([IntPtr]::Size -eq 4)) {
        $regpath = $regpath + " HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $regpath = $regpath + " HKU:\$WEUserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    $propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString'
    $WEApps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, PSPath | Sort-Object DisplayName   
    Remove-PSDrive -Name " HKU" | Out-Null
    Return $WEApps
}#end function

Function New-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = " x-ms-date:" + $date
    $stringToHash = $method + " `n" + $contentLength + " `n" + $contentType + " `n" + $xHeaders + " `n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
    return $authorization
}#end function

Function Send-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = " POST"
    $contentType = " application/json"
    $resource = " /api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString(" r" )
    $contentLength = $body.Length
    $signature = New-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = " https://" + $customerId + " .ods.opinsights.azure.com" + $resource + " ?api-version=2016-04-01"
    
    #validate that payload data does not exceed limits
    if ($body.Length -gt (31.9 *1024*1024))
    {
        throw(" Upload payload is too big and exceed the 32Mb limit for a single upload. Please reduce the payload size. Current payload size is: " + ($body.Length/1024/1024).ToString(" #.#" ) + " Mb" )
    }

   ;  $payloadsize = (" Upload payload size is " + ($body.Length/1024).ToString(" #.#" ) + " Kb " )

   ;  $headers = @{
        " Authorization"        = $signature;
        " Log-Type"             = $logType;
        " x-ms-date"            = $rfc1123date;
        " time-generated-field" = $WETimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    $statusmessage = " $($response.StatusCode) : $($payloadsize)"
    return $statusmessage 
}#end function

function WE-Get-AzureADTenantID {
	# Cloud Join information registry path
	$WEAzureADTenantInfoRegistryKeyPath = " HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
	# Retrieve the child key name that is the tenant id for AzureAD
	$WEAzureADTenantID = Get-ChildItem -Path $WEAzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty " PSChildName"
	return $WEAzureADTenantID
}#end function



if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
    $WEMSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' }
    $WEManagedDeviceInfo = Get-ItemProperty -LiteralPath " Registry::$($WEMSDMServerInfo)"
}
$WEManagedDeviceName = $WEManagedDeviceInfo.EntDeviceName
$WEManagedDeviceID = $WEManagedDeviceInfo.EntDMID
$WEAzureADDeviceID = Get-AzureADDeviceID
$WEAzureADTenantID = Get-AzureADTenantID


$WEComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$WEComputerName = $WEComputerInfo.Name
$WEComputerManufacturer = $WEComputerInfo.Manufacturer

if ($WEComputerManufacturer -match " HP|Hewlett-Packard" ) {
	$WEComputerManufacturer = " HP"
}


if ($WECollectDeviceInventory) {
	
	# Get Windows Update Service Settings
	$WEDefaultAUService = (New-Object -ComObject " Microsoft.Update.ServiceManager" ).Services | Where-Object { $_.isDefaultAUService -eq $WETrue } | Select-Object Name
	$WEAUMeteredNetwork = (Get-ItemProperty -Path HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings\).AllowAutoWindowsUpdateDownloadOverMeteredNetwork 
	if ($WEAUMeteredNetwork -eq " 0" ) {
		$WEAUMetered = " false"
	} else { $WEAUMetered = " true" }
	
	
	# Get Computer Inventory Information 
	$WEComputerOSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
	$WEComputerBIOSInfo = Get-CimInstance -ClassName Win32_BIOS
	$WEComputerModel = $WEComputerInfo.Model
	$WEComputerLastBoot = $WEComputerOSInfo.LastBootUpTime
	$WEComputerUptime = [int](New-TimeSpan -Start $WEComputerLastBoot -End $WEDate).Days
	$WEComputerInstallDate = $WEComputerOSInfo.InstallDate
	$WEDisplayVersion = (Get-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
	if ([string]::IsNullOrEmpty($WEDisplayVersion)) {
		$WEComputerWindowsVersion = (Get-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
	} else {
		$WEComputerWindowsVersion = $WEDisplayVersion
	}
	$WEComputerOSName = $WEComputerOSInfo.Caption
	$WEComputerSystemSkuNumber = $WEComputerInfo.SystemSKUNumber
	$WEComputerSerialNr = $WEComputerBIOSInfo.SerialNumber
	$WEComputerBIOSUUID = Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
	$WEComputerBIOSVersion = $WEComputerBIOSInfo.SMBIOSBIOSVersion
	$WEComputerBIOSDate = $WEComputerBIOSInfo.ReleaseDate
	$WEComputerSMBIOSAssetTag = Get-CimInstance Win32_SystemEnclosure | Select-Object -expandproperty SMBIOSAssetTag 
	$WEComputerFirmwareType = $env:firmware_type
	$WEPCSystemType = $WEComputerInfo.PCSystemType
		switch ($WEPCSystemType){
			0 {$WEComputerPCSystemType = " Unspecified" }
			1 {$WEComputerPCSystemType = " Desktop" }
			2 {$WEComputerPCSystemType = " Laptop" }
			3 {$WEComputerPCSystemType = " Workstation" }
			4 {$WEComputerPCSystemType = " EnterpriseServer" }
			5 {$WEComputerPCSystemType = " SOHOServer" }
			6 {$WEComputerPCSystemType = " AppliancePC" }
			7 {$WEComputerPCSystemType = " PerformanceServer" }
			8 {$WEComputerPCSystemType = " Maximum" }
			default {$WEComputerPCSystemType = " Unspecified" }
		}
	$WEPCSystemTypeEx = $WEComputerInfo.PCSystemTypeEx
		switch ($WEPCSystemTypeEx){
			0 {$WEComputerPCSystemTypeEx = " Unspecified" }
			1 {$WEComputerPCSystemTypeEx = " Desktop" }
			2 {$WEComputerPCSystemTypeEx = " Laptop" }
			3 {$WEComputerPCSystemTypeEx = " Workstation" }
			4 {$WEComputerPCSystemTypeEx = " EnterpriseServer" }
			5 {$WEComputerPCSystemTypeEx = " SOHOServer" }
			6 {$WEComputerPCSystemTypeEx = " AppliancePC" }
			7 {$WEComputerPCSystemTypeEx = " PerformanceServer" }
			8 {$WEComputerPCSystemTypeEx = " Slate" }
			9 {$WEComputerPCSystemTypeEx = " Maximum" }
			default {$WEComputerPCSystemTypeEx = " Unspecified" }
		}
		
	$WEComputerPhysicalMemory = [Math]::Round(($WEComputerInfo.TotalPhysicalMemory / 1GB))
	$WEComputerOSBuild = $WEComputerOSInfo.BuildNumber
	$WEComputerOSRevision = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
	$WEComputerCPU = Get-CimInstance win32_processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors
	$WEComputerProcessorManufacturer = $WEComputerCPU.Manufacturer | Get-Unique
	$WEComputerProcessorName = $WEComputerCPU.Name | Get-Unique
	$WEComputerNumberOfCores = $WEComputerCPU.NumberOfCores | Get-Unique
	$WEComputerNumberOfLogicalProcessors = $WEComputerCPU.NumberOfLogicalProcessors | Get-Unique
	$WEComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku.Trim()
	
	try {
		$WETPMValues = Get-Tpm -ErrorAction SilentlyContinue | Select-Object -Property TPMReady, TPMPresent, TPMEnabled, TPMActivated, ManagedAuthLevel
	} catch {
		$WETPMValues = $null
	}
	
	try {
		$WEComputerTPMThumbprint = (Get-TpmEndorsementKeyInfo).AdditionalCertificates.Thumbprint
	} catch {
		$WEComputerTPMThumbprint = $null
	}
	
	try {
		$WEBitLockerInfo = Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object -Property *
	} catch {
		$WEBitLockerInfo = $null
	}
	
	$WEComputerTPMReady = $WETPMValues.TPMReady
	$WEComputerTPMPresent = $WETPMValues.TPMPresent
	$WEComputerTPMEnabled = $WETPMValues.TPMEnabled
	$WEComputerTPMActivated = $WETPMValues.TPMActivated
	
	$WEComputerBitlockerCipher = $WEBitLockerInfo.EncryptionMethod
	$WEComputerBitlockerStatus = $WEBitLockerInfo.VolumeStatus
	$WEComputerBitlockerProtection = $WEBitLockerInfo.ProtectionStatus
	$WEComputerDefaultAUService = $WEDefaultAUService.Name
	$WEComputerAUMetered = $WEAUMetered
	
	# Get BIOS information
	# Determine manufacturer specific information
	switch -Wildcard ($WEComputerManufacturer) {
		" *Microsoft*" {
			$WEComputerManufacturer = " Microsoft"
			$WEComputerModel = (Get-CIMInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$WEComputerSystemSKU = Get-CIMInstance -Namespace root\wmi -Class MS_SystemInformation | Select-Object -ExpandProperty SystemSKU
		}
		" *HP*" {
			$WEComputerModel = (Get-CIMInstance  -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$WEComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).BaseBoardProduct.Trim()
			
			# Obtain current BIOS release
			$WECurrentBIOSProperties = (Get-CIMInstance -Class Win32_BIOS | Select-Object -Property *)
			
			# Detect new versus old BIOS formats
			switch -wildcard ($($WECurrentBIOSProperties.SMBIOSBIOSVersion)) {
				" *ver*" {
					if ($WECurrentBIOSProperties.SMBIOSBIOSVersion -match '.F.\d+$') {
						$WEComputerBIOSVersion = ($WECurrentBIOSProperties.SMBIOSBIOSVersion -split " Ver." )[1].Trim()
					} else {
						$WEComputerBIOSVersion = [System.Version]::Parse(($WECurrentBIOSProperties.SMBIOSBIOSVersion).TrimStart($WECurrentBIOSProperties.SMBIOSBIOSVersion.Split(" ." )[0]).TrimStart(" ." ).Trim().Split(" " )[0])
					}
				}
				default {
					$WEComputerBIOSVersion = " $($WECurrentBIOSProperties.SystemBIOSMajorVersion).$($WECurrentBIOSProperties.SystemBIOSMinorVersion)"
				}
			}
		}
		" *Dell*" {
			$WEComputerManufacturer = " Dell"
			$WEComputerModel = (Get-CIMInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$WEComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku.Trim()
			
			# Obtain current BIOS release
			$WEComputerBIOSVersion = (Get-CIMInstance -Class Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion).Trim()
			
		}
		" *Lenovo*" {
			$WEComputerManufacturer = " Lenovo"
			$WEComputerModel = (Get-CIMInstance -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version).Trim()
			$WEComputerSystemSKU = ((Get-CIMInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).SubString(0, 4)).Trim()
			
			# Obtain current BIOS release
			$WECurrentBIOSProperties = (Get-CIMInstance -Class Win32_BIOS | Select-Object -Property *)
			
			# Obtain current BIOS release
			#$WEComputerBIOSVersion = ((Get-CimInstance -Class Win32_BIOS | Select-Object -Property *).SMBIOSBIOSVersion).SubString(0, 8)
			$WEComputerBIOSVersion = " $($WECurrentBIOSProperties.SystemBIOSMajorVersion).$($WECurrentBIOSProperties.SystemBIOSMinorVersion)"
		}
	}
	
	#Get network adapters
	$WENetWorkArray = @()
	
	$WECurrentNetAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
	
	foreach ($WECurrentNetAdapter in $WECurrentNetAdapters) {
		$WEIPConfiguration = Get-NetIPConfiguration -InterfaceIndex $WECurrentNetAdapter[0].ifIndex
		$WEComputerNetInterfaceDescription = $WECurrentNetAdapter.InterfaceDescription
		$WEComputerNetProfileName = $WEIPConfiguration.NetProfile.Name
		$WEComputerNetIPv4Adress = $WEIPConfiguration.IPv4Address.IPAddress
		$WEComputerNetInterfaceAlias = $WECurrentNetAdapter.InterfaceAlias
		$WEComputerNetIPv4DefaultGateway = $WEIPConfiguration.IPv4DefaultGateway.NextHop
		$WEComputerNetMacAddress = $WECurrentNetAdapter.MacAddress
		
		$tempnetwork = New-Object -TypeName PSObject
		$tempnetwork | Add-Member -MemberType NoteProperty -Name " NetInterfaceDescription" -Value " $WEComputerNetInterfaceDescription" -Force
		$tempnetwork | Add-Member -MemberType NoteProperty -Name " NetProfileName" -Value " $WEComputerNetProfileName" -Force
		$tempnetwork | Add-Member -MemberType NoteProperty -Name " NetIPv4Adress" -Value " $WEComputerNetIPv4Adress" -Force
		$tempnetwork | Add-Member -MemberType NoteProperty -Name " NetInterfaceAlias" -Value " $WEComputerNetInterfaceAlias" -Force
		$tempnetwork | Add-Member -MemberType NoteProperty -Name " NetIPv4DefaultGateway" -Value " $WEComputerNetIPv4DefaultGateway" -Force
		$tempnetwork | Add-Member -MemberType NoteProperty -Name " MacAddress" -Value " $WEComputerNetMacAddress" -Force
		$WENetWorkArray = $WENetWorkArray + $tempnetwork
	}
	[System.Collections.ArrayList]$WENetWorkArrayList = $WENetWorkArray
	
	# Get Disk Health
	$WEDiskArray = @()
	# Pattern matching for validation
# Pattern matching for validation
$WEDisks = Get-PhysicalDisk | Where-Object { $_.BusType -match " NVMe|SATA|SAS|ATAPI|RAID" }
	
	# Loop through each disk
	foreach ($WEDisk in ($WEDisks | Sort-Object DeviceID)) {
		# Obtain disk health information from current disk
		$WEDiskHealth = Get-PhysicalDisk -UniqueId $($WEDisk.UniqueId) | Get-StorageReliabilityCounter | Select-Object -Property Wear, ReadErrorsTotal, ReadErrorsUncorrected, WriteErrorsTotal, WriteErrorsUncorrected, Temperature, TemperatureMax
		
		# Obtain media type
		$WEDriveDetails = Get-PhysicalDisk -UniqueId $($WEDisk.UniqueId) | Select-Object MediaType, HealthStatus
		$WEDriveMediaType = $WEDriveDetails.MediaType
		$WEDriveHealthState = $WEDriveDetails.HealthStatus
		$WEDiskTempDelta = [int]$($WEDiskHealth.Temperature) - [int]$($WEDiskHealth.TemperatureMax)
		
		# Create custom PSObject
		$WEDiskHealthState = new-object -TypeName PSObject
		
		# Create disk entry
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " Disk Number" -Value $WEDisk.DeviceID
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " FriendlyName" -Value $($WEDisk.FriendlyName)
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " HealthStatus" -Value $WEDriveHealthState
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " MediaType" -Value $WEDriveMediaType
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " Disk Wear" -Value $([int]($WEDiskHealth.Wear))
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " Disk $($WEDisk.DeviceID) Read Errors" -Value $([int]($WEDiskHealth.ReadErrorsTotal))
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " Disk $($WEDisk.DeviceID) Temperature Delta" -Value $WEDiskTempDelta
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " Disk $($WEDisk.DeviceID) ReadErrorsUncorrected" -Value $($WEDisk.ReadErrorsUncorrected)
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " Disk $($WEDisk.DeviceID) ReadErrorsTotal" -Value $($WEDisk.ReadErrorsTotal)
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " Disk $($WEDisk.DeviceID) WriteErrorsUncorrected" -Value $($WEDisk.WriteErrorsUncorrected)
		$WEDiskHealthState | Add-Member -MemberType NoteProperty -Name " Disk $($WEDisk.DeviceID) WriteErrorsTotal" -Value $($WEDisk.WriteErrorsTotal)
		
		$WEDiskArray = $WEDiskArray + $WEDiskHealthState
		[System.Collections.ArrayList]$WEDiskHealthArrayList = $WEDiskArray
	}
	
	
	# Create JSON to Upload to Log Analytics
	$WEInventory = New-Object System.Object
	$WEInventory | Add-Member -MemberType NoteProperty -Name " ManagedDeviceName" -Value " $WEManagedDeviceName" -Force
    $WEInventory | Add-Member -MemberType NoteProperty -Name " AzureADDeviceID" -Value " $WEAzureADDeviceID" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " ManagedDeviceID" -Value " $WEManagedDeviceID" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " ComputerName" -Value " $WEComputerName" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " Model" -Value " $WEComputerModel" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " Manufacturer" -Value " $WEComputerManufacturer" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " PCSystemType" -Value " $WEComputerPCSystemType" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " PCSystemTypeEx" -Value " $WEComputerPCSystemTypeEx" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " ComputerUpTime" -Value " $WEComputerUptime" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " LastBoot" -Value " $WEComputerLastBoot" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " InstallDate" -Value " $WEComputerInstallDate" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " WindowsVersion" -Value " $WEComputerWindowsVersion" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " DefaultAUService" -Value " $WEComputerDefaultAUService" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " AUMetered" -Value " $WEComputerAUMetered" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " SystemSkuNumber" -Value " $WEComputerSystemSkuNumber" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " SerialNumber" -Value " $WEComputerSerialNr" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " SMBIOSUUID" -Value " $WEComputerBIOSUUID" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " SMBIOSAssetTag" -Value " $WEComputerSMBIOSAssetTag" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " BIOSVersion" -Value " $WEComputerBIOSVersion" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " BIOSDate" -Value " $WEComputerBIOSDate" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " SystemSKU" -Value " $WEComputerSystemSKU" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " FirmwareType" -Value " $WEComputerFirmwareType" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " Memory" -Value " $WEComputerPhysicalMemory" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " OSBuild" -Value " $WEComputerOSBuild" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " OSRevision" -Value " $WEComputerOSRevision" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " OSName" -Value " $WEComputerOSName" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " CPUManufacturer" -Value " $WEComputerProcessorManufacturer" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " CPUName" -Value " $WEComputerProcessorName" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " CPUCores" -Value " $WEComputerNumberOfCores" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " CPULogical" -Value " $WEComputerNumberOfLogicalProcessors" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " TPMReady" -Value " $WEComputerTPMReady" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " TPMPresent" -Value " $WEComputerTPMPresent" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " TPMEnabled" -Value " $WEComputerTPMEnabled" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " TPMActived" -Value " $WEComputerTPMActivated" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " TPMThumbprint" -Value " $WEComputerTPMThumbprint" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " BitlockerCipher" -Value " $WEComputerBitlockerCipher" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " BitlockerVolumeStatus" -Value " $WEComputerBitlockerStatus" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " BitlockerProtectionStatus" -Value " $WEComputerBitlockerProtection" -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " NetworkAdapters" -Value $WENetWorkArrayList -Force
	$WEInventory | Add-Member -MemberType NoteProperty -Name " DiskHealth" -Value $WEDiskHealthArrayList -Force
	
	
	$WEDevicePayLoad = $WEInventory
	
}



if ($WECollectAppInventory) {
	#$WEAppLog = " AppInventory"
	
	#Get SID of current interactive users
	$WECurrentLoggedOnUser = (Get-CimInstance win32_computersystem).UserName
	if (-not ([string]::IsNullOrEmpty($WECurrentLoggedOnUser))) {
		$WEAdObj = New-Object System.Security.Principal.NTAccount($WECurrentLoggedOnUser)
		$strSID = $WEAdObj.Translate([System.Security.Principal.SecurityIdentifier])
		$WEUserSid = $strSID.Value
	} else {
		$WEUserSid = $null
	}
	
	#Get Apps for system and current user
	$WEMyApps = Get-InstalledApplications -UserSid $WEUserSid
	$WEUniqueApps = ($WEMyApps | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$WEDuplicatedApps = ($WEMyApps | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$WENewestDuplicateApp = ($WEDuplicatedApps | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$WECleanAppList = $WEUniqueApps + $WENewestDuplicateApp | Sort-Object DisplayName
	
	$WEAppArray = @()
	foreach ($WEApp in $WECleanAppList) {
		$tempapp = New-Object -TypeName PSObject
		$tempapp | Add-Member -MemberType NoteProperty -Name " ComputerName" -Value " $WEComputerName" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name " ManagedDeviceName" -Value " $WEManagedDeviceName" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name " ManagedDeviceID" -Value " $WEManagedDeviceID" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name " AppName" -Value $WEApp.DisplayName -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name " AppVersion" -Value $WEApp.DisplayVersion -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name " AppInstallDate" -Value $WEApp.InstallDate -Force -ErrorAction SilentlyContinue
		$tempapp | Add-Member -MemberType NoteProperty -Name " AppPublisher" -Value $WEApp.Publisher -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name " AppUninstallString" -Value $WEApp.UninstallString -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name " AppUninstallRegPath" -Value $app.PSPath.Split(" ::" )[-1]
		$WEAppArray = $WEAppArray + $tempapp
	}
	
	$WEAppPayLoad = $WEAppArray
}



$WEDevicejson = $WEDevicePayLoad | ConvertTo-Json
$WEAppjson = $WEAppPayLoad | ConvertTo-Json

$WEResponseDeviceInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($WEDevicejson)) -logType $WEDeviceLogName
$WEResponseAppInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($WEAppjson)) -logType $WEAppLogName


$date = Get-Date -Format " dd-MM HH:mm"
$WEOutputMessage = " InventoryDate:$date "


if ($WECollectDeviceInventory) {
    if ($WEResponseDeviceInventory -match " 200 :" ) {
        
        $WEOutputMessage = $WEOutPutMessage + " DeviceInventory:OK " + $WEResponseDeviceInventory
    }
    else {
        $WEOutputMessage = $WEOutPutMessage + " DeviceInventory:Fail "
    }
}
if ($WECollectAppInventory) {
    if ($WEResponseAppInventory -match " 200 :" ) {
        
       ;  $WEOutputMessage = $WEOutPutMessage + " AppInventory:OK " + $WEResponseAppInventory
    }
    else {
       ;  $WEOutputMessage = $WEOutPutMessage + " AppInventory:Fail "
    }
}
Write-Output $WEOutputMessage
Exit 0






# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================