<#
.SYNOPSIS
    Invoke Intunebiosupdate Detect

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
    We Enhanced Invoke Intunebiosupdate Detect

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
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    BIOS Control detection script for MSEndpointMgr Intune MBM
.DESCRIPTION
    This proactive remediation script is part of the Intune version of Modern BIOS management. More information can be found at https://msendpointmgr.com 
    NB: Only edit variables in the Declarations region of the script. 
    The following variables MUST be set: 
    1. DATUri - Url path to BIOSPackages.xml 
.EXAMPLE
	Invoke-IntuneBIOSUpdateDetect.ps1 - Run as SYSTEM 
.NOTES
	Version:    0.9 Beta
    Author:     Maurice Daly / Jan Ketil Skanke @ Cloudway
    Contact:    @JankeSkanke @Modaly_IT
    Creation Date:  01.10.2021
    Purpose/Change: Initial script development
    Created:     2021-14-11
    Updated:     
    Version history:
    0.9 - (2021.14.11) Beta Release

$WEScript:ErrorActionPreference = " SilentlyContinue"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$WEScript:ExitCode = 0



$WEScript:EventLogName = 'MSEndpointMgr'
$WEScript:EventLogSource = 'MSEndpointMgrBIOSMgmt'
New-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -ErrorAction SilentlyContinue


$WEScript:DATUri = " <TO BE SET>"


$WEScript:Manufacturer = (Get-CimInstance -Class " Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()


$WEScript:RegPath = 'HKLM:\SOFTWARE\MSEndpointMgr\BIOSUpdateManagemement'


$WEScript:BIOSUpdateInprogress = $null
$WEScript:BIOSUpdateAttempts = $null
$WEScript:BIOSUpdateTime = $null
$WEScript:BIOSDeployedVersion = $null


function WE-Test-BIOSVersionHP{
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[version]$WEBIOSApprovedVersion,
        [parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$WESystemID
	)  
    $WEOutput = @{}
    # Import HP Module 
    Import-Module HP.ClientManagement

    # Obtain current BIOS verison
    [version]$WECurrentBIOSVersion = Get-HPBIOSVersion

    # Inform current BIOS deployment state
    if ($WEBIOSApprovedVersion -gt $WECurrentBIOSVersion){
        $WEOutputMessage = " BIOS needs an update. Current version is $WECurrentBIOSVersion, available version is $WEBIOSApprovedVersion"
        $WEExitCode = 1
    } 
    elseif ($WEBIOSApprovedVersion -eq $WECurrentBIOSVersion) {
        $WEOutputMessage = " BIOS is current on version $WECurrentBIOSVersion"
        $WEExitCode = 0
    } 
    elseif ($WEBIOSApprovedVersion -lt $WECurrentBIOSVersion) {
        $WEOutputMessage = " BIOS is on a higher version than approved $WECurrentBIOSVersion. Approved version $WEBIOSApprovedVersion"
        $WEExitCode = 0
    } 
    
    $WEOutput = @{
         " Message" = $WEOutputMessage
         " ExitCode" = $WEExitCode
    }

    Return $WEOutput
}#endfunction
function WE-Test-BiosVersionDell{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$WEBIOSPackageDetails 
        )
    $WEOutputMessage = " Dell Not implemented"
    $WEExitCode = 0
    $WEOutput = @{
        " Message" = $WEOutputMessage
        " ExitCode" = $WEExitCode
    }
    Return $WEOutput
    }#endfunction
function WE-Test-BiosVersionLenovo{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$WEBIOSPackageDetails 
        )  
    $WEOutputMessage = " Dell Not implemented"
    $WEExitCode = 0
    $WEOutput = @{
        " Message" = $WEOutputMessage
        " ExitCode" = $WEExitCode
    }
    Return $WEOutput
}#endfunction




[xml]$WEBIOSPackages = Invoke-WebRequest -Uri $WEDATUri -UseBasicParsing


$WEBIOSPackageDetails = $WEBIOSPackages.ArrayOfCMPackage.CMPackage


switch -Wildcard ($WEManufacturer) { 
    {($WEPSItem -match " HP" ) -or ($WEPSItem -match " Hewlett-Packard" )}{
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Validated HP hardware check"
        $WEHPPreReq = [boolean](Get-InstalledModule | Where-Object {$_.Name -match " HPCMSL" } -ErrorAction SilentlyContinue -Verbose:$false)
        if ($WEHPPreReq){
            # Import module
            Import-Module HP.ClientManagement
            # Get matching identifier from baseboard
            $WESystemID = Get-HPDeviceProductID
            $WESupportedModel = $WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID}
            if (-not ([string]::IsNullOrEmpty($WESupportedModel))) {
                [version]$WEBIOSApprovedVersion = ($WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" " )[0] 
                $WEOEM = " HP"
                Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " $($WESupportedModel.Description) succesfully matched on SKU $($WESystemID)"
            } 
            else {
                Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " Model with SKU value $($WESystemID) not found in XML source. Exiting script"
                Write-Output " Model with SKU value $($WESystemID) not found in XML source. Exiting script"
                Exit 0
            }       
        } 
        else { 
            # HP Prereq is missing. Exit script
            Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " HP CMSL Powershell Module is missing. Remediation not possible."
            Write-Output " HP Prereq missing. HPCMSL Powershell Module is missing. Remediation not possible."
            Exit 0
        }
    }
    {($WEPSItem -match " Lenovo" )}{
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Validated Lenovo hardware check"
        $WELenovoPreReq = $false
        if ($WELenovoPreReq){
            # Get matching identifier from baseboard
            $WESystemID = " Something"
            $WESupportedModel = $WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID}
            if (-not ([string]::IsNullOrEmpty($WESupportedModel))) {
                [version]$WEBIOSApprovedVersion = ($WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" " )[0] 
                $WEOEM = " Lenovo"
            } 
            else {
                Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Model $WEComputerModel with SKU value $WESystemSKU not found in XML source"
            }
        }
        else {
        Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " $($WEManufacturer) not implemented"
        Write-output " $($WEManufacturer) not implemented"
        Exit 0
        }
    }
    {($WEPSItem -match " Dell" )}{
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Validated Dell hardware check"
        $WEDellPreReq = $false
        if ($WEDellPreReq){
            # Get matching identifier from baseboard
            $WESystemID = " Something"
            $WESupportedModel = $WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID}
            if (-not ([string]::IsNullOrEmpty($WESupportedModel))) {
                [version]$WEBIOSApprovedVersion = ($WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" " )[0] 
                $WEOEM = " Dell"
            } 
            else {
                Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " Model with SKU value $($WESystemID) not found in XML source. Exiting script"
                Write-Output " Model with SKU value $($WESystemID) not found in XML source. Exiting script"
                Exit 0
            }       
        }
        else {
            Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " $($WEManufacturer) not implemented"
            Write-output " $($WEManufacturer) not implemented"
            Exit 0
        }

    }
    default {
                Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Incompatible Hardware. $($WEManufacturer) not supported"
                Write-output " Incompatible Hardware. $($WEManufacturer) not supported"
                Exit 0
    }
}


if (-NOT(Test-Path -Path " $WERegPath\" )) {
    New-Item -Path " $WERegPath" -Force | Out-Null
    New-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateInprogress' -Value 0 -PropertyType 'DWORD' -Force | Out-Null
    New-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateAttempts' -Value 0 -PropertyType 'DWORD' -Force | Out-Null
    New-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateTime' -Value "" -PropertyType 'String' -Force | Out-Null
    New-ItemProperty -Path " $WERegPath" -Name 'BIOSDeployedVersion' -Value "" -PropertyType 'String' -Force | Out-Null
}


$WEBiosUpdateinProgress = Get-ItemPropertyValue -Path " $($WERegPath)\" -Name BIOSUpdateInprogress
if ($WEBiosUpdateinProgress -ne 0){
    Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " BIOS Update is in Progress"
    # Check if computer has restarted since last try 
    [DateTime]$WEBIOSUpdateTime = Get-ItemPropertyValue -Path " $WERegPath" -Name 'BIOSUpdateTime'
    $WELastBootime = Get-Date (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)
    if ($WEBIOSUpdateTime -gt $WELastBootime){
        # Computer not restarted - Invoke remediation to notify user to reboot
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " BIOSUpdateTime is newer than last reboot, pending first reboot"
        Exit 1
    }
    else {
        # Step 4 Computer restarted - Check BIOS Version
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Computer has restarted - validate bios version"
        $WETestBiosCommand = " Test-BIOSVersion$($WEOEM) -BIOSApprovedVersion $($WEBIOSApprovedVersion) -SystemID $($WESystemID)"
        $WEBIOSCheck = Invoke-Expression $WETestBiosCommand

        if ($WEBIOSCheck.ExitCode -eq 0){
            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Update Complete - Clean up in registry"
            Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateInprogress' -Value 0
            Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateAttempts' -Value 0 
            Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateTime' -Value "" 
            Set-ItemProperty -Path " $WERegPath" -Name 'BIOSDeployedVersion' -Value "" 
            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " $($WEBIOSCheck.Message)"
            Write-Output " $($WEBIOSCheck.Message)"
            Exit 0
        }
        else {
            #Step 5 Computer restarted - BIOS not updated - Invoke remediation if threshold not met
            [int]$WEAttempts = Get-ItemPropertyValue -Path $WERegPath -Name 'BIOSUpdateAttempts'
            if ($WEAttempts -gt 3){
                Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " Update not completed after reboot - giving up after $($WEAttempts) attempts"
                Write-Output " Update not completed after reboot - giving up after $($WEAttempts) attempts"
                Exit 0     
            } else {
                Set-ItemProperty -Path $WERegPath -Name 'BIOSUpdateAttempts' -Value $WEAttempts
                Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Update not completed after reboot - Attempts: $($WEAttempts) - Call remediation script"            
                Write-Output " $($WEBIOSCheck.Message)"
                #$WEAttempts++
                Exit 1
            }
        }
    }
} else {
    # Step 6 BIOS Update not in progress - Check BIOS Version
    Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Validate bios version"
   ;  $WETestBiosCommand = " Test-BIOSVersion$($WEOEM) -BIOSApprovedVersion $($WEBIOSApprovedVersion) -SystemID $($WESystemID)"
   ;  $WEBIOSCheck = Invoke-Expression $WETestBiosCommand

    if ($WEBIOSCheck.ExitCode -eq 1){
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " $($WEBIOSCheck.Message)"
        Write-Output " $($WEBIOSCheck.Message)"
        Exit 1
    }
    else {
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " $($WEBIOSCheck.Message)"
        Write-Output " $($WEBIOSCheck.Message)"
        Exit 0
    } 
}


















} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
