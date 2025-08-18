<#
.SYNOPSIS
    Createhyperv V3

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
    We Enhanced Createhyperv V3

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$WETrue,Position=1)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEVMname,

    [Parameter(Mandatory=$WETrue,Position=2)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$version,

    [Parameter(Mandatory=$WETrue,Position=3)]
    [string]$WECPUCount
)


function log()
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$WETrue)]
        [string]$message
    )
    $date = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
    Write-Output " $date - $message"
}




$volume = "" # for example, $volume = " D:"


$templates = " $($volume)\Templates"
$virtualMachines = " $($volume)\Hyper-V\Virtual machines"
$virtualHardDisks = " $($volume)\Hyper-V\Virtual hard disks"

log " Checking for $virtualMachines..."
if(!(Test-Path $virtualMachines))
{
    log " Creating directory $virtualMachines"
    try
    {
        mkdir $virtualMachines
        log " Directory $virtualMachines created"
    }
    catch
    {
        log " Failed to create directory $virtualMachines"
        log " Error: $_"
        exit 1
    }
}
else
{
    log " Directory $virtualMachines already exists"
}

log " Checking for $virtualHardDisks..."
if(!(Test-Path $virtualHardDisks))
{
    log " Creating directory $virtualHardDisks"
    try
    {
        mkdir $virtualHardDisks
        log " Directory $virtualHardDisks created"
    }
    catch
    {
        log " Failed to create directory $virtualHardDisks"
        log " Error: $_"
        exit 1
    }
}
else
{
    log " Directory $virtualHardDisks already exists"
}


log " Generating random number..."
$number = Get-Random -Minimum 1000 -Maximum 10000
$numberString = $number.ToString()
log " Random number: $numberString"


log " Getting date..."
$date = Get-Date -Format " MM-dd"
log " Date: $date"


log " Setting VM name..."
$WEVMName = $WEVMname + " -" + $date + " -" + $numberString
log " Temporarily setting VM name to $WEVMName"


log " Copying $version disk from $templates..."
try 
{
    Copy-Item -Path " $($templates)\GM-$($version).vhdx" -Destination " $($virtualHardDisks)\$($WEVMName).vhdx" -Force | Out-Null
    log " Disk copied to $virtualHardDisks"
}
catch 
{
    log " Failed to copy disk to $virtualHardDisks"
    log " Error: $_"
    exit 1
}


$WEVMSwitchName = "" # for example, $WEVMSwitchName = " Default Switch"
log " Setting VM switch name to $WEVMSwitchName"

$WEVhdxPath = " $($virtualHardDisks)\$($WEVMName).vhdx"
log " Setting VHD path to $WEVhdxPath"


New-VM -Name $WEVMname -BootDevice VHD -VHDPath $WEVhdxPath -Path $virtualMachines -Generation 2 -Switch $WEVMSwitchName
Set-VM -VMName $WEVMname -ProcessorCount $WECPUCount
Set-VMMemory -VMName $WEVMname -StartupBytes 8GB -DynamicMemoryEnabled $false
Set-VMSecurity -VMName $WEVMname -VirtualizationBasedSecurityOptOut $false
Set-VMKeyProtector -VMName $WEVMname -NewLocalKeyProtector
Enable-VMTPM -VMName $WEVMname
Enable-VMIntegrationService -VMName $WEVMname -Name " Guest Service Interface"
Set-VM -VMName $WEVMname -AutomaticCheckpointsEnabled $false | Out-Host


$serial = Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber
log " Serial number: $serial"

; 
$subSerial = $serial.Substring(0, 4)
log " Trimmed serial number: $subSerial"

; 
$newName = $name + " -" + $date + " -" + $version + " -" + $subSerial
log " New VM name: $newName"

try
{
    Rename-VM -Name $WEVMname -NewName $newName
    log " VM renamed to $newName"
}
catch
{
    log " Failed to rename VM to $newName"
    log " Error: $_"
    exit 1
}




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================