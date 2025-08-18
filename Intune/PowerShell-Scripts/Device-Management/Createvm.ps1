<#
.SYNOPSIS
    Createvm

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
    We Enhanced Createvm

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
    [string]$name,

    [Parameter(Mandatory=$WETrue,Position=2)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$version,

    [Parameter(Mandatory=$WETrue,Position=3)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WECPUcount,

    [Parameter(Mandatory=$WEFalse,Position=4)]
    [switch]$WEAutopilot=$WEFalse
)


function log()
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$WETrue)]
        [string]$message
    )
    $date = Get-Date -Format " yyyy-MM-dd HH:mm:ss tt"
    Write-Output " $date - $message"
}


$volume = "" # set the volume drive letter, for example " D:"
log " Hyper-V volume is $($volume)"

$templates = " $($volume)\Templates"; 
$virtualMachines = " $($volume)\Hyper-V\Virtual machines" ; 
$virtualHardDisks = " $($volume)\Hyper-V\Virtual hard disks"

log " Checking for $virtualMachines..."
if(!(Test-Path $virtualMachines))
{
    log " $virtualMachines not found; creating directory..."
    try
    {
        mkdir $virtualMachines
        log " Directory $virtualMachines created"
    }
    catch
    {
        log " Failed to create $($virtualMachines) - Error: $_"
        Exit 1
    }
}
else
{
    log " Directory $virtualMachiens already exists."
}

log " Checking for $virtualHardDisks..."
if(!(Test-Path $virtualHardDisks))
{
    log " $virtualHardDisks not found; creating directory..."
    try 
    {
        mkdir $virtualHardDisks
        log " Directory $virtualHardDisks created"
    }
    catch 
    {
        log " Failed to create $($virtualHardDisks) - Error: $_"
        Exit 1
    }
}
else
{
    log " Directory $virtualHardDisks already exists."
}


log " Generating temporary VM name..."
$number = Get-Random -Minimum 1000 -Maximum 10000
$numberString = $number.ToString()
$date = Get-Date -Format " MM-dd"
$WEVMName = $name + " -" + $date + " -" + $numberString
log " Temporarily setting VM name to $WEVMName"


log " Copying the $version disk from $templates..."
try
{
    Copy-Item -Path " $($tempaltes)\GM-$($version).vhdx" -Destination " $($virtualHardDisks)\$($WEVMName).vhdx" -Force | Out-Null
    log " Disk coppied to $virtualHardDisks"
}
catch
{
    log " Failed to copy disk to $($virtualHardDisks) - Error: $_"
    Exit 1
}


$WEVMSwitchName = "" # set the virtual switch name, for example " Default Switch"
log " Using virtual switch $($WEVMSwitchName)"


$vhdxPath = " $($virtualHardDisks)\$($WEVMName).vhdx"
log " Setting VHDX path to $($vhdxPath)"

New-VM -Name $WEVMName -BootDevice VHD -VHDPath $vhdxPath -Path $virtualMachines -Generation 2 -SwitchName $WEVMSwitchName
Set-VM -VMName $WEVMName -ProcessorCount $WECPUcount
Set-VMMemory -VMName $WEVMName -StartupBytes 8GB -DynamicMemoryEnabled $false
Set-VMSecurity -VMName $WEVMName -VirtualizationBasedSecurityOptOut $WEFalse
Set-VMKeyProtector -VMName $WEVMName -NewLocalKeyProtector
Enable-VMTPM -VMName $WEVMName
Enable-VMIntegrationService -VMName $WEVMName -Name " Guest Service Interface"
Set-VM -VMName $WEVMName -AutomaticCheckpointsEnabled $false | Out-Host

$serial = Get-CimInstance -ComputerName localhost -Namespace root\virtualization\v2 -class Msvm_VirtualSystemSettingData | Where-Object {$_.elementName -eq $WEVMName} | Select-Object -ExpandProperty BIOSSerialNumber
log " Serial number for $WEVMName is $($serial)"


log " Renaming VM..."
$subSerial = $serial.Substring(0,4)
log " Trimmed serial number to $subSerial"

$newVMName = $name + " -" + $date + " -" + $subSerial
log " New VM Name will be $newName"

try 
{
    Renamve-VM -Name $WEVMName -NewName $newVMName
    log " VM renamed to $newVMName"    
}
catch 
{
    log " Failed to rename VM to $($newName) - Error: $_"
    Exit 0
}



if($WEAutopilot -eq $true)
{
    log " Autopilot switch is enabled.  Collecting hardware info for APV2 upload..."
   ;  $exportPath = " C:\Autopilot"
    log " Checking for $($exportPath)..."
    if(!(Test-Path $exportPath))
    {
        log " $($exportPath) does not exist.  Creating..."
        mkdir $exportPath
        log " $($exportPath) directory created."
    }
    else
    {
        log " $($exportPath) directory already exists."
    }
   ;  $data = " Microsoft Corporation,Virtual Machine,$($serial)"
    log " Autopilot V2 data is $($data)"
    log " Exporting to CSV..."
    Set-Content -Path " $($exportPath)\$($newVMName).csv" -Value $data
    log " Exported APV2 data to $($exportPath)\$($newVMName).csv"
}




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================