<#
.SYNOPSIS
    Createhyperv V2

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
    We Enhanced Createhyperv V2

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
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$WETrue,Position=1)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEName,

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
    [string]$WECPUCount,
    
    [Parameter(Mandatory=$WEFalse,Position=4)]
    [switch]$WEAutopilot = $WEFalse
)

$number = Get-Random -Minimum 1000 -Maximum 10000
$numberString = $number.ToString()
$WEVMName = $WEName + " -" + $version + " -" + $numberString


Copy-Item -Path " D:\Templates\GM-$($version).vhdx" -Destination " C:\Hyper-V\Virtual hard disks\$($WEVMName).vhdx" -Force | Out-Null


$WEVMSwitchName = " Default Switch"
$WEVhdxPath = " C:\Hyper-V\Virtual hard disks\$($WEVMName).vhdx"
$WEVMPath = " C:\Hyper-V\Virtual machines"


New-VM -Name $WEVMName -BootDevice VHD -VHDPath $WEVhdxPath -Path $WEVMPath -Generation 2 -Switch $WEVMSwitchName
Set-VM -VMName $WEVMName -ProcessorCount $WECPUCount
Set-VMMemory -VMName $WEVMName -StartupBytes 8GB -DynamicMemoryEnabled $false
Set-VMSecurity -VMName $WEVMName -VirtualizationBasedSecurityOptOut $false
Set-VMKeyProtector -VMName $WEVMName -NewLocalKeyProtector
Enable-VMTPM -VMName $WEVMName
Enable-VMIntegrationService -VMName $WEVMName -Name " Guest Service Interface"
Set-VM -VMName $WEVMName -AutomaticCheckpointsEnabled $false | Out-Host

if($WEAutopilot -eq $WETrue)
{
    # make a path to export the csv to
    $exportPath = " C:\Autopilot"
    if(!(Test-Path $exportPath))
    {
        mkdir $exportPath
    }
    # get the hardware info: manufacturer, model, serial
   ;  $serial = Get-CimInstance -ComputerName localhost -Namespace root\virtualization\v2 -class Msvm_VirtualSystemSettingData | Where-Object {$_.elementName -eq $WEVMName} | Select-Object -ExpandProperty BIOSSerialNumber
   ;  $data = " Microsoft Corporation,Virtual Machine,$($serial)"
    # add to CSV file in path
    Set-Content -Path " $($exportPath)\$($WEVMName).csv" -Value $data
}



} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
