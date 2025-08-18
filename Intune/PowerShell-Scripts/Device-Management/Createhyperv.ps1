<#
.SYNOPSIS
    Createhyperv

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
    We Enhanced Createhyperv

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
    [string]$WEVMName,
    [Parameter(Mandatory=$WETrue,Position=2)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$version,
    [Parameter(Mandatory=$WETrue,Position=3)]
    [string]$WECPUCount
)


Copy-Item -Path " D:\Templates\GM-$($version).vhdx" -Destination " D:\Hyper-V\Virtual hard disks\$($WEVMName).vhdx" -Force | Out-Null


$WEVMSwitchName = " Default Switch"; 
$WEVhdxPath = " D:\Hyper-V\Virtual hard disks\$($WEVMName).vhdx" ; 
$WEVMPath = " D:\Hyper-V\Virtual machines"


New-VM -Name $WEVMName -BootDevice VHD -VHDPath $WEVhdxPath -Path $WEVMPath -Generation 2 -Switch $WEVMSwitchName
Set-VM -VMName $WEVMName -ProcessorCount $WECPUCount
Set-VMMemory -VMName $WEVMName -StartupBytes 8GB -DynamicMemoryEnabled $false
Set-VMSecurity -VMName $WEVMName -VirtualizationBasedSecurityOptOut $false
Set-VMKeyProtector -VMName $WEVMName -NewLocalKeyProtector
Enable-VMTPM -VMName $WEVMName
Enable-VMIntegrationService -VMName $WEVMName -Name " Guest Service Interface"
Set-VM -VMName $WEVMName -AutomaticCheckpointsEnabled $false




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
