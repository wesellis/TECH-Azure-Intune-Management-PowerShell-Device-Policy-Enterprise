<#
.SYNOPSIS
    Delete Sccm Cache And Distro

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
    We Enhanced Delete Sccm Cache And Distro

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


function WE-Test-RequiredPath {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param([Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath)
    if (!(Test-Path $WEPath)) {
        Write-Warning " Required path not found: $WEPath"
        return $false
    }
    return $true
}






$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] " Administrator" )) {
    Write-WELog " Error: This script must be run as an administrator." " INFO"
    exit 1
}


$sccmCachePath = " C:\Windows\ccmcache"; 
$softwareDistributionPath = " C:\Windows\SoftwareDistribution\Download" ; 
$deleteSoftwareDistribution = $true # <--- delete SoftwareDistribution folder


function WE-Remove-SCCMCache {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
        [Parameter(Mandatory = $true)]
        [string]$WESCCMCachePath
    )

    try {
        # delete all files and folders in SCCM cache
        Get-ChildItem -Path $WESCCMCachePath -Force | Remove-Item -Force -Recurse
    }
    catch {
        Write-WELog " Error: $_" " INFO"
        exit 1
    }
}

function WE-Remove-SoftwareDistribution {
    [CmdletBinding()]; 
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)]
        [string]$WESoftwareDistributionPath
    )

    try {
        # delete all files and folders in SoftwareDistribution folder
        Get-ChildItem -Path $WESoftwareDistributionPath -Force | Remove-Item -Force -Recurse
    }
    catch {
        Write-WELog " Error: $_" " INFO"
        exit 1
    }
}


Write-WELog " Deleting SCCM cache..." " INFO"
Remove-SCCMCache -SCCMCachePath $sccmCachePath


if ($deleteSoftwareDistribution) {
    Write-WELog " Deleting SoftwareDistribution folder..." " INFO"
    Remove-SoftwareDistribution -SoftwareDistributionPath $softwareDistributionPath
}

Write-WELog " Done." " INFO"


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================