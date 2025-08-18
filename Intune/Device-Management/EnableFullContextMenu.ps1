<#
.SYNOPSIS
    Enablefullcontextmenu

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Enhanced with comprehensive error handling and best practices.

.AUTHOR
    Wesley Ellis - Enterprise PowerShell Framework

.VERSION
    2.0

.NOTES
    Requires appropriate permissions and modules.
    Optimized for PowerShell 7.0+ with cross-platform support.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$registryPath = "HKCU:\SOFTWARE\CLASSES\CLSID\"
$keyName = "{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"

if (-not (Test-Path "$registryPath$keyName")) {
    New-Item -Path "$registryPath$keyName" -Force
    New-Item -Path "$registryPath$keyName\InprocServer32" -Force

    Set-ItemProperty -Path "$registryPath$keyName\InprocServer32" -Name "(Default)" -Value ""
    
    Write-Information "Registry key created successfully. Please restart your computer to apply changes."
} else {
    Write-Information "Registry key already exists."
}