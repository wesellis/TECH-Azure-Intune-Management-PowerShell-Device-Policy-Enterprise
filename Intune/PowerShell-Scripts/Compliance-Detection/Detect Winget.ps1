<#
.SYNOPSIS
    Detect Winget

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
    We Enhanced Detect Winget

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

$desiredVersion = " 1.22.3172.0" # <-- can be retrieved from Get-AppxPackage cmdlet: Get-AppxPackage | Where-Object {$_.Name -eq " Microsoft.DesktopAppInstaller" }


function WE-Get-CurrentVersion {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
        [Parameter(Mandatory = $true)]
        [string]$WEPackageName
    )

    try {
       ;  $currentVersion = (Get-AppxPackage | Where-Object { $_.Name -eq $WEPackageName }).Version
        return $currentVersion
    }
    catch {
        Write-WELog " Error: $_" " INFO"
        exit 1
    }
}

; 
$currentVersion = Get-CurrentVersion -PackageName " Microsoft.DesktopAppInstaller"


if ($currentVersion -eq $desiredVersion) {
    Write-WELog " Winget version $currentVersion detected" " INFO"
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================