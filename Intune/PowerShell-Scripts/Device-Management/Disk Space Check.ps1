<#
.SYNOPSIS
    Disk Space Check

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
    We Enhanced Disk Space Check

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
    Disk Space Detection Script for Microsoft Intune

.DESCRIPTION
    Detects low disk space conditions on system drives.
    This script checks available free space and reports if it falls below specified thresholds.
    Safe for production use with comprehensive error handling.

.PARAMETER MinimumFreeSpaceGB
    Minimum required free space in GB (default: 10)

.PARAMETER WhatIf
    Shows what would be detected without making any changes

.NOTES
    Version: 1.0
    Author: Intune Remediation Scripts
    Creation Date: 2025-08-14
    
    Exit Codes:
    0 = Success (sufficient disk space)
    1 = Issue detected (low disk space)
    2 = Script error
    
.EXAMPLE
    .\disk-space-check.ps1
    .\disk-space-check.ps1 -MinimumFreeSpaceGB 20 -WhatIf


[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory = $false)]
    [int]$WEMinimumFreeSpaceGB = 10,
    
    [Parameter(Mandatory = $false)]
    [switch]$WEWhatIf
)


$WELogPath = " $env:TEMP\IntuneRemediation_DiskSpaceDetection.log"
$WETimeStamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"

function WE-Write-LogEntry {
    param([Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEMessage, [string]$WELevel = " INFO" )
    $WELogEntry = " [$WETimeStamp] [$WELevel] $WEMessage"
    Add-Content -Path $WELogPath -Value $WELogEntry -Force
    Write-Output $WELogEntry
}

try {
    Write-LogEntry " Starting disk space detection script"
    Write-LogEntry " Minimum required free space: $WEMinimumFreeSpaceGB GB"
    
    if ($WEWhatIf) {
        Write-LogEntry " Running in WhatIf mode - no changes will be made" " INFO"
    }
    
    # Get system drives (typically C: drive)
    $WESystemDrives = Get-CimInstance -Class Win32_LogicalDisk -Filter " DriveType=3" | Where-Object { $_.DeviceID -eq " C:" }
    
    $WEIssueDetected = $false
    
    foreach ($WEDrive in $WESystemDrives) {
        $WEFreeSpaceGB = [math]::Round($WEDrive.FreeSpace / 1GB, 2)
        $WETotalSpaceGB = [math]::Round($WEDrive.Size / 1GB, 2)
        $WEUsedSpaceGB = $WETotalSpaceGB - $WEFreeSpaceGB
       ;  $WEPercentFree = [math]::Round(($WEFreeSpaceGB / $WETotalSpaceGB) * 100, 2)
        
        Write-LogEntry " Drive $($WEDrive.DeviceID) - Total: $WETotalSpaceGB GB, Free: $WEFreeSpaceGB GB, Used: $WEUsedSpaceGB GB ($WEPercentFree% free)"
        
        if ($WEFreeSpaceGB -lt $WEMinimumFreeSpaceGB) {
            Write-LogEntry " WARNING: Drive $($WEDrive.DeviceID) has insufficient free space: $WEFreeSpaceGB GB (minimum required: $WEMinimumFreeSpaceGB GB)" " WARNING"
           ;  $WEIssueDetected = $true
        } else {
            Write-LogEntry " Drive $($WEDrive.DeviceID) has sufficient free space"
        }
    }
    
    if ($WEIssueDetected) {
        Write-LogEntry " Disk space issue detected - remediation required"
        if ($WEWhatIf) {
            Write-LogEntry " WhatIf: Would report disk space issue for remediation"
            exit 0  # In WhatIf mode, don't trigger remediation
        }
        exit 1  # Trigger remediation
    } else {
        Write-LogEntry " All drives have sufficient free space"
        exit 0  # No remediation needed
    }
    
} catch {
    Write-LogEntry " Error occurred: $($_.Exception.Message)" " ERROR"
    Write-LogEntry " Stack trace: $($_.ScriptStackTrace)" " ERROR"
    exit 2  # Script error
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================