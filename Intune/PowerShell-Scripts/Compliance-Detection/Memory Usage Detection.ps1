<#
.SYNOPSIS
    Memory Usage Detection

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
    We Enhanced Memory Usage Detection

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
    Memory Usage Detection Script for Microsoft Intune

.DESCRIPTION
    Detects high memory usage conditions on Windows systems.
    This script monitors memory consumption and reports if it exceeds specified thresholds.
    Safe for production use with comprehensive error handling and WhatIf support.

.PARAMETER MaxMemoryUsagePercent
    Maximum allowed memory usage percentage (default: 85)

.PARAMETER WhatIf
    Shows what would be detected without making any changes

.NOTES
    Version: 1.0
    Author: Intune Remediation Scripts
    Creation Date: 2025-08-14
    
    Exit Codes:
    0 = Success (normal memory usage)
    1 = Issue detected (high memory usage)
    2 = Script error
    
.EXAMPLE
    .\memory-usage-detection.ps1
    .\memory-usage-detection.ps1 -MaxMemoryUsagePercent 90 -WhatIf


[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory = $false)]
    [int]$WEMaxMemoryUsagePercent = 85,
    
    [Parameter(Mandatory = $false)]
    [switch]$WEWhatIf
)


$WELogPath = " $env:TEMP\IntuneRemediation_MemoryUsageDetection.log"
$WETimeStamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"

[CmdletBinding()]
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
    Write-LogEntry " Starting memory usage detection script"
    Write-LogEntry " Maximum allowed memory usage: $WEMaxMemoryUsagePercent%"
    
    if ($WEWhatIf) {
        Write-LogEntry " Running in WhatIf mode - no changes will be made" " INFO"
    }
    
    # Get memory information
    $WEMemoryInfo = Get-CimInstance -Class Win32_OperatingSystem
    $WETotalMemoryGB = [math]::Round($WEMemoryInfo.TotalVisibleMemorySize / 1MB, 2)
    $WEFreeMemoryGB = [math]::Round($WEMemoryInfo.FreePhysicalMemory / 1MB, 2)
    $WEUsedMemoryGB = $WETotalMemoryGB - $WEFreeMemoryGB
    $WEMemoryUsagePercent = [math]::Round(($WEUsedMemoryGB / $WETotalMemoryGB) * 100, 2)
    
    Write-LogEntry " Memory Statistics:"
    Write-LogEntry "  Total Memory: $WETotalMemoryGB GB"
    Write-LogEntry "  Used Memory: $WEUsedMemoryGB GB"
    Write-LogEntry "  Free Memory: $WEFreeMemoryGB GB"
    Write-LogEntry "  Memory Usage: $WEMemoryUsagePercent%"
    
    # Check if memory usage exceeds threshold
    if ($WEMemoryUsagePercent -gt $WEMaxMemoryUsagePercent) {
        Write-LogEntry " WARNING: Memory usage ($WEMemoryUsagePercent%) exceeds threshold ($WEMaxMemoryUsagePercent%)" " WARNING"
        
        # Get top memory consuming processes for additional context
       ;  $WETopProcesses = Get-Process -ErrorAction Stop | Sort-Object WorkingSet -Descending | Select-Object -First 5
        Write-LogEntry " Top 5 memory consuming processes:"
        foreach ($WEProcess in $WETopProcesses) {
           ;  $WEProcessMemoryMB = [math]::Round($WEProcess.WorkingSet / 1MB, 2)
            Write-LogEntry "  $($WEProcess.Name): $WEProcessMemoryMB MB"
        }
        
        if ($WEWhatIf) {
            Write-LogEntry " WhatIf: Would report high memory usage for remediation"
            exit 0  # In WhatIf mode, don't trigger remediation
        }
        
        Write-LogEntry " High memory usage detected - remediation required"
        exit 1  # Trigger remediation
    } else {
        Write-LogEntry " Memory usage is within acceptable limits"
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