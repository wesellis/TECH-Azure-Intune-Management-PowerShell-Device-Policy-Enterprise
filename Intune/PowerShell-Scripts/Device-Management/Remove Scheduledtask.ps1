<#
.SYNOPSIS
    Remove Scheduledtask

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
    We Enhanced Remove Scheduledtask

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

$WELogFilePath = Join-Path -Path $env:TEMP -ChildPath " ScriptLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"


[CmdletBinding()]
function WE-Write-Log {
    

[CmdletBinding()]
function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
        [ValidateSet(" INFO" , " WARN" , " ERROR" , " SUCCESS" )]
        [string]$Level = " INFO"
    )
    
   ;  $timestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
   ;  $colorMap = @{
        " INFO" = " Cyan" ; " WARN" = " Yellow" ; " ERROR" = " Red" ; " SUCCESS" = " Green"
    }
    
    $logEntry = " $timestamp [WE-Enhanced] [$Level] $Message"
    Write-Information $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEMessage,
        [string]$WEType = " INFO" # Supports INFO, WARNING, ERROR
    )
    $WETimestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
   ;  $WELogMessage = " [$WETimestamp] [$WEType] $WEMessage"
    
    # Write to the console
    switch ($WEType) {
        " ERROR" { Write-Information $WELogMessage -ForegroundColor Red }
        " WARNING" { Write-Information $WELogMessage -ForegroundColor Yellow }
        default { Write-Information $WELogMessage }
    }
    
    # Write to log file
    Add-Content -Path $WELogFilePath -Value $WELogMessage
}

; 
$WETaskName = " Your Task Name"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log " This script must be run as an administrator." -Type " ERROR"
    exit 1
}

Write-Log " Starting removal of scheduled task: $WETaskName"

if (Get-ScheduledTask -TaskName $WETaskName -ErrorAction SilentlyContinue) {
    try {
        Unregister-ScheduledTask -TaskName $WETaskName -Confirm:$false -ErrorAction Stop
        Write-Log " Successfully removed scheduled task: $WETaskName"
    } catch {
        Write-Log " Failed to remove task '$WETaskName': $_" -Type " ERROR"
        exit 1
    }
} else {
    Write-Log " Task '$WETaskName' was not found on this system." -Type " WARNING"
    exit 0
}

Write-Log " Script execution completed."


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================