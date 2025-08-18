<#
.SYNOPSIS
    Scheduledtasktemplate

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
    We Enhanced Scheduledtasktemplate

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WETaskXml = @"
<?xml version=" 1.0" encoding=" UTF-16" ?>
<Task version=" 1.2" xmlns=" http://schemas.microsoft.com/windows/2004/02/mit/task" >
  <RegistrationInfo>
    <Date>2024-04-22T13:19:22.5877406</Date>
    <Author>Administrator</Author>
    <URI>\Your Task Name</URI>
  </RegistrationInfo>
  <Triggers>
    <!-- Define triggers here -->
  </Triggers>
  <Principals>
    <!-- Define principals here -->
  </Principals>
  <Settings>
    <!-- Define settings here -->
  </Settings>
  <Actions Context=" Author" >
    <!-- Define actions here -->
  </Actions>
</Task>
" @




$WETaskName = " Your Task Name"

$WELogFilePath = Join-Path -Path $env:TEMP -ChildPath " ScriptLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function WE-Write-Log {
    

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
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEMessage,
        [string]$WEType = " INFO"
    )
   ;  $WETimestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
   ;  $WELogMessage = " [$WETimestamp] [$WEType] $WEMessage"
    
    switch ($WEType) {
        " ERROR" { Write-Host $WELogMessage -ForegroundColor Red }
        " WARNING" { Write-Host $WELogMessage -ForegroundColor Yellow }
        default { Write-Host $WELogMessage }
    }
    
    Add-Content -Path $WELogFilePath -Value $WELogMessage
}

if (Get-ScheduledTask -TaskName $WETaskName -ErrorAction SilentlyContinue) {
    Write-Log " Task '$WETaskName' already exists. Removing it before creating a new one..." " WARNING"
    try {
        Unregister-ScheduledTask -TaskName $WETaskName -Confirm:$false -ErrorAction Stop
        Write-Log " Task '$WETaskName' successfully removed."
    } catch {
        Write-Log " Failed to remove the task '$WETaskName'. Error details: $_" " ERROR"
        exit 1
    }
}

Write-Log " Creating task '$WETaskName'..."
try {
    Register-ScheduledTask -Xml $WETaskXml -TaskName $WETaskName -ErrorAction Stop
    Write-Log " Task '$WETaskName' successfully created."
} catch {
    Write-Log " Failed to create the task '$WETaskName'. Error details: $_" " ERROR"
    exit 1
}

Write-Log " Script execution completed."

# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================