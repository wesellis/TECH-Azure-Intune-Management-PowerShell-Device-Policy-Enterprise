<#
.SYNOPSIS
    Disable Faststartup

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
    We Enhanced Disable Faststartup

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


$WEErrorActionPreference = "Stop" ; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
Disables Fast Startup by setting the HiberbootEnabled registry value to 0.

.DESCRIPTION
This script modifies the Windows registry to disable the Fast Startup feature. 
Fast Startup can cause issues with dual boot setups, network configurations, or certain hardware. 
By setting the HiberbootEnabled value to 0, the system ensures that Fast Startup is turned off.

.PARAMETERS
None

.PREREQUISITES
- The script must be run in the system context or as an administrator.

.NOTES
- Modifies the registry; ensure you back up the registry before running this script.
- Disabling Fast Startup may slightly increase boot time but improves compatibility with some system configurations.

.EXAMPLE
.\Disable-FastStartup.ps1
Runs the script to disable Fast Startup.

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
        [string]$WEType = " INFO" # Supports INFO, WARNING, ERROR
    )
    $WETimestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
    $WELogMessage = " [$WETimestamp] [$WEType] $WEMessage"
    
    # Write to the console
    switch ($WEType) {
        " ERROR" { Write-Host $WELogMessage -ForegroundColor Red }
        " WARNING" { Write-Host $WELogMessage -ForegroundColor Yellow }
        default { Write-Host $WELogMessage }
    }
    
    # Write to log file
    Add-Content -Path $WELogFilePath -Value $WELogMessage
}
; 
$WERegistryPath = " HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" ; 
$WEValueName = " HiberbootEnabled"

if (Test-Path $WERegistryPath) {
    try {
        # Set the registry value
        Set-ItemProperty -Path $WERegistryPath -Name $WEValueName -Value 0 -Force
        Write-Log " Successfully set $WEValueName to 0 at $WERegistryPath."
    } catch {
        Write-Log " Error: Unable to set $WEValueName. $_"
    }
} else {
    Write-Log " Error: Registry path $WERegistryPath does not exist."
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================