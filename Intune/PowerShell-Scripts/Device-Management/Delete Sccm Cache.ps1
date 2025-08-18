<#
.SYNOPSIS
    Delete Sccm Cache

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
    We Enhanced Delete Sccm Cache

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

$createScheduledTask = $true # <--- create scheduled task to run this script daily
$sccmCachePath = " C:\Windows\ccmcache"


function WE-Remove-SCCMCache {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
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


function WE-Add-ScheduledTask {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WETaskName,
        [Parameter(Mandatory = $true)]
        [string]$WEScriptPath
    )

    # if scheduled task already exists, return
    $taskExists = Get-ScheduledTask | Where-Object { $_.TaskName -eq $WETaskName }
    if ($taskExists) {
        return
    }

    $action = New-ScheduledTaskAction -Execute " powershell.exe" -Argument " -ExecutionPolicy Bypass -File $WEScriptPath"
    $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -At " 10am" -DaysOfWeek Monday
   ;  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $WETaskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -User " SYSTEM"
}

; 
$scriptPath = " C:\Windows\Temp\delete-sccm-cache.ps1"
Copy-Item -Path $WEMyInvocation.MyCommand.Path -Destination $scriptPath -Force


if ($createScheduledTask) {
    Add-ScheduledTask -TaskName " Delete SCCM Cache" -ScriptPath $scriptPath
}


Remove-SCCMCache -SCCMCachePath $sccmCachePath


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================