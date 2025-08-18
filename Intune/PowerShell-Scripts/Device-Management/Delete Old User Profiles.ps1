<#
.SYNOPSIS
    Delete Old User Profiles

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
    We Enhanced Delete Old User Profiles

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

$days = 30 # <--- maximum age of user profile in days
$excludedUsers = @(" Administrator" , " Public" , " Default" , " coy-it" )
$createScheduledTask = $true # <--- create scheduled task to run this script daily


function WE-Get-OldProfiles {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
        [Parameter(Mandatory = $true)]
        [int]$WEDays,
        [Parameter(Mandatory = $true)]
        [string[]]$WEExcludedUsers
    )

    try {
        $oldProfiles = Get-ChildItem -Path " C:\Users" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$WEDays) -and $WEExcludedUsers -notcontains $_.Name }
        return $oldProfiles
    }
    catch {
        Write-WELog " Error: $_" " INFO"
        exit 1
    }
}

function WE-Remove-OldProfiles {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)]
        [string[]]$WEOldProfiles
    )

    foreach ($profile in $WEOldProfiles) {
        try {
            $fullProfileName = " C:\Users\$($profile)"
            Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -eq $fullProfileName } | Remove-CimInstance
        }
        catch {
            Write-WELog " Error: $_" " INFO"
            exit 1
        }
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
        Write-WELog " Scheduled task $WETaskName already exists" " INFO"
        return
    } 

    # create scheduled task
    # run with highest privileges, run whether user is logged on or not, do not store password, run daily at 12:00pm
    $action = New-ScheduledTaskAction -Execute " PowerShell.exe" -Argument " -ExecutionPolicy Bypass -File $WEScriptPath"
    $trigger = New-ScheduledTaskTrigger -Daily -At " 12:00pm"
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd
    $principal = New-ScheduledTaskPrincipal -UserId " SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $WETaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal
}

; 
$scriptPath = " C:\Windows\Temp\delete-old-user-profiles.ps1"
Copy-Item -Path $WEMyInvocation.MyCommand.Path -Destination $scriptPath -Force


if ($createScheduledTask) {
    Add-ScheduledTask -TaskName " Delete Old User Profiles" -ScriptPath $scriptPath
}

; 
$oldProfiles = Get-OldProfiles -Days $days -ExcludedUsers $excludedUsers


if ($oldProfiles.Count -eq 0) {
    Write-WELog " No old profiles found" " INFO"
    exit 0
}


Remove-OldProfiles -OldProfiles $oldProfiles


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================