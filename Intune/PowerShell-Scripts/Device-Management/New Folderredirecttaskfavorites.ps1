<#
.SYNOPSIS
    New Folderredirecttaskfavorites

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
    We Enhanced New Folderredirecttaskfavorites

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
    .SYNOPSIS
        Creates a scheduled task to enable folder redirection at user login.
        Enable folder redirection on Windows 10 Azure AD joined PCs.
        Downloads the folder redirection script from a URL locally and creates the schedule task.



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter()] $WEUrl = " https://raw.githubusercontent.com/aaronparker/intune/main/Folder-Redirection/Redirect-Folders-Favorites.ps1" ,
    [Parameter()] $WEScript = " Redirect-Folders.ps1" ,
    [Parameter()] $WEScriptVb = " Redirect-Folders.vbs" ,
    [Parameter()] $WETaskName = " Folder Redirection" ,
    [Parameter()] $WEGroup = " S-1-5-32-545" ,
    [Parameter()] $WEExecute = " wscript.exe" ,
    [Parameter()] $WETarget = " $env:ProgramData\Intune-Scripts" ,
    [Parameter()] $WEArguments = " $WETarget\$WEScriptVb /b /nologo"
)


$WEVerbosePreference = " Continue"
$stampDate = Get-Date -ErrorAction Stop
$WELogFile = " $env:ProgramData\IntuneScriptLogs\New-FolderRedirectTask-" + $stampDate.ToFileTimeUtc() + " .log"
Start-Transcript -Path $WELogFile


$module = " $env:SystemRoot\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.LocalAccounts\1.0.0.0\Microsoft.Powershell.LocalAccounts.dll"
try {
    Import-Module $module -Force -ErrorAction SilentlyContinue
    $userGroup = (Get-LocalGroup -SID $WEGroup).Name
}
catch {
    Write-Output " Unable to import module Microsoft.PowerShell.LocalAccounts, default group to 'Users'."
}
finally {
    If ($WENull -eq $userGroup) { $userGroup = " Users" }
}


$vbScript = 'Set objShell=CreateObject(" WScript.Shell" )' + " `r`n"
$vbScript = $vbScript + 'Set objFSO=CreateObject(" Scripting.FileSystemObject" )' + " `r`n"
$vbScript = $vbScript + 'strCMD = " powershell -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File ' + " $WETarget\$WEScript" + '" ' + " `r`n"
$vbScript = $vbScript + 'objShell.Run strCMD,0'


If (!(Test-Path -Path $WETarget)) {
    Write-Verbose " Creating $WETarget."
    New-Item -Path $WETarget -Type Directory -Force
}


If (Test-Path " $WETarget\$WEScript" ) {
    Write-Verbose " Removing $WETarget\$WEScript."
    Remove-Item -Path " $WETarget\$WEScript" -Force
}

Write-Verbose " Downloading $WEUrl to $WETarget\$WEScript."
Start-BitsTransfer -Source $WEUrl -Destination " $WETarget\$WEScript" -Priority Foreground -TransferPolicy Always -ErrorAction SilentlyContinue -ErrorVariable $WETransferError
If (Test-Path -Path " $WETarget\$WEScript" ) { Write-Verbose " $WETarget\$WEScript downloaded successfully." }

$vbScript | Out-File -FilePath " $WETarget\$WEScriptVb" -Force -Encoding ascii


If ($WETask = Get-ScheduledTask -TaskName $WETaskName -ErrorAction SilentlyContinue ) {

    Write-Verbose " Folder redirection task exists."
    # If the task Action differs from what we have above, update the values and save the task
    If (!( ($WETask.Actions[0].Execute -eq $WEExecute) -and ($WETask.Actions[0].Arguments -eq $WEArguments) )) {
        Write-Verbose " Updating scheduled task."
        $WETask.Actions[0].Execute = $WEExecute
        $WETask.Actions[0].Arguments = $WEArguments
        $WETask | Set-ScheduledTask -Verbose
    }
    Else {
        Write-Verbose " Existing task action is OK, no change required."
    }
}
Else {
    Write-Verbose " Creating folder redirection scheduled task."
    # Build a new task object
    $action = New-ScheduledTaskAction -Execute $WEExecute -Argument $WEArguments
    $trigger = New-ScheduledTaskTrigger -AtLogon -RandomDelay (New-TimeSpan -Minutes 1)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden -DontStopIfGoingOnBatteries -Compatibility Win8
   ;  $principal = New-ScheduledTaskPrincipal -GroupId $userGroup
   ;  $newTask = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal

    # No task object exists, so register the new task
    Write-Verbose " Registering new task $WETaskName."
    Register-ScheduledTask -InputObject $newTask -TaskName $WETaskName -Verbose
}

Stop-Transcript



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================