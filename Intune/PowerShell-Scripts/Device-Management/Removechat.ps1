<#
.SYNOPSIS
    Removechat

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
    We Enhanced Removechat

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-executionpolicy bypass -command "reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f | Out-Host" '



$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$WEAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-executionpolicy bypass -command " reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f | Out-Host" '

$WEPrincipal = New-ScheduledTaskPrincipal -GroupId " BUILTIN\Administrators" #Warning: the admin Group name is localised

Register-ScheduledTask -TaskName 'uninstallChat' -Action $action -Principal $WEPrincipal

$svc = New-Object -ComObject 'Schedule.Service'
$svc.Connect()

$user = 'NT SERVICE\TrustedInstaller'; 
$folder = $svc.GetFolder('\'); 
$task = $folder.GetTask('uninstallChat')


$task.RunEx($null, 0, 0, $user)

Start-Sleep -Seconds 5


$task.Stop(0)


Unregister-ScheduledTask -TaskName 'uninstallChat' -Confirm:$false



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================