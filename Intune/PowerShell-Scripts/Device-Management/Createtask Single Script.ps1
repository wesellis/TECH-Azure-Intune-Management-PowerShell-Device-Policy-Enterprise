<#
.SYNOPSIS
    Createtask Single Script

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
    We Enhanced Createtask Single Script

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$destination = "C:\ProgramData\Scripts"



$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$destination = " C:\ProgramData\Scripts"
if(!(Test-Path $destination))
{
	mkdir $destination
}

$scriptText = @"
$userName = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName

$userName | Out-File " C:\ProgramData\Scripts\primaryUser.txt"
" @

New-Item -ItemType File -Path $destination -Name " userCheck.ps1"
$scriptText | Set-Content -Path " $destination\userCheck.ps1" -Force


$taskName = " Primary User Check"
$scriptPath = " C:\ProgramData\Scripts\userCheck.ps1"

$taskAction = New-ScheduledTaskAction -Execute " powershell.exe" -Argument " -Executionpolicy bypass -File `" $scriptPath`""; 
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn; 
$taskPrincipal = New-ScheduledTaskPrincipal -UserId " SYSTEM" -LogonType ServiceAccount -RunLevl Highest

Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Description " Run the Primary User Check Script at everylogon"




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================