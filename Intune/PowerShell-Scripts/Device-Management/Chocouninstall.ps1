<#
.SYNOPSIS
    Chocouninstall

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
    We Enhanced Chocouninstall

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

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$WETrue,Position=1)]
    [string]$app
)

<# Check for 64 bit powershell
if(" $env:PROCESSOR_ARCHITEW6432" -ne " ARM64" )
{
    if(Test-Path " $($env:windir)\SysNative\WindowsPowerShell\v1.0\powershell.exe" )
    {
        & " $($env:windir)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File " $WEPSCommandPath"
        exit $WELASTEXITCODE
    }
}#>


$logPath = " C:\ProgramData\Microsoft\IntuneApps\$($app)"
if(!(Test-Path $logPath))
{
    mkdir $logPath
}
Start-Transcript -Path " $($logPath)\$($app)_Uninstall.log"
; 
$choco = " C:\ProgramData\chocolatey"


Write-WELog " Checking if $($app) is installed on $($env:COMPUTERNAME)..." " INFO" ; 
$installed = choco list | Select-String $app

if($installed -ne $null)
{
    Write-WELog " $($app) is installed; uninstalling now..." " INFO"
    try 
    {
        Start-Process -Wait -FilePath " $($choco)\choco.exe" -ArgumentList " uninstall $($app) -y"
        Write-WELog " $($app) was successfully uninstalled." " INFO"    
    }
    catch 
    {
        $message = $_
        Write-WELog " Error uninstalling $($app): $message" " INFO"
    }
}
else
{
    Write-WELog " $($app) is no longer detected." " INFO"
}

Stop-Transcript


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================