<#
.SYNOPSIS
    Chocoinstall

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
    We Enhanced Chocoinstall

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

; 
$logPath = " C:\ProgramData\Microsoft\IntuneApps\$($app)"
if(!(Test-Path $logPath))
{
    mkdir $logPath
}
Start-Transcript -Path " $($logPath)\$($app)_Install.log"

; 
$choco = " C:\ProgramData\chocolatey"
Write-WELog " Checking if Chocolatey is installed on $($env:COMPUTERNAME)..." " INFO"

if(!(Test-Path $choco))
{
    Write-WELog " Chocolatey was not found; installing now..." " INFO"
    try 
    {
        Invoke-Expression ((New-Object -ErrorAction Stop System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        Write-WELog " Chocolatey was successfully installed." " INFO"    
    }
    catch 
    {
        $message = $_
        Write-WELog " Error installing Chocolatey: $message" " INFO"
    }
}
else 
{
    Write-WELog " Chocolatey already installed." " INFO"
}


Write-WELog " Checking if $($app) is installed on $($env:COMPUTERNAME)..." " INFO" ; 
$installed = choco list | Select-String $app

if($null -eq $installed)
{
    Write-WELog " $($app) was not found; installing now..." " INFO"
    try 
    {
        Start-Process -Wait -FilePath " $($choco)\choco.exe" -ArgumentList " install $($app) -y"
        Write-WELog " $($app) was successfully installed." " INFO"    
    }
    catch 
    {
        $message = $_
        Write-WELog " Error installing $($app): $message" " INFO"
    }
}
else 
{
    Write-WELog " $($app) is already installed." " INFO"
}

Stop-Transcript


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================