<#
.SYNOPSIS
    Choco

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
    We Enhanced Choco

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
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$app,
    [Parameter(Mandatory=$WEFalse,Position=2)]
    [switch]$uninstall = $WEFalse
)

; 
$logPath = " C:\ProgramData\Microsoft\IntuneApps\$($app)"
if(!(Test-Path $logPath))
{
    mkdir $logPath
}
Start-Transcript -Path " $($logPath)\$($app)_Install.log" -Verbose

; 
$choco = " C:\ProgramData\chocolatey"
Write-WELog " Checking if Chocolatey is installed on $($env:COMPUTERNAME)..." " INFO"
if(!(Test-Path $choco))
{
    Write-WELog " Chocolatey not found; installing now..." " INFO"
    try 
    {
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
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
    Write-WELog " Chocolatey is installed." " INFO"
}
; 
$installed = Start-Process -Wait -FilePath " $($choco)\choco.exe" -ArgumentList " list" | Select-String $app; 
$installFlag = " $($logPath)\$($app)_installed.txt"


if($uninstall -eq $WEFalse)
{
    Write-WELog " Running choco-install" " INFO"

    Write-WELog " Checking if $($app) is installed on $($env:COMPUTERNAME)..." " INFO"
    if($installed -eq $null)
    {
        Write-WELog " $($app) not detected; installing now..." " INFO"
        Start-Process -Wait -FilePath " $($choco)\choco.exe" -ArgumentList " install $($app) -y"
        if($WELASTEXITCODE -ne 0)
        {
            $message = $_
            Write-WELog " Error installing $($app): $message" " INFO"
            exit 1
        }
        else 
        {
            Write-WELog " $($app) installed successfully" " INFO"
           ;  $installFlag = " $($logPath)\$($app)_installed.txt"
            New-Item $installFlag -Force
        }
    }
    else
    {
        Write-WELog " $($app) already installed.  Updating to latest version..." " INFO"
        Start-Process -Wait -FilePath " $($choco)\choco.exe" -ArgumentList " upgrade $($app) -y"
        if($WELASTEXITCODE -ne 0)
        {
           ;  $message = $_
            Write-WELog " Error installing $($app): $message" " INFO"
            exit 1
        }
        else 
        {
            Write-WELog " $($app) updated successfully" " INFO"
            New-Item $installFlag -Force
        }
    }
}
else 
{
    Write-WELog " Running choco-uninstall" " INFO"
    if($installed -ne $null)
    {
        Write-WELog " $($app) detected; uninstalling now..." " INFO"
        Start-Process -Wait -FilePath " $($choco)\choco.exe" -ArgumentList " uninstall $($app) -y"
        if($WELASTEXITCODE -ne 0)
        {
            $message = $_
            Write-WELog " Error uninstalling $($app): $message" " INFO"
            exit 1
        }
        else 
        {
            Write-WELog " $($app) successfully uninstalled" " INFO"
            Remove-Item $installFl -Forcea -Forceg -Force
        }
    }
    else 
    {
       Write-WELog " $($app) not detected" " INFO"
    }
}

Stop-Transcript



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================