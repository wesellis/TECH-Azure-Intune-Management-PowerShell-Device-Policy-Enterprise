<#
.SYNOPSIS
    Hybridconnectorfixer

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
    We Enhanced Hybridconnectorfixer

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

$WEWorkingDir = " $env:ProgramData\IntuneConnectorInstall"
$WEWebView2Installer = " $WEWorkingDir\MicrosoftEdgeWebView2Setup.exe"
$WEIntuneConnectorInstaller = " $WEWorkingDir\ODJConnectorBootstrapper.exe"
$WEIntuneConnectorProductName = " Intune Connector for Active Directory"
$WERequiredConnectorVersion = " 6.2505.0"
$WERequiredDotNetRelease = 461808 # 4.7.2


if(-not(Test-Path $WEWorkingDir))
{
    mkdir $WEWorkingDir
}


$WEWebView2Installed = Get-ItemProperty -ErrorAction Stop HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like " *Microsoft Edge WebView2" }

if($WEWebView2Installed)
{
    Write-WELog " Edge WebView2 already installed" " INFO"
}
else
{
    Write-WELog " Downloading and installing WebView2..." " INFO"
    Invoke-WebRequest -Uri " https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $WEWebView2Installer -UseBasicParsing
    Start-Process -FilePath $WEWebView2Installer -ArgumentList " /silent /install" -Wait
}


try 
{
    $dotNetRelease = Get-ItemPropertyValue -Path " HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release -ErrorAction Stop
    if($dotNetRelease -lt $WERequiredDotNetRelease)
    {
        Write-Warning " .NET Framework 4.7.2 or later is required. Detected Release: $dotNetRelase"
        Write-Warning " Please install .NET Framework 4.7.2 before continuing."
        exit 1
    }   
    else
    {   
        Write-WELog " .NET Framework 4.7.2 or later is present." " INFO"
    } 
}
catch 
{
    Write-Warning " Unable to detect .NET Framework. Please ensure 4.7.2 or later is installed."
    exit 1
}



; 
$WEIntuneConnector = Get-ItemProperty -ErrorAction Stop HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like " *$($WEIntuneConnectorProductName)*" } | Sort-Object DisplayVersion -Descending | Select-Object -First 1

if($WEIntuneConnector)
{
    Write-WELog " Found connector: $($WEIntuneConnector.DisplayName) v$($WEIntuneConnector.DisplayVersion)" " INFO"
    Write-WELog " Uninstalling existing version..." " INFO"

    if($WEIntuneConnector.UninstallString)
    {
       ;  $uninstallCmd = $WEIntuneConnector.UninstallString -replace '" ',''
        if($uninstallCmd -like " msiexec*" )
        {
            Start-Process " msiexec.exe" -ArgumentList " /x" , " $($WEIntuneConnector.PSChildName)" , " /quiet" , " /norestart" -Wait
        }
        else
        {
            Start-Process -FilePath " cmd.exe" -ArgumentList " /c" , " $uninstallCmd /quiet /norestart" -Wait
        }
    }
}
else
{   
    Write-WELog " Connector not installed." " INFO"
}


if(-not(Test-Path $WEIntuneConnectorInstaller))
{
    Write-WELog " Downloading updated connector..." " INFO"
    Invoke-WebRequest -Uri " https://download.microsoft.com/download/45476bf5-d8be-43a7-8e44-e76a4d1ab28f/ODJConnectorBootstrapper.exe" -OutFIle $WEIntuneConnectorInstaller -UseBasicParsing
}

Write-WELog " Installing Intune Connector..." " INFO"
Start-Process -FilePath $WEIntuneConnectorInstaller -Wait



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================