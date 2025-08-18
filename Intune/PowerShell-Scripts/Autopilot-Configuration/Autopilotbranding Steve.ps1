<#
.SYNOPSIS
    Autopilotbranding Steve

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
    We Enhanced Autopilotbranding Steve

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


[CmdletBinding()]
function WE-Test-RequiredPath {
    param([Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath)
    if (!(Test-Path $WEPath)) {
        Write-Warning "Required path not found: $WEPath"
        return $false
    }
    return $true
}

function WE-Log() {



$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

function WE-Log() {
	[CmdletBinding()]
$ErrorActionPreference = " Stop"
	param(
		[Parameter(Mandatory=$false)] [String] $message
	)

	$ts = get-date -f " yyyy/MM/dd hh:mm:ss tt"
	Write-Output " $ts $message"
}


if (" $env:PROCESSOR_ARCHITEW6432" -ne " ARM64" )
{
    if (Test-Path " $($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" )
    {
        & " $($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File " $WEPSCommandPath"
        Exit $lastexitcode
    }
}


if (-not (Test-Path " $($env:ProgramData)\Microsoft\AutopilotBranding" ))
{
    Mkdir " $($env:ProgramData)\Microsoft\AutopilotBranding"
}
Set-Content -Path " $($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value " Installed"


Start-Transcript " $($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.log"


$installFolder = " $WEPSScriptRoot\"
Log " Install folder: $installFolder"
Log " Loading configuration: $($installFolder)Config.xml"
[Xml]$config = Get-Content -ErrorAction Stop " $($installFolder)Config.xml"


$ci = Get-ComputerInfo -ErrorAction Stop
if ($ci.OsBuildNumber -le 22000) {
	Log " Importing layout: $($installFolder)Layout.xml"
	Copy-Item " $($installFolder)Layout.xml" " C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Force
} else {
	Log " Importing layout: $($installFolder)Start2.bin"
	MkDir -Path " C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item " $($installFolder)Start2.bin" " C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start2.bin" -Force
}


Log " Setting up Autopilot theme"
Mkdir " C:\Windows\Resources\OEM Themes" -Force | Out-Null
Copy-Item " $installFolder\Autopilot.theme" " C:\Windows\Resources\OEM Themes\Autopilot.theme" -Force
Mkdir " C:\Windows\web\wallpaper\Autopilot" -Force | Out-Null
Copy-Item " $installFolder\Autopilot.png" " C:\Windows\web\wallpaper\Autopilot\Autopilot.png" -Force
Log " Setting Autopilot theme as the new user default"
reg.exe load HKLM\TempUser " C:\Users\Default\NTUSER.DAT" | Out-Host
reg.exe add " HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v InstallTheme /t REG_EXPAND_SZ /d " %SystemRoot%\resources\OEM Themes\Autopilot.theme" /f | Out-Host
reg.exe unload HKLM\TempUser | Out-Host


if ($config.Config.TimeZone) {
	Log " Setting time zone: $($config.Config.TimeZone)"
	Set-Timezone -Id $config.Config.TimeZone
}
else {
	# Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
	Set-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name " Value" -Type " String" -Value " Allow" -Force
	Set-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name " SensorPermissionState" -Type " DWord" -Value 1 -Force
	Start-Service -Name " lfsvc" -ErrorAction SilentlyContinue
}


Log " Removing specified in-box provisioned apps"
$apps = Get-AppxProvisionedPackage -online
$config.Config.RemoveApps.App | % {
	$current = $_
	$apps | ? {$_.DisplayName -eq $current} | % {
		try {
			Log " Removing provisioned app: $current"
			$_ | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
		} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    throw
}
	}
}


if ($config.Config.OneDriveSetup) {
	Log " Downloading OneDriveSetup"
	$dest = " $($env:TEMP)\OneDriveSetup.exe"
	$client = new-object -ErrorAction Stop System.Net.WebClient
	$client.DownloadFile($config.Config.OneDriveSetup, $dest)
	Log " Installing: $dest"
	$proc = Start-Process $dest -ArgumentList " /allusers" -WindowStyle Hidden -PassThru
	$proc.WaitForexit $1
	Log " OneDriveSetup exit code: $($proc.ExitCode)"
}


Log " Turning off (old) Edge desktop shortcut"
reg.exe add " HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v DisableEdgeDesktopShortcutCreation /t REG_DWORD /d 1 /f /reg:64 | Out-Host

<# STEP 7: Add language packs
Get-ChildItem -ErrorAction Stop " $($installFolder)LPs" -Filter *.cab | % {
	Log " Adding language pack: $($_.FullName)"
	Add-WindowsPackage -Online -NoRestart -PackagePath $_.FullName
}


if ($config.Config.Language) {
	Log " Configuring language using: $($config.Config.Language)"
	& $env:SystemRoot\System32\control.exe " intl.cpl,,/f:`" $($installFolder)$($config.Config.Language)`""
}#>

; 
$currentWU = (Get-ItemProperty -Path " HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Ignore).UseWuServer
if ($currentWU -eq 1)
{
	Log " Turning off WSUS"
	Set-ItemProperty -Path " HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name " UseWuServer" -Value 0
	Restart-Service wuauserv
}
if ($config.Config.AddFeatures.Feature.Count -gt 0)
{
	$config.Config.AddFeatures.Feature | % {
		Log " Adding Windows feature: $_"
		Add-WindowsCapability -Online -Name $_ -ErrorAction SilentlyContinue | Out-Null
	}
}
if ($currentWU -eq 1)
{
	Log " Turning on WSUS"
	Set-ItemProperty -Path " HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name " UseWuServer" -Value 1
	Restart-Service wuauserv
}

<# STEP 10: Customize default apps
if ($config.Config.DefaultApps) {
	Log " Setting default apps: $($config.Config.DefaultApps)"
	& Dism.exe /Online /Import-DefaultAppAssociations:`" $($installFolder)$($config.Config.DefaultApps)`"
}


Log " Configuring registered user information"
reg.exe add " HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d " $($config.Config.RegisteredOwner)" /f /reg:64 | Out-Host
reg.exe add " HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d " $($config.Config.RegisteredOrganization)" /f /reg:64 | Out-Host


if ($config.Config.OEMInfo)
{
	Log " Configuring OEM branding info"

	reg.exe add " HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /t REG_SZ /d " $($config.Config.OEMInfo.Manufacturer)" /f /reg:64 | Out-Host
	reg.exe add " HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /t REG_SZ /d " $($config.Config.OEMInfo.Model)" /f /reg:64 | Out-Host
	reg.exe add " HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /t REG_SZ /d " $($config.Config.OEMInfo.SupportPhone)" /f /reg:64 | Out-Host
	reg.exe add " HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /t REG_SZ /d " $($config.Config.OEMInfo.SupportHours)" /f /reg:64 | Out-Host
	reg.exe add " HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /t REG_SZ /d " $($config.Config.OEMInfo.SupportURL)" /f /reg:64 | Out-Host
	Copy-Item " $installFolder\$($config.Config.OEMInfo.Logo)" " C:\Windows\$($config.Config.OEMInfo.Logo)" -Force
	reg.exe add " HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d " C:\Windows\$($config.Config.OEMInfo.Logo)" /f /reg:64 | Out-Host
}


Log " Enabling UE-V"
Enable-UEV
Set-UevConfiguration -Computer -SettingsStoragePath " %OneDriveCommercial%\UEV" -SyncMethod External -DisableWaitForSyncOnLogon
Get-ChildItem -ErrorAction Stop " $($installFolder)UEV" -Filter *.xml | % {
	Log " Registering template: $($_.FullName)"
	Register-UevTemplate -Path $_.FullName
}#>


Log " Turning off network location fly-out"
reg.exe add " HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f


Log " Turning off Edge desktop icon"
reg.exe add " HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v " CreateDesktopShortcutDefault" /t REG_DWORD /d 0 /f /reg:64 | Out-Host



reg.exe load HKLM\TempUser " C:\Users\Default\NTUSER.DAT" | Out-Host
reg.exe add " HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f | Out-Host
reg.exe add " HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V AutoCheckSelect /T REG_DWORD /D 0 /F | Out-Host
reg.exe add " HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarAl /T REG_DWORD /D 0 /F | Out-Host
reg.exe add " HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f | Out-Host
reg.exe unload HKLM\TempUser | Out-Host

reg.exe add " HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f /reg:64 | Out-Host

reg.exe add " HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v SearchOnTaskbarMode /t REG_DWORD /d 1 /f | Out-Host


<# installs chocolatey
Invoke-Expression ((New-Object -ErrorAction Stop System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))


; 
$chocoApps = @(
    " notepadplusplus.install" ,
    " googlechrome" ,
    " 7zip.install" ,
    " vscode" ,
    " firefox" ,
    " slack" ,
    " vlc" ,
	" microsoftazurestorageexplorer"
)

foreach ($app in $chocoApps){
    choco install $app -y
}#>

Stop-Transcript





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================