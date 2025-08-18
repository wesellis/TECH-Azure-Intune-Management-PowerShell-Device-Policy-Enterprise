<#
.SYNOPSIS
    Win11Settingsfix

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
    We Enhanced Win11Settingsfix

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
    [CmdletBinding()
try {
    # Main script execution
]
$ErrorActionPreference = "Stop"
[CmdletBinding()]
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

Copy-Item -Path " $($WEPSScriptRoot)\YOURPIC.jpeg" -Destination " C:\Windows\Web\Wallpaper" -Force
Stop-Process -Name explorer -Force


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

Copy-Item -Path " $($WEPSScriptRoot)\YOURPIC.jpeg" -Destination " C:\Windows\Web\Wallpaper" -Force

New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS

$user = (Get-CimInstance -Class Win32_ComputerSystem | Select-Object Username).Username; 
$sid = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value
; 
$userRegPath = " HKU\$($sid)\SOFTWARE"

reg.exe add " $($userRegPath)\Microsoft\Windows\CurrentVersion\Policies\System" /v " Wallpaper" /t REG_SZ /d " C:\Windows\Web\Wallpaper\rubix.jpeg" /f | Out-Host
reg.exe add " $($userRegPath)\Microsoft\Windows\CurrentVersion\Policies\System" /v " WallpaperStyle" /t REG_DWORD /d 4 /f | Out-Host
reg.exe add " $($userRegPath)\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve /reg:64 | Out-Host
reg.exe add " $($userRegPath)\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v " TaskbarDa" /t REG_DWORD /d 0 /f | Out-Host
reg.exe add " $($userRegPath)\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v " TaskbarAl" /t REG_DWORD /d 0 /f | Out-Host
reg.exe add " $($userRegPath)\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v " ShowTaskViewButton" /t REG_DWORD /d 0 /f | Out-Host

reg.exe add " HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v " SearchOnTaskbarMode" /t REG_DWORD /d 1 /f | Out-Host

New-Item -Path " C:\ProgramData\Microsoft\win11Settings.tag" -ItemType File -Force

Stop-Process -Name explorer -Force



} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
