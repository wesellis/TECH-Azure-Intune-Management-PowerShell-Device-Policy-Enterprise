<#
.SYNOPSIS
    Install Winget

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
    We Enhanced Install Winget

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

$wingetUrl = " https://github.com/microsoft/winget-cli/releases/download/v1.7.3172-preview/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
$version = " 1.22.3172.0" # <-- can be retrieved from Get-AppxPackage -ErrorAction Stop cmdlet: Get-AppxPackage -ErrorAction Stop | Where-Object {$_.Name -eq " Microsoft.DesktopAppInstaller" }



$vclibsx64URL = " https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
$uixamlURL = " https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.0"



[CmdletBinding()]
function WE-Get-CurrentVersion -ErrorAction Stop {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)]
        [string]$WEPackageName
    )

    try {
        $currentVersion = (Get-AppxPackage -ErrorAction Stop | Where-Object { $_.Name -eq $WEPackageName }).Version
        return $currentVersion
    }
    catch {
        Write-WELog " Error: $_" " INFO"
        exit 1
    }
}

[CmdletBinding()]
function WE-Install-Winget {
    [CmdletBinding()]; 
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEWingetUrl,
        [Parameter(Mandatory = $true)]
        [string]$WEVersion
    )

    try {
        # download winget
       ;  $wingetInstaller = " $env:TEMP\winget.msixbundle"
        Invoke-WebRequest -Uri $WEWingetUrl -OutFile $wingetInstaller

        # install winget; testing with dism instead with region switch to see if it prevents winget from uninstalling itself post-image
        
        Dism.exe /Online /Add-ProvisionedAppxPackage /PackagePath:$wingetInstaller /SkipLicense /Region:" All" /LogPath:" $env:TEMP\winget.log"

        # verify winget version
        Start-Sleep -Seconds 5
        $wingetVersion = (Get-AppxPackage -ErrorAction Stop | Where-Object { $_.Name -eq " Microsoft.DesktopAppInstaller" }).Version
        if ($wingetVersion -eq $WEVersion) {
            Write-WELog " Winget version $wingetVersion installed successfully" " INFO"
        }
        else {
            Write-WELog " Error: Winget version $wingetVersion installed, but $WEVersion was expected" " INFO"
            exit 1
        }
    }
    catch {
        Write-WELog " Error: $_" " INFO"
        exit 1
    
    }
}

; 
$currentVersion = Get-CurrentVersion -PackageName " Microsoft.DesktopAppInstaller"
if ($currentVersion -ne $version) {
    Write-WELog " Winget version $currentVersion installed, remediation required" " INFO"
    Install-Winget -WingetUrl $wingetUrl -Version $version
    exit 0
}
else {
    Write-WELog " Winget version $currentVersion installed, remediation not required" " INFO"
    exit 1
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================