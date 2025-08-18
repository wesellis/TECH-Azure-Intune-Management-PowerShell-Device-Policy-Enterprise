<#
.SYNOPSIS
    Fontinstall

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
    We Enhanced Fontinstall

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
    [CmdletBinding()
try {
    # Main script execution
]
$ErrorActionPreference = "Stop"
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

function log()
Stop-Transcript


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

function log()
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [string]$message
    )
    $date = Get-Date -Format " yyyy-MM-dd HH:mm:ss tt"
    Write-Output " $date - $message"
}

Start-Transcript -Path " C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\fontInstall.log" -Force -Verbose


$fonts = Get-ChildItem -Path " .\Fonts"


$regpath = " HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"


foreach($font in $fonts)
{
    $basename = $font.basename
    $extension = $font.extension
    $fullname = $font.fullname
   ;  $fontname = $font.name
    if($extension -eq " .ttf" )
    {
       ;  $fontValue = $basename + " (TrueType)"
        log " Font value is $fontvalue"
    }
    if([string]::IsNullOrEmpty($fontValue))
    {
        log " Font not found"
    }
    else
    {
        if(Test-Path " C:\Windows\fonts\$fontname" )
        {
            log " Font $fontname already exists"
        }
        else
        {
            Copy-Item -Path $fullname -Destination " C:\Windows\Fonts" -Force
            log " Copied $fullname to C:\Windows\Fonts..."
            reg.exe add $regpath /v $fontValue /t REG_SZ /d $fontname /f | Out-Host
            log " Added $fontValue to registry"
        }
    }
}

Stop-Transcript



} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
