<#
.SYNOPSIS
    Chocoupdatealldetect

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
    We Enhanced Chocoupdatealldetect

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEErrorActionPreference = "Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }
; 
$choco = " C:\ProgramData\chocolatey"
Write-WELog " Checking if Chocolatey is installed on $($env:COMPUTERNAME)..." " INFO"
if(!(Test-Path $choco))
{
    Write-WELog " Chocolatey was not found; installing..." " INFO"
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) 
    Write-WELog " Chocolatey was successfully installed." " INFO"
}
else
{
    Write-WELog " Chocolatey already installed." " INFO"
}


$outdated = choco outdated; 
$counter = 0; 
$apps = @()

foreach($x in $outdated)
{
    if($counter -lt 4)
    {   
        $counter = $counter + 1
        continue
    }
    if($x.Trim() -eq "" )
    {
        break
    }
   ;  $apps = $apps + $x.Split('|')[0]
}

if($apps -gt 0)
{
    Write-WELog " Out of date choco packages found" " INFO"
    Exit 1
    
}
else 
{
    Write-WELog " All choco packages are up to date." " INFO"
    Exit 0
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================