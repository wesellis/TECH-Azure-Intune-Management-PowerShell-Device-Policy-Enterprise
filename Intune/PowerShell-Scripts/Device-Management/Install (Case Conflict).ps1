<#
.SYNOPSIS
    Install (Case Conflict)

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
    We Enhanced Install (Case Conflict)

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

$allUsers = Get-ChildItem -Path " $($WEENV:SystemDrive)\Users"


function WE-Uninstall-ClassicTeams($teamsPath)
{
    Start-Process -FilePath " $($teamsPath)\Update.exe" -ArgumentList " --uninstall /s" -PassThru -Wait -ErrorAction Stop
}


foreach($user in $allUsers)
{
    # Teams install paths
    $localAppData = " $($WEENV:SystemDrive)\Users\$($user.Name)\AppData\Local\Microsoft\Teams"
    $programData = " $($WEENV:SystemDrive)\$($user.Name)\Microsoft\Teams"

    # Check each install location and remove if found
    if (Test-Path $localAppData) 
    {
        Write-Output " Uninstall Teams classic for user $($user.Name)"
        Uninstall-ClassicTeams -teamsPath $localAppData
    }
    elseif (Test-Path $programData)
    {
        Write-Output " Uninstall Teams classic for user $($user.Name)"
        Uninstall-ClassicTeams -teamsPath $programData
    }
    else
    {
        Write-Output " Classic Teams not installed for user $($user.Name)"
    }
}
; 
$oldFolder = " $($env:SystemDrive)\Users\*\AppData\Local\Microsoft\Teams" ; 
$oldIcon = " $($env:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams*.lnk"

Get-Item $oldFolder | Remove-Item -Recurse -Force
Get-Item $oldIcon | Remove-Item -Recurse -Force

New-Item -Path " C:\ProgramData\Microsoft" -ItemType File -Name " classicTeamsUninstall.txt"


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================