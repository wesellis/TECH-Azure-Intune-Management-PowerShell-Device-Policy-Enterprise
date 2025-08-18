<#
.SYNOPSIS
    Uninstallclassicteams

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
    We Enhanced Uninstallclassicteams

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


function WE-Uninstall-TeamsClassic($teamsPath)



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

function WE-Uninstall-TeamsClassic($teamsPath)
{
    try
    {
        $process = Start-Process -FilePath " $($teamsPath)\Update.exe" -ArgumentList " --uninstall /s" -PassThru -Wait -ErrorAction Stop
        if($process.ExitCode -ne 0)
        {
            $message = $_.Exception.Message
            Write-WELog " Error uninstalling Classic Teams Client: $message" " INFO"
        }
    }
    catch
    {
        $message = $_.Exception.Message
    }
}


$registryPath = " HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

$WEMachineWide = Get-ItemProperty -Path $registryPath | Where-Object {$_.DisplayName -eq " Teams Machine-Wide Installer" }

if($WEMachineWide)
{
    Start-Process -FilePath " msiexec.exe" -ArgumentList " /x "" $($WEMachineWide.PSChildName)"" /qn" -NoNewWindow -Wait
}
else
{
    Write-WELog " Teams Classic (Machine-Wide installer) not found" " INFO"
}

$WEAllUsers = Get-ChildItem -Path " $($WEENV:SystemDrive)\Users"

foreach($user in $WEAllUsers)
{
    Write-WELog " Processing user: $($user.Name)" " INFO"
    $localAppData = " $($WEENV:SystemDrive)\Users\$($user.name)\AppData\Local\Microsoft\Teams"
    $programData = " $($WEENV:ProgramData)\$($WEUser.Name)\Microsoft\Teams"

    if(Test-Path " $localAppdata\Current\Teams.exe" )
    {
        Write-WELog " Uninstall Teams for user $($user.Name)" " INFO"
        Uninstall-TeamsClassic -teamsPath $localAppData
    }
    elseif(Test-Path " $programData\Current\Teams.exe" )
    {
        Write-WELog " Uninstall Teams for user $($user.Name)" " INFO"
        Uninstall-TeamsClassic -teamsPath $programData
    }
    else
    {
        Write-WELog " Teams classic not found for user $($user.Name)" " INFO"
    }
}
; 
$WETeamsFolder_old = " $($WEENV:SystemDrive)\Users\*\AppData\Local\Microsoft\Teams" ; 
$WETeamsIcon_old = " $($WEENV:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams*.lnk"
Get-Item -ErrorAction Stop $WETeamsFolder_old | Remove-Item -Force -Recurse
Get-Item -ErrorAction Stop $WETeamsIcon_old | Remove-Item -Force Recurse




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================