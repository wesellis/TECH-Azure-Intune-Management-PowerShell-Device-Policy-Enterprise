<#
.SYNOPSIS
    Bulkgrouptagupdate

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
    We Enhanced Bulkgrouptagupdate

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

$nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction Ignore
if(-not($nuget))
{
    Install-PackageProvider -Name NuGet -confirm:$false -Force
    Write-WELog " Installed NuGet" " INFO"
}
else
{
    Write-WELog " NuGet already installed" " INFO"
}

$module = Get-Module -ListAvailable -Name WindowsAutopilotIntune -ErrorAction Ignore
if(-not($module))
{
    Install-Module -Name WindowsAutopilotIntune -confirm:$false -Force
    Write-WELog " Installed WindowsAutopilotIntune" " INFO"
}
else
{
    Write-WELog " WindowsAutopilotIntune already installed" " INFO"
}



Connect-MgGraph






$serialNumbers = Import-Csv -Path " C:\path\to\serialNumbers.csv" | Select-Object -ExpandProperty SerialNumber


foreach ($serialNumber in $serialNumbers) {
    try 
    {
        $id = (Get-AutopilotDevice -serial $serialNumber).id
        Set-AutopilotDevice -id $id -GroupTag " NewGroupTag"
        Write-WELog " Changed group tag for device with serial number $serialNumber" " INFO"        
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-WELog " Failed to change group tag for device with serial number $($serialNumber): $message" " INFO"
    }

}


$oldGroupTag = " OldGroupTag"

; 
$devices = Get-AutopilotDevice -GroupTag $oldGroupTag
foreach($device in $devices)
{
    try 
    {
        Set-AutopilotDevice -id $device.id -GroupTag " NewGroupTag"
        Write-WELog " Changed group tag for device with serial number $($device.serialNumber)" " INFO"        
    }
    catch 
    {
       ;  $message = $_.Exception.Message
        Write-WELog " Failed to change group tag for device with serial number $($device.serialNumber): $message" " INFO"
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================