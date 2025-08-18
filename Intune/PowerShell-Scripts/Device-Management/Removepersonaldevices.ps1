<#
.SYNOPSIS
    Removepersonaldevices

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
    We Enhanced Removepersonaldevices

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


function log()



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

function log()
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [string]$message
    )
    $date = Get-Date -Format " yyyy-MM-dd hh:mm:ss tt"
    Write-Output " $date - $message"
}



$nuget = Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction Ignore
if(-not($nuget))
{
    log " NuGet not found, installing..."
    Install-PackageProvider -Name NuGet -Confirm:$false -Force
}
else
{
    log " NuGet already installed."
}


$graphModule = Get-InstalledModule -Name Microsoft.Graph -ErrorAction Ignore
if(-not($graphModule))
{
    log " Microsoft Graph module not found, installing now..."
    Install-Module -Name Microsoft.Graph -Confirm:$false -Force
}
else
{
    log " Microsoft Graph module already installed."
}

<# Authentication method 1 - app reg and client secret

$clientID = " <CLIENT ID>"

$clientSecret = " <CLIENT SECRET>"
$tenantID = " <TENANT ID>"

$WESecureClientSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$WEClientSecureCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientID, $WESecureClientSecret
Connect-MgGraph -ClientSecretCredential $WEClientSecureCredential -TenantId $tenantID



Connect-MgGraph -Scopes " DeviceManagementManagedDevices.ReadWrite.All"

; 
$personalDevices = (Invoke-MgGraphRequest -Method GET -Uri " https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=ownerType eq 'personal'" ).value


foreach($device in $personalDevices)
{
    log " Found personal device $($device.deviceName)."
   ;  $id = $device.id
    try 
    {
        log " Attempting to delete $($device.deviceName) from tenant..."
        Invoke-MgGraphRequest -Method DELETE -Uri " https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($id)"
        log " Device $($device.deviceName) was deleted."        
    }
    catch 
    {
        log " Error trying to remove device $($device.deviceName): $_"
    }
}






# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================