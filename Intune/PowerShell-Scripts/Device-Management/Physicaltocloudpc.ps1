<#
.SYNOPSIS
    Physicaltocloudpc

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
    We Enhanced Physicaltocloudpc

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

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Intune)) {
    Install-Module Microsoft.Graph.Intune -Force -Scope CurrentUser
}


$deviceEndpoint = " https://graph.microsoft.com/beta/deviceManagement/managedDevices"


Connect-MgGraph -Scopes " Device.Read.All" , " User.Read.All"
; 
$devices = Invoke-MgGraphRequest -Method Get -Uri " $($deviceEndpoint)?`$filter=operatingSystem eq 'Windows'"

; 
$skuMapping = @{
    " 2vCPU-4GB-64GB"  = @{  RAM = 4; Storage = 64 }
    " 2vCPU-8GB-128GB" = @{  RAM = 8; Storage = 128 }
    " 4vCPU-16GB-256GB" = @{ RAM = 16; Storage = 256 }
    " 8vCPU-32GB-512GB" = @{ RAM = 32; Storage = 512 }
}


[CmdletBinding()]
function WE-Get-Windows365SKU -ErrorAction Stop {
    param ($ram, $storage)
    
    # Sort SKUs by RAM and Storage (ensuring we always pick the smallest SKU that meets/exceeds both)
    $sortedSkus = $skuMapping.GetEnumerator() | 
                  Sort-Object { $_.Value.RAM }, { $_.Value.Storage }
    
    foreach ($sku in $sortedSkus) {
        $specs = $sku.Value
        if ($ram -le $specs.RAM -and $storage -le $specs.Storage) {
            return $sku.Key
        }
    }
    
    return " Custom SKU Required"
}

$deviceReport = @()

foreach ($device in $devices.value) {
    $deviceID = $device.id
    $deviceName = $device.deviceName
    $osVersion = $device.operatingSystemVersion
    $primaryUser = $device.userPrincipalName

    # Fetch hardware details for each device
    $hardwareUri = " $deviceEndpoint/$deviceID"
    $hardwareDetails = Invoke-MgGraphRequest -Method Get -Uri " $($hardwareUri)?`$select=hardwareInformation"
    $memoryDetails = Invoke-MgGraphRequest -Method Get -Uri " $($hardwareUri)?`$select=hardwareInformation,physicalMemoryInBytes"

    $storage = $hardwareDetails.hardwareInformation.totalStorageSpace / 1GB
   ;  $ram = $memoryDetails.physicalMemoryInBytes / 1GB

    # Determine recommended Windows 365 SKU
   ;  $recommendedSKU = Get-Windows365SKU -ram $ram -storage $storage

    # Add device info to the report
   ;  $deviceReport = $deviceReport + [PSCustomObject]@{
        DeviceName      = $deviceName
        OSVersion      = $osVersion
        PrimaryUser    = $primaryUser
        RAM            = [math]::Round($ram, 2)
        Storage        = [math]::Round($storage, 2)
        RecommendedSKU = $recommendedSKU
    }
}


$deviceReport | Format-Table -AutoSize




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================