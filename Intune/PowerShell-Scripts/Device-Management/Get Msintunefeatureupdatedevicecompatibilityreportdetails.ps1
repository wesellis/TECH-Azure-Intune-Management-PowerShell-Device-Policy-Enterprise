<#
.SYNOPSIS
    Get Msintunefeatureupdatedevicecompatibilityreportdetails

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
    We Enhanced Get Msintunefeatureupdatedevicecompatibilityreportdetails

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
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

$WEGlobal:AuthenticationHeader = Get-AccessToken -TenantID " <tenant_id" -ClientID " <client_id>" -RedirectUri " http://localhost"


$WEReportName = " MEMUpgradeCompatibility"
$WEAssetType = @(" Application" , " Driver" ) # Application, Driver, Other
$WERiskStatus = " MediumRisk" # LowRisk, MediumRisk, HighRisk
$WEOperatingSystemName = " Windows 11"
$WEOperatingSystemVersion = " 23H2"


function WE-ConvertTo-Base64String {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory = $true, HelpMessage = " Specify the string to be encoded as Base64." )]
        [ValidateNotNullOrEmpty()]
        [string]$WEValue
    )
    Process {
        # Encode string from parameter input
        $WEEncodedString = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($WEValue))

        # Handle return value
        return $WEEncodedString
    }
}

function WE-ConvertFrom-Base64String {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
        [parameter(Mandatory = $true, HelpMessage = " Specify the string to be decoded from Base64 to a human-readable string." )]
        [ValidateNotNullOrEmpty()]
        [string]$WEValue
    )
    Process {
        # Decode string from parameter input
        $WEDecodedString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($WEValue))

        # Handle return value
        return $WEDecodedString
    }
}


$WEReportFilterTableNames = @{
    MEMUpgradeCompatibility = " MEMUpgradeReadinessTargetOS"
}


$WEReportTableIdentifiers = @{
    MEMUpgradeCompatibility = " MEMUpgradeReadinessOrgAppAndDriverV2_00000000-0000-0000-0000-000000000001"
}


$WEReportAssetTypeTableValues = @{
    " All" = 0
    " Application" = 1
    " Driver" = 2
    " Other" = 3
}


$WEReportReadinessStatusTableValues = @{
    " LowRisk" = 0
    " MediumRisk" = 1
    " HighRisk" = 2
}


$WEReportFiltersBodyTable = @{
    name = $WEReportFilterTableNames[$WEReportName]
    select = $null
    skip = 0
    top = 100
    filter = [string]::Empty
    orderBy = @(" DisplayName desc" )
}


$WEReportFiltersUri = " deviceManagement/reports/getReportFilters"
$WEReportFiltersResponse = Invoke-MSGraphOperation -Post -APIVersion " Beta" -Resource $WEReportFiltersUri -Body ($WEReportFiltersBodyTable | ConvertTo-Json)
if ($WEReportFiltersResponse.Values.Count -ge 1) {
    # Construct array list for all report filter values
    $WEReportFilterValuesList = New-Object -TypeName " System.Collections.ArrayList"
    
    # Construct a new custom object for each report filter value returned from request
    foreach ($WEReportFilterValue in $WEReportFiltersResponse.Values) {
        $WEPSObject = [PSCustomObject]@{
            ID = $WEReportFilterValue[0]
            DisplayName = $WEReportFilterValue[1]
        }
        $WEReportFilterValuesList.Add($WEPSObject) | Out-Null
    }

    # Select target operating system filter value from list based on parameter input
    $WETargetOperatingSystemFilter = $WEReportFilterValuesList | Where-Object { ($WEPSItem.DisplayName -like " *$($WEOperatingSystemName)*" ) -and ($WEPSItem.DisplayName -like " *$($WEOperatingSystemVersion)*" ) }
}


$WEFilterPickerEncodedString = ConvertTo-Base64String -Value ([System.Uri]::EscapeDataString($WETargetOperatingSystemFilter.DisplayName))


$WECachedReportConfigurationsFilterString = " (ReadinessStatus eq '$($WEReportReadinessStatusTableValues[$WERiskStatus])') and (TargetOS eq '$($WETargetOperatingSystemFilter.ID)')"
if ($WEAssetType -ne $null) {
    if ($WEAssetType.Count -eq 1) {
       ;  $WECachedReportConfigurationsFilterString = $WECachedReportConfigurationsFilterString + " and (AssetType eq '$($WEReportAssetTypeTableValues[$WEAssetType])')"
    }
    else {
       ;  $WECachedReportConfigurationsFilterString = $WECachedReportConfigurationsFilterString + " and ("
        for ($i = 0; $i -lt $WEAssetType.Count; $i++) {
            if ($i -gt 0) {
                $WECachedReportConfigurationsFilterString = $WECachedReportConfigurationsFilterString + " or "
            }
            $WECachedReportConfigurationsFilterString = $WECachedReportConfigurationsFilterString + " AssetType eq '$($WEReportAssetTypeTableValues[$WEAssetType[$i]])'"
        }
        $WECachedReportConfigurationsFilterString = $WECachedReportConfigurationsFilterString + " )"
    }
}

$WECachedReportConfigurationsBodyTable = @{
    id = $WEReportTableIdentifiers[$WEReportName]
    filter = $WECachedReportConfigurationsFilterString
    metadata = " TargetOS=>filterPicker=$($WEFilterPickerEncodedString)"
    orderBy = @()
    select = @(" AssetType" , " AssetName" , " AssetVendor" , " AssetVersion" , " DeviceIssuesCount" , " ReadinessStatus" , " IssueTypes" )
}


$WECachedReportConfigurationsUri = " deviceManagement/reports/cachedReportConfigurations"
$WECachedReportConfigurationsResponse = Invoke-MSGraphOperation -Post -APIVersion " Beta" -Resource $WECachedReportConfigurationsUri -Body ($WECachedReportConfigurationsBodyTable | ConvertTo-Json)
$WECachedReportConfigurationsResponse


$WECachedReportConfigurationsStatusUri = " deviceManagement/reports/cachedReportConfigurations('$($WECachedReportConfigurationsResponse.id)')"
$WECachedReportConfigurationsStatusResponse = Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource $WECachedReportConfigurationsStatusUri
while ($WECachedReportConfigurationsStatusResponse.status -like " inProgress" ) {
    $WECachedReportConfigurationsStatusResponse = Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource $WECachedReportConfigurationsStatusUri
    Start-Sleep -Seconds 1
}


$WECachedReportAssetsBodyTable = @{
    id = $WECachedReportConfigurationsResponse.id
    skip = 0
    top = 50
    search = [string]::Empty # Search for specific assets
    orderBy = @()
    select = @(" AssetType" , " AssetName" , " AssetVendor" , " AssetVersion" , " DeviceIssuesCount" , " ReadinessStatus" , " IssueTypes" )
    filter = [string]::Empty
}


$WEAssetList = New-Object -TypeName " System.Collections.Generic.List[System.Object]"


$WECachedReportAssetsUri = " deviceManagement/reports/getCachedReport"; 
$WECachedReportAssetsResponse = Invoke-MSGraphOperation -Post -APIVersion " Beta" -Resource $WECachedReportAssetsUri -Body ($WECachedReportAssetsBodyTable | ConvertTo-Json)
foreach ($WECachedReportAsset in $WECachedReportAssetsResponse.Values) {
    # Construct a new custom object for each asset value returned from request, using the schema to dynamically add properties
   ;  $WEAsset = New-Object -TypeName " PSObject"
    for ($i = 0; $i -lt $WECachedReportAssetsResponse.Values[0].Count; $i++) {
        $WEAssetSchemaCurrent = $WECachedReportAssetsResponse.Schema[$i].Column
        $WEAsset | Add-Member -MemberType " NoteProperty" -Name $WEAssetSchemaCurrent -Value $WECachedReportAsset[$i]
    }

    # Update the AssetType property to a human-readable string
    $WEAsset.AssetType = ($WEReportAssetTypeTableValues.GetEnumerator() | Where-Object { $WEPSItem.Value -eq $WEAsset.AssetType }).Name

    # Update the ReadinessStatus property to a human-readable string
    $WEAsset.ReadinessStatus = ($WEReportReadinessStatusTableValues.GetEnumerator() | Where-Object { $WEPSItem.Value -eq $WEAsset.ReadinessStatus }).Name

    # Add the asset to the list
    $WEAssetList.Add($WEAsset)
}
$WEAssetList | Select-Object -First 2 | Format-Table -AutoSize



$WEAffectedDevicesList = New-Object -TypeName " System.Collections.Generic.List[System.Object]"


$WEAffectedDevicesFilterReportBodyTable = @{
    name = " MEMUpgradeReadinessOprDevicesPerAsset"
    filter = " (TargetOS eq 'NI23H2') and (AssetType eq '2') and (AssetName eq 'Logitech BRIO (usbvideo.sys)') and (AssetVendor eq 'Logitech') and (AssetVersion eq '1.0.85.0')"
    orderBy = @(" AssetName asc" )
    select = @(" DeviceName" , " DeviceManufacturer" , " DeviceModel" , " OSVersion" , " IssueTypes" )
    top = 40
    skip = 0
}
$WEReportFiltersUri = " deviceManagement/reports/getReportFilters"; 
$WEReportFiltersResponse = Invoke-MSGraphOperation -Post -APIVersion " Beta" -Resource $WEReportFiltersUri -Body ($WEAffectedDevicesFilterReportBodyTable | ConvertTo-Json)

foreach ($WEAffectedDevice in $WEReportFiltersResponse.Values) {
    # Construct a new custom object for each asset value returned from request, using the schema to dynamically add properties
   ;  $WEDevice = New-Object -TypeName " PSObject"
    for ($i = 0; $i -lt $WEReportFiltersResponse.Values[0].Count; $i++) {
        $WEDeviceSchemaCurrent = $WEReportFiltersResponse.Schema[$i].Column
        $WEDevice | Add-Member -MemberType " NoteProperty" -Name $WEDeviceSchemaCurrent -Value $WEAffectedDevice[$i]
    }

    # Add the device to the list
    $WEAffectedDevicesList.Add($WEDevice)
}
$WEAffectedDevicesList | Format-Table -AutoSize




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
