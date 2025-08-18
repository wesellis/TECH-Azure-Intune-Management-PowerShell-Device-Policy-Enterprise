<#
.SYNOPSIS
    Output Intunedevicereport

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
    We Enhanced Output Intunedevicereport

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#
    .SYNOPSIS
        Outputs configuration objects from an Intune tenant into an Excel workbook



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter()]
    [System.String] $WEFilePath = $(Join-Path (Resolve-Path $pwd) " Devices.xlsx" )
)


Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -ErrorAction SilentlyContinue
If ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne " Trusted" ) {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}
$modules = @('PSWriteExcel')
ForEach ($module in $modules) {
    Install-Module -Name $module -Scope CurrentUser
    Import-Module -Name $module
}


$WEDevices = Get-IntuneManagedDevice -ErrorAction Stop | `
    Select-Object -Property userDisplayName, userPrincipalName, emailAddress, deviceName, enrolledDateTime, `
    manufacturer, model, operatingSystem, osVersion, deviceEnrollmentType, lastSyncDateTime, complianceState, deviceCategoryDisplayName, `
    managedDeviceName, managedDeviceOwnerType, deviceRegistrationState, easActivated, azureADRegistered, exchangeAccessState | `
    Sort-Object enrolledDateTime -Descending

; 
$WEExcel = New-ExcelDocument; 
$WEExcelWorkSheet = Add-ExcelWorkSheet -ExcelDocument $WEExcel -WorksheetName " Devices" -Suppress $WEFalse -Option 'Replace'
Add-ExcelWorksheetData -ExcelWorksheet $WEExcelWorkSheet -DataTable $WEDevices -AutoFit -Suppress $WETrue -FreezeTopRow -TableStyle Light9
Save-ExcelDocument -ExcelDocument $WEExcel -FilePath $WEFilePath -OpenWorkBook




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
