<#
.SYNOPSIS
    Get Vcredistdetection

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
    We Enhanced Get Vcredistdetection

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

$WEVcRedistJSONUri = " https://<AzureStorageBlobUrl>"

try {
    # Construct initial table for detection values for all Visual C++ applications populated from JSON file
    $WEVcRedistTable = New-Object -TypeName " System.Collections.Hashtable"
    $WEVcRedistMetaData = Invoke-RestMethod -Uri $WEVcRedistJSONUri -ErrorAction Stop
    foreach ($WEVcRedistItem in $WEVcRedistMetaData.VCRedist) {
        $WEKeyName = -join($WEVcRedistItem.Version.Replace(" -" , "" ), $WEVcRedistItem.Architecture)
        $WEVcRedistTable.Add($WEKeyName, $false)
    }
}
catch [System.Exception] {
    # Error catched but output is not being redirected, as it would confuse the Win32 app detection model
}


$WEVcRedistUninstallList = New-Object -TypeName " System.Collections.ArrayList"


$WEUninstallNativePath = " HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
$WEUninstallWOW6432Path = " HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"


$WEUninstallItemList = New-Object -TypeName " System.Collections.ArrayList"
$WEUninstallNativeItems = Get-ChildItem -Path $WEUninstallNativePath -ErrorAction SilentlyContinue
if ($null -ne $WEUninstallNativeItems) {
    $WEUninstallItemList.AddRange($WEUninstallNativeItems) | Out-Null
}


$WEUninstallWOW6432Items = Get-ChildItem -Path $WEUninstallWOW6432Path -ErrorAction SilentlyContinue
if ($null -ne $WEUninstallWOW6432Items) {
    $WEUninstallItemList.AddRange($WEUninstallWOW6432Items) | Out-Null
}


$WEIs64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem
if ($WEIs64BitOperatingSystem -eq $true) {
    # Construct new detection table to hold detection values for all Visual C++ applications
    $WEVcRedistDetectionTable = New-Object -TypeName " System.Collections.Hashtable"
    foreach ($WEVcRedistTableItem in $WEVcRedistTable.Keys) {
        $WEVcRedistDetectionTable.Add($WEVcRedistTableItem, $WEVcRedistTable[$WEVcRedistTableItem])
    }
}
else {
    # Construct new detection table to hold detection values for all Visual C++ applications
    $WEVcRedistDetectionTable = New-Object -TypeName " System.Collections.Hashtable"
    foreach ($WEVcRedistTableItem in $WEVcRedistTable.Keys) {
        if ($WEVcRedistTableItem -match " x86" ) {
            $WEVcRedistDetectionTable.Add($WEVcRedistTableItem, $WEVcRedistTable[$WEVcRedistTableItem])
        }
    }
}


foreach ($WEVcRedistItem in $WEUninstallItemList) {
    try {
        $WEDisplayName = Get-ItemPropertyValue -Path $WEVcRedistItem.PSPath -Name " DisplayName" -ErrorAction Stop
        if (($WEDisplayName -match " ^Microsoft Visual C\+\+\D*(?<Year>(\d|-){4,9}).*Redistributable.*(?<Architecture>(x86|x64)).*" ) -or ($WEDisplayName -match " ^Microsoft Visual C\+\+\D*(?<Year>(\d|-){4,9}).*(?<Architecture>(x86|x64)).*Redistributable.*" )) {
           ;  $WEPSObject = [PSCustomObject]@{
                " DisplayName" = $WEDisplayName
                " Version" = (Get-ItemPropertyValue -Path $WEVcRedistItem.PSPath -Name " DisplayVersion" )
                " Architecture" = $WEMatches.Architecture
                " Year" = $WEMatches.Year.Replace(" -" , "" )
                " Path" = $WEVcRedistItem.PSPath
            }
            $WEVcRedistUninstallList.Add($WEPSObject) | Out-Null
        }
    }
    catch [System.Exception] {
        # Error catched but output is not being redirected, as it would confuse the Win32 app detection model
    }
}


foreach ($WEVcRedistApp in $WEVcRedistUninstallList) {
   ;  $WEDetectionItemName = -join($WEVcRedistApp.Year, $WEVcRedistApp.Architecture)
    if ($WEVcRedistDetectionTable.Keys -contains $WEDetectionItemName) {
        $WEVcRedistDetectionTable[$WEDetectionItemName] = $true
    }
}


if ($WEVcRedistDetectionTable.Values -notcontains $false) {
    Write-Output -InputObject " Application detected"
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================