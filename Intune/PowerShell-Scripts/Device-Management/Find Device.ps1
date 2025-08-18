<#
.SYNOPSIS
    Find Device

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
    We Enhanced Find Device

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
    Find an enrolled device location via Microsoft Intune / Graph
    Original script: https://github.com/damienvanrobaeys/Intune_Scripts/blob/main/Locate%20device/Invoke_LocateDevice.ps1



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [System.String] $WEDeviceName,
    [System.Management.Automation.SwitchParameter] $WELastLocation,
    [System.Management.Automation.SwitchParameter] $WEShowMap,
    [System.Management.Automation.SwitchParameter] $WEAddress
)

$WEVerbosePreference = " Continue"
Write-Verbose -Message " Device name to locate is: $WEDeviceName"
Write-Verbose -Message " Looking for the device ID..."

try {
    $WEGetDevice = Get-IntuneManagedDevice | Get-MSGraphAllPages | Where-Object { $_.deviceName -like " $WEDeviceName" }
}
catch {
    Throw $_
}
If ($WENull -eq $WEGetDevice) {
    Write-Error -Message " Cannot find device: $WEDeviceName."
}
Else {
    Write-Verbose -Message " Device ID is: $($WEGetDevice.ID)."

    $WEUrlLocation = " https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($WEGetDevice.ID)"
    $WEUrlLocateAction = " https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($WEGetDevice.ID)/locateDevice"

    If ($WELastLocation) {
        try {
            $params = @{
                Url        = $WEUrlLocation
                HttpMethod = " GET"
            }
            $WECheckLocation = (Invoke-MSGraphRequest @params).deviceActionResults.deviceLocation
        }
        catch {
            Throw $_
        }

        If ($WENull -ne $WECheckLocation) {
            Write-Verbose -Message " Last check date is: $($WECheckLocation.lastCollectedDateTime)."
        }
        Else {
            Write-Warning -Message " Location for device is empty: $WEDeviceName."
        }
    }
    Else {
        try {
            $params = @{
                Url        = $WEUrlLocateAction
                HttpMethod = " POST"
            }
            Invoke-MSGraphRequest @params
        }
        catch {
            Throw $_
        }

        Do {
            try {
                $params = @{
                    Url        = $WEUrlLocation
                    HttpMethod = " GET"
                }
                $WECheckLocation = (Invoke-MSGraphRequest @params).deviceActionResults.deviceLocation
            }
            catch {
                Throw $_
            }

            If ($WENull -eq $WECheckLocation) {
                Write-Verbose -Message " Locating the device..."
                Start-Sleep 5
            }

        } Until ($WENull -ne $WECheckLocation)
    }

    If ($WENull -ne $WECheckLocation) {

        If ($WEPSBoundParameters.ContainsKey(" ShowMap" )) {
            Start-Process " https://www.google.com/maps?q=$($WECheckLocation.latitude),$($WECheckLocation.longitude)"
        }

        If ($WEPSBoundParameters.ContainsKey(" Address" )) {
            $WELatitude = ($WECheckLocation.latitude.ToString()).replace(" ," , " ." )
            $WELongitude = ($WECheckLocation.longitude.ToString()).replace(" ," , " ." )
           ;  $WELocation = " https://geocode.xyz/$($WELatitude),$($WELongitude)?geoit=json"

            try {
               ;  $params = @{
                    Uri             = $WELocation
                    UseBasicParsing = $true
                }
                Invoke-RestMethod @params
            }
            catch {
                Write-Warning -Message " Error while getting location address"
            }
        }

        If (!($WEShowMap) -and !($WEAddress)) {
            $WECheckLocation
        }
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================