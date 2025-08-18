<#
.SYNOPSIS
    Get Geocoordinate

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
    We Enhanced Get Geocoordinate

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


function WE-Get-GeoCoordinate {



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

function WE-Get-GeoCoordinate {
    # Source: https://github.com/MSEndpointMgr/Intune/tree/master/Autopilot

    # Construct return value object
    $WECoordinates = [PSCustomObject]@{
        Latitude  = $null
        Longitude = $null
    }

    try {
        Add-Type -AssemblyName " System.Device"
       ;  $WEGeoCoordinateWatcher = New-Object -TypeName " System.Device.Location.GeoCoordinateWatcher"
    }
    catch {
        throw $_
    }

    # Wait until watcher resolves current location coordinates
    $WEGeoCoordinateWatcher.Start()
   ;  $WEGeoCounter = 0
    while (($WEGeoCoordinateWatcher.Status -notlike " Ready" ) -and ($WEGeoCoordinateWatcher.Permission -notlike " Denied" ) -and ($WEGeoCounter -le 60)) {
        Start-Sleep -Seconds 1
        $WEGeoCounter++
    }

    try {
        if ($WEGeoCoordinateWatcher.Permission -like " Denied" ) {
            # Break operation and return empty object since permission was denied
            return $WECoordinates
        }
        else {
            # Set coordinates for return value
            $WECoordinates.Latitude = ($WEGeoCoordinateWatcher.Position.Location.Latitude).ToString().Replace(" ," , " ." )
            $WECoordinates.Longitude = ($WEGeoCoordinateWatcher.Position.Location.Longitude).ToString().Replace(" ," , " ." )
            # Handle return value
            return $WECoordinates
        }
    }
    catch {
        throw $_
    }
    finally {
        # Stop and dispose of the GeCoordinateWatcher object
        $WEGeoCoordinateWatcher.Stop()
        $WEGeoCoordinateWatcher.Dispose()
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================