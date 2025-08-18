<#
.SYNOPSIS
    Set Windowstimezone

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
    We Enhanced Set Windowstimezone

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


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    Automatically detect the current location using Location Services in Windows 10 and call the Azure Maps API to determine and set the Windows time zone based on current location data.

.DESCRIPTION
    This script will automatically set the Windows time zone based on current location data. It does so by detecting the current position (latitude and longitude) from Location services
    in Windows 10 and then calls the Azure Maps API to determine correct Windows time zone based of the current position. If Location Services is not enabled in Windows 10, it will automatically
    be enabled and ensuring the service is running.

.PARAMETER AzureMapsSharedKey
    Specify the Azure Maps API shared key available under the Authentication blade of the resource in Azure.

.NOTES
    FileName:    Set-WindowsTimeZone.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-05-19
    Updated:     2022-01-28

    Version history:
    1.0.0 - (2020-05-19) - Script created
    1.0.1 - (2020-05-23) - Added registry key presence check for lfsvc configuration and better handling of selecting a single Windows time zone when multiple objects with different territories where returned (thanks to @jgkps for reporting)
    1.0.2 - (2020-09-10) - Improved registry key handling for enabling location services
    1.0.3 - (2020-12-22) - Added support for TLS 1.2 to disable location services once script has completed
    1.0.4 - (2022-01-28) - Fixed an issue with latest merge from JankeSkanke that messed up brackets rendering the script unsuable

[CmdletBinding(SupportsShouldProcess = $true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $false, HelpMessage = " Specify the Azure Maps API shared key available under the Authentication blade of the resource in Azure." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEAzureMapsSharedKey = " <ENTER_YOUR_SHARED_KEY_HERE>"
)
Begin {
    # Enable TLS 1.2 support for downloading modules from PSGallery
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Process {
    # Functions
    function WE-Write-LogEntry {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Value added to the log file." )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEValue,

            [parameter(Mandatory = $true, HelpMessage = " Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error." )]
            [ValidateNotNullOrEmpty()]
            [ValidateSet(" 1" , " 2" , " 3" )]
            [string]$WESeverity
        )
        # Determine log file location
        $WELogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath " Temp" ) -ChildPath " Set-WindowsTimeZone.log"
        
        # Construct time stamp for log entry
        if (-not(Test-Path -Path 'variable:global:TimezoneBias')) {
            [string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
            if ($WETimezoneBias -match " ^-" ) {
                $WETimezoneBias = $WETimezoneBias.Replace('-', '+')
            }
            else {
                $WETimezoneBias = '-' + $WETimezoneBias
            }
        }
        $WETime = -join @((Get-Date -Format " HH:mm:ss.fff" ), $WETimezoneBias)
        
        # Construct date for log entry
        $WEDate = (Get-Date -Format " MM-dd-yyyy" )
        
        # Construct context for log entry
        $WEContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" WindowsTimeZone"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
        
        # Add value to log file
        try {
            Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message " Unable to append log entry to Set-WindowsTimeZone.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function WE-Get-GeoCoordinate {
        # Construct return value object
        $WECoordinates = [PSCustomObject]@{
            Latitude = $null
            Longitude = $null
        }

        Write-LogEntry -Value " Attempting to start resolving the current device coordinates" -Severity 1
        $WEGeoCoordinateWatcher = New-Object -TypeName " System.Device.Location.GeoCoordinateWatcher"
        $WEGeoCoordinateWatcher.Start()

        # Wait until watcher resolves current location coordinates
        $WEGeoCounter = 0
        while (($WEGeoCoordinateWatcher.Status -notlike " Ready" ) -and ($WEGeoCoordinateWatcher.Permission -notlike " Denied" ) -and ($WEGeoCounter -le 60)) {
            Start-Sleep -Seconds 1
            $WEGeoCounter++
        }

        # Break operation and return empty object since permission was denied
        if ($WEGeoCoordinateWatcher.Permission -like " Denied" ) {
            Write-LogEntry -Value " Permission was denied accessing coordinates from location services" -Severity 3

            # Stop and dispose of the GeCoordinateWatcher object
            $WEGeoCoordinateWatcher.Stop()
            $WEGeoCoordinateWatcher.Dispose()

            # Handle return error
            return $WECoordinates
        }

        # Set coordinates for return value
        $WECoordinates.Latitude = ($WEGeoCoordinateWatcher.Position.Location.Latitude).ToString().Replace(" ," , " ." )
        $WECoordinates.Longitude = ($WEGeoCoordinateWatcher.Position.Location.Longitude).ToString().Replace(" ," , " ." )

        # Stop and dispose of the GeCoordinateWatcher object
        $WEGeoCoordinateWatcher.Stop()
        $WEGeoCoordinateWatcher.Dispose()

        # Handle return value
        return $WECoordinates
    }

    function WE-New-RegistryKey {
        [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEPath
        )
        try {
            Write-LogEntry -Value " Checking presence of registry key: $($WEPath)" -Severity 1
            if (-not(Test-Path -Path $WEPath)) {
                Write-LogEntry -Value " Attempting to create registry key: $($WEPath)" -Severity 1
                New-Item -Path $WEPath -ItemType " Directory" -Force -ErrorAction Stop | Out-Null
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value " Failed to create registry key '$($WEPath)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function WE-Set-RegistryValue {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath,

            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEName,        

            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEValue,

            [parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet(" String" , " ExpandString" , " Binary" , " DWord" , " MultiString" , " Qword" )]
            [string]$WEType = " String"
        )
        try {
            Write-LogEntry -Value " Checking presence of registry value '$($WEName)' in registry key: $($WEPath)" -Severity 1
            $WERegistryValue = Get-ItemPropertyValue -Path $WEPath -Name $WEName -ErrorAction SilentlyContinue
            if ($WERegistryValue -ne $null) {
                Write-LogEntry -Value " Setting registry value '$($WEName)' to: $($WEValue)" -Severity 1
                Set-ItemProperty -Path $WEPath -Name $WEName -Value $WEValue -Force -ErrorAction Stop
            }
            else {
                New-RegistryKey -Path $WEPath -ErrorAction Stop
                Write-LogEntry -Value " Setting registry value '$($WEName)' to: $($WEValue)" -Severity 1
                New-ItemProperty -Path $WEPath -Name $WEName -PropertyType $WEType -Value $WEValue -Force -ErrorAction Stop | Out-Null
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value " Failed to create or update registry value '$($WEName)' in '$($WEPath)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function WE-Enable-LocationServices {
        $WEAppsAccessLocation = " HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
        Set-RegistryValue -Path $WEAppsAccessLocation -Name " LetAppsAccessLocation" -Value 0 -Type " DWord"

        $WELocationConsentKey = " HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        Set-RegistryValue -Path $WELocationConsentKey -Name " Value" -Value " Allow" -Type " String"

        $WESensorPermissionStateKey = " HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        Set-RegistryValue -Path $WESensorPermissionStateKey -Name " SensorPermissionState" -Value 1 -Type " DWord"

        $WELocationServiceConfigurationKey = " HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
        Set-RegistryValue -Path $WELocationServiceConfigurationKey -Name " Status" -Value 1 -Type " DWord"

        $WELocationService = Get-Service -Name " lfsvc"
        Write-LogEntry -Value " Checking location service 'lfsvc' for status: Running" -Severity 1
        if ($WELocationService.Status -notlike " Running" ) {
            Write-LogEntry -Value " Location service is not running, attempting to start service" -Severity 1
            Start-Service -Name " lfsvc"
        }
        elseif ($WELocationService.Status -like " Running" ) {
            Write-LogEntry -Value " Location service is already running, restart service to apply new configuration" -Severity 1
            Restart-Service -Name " lfsvc"
        }
    }

    function WE-Disable-LocationServices {
        $WELocationConsentKey = " HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        Set-RegistryValue -Path $WELocationConsentKey -Name " Value" -Value " Deny" -Type " String"

        $WESensorPermissionStateKey = " HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        Set-RegistryValue -Path $WESensorPermissionStateKey -Name " SensorPermissionState" -Value 0 -Type " DWord"

        $WELocationServiceConfigurationKey = " HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
        Set-RegistryValue -Path $WELocationServiceConfigurationKey -Name " Status" -Value 0 -Type " DWord"
    }

    Write-LogEntry -Value " Starting to determine the desired Windows time zone configuration" -Severity 1

    try {
        # Load required assembly and construct a GeCoordinateWatcher object
        Write-LogEntry -Value " Attempting to load required 'System.Device' assembly" -Severity 1
        Add-Type -AssemblyName " System.Device" -ErrorAction Stop

        try {
            # Ensure Location Services in Windows is enabled and service is running
            Enable-LocationServices

            # Retrieve the latitude and longitude values
            $WEGeoCoordinates = Get-GeoCoordinate
            if (($WEGeoCoordinates.Latitude -ne $null) -and ($WEGeoCoordinates.Longitude -ne $null)) {
                Write-LogEntry -Value " Successfully resolved current device coordinates" -Severity 1
                Write-LogEntry -Value " Detected latitude: $($WEGeoCoordinates.Latitude)" -Severity 1
                Write-LogEntry -Value " Detected longitude: $($WEGeoCoordinates.Longitude)" -Severity 1

                # Construct query string for Azure Maps API request
                $WEAzureMapsQuery = -join@($WEGeoCoordinates.Latitude, " ," , $WEGeoCoordinates.Longitude)

                try {
                    # Call Azure Maps timezone/byCoordinates API to retrieve IANA time zone id
                    Write-LogEntry -Value " Attempting to determine IANA time zone id from Azure MAPS API using query: $($WEAzureMapsQuery)" -Severity 1
                    $WEAzureMapsTimeZoneURI = " https://atlas.microsoft.com/timezone/byCoordinates/json?subscription-key=$($WEAzureMapsSharedKey)&api-version=1.0&options=all&query=$($WEAzureMapsQuery)"
                    $WEAzureMapsTimeZoneResponse = Invoke-RestMethod -Uri $WEAzureMapsTimeZoneURI -Method " Get" -ErrorAction Stop
                    if ($WEAzureMapsTimeZoneResponse -ne $null) {
                        $WEIANATimeZoneValue = $WEAzureMapsTimeZoneResponse.TimeZones.Id
                        Write-LogEntry -Value " Successfully retrieved IANA time zone id from current position data: $($WEIANATimeZoneValue)" -Severity 1

                        try {
                            # Call Azure Maps timezone/enumWindows API to retrieve the Windows time zone id
                            Write-LogEntry -Value " Attempting to Azure Maps API to enumerate Windows time zone ids" -Severity 1
                            $WEAzureMapsWindowsEnumURI = " https://atlas.microsoft.com/timezone/enumWindows/json?subscription-key=$($WEAzureMapsSharedKey)&api-version=1.0"
                           ;  $WEAzureMapsWindowsEnumResponse = Invoke-RestMethod -Uri $WEAzureMapsWindowsEnumURI -Method " Get" -ErrorAction Stop
                            if ($WEAzureMapsWindowsEnumResponse -ne $null) {
                               ;  $WETimeZoneID = $WEAzureMapsWindowsEnumResponse | Where-Object { ($WEPSItem.IanaIds -like $WEIANATimeZoneValue) -and ($WEPSItem.Territory.Length -eq 2) } | Select-Object -ExpandProperty WindowsId
                                Write-LogEntry -Value " Successfully determined the Windows time zone id: $($WETimeZoneID)" -Severity 1

                                try {
                                    # Set the time zone
                                    Write-LogEntry -Value " Attempting to configure the Windows time zone id with value: $($WETimeZoneID)" -Severity 1
                                    Set-TimeZone -Id $WETimeZoneID -ErrorAction Stop
                                    Write-LogEntry -Value " Successfully configured the Windows time zone" -Severity 1
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value " Failed to set Windows time zone. Error message: $($WEPSItem.Exception.Message)" -Severity 3
                                }
                            }
                            else {
                                Write-LogEntry -Value " Invalid response from Azure Maps call enumerating Windows time zone ids" -Severity 3
                            }
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value " Failed to call Azure Maps API to enumerate Windows time zone ids. Error message: $($WEPSItem.Exception.Message)" -Severity 3
                        }
                    }
                    else {
                        Write-LogEntry -Value " Invalid response from Azure Maps query when attempting to retrieve the IANA time zone id" -Severity 3
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value " Failed to retrieve the IANA time zone id based on current position data from Azure Maps. Error message: $($WEPSItem.Exception.Message)" -Severity 3
                }
            }
            else {
                Write-LogEntry -Value " Unable to determine current device coordinates from location services, breaking operation" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value " Failed to determine Windows time zone. Error message: $($WEPSItem.Exception.Message)" -Severity 3
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value " Failed to load required 'System.Device' assembly, breaking operation" -Severity 3
    }    
}
End {
    # Set Location Services to disabled to let other policy configuration manage the state
    Disable-LocationServices
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================