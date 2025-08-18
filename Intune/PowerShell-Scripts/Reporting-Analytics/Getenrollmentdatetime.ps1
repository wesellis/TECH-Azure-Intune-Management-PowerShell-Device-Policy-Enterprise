<#
.SYNOPSIS
    Getenrollmentdatetime

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
    We Enhanced Getenrollmentdatetime

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEErrorActionPreference = "SilentlyContinue"

$enrollmentPath = " HKLM:\SOFTWARE\Microsoft\Enrollments\"
$enrollments = Get-ChildItem -Path $enrollmentPath
foreach($enrollment in $enrollments)
{
    $object = Get-ItemProperty Registry::$enrollment
    $enrollPath = Join-Path -Path $enrollmentPath -ChildPath $object.PSChildName
    $key = Get-ItemProperty -Path $enrollPath -Name " DiscoveryServiceFullURL"
    if($key)
    {
        $regPath = " $($enrollPath)\DeviceEnroller"
        break
    }
    else
    {
        Write-WELog " Not enrolled" " INFO"
    }
}


$firstSessionBinary = Get-ItemProperty -Path $regPath -Name " FirstSessionTimestamp" -ErrorAction SilentlyContinue

function convertFromBinary($binary)
{
    if($binary)
    {
        $fileTime = [System.BitConverter]::ToInt64($binary, 0)
        return [datetime]::FromFileTimeUtc($fileTime)
    }
    return " Not Found"
}

$firstSessionTime = convertFromBinary($firstSessionBinary.FirstSessionTimestamp)
; 
$currentTime = Get-Date
; 
$timeDifference = $currentTime - $firstSessionTime

if($timeDifference.TotalHours -lt 3)
{
    Write-Output " Install"
}
else
{
    Write-Output " Dont Install"
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================