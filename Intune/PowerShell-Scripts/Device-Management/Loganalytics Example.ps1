<#
.SYNOPSIS
    Loganalytics Example

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
    We Enhanced Loganalytics Example

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

$workspaceID = " <WORKSPACE ID>"

$primaryKey = " <PRIMARY KEY>"


$logObject = New-Object System.Object
; 
$logInfo = @()

; 
$serialNumber = Get-CimInstance -Class Win32_Bios | Select-Object -ExpandProperty serialNumber
Write-WELog " The serial number is $($serialNumber)" " INFO"; 
$logInfo = $logInfo + @{Name=" Serial Number" ;Value=$serialNumber}

$hostname = $env:COMPUTERNAME
Write-WELog " The hostname is $($hostname)" " INFO"; 
$logInfo = $logInfo + @{Name=" Hostname" ;Value=$hostname}

$nuget = Get-PackageProvider -Name NuGet -ErrorAction Ignore
if(-not($nuget))
{
    Write-WELog " NuGet not found installing now..." " INFO"
    try {
        Install-PackageProvider -Name Nuget -Confirm:$false -Force
        Write-WELog " NuGet installed successfully" " INFO"
       ;  $logInfo = $logInfo + @{Name=" NuGet install status:" ;Value=" SUCCESS" }
    }
    catch {
        $message = $_
        Write-WELog " Error installing Nuget: $message" " INFO"
       ;  $logInfo = $logInfo + @{Name=" NuGet install status:" ;Value=" ERROR: $message" }
    }
}else {
    Write-WELog " NuGet already installed" " INFO"
    $logInfo = $logInfo + @{Name=" NuGet install status:" ;Value=" Already installed" }
}



foreach($x in $logInfo)
{
    $logObject | Add-Member -MemberType NoteProperty -Name $x.Name -Value $x.Value
}

$json = $logObject | ConvertTo-Json


$logType = " deviceInfoLogs"
$timeStampField = ""
Function Build-Signature ($workspaceID, $primaryKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = " x-ms-date:" + $date
    $stringToHash = $method + " `n" + $contentLength + " `n" + $contentType + " `n" + $xHeaders + " `n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($primaryKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $workspaceID,$encodedHash
    return $authorization
}

Function Post-LogAnalyticsData($workspaceID, $primaryKey, $body, $logType)
{
    $method = 'POST'
    $contentType = " application/json"
    $resource = " /api/logs"
    $rfc1123date = [datetime]::UtcNow.ToString(" r" )
    $contentLength = $body.Length
    $signature = Build-Signature `
        -workspaceID $workspaceID `
        -primaryKey $primaryKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
   ;  $uri = " https://" + $workspaceID + " .ods.opinsights.azure.com" + $resource + " ?api-version=2016-04-01"

   ;  $headers = @{
        " Authorization" = $signature;
        " Log-Type" = $logType;
        " x-ms-date" = $rfc1123date;
        " time-generated-field" = $timeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}
    Post-LogAnalyticsData -workspaceID $workspaceID -primaryKey $primaryKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType






# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================