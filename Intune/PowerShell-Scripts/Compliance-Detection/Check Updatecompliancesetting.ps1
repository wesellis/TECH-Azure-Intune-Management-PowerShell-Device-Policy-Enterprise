<#
.SYNOPSIS
    Check Updatecompliancesetting

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
    We Enhanced Check Updatecompliancesetting

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


function WE-Test-RequiredPath {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param([Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath)
    if (!(Test-Path $WEPath)) {
        Write-Warning " Required path not found: $WEPath"
        return $false
    }
    return $true
}

<#


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.Synopsis
Proactive Remediation to check clients meet the requirement for update compliance processing. 

.Description
Adapted from Microsoft script for update compliance processing at:- 
https://docs.microsoft.com/en-us/windows/deployment/update/update-compliance-configuration-script

-------------------------------------------
Client Conditions Checked
-------------------------------------------
-CheckSqmID 
-CheckCommercialId
-CheckTelemetryOptIn
-CheckConnectivityURL(s)
-CheckUtcCsp
-CheckDiagtrackDLLVersion
-CheckDiagtrackService
-CheckMSAService
-CheckAllowDeviceNameInTelemetry
-CheckAllowUpdateComplianceProcessing
-CheckAllowWUfBCloudProcessing
-CheckConfigureTelemetryOptInChangeNotification
-CheckConfigureTelemetryOptInSettingsUx

-------------------------------------------
Proactive Remediation Information
-------------------------------------------
-Run script in 64-bit PowerShell option when creating the PR

Scenario: All tests passed
Proactive Remediation Predetection Output: " OK"

Scenario: One or more tests failed
Proactive Remediation Predetection Output: <JSON>
[{" Test" :" CheckConnectivityURL1" ," Status" :" Failed" ," Result" :" Failed. Could not access https://v10c.events.data.microsoft.comm/ping" },
{" Test" :" CheckConnectivityOverallResult" ," Status" :" Failed" ," Result" :" At least one of the required URLs is not accesible" }]

.Notes
Created on:   04/12/2021
Created by:   Ben Whitmore @CloudWay
Filename:     Check-UpdateComplianceSettings.ps1

**Version 1.0.08.12 - 07/12/21
- Changed .net webrequest method to Test-NetConnection

**Version 1.0.07.12 - 07/12/21
- Fixed padding issue for diagtrack test

**Version 1.0.06.12 - 06/12/21  
- Release

-------------------------------------------
Manual Testing
-------------------------------------------
-To run manually, launch Powershell as 64bit in SYSTEM context, use " psexec64.exe -s -i C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
-The output for the PR is as follows:-
 
-------------------------------------------
Parameter " Detailed" Example Output
-------------------------------------------

Test                                           Status Result
----                                           ------ ------
CheckSqmID                                     Passed SQMID found in registry
CheckCommercialIDValue1                        Passed Valid GUID found in registry key value
CheckCommercialIDValue2                        Info   CommercialID value is empty
CheckCommercialIDOverallStatus                 Passed CommercialID registry key value 1 is valid
CheckTelemetryOptIn1                           Info   AllowTelemetry value is empty
CheckTelemetryOptIn2                           Passed AllowTelemetry value is 3
CheckTelemetryOptIn3                           Passed AllowTelemetry_PolicyManager value is 3
CheckTelemetryOptInOverallStatus               Passed AllowTelemetry_PolicyManager registry key found and wins
CheckConnectivityURL1                          Passed https://v10c.events.data.microsoft.com/ping accessible
CheckConnectivityURL2                          Passed https://login.live.com accessible
CheckConnectivityOverallResult                 Passed All of the required URLs are accesible
CheckUtcCsp                                    Passed UTC CSP verified
CheckDiagtrackService                          Passed Diagtrack service is running
CheckMSAService                                Passed MSAService is set to Manual (Triggered Start) but is not running
CheckAllowDeviceName                           Passed AllowDeviceNameInTelemetry value is 1
CheckAllowUpdateComplianceProcessing           Passed AllowUpdateComplianceProcessing value is 16
CheckAllowWUfBCloudProcessing                  Passed AllowWUfBCloudProcessing value is 8
CheckConfigureTelemetryOptInChangeNotification Passed ConfigureTelemetryOptInChangeNotification value is 1
CheckConfigureTelemetryOptInSettingsUx         Passed ConfigureTelemetryOptInSettingsUx value is 1

All Tests Passed

-------------------------------------------
Parameter " ExportJSON" Example Output
-------------------------------------------

Test                                           Status Result
----                                           ------ ------
CheckSqmID                                     Passed SQMID found in registry
CheckCommercialIDValue1                        Passed Valid GUID found in registry key value
CheckCommercialIDValue2                        Info   CommercialID value is empty
CheckCommercialIDOverallStatus                 Passed CommercialID registry key value 1 is valid
CheckTelemetryOptIn1                           Info   AllowTelemetry value is empty
CheckTelemetryOptIn2                           Passed AllowTelemetry value is 3
CheckTelemetryOptIn3                           Passed AllowTelemetry_PolicyManager value is 3
CheckTelemetryOptInOverallStatus               Passed AllowTelemetry_PolicyManager registry key found and wins
CheckConnectivityURL1                          Passed v10c.events.data.microsoft.com accessible
CheckConnectivityURL2                          Passed settings-win.data.microsoft.com accessible
CheckConnectivityURL3                          Passed adl.windows.com accessible
CheckConnectivityURL4                          Passed watson.telemetry.microsoft.com accessible
CheckConnectivityURL5                          Passed oca.telemetry.microsoft.com accessible
CheckConnectivityURL6                          Passed login.live.com accessible
CheckConnectivityOverallResult                 Passed All of the required URLs are accesible
CheckUtcCsp                                    Passed UTC CSP verified
CheckDiagtrackService                          Passed Diagtrack service is running
CheckMSAService                                Passed MSAService is set to Manual (Triggered Start) but is not running
CheckAllowDeviceName                           Passed AllowDeviceNameInTelemetry value is 1
CheckAllowUpdateComplianceProcessing           Passed AllowUpdateComplianceProcessing value is 16
CheckAllowWUfBCloudProcessing                  Passed AllowWUfBCloudProcessing value is 8
CheckConfigureTelemetryOptInChangeNotification Passed ConfigureTelemetryOptInChangeNotification value is 1
CheckConfigureTelemetryOptInSettingsUx         Passed ConfigureTelemetryOptInSettingsUx value is 1

.Example 
Check-UpdateComplianceSetting.ps1

.Example 
Check-UpdateComplianceSetting.ps1 -Detailed

.Example 
Check-UpdateComplianceSetting.ps1 -ExportJSON


[CmdletBinding(DefaultParameterSetName = " Default" )]
[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
    [Parameter(Mandatory = $false, ParameterSetName = " Detailed" )]
    [Switch]$WEDetailed,
    [Parameter(Mandatory = $false, ParameterSetName = " ExportJSON" )]
    [Switch]$WEExportJSON
)


$global:ConnectivityEndpoint = @(
    " v10c.events.data.microsoft.com"
    " settings-win.data.microsoft.com"
    " adl.windows.com"
    " watson.telemetry.microsoft.com"
    " oca.telemetry.microsoft.com"
    " login.live.com"
)


$global:osVersion = (Get-CimInstance Win32_OperatingSystem).Version


[int] $global:osBuildNumber = (Get-CimInstance Win32_OperatingSystem).BuildNumber


$global:operatingSystemName = (Get-CimInstance Win32_OperatingSystem).Name


$WEGlobal:ScriptOut = $WENull
$WEGlobal:ScriptOut = @()

$WEGlobal:ErrorOut = $WENull
$WEGlobal:ErrorOut = @()

$main = {
    Try {  
        
        if (([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem -eq $false ) {
            Write-Warning " The Update Compliance Configuration script is not running under System account. Please run the script as System."
        }
          
        CheckSqmID 
        CheckCommercialId
        CheckTelemetryOptIn   
        CheckConnectivity           

        if ($global:osBuildNumber -gt 17134) {
            CheckUtcCsp
        }

        CheckDiagtrackService

        if ($global:osBuildNumber -ge 10240) {
            CheckMSAService
        }

        CheckAllowDeviceNameInTelemetry
        CheckAllowUpdateComplianceProcessing
        CheckAllowWUfBCloudProcessing
        CheckConfigureTelemetryOptInChangeNotification
        CheckConfigureTelemetryOptInSettingsUx
    }
    Catch {
        $errMsg = $_.Exception.Message
        return $errMsg
    }

    $WETotalChecks = ($WEGlobal:ScriptOut | Measure-Object).Count

    $WEFailureFound = $false
    $errCount = 0
    $WEFailureTable = @()

    Foreach ($WEResult in $WEGlobal:ScriptOut) {
        If ($WEResult -like " *Failed*" ) {
            $WEFailureTable = $WEFailureTable + $WEResult
            $errCount++
            $WEFailureFound = $true
        }
    }

    If ((-not $WEExportJSON) -and $WEDetailed -and (-not $WEFailurefound)) {
        $WEGlobal:ScriptOut
    }

    If ((-not $WEDetailed) -and $WEExportJSON -and (-not $WEFailurefound)) {
        $WEGlobal:ScriptOut | ConvertTo-Json
    }

    If ((-not $WEFailureFound) -and (-not $WEExportJSON) -and (-not $WEDetailed)) {
        Write-Output " OK"
        Exit 0
    } 
    If ((-not $WEFailureFound) -and (-not $WEExportJSON) -and $WEDetailed) {
        Write-Output " `nAll Tests Passed"
        Exit 0
    } 
    If ($WEFailureFound -and (-not $WEExportJSON) -and $WEDetailed) {
        $WEGlobal:ScriptOut
        Write-Output " `n$($errCount)/$($WETotalChecks) Tests Failed"
        Exit 1  
    }
    If ($WEFailureFound -and $WEExportJSON) {
        $WEGlobal:ScriptOut | ConvertTo-Json -Compress
        Exit 1  
    }
    If ($WEFailureFound -and (-not $WEExportJSON) -and (-not $WEDetailed)) {
        $WEFailureTable | ConvertTo-Json -Compress
        Exit 1 
    }
}
Function Write-Array {

    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $WEFalse)]
        [String]$WEOutArray,   
        [Parameter(Mandatory = $WEFalse)]
        [String]$WETest,
        [Parameter(Mandatory = $WEFalse)]
        [String]$WEStatus,
        [Parameter(Mandatory = $WEFalse)]
        [String]$WEResult 
    )

    $WEOutputPass = New-Object -TypeName psobject 
    $WEOutputPass | Add-Member -MemberType NoteProperty -Name Test -Value $WETest -Force -PassThru | Out-Null
    $WEOutputPass | Add-Member -MemberType NoteProperty -Name Status -Value $WEStatus -Force -PassThru | Out-Null
    $WEOutputPass | Add-Member -MemberType NoteProperty -Name Result -Value $WEResult -Force -PassThru | Out-Null
    $WEGlobal:ScriptOut += $WEOutputPass
    $WEOutputPass = $WENull
}
function WE-CheckCommercialID {
    $commercialIDValue1ResultFail = $false
    $commercialIDValue2ResultFail = $false
    Try {
        $commercialIDValue1 = (Get-ItemProperty -Path " HKLM:SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name " CommercialID" -ErrorAction SilentlyContinue).CommercialID 
        $commercialIDValue2 = (Get-ItemProperty -Path " HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name " CommercialID" -ErrorAction SilentlyContinue).CommercialID 
        
        If (($commercialIDValue1 -eq $null) -or ($commercialIDValue1 -eq [string]::Empty)) {
            Write-Array -Status " Info" -Test " CheckCommercialIDValue1" -Result " CommercialID value is empty"
            $commercialIDValue1ResultFail = $true
        } 
        If (([guid]::TryParse($commercialIDValue1, $([ref][guid]::Empty)) -eq $true)) {
            Write-Array -Status " Passed" -Test " CheckCommercialIDValue1" -Result " Valid GUID found in registry key value"
        }

        If (($commercialIDValue2 -eq $null) -or ($commercialIDValue2 -eq [string]::Empty)) {
            Write-Array -Status " Info" -Test " CheckCommercialIDValue2" -Result " CommercialID value is empty"
            $commercialIDValue2ResultFail = $true
        }
        If (([guid]::TryParse($commercialIDValue2, $([ref][guid]::Empty)) -eq $true)) {
            Write-Array -Status " Passed" -Test " CheckCommercialIDValue1" -Result " Valid GUID found in registry key value"
        }

        If ($commercialIDValue1ResultFail -and $commercialIDValue2ResultFail) {
            Write-Array -Status " Failed" -Test " CheckCommercialIDOverallStatus" -Result " Both CommercialID registry key values are invalid"
        }
        else {
            If (-not ($commercialIDValue1ResultFail) -and ($commercialIDValue2ResultFail)) {
                Write-Array -Status " Passed" -Test " CheckCommercialIDOverallStatus" -Result " CommercialID registry key value 1 is valid"
            }
            If (-not ($commercialIDValue2ResultFail) -and ($commercialIDValue1ResultFail)) {
                Write-Array -Status " Passed" -Test " CheckCommercialIDOverallStatus" -Result " CommercialID registry key value 2 is valid"
            }
            If (-not ($commercialIDValue2ResultFail) -and (-not($commercialIDValue1ResultFail))) {
                Write-Array -Status " Passed" -Test " CheckCommercialIDOverallStatus" -Result " CommercialID registry key value 2 is valid"
            }
        }
    }
    Catch {
        Write-Array -Status " Failed" -Test " CheckCommercialIDOverallStatus" -Result " Unexpected Exception"
    }  
}

function WE-CheckSqmID {
    Try {
        $WESQMID = (Get-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\SQMClient" -Name MachineId).MachineId
        if (($WESQMID -eq $null) -or ($WESQMID -eq [string]::Empty)) {
            Write-Array -Status " Failed" -Test " CheckSqmID" -Result " SQMID Not found"
        }
        else {
            Write-Array -Status " Passed" -Test " CheckSqmID" -Result " SQMID found in registry"
        }
    }
    Catch {    
        Write-Array -Status " Failed" -Test " CheckSqmID" -Result " Unexpecetd Exception"
    }
}

function WE-CheckTelemetryOptIn {
    $vAllowTelemetryPath1 = " HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $vAllowTelemetryPath2 = " HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"

    $vAllowTelemetryPath1ResultFail = $false
    $vAllowTelemetryPath2ResultFail = $false
    $vAllowTelemetryPath3ResultFail = $false

    Try {
        
        $allowTelemetryProperty1 = (Get-ItemProperty -Path $vAllowTelemetryPath1 -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry
        $allowTelemetryProperty2 = (Get-ItemProperty -Path $vAllowTelemetryPath2 -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry
        $allowTelemetryProperty3 = (Get-ItemProperty -Path $vAllowTelemetryPath1 -Name AllowTelemetry_PolicyManager -ErrorAction SilentlyContinue).AllowTelemetry_PolicyManager
        
        if (($allowTelemetryProperty1 -ne $null) -or ($allowTelemetryProperty1 -eq [string]::Empty)) {

            if ($allowTelemetryProperty1 -isnot [Int32]) {
                Write-Array -Status " Info" -Test " CheckTelemetryOptIn1" -Result " Invalid value for AllowTelemetry" 
                $vAllowTelemetryPath1ResultFail = $true   
            }
            if (-not ([int]$allowTelemetryProperty1 -ge 1 -and [int]$allowTelemetryProperty1 -le 3)) {
                Write-Array -Status " Info" -Test " CheckTelemetryOptIn1" -Result " AllowTelemetry value is $($allowTelemetryProperty1)"
                $vAllowTelemetryPath1ResultFail = $true   
            }
            else {
                Write-Array -Status " Passed" -Test " CheckTelemetryOptIn1" -Result " AllowTelemetry value is $($allowTelemetryProperty1)"
            }
        }
        else {
            Write-Array -Status " Info" -Test " CheckTelemetryOptIn1" -Result " AllowTelemetry value is empty"
            $vAllowTelemetryPath1ResultFail = $true
        }

        if (($allowTelemetryProperty2 -ne $null) -or ($allowTelemetryProperty2 -eq [string]::Empty)) {

            if ($allowTelemetryProperty2 -isnot [Int32]) {
                Write-Array -Status " Info" -Test " CheckTelemetryOptIn2" -Result " Invalid value for AllowTelemetry" 
                $vAllowTelemetryPath2ResultFail = $true   
            }
            if (-not ([int]$allowTelemetryProperty2 -ge 1 -and [int]$allowTelemetryProperty2 -le 3)) {
                Write-Array -Status " Info" -Test " CheckTelemetryOptIn2" -Result " AllowTelemetry value is $($allowTelemetryProperty2)"
                $vAllowTelemetryPath2ResultFail = $true   
            }
            else {
                Write-Array -Status " Passed" -Test " CheckTelemetryOptIn2" -Result " AllowTelemetry value is $($allowTelemetryProperty2)"
            }
        }
        else {
            Write-Array -Status " Info" -Test " CheckTelemetryOptIn2" -Result " AllowTelemetry value is empty"
            $vAllowTelemetryPath2ResultFail = $true
        }

        if (($allowTelemetryProperty3 -ne $null) -or ($allowTelemetryProperty3 -eq [string]::Empty)) {

            if ($allowTelemetryProperty3 -isnot [Int32]) {
                Write-Array -Status " Info" -Test " CheckTelemetryOptIn3" -Result " Invalid value for AllowTelemetry_PolicyManager" 
                $vAllowTelemetryPath3ResultFail = $true   
            }
            if (-not ([int]$allowTelemetryProperty3 -ge 1 -and [int]$allowTelemetryProperty2 -le 3)) {
                Write-Array -Status " Info" -Test " CheckTelemetryOptIn3" -Result " AllowTelemetry_PolicyManager value is $($allowTelemetryProperty3)"
                $vAllowTelemetryPath3ResultFail = $true   
            }
            else {
                Write-Array -Status " Passed" -Test " CheckTelemetryOptIn3" -Result " AllowTelemetry_PolicyManager value is $($allowTelemetryProperty3)"
            }
        }
        else {
            Write-Array -Status " Info" -Test " CheckTelemetryOptIn3" -Result " AllowTelemetry_PolicyManager value is empty"
            $vAllowTelemetryPath3ResultFail = $true
        }

        If ($vAllowTelemetryPath1ResultFail -and $vAllowTelemetryPath2ResultFail -and $vAllowTelemetryPath3ResultFail) {
            Write-Array -Status " Failed" -Test " CheckTelemetryOptInOverallStatus" -Result " All possible AllowTelemetry registry keys are invalid"
        }

        If (-not $vAllowTelemetryPath3ResultFail) {
            Write-Array -Status " Passed" -Test " CheckTelemetryOptInOverallStatus" -Result " AllowTelemetry_PolicyManager registry key found and wins"
        }
        else {
            Write-Array -Status " Passed" -Test " CheckTelemetryOptInOverallStatus" -Result " At least one AllowTelemetry registry key is valid"
        }
    }     
    Catch {
        $_.exception.message
        Write-Array -Status " Failed" -Test " CheckTelemetryOptInOverallStatus" -Result " Unexpected Exception when gathering AllowTelemetry registry key(s)" 
    }
}

function WE-CheckConnectivity {
    $i = 0
    $WECheckConnectivityOverallStatus = $false
    Try {   

        Foreach ($WEEndpoint in $global:ConnectivityEndpoint) {
            $WERequest = $null
            Try {
                $i ++
                $WERequest = (Test-NetConnection $WEEndpoint -Port 443).TcpTestSucceeded

                If ($WERequest -eq 'True') {
                    Write-Array -Status " Passed" -Test " CheckConnectivityEndpoint$($i)" -Result " $($WEEndpoint) accessible"
                }
                Else {
                    Write-Array -Status " Failed" -Test " CheckConnectivityEndpoint$($i)" -Result " Failed. Could not access $($WEEndpoint)"
                    $WECheckConnectivityOverallStatus = $true
                }
            }
            Catch {
                Write-Array -Status " Failed" -Test " CheckConnectivityEndpoint$($i)" -Result " Failed. Could not access $($WEEndpoint)"
                $WECheckConnectivityOverallStatus = $true
            }
        }

        If ($WECheckConnectivityOverallStatus) {
            Write-Array -Status " Failed" -Test " CheckConnectivityOverallResult" -Result " At least one of the required endpoints is not accessible"
        }
        else {
            Write-Array -Status " Passed" -Test " CheckConnectivityOverallResult" -Result " All of the required endpoints are accessible"
        }
    }
    Catch {
        Write-Array -Status " Failed" -Test " CheckConnectivityOverallResult" -Result " Unexpected Exception"
    }
}

function WE-CheckUtcCsp {
    Try {
        $WEClassName = " MDM_Win32CompatibilityAppraiser_UniversalTelemetryClient01"
        $WEBridgeNamespace = " root\cimv2\mdm\dmmap"
        $WEFieldName = " UtcConnectionReport"
        $WECspInstance = get-ciminstance -Namespace $WEBridgeNamespace -ClassName $WEClassName
        $WEData = $WECspInstance.$WEFieldName
        $WEXmlData = [xml]$WEData

        if (0 -eq $WEXmlData.ConnectionReport.ConnectionSummary.DataUploaded) {
            Write-Array -Status " Failed" -Test " CheckUtcCsp" -Result " Recent data uploads failed"
        }
        else {
            Write-Array -Status " Passed" -Test " CheckUtcCsp" -Result " UTC CSP verified"
        }
    }
    Catch {
        Write-Array -Status " Failed" -Test " CheckUtcCsp" -Result " Unexpected Exception"
    }
}

function WE-CheckDiagtrackService {

    Try {
        if (Test-Path " C:\Windows\System32\diagtrack.dll" ) {
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(" C:\Windows\System32\diagtrack.dll" )

            [string]$majorPart = $versionInfo.FileMajorPart
            [string]$minorPart = $versionInfo.FileMinorPart
            [string]$buildPart = $versionInfo.FileBuildPart
            [string]$fileRevision = $versionInfo.FilePrivatePart

            $diagtrackVersion = $majorPart + $minorPart + $buildPart
            [string]$dot = " ."
            [string]$diagtrackVersionFormatted = $majorPart + $dot + $minorPart + $dot + $buildPart

            if ([int]$diagtrackVersion -lt 10010586 ) {
                Write-Array -Status " Warning" -Test " CheckDiagtrackDLLVersion" -Result " Unexpected Version $($diagtrackVersion)"
            }

            [string]$minRevision = " 0" 
            if ($global:operatingSystemName.ToLower().Contains(" windows 10" )) {
                if ([int]$diagtrackVersion -eq 10014393 -and [int]$fileRevision -lt 2513) {
                    $minRevision = " 2513"
                    $diagtrackVersionFormattedFull = $diagtrackVersionFormatted + $dot + $minRevision

                    Write-Array -Status " Warning" -Test " CheckDiagtrackDLLVersion" -Result " Unexpected Version $($diagtrackVersionFormattedFull)"
                }

                if ([int]$diagtrackVersion -eq 10015063 -and [int]$fileRevision -lt 1356) {
                    $minRevision = " 1356"
                    $diagtrackVersionFormattedFull = $diagtrackVersionFormatted + $dot + $minRevision
                    Write-Array -Status " Warning" -Test " CheckDiagtrackDLLVersion" -Result " Unexpected Version $($diagtrackVersionFormattedFull)"
                }

                if ([int]$diagtrackVersion -eq 10016299 -and [int]$fileRevision -lt 696) {
                    $minRevision = " 696"
                    $diagtrackVersionFormattedFull = $diagtrackVersionFormatted + $dot + $minRevision
                    Write-Array -Status " Warning" -Test " CheckDiagtrackDLLVersion" -Result " Unexpected Version $($diagtrackVersionFormattedFull)"
                }

                if ([int]$diagtrackVersion -eq 10017134 -and [int]$fileRevision -lt 320) {
                    $minRevision = " 320"
                    $diagtrackVersionFormattedFull = $diagtrackVersionFormatted + $dot + $minRevision
                    Write-Array -Status " Warning" -Test " CheckDiagtrackDLLVersion" -Result " Unexpected Version $($diagtrackVersionFormattedFull)"
                }
            }
        }
        else {
            Write-Array -Status " Failed" -Test " CheckDiagtrackDLLVersion" -Result " DLL not found at C:\Windows\System32\diagtrack.dll"
        }

        $serviceName = " diagtrack"
        $serviceInfo = Get-Service -Name $serviceName
        $status = $serviceInfo.Status

        if ($status.ToString().ToLower() -ne " running" ) {
            Write-Array -Status " Failed" -Test " CheckDiagtrackService" -Result " Service not running"
        }
        Write-Array -Status " Passed" -Test " CheckDiagtrackService" -Result " Diagtrack service is running"
    }
    Catch {
        Write-Array -Status " Failed" -Test " CheckDiagtrackService" -Result " Unexpected Exception"
    }
}

function WE-CheckMSAService {
    Try {
        $serviceInfo = Get-CimInstance win32_service -Filter " Name='wlidsvc'"
        $serviceStartMode = $serviceInfo.StartMode
        $serviceStatus = $serviceInfo.State

        if ($serviceStartMode.ToString().ToLower() -eq " disabled" ) {    
            Write-Array -Status " Failed" -Test " CheckMSAService" -Result " Service is disabled"
        }
        else {
            if ($serviceStartMode.ToString().TOLower() -eq " manual" ) {
                if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wlidsvc\TriggerInfo') {
                    If ($serviceStatus.ToString().TOLower() -eq " stopped" ) {
                        Write-Array -Status " Passed" -Test " CheckMSAService" -Result " MSAService is set to Manual (Triggered Start) but is not running"
                    } 
                    If ($serviceStatus.ToString().TOLower() -eq " running" ) {
                        Write-Array -Status " Passed" -Test " CheckMSAService" -Result " MSAService is set to Manual (Triggered Start) and is running"
                    } 
                }
            }
        }
    } 
    Catch {
        Write-Array -Status " Failed" -Test " CheckMSAService" -Result " Unexpected Exception"
    }
}

function WE-CheckAllowDeviceNameInTelemetry {
    $vAllowDeviceNamePath = " HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    
    Try {
        
        $allowDeviceNameProperty = (Get-ItemProperty -Path $vAllowDeviceNamePath -Name AllowDeviceNameInTelemetry -ErrorAction SilentlyContinue).AllowDeviceNameInTelemetry
       
        if (($allowDeviceNameProperty -ne $null) -or ($allowDeviceNameProperty -eq [string]::Empty)) {

            if ($allowDeviceNameProperty -isnot [Int32]) {
                Write-Array -Status " Warning" -Test " CheckAllowDeviceName" -Result " Invalid value for AllowDeviceNameInTelemetry"   
            }
            if (-not ([int]$allowDeviceNameProperty -eq 1 )) {
                Write-Array -Status " Warning" -Test " CheckAllowDeviceName" -Result " AllowDeviceNameInTelemetry value is $allowDeviceNameProperty"  
            }
            else {
                Write-Array -Status " Passed" -Test " CheckAllowDeviceName" -Result " AllowDeviceNameInTelemetry value is $allowDeviceNameProperty"
            }
        }
        else {
            Write-Array -Status " Info" -Test " CheckAllowDeviceName" -Result " AllowDeviceNameInTelemetry value is empty"
        }
    }     
    Catch {
        $_.exception.message
        Write-Array -Status " Warning" -Test " CheckAllowDeviceName" -Result " Unexpected Exception when gathering AllowDeviceNameInTelemetry registry value" 
    }
}

function WE-CheckAllowUpdateComplianceProcessing {
    $vAllowUpdateComplianceProcessingPath = " HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"
    
    Try {
        
        $allowUpdateComplianceProcessingProperty = (Get-ItemProperty -Path $vAllowUpdateComplianceProcessingPath -Name AllowUpdateComplianceProcessing -ErrorAction SilentlyContinue).AllowUpdateComplianceProcessing
       
        if (($allowUpdateComplianceProcessingProperty -ne $null) -or ($allowUpdateComplianceProcessingProperty -eq [string]::Empty)) {

            if ($allowUpdateComplianceProcessingProperty -isnot [Int32]) {
                Write-Array -Status " Warning" -Test " CheckAllowUpdateComplianceProcessing" -Result " Invalid value for AllowUpdateComplianceProcessing" 
            }
            if (-not ([int]$allowUpdateComplianceProcessingProperty -eq 16 )) {
                Write-Array -Status " Warning" -Test " CheckAllowUpdateComplianceProcessing" -Result " AllowUpdateComplianceProcessing value is $allowUpdateComplianceProcessingProperty"  
            }
            else {
                Write-Array -Status " Passed" -Test " CheckAllowUpdateComplianceProcessing" -Result " AllowUpdateComplianceProcessing value is $allowUpdateComplianceProcessingProperty"
            }
        }
        else {
            Write-Array -Status " Info" -Test " CheckAllowUpdateComplianceProcessing" -Result " AllowUpdateComplianceProcessing value is empty"
        }
    }     
    Catch {
        $_.exception.message
        Write-Array -Status " Warning" -Test " CheckAllowUpdateComplianceProcessing" -Result " Unexpected Exception when gathering AllowUpdateComplianceProcessing registry value" 
    }
}

function WE-CheckAllowWUfBCloudProcessing {
    $vAllowWUfBCloudProcessingPath = " HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"
    
    Try {
        
        $WEAllowWUfBCloudProcessingProperty = (Get-ItemProperty -Path $vAllowWUfBCloudProcessingPath -Name AllowWUfBCloudProcessing -ErrorAction SilentlyContinue).AllowWUfBCloudProcessing
       
        if (($WEAllowWUfBCloudProcessingProperty -ne $null) -or ($WEAllowWUfBCloudProcessingProperty -eq [string]::Empty)) {

            if ($WEAllowWUfBCloudProcessingProperty -isnot [Int32]) {
                Write-Array -Status " Warning" -Test " CheckAllowWUfBCloudProcessing" -Result " Invalid value for AllowWUfBCloudProcessing"   
            }
            if (-not ([int]$WEAllowWUfBCloudProcessingProperty -eq 8 )) {
                Write-Array -Status " Warning" -Test " CheckAllowWUfBCloudProcessing" -Result " AllowWUfBCloudProcessing value is $WEAllowWUfBCloudProcessingProperty"  
            }
            else {
                Write-Array -Status " Passed" -Test " CheckAllowWUfBCloudProcessing" -Result " AllowWUfBCloudProcessing value is $WEAllowWUfBCloudProcessingProperty"
            }
        }
        else {
            Write-Array -Status " Info" -Test " CheckAllowWUfBCloudProcessing" -Result " AllowWUfBCloudProcessing value is empty"
        }
    }     
    Catch {
        $_.exception.message
        Write-Array -Status " Warning" -Test " CheckAllowWUfBCloudProcessing" -Result " Unexpected Exception when gathering AllowWUfBCloudProcessing registry value" 
    }
}

function WE-CheckConfigureTelemetryOptInChangeNotification {
    $vConfigureTelemetryOptInChangeNotificationPath = " HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"
    
    Try {
        
        $WEConfigureTelemetryOptInChangeNotificationProperty = (Get-ItemProperty -Path $vConfigureTelemetryOptInChangeNotificationPath -Name ConfigureTelemetryOptInChangeNotification -ErrorAction SilentlyContinue).ConfigureTelemetryOptInChangeNotification
       
        if (($WEConfigureTelemetryOptInChangeNotificationProperty -ne $null) -or ($WEConfigureTelemetryOptInChangeNotificationProperty -eq [string]::Empty)) {

            if ($WEConfigureTelemetryOptInChangeNotificationProperty -isnot [Int32]) {
                Write-Array -Status " Warning" -Test " CheckConfigureTelemetryOptInChangeNotification" -Result " Invalid value for ConfigureTelemetryOptInChangeNotification"   
            }
            if (-not ([int]$WEConfigureTelemetryOptInChangeNotificationProperty -eq 1 )) {
                Write-Array -Status " Warning" -Test " CheckConfigureTelemetryOptInChangeNotification" -Result " ConfigureTelemetryOptInChangeNotification value is $WEConfigureTelemetryOptInChangeNotificationProperty"  
            }
            else {
                Write-Array -Status " Passed" -Test " CheckConfigureTelemetryOptInChangeNotification" -Result " ConfigureTelemetryOptInChangeNotification value is $WEConfigureTelemetryOptInChangeNotificationProperty"
            }
        }
        else {
            Write-Array -Status " Info" -Test " CheckConfigureTelemetryOptInChangeNotification" -Result " ConfigureTelemetryOptInChangeNotification value is empty"
        }
    }     
    Catch {
        $_.exception.message
        Write-Array -Status " Warning" -Test " CheckConfigureTelemetryOptInChangeNotification" -Result " Unexpected Exception when gathering ConfigureTelemetryOptInChangeNotification registry value" 
    }
}

function WE-CheckConfigureTelemetryOptInSettingsUx {
   ;  $vConfigureTelemetryOptInChangeNotificationPath = " HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"
    
    Try {
        
       ;  $WEConfigureTelemetryOptInChangeNotificationProperty = (Get-ItemProperty -Path $vConfigureTelemetryOptInChangeNotificationPath -Name ConfigureTelemetryOptInSettingsUx -ErrorAction SilentlyContinue).ConfigureTelemetryOptInSettingsUx
       
        if (($WEConfigureTelemetryOptInChangeNotificationProperty -ne $null) -or ($WEConfigureTelemetryOptInChangeNotificationProperty -eq [string]::Empty)) {

            if ($WEConfigureTelemetryOptInChangeNotificationProperty -isnot [Int32]) {
                Write-Array -Status " Warning" -Test " CheckConfigureTelemetryOptInSettingsUx" -Result " Invalid value for ConfigureTelemetryOptInSettingsUx"   
            }
            if (-not ([int]$WEConfigureTelemetryOptInChangeNotificationProperty -eq 1 )) {
                Write-Array -Status " Warning" -Test " CheckConfigureTelemetryOptInSettingsUx" -Result " ConfigureTelemetryOptInSettingsUx value is $WEConfigureTelemetryOptInChangeNotificationProperty"  
            }
            else {
                Write-Array -Status " Passed" -Test " CheckConfigureTelemetryOptInSettingsUx" -Result " ConfigureTelemetryOptInSettingsUx value is $WEConfigureTelemetryOptInChangeNotificationProperty"
            }
        }
        else {
            Write-Array -Status " Info" -Test " CheckConfigureTelemetryOptInSettingsUx" -Result " ConfigureTelemetryOptInSettingsUx value is empty"
        }
    }     
    Catch {
        $_.exception.message
        Write-Array -Status " Warning" -Test " CheckConfigureTelemetryOptInSettingsUx" -Result " Unexpected Exception when gathering ConfigureTelemetryOptInSettingsUx registry value" 
    }
}

&$main


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================