<#
.SYNOPSIS
    Invoke Bitlockerkeyissueremediation

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
    We Enhanced Invoke Bitlockerkeyissueremediation

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
    This script retrieves the Bitlocker keys from the enterprise API and optionally deletes the x oldest keys if the total count exceeds the specified
    threshold value or the maximum of 200 keys.

.DESCRIPTION
This script retrieves BitLocker recovery keys from the enterprise API and deletes the oldest keys if the total count exceeds a threshold. 
The script also enforces BitLocker encryption on the OS drive if no keys are found and the FVE policy is enforced, and backs up BitLocker keys to Entra.
It does not require authetnication to Graph as it uses the MS-Organization-Access certificate to access the enterprise API.

Created on:   2025-03-13
Updated on:   2025-03-20
Created by:   Ben Whitmore / Rudy Ooms @PatchMyPC
Contributors: Maurice Daly
Filename:     Invoke-BitLockerKeyIssueDetection.ps1

    ---------------------------------------------------------------------------------
LEGAL DISCLAIMER

The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------

.NOTES
    Requires admin privileges and an MS-Organization-Access certificate. When running as a remediation script, the script should be run as SYSTEM.



$WELogDirectory = " $env:SystemDrive\ProgramData\Microsoft\IntuneManagementExtension\Logs"


$WEKeysToDeleteCount = 10
$WEKeyHighWaterMark = 20
$WEKeyCriticalWaterMark = 200





function global:Write-LogEntry {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true,
            HelpMessage = 'Value added to the log file.')]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEValue,
        [Parameter(Mandatory = $false,
            HelpMessage = 'Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.')]
        [ValidateSet('1', '2', '3')]
        [ValidateNotNullOrEmpty()]
        [string]$WESeverity = '1',
        [Parameter(Mandatory = $false,
            HelpMessage = 'Name of the log file that the entry will written to.')]
        [ValidateNotNullOrEmpty()]
        [string]$WELogFileName = " PMPC-BitLockerMaintenance.log" ,
        [switch]$WEUpdateUI
    )
	
    # Determine log file location
    $script:LogFilePath = Join-Path -Path $WELogDirectory -ChildPath $WELogFileName
	
    # Construct time stamp for log entry
    $WETime = -join @((Get-Date -Format " HH:mm:ss.fff" ), " " , (Get-CimInstance -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
	
    # Construct date for log entry
    $WEDate = (Get-Date -Format " MM-dd-yyyy" )
	
    # Construct context for log entry
    $WEContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	
    # Construct final log entry
    $WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" PMPC-BitLockerMaintenance"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
	
    # Add value to log file
    try {
        #Write-Output " $($WEValue)"
        Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
    } catch [System.Exception] {
        Write-Warning -Message " Unable to append log entry to PMPC-BitLockerMaintenance.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}

[CmdletBinding()]
function WE-Invoke-BitLockerKeyRemoval {
    # Get BitLocker recovery keys from manage-bde for all volumes
    $WEBitLockerKeys = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.KeyProtector -ne $null } | Select-Object -ExpandProperty KeyProtector
    $WEBitLockerKeyProtectorIds = $WEBitLockerKeys | Where-Object { $_.KeyProtectorType -eq " RecoveryPassword" } | Select-Object -ExpandProperty KeyProtectorId
    # Remove {} from $WEBitLockerKeyProtectors
    $WEBitLockerKeyProtectorIds = $WEBitLockerKeyProtectors -replace '[{}]', ''

    # Remove all BitLocker keys which are not in the $WEBitLockerKeyProtectors
    $WEKeyIdsToDelete = $WEResults | Where-Object { $_.KeyId -notin $WEBitLockerKeyProtectorIds } | Select-Object -ExpandProperty KeyId -Unique

    # Delete BitLocker keys if the $keysToDelete count is greater than 0
    if ($WEKeyIdsToDelete.Count -gt 0) {
        Write-LogEntry -Value " [BitLocker Key Deletion] - Removing $($WEKeysToDelete.Count) BitLocker keys" -Severity 1
        try {           

            # Create a foreach loop to delete keys in batches of 15
            $WEBatchCount = 15
            $WETotalBatchCount = $WEKeyIdsToDelete.Count
            $WEBatchMarker = 0

            # Check if the number of keys to delete is greater than the initial batch size
            # Create a while loop to delete keys in batches of 15
            while ($WEBatchMarker -lt $WETotalBatchCount) {
                # Determine the number of keys to delete in this batch
                $WERemainingKeys = $WETotalBatchCount - $WEBatchMarker
                $WEKeysToDeleteCount = if ($WERemainingKeys -lt $WEBatchCount) { $WERemainingKeys } else { $WEBatchCount }

                # Get the keys to delete for this batch
                $WEKeysToDelete = $WEKeyIdsToDelete[$WEBatchMarker..($WEBatchMarker + $WEKeysToDeleteCount - 1)]

                # Create the body for the API request
               ;  $WEDeleteBody = @{ " kids" = $WEKeysToDelete } | ConvertTo-Json -Compress
               ;  $WEDeleteResponse = Invoke-WebRequest -Uri $WEBitLockerDeleteURL -Method Delete -Headers $WEHeaders -Certificate $WECertificate -Body $WEDeleteBody -ContentType " application/json" -UseBasicParsing

                if ($WEDeleteResponse.StatusCode -eq " 200" ) {
                    Write-LogEntry -Value " - Successfully deleted $($WEKeysToDelete.Count) BitLocker Recovery Keys" -Severity 1

                    # Increment the batch marker by the number of keys processed
                   ;  $WEBatchMarker = $WEBatchMarker + $WEKeysToDeleteCount
                } else {
                    Write-LogEntry -Value " [Error] - Error deleting BitLocker keys: $($WEDeleteResponse.StatusCode)" -Severity 3; exit 1
                }
            }

            # Check if the response status code is 200
            if ($WEDeleteResponse.StatusCode -eq " 200" ) {
                Write-LogEntry -Value " - Successfully deleted $($WEKeyIdsToDelete.Count) BitLocker Recovery Keys" -Severity 1
                
                # Resume the BitLocker encryption process
                Write-LogEntry -Value " [BitLocker Protection] - Resuming BitLocker encryption on volumes in a degraded state or where protection is disabled." -Severity 1
                $WEBitLockerVolumes = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeStatus -eq " Degraded" -or $_.ProtectionStatus -eq " Off" }
                if ($WEBitLockerVolumes) {
                    foreach ($WEVolume in $WEBitLockerVolumes) {
                        try {
                            Write-LogEntry -Value " - Resuming BitLocker encryption on volume: $($WEVolume.MountPoint)" -Severity 1
                            Resume-BitLocker -MountPoint $WEVolume.MountPoint
                        } catch {
                            Write-LogEntry -Value " [Error] - Failed to resume BitLocker encryption on volume: $($WEVolume.MountPoint). Error: $($_.Exception.Message)" -Severity 2
                        }
                    }
                } else {
                    Write-LogEntry -Value " - No BitLocker volumes found in a degraded state." -Severity 1
                }

                # Check if there are any BitLocker volumes with key protectors
               ;  $WEBitLockerVolumes = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.KeyProtector -ne $null }

                # Force BitLocker key escrow to Entra
                if ($WEBitLockerVolumes) {
                    Write-LogEntry -Value " [BitLocker Key Escrow] - Backing up BitLocker keys to Entra" -Severity 1
                    foreach ($WEVolume in $WEBitLockerVolumes) {
                        Write-LogEntry -Value " - Processing volume: $($WEVolume.MountPoint)" -Severity 1

                        # Get all key protectors for the volume
                       ;  $WEKeyProtectors = $WEVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq " RecoveryPassword" }

                        # Backup each key protector to Entra
                        foreach ($WEKeyProtector in $WEKeyProtectors) {
                            try {
                                Write-LogEntry -Value " - Backing up key protector with ID: $($WEKeyProtector.KeyProtectorId)" -Severity 1 
                                BackupToAAD-BitLockerKeyProtector -MountPoint $WEVolume.MountPoint -KeyProtectorId $WEKeyProtector.KeyProtectorId
                                Write-LogEntry -Value " - Successfully backed up key protector with ID: $($WEKeyProtector.KeyProtectorId)" -Severity 1
                            } catch {
                                Write-LogEntry -Value " - Failed to back up key protector with ID: $($WEKeyProtector.KeyProtectorId). Error: $($_.Exception.Message)" -Severity 3; exit 1
                            }
                        }
                    }
                    Write-LogEntry -Value " [BitLocker Key Escrow] - Successfully backed up BitLocker keys to Entra" -Severity 1; exit 0
                } else {
                    Write-LogEntry -Value " [Warning] - No BitLocker volumes with key protectors found." -Severity 2; exit 0
                }  
            } else {
                Write-LogEntry -Value " [Error] - Error deleting BitLocker keys: $($WEDeleteResponse.StatusCode)" -Severity 3; exit 1
            }   
        } catch {
            Write-LogEntry -Value " [Error] - Failed to delete BitLocker Recovery Keys. Error: $_" -Severity 3; exit 1
        }
    } else {
        Write-LogEntry -Value " - No BitLocker keys to delete." -Severity 1; exit 0
    }
}



Write-LogEntry -Value " [BitLocker Key Maintenance] - Starting key remediation process" -Severity 1
Write-LogEntry -Value " - Obtaining certificate for BitLocker key retrieval" -Severity 1

try {
    # Retrieve the MS-Organization-Access certificate
    $WECertificate = Get-ChildItem -ErrorAction Stop Cert:\LocalMachine\My | Where-Object { $_.Issuer -like " *MS-Organization-Access*" } | Select-Object -First 1
} catch {
    Write-LogEntry -Value " [Certificate Error] - MS-Organization-Access certificate not found. $($_.Exception.Message)]" -Severity 3; exit 1
}


if ($WECertificate) {
    Write-LogEntry -Value " [Certificate] - MS-Organization-Access certificate found." -Severity 1
    # Extract Device ID from the certificate subject
    Write-LogEntry -Value " - Attempting to extract Device ID from the certificate subject" -Severity 1
    if ($WECertificate.Subject -match " CN=([a-f0-9\-]+)" ) {
        $WEDeviceId = $matches[1]

        # Construct API request details
        $WEBitLockerUrl = " https://enterpriseregistration.windows.net/manage/common/bitlocker/$WEDeviceId"
        $WEBitLockerDeleteURL = " https://enterpriseregistration.windows.net/manage/common/bitlocker/$deviceId"
       ;  $WEHeaders = @{
            " User-Agent"              = " BitLocker/10.0.27783 (Windows)"
            " Accept"                  = " application/json"
            " ocp-adrs-client-name"    = " Windows"
            " ocp-adrs-client-version" = " 10.0.27783"
        }

       ;  $WEResults = @()

        if (-not([string]::IsNullOrEmpty($WEDeviceId))) {
            Write-LogEntry -Value " - Device ID extracted from certificate subject: $WEDeviceId" -Severity 1
        } else {
            Write-LogEntry -Value " [Error] - Unable to extract Device ID from the certificate." -Severity 3; exit 1
        }
    }
} else {
    Write-LogEntry -Value " [Certificate Error] - MS-Organization-Access certificate not found." -Severity 3; exit 1
}


try {
    Write-LogEntry -Value " [BitLocker API] - Retrieving BitLocker key details from enterprise API" -Severity 1
    $WEResponse = Invoke-WebRequest -Uri $WEBitLockerUrl -Method GET -Headers $WEHeaders -Certificate $WECertificate -UseBasicParsing
    if ($WEResponse.StatusCode -eq " 200" ) {
        Write-LogEntry -Value " - Successfully queried API URI ($WEBitLockerUrl) with status code $($WEReponse.StatusCode)" -Severity 1
        Write-LogEntry -Value " - Parsing BitLocker key details" -Severity 1
       ;  $WEKeyData = $WEResponse.Content | ConvertFrom-Json
        if ($WEKeyData.keys) {
            foreach ($WEKey in $WEKeyData.keys) {
               ;  $WEResults = $WEResults + [PSCustomObject]@{
                    KeyId        = $WEKey.kid
                    CreationTime = $WEKey.creationtime
                    VolumeType   = $WEKey.volumetype
                }
            }
        } else {
            Write-LogEntry -Value " - No BitLocker keys found for this device. Flagging for remediation to enforce BitLocker encryption" -Severity 1; exit 1
        }
    } else {
        Write-LogEntry -Value " [Error] - Error retrieving communicating with API URI ($WEBitLockerUrl): $($WEResponse.StatusCode)" -Severity 3; exit 1
    }


} catch {
    Write-LogEntry -Value " [Error] - Error retrieving BitLocker key details: $($_.Exception.Message)" -Severity 3; exit 1
}


if ($WEResults.Count -gt 0) {
    Write-LogEntry -Value " - BitLocker key details retrieved successfully" -Severity 1
    Write-LogEntry -Value " - Found $($WEResults.Count) BitLocker keys" -Severity 1
    Write-LogEntry -Value " - Checking key count against configured thresholds" -Severity 1
    if ($WEResults.Count -ge $WEKeyHighWaterMark) {
        if ($WEResults.Count -ge $WEKeyCriticalWaterMark) {
            Write-LogEntry -Value " [Critical] - Number of BitLocker keys exceeds the configured max value of $WEKeyCriticalWaterMark" -Severity 3
            # Call the function to delete the oldest keys
            Invoke-BitLockerKeyRemoval
        } else {
            Write-LogEntry -Value " [Warning] - Number of BitLocker keys exceeds the configured max value of $WEKeyHighWaterMark" -Severity 2
            # Call the function to delete the oldest keys
            Invoke-BitLockerKeyRemoval
        }
    } else {
        Write-LogEntry -Value " [Healthy State] - Key count is $($WEResults.Count), which is less than $WEKeyHighWaterMark. No action required." -Severity 1; exit 0
    }
} else {
    # Check if BitLocker encryption should be enforced from the FVE registry key
    if ((Test-Path -Path " HKLM:\SOFTWARE\Policies\Microsoft\FVE" ) -eq $true) {
        # Check if the OSEncrpytionType is set to 1
        $WEOSEncryptionType = Get-ItemProperty -Path " HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name " OSEncryptionType" -ErrorAction SilentlyContinue
        if ($WEOSEncryptionType.OSEncryptionType -eq 1) {
            Write-LogEntry -Value " [Warning] - BitLocker policy enforced, however, no keys are found. Enforcing BitLokcer on OS drive" -Severity 2
            Enable-BitLocker -MountPoint " C:" -EncryptionMethod XtsAES256 -UsedSpaceOnly -SkipHardwareTest -TpmProtector | Out-Null
            Enable-BitLocker -MountPoint " C:" -EncryptionMethod XtsAES256 -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector | Out-Null
            BackupToAAD-BitLockerKeyProtector -MountPoint " C:" -KeyProtectorId $WEBitLockerVolume.KeyProtector[1].KeyProtectorId -ErrorAction SilentlyContinue
        } else {
            Write-LogEntry -Value " [Healthy State] - BitLocker policy not enforced for OS drive." -Severity 1; exit 0
        }
    } else {
        Write-LogEntry -Value " [Healthy State] - No BitLocker keys found and BitLocker encryption is not enforced. No action required." -Severity 1; exit 0
    }
}








# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================