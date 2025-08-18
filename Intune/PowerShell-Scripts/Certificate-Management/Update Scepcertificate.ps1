<#
.SYNOPSIS
    Update Scepcertificate

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
    We Enhanced Update Scepcertificate

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
    Remove existing SCEP device certificate and enroll a new until subject name matches desired configuration.

.DESCRIPTION
    Remove existing SCEP device certificate and enroll a new until subject name matches desired configuration.

.NOTES
    FileName:    Update-SCEPCertificate.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-12-21
    Updated:     2020-04-24

    Version history:
    1.0.0 - (2019-12-21) Script created
    1.0.1 - (2020-04-24) Added to check for certificate with subject names matching CN=WIN in addition to CN=DESKTOP and CN=LAPTOP

Process {
    # Functions
    function WE-Write-CMLogEntry {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory=$true, HelpMessage=" Value added to the log file." )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEValue,
            
            [parameter(Mandatory=$true, HelpMessage=" Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error." )]
            [ValidateNotNullOrEmpty()]
            [ValidateSet(" 1" , " 2" , " 3" )]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESeverity,
            
            [parameter(Mandatory=$false, HelpMessage=" Name of the log file that the entry will written to." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEFileName = " SCEPCertificateUpdate.log"
        )
        # Determine log file location
        $WEWindowsTempLocation = (Join-Path -Path $env:windir -ChildPath " Temp" )
        $WELogFilePath = Join-Path -Path $WEWindowsTempLocation -ChildPath $WEFileName
        
        # Construct time stamp for log entry
        $WETime = -join @((Get-Date -Format " HH:mm:ss.fff" ), " +" , (Get-CimInstance -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $WEDate = (Get-Date -Format " MM-dd-yyyy" )
        
        # Construct context for log entry
        $WEContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" SCEPCertificateUpdate"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
        
        # Add value to log file and if specified console output
        try {
            if ($WEScript:PSBoundParameters[" Verbose" ]) {
                # Write either verbose or warning output to console
                switch ($WESeverity) {
                    1 {
                        Write-Verbose -Message $WEValue
                    }
                    default {
                        Write-Warning -Message $WEValue
                    }
                }

                # Write output to log file
                Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
            }
            else {
                # Write output to log file
                Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
            }
        }
        catch [System.Exception] {
            Write-Warning -Message " Unable to append log entry to SCEPCertificateUpdate.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function WE-Get-SCEPCertificate {
        do {
            $WESCEPCertificate = Get-ChildItem -Path " Cert:\LocalMachine\My" | Where-Object { ($_.Subject -match " CN=DESKTOP" ) -or ($_.Subject -match " CN=LAPTOP" ) -or ($_.Subject -match " CN=WIN" ) }
            if ($WESCEPCertificate -eq $null) {
                Write-CMLogEntry -Value " Unable to locate SCEP certificate, waiting 10 seconds before checking again" -Severity 2
                Start-Sleep -Seconds 10
            }
            else {
                Write-CMLogEntry -Value " Successfully located SCEP certificate with subject: $($WESCEPCertificate.Subject)" -Severity 1
                return $WESCEPCertificate
            }
        }
        until ($WESCEPCertificate -ne $null)
    }

    function WE-Remove-SCEPCertificate {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$WEInputObject
        )
        # Remove SCEP issued certificate
        Write-CMLogEntry -Value " Attempting to remove certificate with subject name: $($WEInputObject.Subject)" -Severity 1
        Remove-Item -Path $WEInputObject.PSPath -Force
    }

    function WE-Test-SCEPCertificate {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string[]]$WESubject
        )
        # Force a manual MDM policy sync
        Write-CMLogEntry -Value " Triggering manual MDM policy sync" -Severity 1
        Get-ScheduledTask | Where-Object { $_.TaskName -eq " PushLaunch" } | Start-ScheduledTask

        # Check if new SCEP issued certificate was successfully installed
        Write-CMLogEntry -Value " Attempting to check if SCEP certificate was successfully installed after a manual MDM policy sync" -Severity 1
        do {
            $WESCEPCertificateInstallEvent = Get-WinEvent -LogName " Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" | Where-Object { ($_.Id -like " 39" ) -and ($_.TimeCreated -ge (Get-Date).AddMinutes(-1)) }
        }
        until ($WESCEPCertificateInstallEvent -ne $null)
        Write-CMLogEntry -Value " SCEP certificate was successfully installed after a manual MDM policy sync, proceeding to validate it's subject name" -Severity 1

        # Attempt to locate SCEP issued certificate where the subject name matches either 'DESKTOP', 'LAPTOP' or 'WIN'
        $WESubjectNames = $WESubject -join " |"
        $WESCEPCertificate = Get-ChildItem -Path " Cert:\LocalMachine\My" | Where-Object { $_.Subject -match $WESubjectNames }
        if ($WESCEPCertificate -eq $null) {
            Write-CMLogEntry -Value " SCEP certificate subject name does not match, returning failure" -Severity 3
            return $false
        }
        else {
            Write-CMLogEntry -Value " SCEP certificate subject name matches desired input, returning success" -Severity 1
            return $true
        }
    }

    # Define the desired subject name matching patterns for a successful SCEP certificate installation
    $WESubjectNames = @(" CN=CL" , " CN=CORP" )

    # Attempt to locate and wait for SCEP issued certificate where the subject name matches either 'DESKTOP', 'LAPTOP' or 'WIN'
   ;  $WESCEPCertificateItem = Get-SCEPCertificate
    if ($WESCEPCertificateItem -ne $null) {
        # Remove existing SCEP issues certificate with subject name matching either 'DESKTOP', 'LAPTOP' or 'WIN'
        Remove-SCEPCertificate -InputObject $WESCEPCertificateItem

        # Validate that new certificate was installed and it contains the correct subject name
        do {
           ;  $WESCEPResult = Test-SCEPCertificate -Subject $WESubjectNames
            if ($WESCEPResult -eq $false) {
                # SCEP certificate installed did not match desired subject named, remove it and attempt to enroll a new
                Write-CMLogEntry -Value " Failed to validate SCEP certificate subject name, removing existing SCEP certificate" -Severity 3
                Remove-SCEPCertificate -InputObject (Get-SCEPCertificate)
            }
            else {
                Write-CMLogEntry -Value " Successfully validated desired SCEP certificate was successfully installed" -Severity 1
            }
        }
        until ($WESCEPResult -eq $true)
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================