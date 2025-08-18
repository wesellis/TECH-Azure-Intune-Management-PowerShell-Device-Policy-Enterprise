<#
.SYNOPSIS
    Enable Bitlockerencryption

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
    We Enhanced Enable Bitlockerencryption

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
    Enable BitLocker with both TPM and recovery password key protectors on Windows 10 devices.

.DESCRIPTION
    Enable BitLocker with both TPM and recovery password key protectors on Windows 10 devices.

.PARAMETER EncryptionMethod
    Define the encryption method to be used when enabling BitLocker.

.PARAMETER OperationalMode
    Set the operational mode of this script.

.PARAMETER CompanyName
    Set the company name to be used as registry root when running in Backup mode.

.NOTES
    FileName:    Enable-BitLockerEncryption.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-10-29
    Updated:     2020-01-13

    Version history:
    1.0.0 - (2019-10-29) Script created
    1.0.1 - (2020-01-03) Added functionality to check if TPM chip is owned and take ownership if it's not
    1.0.2 - (2020-01-13) Added functionality to create a schedule task that runs at user logon in case the escrow of the recovery key to AAD device object failed due to device not being registered at the time

[CmdletBinding(SupportsShouldProcess = $true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $false, HelpMessage = " Define the encryption method to be used when enabling BitLocker." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" Aes128" , " Aes256" , " XtsAes128" , " XtsAes256" )]
    [string]$WEEncryptionMethod = " XtsAes256" ,

    [parameter(Mandatory = $false, HelpMessage = " Set the operational mode of this script." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" Encrypt" , " Backup" )]
    [string]$WEOperationalMode = " Encrypt" ,

    [parameter(Mandatory = $false, HelpMessage = " Set the company name to be used as registry root when running in Backup mode." )]
    [ValidateNotNullOrEmpty()]
    [string]$WECompanyName = " SCConfigMgr"
)
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
		$WELogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath " Temp" ) -ChildPath " Enable-BitLockerEncryption.log"
		
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
		$WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" BitLockerEncryption"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
		
		# Add value to log file
		try {
			Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
		}
		catch [System.Exception] {
			Write-Warning -Message " Unable to append log entry to Enable-BitLockerEncryption.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
		}
    }
    
    function WE-Invoke-Executable {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Specify the file name or path of the executable to be invoked, including the extension" )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEFilePath,

            [parameter(Mandatory = $false, HelpMessage = " Specify arguments that will be passed to the executable" )]
            [ValidateNotNull()]
            [string]$WEArguments
        )
        
        # Construct a hash-table for default parameter splatting
        $WESplatArgs = @{
            FilePath = $WEFilePath
            NoNewWindow = $true
            Passthru = $true
            RedirectStandardOutput = " null.txt"
            ErrorAction = " Stop"
        }
        
        # Add ArgumentList param if present
        if (-not ([System.String]::IsNullOrEmpty($WEArguments))) {
            $WESplatArgs.Add(" ArgumentList" , $WEArguments)
        }
        
        # Invoke executable and wait for process to exit
        try {
           ;  $WEInvocation = Start-Process @SplatArgs
           ;  $WEHandle = $WEInvocation.Handle
            $WEInvocation.WaitForexit $1
    
            # Remove redirected output file
            Remove-Item -Path (Join-Path -Path $WEPSScriptRoot -ChildPath " null.txt" ) -Force
    
        }
        catch [System.Exception] {
            Write-Warning -Message $_.Exception.Message; break
        }
        
        return $WEInvocation.ExitCode
    }

    function WE-Test-RegistryValue {
        [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath,
    
            [parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            [string]$WEName
        )
        # If item property value exists return True, else catch the failure and return False
        try {
            if ($WEPSBoundParameters[" Name" ]) {
                $WEExistence = Get-ItemProperty -Path $WEPath | Select-Object -ExpandProperty $WEName -ErrorAction Stop
            }
            else {
                $WEExistence = Get-ItemProperty -Path $WEPath -ErrorAction Stop
            }
            
            if ($WEExistence -ne $null) {
                return $true
            }
        }
        catch [System.Exception] {
            return $false
        }
    }
    
    function WE-Set-RegistryValue {
        [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath,
    
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEName,        
    
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WEValue
        )
        try {
            $WERegistryValue = Get-ItemProperty -Path $WEPath -Name $WEName -ErrorAction SilentlyContinue
            if ($WERegistryValue -ne $null) {
                Set-ItemProperty -Path $WEPath -Name $WEName -Value $WEValue -Force -ErrorAction Stop
            }
            else {
                New-ItemProperty -Path $WEPath -Name $WEName -PropertyType String -Value $WEValue -Force -ErrorAction Stop | Out-Null
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value " Failed to create or update registry value '$($WEName)' in '$($WEPath)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }    

    # Check if we're running as a 64-bit process or not
    if (-not[System.Environment]::Is64BitProcess) {
        # Get the sysnative path for powershell.exe
        $WESysNativePowerShell = Join-Path -Path ($WEPSHOME.ToLower().Replace(" syswow64" , " sysnative" )) -ChildPath " powershell.exe"

        # Construct new ProcessStartInfo object to restart powershell.exe as a 64-bit process and re-run scipt
        $WEProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $WEProcessStartInfo.FileName = $WESysNativePowerShell
        $WEProcessStartInfo.Arguments = " -ExecutionPolicy Bypass -File "" $($WEPSCommandPath)"""
        $WEProcessStartInfo.RedirectStandardOutput = $true
        $WEProcessStartInfo.RedirectStandardError = $true
        $WEProcessStartInfo.UseShellExecute = $false
        $WEProcessStartInfo.WindowStyle = " Hidden"
        $WEProcessStartInfo.CreateNoWindow = $true

        # Instatiate the new 64-bit process
        $WEProcess = [System.Diagnostics.Process]::Start($WEProcessStartInfo)

        # Read standard error output to determine if the 64-bit script process somehow failed
        $WEErrorOutput = $WEProcess.StandardError.ReadToEnd()
        if ($WEErrorOutput) {
            Write-Error -Message $WEErrorOutput
        }
    }
    else {
        try {
            # Define the company registry root key
            $WERegistryRootPath = " HKLM:\SOFTWARE\$($WECompanyName)"
            if (-not(Test-RegistryValue -Path $WERegistryRootPath)) {
                Write-LogEntry -Value " Attempting to create registry root path for recovery password escrow results" -Severity 1
                New-Item -Path $WERegistryRootPath -ItemType Directory -Force -ErrorAction Stop
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value " An error occurred while creating registry root item '$($WERegistryRootPath)'. Error message: $($_.Exception.Message)" -Severity 3
        }
        
        # Switch execution context depending on selected operational mode for the script as parameter input
        switch ($WEOperationalMode) {
            " Encrypt" {
                Write-LogEntry -Value " Current operational mode for script: $($WEOperationalMode)" -Severity 1

                try {
                    # Import required module for managing BitLocker
                    Import-Module -Name " BitLocker" -DisableNameChecking -Verbose:$false -ErrorAction Stop
        
                    try {
                        # Check if TPM chip is currently owned, if not take ownership
                        $WETPMClass = Get-CimInstance -Namespace " root\cimv2\Security\MicrosoftTPM" -Class " Win32_TPM"
                        $WEIsTPMOwned = $WETPMClass.IsOwned().IsOwned
                        if ($WEIsTPMOwned -eq $false) {
                            Write-LogEntry -Value " TPM chip is currently not owned, value from WMI class method 'IsOwned' was: $($WEIsTPMOwned)" -Severity 1
                            
                            # Generate a random pass phrase to be used when taking ownership of TPM chip
                            $WENewPassPhrase = (New-Guid).Guid.Replace(" -" , "" ).SubString(0, 14)
        
                            # Construct owner auth encoded string
                            $WENewOwnerAuth = $WETPMClass.ConvertToOwnerAuth($WENewPassPhrase).OwnerAuth
        
                            # Attempt to take ownership of TPM chip
                            $WEInvocation = $WETPMClass.TakeOwnership($WENewOwnerAuth)
                            if ($WEInvocation.ReturnValue -eq 0) {
                                Write-LogEntry -Value " TPM chip ownership was successfully taken" -Severity 1
                            }
                            else {
                                Write-LogEntry -Value " Failed to take ownership of TPM chip, return value from invocation: $($WEInvocation.ReturnValue)" -Severity 3
                            }
                        }
                        else {
                            Write-LogEntry -Value " TPM chip is currently owned, will not attempt to take ownership" -Severity 1
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value " An error occurred while taking ownership of TPM chip. Error message: $($_.Exception.Message)" -Severity 3
                    }
        
                    try {
                        # Retrieve the current encryption status of the operating system drive
                        Write-LogEntry -Value " Attempting to retrieve the current encryption status of the operating system drive" -Severity 1
                        $WEBitLockerOSVolume = Get-BitLockerVolume -MountPoint $env:SystemRoot -ErrorAction Stop
        
                        if ($WEBitLockerOSVolume -ne $null) {
                            # Determine whether BitLocker is turned on or off
                            if (($WEBitLockerOSVolume.VolumeStatus -like " FullyDecrypted" ) -or ($WEBitLockerOSVolume.KeyProtector.Count -eq 0)) {
                                Write-LogEntry -Value " Current encryption status of the operating system drive was detected as: $($WEBitLockerOSVolume.VolumeStatus)" -Severity 1
        
                                try {
                                    # Enable BitLocker with TPM key protector
                                    Write-LogEntry -Value " Attempting to enable BitLocker protection with TPM key protector for mount point: $($env:SystemRoot)" -Severity 1
                                    Enable-BitLocker -MountPoint $WEBitLockerOSVolume.MountPoint -TpmProtector -UsedSpaceOnly -EncryptionMethod $WEEncryptionMethod -SkipHardwareTest -ErrorAction Stop
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value " An error occurred while enabling BitLocker with TPM key protector for mount point '$($env:SystemRoot)'. Error message: $($_.Exception.Message)" -Severity 3
                                }
        
                                try {
                                    # Enable BitLocker with recovery password key protector
                                    Write-LogEntry -Value " Attempting to enable BitLocker protection with recovery password key protector for mount point: $($env:SystemRoot)" -Severity 1
                                    Enable-BitLocker -MountPoint $WEBitLockerOSVolume.MountPoint -RecoveryPasswordProtector -UsedSpaceOnly -EncryptionMethod $WEEncryptionMethod -SkipHardwareTest -ErrorAction Stop
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value " An error occurred while enabling BitLocker with recovery password key protector for mount point '$($env:SystemRoot)'. Error message: $($_.Exception.Message)" -Severity 3
                                }
                            }
                            elseif (($WEBitLockerOSVolume.VolumeStatus -like " FullyEncrypted" ) -or ($WEBitLockerOSVolume.VolumeStatus -like " UsedSpaceOnly" )) {
                                Write-LogEntry -Value " Current encryption status of the operating system drive was detected as: $($WEBitLockerOSVolume.VolumeStatus)" -Severity 1
                                Write-LogEntry -Value " Validating that all desired key protectors are enabled" -Severity 1
        
                                # Validate that not only the TPM protector is enabled, add recovery password protector
                                if ($WEBitLockerOSVolume.KeyProtector.Count -lt 2) {
                                    if ($WEBitLockerOSVolume.KeyProtector.KeyProtectorType -like " Tpm" ) {
                                        Write-LogEntry -Value " Recovery password key protector is not present" -Severity 1
        
                                        try {
                                            # Enable BitLocker with TPM key protector
                                            Write-LogEntry -Value " Attempting to enable BitLocker protection with recovery password key protector for mount point: $($env:SystemRoot)" -Severity 1
                                            Enable-BitLocker -MountPoint $WEBitLockerOSVolume.MountPoint -RecoveryPasswordProtector -UsedSpaceOnly -EncryptionMethod $WEEncryptionMethod -SkipHardwareTest -ErrorAction Stop
                                        }
                                        catch [System.Exception] {
                                            Write-LogEntry -Value " An error occurred while enabling BitLocker with TPM key protector for mount point '$($env:SystemRoot)'. Error message: $($_.Exception.Message)" -Severity 3
                                        }
                                    }
        
                                    if ($WEBitLockerOSVolume.KeyProtector.KeyProtectorType -like " RecoveryPassword" ) {
                                        Write-LogEntry -Value " TPM key protector is not present" -Severity 1
        
                                        try {
                                            # Add BitLocker recovery password key protector
                                            Write-LogEntry -Value " Attempting to enable BitLocker protection with TPM key protector for mount point: $($env:SystemRoot)" -Severity 1
                                            Enable-BitLocker -MountPoint $WEBitLockerOSVolume.MountPoint -TpmProtector -UsedSpaceOnly -EncryptionMethod $WEEncryptionMethod -SkipHardwareTest -ErrorAction Stop
                                        }
                                        catch [System.Exception] {
                                            Write-LogEntry -Value " An error occurred while enabling BitLocker with recovery password key protector for mount point '$($env:SystemRoot)'. Error message: $($_.Exception.Message)" -Severity 3
                                        }
                                    }                            
                                }
                                else {
                                    # BitLocker is in wait state
                                    Invoke-Executable -FilePath " manage-bde.exe" -Arguments " -On $($WEBitLockerOSVolume.MountPoint) -UsedSpaceOnly"
                                }                        
                            }
                            else {
                                Write-LogEntry -Value " Current encryption status of the operating system drive was detected as: $($WEBitLockerOSVolume.VolumeStatus)" -Severity 1
                            }
        
                            # Validate that previous configuration was successful and all key protectors have been enabled and encryption is on
                            $WEBitLockerOSVolume = Get-BitLockerVolume -MountPoint $env:SystemRoot
        
                            # Wait for encryption to complete
                            if ($WEBitLockerOSVolume.VolumeStatus -like " EncryptionInProgress" ) {
                                do {
                                    $WEBitLockerOSVolume = Get-BitLockerVolume -MountPoint $env:SystemRoot
                                    Write-LogEntry -Value " Current encryption percentage progress: $($WEBitLockerOSVolume.EncryptionPercentage)" -Severity 1
                                    Write-LogEntry -Value " Waiting for BitLocker encryption progress to complete, sleeping for 15 seconds" -Severity 1
                                    Start-Sleep -Seconds 15
                                }
                                until ($WEBitLockerOSVolume.EncryptionPercentage -eq 100)
                                Write-LogEntry -Value " Encryption of operating system drive has now completed" -Severity 1
                            }
        
                            if (($WEBitLockerOSVolume.VolumeStatus -like " FullyEncrypted" ) -and ($WEBitLockerOSVolume.KeyProtector.Count -eq 2)) {
                                try {
                                    # Attempt to backup recovery password to Azure AD device object
                                    Write-LogEntry -Value " Attempting to backup recovery password to Azure AD device object" -Severity 1
                                    $WERecoveryPasswordKeyProtector = $WEBitLockerOSVolume.KeyProtector | Where-Object { $_.KeyProtectorType -like " RecoveryPassword" }
                                    if ($WERecoveryPasswordKeyProtector -ne $null) {
                                        BackupToAAD-BitLockerKeyProtector -MountPoint $WEBitLockerOSVolume.MountPoint -KeyProtectorId $WERecoveryPasswordKeyProtector.KeyProtectorId -ErrorAction Stop
                                        Write-LogEntry -Value " Successfully backed up recovery password details" -Severity 1
                                    }
                                    else {
                                        Write-LogEntry -Value " Unable to determine proper recovery password key protector for backing up of recovery password details" -Severity 2
                                    }
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value " An error occurred while attempting to backup recovery password to Azure AD. Error message: $($_.Exception.Message)" -Severity 3

                                    # Copy executing script to system temporary directory
                                    Write-LogEntry -Value " Attempting to copy executing script to system temporary directory" -Severity 1
                                    $WESystemTemp = Join-Path -Path $env:SystemRoot -ChildPath " Temp"
                                    if (-not(Test-Path -Path (Join-Path -Path $WESystemTemp -ChildPath " $($WEMyInvocation.MyCommand.Name)" ) -PathType Leaf)) {
                                        try {
                                            # Copy executing script
                                            Write-LogEntry -Value " Copying executing script to staging folder for scheduled task usage" -Severity 1
                                            Copy-Item $WEMyInvocation.MyCommand.Definition -Destination $WESystemTemp -ErrorAction Stop

                                            try {
                                                # Create escrow scheduled task to backup recovery password to Azure AD at a later time
                                                $WETaskAction = New-ScheduledTaskAction -Execute " powershell.exe" -Argument " -ExecutionPolicy Bypass -NoProfile -File $($WESystemTemp)\$($WEMyInvocation.MyCommand.Name) -OperationalMode Backup" -ErrorAction Stop
                                                $WETaskTrigger = New-ScheduledTaskTrigger -AtLogOn -ErrorAction Stop
                                                $WETaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden -DontStopIfGoingOnBatteries -Compatibility " Win8" -RunOnlyIfNetworkAvailable -MultipleInstances " IgnoreNew" -ErrorAction Stop
                                                $WETaskPrincipal = New-ScheduledTaskPrincipal -UserId " NT AUTHORITY\SYSTEM" -LogonType " ServiceAccount" -RunLevel " Highest" -ErrorAction Stop
                                                $WEScheduledTask = New-ScheduledTask -Action $WETaskAction -Principal $WETaskPrincipal -Settings $WETaskSettings -Trigger $WETaskTrigger -ErrorAction Stop
                                                Register-ScheduledTask -InputObject $WEScheduledTask -TaskName " Backup BitLocker Recovery Password to Azure AD" -TaskPath " \Microsoft" -ErrorAction Stop

                                                try {
                                                    # Attempt to create BitLocker recovery password escrow registry value
                                                    if (-not(Test-RegistryValue -Path $WERegistryRootPath -Name " BitLockerEscrowResult" )) {
                                                        Write-LogEntry -Value " Setting initial 'BitLockerEscrowResult' registry value to: None" -Severity 1
                                                        Set-RegistryValue -Path $WERegistryRootPath -Name " BitLockerEscrowResult" -Value " None"
                                                    }
                                                }
                                                catch [System.Exception] {
                                                    Write-LogEntry -Value " Unable to register scheduled task for backup of recovery password. Error message: $($_.Exception.Message)" -Severity 3
                                                }
                                            }
                                            catch [System.Exception] {
                                                Write-LogEntry -Value " Unable to register scheduled task for backup of recovery password. Error message: $($_.Exception.Message)" -Severity 3
                                            }
                                        }
                                        catch [System.Exception] {
                                            Write-LogEntry -Value " Unable to stage script in system temporary directory for scheduled task. Error message: $($_.Exception.Message)" -Severity 3
                                        }
                                    }
                                }
                            }
                            else {
                                Write-LogEntry -Value " Validation of current encryption status for operating system drive was not successful" -Severity 2
                                Write-LogEntry -Value " Current volume status for mount point '$($WEBitLockerOSVolume.MountPoint)': $($WEBitLockerOSVolume.VolumeStatus)" -Severity 2
                                Write-LogEntry -Value " Count of enabled key protectors for volume: $($WEBitLockerOSVolume.KeyProtector.Count)" -Severity 2
                            }
                        }
                        else {
                            Write-LogEntry -Value " Current encryption status query returned an empty result, this was not expected at this point" -Severity 2
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value " An error occurred while retrieving the current encryption status of operating system drive. Error message: $($_.Exception.Message)" -Severity 3
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value " An error occurred while importing the BitLocker module. Error message: $($_.Exception.Message)" -Severity 3
                }
            }
            " Backup" {
                Write-LogEntry -Value " Current operational mode for script: $($WEOperationalMode)" -Severity 1

                # Retrieve the current encryption status of the operating system drive
                $WEBitLockerOSVolume = Get-BitLockerVolume -MountPoint $env:SystemRoot

                # Attempt to backup recovery password to Azure AD device object if volume is encrypted
                if (($WEBitLockerOSVolume.VolumeStatus -like " FullyEncrypted" ) -and ($WEBitLockerOSVolume.KeyProtector.Count -eq 2)) {
                    try {
                        $WEBitLockerEscrowResultsValue = Get-ItemPropertyValue -Path $WERegistryRootPath -Name " BitLockerEscrowResult" -ErrorAction Stop
                        if ($WEBitLockerEscrowResultsValue -match " None|False" ) {
                            try {
                                Write-LogEntry -Value " Attempting to backup recovery password to Azure AD device object" -Severity 1
                               ;  $WERecoveryPasswordKeyProtector = $WEBitLockerOSVolume.KeyProtector | Where-Object { $_.KeyProtectorType -like " RecoveryPassword" }
                                if ($WERecoveryPasswordKeyProtector -ne $null) {
                                    BackupToAAD-BitLockerKeyProtector -MountPoint $WEBitLockerOSVolume.MountPoint -KeyProtectorId $WERecoveryPasswordKeyProtector.KeyProtectorId -ErrorAction Stop
                                    Set-RegistryValue -Path $WERegistryRootPath -Name " BitLockerEscrowResult" -Value " True"
                                    Write-LogEntry -Value " Successfully backed up recovery password details" -Severity 1
                                }
                                else {
                                    Write-LogEntry -Value " Unable to determine proper recovery password key protector for backing up of recovery password details" -Severity 2
                                }
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value " An error occurred while attempting to backup recovery password to Azure AD. Error message: $($_.Exception.Message)" -Severity 3
                                Set-RegistryValue -Path $WERegistryRootPath -Name " BitLockerEscrowResult" -Value " False"
                            }
                        }
                        else {
                            Write-LogEntry -Value " Value for 'BitLockerEscrowResults' was '$($WEBitLockerEscrowResultsValue)', will not attempt to backup recovery password once more" -Severity 1

                            try {
                                # Disable scheduled task
                               ;  $WEScheduledTask = Get-ScheduledTask -TaskName " Backup BitLocker Recovery Password to Azure AD" -ErrorAction Stop
                                Disable-ScheduledTask -InputObject $WEScheduledTask -ErrorAction Stop
                                Write-LogEntry -Value " Successfully disabled scheduled task named 'Backup BitLocker Recovery Password to Azure AD'" -Severity 1
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value " An error occurred while disabling scheduled task to backup recovery password. Error message: $($_.Exception.Message)" -Severity 3
                            }
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value " An error occurred while reading 'BitLockerEscrowResults' registry value. Error message: $($_.Exception.Message)" -Severity 3
                    }
                }
            }
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================