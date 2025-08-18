<#
.SYNOPSIS
    Invoke Hpdriverupdate

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
    We Enhanced Invoke Hpdriverupdate

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
    Download and install the latest set of drivers and driver software from HP repository online using HP Image Assistant for current client device.

.DESCRIPTION
    This script will download and install the latest matching drivers and driver software from HP repository online using HP Image Assistant that will
    analyze what's required for the current client device it's running on.

.PARAMETER RunMode
    Select run mode for this script, either Stage or Execute.

.PARAMETER HPIAAction
    Specify the HP Image Assistant action to perform, e.g. Download or Install.

.EXAMPLE
    .\Invoke-HPDriverUpdate.ps1 -RunMode " Stage"

.NOTES
    FileName:    Invoke-HPDriverUpdate.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-08-12
    Updated:     2021-04-07

    Version history:
    1.0.0 - (2020-08-12) Script created
    1.0.1 - (2020-09-15) Added a fix for registering default PSGallery repository if not already registered
    1.0.2 - (2020-09-28) Added a new parameter HPIAAction that controls whether to Download or Install applicable drivers
    1.0.3 - (2021-04-07) Replaced Get-Softpaq -ErrorAction Stop cmdlet with a hard-coded softpaq number with the newly added Install-HPImageAssistant cmdlet in the HPCMSL module

[CmdletBinding(SupportsShouldProcess = $true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $true, HelpMessage = " Select run mode for this script, either Stage or Execute." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" Stage" , " Execute" )]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WERunMode,

    [parameter(Mandatory = $false, HelpMessage = " Specify the HP Image Assistant action to perform, e.g. Download or Install." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" Download" , " Install" )]
    [string]$WEHPIAAction = " Install"
)
Begin {
    # Enable TLS 1.2 support for downloading modules from PSGallery
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Process {
    # Functions
    [CmdletBinding()]
function WE-Write-LogEntry {
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
			[string]$WEFileName = " HPDriverUpdate.log"
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
		$WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" HPDriverUpdate"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
		
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
            }

            # Write output to log file
            Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
		}
		catch [System.Exception] {
			Write-Warning -Message " Unable to append log entry to HPDriverUpdate.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
		}
    }
    
    [CmdletBinding()]
function WE-Set-RegistryValue -ErrorAction Stop {
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
            [string]$WEValue
        )
        try {
            $WERegistryValue = Get-ItemProperty -Path $WEPath -Name $WEName -ErrorAction SilentlyContinue
            if ($null -ne $WERegistryValue) {
                Set-ItemProperty -Path $WEPath -Name $WEName -Value $WEValue -Force -ErrorAction Stop
            }
            else {
                if (-not(Test-Path -Path $WEPath)) {
                    New-Item -Path $WEPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
                New-ItemProperty -Path $WEPath -Name $WEName -PropertyType String -Value $WEValue -Force -ErrorAction Stop
            }
        }
        catch [System.Exception] {
            Write-Warning -Message " Failed to create or update registry value '$($WEName)' in '$($WEPath)'. Error message: $($_.Exception.Message)"
        }
    }

    [CmdletBinding()]
function WE-Invoke-Executable {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Specify the file name or path of the executable to be invoked, including the extension." )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEFilePath,
    
            [parameter(Mandatory = $false, HelpMessage = " Specify arguments that will be passed to the executable." )]
            [ValidateNotNull()]
            [string]$WEArguments
        )
        
        # Construct a hash-table for default parameter splatting
        $WESplatArgs = @{
            FilePath = $WEFilePath
            NoNewWindow = $true
            Passthru = $true
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
        }
        catch [System.Exception] {
            Write-Warning -Message $_.Exception.Message; break
        }
        
        # Handle return value with exitcode from process
        return $WEInvocation.ExitCode
    }

    [CmdletBinding()]
function WE-Start-PowerShellSysNative {
        [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
            [parameter(Mandatory = $false, HelpMessage = " Specify arguments that will be passed to the sysnative PowerShell process." )]
            [ValidateNotNull()]
            [string]$WEArguments
        )

        # Get the sysnative path for powershell.exe
        $WESysNativePowerShell = Join-Path -Path ($WEPSHOME.ToLower().Replace(" syswow64" , " sysnative" )) -ChildPath " powershell.exe"

        # Construct new ProcessStartInfo object to restart powershell.exe as a 64-bit process and re-run scipt
        $WEProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $WEProcessStartInfo.FileName = $WESysNativePowerShell
        $WEProcessStartInfo.Arguments = $WEArguments
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

    # Stage script in system root directory for ActiveSetup
   ;  $WEWindowsTempPath = Join-Path -Path $env:SystemRoot -ChildPath " Temp"
    if (-not(Test-Path -Path (Join-Path -Path $WEWindowsTempPath -ChildPath $WEMyInvocation.MyCommand.Name))) {
        Write-LogEntry -Value " Attempting to stage '$($WEMyInvocation.MyCommand.Definition)' to: $($WEWindowsTempPath)" -Severity 1
        Copy-Item $WEMyInvocation.MyCommand.Definition -Destination $WEWindowsTempPath -Force
    }
    else {
        Write-LogEntry -Value " Found existing script file '$($WEMyInvocation.MyCommand.Definition)' in '$($WEWindowsTempPath)', will not attempt to stage again" -Severity 1
    }

    # Check if we're running as a 64-bit process or not, if not restart as a 64-bit process
    if (-not[System.Environment]::Is64BitProcess) {
        Write-LogEntry -Value " Re-launching the PowerShell instance as a 64-bit process in Stage mode since it was originally launched as a 32-bit process" -Severity 1
        Start-PowerShellSysNative -Arguments " -ExecutionPolicy Bypass -File $($env:SystemRoot)\Temp\$($WEMyInvocation.MyCommand.Name) -RunMode Stage"
    }
    else {
        # Validate that script is executed on HP hardware
       ;  $WEManufacturer = (Get-CimInstance -Class " Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()
        switch -Wildcard ($WEManufacturer) {
            " *HP*" {
                Write-LogEntry -Value " Validated HP hardware check, allowed to continue" -Severity 1
            }
            " *Hewlett-Packard*" {
                Write-LogEntry -Value " Validated HP hardware check, allowed to continue" -Severity 1
            }
            default {
                Write-LogEntry -Value " Unsupported hardware detected, HP hardware is required for this script to operate" -Severity 3; exit 1
            }
        }

        switch ($WERunMode) {
            " Stage" {
                Write-LogEntry -Value " Current script host process is running in 64-bit: $([System.Environment]::Is64BitProcess)" -Severity 1

                try {
                    # Install latest NuGet package provider
                    Write-LogEntry -Value " Attempting to install latest NuGet package provider" -Severity 1
                    $WEPackageProvider = Install-PackageProvider -Name " NuGet" -Force -ErrorAction Stop -Verbose:$false
    
                    # Ensure default PSGallery repository is registered
                    Register-PSRepository -Default -ErrorAction SilentlyContinue

                    # Attempt to get the installed PowerShellGet module
                    Write-LogEntry -Value " Attempting to locate installed PowerShellGet module" -Severity 1
                   ;  $WEPowerShellGetInstalledModule = Get-InstalledModule -Name " PowerShellGet" -ErrorAction SilentlyContinue -Verbose:$false
                    if ($null -ne $WEPowerShellGetInstalledModule) {
                        try {
                            # Attempt to locate the latest available version of the PowerShellGet module from repository
                            Write-LogEntry -Value " Attempting to request the latest PowerShellGet module version from repository" -Severity 1
                           ;  $WEPowerShellGetLatestModule = Find-Module -Name " PowerShellGet" -ErrorAction Stop -Verbose:$false
                            if ($null -ne $WEPowerShellGetLatestModule) {
                                if ($WEPowerShellGetInstalledModule.Version -lt $WEPowerShellGetLatestModule.Version) {
                                    try {
                                        # Newer module detected, attempt to update
                                        Write-LogEntry -Value " Newer version detected, attempting to update the PowerShellGet module from repository" -Severity 1
                                        Update-Module -Name " PowerShellGet" -Scope " AllUsers" -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                                    }
                                    catch [System.Exception] {
                                        Write-LogEntry -Value " Failed to update the PowerShellGet module. Error message: $($_.Exception.Message)" -Severity 3 ; exit 1
                                    }
                                }
                            }
                            else {
                                Write-LogEntry -Value " Location request for the latest available version of the PowerShellGet module failed, can't continue" -Severity 3; exit 1
                            }
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value " Failed to retrieve the latest available version of the PowerShellGet module, can't continue. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                        }
                    }
                    else {
                        try {
                            # PowerShellGet module was not found, attempt to install from repository
                            Write-LogEntry -Value " PowerShellGet module was not found, will attempting to install it and it's dependencies from repository" -Severity 1
                            Write-LogEntry -Value " Attempting to install PackageManagement module from repository" -Severity 1
                            Install-Module -Name " PackageManagement" -Force -Scope AllUsers -AllowClobber -ErrorAction Stop -Verbose:$false
                            Write-LogEntry -Value " Attempting to install PowerShellGet module from repository" -Severity 1
                            Install-Module -Name " PowerShellGet" -Force -Scope AllUsers -AllowClobber -ErrorAction Stop -Verbose:$false
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value " Unable to install PowerShellGet module from repository. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                        }
                    }
    
                    try {
                        # Invoke executing script again in Execute run mode after package provider and modules have been installed/updated
                        Write-LogEntry -Value " Re-launching the PowerShell instance in Execute mode to overcome a bug with PowerShellGet" -Severity 1
                        Start-PowerShellSysNative -Arguments " -ExecutionPolicy Bypass -File $($env:SystemRoot)\Temp\$($WEMyInvocation.MyCommand.Name) -RunMode Execute"
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value " Failed to restart executing script in Execute run mode. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value " Unable to install latest NuGet package provider. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                }            
            }
            " Execute" {
                try {
                    # Install HP Client Management Script Library
                    Write-LogEntry -Value " Attempting to install HPCMSL module from repository" -Severity 1
                    Install-Module -Name " HPCMSL" -AcceptLicense -Force -ErrorAction Stop -Verbose:$false
    
                    # Create HPIA directory for HP Image Assistant extraction
                    $WEHPImageAssistantExtractPath = Join-Path -Path $env:SystemRoot -ChildPath " Temp\HPIA"
                    if (-not(Test-Path -Path $WEHPImageAssistantExtractPath)) {
                        Write-LogEntry -Value " Creating directory for HP Image Assistant extraction: $($WEHPImageAssistantExtractPath)" -Severity 1
                        New-Item -Path $WEHPImageAssistantExtractPath -ItemType " Directory" -Force | Out-Null
                    }
    
                    # Create HP logs for HP Image Assistant
                    $WEHPImageAssistantReportPath = Join-Path -Path $env:SystemRoot -ChildPath " Temp\HPIALogs"
                    if (-not(Test-Path -Path $WEHPImageAssistantReportPath)) {
                        Write-LogEntry -Value " Creating directory for HP Image Assistant report logs: $($WEHPImageAssistantReportPath)" -Severity 1
                        New-Item -Path $WEHPImageAssistantReportPath -ItemType " Directory" -Force | Out-Null
                    }
    
                    # Create HP Drivers directory for driver content
                    $WESoftpaqDownloadPath = Join-Path -Path $env:SystemRoot -ChildPath " Temp\HPDrivers"
                    if (-not(Test-Path -Path $WESoftpaqDownloadPath)) {
                        Write-LogEntry -Value " Creating directory for softpaq downloads: $($WESoftpaqDownloadPath)" -Severity 1
                        New-Item -Path $WESoftpaqDownloadPath -ItemType " Directory" -Force | Out-Null
                    }
    
                    # Set current working directory to HPIA directory
                    Write-LogEntry -Value " Switching working directory to: $($env:SystemRoot)\Temp" -Severity 1
                    Set-Location -Path (Join-Path -Path $env:SystemRoot -ChildPath " Temp" )
    
                    try {
                        # Download HP Image Assistant softpaq and extract it to Temp directory
                        Write-LogEntry -Value " Attempting to download and extract HP Image Assistant to: $($WEHPImageAssistantExtractPath)" -Severity 1
                        Install-HPImageAssistant -Extract -DestinationPath $WEHPImageAssistantExtractPath -Quiet -ErrorAction Stop
    
                        try {
                            # Invoke HP Image Assistant to install drivers and driver software
                            $WEHPImageAssistantExecutablePath = Join-Path -Path $env:SystemRoot -ChildPath " Temp\HPIA\HPImageAssistant.exe"
                            switch ($WEHPIAAction) {
                                " Download" {
                                    Write-LogEntry -Value " Attempting to execute HP Image Assistant to download drivers including driver software, this might take some time" -Severity 1

                                    # Prepare arguments for HP Image Assistant download mode
                                    $WEHPImageAssistantArguments = " /Operation:Analyze /Action:Download /Selection:All /Silent /Category:Drivers,Software /ReportFolder:$($WEHPImageAssistantReportPath) /SoftpaqDownloadFolder:$($WESoftpaqDownloadPath)"

                                    # Set HP Image Assistant operational mode in registry
                                    Set-RegistryValue -Path " HKLM:\SOFTWARE\HP\ImageAssistant" -Name " OperationalMode" -Value " Download" -ErrorAction Stop
                                }
                                " Install" {
                                    Write-LogEntry -Value " Attempting to execute HP Image Assistant to download and install drivers including driver software, this might take some time" -Severity 1

                                    # Prepare arguments for HP Image Assistant install mode
                                   ;  $WEHPImageAssistantArguments = " /Operation:Analyze /Action:Install /Selection:All /Silent /Category:Drivers,Software /ReportFolder:$($WEHPImageAssistantReportPath) /SoftpaqDownloadFolder:$($WESoftpaqDownloadPath)"

                                    # Set HP Image Assistant operational mode in registry
                                    Set-RegistryValue -Path " HKLM:\SOFTWARE\HP\ImageAssistant" -Name " OperationalMode" -Value " Install" -ErrorAction Stop
                                }
                            }

                            # Invoke HP Image Assistant
                           ;  $WEInvocation = Invoke-Executable -FilePath $WEHPImageAssistantExecutablePath -Arguments $WEHPImageAssistantArguments -ErrorAction Stop
    
                            # Add a registry key for Win32 app detection rule based on HP Image Assistant exit code
                            switch ($WEInvocation) {
                                0 {
                                    Write-LogEntry -Value " HP Image Assistant returned successful exit code: $($WEInvocation)" -Severity 1
                                    Set-RegistryValue -Path " HKLM:\SOFTWARE\HP\ImageAssistant" -Name " ExecutionResult" -Value " Success" -ErrorAction Stop
                                }
                                256 { # The analysis returned no recommendations
                                    Write-LogEntry -Value " HP Image Assistant returned there were no recommendations for this system, exit code: $($WEInvocation)" -Severity 1
                                    Set-RegistryValue -Path " HKLM:\SOFTWARE\HP\ImageAssistant" -Name " ExecutionResult" -Value " Success" -ErrorAction Stop
                                }
                                3010 { # Softpaqs installations are successful, but at least one requires a restart
                                    Write-LogEntry -Value " HP Image Assistant returned successful exit code: $($WEInvocation)" -Severity 1
                                    Set-RegistryValue -Path " HKLM:\SOFTWARE\HP\ImageAssistant" -Name " ExecutionResult" -Value " Success" -ErrorAction Stop
                                }
                                3020 { # One or more Softpaq's failed to install
                                    Write-LogEntry -Value " HP Image Assistant did not install one or more softpaqs successfully, examine the Readme*.html file in: $($WEHPImageAssistantReportPath)" -Severity 2
                                    Write-LogEntry -Value " HP Image Assistant returned successful exit code: $($WEInvocation)" -Severity 1
                                    Set-RegistryValue -Path " HKLM:\SOFTWARE\HP\ImageAssistant" -Name " ExecutionResult" -Value " Success" -ErrorAction Stop
                                }
                                default {
                                    Write-LogEntry -Value " HP Image Assistant returned unhandled exit code: $($WEInvocation)" -Severity 3
                                    Set-RegistryValue -Path " HKLM:\SOFTWARE\HP\ImageAssistant" -Name " ExecutionResult" -Value " Failed" -ErrorAction Stop
                                }
                            }
    
                            if ($WEHPIAAction -like " Install" ) {
                                # Cleanup downloaded softpaq executable that was extracted
                                Write-LogEntry -Value " Attempting to cleanup directory for downloaded softpaqs: $($WESoftpaqDownloadPath)" -Severity 1
                                Remove-Item -Path $WESoftpaqDownloadPath -Force -Recurse -Confirm:$false
                            }
    
                            # Cleanup extracted HPIA directory
                            Write-LogEntry -Value " Attempting to cleanup extracted HP Image Assistant directory: $($WEHPImageAssistantExtractPath)" -Severity 1
                            Remove-Item -Path $WEHPImageAssistantExtractPath -Force -Recurse -Confirm:$false
    
                            # Remove script from Temp directory
                            Write-LogEntry -Value " Attempting to self-destruct executing script file: $($WEMyInvocation.MyCommand.Definition)" -Severity 1
                            Remove-Item -Path $WEMyInvocation.MyCommand.Definition -Force -Confirm:$false
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value " Failed to run HP Image Assistant to install drivers and driver software. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value " Failed to download and extract HP Image Assistant softpaq. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value " Unable to install HPCMSL module from repository. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                }
            }
        }        
    }   
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================