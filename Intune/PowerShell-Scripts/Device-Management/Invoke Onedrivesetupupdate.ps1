<#
.SYNOPSIS
    Invoke Onedrivesetupupdate

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
    We Enhanced Invoke Onedrivesetupupdate

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
.SYNOPSIS
    Download the latest OneDriveSetup.exe on the production ring, replace built-in version and initate per-machine OneDrive setup.

.DESCRIPTION
    This script will download the latest OneDriveSetup.exe from the production ring, replace the built-in executable, initiate the 
    per-machine install which will result in the latest version of OneDrive will always be installed and synchronization can begin right away.

.PARAMETER DownloadPath
    Specify a path for where OneDriveSetup.exe will be temporarily downloaded to.

.EXAMPLE
    .\Invoke-OneDriveSetupUpdate.ps1

.NOTES
    FileName:    Invoke-OneDriveSetupUpdate.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2021-01-18
    Updated:     2021-01-18

    Version history:
    1.0.0 - (2021-01-18) Script created

[CmdletBinding(SupportsShouldProcess = $true)]
[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
    [parameter(Mandatory = $false, HelpMessage = " Specify a path for where OneDriveSetup.exe will be temporarily downloaded to." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEDownloadPath = (Join-Path -Path $env:windir -ChildPath " Temp" )
)
Begin {
    # Install required modules for script execution
    $WEModules = @(" NTFSSecurity" )
    foreach ($WEModule in $WEModules) {
        try {
            $WECurrentModule = Get-InstalledModule -Name $WEModule -ErrorAction Stop -Verbose:$false
            if ($null -ne $WECurrentModule) {
                $WELatestModuleVersion = (Find-Module -Name $WEModule -ErrorAction Stop -Verbose:$false).Version
                if ($WELatestModuleVersion -gt $WECurrentModule.Version) {
                    $WEUpdateModuleInvocation = Update-Module -Name $WEModule -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                }
            }
        }
        catch [System.Exception] {
            try {
                # Install NuGet package provider
                $WEPackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false
        
                # Install current missing module
                Install-Module -Name $WEModule -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
            catch [System.Exception] {
                Write-Warning -Message " An error occurred while attempting to install $($WEModule) module. Error message: $($_.Exception.Message)"
            }
        }
    }

    # Determine the localized name of the principals required for the functionality of this script
    $WELocalSystemPrincipal = " NT AUTHORITY\SYSTEM"
}
Process {
    # Functions
    [CmdletBinding()]
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
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESeverity,
    
            [parameter(Mandatory = $false, HelpMessage = " Name of the log file that the entry will written to." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEFileName = " Invoke-OneDriveSetupUpdate.log"
        )
        # Determine log file location
        $WELogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath " Temp" ) -ChildPath $WEFileName
        
        # Construct time stamp for log entry
        $WETime = -join @((Get-Date -Format " HH:mm:ss.fff" ), " +" , (Get-CimInstance -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $WEDate = (Get-Date -Format " MM-dd-yyyy" )
        
        # Construct context for log entry
        $WEContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" OneDriveSetupUpdate"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
        
        # Add value to log file
        try {
            Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message " Unable to append log entry to Invoke-OneDriveSetupUpdate.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    [CmdletBinding()]
function WE-Start-DownloadFile {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage=" URL for the file to be downloaded." )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEURL,
    
            [parameter(Mandatory = $true, HelpMessage=" Folder where the file will be downloaded." )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath,
    
            [parameter(Mandatory = $true, HelpMessage=" Name of the file including file extension." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEName
        )
        Begin {
            # Set global variable
            $WEErrorActionPreference = " Stop"

            # Construct WebClient object
            $WEWebClient = New-Object -TypeName " System.Net.WebClient"
        }
        Process {
            try {
                # Create path if it doesn't exist
                if (-not(Test-Path -Path $WEPath)) {
                    New-Item -Path $WEPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
        
                # Start download of file
                $WEWebClient.DownloadFile($WEURL, (Join-Path -Path $WEPath -ChildPath $WEName))
            }
            catch [System.Exception] {
                Write-LogEntry -Value " - Failed to download file from URL '$($WEURL)'" -Severity 3
            }
        }
        End {
            # Dispose of the WebClient object
            $WEWebClient.Dispose()
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

    try {
        try {
            # Attempt to remove existing OneDriveSetup.exe in temporary location
            if (Test-Path -Path (Join-Path -Path $WEDownloadPath -ChildPath " OneDriveSetup.exe" )) {
                Write-LogEntry -Value " Found existing 'OneDriveSetup.exe' in temporary download path, removing it" -Severity 1
                Remove-Item -Path (Join-Path -Path $WEDownloadPath -ChildPath " OneDriveSetup.exe" ) -Force -ErrorAction Stop
            }

            # Download the OneDriveSetup.exe file to temporary location
            $WEOneDriveSetupURL = " https://go.microsoft.com/fwlink/p/?LinkId=248256"
            Write-LogEntry -Value " Attempting to download the latest OneDriveSetup.exe file from Microsoft download page to temporary download path: $($WEDownloadPath)" -Severity 1
            Write-LogEntry -Value " Using URL for download: $($WEOneDriveSetupURL)" -Severity 1
            Start-DownloadFile -URL $WEOneDriveSetupURL -Path $WEDownloadPath -Name " OneDriveSetup.exe" -ErrorAction Stop

            # Validate OneDriveSetup.exe file has successfully been downloaded to temporary location
            if (Test-Path -Path $WEDownloadPath) {
                if (Test-Path -Path (Join-Path -Path $WEDownloadPath -ChildPath " OneDriveSetup.exe" )) {
                    Write-LogEntry -Value " Detected 'OneDriveSetup.exe' in the temporary download path" -Severity 1

                    try {
                        # Attempt to import the NTFSSecurity module as a verification that it was successfully installed
                        Write-LogEntry -Value " Attempting to import the 'NTFSSecurity' module" -Severity 1
                        Import-Module -Name " NTFSSecurity" -Verbose:$false -ErrorAction Stop

                        try {
                            # Save the existing access rules and ownership information
                            Write-LogEntry -Value " Attempting to read and temporarily store existing access permissions for built-in 'OneDriveSetup.exe' executable" -Severity 1
                            $WEOneDriveSetupFile = Join-Path -Path $env:windir -ChildPath " SysWOW64\OneDriveSetup.exe"
                            Write-LogEntry -Value " Reading from file: $($WEOneDriveSetupFile)" -Severity 1
                            $WEOneDriveSetupAccessRules = Get-NTFSAccess -Path $WEOneDriveSetupFile -Verbose:$false -ErrorAction Stop
                            $WEOneDriveSetupOwner = (Get-NTFSOwner -Path $WEOneDriveSetupFile -ErrorAction Stop).Owner | Select-Object -ExpandProperty " AccountName"

                            try {
                                # Set owner to system for built-in OneDriveSetup executable
                                Write-LogEntry -Value " Setting ownership for '$($WELocalSystemPrincipal)' on file: $($WEOneDriveSetupFile)" -Severity 1
                                Set-NTFSOwner -Path $WEOneDriveSetupFile -Account $WELocalSystemPrincipal -ErrorAction Stop

                                try {
                                    Write-LogEntry -Value " Setting access right 'FullControl' for owner '$($WELocalSystemPrincipal)' on file: '$($WEOneDriveSetupFile)" -Severity 1
                                    Add-NTFSAccess -Path $WEOneDriveSetupFile -Account $WELocalSystemPrincipal -AccessRights " FullControl" -AccessType " Allow" -ErrorAction Stop

                                    try {
                                        # Remove built-in OneDriveSetup executable
                                        Write-LogEntry -Value " Attempting to remove built-in built-in 'OneDriveSetup.exe' executable file: $($WEOneDriveSetupFile)" -Severity 1
                                        Remove-Item -Path $WEOneDriveSetupFile -Force -ErrorAction Stop
    
                                        try {
                                            # Copy downloaded OneDriveSetup file to default location
                                            $WEOneDriveSetupSourceFile = Join-Path -Path $WEDownloadPath -ChildPath " OneDriveSetup.exe"
                                            Write-LogEntry -Value " Attempting to copy downloaded '$($WEOneDriveSetupSourceFile)' to: $($WEOneDriveSetupFile)" -Severity 1
                                            Copy-Item -Path $WEOneDriveSetupSourceFile -Destination $WEOneDriveSetupFile -Force -Verbose:$false -ErrorAction Stop
    
                                            try {
                                                # Restore access rules and owner information
                                                foreach ($WEOneDriveSetupAccessRule in $WEOneDriveSetupAccessRules) {
                                                    if ($WEOneDriveSetupAccessRule.Account.AccountName -match " APPLICATION PACKAGE AUTHORITY" ) {
                                                       ;  $WEAccountName = ($WEOneDriveSetupAccessRule.Account.AccountName.Split(" \" ))[1]
                                                    }
                                                    else {
                                                       ;  $WEAccountName = $WEOneDriveSetupAccessRule.Account.AccountName
                                                    }

                                                    Write-LogEntry -Value " Restoring access right '$($WEOneDriveSetupAccessRule.AccessRights)' for account '$($WEAccountName)' on file: $($WEOneDriveSetupFile)" -Severity 1
                                                    Add-NTFSAccess -Path $WEOneDriveSetupFile -Account $WEAccountName -AccessRights $WEOneDriveSetupAccessRule.AccessRights -AccessType " Allow" -ErrorAction Stop
                                                }

                                                try {
                                                    # Disable inheritance for the updated built-in OneDriveSetup executable
                                                    Write-LogEntry -Value " Disabling and removing inherited access rules on file: $($WEOneDriveSetupFile)" -Severity 1
                                                    Disable-NTFSAccessInheritance -Path $WEOneDriveSetupFile -RemoveInheritedAccessRules -ErrorAction Stop

                                                    try {
                                                        # Restore owner information
                                                        Write-LogEntry -Value " Restoring owner '$($WEOneDriveSetupOwner)' on file: $($WEOneDriveSetupFile)" -Severity 1
                                                        Set-NTFSOwner -Path $WEOneDriveSetupFile -Account $WEOneDriveSetupOwner -ErrorAction Stop
    
                                                        try {
                                                            # Attempt to remove existing OneDriveSetup.exe in temporary location
                                                            if (Test-Path -Path $WEOneDriveSetupSourceFile) {
                                                                Write-LogEntry -Value " Deleting 'OneDriveSetup.exe' from temporary download path" -Severity 1
                                                                Remove-Item -Path $WEOneDriveSetupSourceFile -Force -ErrorAction Stop
                                                            }
    
                                                            Write-LogEntry -Value " Successfully updated built-in 'OneDriveSetup.exe' executable to the latest version" -Severity 1

                                                            try {
                                                                # Initiate updated built-in OneDriveSetup.exe and install as per-machine
                                                                Write-LogEntry -Value " Initiate per-machine OneDrive setup installation, this process could take some time" -Severity 1
                                                                Invoke-Executable -FilePath $WEOneDriveSetupFile -Arguments " /allusers /update" -ErrorAction Stop

                                                                Write-LogEntry -Value " Successfully installed OneDrive as per-machine" -Severity 1
                                                            }
                                                            catch [System.Exception] {
                                                                Write-LogEntry -Value " Failed to install OneDrive as per-machine. Error message: $($_.Exception.Message)" -Severity 3
                                                            }
                                                        }
                                                        catch [System.Exception] {
                                                            Write-LogEntry -Value " Failed to remove '$($WEOneDriveSetupSourceFile)'. Error message: $($_.Exception.Message)" -Severity 3
                                                        }
                                                    }
                                                    catch [System.Exception] {
                                                        Write-LogEntry -Value " Failed to restore owner for account '$($WEOneDriveSetupOwner)'. Error message: $($_.Exception.Message)" -Severity 3
                                                    }
                                                }
                                                catch [System.Exception] {
                                                    Write-LogEntry -Value " Failed to disable inheritance for '$($WEOneDriveSetupFile)'. Error message: $($_.Exception.Message)" -Severity 3
                                                }
                                            }
                                            catch [System.Exception] {
                                                Write-LogEntry -Value " Failed to restore access right '$($WEOneDriveSetupAccessRule.AccessRights)' for account '$($WEOneDriveSetupAccessRule.Account.AccountName)' on file '$($WEOneDriveSetupFile)'. Error message: $($_.Exception.Message)" -Severity 3
                                            }
                                        }
                                        catch [System.Exception] {
                                            Write-LogEntry -Value " Failed to copy '$($WEOneDriveSetupSourceFile)' to default location. Error message: $($_.Exception.Message)" -Severity 3
                                        }
                                    }
                                    catch [System.Exception] {
                                        Write-LogEntry -Value " Failed to remove built-in executable file '$($WEOneDriveSetupFile)'. Error message: $($_.Exception.Message)" -Severity 3
                                    }
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value " Failed to set access right 'FullControl' for owner on file: '$($WEOneDriveSetupFile)'. Error message: $($_.Exception.Message)" -Severity 3
                                }
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value " Failed to set ownership for '$($WELocalSystemPrincipal)' on file: $($WEOneDriveSetupFile). Error message: $($_.Exception.Message)" -Severity 3
                            }
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value " Failed to temporarily store existing access permissions for built-in 'OneDriveSetup.exe' executable. Error message: $($_.Exception.Message)" -Severity 3
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value " Failed to import the 'NTFSSecurity' module. Error message: $($_.Exception.Message)" -Severity 3
                    }
                }
                else {
                    Write-LogEntry -Value " Unable to detect 'OneDriveSetup.exe' in the temporary download path" -Severity 3
                }
            }
            else {
                Write-LogEntry -Value " Unable to locate download path '$($WEDownloadPath)', ensure the directory exists" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value " Failed to restore owner for account '$($WEOneDriveSetupOwner)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value " Failed to download OneDriveSetup.exe file. Error message: $($_.Exception.Message)" -Severity 3
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================