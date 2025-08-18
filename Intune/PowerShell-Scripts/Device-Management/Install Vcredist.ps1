<#
.SYNOPSIS
    Install Vcredist

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
    We Enhanced Install Vcredist

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
    Install Visual C++ Redistributable applications defined in the specified JSON master file.

.DESCRIPTION
    Install Visual C++ Redistributable applications defined in the specified JSON master file.

.PARAMETER URL
    Specify the Azure Storage blob URL where JSON file is accessible from.

.EXAMPLE
    # Install all Visual C++ Redistributable applications defined in a JSON file published at a given URL:
    .\Install-VisualCRedist.ps1 -URL " https://<AzureStorageBlobUrl>"

.NOTES
    FileName:    Install-VisualCRedist.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-02-05
    Updated:     2020-02-05

    Version history:
    1.0.0 - (2020-02-05) Script created

[CmdletBinding(SupportsShouldProcess = $true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $false, HelpMessage = " Specify the Azure Storage blob URL where JSON file is accessible from." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEURL = " https://<AzureStorageBlobUrl>"
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
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESeverity,

            [parameter(Mandatory = $false, HelpMessage = " Name of the log file that the entry will written to." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEFileName = " VisualCRedist.log"
        )
        # Determine log file location
        $WELogFilePath = Join-Path -Path $env:SystemRoot -ChildPath (Join-Path -Path " Temp" -ChildPath $WEFileName)
        
        # Construct time stamp for log entry
        $WETime = -join @((Get-Date -Format " HH:mm:ss.fff" ), " +" , (Get-CimInstance -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $WEDate = (Get-Date -Format " MM-dd-yyyy" )
        
        # Construct context for log entry
        $WEContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" VisualCRedist"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
        
        # Add value to log file
        try {
            Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message " Unable to append log entry to VisualCRedist.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

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

    Write-LogEntry -Value " Starting installation of Visual C++ applications" -Severity 1
    
    try {
        # Load JSON meta data from Azure Storage blob file    
        Write-LogEntry -Value " Loading meta data from URL: $($WEURL)" -Severity 1
        $WEVcRedistMetaData = Invoke-RestMethod -Uri $WEURL -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Warning -Message " Failed to access JSON file. Error message: $($_.Exception.Message)" ; break
    }

    # Set install root path based on current working directory
    $WEInstallRootPath = Join-Path -Path $WEPSScriptRoot -ChildPath " Source"

    # Get current architecture of operating system
    $WEIs64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem

    # Process each item from JSON meta data
    foreach ($WEVcRedistItem in $WEVcRedistMetaData.VCRedist) {
        if (($WEIs64BitOperatingSystem -eq $false) -and ($WEVcRedistItem.Architecture -like " x64" )) {
            Write-LogEntry -Value " Skipping installation of '$($WEVcRedistItem.Architecture)' for '$($WEVcRedistItem.DisplayName)' on a non 64-bit operating system" -Severity 2
        }
        else {
            Write-LogEntry -Value " Processing item for installation: $($WEVcRedistItem.DisplayName)" -Severity 1

            # Determine execution path for current item
           ;  $WEFileExecutionPath = Join-Path -Path $WEInstallRootPath -ChildPath (Join-Path -Path $WEVcRedistItem.Version -ChildPath (Join-Path -Path $WEVcRedistItem.Architecture -ChildPath $WEVcRedistItem.FileName))
            Write-LogEntry -Value " Determined file execution path for current item: $($WEFileExecutionPath)" -Severity 1
    
            # Install current executable
            if (Test-Path -Path $WEFileExecutionPath) {
                Write-LogEntry -Value " Starting installation of: $($WEVcRedistItem.DisplayName)" -Severity 1
               ;  $WEInvocation = Invoke-Executable -FilePath $WEFileExecutionPath -Arguments $WEVcRedistItem.Parameters
    
                switch ($WEInvocation) {
                    0 {
                        Write-LogEntry -Value " Successfully installed application" -Severity 1
                    }
                    3010 {
                        Write-LogEntry -Value " Successfully installed application, but a restart is required" -Severity 1
                    }
                    default {
                        Write-LogEntry -Value " Failed to install application, exit code: $($WEInvocation)" -Severity 3
                    }
                }
            }
            else {
                Write-LogEntry -Value " Unable to detect file executable for: $($WEVcRedistItem.DisplayName)" -Severity 3
                Write-LogEntry -Value " Expected file could not be found: $($WEFileExecutionPath)" -Severity 3
            }
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================