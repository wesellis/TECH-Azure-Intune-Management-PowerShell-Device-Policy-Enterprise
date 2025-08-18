<#
.SYNOPSIS
    Officewin32Detectionscript

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
    We Enhanced Officewin32Detectionscript

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
		[string]$WEFileName = $WELogFileName
	)
	# Determine log file location
	$WELogFilePath = Join-Path -Path $env:SystemRoot -ChildPath $(" Temp\$WEFileName" )
	
	# Construct time stamp for log entry
	$WETime = -join @((Get-Date -Format " HH:mm:ss.fff" ), " " , (Get-CimInstance -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
	
	# Construct date for log entry
	$WEDate = (Get-Date -Format " MM-dd-yyyy" )
	
	# Construct context for log entry
	$WEContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	
	# Construct final log entry
	$WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" $($WELogFileName)"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
	
	# Add value to log file
	try {
		Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
		if ($WESeverity -eq 1) {
			Write-Verbose -Message $WEValue
		} elseif ($WESeverity -eq 3) {
			Write-Warning -Message $WEValue
		}
	} catch [System.Exception] {
		Write-Warning -Message " Unable to append log entry to $WELogFileName.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
	}
}

$WELogFileName = " M365AppsSetup.log"
Write-LogEntry -Value " Start Office Install detection logic" -Severity 1
$WERegistryKeys = Get-ChildItem -Path " HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"; 
$WEM365Apps = " Microsoft 365 Apps for enterprise" ; 
$WEM365AppsCheck = $WERegistryKeys | Where-Object { $_.GetValue(" DisplayName" ) -match $WEM365Apps }
if ($WEM365AppsCheck) {
    Write-LogEntry -Value " Office detected OK" -Severity 1
    Write-Output " Office Detected"
	Exit 0
   }else{
    Write-LogEntry -Value " Office not detected" -Severity 2
    Exit 1
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================