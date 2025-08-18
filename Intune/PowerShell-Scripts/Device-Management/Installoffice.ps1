<#
.SYNOPSIS
    Installoffice

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
    We Enhanced Installoffice

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
  Script to install Office as a Win32 App during Autopilot

.DESCRIPTION
    Script to install Office as a Win32 App during Autopilot by downloading the latest Office Deployment Toolkit
    Running Setup.exe from downloaded files with provided config.xml file. 

.NOTES
  Version:        1.0
  Author:         Jan Ketil Skanke
  Creation Date:  01.07.2021
  Purpose/Change: Initial script development
        Author:      Jan Ketil Skanke
        Contact:     @JankeSkanke
        Updated:     2021-09-08
        Version history:
        1.0.0 - (2020-10-11) Script created



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
[CmdletBinding()]
function WE-Start-DownloadFile {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEURL,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$WEName
    )
    Begin {
        # Construct WebClient object
        $WEWebClient = New-Object -TypeName System.Net.WebClient
    }
    Process {
        # Create path if it doesn't exist
        if (-not(Test-Path -Path $WEPath)) {
            New-Item -Path $WEPath -ItemType Directory -Force | Out-Null
        }

        # Start download of file
        $WEWebClient.DownloadFile($WEURL, (Join-Path -Path $WEPath -ChildPath $WEName))
    }
    End {
        # Dispose of the WebClient object
        $WEWebClient.Dispose()
    }
}



$WELogFileName = " M365AppsSetup.log"



Write-LogEntry -Value " Initiating Office setup process" -Severity 1

if (Test-Path " $($env:SystemRoot)\Temp\OfficeSetup" ){
    Remove-Item -Path " $($env:SystemRoot)\Temp\OfficeSetup" -Recurse -Force -ErrorAction SilentlyContinue
}

$WESetupFolder = (New-Item -ItemType " directory" -Path " $($env:SystemRoot)\Temp" -Name OfficeSetup -Force).FullName

try{
    #Download latest Office Deployment Toolkit
    $WEODTDownloadURL = " https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117"
    $WEWebResponseURL = ((Invoke-WebRequest -Uri $WEODTDownloadURL -UseBasicParsing -ErrorAction Stop -Verbose:$false).links | Where-Object { $_.outerHTML -like " *click here to download manually*" }).href
    $WEODTFileName = Split-Path -Path $WEWebResponseURL -Leaf
    $WEODTFilePath = $WESetupFolder
    Write-LogEntry -Value " Attempting to download latest Office Deployment Toolkit executable" -Severity 1
    Start-DownloadFile -URL $WEWebResponseURL -Path $WEODTFilePath -Name $WEODTFileName
    
    try{
        #Extract setup.exe from ODT Package
        $WEODTExecutable = (Join-Path -Path $WEODTFilePath -ChildPath $WEODTFileName)
        $WEODTExtractionPath = (Join-Path -Path $WEODTFilePath -ChildPath (Get-ChildItem -Path $WEODTExecutable).VersionInfo.ProductVersion)
        $WEODTExtractionArguments = " /quiet /extract:$($WEODTExtractionPath)"
        Write-LogEntry -Value " Attempting to extract the setup.exe executable from Office Deployment Toolkit" -Severity 1
        Start-Process -FilePath $WEODTExecutable -ArgumentList $WEODTExtractionArguments -NoNewWindow -Wait -ErrorAction Stop
        $WESetupFilePath = ($WEODTExtractionPath | Get-ChildItem -ErrorAction Stop | Where-Object {$_.Name -eq " setup.exe" }).FullName
        Write-LogEntry -Value " Setup file ready at $($WESetupFilePath)" -Severity 1
        try{
            #Prepare Office Installation
            Copy-Item -Path $WESetupFilePath -Destination $WESetupFolder -Force -ErrorAction Stop
           ;  $WEOfficeCR2Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(" $($WESetupFolder)\setup.exe" ).FileVersion 
            Write-LogEntry -Value " Office C2R Setup is running version $WEOfficeCR2Version" -Severity 1
            Copy-Item " $($WEPSScriptRoot)\configuration.xml" $WESetupFolder -Force -ErrorAction Stop
            Write-LogEntry -Value " Office Setup configuration filed copied" -Severity 1           
            Try{
                #Running office installer
                Write-LogEntry -Value " Starting M365 Apps Install with Win32App method" -Severity 1
               ;  $WEOfficeInstall = Start-Process " $($WESetupFolder)\setup.exe" -ArgumentList " /configure $($WESetupFolder)\configuration.xml" -Wait -PassThru -ErrorAction Stop
              }
            catch [System.Exception]{
                Write-LogEntry -Value  " Error running the M365 Apps install. Errormessage: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception]{
            Write-LogEntry -Value  " Error preparing office installation. Errormessage: $($_.Exception.Message)" -Severity 3
        }
    }
    catch [System.Exception]{
        Write-LogEntry -Value  " Error extraction setup.exe from ODT Package. Errormessage: $($_.Exception.Message)" -Severity 3
    }
    
}
catch [System.Exception]{
    Write-LogEntry -Value  " Error downloading Office Deployment Toolkit. Errormessage: $($_.Exception.Message)" -Severity 3
}
Write-LogEntry -Value " M365 Apps setup completed" -Severity 1



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================