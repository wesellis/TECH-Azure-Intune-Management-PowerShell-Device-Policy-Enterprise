<#
.SYNOPSIS
    Save Vcredist

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
    We Enhanced Save Vcredist

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
    Download Visual C++ Redistributable executables defined in the specified JSON master file.

.DESCRIPTION
    Download Visual C++ Redistributable executables defined in the specified JSON master file.
    All files will be downloaded into a folder named Source that will be created automatically in the executing directory of the script.

.PARAMETER URL
    Specify the Azure Storage blob URL where JSON file is accessible from.

.EXAMPLE
    # Download all Visual C++ Redistributable executables defined in a JSON file published at a given URL:
    .\Save-VCRedist.ps1 -URL " https://<AzureStorageBlobUrl>"

.NOTES
    FileName:    Save-VisualCRedist.ps1
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
           ;  $WEWebClient = New-Object -TypeName System.Net.WebClient
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

    try {
        # Load JSON meta data from Azure Storage blob file    
        Write-Verbose -Message " Loading meta data from URL: $($WEURL)"
       ;  $WEVcRedistMetaData = Invoke-RestMethod -Uri $WEURL -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Warning -Message " Failed to access JSON file. Error message: $($_.Exception.Message)" ; break
    }

    # Set download path based on current working directory
    $WEDownloadRootPath = Join-Path -Path $WEPSScriptRoot -ChildPath " Source"    

    # Process each item from JSON meta data
    foreach ($WEVcRedistItem in $WEVcRedistMetaData.VCRedist) {
        Write-Verbose -Message " Processing item: $($WEVcRedistItem.DisplayName)"

        # Determine download path for current item
       ;  $WEDownloadPath = Join-Path -Path $WEDownloadRootPath -ChildPath (Join-Path -Path $WEVcRedistItem.Version -ChildPath $WEVcRedistItem.Architecture)
        Write-Verbose -Message " Determined download path for current item: $($WEDownloadPath)"

        # Create download path if it doesn't exist
        if (-not(Test-Path -Path $WEDownloadPath)) {
            New-Item -Path $WEDownloadPath -ItemType Directory -Force | Out-Null
        }

        # Start download of current item
        Start-DownloadFile -Path $WEDownloadPath -URL $WEVcRedistItem.URL -Name $WEVcRedistItem.FileName
        Write-Verbose -Message " Successfully downloaded: $($WEVcRedistItem.DisplayName)"
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================