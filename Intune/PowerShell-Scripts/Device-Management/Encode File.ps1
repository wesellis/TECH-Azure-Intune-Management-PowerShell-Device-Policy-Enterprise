<#
.SYNOPSIS
    Encode File

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
    We Enhanced Encode File

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#PSScriptInfo
    .VERSION 1.0
    .GUID 3ea6c490-deb5-476d-9809-69bef723b820
    .AUTHOR Aaron Parker, @stealthpuppy
    .COMPANYNAME stealthpuppy
    .COPYRIGHT Aaron Parker, https://stealthpuppy.com
    .TAGS Encode Base64
    .LICENSEURI https://github.com/aaronparker/Intune/blob/master/LICENSE
    .PROJECTURI https://github.com/aaronparker/Intune
    .ICONURI
    .EXTERNALMODULEDEPENDENCIES
    .REQUIREDSCRIPTS
    .EXTERNALSCRIPTDEPENDENCIES
    .RELEASENOTES
    .PRIVATEDATA

<#
    .DESCRIPTION
        Encode a file in Base64.



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter()]
    [System.String] $WEInputFile,

    [Parameter()]
    [System.String] $WEOutputFile
)

Function Encode-Text {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [Parameter()]
        $WEText
    )

    # Covert to Base64
    $WEBytes = [System.Text.Encoding]::Unicode.GetBytes($WEText)
   ;  $WEEncodedText = [Convert]::ToBase64String($WEBytes)

    # Return the output to the pipeline
    Write-Output $WEEncodedText
}

; 
$inputFileContent = Get-Content -Path $WEInputFile


Encode-Text -Text $inputFileContent | Out-File -FilePath $WEOutputFile




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
