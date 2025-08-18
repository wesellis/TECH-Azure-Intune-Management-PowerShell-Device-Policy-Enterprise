<#
.SYNOPSIS
    Detection

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
    We Enhanced Detection

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
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

$applicationNames = @(" Dell SupportAssist" , " Dell SupportAssist Remediation" , " Dell SupportAssist OS Recovery Plugin for Dell Update" )


[CmdletBinding()]
function WE-Get-RegistryKey -ErrorAction Stop {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$softwareName
    )

    begin {
        $registryPaths = @(
            " HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            " HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $registryKeys = @()
    }

    process {
       ;  $registryKeys = $registryKeys + Get-ItemProperty -Path $registryPaths | 
        Where-Object { $softwareName -contains $_.DisplayName } | 
        Select-Object DisplayName,UninstallString,QuietUninstallString
    }

    end {
        return $registryKeys
    }
}
; 
$registryKeys = $applicationNames | Get-RegistryKey -ErrorAction Stop


return ($null -ne $registryKeys)



} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
