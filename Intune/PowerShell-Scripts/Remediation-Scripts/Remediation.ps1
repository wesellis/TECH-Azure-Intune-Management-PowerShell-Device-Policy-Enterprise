<#
.SYNOPSIS
    Remediation

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
    We Enhanced Remediation

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

$applicationNames = @(" Dell SupportAssist" , " Dell SupportAssist Remediation" , " Dell SupportAssist OS Recovery Plugin for Dell Update" )


[CmdletBinding()]
function WE-Get-RegistryKey -ErrorAction Stop {
    

[CmdletBinding()]
function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
        [ValidateSet(" INFO" , " WARN" , " ERROR" , " SUCCESS" )]
        [string]$Level = " INFO"
    )
    
   ;  $timestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
   ;  $colorMap = @{
        " INFO" = " Cyan" ; " WARN" = " Yellow" ; " ERROR" = " Red" ; " SUCCESS" = " Green"
    }
    
    $logEntry = " $timestamp [WE-Enhanced] [$Level] $Message"
    Write-Information $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
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
        $registryKeys = $registryKeys + Get-ItemProperty -Path $registryPaths | 
        Where-Object { $softwareName -contains $_.DisplayName } | 
        Select-Object DisplayName,UninstallString,QuietUninstallString
    }

    end {
        return $registryKeys
    }
}

[CmdletBinding()]
function WE-Uninstall-Application {
    

[CmdletBinding()]
function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
        [ValidateSet(" INFO" , " WARN" , " ERROR" , " SUCCESS" )]
        [string]$Level = " INFO"
    )
    
   ;  $timestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
   ;  $colorMap = @{
        " INFO" = " Cyan" ; " WARN" = " Yellow" ; " ERROR" = " Red" ; " SUCCESS" = " Green"
    }
    
    $logEntry = " $timestamp [WE-Enhanced] [$Level] $Message"
    Write-Information $logEntry -ForegroundColor $colorMap[$Level]
}

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object[]]$registryKey
    )

    process {
        # if there exists a quiet uninstall string, use it
        if ($registryKey.QuietUninstallString) {
            $uninstallString = $registryKey.QuietUninstallString
        } else {
            $uninstallString = $registryKey.UninstallString -replace '/I', '/X'
            $uninstallString = $uninstallString + ' /qn'
        }

        try {
            Start-Process " cmd.exe" -ArgumentList " /c $uninstallString" -Wait -NoNewWindow
        } catch {
            Write-WELog " An error occurred while uninstalling the application: $_" " INFO" -ForegroundColor Red
        }
    }
}



$registryKeys = $applicationNames | Get-RegistryKey -ErrorAction Stop

if (($registryKeys | Where-Object { $_.DisplayName -eq $applicationNames[2] }).Count -eq 2) {
   ;  $registryKeys = $registryKeys | Where-Object { $_.DisplayName -ne $applicationNames[2] -or $_.QuietUninstallString -ne $null }
}

$registryKeys | Uninstall-Application

; 
$registryKeys = $applicationNames | Get-RegistryKey -ErrorAction Stop
if ($registryKeys) {
    Write-WELog " Dell SupportAssist is still installed." " INFO" -ForegroundColor Red
} else {
    Write-WELog " Dell SupportAssist has been uninstalled." " INFO" -ForegroundColor Green
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================