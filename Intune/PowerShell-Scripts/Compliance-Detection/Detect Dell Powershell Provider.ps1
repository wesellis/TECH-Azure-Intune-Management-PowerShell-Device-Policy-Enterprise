<#
.SYNOPSIS
    Detect Dell Powershell Provider

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
    We Enhanced Detect Dell Powershell Provider

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


try {        
}


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

try {        
    if (Get-InstalledModule -Name " DellBIOSProvider" ){
        #Exit 0 for Intune if NO error
       ;  $version = Get-InstalledModule dellbiosprovider

        if($version.Version -ge [System.Version]" 2.4.0" ) {
            # Exit 0 for InTune: Installed and updated
            Write-WELog " DellBIOSProvider already installed, updated!" " INFO"
            exit 0
        }
        else {
            # Exit 1 for InTune: Needs updated
            Write-WELog " DellBIOSProvider needs updating!" " INFO"
            exit 1
        }
        
    }
    else {
        # Exit 1 for Intune: Not installed
        Write-WELog " DellBIOSProvider is NOT installed!" " INFO"
        exit 1
    }
}
catch {
   ;  $errMsg = $_.Exception.Message
    return $errMsg
    exit 1
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================