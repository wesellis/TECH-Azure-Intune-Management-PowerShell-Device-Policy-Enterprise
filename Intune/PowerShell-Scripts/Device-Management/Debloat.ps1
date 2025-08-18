<#
.SYNOPSIS
    Debloat

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
    We Enhanced Debloat

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$bloatApps = @(
}


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$bloatApps = @(
    " Microsoft.XboxApp" ,
    " Clipchamp.Clipchamp" ,
    " Microsoft.MSPaint" ,
    " Microsoft.MicrosoftSolitaireCollection"
)

foreach($app in $bloatApps)
{
   ;  $installed = (Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq " $($app)" })
    if($installed)
    {
        try {
            $installed | Remove-AppxProvisionedPackage -Online
        }
        catch {
           ;  $message = $_
            Write-WELog " Error removing $($app): $message" " INFO"
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================