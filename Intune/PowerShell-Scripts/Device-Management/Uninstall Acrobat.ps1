<#
.SYNOPSIS
    Uninstall Acrobat

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
    We Enhanced Uninstall Acrobat

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

[CmdletBinding()]
function WE-Get-AdobeAcrobat -ErrorAction Stop {
   ;  $adobeAcrobat32 = Get-ItemProperty -ErrorAction Stop HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like " *Adobe Acrobat*" }
   ;  $adobeAcrobat64 = Get-ItemProperty -ErrorAction Stop HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like " *Adobe Acrobat*" }

    # if both are null, return null; else return the install directory
    if ($null -eq $adobeAcrobat32 -and $null -eq $adobeAcrobat64) {
        return $null
    }
    else {
        return $adobeAcrobat32, $adobeAcrobat64
    }
}


[CmdletBinding()]
function WE-Remove-AdobeAcrobat -ErrorAction Stop {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$uninstallString
    )

    begin {
        Write-WELog " Uninstalling Adobe Acrobat..." " INFO"
    }

    process {
        # uninstall the application
        # replace /I with /X to uninstall
        $uninstallString = $uninstallString -replace " /I" , " /X"
       ;  $uninstallString = $uninstallString + " /qn"

        cmd /c $uninstallString
    }

    end {
        # check if the uninstall was successful
       ;  $adobeAcrobat = Get-AdobeAcrobat -ErrorAction Stop
        if ($null -eq $adobeAcrobat) {
            Write-WELog " Adobe Acrobat has been uninstalled." " INFO" -ForegroundColor Green
        }
        else {
            Write-WELog " Adobe Acrobat was not uninstalled." " INFO" -ForegroundColor Red
        }
    }


}

Get-AdobeAcrobat -ErrorAction Stop | Select-Object -ExpandProperty UninstallString | Remove-AdobeAcrobat -ErrorAction Stop



} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
