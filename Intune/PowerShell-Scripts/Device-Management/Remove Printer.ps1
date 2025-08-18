<#
.SYNOPSIS
    Remove Printer

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
    We Enhanced Remove Printer

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
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

.Synopsis
Created on:   31/12/2021
Created by:   Ben Whitmore
Filename:     Remove-Printer.ps1

powershell.exe -executionpolicy bypass -file .\Remove-Printer.ps1 -PrinterName " Canon Printer Upstairs"

.Example
.\Remove-Printer.ps1 -PrinterName " Canon Printer Upstairs"


[CmdletBinding()]; 
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory = $WETrue)]
    [String]$WEPrinterName
)

Try {
    #Remove Printer
   ;  $WEPrinterExist = Get-Printer -Name $WEPrinterName -ErrorAction SilentlyContinue
    if ($WEPrinterExist) {
        Remove-Printer -Name $WEPrinterName -Confirm:$false
    }
}
Catch {
    Write-Warning " Error removing Printer"
    Write-Warning " $($_.Exception.Message)"
}



} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
