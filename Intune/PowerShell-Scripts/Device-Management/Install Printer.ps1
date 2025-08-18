<#
.SYNOPSIS
    Install Printer

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
    We Enhanced Install Printer

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

.Synopsis
Created on:   31/12/2021
Created by:   Ben Whitmore
Filename:     Install-Printer.ps1

Simple script to install a network printer from an INF file. The INF and required CAB files hould be in the same directory as the script if creating a Win32app



Install:
powershell.exe -executionpolicy bypass -file .\Install-Printer.ps1 -PortName " IP_10.10.1.1" -PrinterIP " 10.1.1.1" -PrinterName " Canon Printer Upstairs" -DriverName " Canon Generic Plus UFR II" -INFFile " CNLB0MA64.inf"

Uninstall:
powershell.exe -executionpolicy bypass -file .\Remove-Printer.ps1 -PrinterName " Canon Printer Upstairs"

Detection:
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Print\Printers\Canon Printer Upstairs
Name = " Canon Printer Upstairs"

.Example
.\Install-Printer.ps1 -PortName " IP_10.10.1.1" -PrinterIP " 10.1.1.1" -PrinterName " Canon Printer Upstairs" -DriverName " Canon Generic Plus UFR II" -INFFile " CNLB0MA64.inf"


[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory = $WETrue)]
    [String]$WEPortName,
    [Parameter(Mandatory = $WETrue)]
    [String]$WEPrinterIP,
    [Parameter(Mandatory = $WETrue)]
    [String]$WEPrinterName,
    [Parameter(Mandatory = $WETrue)]
    [String]$WEDriverName,
    [Parameter(Mandatory = $WETrue)]
    [String]$WEINFFile
)


$WEThrowbad = $WENull


If ($WEENV:PROCESSOR_ARCHITEW6432 -eq " AMD64" ) {
    Try {
        &" $WEENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -File $WEPSCOMMANDPATH -PortName $WEPortName -PrinterIP $WEPrinterIP -DriverName $WEDriverName -PrinterName $WEPrinterName -INFFile $WEINFFile
    }
    Catch {
        Write-Error " Failed to start $WEPSCOMMANDPATH"
        Write-Warning " $($_.Exception.Message)"
        $WEThrowbad = $WETrue
    }
}

function WE-Write-LogEntry {
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEValue,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$WEFileName = " $($WEPrinterName).log" ,
        [switch]$WEStamp
    )

    #Build Log File appending System Date/Time to output
    $WELogFile = Join-Path -Path $env:SystemRoot -ChildPath $(" Temp\$WEFileName" )
    $WETime = -join @((Get-Date -Format " HH:mm:ss.fff" ), " " , (Get-CimInstance -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
    $WEDate = (Get-Date -Format " MM-dd-yyyy" )

    If ($WEStamp) {
        $WELogText = " <$($WEValue)> <time="" $($WETime)"" date="" $($WEDate)"" >"
    }
    else {
        $WELogText = " $($WEValue)"   
    }
	
    Try {
        Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFile -ErrorAction Stop
    }
    Catch [System.Exception] {
        Write-Warning -Message " Unable to add log entry to $WELogFile.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}

Write-LogEntry -Value " ##################################"
Write-LogEntry -Stamp -Value " Installation started"
Write-LogEntry -Value " ##################################"
Write-LogEntry -Value " Install Printer using the following values..."
Write-LogEntry -Value " Port Name: $WEPortName"
Write-LogEntry -Value " Printer IP: $WEPrinterIP"
Write-LogEntry -Value " Printer Name: $WEPrinterName"
Write-LogEntry -Value " Driver Name: $WEDriverName"
Write-LogEntry -Value " INF File: $WEINFFile"

$WEINFARGS = @(
    " /add-driver"
    " $WEINFFile"
)

If (-not $WEThrowBad) {

    Try {

        #Stage driver to driver store
        Write-LogEntry -Stamp -Value " Staging Driver to Windows Driver Store using INF "" $($WEINFFile)"""
        Write-LogEntry -Stamp -Value " Running command: Start-Process pnputil.exe -ArgumentList $($WEINFARGS) -wait -passthru"
        Start-Process pnputil.exe -ArgumentList $WEINFARGS -wait -passthru

    }
    Catch {
        Write-Warning " Error staging driver to Driver Store"
        Write-Warning " $($_.Exception.Message)"
        Write-LogEntry -Stamp -Value " Error staging driver to Driver Store"
        Write-LogEntry -Stamp -Value " $($_.Exception)"
        $WEThrowBad = $WETrue
    }
}

If (-not $WEThrowBad) {
    Try {
    
        #Install driver
        $WEDriverExist = Get-PrinterDriver -Name $WEDriverName -ErrorAction SilentlyContinue
        if (-not $WEDriverExist) {
            Write-LogEntry -Stamp -Value " Adding Printer Driver "" $($WEDriverName)"""
            Add-PrinterDriver -Name $WEDriverName -Confirm:$false
        }
        else {
            Write-LogEntry -Stamp -Value " Print Driver "" $($WEDriverName)"" already exists. Skipping driver installation."
        }
    }
    Catch {
        Write-Warning " Error installing Printer Driver"
        Write-Warning " $($_.Exception.Message)"
        Write-LogEntry -Stamp -Value " Error installing Printer Driver"
        Write-LogEntry -Stamp -Value " $($_.Exception)"
        $WEThrowBad = $WETrue
    }
}

If (-not $WEThrowBad) {
    Try {

        #Create Printer Port
        $WEPortExist = Get-Printerport -Name $WEPortName -ErrorAction SilentlyContinue
        if (-not $WEPortExist) {
            Write-LogEntry -Stamp -Value " Adding Port "" $($WEPortName)"""
            Add-PrinterPort -name $WEPortName -PrinterHostAddress $WEPrinterIP -Confirm:$false
        }
        else {
            Write-LogEntry -Stamp -Value " Port "" $($WEPortName)"" already exists. Skipping Printer Port installation."
        }
    }
    Catch {
        Write-Warning " Error creating Printer Port"
        Write-Warning " $($_.Exception.Message)"
        Write-LogEntry -Stamp -Value " Error creating Printer Port"
        Write-LogEntry -Stamp -Value " $($_.Exception)"
        $WEThrowBad = $WETrue
    }
}

If (-not $WEThrowBad) {
    Try {

        #Add Printer
        $WEPrinterExist = Get-Printer -Name $WEPrinterName -ErrorAction SilentlyContinue
        if (-not $WEPrinterExist) {
            Write-LogEntry -Stamp -Value " Adding Printer "" $($WEPrinterName)"""
            Add-Printer -Name $WEPrinterName -DriverName $WEDriverName -PortName $WEPortName -Confirm:$false
        }
        else {
            Write-LogEntry -Stamp -Value " Printer "" $($WEPrinterName)"" already exists. Removing old printer..."
            Remove-Printer -Name $WEPrinterName -Confirm:$false
            Write-LogEntry -Stamp -Value " Adding Printer "" $($WEPrinterName)"""
            Add-Printer -Name $WEPrinterName -DriverName $WEDriverName -PortName $WEPortName -Confirm:$false
        }

        $WEPrinterExist2 = Get-Printer -Name $WEPrinterName -ErrorAction SilentlyContinue
        if ($WEPrinterExist2) {
            Write-LogEntry -Stamp -Value " Printer "" $($WEPrinterName)"" added successfully"
        }
        else {
            Write-Warning " Error creating Printer"
            Write-LogEntry -Stamp -Value " Printer "" $($WEPrinterName)"" error creating printer"
           ;  $WEThrowBad = $WETrue
        }
    }
    Catch {
        Write-Warning " Error creating Printer"
        Write-Warning " $($_.Exception.Message)"
        Write-LogEntry -Stamp -Value " Error creating Printer"
        Write-LogEntry -Stamp -Value " $($_.Exception)"
       ;  $WEThrowBad = $WETrue
    }
}

If ($WEThrowBad) {
    Write-Error " An error was thrown during installation. Installation failed. Refer to the log file in %temp% for details"
    Write-LogEntry -Stamp -Value " Installation Failed"
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================