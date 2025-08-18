<#
.SYNOPSIS
    Remeditate

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
    We Enhanced Remeditate

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

[CmdletBinding()]
function WE-Start-PowerShellSysNative {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory = $false, HelpMessage = " Specify arguments that will be passed to the sysnative PowerShell process." )]
        [ValidateNotNull()]
        [string]$WEArguments
    )

    # Get the sysnative path for powershell.exe
    $WESysNativePowerShell = Join-Path -Path ($WEPSHOME.ToLower().Replace(" syswow64" , " sysnative" )) -ChildPath " powershell.exe"

    # Construct new ProcessStartInfo object to run scriptblock in fresh process
    $WEProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $WEProcessStartInfo.FileName = $WESysNativePowerShell
    $WEProcessStartInfo.Arguments = $WEArguments
    $WEProcessStartInfo.RedirectStandardOutput = $true
    $WEProcessStartInfo.RedirectStandardError = $true
    $WEProcessStartInfo.UseShellExecute = $false
    $WEProcessStartInfo.WindowStyle = " Hidden"
    $WEProcessStartInfo.CreateNoWindow = $true

    # Instatiate the new 64-bit process
    $WEProcess = [System.Diagnostics.Process]::Start($WEProcessStartInfo)

    # Read standard error output to determine if the 64-bit script process somehow failed
   ;  $WEErrorOutput = $WEProcess.StandardError.ReadToEnd()
    if ($WEErrorOutput) {
        Write-Error -Message $WEErrorOutput
    }
}#endfunction

 # Enable TLS 1.2 support for downloading modules from PSGallery (Required)
 [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
; 
$WEManufacturer = (Get-CimInstance -Class " Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()
switch -Wildcard ($WEManufacturer) {
    " *HP*" {
        Write-output " Validated HP hardware check" 
    }
    " *Hewlett-Packard*" {
        Write-output " Validated HP hardware check" 
    }
    default {
        Write-output " Not running on HP Hardware, Script not applicable" ; exit 0
    }
}


try {
Write-Output " Attempting to install latest NuGet package provider"
$WEPackageProvider = Install-PackageProvider -Name " NuGet" -Force -ErrorAction Stop -Verbose:$false
}
catch [System.Exception] {
    Write-output " Unable to install latest NuGet package provider. Error message: $($_.Exception.Message)" ; exit 1
}   


if ($WEPackageProvider.Version -ge " 2.8.5" ){
    $WEPowerShellGetInstalledModule = Get-InstalledModule -Name " PowerShellGet" -ErrorAction SilentlyContinue -Verbose:$false
    if ($null -ne $WEPowerShellGetInstalledModule) {
        try {
            # Attempt to locate the latest available version of the PowerShellGet module from repository
            Write-Output " Attempting to request the latest PowerShellGet module version from repository" 
           ;  $WEPowerShellGetLatestModule = Find-Module -Name " PowerShellGet" -ErrorAction Stop -Verbose:$false
            if ($null -ne $WEPowerShellGetLatestModule) {
                if ($WEPowerShellGetInstalledModule.Version -lt $WEPowerShellGetLatestModule.Version) {
                    try {
                        # Newer module detected, attempt to update
                        Write-Output " Newer version detected, attempting to update the PowerShellGet module from repository" 
                        Update-Module -Name " PowerShellGet" -Scope " AllUsers" -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                    }
                    catch [System.Exception] {
                        Write-Output " Failed to update the PowerShellGet module. Error message: $($_.Exception.Message)" ; exit 1
                    }
                }
            }
            else {
                Write-Output " Location request for the latest available version of the PowerShellGet module failed, can't continue" ; exit 1
            }
        }
        catch [System.Exception] {
            Write-Output " Failed to retrieve the latest available version of the PowerShellGet module, can't continue. Error message: $($_.Exception.Message)" ; exit 1
        }
    } else {
        try {
            # PowerShellGet module was not found, attempt to install from repository
            Write-Output " PowerShellGet module was not found, attempting to install it including dependencies from repository" 
            Write-Output " Attempting to install PackageManagement module from repository" 
            Install-Module -Name " PackageManagement" -Force -Scope AllUsers -AllowClobber -ErrorAction Stop -Verbose:$false
            Write-Output " Attempting to install PowerShellGet module from repository" 
            Install-Module -Name " PowerShellGet" -Force -Scope AllUsers -AllowClobber -ErrorAction Stop -Verbose:$false
        }
        catch [System.Exception] {
            Write-Output " Unable to install PowerShellGet module from repository. Error message: $($_.Exception.Message)" ; exit 1
        }
    }
    
    #Install the latest HPCMSL Module
    $WEHPInstalledModule = Get-InstalledModule -ErrorAction Stop | Where-Object {$_.Name -match " HPCMSL" } -ErrorAction SilentlyContinue -Verbose:$false
    if ($null -ne $WEHPInstalledModule) {
       ;  $WEHPGetLatestModule = Find-Module -Name " HPCMSL" -ErrorAction Stop -Verbose:$false
        if ($WEHPInstalledModule.Version -lt $WEHPGetLatestModule.Version) {
            Write-Output " Newer HPCMSL version detected, updating from repository"
           ;  $scriptBlock = {
                try {
                    # Install HP Client Management Script Library
                    Write-Output -Value " Attempting to install HPCMSL module from repository" 
                    Install-Module -Name " HPCMSL" -AcceptLicense -Force -SkipPublisherCheck -ErrorAction Stop -Verbose:$false
                } 
                catch [System.Exception] {
                    Write-OutPut -Value " Unable to install HPCMSL module from repository. Error message: $($_.Exception.Message)" ; exit 1
                }
            } 
            Start-PowerShellSysNative -Arguments " -ExecutionPolicy Bypass $($scriptBlock)"
        } else {
            Write-Output " HPCMSL Module is up to date" ; exit 0
        }
    } else {
        Write-Output " HPCMSL Module is missing, try to install from repository"
        $scriptBlock = {
            try {
                # Install HP Client Management Script Library
                Write-Output -Value " Attempting to install HPCMSL module from repository" 
                Install-Module -Name " HPCMSL" -AcceptLicense -Force -ErrorAction Stop -Verbose:$false
            } 
            catch [System.Exception] {
                Write-OutPut -Value " Unable to install HPCMSL module from repository. Error message: $($_.Exception.Message)" ; exit 1
            }
        } 
        Start-PowerShellSysNative -Arguments " -ExecutionPolicy Bypass $($scriptBlock)"
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================