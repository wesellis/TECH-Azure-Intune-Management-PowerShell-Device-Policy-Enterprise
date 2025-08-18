<#
.SYNOPSIS
    Script Intunepstemplate

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
    We Enhanced Script Intunepstemplate

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


if (-not[System.Environment]::Is64BitProcess) {
     # Get the sysnative path for powershell.exe
    $WESysNativePowerShell = Join-Path -Path ($WEPSHOME.ToLower().Replace("syswow64" , " sysnative" )) -ChildPath " powershell.exe"

    # Construct new ProcessStartInfo object to restart powershell.exe as a 64-bit process and re-run scipt
    $WEProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $WEProcessStartInfo.FileName = $WESysNativePowerShell
    $WEProcessStartInfo.Arguments = " -ExecutionPolicy Bypass -File "" $($WEPSCommandPath)"""
    $WEProcessStartInfo.RedirectStandardOutput = $true
    $WEProcessStartInfo.RedirectStandardError = $true
    $WEProcessStartInfo.UseShellExecute = $false
    $WEProcessStartInfo.WindowStyle = " Hidden"
    $WEProcessStartInfo.CreateNoWindow = $true

    # Instatiate the new 64-bit process
   ;  $WEProcess = [System.Diagnostics.Process]::Start($WEProcessStartInfo)

    # Read standard error output to determine if the 64-bit script process somehow failed
   ;  $WEErrorOutput = $WEProcess.StandardError.ReadToEnd()
    if ($WEErrorOutput) {
        Write-Error -Message $WEErrorOutput
    }
}
else {
    # Code to be executed as 64-bit
}

# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================