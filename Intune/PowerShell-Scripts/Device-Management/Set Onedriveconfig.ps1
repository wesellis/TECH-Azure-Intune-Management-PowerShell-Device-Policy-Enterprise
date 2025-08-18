<#
.SYNOPSIS
    Set Onedriveconfig

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
    We Enhanced Set Onedriveconfig

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

if (-not[System.Environment]::Is64BitProcess) {
    # Get the sysnative path for powershell.exe
   $WESysNativePowerShell = Join-Path -Path ($WEPSHOME.ToLower().Replace(" syswow64" , " sysnative" )) -ChildPath " powershell.exe"

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
   $WEProcess = [System.Diagnostics.Process]::Start($WEProcessStartInfo)

   # Read standard error output to determine if the 64-bit script process somehow failed
   $WEErrorOutput = $WEProcess.StandardError.ReadToEnd()
   if ($WEErrorOutput) {
       Write-Error -Message $WEErrorOutput
   }
}
else {
    # Construct a list of custom objects to configure OneDrive
    $WERegistryList = New-Object -TypeName System.Collections.ArrayList

    # Construct custom object for enabling silent account configuration
   ;  $WERegistryItem = [PSCustomObject]@{
        " Path" = " HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        " Name" = " SilentAccountConfig"
        " Value" = " 1"
    }
    $WERegistryList.Add($WERegistryItem) | Out-Null

    # Construct custom object for enabling Files on Demand
   ;  $WERegistryItem = [PSCustomObject]@{
        " Path" = " HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        " Name" = " FilesOnDemandEnabled"
        " Value" = " 1"
    }
    $WERegistryList.Add($WERegistryItem) | Out-Null

    # Process each item in the array list
    foreach ($WEItem in $WERegistryList) {
        # Verify if registry path exists, if not create key including value
        if (-not(Test-Path -Path $WEItem.Path)) {
            New-Item -Path $WEItem.Path -Force | Out-Null
            New-ItemProperty -Path $WEItem.Path -Name $WEItem.Name -Value $WEItem.Value -PropertyType DWORD -Force | Out-Null
        }
        else {
            New-ItemProperty -Path $WEItem.Path -Name $WEItem.Name -Value $WEItem.Value -PropertyType DWORD -Force | Out-Null
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================