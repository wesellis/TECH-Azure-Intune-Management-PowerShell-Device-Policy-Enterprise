<#
.SYNOPSIS
    Intunegraph Example

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
    We Enhanced Intunegraph Example

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


function WE-Filter-Intune($emailAddress,$WEOSVersion)



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

function WE-Filter-Intune($emailAddress,$WEOSVersion)
{
  if($emailAddress -ne $null)
  {
    $intuneDevices = Get-MgDeviceManagementManagedDevices | Where-Object {$_.EmailAddress -eq " $($emailAddress)" }
    if($intuneDevices.Count -gt 0)
    {
      $userDevices = $intuneDevices | Select-Object DisplayName,OSVersion
     if($osVersion -ne $null)
     {
      ;  $selectedDevices = $userDevices | Where-Object {$_.OSVersion -match " $($WEOSVersion)" }
       return $selectedDevices
     }
     else
     {
      ;  $selectedDevices = $userDevices
       return $userDevices
     }
    }
    else
    {
      Write-WELog " No device found associated with $($emailAddress)" " INFO"
    }
  }
  else
  {
    Write-Host " No email address provided to function
  }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================