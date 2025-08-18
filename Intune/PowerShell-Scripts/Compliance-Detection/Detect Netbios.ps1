<#
.SYNOPSIS
    Detect Netbios

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
    We Enhanced Detect Netbios

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


Set-ExecutionPolicy -scope Process Unrestricted



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

Set-ExecutionPolicy -scope Process Unrestricted

$reg_path = " HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" # Enter the Registry key path.
$reg_key = " NetbiosOptions" # Enter the Registry key dword name.
$reg_value = 2 # Enter the desired value to REMEDIATE the vulnerability.


$child_items = Get-ChildItem -ErrorAction Stop $reg_path


$results = @()


foreach ($child_item in $child_items) {
    $interface_name = $child_item.PSChildName
    $regentry = Get-ItemProperty -Path $child_item.PSPath -Name $reg_key

    if ($null -eq $regentry -or $regentry.$reg_key -ne $reg_value) {
        # Outcome if disabled or registry key does not exist
        $outcome = " $interface_name - Not disabled or Registry Key does not exist."
        $results = $results + $outcome

        Write-Information $outcome
    } else {
        # Outcome if enabled
        $outcome = " $interface_name - Netbios is Disabled"
       ;  $results = $results + $outcome
        Write-Information $outcome
    }
}

; 

# Pattern matching for validation
$failed = $results -match " Not disabled|Registry Key does not exist"
if ($failed) {
    # Exit 1 for Intune if any interface failed
    Write-WELog " Some interfaces are not disabled or have missing registry keys. Exiting wiith code 1." " INFO"
    exit 1
} else {
    # Exit 0 for Intune if all interfaces passed
    Write-WELog " All interfaces are disabled. Exiting. Beep Boop boooooop." " INFO"
    exit 0
}


Write-WELog " Outcome of each interface entry:" " INFO"
$results



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================