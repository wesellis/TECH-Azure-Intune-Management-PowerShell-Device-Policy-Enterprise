<#
.SYNOPSIS
    Remediate Netbios

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
    We Enhanced Remediate Netbios

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
$changedEntries


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

Set-ExecutionPolicy -scope Process Unrestricted

$reg_path = " HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" # Enter the Registry key path.
$reg_key = " NetbiosOptions" # Enter the Registry key dword name.
$reg_value = 2 # Enter the desired value to REMEDIATE the vulnerability.
$reg_type = " DWORD" # Do not change unless the Value is not a DWORD


$results = @()
$changedEntries = @()

try {
    # Change the value of the " NetbiosOptions" registry key for each interface
    $child_items = Get-ChildItem $reg_path
    foreach ($child_item in $child_items) {
        $interface_name = $child_item.PSChildName
        $interface_path = $child_item.PSPath

        New-ItemProperty -Path $interface_path -Name $reg_key -PropertyType $reg_type -Value $reg_value -Force

        # Recheck the value of the " NetbiosOptions" registry key for the interface
        $regentry = Get-ItemProperty -Path $interface_path -Name $reg_key

        if ($regentry.$reg_key -eq $reg_value) {
            # Outcome if disabled
            $outcome = " $interface_name - Netbios is Disabled!"
            $results = $results + $outcome
            $changedEntries = $changedEntries + $interface_name
            Write-Host $outcome
        } elseif ($regentry.$reg_key -eq $null) {
            # Outcome if registry key does not exist
            $outcome = " $interface_name - Yousa registry key does not exist!"
            $results = $results + $outcome
            Write-Host $outcome
        } else {
            # Outcome if not disabled
            $outcome = " $interface_name - Netbios is not disabled. Mesa running again!"
            $results = $results + $outcome
            Write-Host $outcome
        }
    }

    # Check if any interface was not disabled or had a missing registry key
    # Pattern matching for validation; 
# Pattern matching for validation
$failed = $results -match " Netbios is not disabled|Yousa registry key does not exist"
    if ($failed) {
        # Exit 1 for Intune if any interface failed
        Write-WELog " Some interfaces are not disabled or have missing registry keys. Exiting." " INFO"
        exit 1
    } else {
        # Exit 0 for Intune if all interfaces passed
        Write-WELog " All interfaces are disabled. Exiting. Beep Boop boooooop..." " INFO"
        exit 0
    }

} catch {
   ;  $errMsg = $_.Exception.Message
    return $errMsg
    exit 1
}


Write-WELog " Outcome of each interface entry:" " INFO"
$results


Write-WELog " Changed entries:" " INFO"
$changedEntries


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================