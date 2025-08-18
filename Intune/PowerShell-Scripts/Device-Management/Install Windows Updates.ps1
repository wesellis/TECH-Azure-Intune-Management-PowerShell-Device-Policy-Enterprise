<#
.SYNOPSIS
    Install Windows Updates

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
    We Enhanced Install Windows Updates

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
$ErrorActionPreference = " Stop"
param(
    [switch]$WEWhatIf = $false
)


Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force


try {
    Import-Module PSWindowsUpdate -ErrorAction Stop
    Write-Output " PSWindowsUpdate module imported successfully"
} catch {
    Write-Warning " PSWindowsUpdate module not available. Installing..."
    if (-not $WEWhatIf) {
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
        Import-Module PSWindowsUpdate
    } else {
        Write-Output " [WHATIF] Would install PSWindowsUpdate module"
        return
    }
}


function WE-Get-AvailableUpdates {
    try {
        $updates = Get-WUList -Verbose:$false
        return $updates
    } catch {
        Write-Error " Failed to retrieve available updates: $($_.Exception.Message)"
        return $null
    }
}


function WE-Install-WindowsUpdates {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [switch]$WEWhatIf
    )
    
    try {
        $updates = Get-AvailableUpdates
        
        if ($null -eq $updates -or $updates.Count -eq 0) {
            Write-Output " No updates available"
            return $true
        }
        
        Write-Output " Found $($updates.Count) available updates"
        
        if ($WEWhatIf) {
            Write-Output " [WHATIF] Would install the following updates:"
            foreach ($update in $updates) {
                Write-Output "  - $($update.Title)"
            }
            return $true
        }
        
        # Install updates (excluding driver updates for safety)
       ;  $result = Install-WindowsUpdate -AcceptAll -IgnoreReboot -NotCategory " Drivers" -Confirm:$false
        
        if ($result) {
            Write-Output " Updates installed successfully"
            return $true
        } else {
            Write-Warning " Some updates may not have installed correctly"
            return $false
        }
        
    } catch {
        Write-Error " Failed to install updates: $($_.Exception.Message)"
        return $false
    }
}


try {
    Write-Output " Starting Windows Updates remediation script"
    
    if ($WEWhatIf) {
        Write-Output " [WHATIF] Running in simulation mode - no changes will be made"
    }
    
   ;  $success = Install-WindowsUpdates -WhatIf:$WEWhatIf
    
    if ($success) {
        Write-Output " Windows Updates remediation completed successfully"
        exit 0
    } else {
        Write-Error " Windows Updates remediation failed"
        exit 1
    }
    
} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    exit 1
}





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================