<#
.SYNOPSIS
    Update Software

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
    We Enhanced Update Software

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
    [switch]$WEWhatIf = $false,
    [string[]]$WEIncludePackages = @(),
    [string[]]$WEExcludePackages = @()
)


Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force


function WE-Test-WingetAvailability {
    try {
        $winget = Get-Command winget -ErrorAction Stop
        Write-Output " Winget is available at: $($winget.Source)"
        return $true
    } catch {
        Write-Warning " Winget is not available on this system"
        return $false
    }
}


function WE-Get-OutdatedPackages {
    try {
        Write-Output " Checking for available software updates..."
        $upgrades = winget upgrade --accept-source-agreements 2>$null | Out-String
        
        if ($upgrades -match " No available upgrades" ) {
            Write-Output " No software updates available"
            return @()
        }
        
        # Parse winget output to get package list
        # Pattern matching for validation
# Pattern matching for validation
$lines = $upgrades -split " `n" | Where-Object { $_ -match " ^[^-]+\s+[^-]+\s+[^-]+\s+[^-]+" -and $_ -notmatch " ^Name" }
        
        $packages = @()
        foreach ($line in $lines) {
            if ($line.Trim() -ne "" ) {
                $parts = $line -split " \s{2,}" | Where-Object { $_.Trim() -ne "" }
                if ($parts.Count -ge 3) {
                    $packages = $packages + [PSCustomObject]@{
                        Name = $parts[0].Trim()
                        Id = $parts[1].Trim()
                        Version = $parts[2].Trim()
                        Available = if ($parts.Count -gt 3) { $parts[3].Trim() } else { " Unknown" }
                    }
                }
            }
        }
        
        Write-Output " Found $($packages.Count) packages with available updates"
        return $packages
        
    } catch {
        Write-Error " Failed to check for software updates: $($_.Exception.Message)"
        return @()
    }
}


function WE-Get-FilteredPackages {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [array]$WEPackages,
        [string[]]$WEIncludeList,
        [string[]]$WEExcludeList
    )
    
    $filtered = $WEPackages
    
    # Apply include filter if specified
    if ($WEIncludeList.Count -gt 0) {
        $filtered = $filtered | Where-Object {
            $package = $_
            $WEIncludeList | ForEach-Object {
                if ($package.Name -like " *$_*" -or $package.Id -like " *$_*" ) {
                    return $package
                }
            }
        }
        Write-Output " After include filter: $($filtered.Count) packages"
    }
    
    # Apply exclude filter
    if ($WEExcludeList.Count -gt 0) {
        $filtered = $filtered | Where-Object {
            $package = $_
            $exclude = $false
            foreach ($excludePattern in $WEExcludeList) {
                if ($package.Name -like " *$excludePattern*" -or $package.Id -like " *$excludePattern*" ) {
                    $exclude = $true
                    break
                }
            }
            return -not $exclude
        }
        Write-Output " After exclude filter: $($filtered.Count) packages"
    }
    
    return $filtered
}


function WE-Update-SoftwarePackages {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [array]$WEPackages,
        [switch]$WEWhatIf
    )
    
    if ($WEPackages.Count -eq 0) {
        Write-Output " No packages to update"
        return $true
    }
    
    $successCount = 0
    $failureCount = 0
    
    foreach ($package in $WEPackages) {
        try {
            if ($WEWhatIf) {
                Write-Output " [WHATIF] Would update: $($package.Name) ($($package.Id)) from $($package.Version) to $($package.Available)"
                $successCount++
            } else {
                Write-Output " Updating: $($package.Name) ($($package.Id))..."
                
                # Update the package using winget
                $result = winget upgrade --id $package.Id --accept-package-agreements --accept-source-agreements --silent 2>&1
                
                if ($WELASTEXITCODE -eq 0) {
                    Write-Output " Successfully updated: $($package.Name)"
                    $successCount++
                } else {
                    Write-Warning " Failed to update $($package.Name): $result"
                    $failureCount++
                }
            }
        } catch {
            Write-Error " Error updating $($package.Name): $($_.Exception.Message)"
            $failureCount++
        }
    }
    
    Write-Output " Update summary: $successCount successful, $failureCount failed"
    
    # Return success if more than 80% succeeded or no failures
    return ($failureCount -eq 0 -or ($successCount / ($successCount + $failureCount)) -gt 0.8)
}


function WE-Test-SystemRequirements {
    try {
        # Check Windows version (Winget requires Windows 10 1709 or later)
        $osVersion = [System.Environment]::OSVersion.Version
        if ($osVersion.Major -lt 10) {
            Write-Error " This script requires Windows 10 or later"
            return $false
        }
        
        # Check if running as administrator for some updates
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] " Administrator" )
        if (-not $isAdmin) {
            Write-Warning " Running without administrator privileges. Some updates may fail."
        }
        
        Write-Output " System requirements check passed"
        return $true
        
    } catch {
        Write-Warning " Cannot verify system requirements: $($_.Exception.Message)"
        return $true  # Assume compatible if we can't check
    }
}


try {
    Write-Output " Starting software update remediation script"
    
    if ($WEWhatIf) {
        Write-Output " [WHATIF] Running in simulation mode - no changes will be made"
    }
    
    if ($WEIncludePackages.Count -gt 0) {
        Write-Output " Include filter: $($WEIncludePackages -join ', ')"
    }
    
    if ($WEExcludePackages.Count -gt 0) {
        Write-Output " Exclude filter: $($WEExcludePackages -join ', ')"
    }
    
    # Check system requirements
    if (-not (Test-SystemRequirements)) {
        Write-Error " System requirements not met"
        exit 1
    }
    
    # Check if Winget is available
    if (-not (Test-WingetAvailability)) {
        Write-Error " Winget package manager is required but not available"
        exit 1
    }
    
    # Get list of outdated packages
    $outdatedPackages = Get-OutdatedPackages
    
    if ($outdatedPackages.Count -eq 0) {
        Write-Output " All software packages are up to date"
        exit 0
    }
    
    # Apply filters
   ;  $packagesToUpdate = Get-FilteredPackages -Packages $outdatedPackages -IncludeList $WEIncludePackages -ExcludeList $WEExcludePackages
    
    if ($packagesToUpdate.Count -eq 0) {
        Write-Output " No packages match the specified criteria for update"
        exit 0
    }
    
    # Update packages
   ;  $success = Update-SoftwarePackages -Packages $packagesToUpdate -WhatIf:$WEWhatIf
    
    if ($success) {
        Write-Output " Software update remediation completed successfully"
        exit 0
    } else {
        Write-Error " Software update remediation completed with errors"
        exit 1
    }
    
} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    exit 1
}





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================