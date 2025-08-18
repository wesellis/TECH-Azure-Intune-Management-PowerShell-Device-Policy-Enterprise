# ============================================================================
# Wesley Ellis Enterprise Teams Classic Cleanup & Migration Tool
# Author: Wesley Ellis
# Contact: wesellis.com
# Version: 3.0 Enterprise Edition
# Date: August 2025
# Description: Advanced Microsoft Teams Classic removal and migration to New Teams
#              with comprehensive logging, validation, and enterprise reporting
# ============================================================================

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, HelpMessage="Generate detailed cleanup report")]
    [switch]$WEGenerateReport,
    
    [Parameter(Mandatory=$false, HelpMessage="Validate New Teams installation")]
    [switch]$WEValidateNewTeams,
    
    [Parameter(Mandatory=$false, HelpMessage="Test mode - scan only, no removal")]
    [switch]$WETestMode,
    
    [Parameter(Mandatory=$false, HelpMessage="Force removal even if New Teams not detected")]
    [switch]$WEForceRemoval,
    
    [Parameter(Mandatory=$false, HelpMessage="Clean registry entries")]
    [switch]$WECleanRegistry
)

# Wesley Ellis Enhanced Framework
$WEScript = "WE-TeamsCleanup-Enterprise"
$WEVersion = "3.0"
$WEStartTime = Get-Date -ErrorAction Stop

# Enhanced logging function
[CmdletBinding()]
function Write-WETeamsLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "ACTION", "SCAN")]
        [string]$Level = "INFO",
        [string]$User = "SYSTEM"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colorMap = @{
        "INFO" = "White"
        "WARN" = "Yellow" 
        "ERROR" = "Red"
        "SUCCESS" = "Green"
        "ACTION" = "Magenta"
        "SCAN" = "Cyan"
    }
    
    $logEntry = "$timestamp [$WEScript] [$User] [$Level] $Message"
    Write-Information $logEntry -ForegroundColor $colorMap[$Level]
    
    # Always log to file for compliance and auditing
    $logPath = "$env:TEMP\WE-TeamsCleanup-$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logPath -Value $logEntry
}

# Wesley Ellis Teams Installation Detection
[CmdletBinding()]
function Get-WETeamsInstallations -ErrorAction Stop {
    param([string]$UserProfile)
    
    $installations = @()
    
    # Common Classic Teams installation paths
    $teamsPaths = @(
        "$UserProfile\AppData\Local\Microsoft\Teams",
        "$UserProfile\AppData\Roaming\Microsoft\Teams",
        "${env:ProgramFiles}\Microsoft\Teams",
        "${env:ProgramFiles(x86)}\Microsoft\Teams"
    )
    
    foreach ($path in $teamsPaths) {
        if (Test-Path $path) {
            $updateExe = Join-Path $path "Update.exe"
            $teamsExe = Join-Path $path "Teams.exe"
            
            $installation = @{
                Path = $path
                Type = "Classic"
                HasUpdateExe = Test-Path $updateExe
                HasTeamsExe = Test-Path $teamsExe
                Size = if (Test-Path $path) { (Get-ChildItem -ErrorAction Stop $path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum } else { 0 }
                LastModified = if (Test-Path $path) { (Get-Item -ErrorAction Stop $path).LastWriteTime } else { $null }
            }
            
            $installations += $installation
        }
    }
    
    # Check for New Teams (MS Store version)
    $newTeamsPath = Get-AppxPackage -Name "MSTeams*" -AllUsers -ErrorAction SilentlyContinue
    if ($newTeamsPath) {
        $installations += @{
            Path = $newTeamsPath.InstallLocation
            Type = "NewTeams"
            Version = $newTeamsPath.Version
            PackageFullName = $newTeamsPath.PackageFullName
        }
    }
    
    return $installations
}

# Enhanced Teams Uninstallation Function
[CmdletBinding()]
function Remove-WEClassicTeams -ErrorAction Stop {
    param(
        [string]$TeamsPath,
        [string]$UserName,
        [bool]$TestMode = $false
    )
    
    Write-WETeamsLog "Processing Teams installation at: $TeamsPath" "ACTION" $UserName
    
    if ($TestMode) {
        Write-WETeamsLog "TEST MODE: Would remove Classic Teams from $TeamsPath" "SCAN" $UserName
        return @{ Status = "TestMode"; Message = "No removal performed in test mode" }
    }
    
    try {
        $updateExe = Join-Path $TeamsPath "Update.exe"
        
        if (Test-Path $updateExe) {
            Write-WETeamsLog "Executing uninstaller: $updateExe" "ACTION" $UserName
            
            # Kill any running Teams processes first
            $teamsProcesses = Get-Process -Name "Teams*", "ms-teams*" -ErrorAction SilentlyContinue
            if ($teamsProcesses) {
                Write-WETeamsLog "Stopping $($teamsProcesses.Count) Teams processes" "ACTION" $UserName
                $teamsProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }
            
            # Execute uninstaller
            $process = Start-Process -FilePath $updateExe -ArgumentList "--uninstall", "/s" -PassThru -Wait -ErrorAction Stop
            
            if ($process.ExitCode -eq 0) {
                Write-WETeamsLog "Classic Teams uninstaller completed successfully" "SUCCESS" $UserName
                
                # Clean up remaining folders
                Start-Sleep -Seconds 2
                if (Test-Path $TeamsPath) {
                    Remove-Item -Path $TeamsPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-WETeamsLog "Cleaned up remaining folder: $TeamsPath" "SUCCESS" $UserName
                }
                
                return @{ Status = "Success"; Message = "Classic Teams removed successfully" }
            } else {
                Write-WETeamsLog "Uninstaller returned exit code: $($process.ExitCode)" "WARN" $UserName
                return @{ Status = "Warning"; Message = "Uninstaller completed with warnings" }
            }
        } else {
            Write-WETeamsLog "Update.exe not found, attempting manual cleanup" "WARN" $UserName
            
            if (Test-Path $TeamsPath) {
                Remove-Item -Path $TeamsPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-WETeamsLog "Manual cleanup completed" "SUCCESS" $UserName
                return @{ Status = "Success"; Message = "Manual cleanup completed" }
            }
        }
        
    } catch {
        Write-WETeamsLog "Failed to remove Classic Teams: $($_.Exception.Message)" "ERROR" $UserName
        return @{ Status = "Failed"; Error = $_.Exception.Message }
    }
}

# Registry Cleanup Function
[CmdletBinding()]
function Remove-WETeamsRegistry -ErrorAction Stop {
    param([string]$UserName)
    
    if (-not $WECleanRegistry) {
        return @{ Status = "Skipped"; Message = "Registry cleanup not requested" }
    }
    
    Write-WETeamsLog "Performing registry cleanup" "ACTION" $UserName
    
    try {
        $registryPaths = @(
            "HKCU:\Software\Microsoft\Teams",
            "HKCU:\Software\Microsoft\Office\Teams",
            "HKLM:\SOFTWARE\Microsoft\Teams"
        )
        
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-WETeamsLog "Removed registry key: $regPath" "SUCCESS" $UserName
            }
        }
        
        return @{ Status = "Success"; Message = "Registry cleanup completed" }
        
    } catch {
        Write-WETeamsLog "Registry cleanup error: $($_.Exception.Message)" "WARN" $UserName
        return @{ Status = "Warning"; Error = $_.Exception.Message }
    }
}

# Main Execution Block
Write-WETeamsLog "Wesley Ellis Enterprise Teams Cleanup Tool v$WEVersion Starting" "INFO"
Write-WETeamsLog "Author: Wesley Ellis | Contact: wesellis.com" "INFO"
Write-WETeamsLog "Test Mode: $WETestMode | Force Removal: $WEForceRemoval" "INFO"

# Enhanced error handling for enterprise environments
try {
    # Get all user profiles
    $allUsers = Get-ChildItem -Path "$($env:SystemDrive)\Users" -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }
    Write-WETeamsLog "Scanning $($allUsers.Count) user profiles" "INFO"
    
    $WECleanupResults = @()
    $totalClassicInstalls = 0
    $totalNewTeamsInstalls = 0
    $totalSizeRecovered = 0
    
    foreach ($user in $allUsers) {
        # Skip system accounts
        if ($user.Name -in @('Public', 'Default', 'Default User', 'All Users')) {
            continue
        }
        
        Write-WETeamsLog "Processing user profile: $($user.Name)" "SCAN" $user.Name
        
        # Scan for Teams installations
        $installations = Get-WETeamsInstallations -UserProfile $user.FullName
        $classicInstalls = $installations | Where-Object { $_.Type -eq "Classic" }
        $newTeamsInstalls = $installations | Where-Object { $_.Type -eq "NewTeams" }
        
        Write-WETeamsLog "Found $($classicInstalls.Count) Classic Teams installations" "SCAN" $user.Name
        if ($newTeamsInstalls.Count -gt 0) {
            Write-WETeamsLog "New Teams detected: $($newTeamsInstalls[0].Version)" "SUCCESS" $user.Name
        }
        
        $userResults = @{
            UserName = $user.Name
            ClassicInstallationsFound = $classicInstalls.Count
            NewTeamsDetected = $newTeamsInstalls.Count -gt 0
            CleanupResults = @()
            TotalSizeRecovered = 0
        }
        
        # Process each Classic Teams installation
        foreach ($install in $classicInstalls) {
            $totalClassicInstalls++
            $installSizeMB = [math]::Round($install.Size / 1MB, 2)
            $totalSizeRecovered += $install.Size
            $userResults.TotalSizeRecovered += $install.Size
            
            Write-WETeamsLog "Classic Teams found: $($install.Path) ($installSizeMB MB)" "SCAN" $user.Name
            
            # Check if we should proceed with removal
            $shouldRemove = $WEForceRemoval -or $newTeamsInstalls.Count -gt 0 -or (-not $WEValidateNewTeams)
            
            if ($shouldRemove) {
                $cleanupResult = Remove-WEClassicTeams -TeamsPath $install.Path -UserName $user.Name -TestMode $WETestMode
                $userResults.CleanupResults += $cleanupResult
            } else {
                Write-WETeamsLog "Skipping removal - New Teams not detected and force removal disabled" "WARN" $user.Name
                $userResults.CleanupResults += @{ Status = "Skipped"; Message = "New Teams validation failed" }
            }
        }
        
        # Registry cleanup if requested
        if ($classicInstalls.Count -gt 0) {
            $regResult = Remove-WETeamsRegistry -UserName $user.Name
            $userResults.CleanupResults += $regResult
        }
        
        $totalNewTeamsInstalls += $newTeamsInstalls.Count
        $WECleanupResults += $userResults
    }
    
    # Clean up common shortcuts and start menu entries
    Write-WETeamsLog "Cleaning up global shortcuts and start menu entries" "ACTION"
    
    $shortcutPaths = @(
        "$env:SystemDrive\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams*.lnk",
        "$env:SystemDrive\Users\*\Desktop\Microsoft Teams*.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Teams*.lnk"
    )
    
    foreach ($shortcutPath in $shortcutPaths) {
        $shortcuts = Get-Item -ErrorAction Stop $shortcutPath -ErrorAction SilentlyContinue
        if ($shortcuts) {
            if (-not $WETestMode) {
                Remove-Item -ErrorAction Stop $shortcuts -Force -ErrorAction SilentlyContinue
            }
            Write-WETeamsLog "$(if($WETestMode){'Would remove'}else{'Removed'}) $($shortcuts.Count) shortcut(s)" "SUCCESS"
        }
    }
    
    # Generate comprehensive summary
    $totalSizeRecoveredMB = [math]::Round($totalSizeRecovered / 1MB, 2)
    $executionTime = (Get-Date) - $WEStartTime
    
    Write-WETeamsLog "🎉 Wesley Ellis Enterprise Teams Cleanup Complete!" "SUCCESS"
    Write-WETeamsLog "   Users Processed: $($allUsers.Count)" "SUCCESS"
    Write-WETeamsLog "   Classic Teams Found: $totalClassicInstalls" "SUCCESS"
    Write-WETeamsLog "   New Teams Detected: $totalNewTeamsInstalls" "SUCCESS"
    Write-WETeamsLog "   Disk Space Recovered: $totalSizeRecoveredMB MB" "SUCCESS"
    Write-WETeamsLog "   Execution Time: $($executionTime.TotalMinutes.ToString('F1')) minutes" "SUCCESS"
    Write-WETeamsLog "   Contact: wesellis.com" "SUCCESS"
    
    # Export detailed report if requested
    if ($WEGenerateReport) {
        $reportPath = "$env:TEMP\WE-TeamsCleanup-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        
        $report = @{
            ScriptInfo = @{
                Name = $WEScript
                Version = $WEVersion
                Author = "Wesley Ellis"
                Contact = "wesellis.com"
                ExecutionTime = $executionTime.ToString()
                TestMode = $WETestMode
            }
            Summary = @{
                UsersProcessed = $allUsers.Count
                ClassicTeamsFound = $totalClassicInstalls
                NewTeamsDetected = $totalNewTeamsInstalls
                DiskSpaceRecoveredMB = $totalSizeRecoveredMB
            }
            DetailedResults = $WECleanupResults
        }
        
        $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
        Write-WETeamsLog "Detailed report exported: $reportPath" "SUCCESS"
    }
    
    # Exit with appropriate code
    if ($totalClassicInstalls -gt 0) {
        exit 1  # Found and processed Classic Teams installations
    } else {
        exit 0  # No Classic Teams found
    }
    
} catch {
    Write-WETeamsLog "❌ Critical error in Teams cleanup: $($_.Exception.Message)" "ERROR"
    Write-WETeamsLog "Contact wesellis.com for enterprise support" "ERROR"
    exit 2  # Error occurred
}

# Wesley Ellis Enterprise Intune Management Solutions
# Advanced device management: wesellis.com
# ============================================================================