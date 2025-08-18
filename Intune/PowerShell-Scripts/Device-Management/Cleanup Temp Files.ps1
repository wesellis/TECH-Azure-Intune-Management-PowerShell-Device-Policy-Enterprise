<#
.SYNOPSIS
    Cleanup Temp Files

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
    We Enhanced Cleanup Temp Files

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
    [int]$WEDaysOld = 7,
    [switch]$WEIncludeRecycleBin = $false
)


Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force


$WETempDirectories = @(
    $env:TEMP,
    $env:TMP,
    " $env:LOCALAPPDATA\Temp" ,
    " $env:WINDIR\Temp" ,
    " $env:WINDIR\Prefetch" ,
    " $env:LOCALAPPDATA\Microsoft\Windows\INetCache" ,
    " $env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files"
)


$WETempExtensions = @(
    " *.tmp" ,
    " *.temp" ,
    " *.log" ,
    " *.dmp" ,
    " *.chk" ,
    " *.old" ,
    " *.bak"
)


function WE-Get-ReadableFileSize {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param([long]$WESize)
    
    $WEUnits = @(" B" , " KB" , " MB" , " GB" , " TB" )
    $WEIndex = 0
    
    while ($WESize -gt 1024 -and $WEIndex -lt $WEUnits.Length - 1) {
        $WESize = $WESize / 1024
        $WEIndex++
    }
    
    return " {0:N2} {1}" -f $WESize, $WEUnits[$WEIndex]
}


function WE-Remove-TempItems {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath,
        [string[]]$WEExtensions,
        [int]$WEDaysOld,
        [switch]$WEWhatIf
    )
    
    $WEItemsRemoved = 0
   ;  $WESizeFreed = 0
   ;  $WEErrors = 0
    
    try {
        if (-not (Test-Path $WEPath)) {
            Write-Verbose " Path does not exist: $WEPath"
            return [PSCustomObject]@{ ItemsRemoved = 0; SizeFreed = 0; Errors = 0 }
        }
        
        Write-Output " Processing directory: $WEPath"
        
        # Calculate cutoff date
        $WECutoffDate = (Get-Date).AddDays(-$WEDaysOld)
        
        # Get files to delete
        $WEFilesToDelete = @()
        foreach ($extension in $WEExtensions) {
            try {
                $files = Get-ChildItem -Path $WEPath -Filter $extension -Recurse -File -ErrorAction SilentlyContinue |
                         Where-Object { $_.LastWriteTime -lt $WECutoffDate }
                $WEFilesToDelete = $WEFilesToDelete + $files
            } catch {
                Write-Verbose " Error getting files with extension $extension in $WEPath: $($_.Exception.Message)"
            }
        }
        
        # Also get old directories (empty or containing only temp files)
        $WEDirectoriesToDelete = @()
        try {
            $WEDirectoriesToDelete = Get-ChildItem -Path $WEPath -Directory -Recurse -ErrorAction SilentlyContinue |
                                  Where-Object { $_.LastWriteTime -lt $WECutoffDate }
        } catch {
            Write-Verbose " Error getting directories in $WEPath: $($_.Exception.Message)"
        }
        
        # Process files
        foreach ($file in $WEFilesToDelete) {
            try {
                if ($WEWhatIf) {
                    Write-Output " [WHATIF] Would delete file: $($file.FullName) ($(Get-ReadableFileSize $file.Length))"
                    $WEItemsRemoved++
                    $WESizeFreed = $WESizeFreed + $file.Length
                } else {
                    $fileSize = $file.Length
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-Verbose " Deleted file: $($file.FullName)"
                    $WEItemsRemoved++
                   ;  $WESizeFreed = $WESizeFreed + $fileSize
                }
            } catch {
                Write-Warning " Failed to delete file $($file.FullName): $($_.Exception.Message)"
                $WEErrors++
            }
        }
        
        # Process empty directories
        foreach ($directory in ($WEDirectoriesToDelete | Sort-Object FullName -Descending)) {
            try {
                # Check if directory is empty or contains only files we're about to delete
               ;  $remainingItems = Get-ChildItem -Path $directory.FullName -Recurse -ErrorAction SilentlyContinue
                
                if ($remainingItems.Count -eq 0) {
                    if ($WEWhatIf) {
                        Write-Output " [WHATIF] Would delete empty directory: $($directory.FullName)"
                        $WEItemsRemoved++
                    } else {
                        Remove-Item -Path $directory.FullName -Force -Recurse -ErrorAction Stop
                        Write-Verbose " Deleted empty directory: $($directory.FullName)"
                        $WEItemsRemoved++
                    }
                }
            } catch {
                Write-Warning " Failed to delete directory $($directory.FullName): $($_.Exception.Message)"
                $WEErrors++
            }
        }
        
    } catch {
        Write-Error " Failed to process directory $WEPath: $($_.Exception.Message)"
        $WEErrors++
    }
    
    return [PSCustomObject]@{
        ItemsRemoved = $WEItemsRemoved
        SizeFreed = $WESizeFreed
        Errors = $WEErrors
    }
}


function WE-Clear-RecycleBin {
    [CmdletBinding()]; 
$ErrorActionPreference = " Stop"
param([switch]$WEWhatIf)
    
    try {
        if ($WEWhatIf) {
            Write-Output " [WHATIF] Would empty the Recycle Bin"
            return [PSCustomObject]@{ Success = $true; Error = $null }
        } else {
            # Clear recycle bin using shell application
            $shell = New-Object -ComObject Shell.Application
           ;  $recycleBin = $shell.Namespace(0xA)
            
            if ($recycleBin.Items().Count -gt 0) {
                $recycleBin.Items() | ForEach-Object { $_.InvokeVerb(" delete" ) }
                Write-Output " Recycle Bin emptied successfully"
            } else {
                Write-Output " Recycle Bin is already empty"
            }
            
            return [PSCustomObject]@{ Success = $true; Error = $null }
        }
    } catch {
        $errorMsg = " Failed to empty Recycle Bin: $($_.Exception.Message)"
        Write-Warning $errorMsg
        return [PSCustomObject]@{ Success = $false; Error = $errorMsg }
    }
}


function WE-Start-DiskCleanup {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param([switch]$WEWhatIf)
    
    try {
        if ($WEWhatIf) {
            Write-Output " [WHATIF] Would run Windows Disk Cleanup utility"
            return $true
        } else {
            Write-Output " Running Windows Disk Cleanup..."
            
            # Run disk cleanup silently
            $cleanupProcess = Start-Process -FilePath " cleanmgr.exe" -ArgumentList " /sagerun:1" -Wait -PassThru -WindowStyle Hidden
            
            if ($cleanupProcess.ExitCode -eq 0) {
                Write-Output " Disk Cleanup completed successfully"
                return $true
            } else {
                Write-Warning " Disk Cleanup completed with exit code: $($cleanupProcess.ExitCode)"
                return $false
            }
        }
    } catch {
        Write-Warning " Failed to run Disk Cleanup: $($_.Exception.Message)"
        return $false
    }
}


function WE-Get-DiskSpaceInfo {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param([string]$WEDrive = " C:" )
    
    try {
        $disk = Get-CimInstance -Class Win32_LogicalDisk -Filter " DeviceID='$WEDrive'"
        
        return [PSCustomObject]@{
            Drive = $WEDrive
            TotalSize = $disk.Size
            FreeSpace = $disk.FreeSpace
            UsedSpace = $disk.Size - $disk.FreeSpace
            FreeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        }
    } catch {
        Write-Warning " Failed to get disk space information for $WEDrive: $($_.Exception.Message)"
        return $null
    }
}


try {
    Write-Output " Starting temporary files cleanup remediation script"
    
    if ($WEWhatIf) {
        Write-Output " [WHATIF] Running in simulation mode - no changes will be made"
    }
    
    Write-Output " Configuration:"
    Write-Output "  - Days old threshold: $WEDaysOld"
    Write-Output "  - Include Recycle Bin: $WEIncludeRecycleBin"
    
    # Get initial disk space
    $initialDiskSpace = Get-DiskSpaceInfo
    if ($initialDiskSpace) {
        Write-Output " Initial disk space on $($initialDiskSpace.Drive):"
        Write-Output "  - Total: $(Get-ReadableFileSize $initialDiskSpace.TotalSize)"
        Write-Output "  - Free: $(Get-ReadableFileSize $initialDiskSpace.FreeSpace) ($($initialDiskSpace.FreeSpacePercent)%)"
    }
    
    $totalItemsRemoved = 0
    $totalSizeFreed = 0
    $totalErrors = 0
    
    # Clean temp directories
    foreach ($tempDir in $WETempDirectories) {
        if ([string]::IsNullOrEmpty($tempDir)) { continue }
        
        $result = Remove-TempItems -Path $tempDir -Extensions $WETempExtensions -DaysOld $WEDaysOld -WhatIf:$WEWhatIf
        $totalItemsRemoved = $totalItemsRemoved + $result.ItemsRemoved
        $totalSizeFreed = $totalSizeFreed + $result.SizeFreed
        $totalErrors = $totalErrors + $result.Errors
    }
    
    # Clear recycle bin if requested
    if ($WEIncludeRecycleBin) {
        $recycleBinResult = Clear-RecycleBin -WhatIf:$WEWhatIf
        if (-not $recycleBinResult.Success) {
            $totalErrors++
        }
    }
    
    # Run disk cleanup
    $diskCleanupSuccess = Start-DiskCleanup -WhatIf:$WEWhatIf
    if (-not $diskCleanupSuccess) {
        $totalErrors++
    }
    
    # Get final disk space
    if (-not $WEWhatIf) {
        Start-Sleep -Seconds 2  # Allow time for cleanup to complete
       ;  $finalDiskSpace = Get-DiskSpaceInfo
        if ($finalDiskSpace -and $initialDiskSpace) {
           ;  $spaceFreed = $finalDiskSpace.FreeSpace - $initialDiskSpace.FreeSpace
            Write-Output " Final disk space on $($finalDiskSpace.Drive):"
            Write-Output "  - Total: $(Get-ReadableFileSize $finalDiskSpace.TotalSize)"
            Write-Output "  - Free: $(Get-ReadableFileSize $finalDiskSpace.FreeSpace) ($($finalDiskSpace.FreeSpacePercent)%)"
            Write-Output "  - Space freed: $(Get-ReadableFileSize $spaceFreed)"
        }
    }
    
    # Summary
    Write-Output " Cleanup Summary:"
    Write-Output "  - Items processed: $totalItemsRemoved"
    Write-Output "  - Size freed: $(Get-ReadableFileSize $totalSizeFreed)"
    Write-Output "  - Errors encountered: $totalErrors"
    
    if ($totalErrors -eq 0) {
        Write-Output " Temporary files cleanup completed successfully"
        exit 0
    } else {
        Write-Warning " Temporary files cleanup completed with $totalErrors errors"
        exit 1
    }
    
} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    exit 1
}





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================