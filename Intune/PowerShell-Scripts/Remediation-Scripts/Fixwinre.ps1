<#
.SYNOPSIS
    Fixwinre

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
    We Enhanced Fixwinre

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

$disk = Get-Disk | Where-Object { $_.PartitionStyle -eq 'GPT' } | Sort-Object -Property Number | Select-Object -Last 1


$partition = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Type -eq 'Recovery' }


$allPartitions = Get-Partition -DiskNumber $disk.Number | Sort-Object -Property PartitionNumber


if ($partition.PartitionNumber -eq $allPartitions[-1].PartitionNumber) {
    # Calculate the new size in bytes
   ;  $newSize = 1GB

    # Calculate the size to add in bytes
   ;  $sizeToAdd = $newSize - $partition.Size

    # Resize the partition
    Resize-Partition -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -Size ($partition.Size + $sizeToAdd)
} else {
    Write-Output " The Win RE partition is not the last partition on the disk."
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================