<#
.SYNOPSIS
    W365 Backup

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
    We Enhanced W365 Backup

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


function log
{
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
        [string]$WEMessage
    )
    $WETimeStamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
    Write-Output = " $WETimeStamp - $WEMessage"
}


$WELogFile = " $($env:PROGRAMDATA)\w365Backup.log"

if(!(Test-Path $WELogFile))
{
    New-Item -Path $WELogFile -ItemType File
}

Start-Transcript -Path $WELogFile -Append -Verbose
log " Starting w365BACKUP script..."


$WEStorageAccountName = " <STORAGE ACCOUNT NAME>"
$WEStorageAccountKey = " <STORAGE ACCOUNT KEY>"
$WESASToken = " <SAS TOKEN>"
$WEFileShare = " <FILESHARE NAME>"


$WECurrentUser = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName
$WECurrentUserSID = (New-Object System.Security.Principal.NTAccount($WECurrentUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
log " Current user: $($WECurrentUser)"
log " Current user SID: $($WECurrentUserSID)"


log " Checking for Az.Storage module..."
if(-not(Get-Module -ListAvailable -Name Az.Storage -ErrorAction SilentlyContinue))
{
    log " Az.Storage module not found. Installing..."
    Install-Module -Name Az.Storage -Force -AllowClobber -Verbose
}
else 
{
    log " Az.Storage module found."
}

Import-Module Az.Storage



log " Setting storage context..."
$WEStorageContext = New-AzStorageContext -StorageAccountName $WEStorageAccountName -StorageAccountKey $WEStorageAccountKey
if(-not $WEStorageContext)
{  
    log " Failed to set storage context"
    Exit 1
}
else 
{
    log " Storage context is set"
}


log " Checking for existing SID folder in Azure Storage..."
$WEAzureShare = Get-AzStorageFile -ShareName $WEFileShare -Path $WECurrentUserSID -Context $WEStorageContext -ErrorAction SilentlyContinue
if($null -eq $WEAzureShare)
{
    log " Folder not found. Creating..."
    New-AzStorageDirectory -ShareName $WEFileShare -Path $WECurrentUserSID -Context $WEStorageContext
    log " Folder created"
}
else
{
    log " Folder exists"
}


$WEUserLocations = @()
$WEUserProfilePath = (Get-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($WECurrentUserSID)" ).ProfileImagePath
$WESourceFolders = @(" Documents" , " Downloads" , " Desktop" , " Pictures" , " AppData" )
foreach($WEFolder in $WESourceFolders)
{
    $WEUserLocations = $WEUserLocations + " $($WEUserProfilePath)\$($WEFolder)"
    log " Added $($WEUserProfilePath)\$($WEFolder) to backup list"
}


log " Checking for AzCopy..."
$WEAzCopyPath = " C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
if(!(Test-Path $WEAzCopyPath))
{
    log " AzCopy not found. Downloading..."

    $WEAzCopyUrl = " https://aka.ms/downloadazcopy-v10-windows"
    $WETempZipPath = " $($env:TEMP)\azcopy.zip"
    $WEExtractPath = " $($env:TEMP)\azcopy"

    try 
    {
        Invoke-WebRequest -Uri $WEAzCopyUrl -OutFile $WETempZipPath
        Expand-Archive -Path $WETempZipPath -DestinationPath $WEExtractPath -Force
        log " AzCopy downloaded and extracted to $($WEExtractPath)"    
    }
    catch 
    {
        log " Failed to download AzCopy: $_"
        Exit 1
    }

    $WEAzCopyExe = Get-ChildItem -Path $WEExtractPath -Recurse -Filter " azcopy.exe" | Select-Object -First 1 -ExpandProperty FullName
    if($WEAzCopyExe)
    {
       ;  $WEAzCopyPath = $WEAzCopyExe
        log " AzCopy is installed at: $($WEAzCopyPath)"
    }
    else
    {
        log " Error: AzCopy executable not found after extraction."
        Exit 1
    }
}
else
{
    log " AzCopy found at: $WEAzCopyPath"
}


log " Backing up user data to Azure..." ; 
$WEDestinationPath = " https://$($WEStorageAccountName).file.core.windows.net/$($WEFileShare)/$($WECurrentUserSID)?$($WESASToken)"
foreach($WELocation in $WEUserLocations)
{
    log " Copying $WELocation to Azure"
    try 
    {
        Start-Process -Wait $WEAzCopyPath -ArgumentList " copy $($WELocation) $($WEDestinationPath) --recursive=true"
        log " Copied $WELocation to Azure file share successfully"    
    }
    catch 
    {
        log " Filed to copy $WELocation to Azure File Share: $_"
    }
}

log " User data backup complete."

Stop-Transcript


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================