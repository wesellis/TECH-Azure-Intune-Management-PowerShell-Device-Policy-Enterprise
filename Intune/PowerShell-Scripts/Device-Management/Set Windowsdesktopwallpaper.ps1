<#
.SYNOPSIS
    Set Windowsdesktopwallpaper

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
    We Enhanced Set Windowsdesktopwallpaper

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    Replace the default img0.jpg wallpaper image in Windows 10, by downloading the new wallpaper stored in an Azure Storage blob.

.DESCRIPTION
    Downloads a single or multiple desktop wallpaper files located in an Azure Storage Blog container to a folder named Wallpaper in ProgramData.

.PARAMETER StorageAccountName
    Name of the Azure Storage Account.

.PARAMETER ContainerName
    Name of the Azure Storage Blob container.

.EXAMPLE
    .\Set-WindowsDesktopWallpaper.ps1

.NOTES
    FileName:    Set-DesktopWallpaperContent.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-06-04
    Updated:     2020-11-26

    Version history:
    1.0.0 - (2020-06-04) Script created
    1.1.0 - (2020-11-26) Added support for 4K wallpapers

[CmdletBinding(SupportsShouldProcess = $true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $false, HelpMessage = " Name of the Azure Storage Account." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEStorageAccountName = " <StorageAccountName>" ,

    [parameter(Mandatory = $false, HelpMessage = " Name of the Azure Storage Blob container." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEContainerName = " <ContainerName>"
)
Begin {
    # Install required modules for script execution
    $WEModules = @(" NTFSSecurity" , " Az.Storage" , " Az.Resources" )
    foreach ($WEModule in $WEModules) {
        try {
            $WECurrentModule = Get-InstalledModule -Name $WEModule -ErrorAction Stop -Verbose:$false
            if ($WECurrentModule -ne $null) {
                $WELatestModuleVersion = (Find-Module -Name $WEModule -ErrorAction Stop -Verbose:$false).Version
                if ($WELatestModuleVersion -gt $WECurrentModule.Version) {
                    $WEUpdateModuleInvocation = Update-Module -Name $WEModule -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                }
            }
        }
        catch [System.Exception] {
            try {
                # Install NuGet package provider
                $WEPackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false
        
                # Install current missing module
                Install-Module -Name $WEModule -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
            catch [System.Exception] {
                Write-Warning -Message " An error occurred while attempting to install $($WEModule) module. Error message: $($_.Exception.Message)"
            }
        }
    }

    # Determine the localized name of the principals required for the functionality of this script
    $WELocalAdministratorsPrincipal = " BUILTIN\Administrators"
    $WELocalUsersPrincipal = " BUILTIN\Users"
    $WELocalSystemPrincipal = " NT AUTHORITY\SYSTEM"
    $WETrustedInstallerPrincipal = " NT SERVICE\TrustedInstaller"
    $WERestrictedApplicationPackagesPrincipal = " ALL RESTRICTED APPLICATION PACKAGES"
    $WEApplicationPackagesPrincipal = " ALL APPLICATION PACKAGES"

    # Retrieve storage account context
    $WEStorageAccountContext = New-AzStorageContext -StorageAccountName $WEStorageAccountName -Anonymous -ErrorAction Stop
}
Process {
    # Functions
    function WE-Write-LogEntry {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Value added to the log file." )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEValue,
    
            [parameter(Mandatory = $true, HelpMessage = " Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error." )]
            [ValidateNotNullOrEmpty()]
            [ValidateSet(" 1" , " 2" , " 3" )]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESeverity,
    
            [parameter(Mandatory = $false, HelpMessage = " Name of the log file that the entry will written to." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEFileName = " Set-WindowsDesktopWallpaper.log"
        )
        # Determine log file location
        $WELogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath " Temp" ) -ChildPath $WEFileName
        
        # Construct time stamp for log entry
        $WETime = -join @((Get-Date -Format " HH:mm:ss.fff" ), " +" , (Get-CimInstance -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $WEDate = (Get-Date -Format " MM-dd-yyyy" )
        
        # Construct context for log entry
        $WEContext = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $WELogText = " <![LOG[$($WEValue)]LOG]!><time="" $($WETime)"" date="" $($WEDate)"" component="" WindowsDesktopWallpaper"" context="" $($WEContext)"" type="" $($WESeverity)"" thread="" $($WEPID)"" file="""" >"
        
        # Add value to log file
        try {
            Out-File -InputObject $WELogText -Append -NoClobber -Encoding Default -FilePath $WELogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message " Unable to append log entry to Set-WindowsDesktopWallpaper.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function WE-Get-AzureBlobContent {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Name of the Azure Storage Account." )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEStorageAccountName,
    
            [parameter(Mandatory = $true, HelpMessage = " Name of the Azure Storage Blob container." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEContainerName
        )
        try {   
            # Construct array list for return value containing file names
            $WEBlobList = New-Object -TypeName System.Collections.ArrayList
    
            try {
                # Retrieve content from storage account blob
                $WEStorageBlobContents = Get-AzStorageBlob -Container $WEContainerName -Context $WEStorageAccountContext -ErrorAction Stop
                if ($WEStorageBlobContents -ne $null) {
                    foreach ($WEStorageBlobContent in $WEStorageBlobContents) {
                        Write-LogEntry -Value " Adding content file from Azure Storage Blob to return list: $($WEStorageBlobContent.Name)" -Severity 1
                        $WEBlobList.Add($WEStorageBlobContent) | Out-Null
                    }
                }
    
                # Handle return value
                return $WEBlobList
            }
            catch [System.Exception] {
                Write-LogEntry -Value " Failed to retrieve storage account blob contents. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value " Failed to retrieve storage account context. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function WE-Invoke-WallpaperFileDownload {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Name of the image file in the Azure Storage blob." )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEFileName,

            [parameter(Mandatory = $true, HelpMessage = " Download destination directory for the image file." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEDestination
        )        
        try {
            # Download default wallpaper content file from storage account
            Write-LogEntry -Value " Downloading content file from Azure Storage Blob: $($WEFileName)" -Severity 1
            $WEStorageBlobContent = Get-AzStorageBlobContent -Container $WEContainerName -Blob $WEFileName -Context $WEStorageAccountContext -Destination $WEDestination -Force -ErrorAction Stop

            try {
                # Grant non-inherited permissions for wallpaper item
                $WEWallpaperImageFilePath = Join-Path -Path $WEDestination -ChildPath $WEFileName
                Write-LogEntry -Value " Granting '$($WELocalSystemPrincipal)' Read and Execute on: $($WEWallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WEWallpaperImageFilePath -Account $WELocalSystemPrincipal -AccessRights " ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value " Granting '$($WELocalAdministratorsPrincipal)' Read and Execute on: $($WEWallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WEWallpaperImageFilePath -Account $WELocalAdministratorsPrincipal -AccessRights " ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value " Granting '$($WELocalUsersPrincipal)' Read and Execute on: $($WEWallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WEWallpaperImageFilePath -Account $WELocalUsersPrincipal -AccessRights " ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value " Granting '$($WEApplicationPackagesPrincipal)' Read and Execute on: $($WEWallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WEWallpaperImageFilePath -Account $WEApplicationPackagesPrincipal -AccessRights " ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value " Granting '$($WERestrictedApplicationPackagesPrincipal)' Read and Execute on: $($WEWallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WEWallpaperImageFilePath -Account $WERestrictedApplicationPackagesPrincipal -AccessRights " ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value " Granting '$($WETrustedInstallerPrincipal)' Full Control on: $($WEWallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WEWallpaperImageFilePath -Account $WETrustedInstallerPrincipal -AccessRights " FullControl" -ErrorAction Stop
                Write-LogEntry -Value " Disabling inheritance on: $($WEWallpaperImageFilePath)" -Severity 1
                Disable-NTFSAccessInheritance -Path $WEWallpaperImageFilePath -RemoveInheritedAccessRules -ErrorAction Stop

                try {
                    # Set owner to trusted installer for new wallpaper file
                    Write-LogEntry -Value " Setting ownership for '$($WETrustedInstallerPrincipal)' on wallpaper image file: $($WEWallpaperImageFilePath)" -Severity 1
                    Set-NTFSOwner -Path $WEWallpaperImageFilePath -Account $WETrustedInstallerPrincipal -ErrorAction Stop
                }
                catch [System.Exception] {
                    Write-LogEntry -Value " Failed to set ownership for '$($WETrustedInstallerPrincipal)' on wallpaper image file: $($WEWallpaperImageFilePath). Error message: $($_.Exception.Message)" -Severity 3
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value " Failed to revert permissions for wallpaper image file. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value " Failed to downloaded wallpaper content from Azure Storage Blob. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function WE-Remove-WallpaperFile {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Full path to the image file to be removed." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEFilePath
        )
        try {
            # Take ownership of the wallpaper file
            Write-LogEntry -Value " Determining if ownership needs to be changed for file: $($WEFilePath)" -Severity 1
            $WECurrentOwner = Get-Item -Path $WEFilePath | Get-NTFSOwner
            if ($WECurrentOwner.Owner -notlike $WELocalAdministratorsPrincipal) {
                Write-LogEntry -Value " Amending owner as '$($WELocalAdministratorsPrincipal)' temporarily for: $($WEFilePath)" -Severity 1
                Set-NTFSOwner -Path $WEFilePath -Account $WELocalAdministratorsPrincipal -ErrorAction Stop
            }

            try {
                # Grant local Administrators group and system full control
                Write-LogEntry -Value " Granting '$($WELocalSystemPrincipal)' Full Control on: $($WEFilePath)" -Severity 1
                Add-NTFSAccess -Path $WEFilePath -Account $WELocalSystemPrincipal -AccessRights " FullControl" -AccessType " Allow" -ErrorAction Stop
                Write-LogEntry -Value " Granting '$($WELocalAdministratorsPrincipal)' Full Control on: $($WEFilePath)" -Severity 1
                Add-NTFSAccess -Path $WEFilePath -Account $WELocalAdministratorsPrincipal -AccessRights " FullControl" -AccessType " Allow" -ErrorAction Stop

                try {
                    # Remove existing local default wallpaper file
                    Write-LogEntry -Value " Attempting to remove existing default wallpaper image file: $($WEFilePath)" -Severity 1
                    Remove-Item -Path $WEFilePath -Force -ErrorAction Stop
                }
                catch [System.Exception] {
                    Write-LogEntry -Value " Failed to remove wallpaper image file '$($WEFilePath)'. Error message: $($_.Exception.Message)" -Severity 3
                }                    
            }
            catch [System.Exception] {
                Write-LogEntry -Value " Failed to grant Administrators and local system with full control for wallpaper image file. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value " Failed to take ownership of '$($WEFilePath)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    # Check if desktop wallpaper content exists on the specified storage account
    $WEAzureStorageBlobContent = Get-AzureBlobContent -StorageAccountName $WEStorageAccountName -ContainerName $WEContainerName
    if ($WEAzureStorageBlobContent -ne $null) {
        # Replace default wallpaper content locally with item from storage account
        $WEDefaultWallpaperBlobFile = $WEAzureStorageBlobContent | Where-Object { $WEPSItem.Name -like " img0.jpg" }
        if ($WEDefaultWallpaperBlobFile -ne $null) {
            Write-LogEntry -Value " Detected default wallpaper file 'img0' in container, will replace local wallpaper file" -Severity 1

            # Remove default wallpaper image file
            $WEDefaultWallpaperImagePath = Join-Path -Path $env:windir -ChildPath " Web\Wallpaper\Windows\img0.jpg"
            Remove-WallpaperFile -FilePath $WEDefaultWallpaperImagePath

            # Download new wallpaper content from storage account
            Invoke-WallpaperFileDownload -FileName $WEDefaultWallpaperBlobFile.Name -Destination (Split-Path -Path $WEDefaultWallpaperImagePath -Parent)
        }

        # Check if additional wallpaper files are present in the Azure Storage blob and replace those in the default location
        # Pattern matching for validation
# Pattern matching for validation
$WEWallpaperBlobFiles = $WEAzureStorageBlobContent | Where-Object { $WEPSItem.Name -match " ^img(\d?[1-9]|[1-9]0).jpg$" }
        if ($WEWallpaperBlobFiles -ne $null) {
            Write-LogEntry -Value " Detected theme wallpaper files in container, will replace matching local theme wallpaper files" -Severity 1

            # Remove all items in '%windir%\Web\Wallpaper\Theme1' (Windows 10) directory and replace with wallpaper content from storage account
            $WEThemeWallpaperImagePath = Join-Path -Path $env:windir -ChildPath " Web\Wallpaper\Theme1"
            $WEThemeWallpaperImages = Get-ChildItem -Path $WEThemeWallpaperImagePath -Filter " *.jpg"
            foreach ($WEThemeWallpaperImage in $WEThemeWallpaperImages) {
                # Remove current theme wallpaper image file
                Remove-WallpaperFile -FilePath $WEThemeWallpaperImage.FullName
            }

            foreach ($WEWallpaperBlobFile in $WEWallpaperBlobFiles) {
                # Download new wallpaper content from storage account
                Invoke-WallpaperFileDownload -FileName $WEWallpaperBlobFile.Name -Destination $WEThemeWallpaperImagePath
            }
        }

        # Check if 4K wallpaper files are present in the Azure Storage blog and replace those in the default location
        # Pattern matching for validation
# Pattern matching for validation
$WEWallpaperBlob4KFiles = $WEAzureStorageBlobContent | Where-Object { $WEPSItem.Name -match " ^img0_(\d+)x(\d+).*.jpg$" }
        if ($WEWallpaperBlob4KFiles -ne $null) {
            Write-LogEntry -Value " Detected 4K wallpaper files in container, will replace matching local wallpaper file" -Severity 1

            # Define 4K wallpaper path and retrieve all image files
            $4KWallpaperImagePath = Join-Path -Path $env:windir -ChildPath " Web\4K\Wallpaper\Windows"
           ;  $4KWallpaperImages = Get-ChildItem -Path $4KWallpaperImagePath -Filter " *.jpg"
            
            foreach ($WEWallpaperBlob4KFile in $WEWallpaperBlob4KFiles) {
                # Remove current 4K wallpaper image file and replace with image from storage account
                if ($WEWallpaperBlob4KFile.Name -in $4KWallpaperImages.Name) {
                    Write-LogEntry -Value " Current container item with name '$($WEWallpaperBlob4KFile.Name)' matches local wallpaper item, starting replacement process" -Severity 1
                    
                    # Get matching local wallpaper image for current container item
                   ;  $4KWallpaperImage = $4KWallpaperImages | Where-Object { $WEPSItem.Name -like $WEWallpaperBlob4KFile.Name }

                    # Remove current theme wallpaper image file
                    Remove-WallpaperFile -FilePath $4KWallpaperImage.FullName

                    # Download new wallpaper content from storage account
                    Invoke-WallpaperFileDownload -FileName $WEWallpaperBlob4KFile.Name -Destination $4KWallpaperImagePath
                }
                else {
                    Write-LogEntry -Value " Downloaded 4K wallpaper with file name '$($WEWallpaperBlob4KFile.Name)' doesn't match any of the built-in 4K wallpaper image file names, skipping" -Severity 2
                }
            }
        }
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================