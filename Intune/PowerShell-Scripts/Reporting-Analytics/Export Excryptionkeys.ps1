<#
.SYNOPSIS
    Export Excryptionkeys

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
    We Enhanced Export Excryptionkeys

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
    Export encryption keys from .intunewin files.
    This can be used when downloading intunewin files from Intune.

    This is a prt of the IntuneManage GitHub Repository
    https://github.com/Micke-K/IntuneManagement/
    (c) Mikael Karlsson MIT License - https://github.com/Micke-K/IntuneManagement/blob/master/LICENSE

    Exprot file name will be <IntunewinFileBaseName>_<UnencryptedFileSize>.json
    Do NOT rename the exported file. The script will try to find excryption file based on the generated name.

    Encryption information is file specific. If the same .intunewin file is imported in multiple tenants,
    the same ecryption file can be used to decrypt it when downloading or exporting the app content.

    .Sample
    Export-EncrytionKeys -RootFolder C:\Intune\Packages -ExportFolder C:\Intune\Download
    This will search C:\Intune\Packages and all subfolder for .intunewin files and export
    the encryption keys to the C:\Intune\Download.



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Alias(" RF" )]
    # Root folder where intunewin files are located.    
    $WERootFolder,
    [Alias(" EF" )]
    # Folder where encryption files should be exported to
    # If this is empty, the encryption file will be saved to the same folder as the intunewin file
    $WEExportFolder)

function WE-Export-IntunewinFileObject
{
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param($file, $objectName, $toFile)
   
    try
    {
        Add-Type -Assembly System.IO.Compression.FileSystem

        $zip = [IO.Compression.ZipFile]::OpenRead($file)

        $zip.Entries | where { $_.Name -like $objectName } | foreach {

            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $toFile, $true)
        }   

        $zip.Dispose()
        return $true
    }
    catch 
    {
        Write-Warning " Failed to get info from $file. Error: $($_.Exception.Message)"
        return $false
    }

}

function WE-Export-EncryptionKeys
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(ValueFromPipeline=$true)]
        $fileInfo,
        $exportFolder = $fileInfo.DirectoryName
    )

    begin 
    {
    }

    process
    {
        if($fileInfo -isnot [IO.FileInfo]) { return }

        if(-not $exportFolder) { $exportFolder = $fileInfo.DirectoryName }

        $tmpFile = [IO.Path]::GetTempFileName()

        if((Export-IntunewinFileObject $fileInfo.FullName " detection.xml" $tmpFile) -ne $true)
        {
            return
        }

        $tmpFI = [IO.FileInfo]$tmpFile

        try
        {
            if($tmpFI.Length -eq 0)
            { 
                throw " Detection.xml not exported"
            }            
            [xml]$WEDetectionXML = Get-Content $tmpFile
        }
        catch
        {
            Write-Warning " Failed to export detection.xml file. Error: $($_.Exception.Message)"
            return
        }
        finally
        {
            Remove-Item -Path $tmpFile -Force | Out-Null
        }

        # Get encryption info from detection.xml and build encryptionInfo object

        $encryptionInfo = @{}
        $encryptionInfo.encryptionKey = $WEDetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
        $encryptionInfo.macKey = $WEDetectionXML.ApplicationInfo.EncryptionInfo.macKey
        $encryptionInfo.initializationVector = $WEDetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
        $encryptionInfo.mac = $WEDetectionXML.ApplicationInfo.EncryptionInfo.mac
        $encryptionInfo.profileIdentifier = " ProfileVersion1"
        $encryptionInfo.fileDigest = $WEDetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
        $encryptionInfo.fileDigestAlgorithm = $WEDetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm

        $fileData = @{}
        $fileData.Name = $WEDetectionXML.ApplicationInfo.Name
        $fileData.UnencryptedContentSize = $WEDetectionXML.ApplicationInfo.UnencryptedContentSize
        $fileData.SetupFile = $WEDetectionXML.ApplicationInfo.SetupFile

        $msiInfo = @{}
        if($WEDetectionXML.ApplicationInfo.MsiInfo)
        {
            $msiInfo.MsiPublisher = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiPublisher
            $msiInfo.MsiProductCode = $WEDetectionXML.ApplicationInfo.MsiInfo.Publisher
            $msiInfo.MsiProductVersion = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion
            $msiInfo.MsiPackageCode = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiPackageCode
            $msiInfo.MsiUpgradeCode = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiUpgradeCode
            $msiInfo.MsiIsMachineInstall = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiIsMachineInstall
            $msiInfo.MsiIsUserInstall = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiIsUserInstall
            $msiInfo.MsiIncludesServices = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiIncludesServices
            $msiInfo.MsiIncludesODBCDataSource = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiIncludesODBCDataSource
            $msiInfo.MsiContainsSystemRegistryKeys = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiContainsSystemRegistryKeys
            $msiInfo.MsiContainsSystemFolders = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiContainsSystemFolders
        }
        # Create mobileAppContentFile object for the file
        $fileEncryptionInfo = @{}
        $fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo
        $fileEncryptionInfo.fileData = $fileData
        if($msiInfo.Count -gt 0)
        {
            $fileEncryptionInfo.MsiInfo = $msiInfo
        }
    
       ;  $json = $fileEncryptionInfo | ConvertTo-Json -Depth 10

        if([IO.Directory]::Exists($exportFolder) -eq $false)
        {
            md $exportFolder | Out-Null
        }

       ;  $fileName = $exportFolder + " \$($fileInfo.BaseName)_$($WEDetectionXML.ApplicationInfo.UnencryptedContentSize).json"

        Write-WELog " Save encryption for $($fileInfo.BaseName) file $fileName" " INFO"
        $json | Out-File -FilePath $fileName -Force -Encoding utf8
    }

    end
    {
    }

}

Get-ChildItem -Path $WERootFolder -Filter " *.intunewin" -Recurse | Export-EncryptionKeys -exportFolder $WEExportFolder


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================