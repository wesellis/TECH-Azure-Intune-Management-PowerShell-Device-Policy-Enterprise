<#
.SYNOPSIS
    Redirect Folders Favorites

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
    We Enhanced Redirect Folders Favorites

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
    .SYNOPSIS
        Creates a scheduled task to implement folder redirection for.

    .NOTES
        Name: Redirect-Folders.ps1
        Author: Aaron Parker



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param ()


$WEVerbosePreference = " Continue"
$stampDate = Get-Date; 
$WELogFile = " $env:LocalAppData\IntuneScriptLogs\Redirect-Folders-" + $stampDate.ToFileTimeUtc() + " .log"
Start-Transcript -Path $WELogFile

[CmdletBinding()]
Function Set-KnownFolderPath -ErrorAction Stop {
    <#
        .SYNOPSIS
            Sets a known folder's path using SHSetKnownFolderPath.
        .PARAMETER KnownFolder
            The known folder whose path to set.
        .PARAMETER Path
            The target path to redirect the folder to.
        .NOTES
            Forked from: https://gist.github.com/semenko/49a28675e4aae5c8be49b83960877ac5
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Contacts', 'Desktop', 'Documents', 'Downloads', 'Favorites', 'Games', 'Links',  'Music', 'Pictures', 'Videos')]
        [System.String] $WEKnownFolder,

        [Parameter(Mandatory = $true)]
        [System.String] $WEPath
    )

    # Define known folder GUIDs
   ;  $WEKnownFolders = @{
        'Contacts'       = '56784854-C6CB-462b-8169-88E350ACB882';
        'Desktop'        = @('B4BFCC3A-DB2C-424C-B029-7FE99A87C641');
        'Documents'      = @('FDD39AD0-238F-46AF-ADB4-6C85480369C7', 'f42ee2d3-909f-4907-8871-4c22fc0bf756');
        'Downloads'      = @('374DE290-123F-4565-9164-39C4925E467B', '7d83ee9b-2244-4e70-b1f5-5393042af1e4');
        'Favorites'      = '1777F761-68AD-4D8A-87BD-30B759FA33DD';
        'Games'          = 'CAC52C1A-B53D-4edc-92D7-6B2E8AC19434';
        'Links'          = 'bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968';
        'Music'          = @('4BD8D571-6D19-48D3-BE97-422220080E43', 'a0c69a99-21c8-4671-8703-7934162fcf1d');
        'Pictures'       = @('33E28130-4E1E-4676-835A-98395C3BC3BB', '0ddd015d-b06c-45d5-8c4c-f59713854639');
        'Videos'         = @('18989B1D-99B5-455B-841C-AB7C74E4DDFC', '35286a68-3c57-41a1-bbb1-0eae73d76c95');
    }

    # Define SHSetKnownFolderPath if it hasn't been defined already
    $WEType = ([System.Management.Automation.PSTypeName]'KnownFolders').Type
    If (-not $WEType) {
       ;  $WESignature = @'
[DllImport(" shell32.dll" )]
public extern static int SHSetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] string path);
'@
        $WEType = Add-Type -MemberDefinition $WESignature -Name 'KnownFolders' -Namespace 'SHSetKnownFolderPath' -PassThru
    }

    # Make path, if doesn't exist
    If (!(Test-Path $WEPath -PathType Container)) {
        New-Item -Path $WEPath -Type Directory -Force -Verbose
    }

    # Validate the path
    If (Test-Path $WEPath -PathType Container) {
        # Call SHSetKnownFolderPath
        #  return $WEType::SHSetKnownFolderPath([ref]$WEKnownFolders[$WEKnownFolder], 0, 0, $WEPath)
        ForEach ($guid in $WEKnownFolders[$WEKnownFolder]) {
            Write-Verbose " Redirecting $WEKnownFolders[$WEKnownFolder]"
            $result = $WEType::SHSetKnownFolderPath([ref]$guid, 0, 0, $WEPath)
            If ($result -ne 0) {
                $errormsg = " Error redirecting $($WEKnownFolder). Return code $($result) = $((New-Object -ErrorAction Stop System.ComponentModel.Win32Exception($result)).message)"
                Throw $errormsg
            }
        }
    }
    Else {
        Throw New-Object -ErrorAction Stop System.IO.DirectoryNotFoundException " Could not find part of the path $WEPath."
    }

    # Fix up permissions, if we're still here
    Attrib +r $WEPath
    Write-Output $WEPath
}

[CmdletBinding()]
Function Get-KnownFolderPath -ErrorAction Stop {
    <#
        .SYNOPSIS
            Gets a known folder's path using GetFolderPath.
        .PARAMETER KnownFolder
            The known folder whose path to get. Validates set to ensure only knwwn folders are passed.
        .NOTES
            https://stackoverflow.com/questions/16658015/how-can-i-use-powershell-to-call-shgetknownfolderpath
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Contacts', 'Desktop', 'Documents', 'Downloads', 'Favorites', 'Games', 'Links',  'Music', 'Pictures', 'Videos')]
        [System.String] $WEKnownFolder
    )
    [Environment]::GetFolderPath($WEKnownFolder)
}

[CmdletBinding()]
Function Move-File {
    <#
        .SYNOPSIS
            Moves contents of a folder with output to a log.
            Uses Robocopy to ensure data integrity and all moves are logged for auditing.
            Means we don't need to re-write functionality in PowerShell.
        .PARAMETER Source
            The source folder.
        .PARAMETER Destination
            The destination log.
        .PARAMETER Log
            The log file to store progress/output
    #>
    param(
        $WESource,
        $WEDestination,
        $WELog
    )
    If (!(Test-Path (Split-Path $WELog))) { New-Item -Path (Split-Path $WELog) -ItemType Container }
    Write-Verbose " Moving data in folder $WESource to $WEDestination."
    Robocopy.exe " $WESource" " $WEDestination" /E /MOV /XJ /XF *.ini /R:1 /W:1 /NP /LOG+:$WELog
}

[CmdletBinding()]
Function Redirect-Folder {
    <#
        .SYNOPSIS
            Function exists to reduce code required to redirect each folder.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.String] $WESyncFolder,

        [Parameter(Mandatory = $true)]
        [System.String] $WEGetFolder,

        [Parameter(Mandatory = $true)]
        [System.String] $WESetFolder,

        [Parameter(Mandatory = $true)]
        [System.String] $WETarget
    )

    # Get current Known folder path
    $WEFolder = Get-KnownFolderPath -KnownFolder $WEGetFolder

    # If paths don't match, redirect the folder
    If ($WEFolder -ne " $WESyncFolder\$WETarget" ) {
        # Redirect the folder
        Write-Verbose " Redirecting $WESetFolder to $WESyncFolder\$WETarget"
        Set-KnownFolderPath -KnownFolder $WESetFolder -Path " $WESyncFolder\$WETarget"

        # Move files/folders into the redirected folder
        Write-Verbose " Moving data from $WESetFolder to $WESyncFolder\$WETarget"
       ;  $log = " $env:LocalAppData\IntuneScriptLogs\Robocopy-" + $stampDate.ToFileTimeUtc() + " .log"
        Move-File -Source $WEFolder -Destination " $WESyncFolder\$WETarget" -Log $log

        # Hide the source folder (rather than delete it)
        Attrib +h $WEFolder
    }
    Else {
        Write-Verbose " Folder $WEGetFolder matches target. Skipping redirection."
    }
}

; 
$WESyncFolder = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\OneDrive\Accounts\Business1' -Name 'UserFolder'
Write-Verbose " Target sync folder is $WESyncFolder."


If (Test-Path $WESyncFolder) {
    Redirect-Folder -SyncFolder $WESyncFolder -GetFolder 'Favorites' -SetFolder 'Favorites' -Target 'Favorites'
}
Else {
    Write-Verbose " $WESyncFolder does not (yet) exist. Skipping folder redirection until next logon."
}

Stop-Transcript -Verbose




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
