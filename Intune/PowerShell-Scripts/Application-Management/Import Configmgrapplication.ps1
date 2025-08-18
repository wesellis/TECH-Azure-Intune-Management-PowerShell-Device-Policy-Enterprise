<#
.SYNOPSIS
    Import Configmgrapplication

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
    We Enhanced Import Configmgrapplication

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

[CmdletBinding(SupportsShouldProcess = $true, HelpURI = " https://vcredist.com/import-vcconfigmgrapplication/" )]

[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
    [Parameter(Mandatory = $false)]
    [System.ObsoleteAttribute(" This parameter is not longer supported. The Path property must be on the object passed to -VcList." )]
    [System.String] $WEPath,

    [Parameter(Mandatory = $true, Position = 2)]
    [ValidateNotNullOrEmpty()]
    [System.String] $WECMPath,

    [Parameter(Mandatory = $true, Position = 3)]
    [ValidateScript( { if ($_ -match " ^[a-zA-Z0-9]{3}$" ) { $true } else { throw " $_ is not a valid ConfigMgr site code." } })]
    [System.String] $WESMSSiteCode,

    [Parameter(Mandatory = $false, Position = 4)]
    [ValidatePattern(" ^[a-zA-Z0-9]+$" )]
    [System.String] $WEAppFolder = "" ,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter] $WESilent,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter] $WENoCopy,

    [Parameter(Mandatory = $false, Position = 5)]
    [ValidatePattern(" ^[a-zA-Z0-9]+$" )]
    [System.String];  $WEPublisher = "" ,

    [Parameter(Mandatory = $false, Position = 6)]
    [ValidatePattern(" ^[a-zA-Z0-9\+ ]+$" )]
    [System.String];  $WEKeyword = ""
)

begin {
    #region If the ConfigMgr console is installed, load the PowerShell module; Requires PowerShell module to be installed
    if (Test-Path -Path env:SMS_ADMIN_UI_PATH) {
        try {
            # Import the ConfigurationManager.psd1 module
            $params = @{
                Path        = $(Split-Path -Path $env:SMS_ADMIN_UI_PATH -Parent)
                Filter      = " ConfigurationManager.psd1"
                ErrorAction = " SilentlyContinue"
            }
            $WEModuleFile = Get-ChildItem -ErrorAction Stop @params
            if (-not[System.String]::IsNullOrEmpty($WEModuleFile)) {
                Write-Verbose -Message " Importing module: $($WEModuleFile.FullName)"
                Import-Module -Name $WEModuleFile.FullName -Verbose:$false
            }
            else {
                $WEMsg = " Could not load ConfigurationManager.psd1 from $(Split-Path -Path $env:SMS_ADMIN_UI_PATH -Parent). Please make sure that the Configuration Manager console is installed."
                throw [System.IO.FileNotFoundException]::New($WEMsg)
            }
        }
        catch {
            throw $_
        }
    }
    else {
        $WEMsg = " Cannot find environment variable SMS_ADMIN_UI_PATH. Is the ConfigMgr console and PowerShell module installed?"
        throw [System.Exception]::New($WEMsg)
    }
    #endregion

    #region Validate $WECMPath
    if (Resolve-Path -Path $WECMPath) {
        $WECMPath = $WECMPath.TrimEnd(" \" )

        # Create the folder for importing the Redistributables into
        if ($WEAppFolder.Length -gt 0) {
            $WEDestCmFolder = " $($WESMSSiteCode):\Application\$($WEAppFolder)"
            if ($WEPSCmdlet.ShouldProcess($WEDestCmFolder, " Creating" )) {
                Write-Verbose -Message " Creating: $WEDestCmFolder."
                New-Item -Path $WEDestCmFolder -ErrorAction " Continue" > $null
            }
        }
        else {
            Write-Verbose -Message " Importing into: $($WESMSSiteCode):\Application."
            $WEDestCmFolder = " $($WESMSSiteCode):\Application"
        }
    }
    else {
        $WEMsg = " Unable to confirm '$WECMPath' exists. Please check that '$WECMPath' is valid."
        throw [System.IO.DirectoryNotFoundException]::New($WEMsg)
    }
    #endregion
}

process {


        # Import as an application into ConfigMgr
        if ($WEPSCmdlet.ShouldProcess(" '$($WEVcRedist.Name)' in $WECMPath" , " Import ConfigMgr app" )) {

            # Create the ConfigMgr application with properties from the manifest
            if ((Get-Item -Path $WEDestCmFolder).PSDrive.Name -eq $WESMSSiteCode) {
                if ($WEPSCmdlet.ShouldProcess($WEVcRedist.Name + " $($WEVcRedist.Architecture)" , " Creating ConfigMgr application" )) {

                    # Build paths
                    $WESourceFolder = $(Split-Path -Path $WEVcRedist.Path -Parent)
                    $WEContentLocation = [System.IO.Path]::Combine($WECMPath, $WEVcRedist.Release, $WEVcRedist.Version, $WEVcRedist.Architecture)

                    #region Copy VcRedists to the network location. Use robocopy for robustness
                    if ($WEPSBoundParameters.Contains($WENoCopy)) {
                        Write-Warning -Message " NoCopy specified, skipping copy to $WEContentLocation. Ensure VcRedists exist in the target."
                    }
                    else {
                        if ($WEPSCmdlet.ShouldProcess(" '$($WEVcRedist.Path)' to '$($WEContentLocation)'" , " Copy" )) {
                            if (!(Test-Path -Path $WEContentLocation)) {
                                New-Item -Path $WEContentLocation -ItemType " Directory" -ErrorAction " Continue" > $null
                            }
                            try {
                                $invokeProcessParams = @{
                                    FilePath     = " $env:SystemRoot\System32\robocopy.exe"
                                    ArgumentList = " $(Split-Path -Path $WEVcRedist.Path -Leaf) `" $WESourceFolder`" `" $WEContentLocation`" /S /XJ /R:1 /W:1 /NP /NJH /NJS /NFL /NDL"
                                }
                                Invoke-Process @invokeProcessParams | Out-Null
                            }
                            catch [System.Exception] {
                                $WEErr = $_
                                $WETarget = Join-Path -Path $WEContentLocation -ChildPath $(Split-Path -Path $WEVcRedist.Path -Leaf)
                                if (Test-Path -Path $WETarget) {
                                    Write-Verbose -Message " Copy successful: '$WETarget'."
                                }
                                else {
                                    Write-Warning -Message " Failed to copy Redistributables from '$($WEVcRedist.Path)' to '$WEContentLocation'."
                                    throw $WEErr
                                }
                            }
                        }
                    }
                    #endregion

                    # Change to the SMS Application folder before importing the applications
                    try {
                        Write-Verbose -Message " Setting location to: $WEDestCmFolder"
                        Set-Location -Path $WEDestCmFolder -ErrorAction " Continue"
                    }
                    catch [System.Exception] {
                        Write-Warning -Message " Failed to set location to: $WEDestCmFolder."
                        throw $_
                    }

                    try {
                        # Splat New-CMApplication -ErrorAction Stop parameters, add the application and move into the target folder
                        $WEApplicationName = " Visual C++ Redistributable $($WEVcRedist.Release) $($WEVcRedist.Architecture) $($WEVcRedist.Version)"
                        $cmAppParams = @{
                            Name              = $WEApplicationName
                            Description       = " $WEPublisher $WEApplicationName imported by $($WEMyInvocation.MyCommand). https://vcredist.com"
                            SoftwareVersion   = $WEVcRedist.Version
                            LinkText          = $WEVcRedist.URL
                            Publisher         = $WEPublisher
                            Keyword           = $WEKeyword
                            ReleaseDate       = $(Get-Date -Format (([System.Globalization.CultureInfo]::CurrentUICulture.DateTimeFormat).ShortDatePattern))
                            PrivacyUrl        = " https://go.microsoft.com/fwlink/?LinkId=521839"
                            UserDocumentation = " https://visualstudio.microsoft.com/vs/support/"
                        }
                        $app = New-CMApplication -ErrorAction Stop @cmAppParams
                        if ($WEAppFolder) {
                            $app | Move-CMObject -FolderPath $WEDestCmFolder -ErrorAction " SilentlyContinue" > $null
                        }
                    }
                    catch [System.Exception] {
                        Write-Warning -Message " Failed to create application $($WEVcRedist.Name) $($WEVcRedist.Architecture)."
                        throw $_
                    }
                    # Write app detail to the pipeline
                    Write-Output -InputObject $app
                }

                # Add a deployment type to the application
                if ($WEPSCmdlet.ShouldProcess($(" $($WEVcRedist.Name) $($WEVcRedist.Architecture) $($WEVcRedist.Version)" ), " Adding deployment type" )) {

                    # Change to the SMS Application folder before importing the applications
                    try {
                        Write-Verbose -Message " Set location to: $WEDestCmFolder"
                        Set-Location -Path $WEDestCmFolder -ErrorAction " Continue"
                    }
                    catch [System.Exception] {
                        Write-Warning -Message " Failed to set location to: $WEDestCmFolder."
                        throw $_
                    }

                    try {
                        # Create the detection method
                        $params = @{
                            Hive    = " LocalMachine"
                            Is64Bit = if ($WEVcRedist.UninstallKey -eq " 64" ) { $true } else { $false }
                            KeyName = " SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($WEVcRedist.ProductCode)"
                        }
                       ;  $detectionClause = New-CMDetectionClauseRegistryKey -ErrorAction Stop @params

                        # Splat Add-CMScriptDeploymentType parameters and add the application deployment type
                       ;  $cmScriptParams = @{
                            ApplicationName          = $WEApplicationName
                            InstallCommand           = " $(Split-Path -Path $WEVcRedist.Path -Leaf) $(if ($WESilent) { $WEVcRedist.SilentInstall } else { $WEVcRedist.Install })"
                            ContentLocation          = $WEContentLocation
                            AddDetectionClause       = $detectionClause
                            DeploymentTypeName       = " SCRIPT_$($WEVcRedist.Name)"
                            UserInteractionMode      = " Hidden"
                            UninstallCommand         = $WEVcRedist.SilentUninstall
                            LogonRequirementType     = " WhetherOrNotUserLoggedOn"
                            InstallationBehaviorType = " InstallForSystem"
                            Comment                  = " Generated by $($WEMyInvocation.MyCommand). https://vcredist.com"
                        }
                        Add-CMScriptDeploymentType @cmScriptParams > $null
                    }
                    catch [System.Exception] {
                        Write-Warning -Message " Failed to add script deployment type."
                        throw $_
                    }
                }
            }
        }

}

end {
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================