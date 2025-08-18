<#
.SYNOPSIS
    Invoke Intunebiosupdate Remediate

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
    We Enhanced Invoke Intunebiosupdate Remediate

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


function WE-Test-RequiredPath {
    param([Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath)
    if (!(Test-Path $WEPath)) {
        Write-Warning "Required path not found: $WEPath"
        return $false
    }
    return $true
}

<#


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    BIOS Control remediation script for MSEndpointMgr Intune MBM
.DESCRIPTION
    This proactive remediation script is part of the Intune version of Modern BIOS management. More information can be found at https://msendpointmgr.com 
    NB: Only edit variables in the Declarations region of the script. 
    The following variables MUST be set: 
    1. DATUri - Url path to BIOSPackages.xml 
    2. LogoImageUri - Url to logo image for toast notification 
    3. HeroImageUri - Url to hero image for toast notification 

    If you have a common BIOS password on all devices, that can be added to this script for support (HP), but be aware that both local admin users on the devices and Intune admins will 
    be able to retrive this password if you do so. 

.EXAMPLE
	Invoke-IntuneBIOSUpdateRemediate.ps1 - Run as SYSTEM 
.NOTES
	Version:    0.9 Beta
    Author:     Maurice Daly / Jan Ketil Skanke @ Cloudway
    Contact:    @JankeSkanke @Modaly_IT
    Creation Date:  01.10.2021
    Purpose/Change: Initial script development
    Created:     2021-14-11
    Updated:     
    Version history:
    0.9 - (2021.14.11) Beta Release



$WEScript:ErrorActionPreference = " SilentlyContinue"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$WEScript:ExitCode = 0

$WEScript:EventLogName = 'MSEndpointMgr'
$WEScript:EventLogSource = 'MSEndpointMgrBIOSMgmt'
New-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -ErrorAction SilentlyContinue

$WEScript:AppID = " MSEndpointMgr.SystemToast.UpdateNotification"
$WEScript:AppDisplayName = " MSEndpointMgr"
$WEScript:IconUri = " %SystemRoot%\system32\@WindowsUpdateToastIcon.png"
$WEScript:ToastMediafolder = " $env:programdata\MSEndpointMgr\ToastNotification"


$WEScript:ToastSettings = @{
    LogoImageUri = " <TO BE SET>"
    HeroImageUri = " <TO BE SET>"
    LogoImage = " $WEToastMediafolder\ToastLogoImage.png"
    HeroImage = " $WEToastMediafolder\ToastHeroImage.png"
    AttributionText = " Bios Update Notification"
    HeaderText = " It is time to update your BIOS!"
    TitleText = " Firmware update needed!"
    BodyText1 = " For security reasons it is important that the firmware on your machine is up to date. This update requires a reboot of your device"
    BodyText2 = " Please save your work and restart your device today. Thank you in advance."
    ActionButtonContent = " Restart Now"
}
$WEScript:Scenario = 'reminder' # <!-- Possible values are: reminder | short | long | alarm

$WEScript:BIOSPswd = $null

$WEScript:DATUri = " <TO BE SET>"

$WEScript:Manufacturer = (Get-CimInstance -Class " Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()

$WEScript:RegPath = 'HKLM:\SOFTWARE\MSEndpointMgr\BIOSUpdateManagemement'





function WE-Add-NotificationApp {
    <#
    .SYNOPSIS
    Function to verify and register toast notification app in registry as system

    .DESCRIPTION
    This function must be run as system and registers the toast notification app with your own name and icon. 

    .PARAMETER AppID
    The AppID (Name) to be used to the toast notification. Example: MSEndpointMgr.SystemToast.UpdateNotification

    .PARAMETER AppDisplayName
    The Display Name for your  toast notification app. Example: MSEndpointMgr

    .PARAMETER IconUri
    The path to the icon shown in the Toast Notification. Expample: %SystemRoot%\system32\@WindowsUpdateToastIcon.png

    .PARAMETER ShowInSettings
    Default Value 0 is recommended. Not required. But can be change to 1. Not recommended for this solution
    #>    
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [Parameter(Mandatory=$true)]$WEAppID,
        [Parameter(Mandatory=$true)]$WEAppDisplayName,
        [Parameter(Mandatory=$true)]$WEIconUri,
        [Parameter(Mandatory=$false)][int]$WEShowInSettings = 0
    )
    # Verify if PSDrive Exists
    $WEHKCR = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
    If (!($WEHKCR))
    {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -Scope Script
    }
    $WEAppRegPath = " HKCR:\AppUserModelId"
    $WERegPath = " $WEAppRegPath\$WEAppID"
    # Verify if App exists in registry
    If (!(Test-Path $WERegPath))
    {
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Toast Notification App does not exists - creating"
        $null = New-Item -Path $WEAppRegPath -Name $WEAppID -Force
    }
    # Verify Toast App Displayname
    $WEDisplayName = Get-ItemProperty -Path $WERegPath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
    If ($WEDisplayName -ne $WEAppDisplayName)
    {
        $null = New-ItemProperty -Path $WERegPath -Name DisplayName -Value $WEAppDisplayName -PropertyType String -Force
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Toast notification app $($WEDisplayName) created"
    }
    # Verify Show in settings value
    $WEShowInSettingsValue = Get-ItemProperty -Path $WERegPath -Name ShowInSettings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ShowInSettings -ErrorAction SilentlyContinue
    If ($WEShowInSettingsValue -ne $WEShowInSettings)
    {
        $null = New-ItemProperty -Path $WERegPath -Name ShowInSettings -Value $WEShowInSettings -PropertyType DWORD -Force
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Toast notification app settings applied"
    }
    # Verify toast icon value
    $WEIconSettingsValue = Get-ItemProperty -Path $WERegPath -Name IconUri -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IconUri -ErrorAction SilentlyContinue
    If ($WEIconSettingsValue -ne $WEIconUri)
    {
        $null = New-ItemProperty -Path $WERegPath -Name IconUri -Value $WEIconUri -PropertyType ExpandString -Force
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Toast notification app icon set"
    }
    # Clean up
    Remove-PSDrive -Name HKCR -Force
}#endfunction
function WE-Add-ToastRebootProtocolHandler{
    <#
    .SYNOPSIS
    Function to add the reboot protocol handler for your toast notifications

    .DESCRIPTION
    This function must be run as system and registers the protocal handler for toast reboot. 
    #>    
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | out-null
    $WEProtocolHandler = Get-Item 'HKCR:\MSEndpointMgrToastReboot' -ErrorAction SilentlyContinue
    if (!$WEProtocolHandler) {
        #create handler for reboot
        New-Item 'HKCR:\MSEndpointMgrToastReboot' -Force
        Set-Itemproperty 'HKCR:\MSEndpointMgrToastReboot' -Name '(DEFAULT)' -Value 'url:MSEndpointMgrToastReboot' -Force
        Set-Itemproperty 'HKCR:\MSEndpointMgrToastReboot' -Name 'URL Protocol' -Value '' -Force
        New-Itemproperty -path 'HKCR:\MSEndpointMgrToastReboot' -PropertyType DWORD -Name 'EditFlags' -Value 2162688
        New-Item 'HKCR:\MSEndpointMgrToastReboot\Shell\Open\command' -Force
        Set-Itemproperty 'HKCR:\MSEndpointMgrToastReboot\Shell\Open\command' -Name '(DEFAULT)' -Value 'C:\Windows\System32\shutdown.exe -r -t 60 -c " Your computer will be restarted in 1 minute to complete the BIOS Update process." ' -Force
    }
    Remove-PSDrive -Name HKCR -Force -ErrorAction SilentlyContinue
}#endfunction
function WE-Test-UserSession {
    #Check if a user is currently logged on before doing user action
    [String]$WECurrentlyLoggedOnUser = (Get-CimInstance -Class Win32_ComputerSystem |  Where-Object {$_.Username} | Select-Object UserName).UserName
    if ($WECurrentlyLoggedOnUser){
        $WESAMName = [String]$WECurrentlyLoggedOnUser.Split(" \" )[1]
        #$WEUserPath = (Get-ChildItem  -Path HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache\ -Recurse -ErrorAction SilentlyContinue | ForEach-Object { if((Get-ItemProperty -Path $_.PsPath) -match $WESAMName) {$_.PsPath} } ) | Where-Object {$WEPSItem -Match 'S-\d-\d{2}-\d-\d{10}-\d{10}-\d{10}-\d{10}'}
        #$WEFullName = (Get-ItemProperty -Path $WEUserPath | Select-Object DisplayName).DisplayName
        $WEReturnObject = $WESAMName 
    }else {
        $WEReturnObject = $false
    }
    Return $WEReturnObject
}#endfunction
function WE-Invoke-ToastNotification {
    param(
        [Parameter(Mandatory=$false)]$WEFullName,
        [parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[array]$WEToastSettings,
        [Parameter(Mandatory=$true)]$WEAppID,
        [Parameter(Mandatory=$true)]$WEScenario
    )

$WEMyScriptBlockString = "
function WE-Start-ToastNotification {
    `$WELoad = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    `$WELoad = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    # Load the notification into the required format
    `$WEToastXML = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
    `$WEToastXML.LoadXml(`$WEToast.OuterXml)
    # Display the toast notification
    try {
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(`" $WEAppID`" ).Show(`$WEToastXml)
    }
    catch { 
        Write-Output -Message 'Something went wrong when displaying the toast notification' -Level Warn     
        Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message `" Something went wrong when displaying the toast notification`"
    }
    Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message `" Toast Notification successfully delivered to logged on user`"
}

Invoke-WebRequest -Uri $($WEToastSettings.LogoImageUri) -OutFile $($WEToastSettings.LogoImage)
Invoke-WebRequest -Uri $($WEToastSettings.HeroImageUri) -OutFile $($WEToastSettings.HeroImage)

[xml]`$WEToast = @`"
<toast scenario=`" $WEScenario`" >
    <visual>
    <binding template=`" ToastGeneric`" >
        <image placement=`" hero`" src=`" $($WEToastSettings.HeroImage)`" />
        <image id=`" 1`" placement=`" appLogoOverride`" hint-crop=`" circle`" src=`" $($WEToastSettings.LogoImage)`" />
        <text placement=`" attribution`" >$($WEToastSettings.AttributionText)</text>
        <text>$($WEToastSettings.HeaderText)</text>
        <group>
            <subgroup>
                <text hint-style=`" title`" hint-wrap=`" true`" >$($WEToastSettings.TitleText)</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style=`" body`" hint-wrap=`" true`" >$($WEToastSettings.BodyText1)</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style=`" body`" hint-wrap=`" true`" >$($WEToastSettings.BodyText2)</text>
            </subgroup>
        </group>
    </binding>
    </visual>
    <actions>
        <input id=`" snoozeTime`" type=`" selection`" defaultInput=`" 60`" >
        <selection id=`" 1`" content=`" 1 minute`" />
        <selection id=`" 15`" content=`" 15 minutes`" />
        <selection id=`" 60`" content=`" 1 hour`" />
        <selection id=`" 240`" content=`" 4 hours`" />
        <selection id=`" 1440`" content=`" 1 day`" />
        </input>
        <action activationType=`" protocol`" arguments=`" MSEndpointMgrToastReboot:`" content=`" $($WEToastSettings.ActionButtonContent)`" />
        <action activationType=`" system`" arguments=`" snooze`" hint-inputId=`" snoozeTime`" content=`" Snooze`" />
    </actions>
    <audio src=`" ms-winsoundevent:Notification.Default`" />
</toast>
`" @

Start-ToastNotification
"

$WEMyScriptBlock = [ScriptBlock]::create($WEMyScriptBlockString) 
$WEEncodedScript = [System.Convert]::ToBase64String([System.Text.Encoding]::UNICODE.GetBytes($WEMyScriptBlock))


If (!($WEToastGUID)) {
    $WEToastGUID = ([guid]::NewGuid()).ToString().ToUpper()
}
$WETask_TimeToRun = (Get-Date).AddSeconds(10).ToString('s')
$WETask_Expiry = (Get-Date).AddSeconds(120).ToString('s')
$WETask_Trigger = New-ScheduledTaskTrigger -Once -At $WETask_TimeToRun
$WETask_Trigger.EndBoundary = $WETask_Expiry
$WETask_Principal = New-ScheduledTaskPrincipal -GroupId " S-1-5-32-545" -RunLevel Limited
$WETask_Settings = New-ScheduledTaskSettingsSet -Compatibility V1 -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 600) -AllowStartIfOnBatteries
$WETask_Action = New-ScheduledTaskAction -Execute " C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Argument " -NoProfile -WindowStyle Hidden -EncodedCommand $WEEncodedScript"

$WENew_Task = New-ScheduledTask -Description " Toast_Notification_$($WEToastGuid) Task for user notification" -Action $WETask_Action -Principal $WETask_Principal -Trigger $WETask_Trigger -Settings $WETask_Settings
Register-ScheduledTask -TaskName " Toast_Notification_$($WEToastGuid)" -InputObject $WENew_Task | Out-Null
Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Toast Notification Task created for logged on user: Toast_Notification_$($WEToastGuid)"
}#endfunction
function WE-Invoke-BIOSUpdateHP{
    param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [version]$WEBIOSApprovedVersion,
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WESystemID
        )  
    $WEOutput = @{}
    # Import HP Module 
    Import-Module HP.ClientManagement
    # Get Date
    $WEDate = Get-Date
    # Obtain current BIOS verison
    [version]$WECurrentBIOSVersion = Get-HPBIOSVersion

    # Inform current BIOS deployment state
    if ($WEBIOSApprovedVersion -gt $WECurrentBIOSVersion){
        $WEHPBIOSVersions = Get-HPBIOSUpdates
        foreach ($WEHPBIOSVersion in $WEHPBIOSVersions.Ver){
            if ([version]$WEHPBIOSVersion -eq $WEBIOSApprovedVersion) {
                $WEHPVersion = $WEHPBIOSVersion
            }
        }
        if ([version]$WEHPVersion -contains $WEBIOSApprovedVersion) {
            # Process BIOS update
            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Processing BIOS flash update process"
            # Check for BIOS password and update flash cmdline
            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Checking if BIOS password is set"
            $WEBIOSPasswordSet = Get-HPBIOSSetupPasswordIsSet
            switch ($WEBIOSPasswordSet) {
                $true {
                    # Verify that an password has been provided
                    Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " BIOS password is password protected"
                    if (-not ([string]::IsNullOrEmpty($WEBIOSPswd))){ 
                        # Perform BIOS flash update using provided password
                        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Updating HP BIOS to version $WEHPVersion using supplied password"
                        $WEHPBIOSUpdateProcess = Get-HPBIOSUpdates -Version $WEHPVersion -Password $WEBIOSPswd -Flash -Bitlocker suspend -Yes -Quiet -ErrorAction SilentlyContinue
                        # Writing status to registry for detection
                        [int]$WEAttempts = Get-ItemPropertyValue -Path $WERegPath -Name 'BIOSUpdateAttempts'
                        $WEAttempts++ 
                        Set-ItemProperty -Path $WERegPath -Name 'BIOSUpdateAttempts' -Value $WEAttempts
                        Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateInprogress' -Value 1
                        Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateTime' -Value $WEDate 
                        Set-ItemProperty -Path " $WERegPath" -Name 'BIOSDeployedVersion' -Value $WEHPVersion
                        $WEOutputMessage = " Updating HP BIOS to version $WEHPVersion using supplied password"
                        $WEExitCode = 0
                        #Invoke Toast 
                        if (Test-UserSession){
                            #User is logged on - send toast to user to perform the reboot
                            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " User session found - notify user to reboot with toast"
                            Invoke-ToastNotification -ToastSettings $WEToastSettings -AppID $WEAppID -Scenario $WEScenario
                        } else {
                            #No user logged on - enforcing a reboot to finalize BIOS flashing                
                            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " No user currenty logged on - restarting computer to finalize BIOS flashing"
                            $WERestartCommand = 'C:\Windows\System32\shutdown.exe'
                            $WERestartArguments = '-r -t 60 -c " Your computer will be restarted in 1 minute to complete the BIOS Update process." '
                            Start-Process $WERestartCommand -ArgumentList $WERestartArguments -NoNewWindow
                        }
                    } else {
                        Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " Password is set, but not password is provided. BIOS Update is halted"
                        $WEOutputMessage = " Password is set, but not password is provided. BIOS Update is halted"
                        $WEExitCode = 1
                    }
                }
                $false {
                    # Perform BIOS flash update
                    Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Updating HP BIOS to version $WEHPVersion"
                    $WEHPBIOSUpdateProcess = Get-HPBIOSUpdates -Version $WEHPVersion -Flash -Bitlocker suspend -Yes -Quiet -ErrorAction SilentlyContinue
                    # Writing status to registry for detection
                    [int]$WEAttempts = Get-ItemPropertyValue -Path $WERegPath -Name 'BIOSUpdateAttempts'
                    $WEAttempts++ 
                    Set-ItemProperty -Path $WERegPath -Name 'BIOSUpdateAttempts' -Value $WEAttempts
                    Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateInprogress' -Value 1
                    Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateTime' -Value $WEDate 
                    Set-ItemProperty -Path " $WERegPath" -Name 'BIOSDeployedVersion' -Value $WEHPVersion
                    #Invoke Toast 
                    if (Test-UserSession){
                        #User is logged on - send toast to user to perform the reboot
                        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " User session found - notify user to reboot with toast"
                        Invoke-ToastNotification -ToastSettings $WEToastSettings -AppID $WEAppID -Scenario $WEScenario
                    } else {
                        #No user logged on - enforcing a reboot to finalize BIOS flashing                
                        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " No user currenty logged on - restarting computer to finalize BIOS flashing"
                        $WERestartCommand = 'C:\Windows\System32\shutdown.exe'
                        $WERestartArguments = '-r -t 60 -c " Your computer will be restarted in 1 minute to complete the BIOS Update process." '
                        Start-Process $WERestartCommand -ArgumentList $WERestartArguments -NoNewWindow
                    }
                    $WEOutputMessage = " Updated HP BIOS to version $WEHPVersion"
                    $WEExitCode = 0
                }                
            }
        } 
        else {
            $WEOutputMessage = " BIOS update not found. $WEBIOSApprovedVersion not found in HP returned values from HP"
            $WEExitCode = 1
        }
    } 
    elseif ($WEBIOSApprovedVersion -eq $WECurrentBIOSVersion) {
        $WEOutputMessage = " BIOS is current on version $WECurrentBIOSVersion"
        $WEExitCode = 0
    } 
    elseif ($WEBIOSApprovedVersion -lt $WECurrentBIOSVersion) {
        $WEOutputMessage = " BIOS is on a higher version than approved $WECurrentBIOSVersion. Approved version $WEBIOSApprovedVersion"
        $WEExitCode = 0
    } 
    
    $WEOutput = @{
            " Message" = $WEOutputMessage
            " ExitCode" = $WEExitCode
    }

    Return $WEOutput
}#endfunction
function WE-Invoke-BIOSUpdateDell{
    param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$WEBIOSPackageDetails 
        )  
$WEOutputMessage = " Dell not Implemented yet"
$WEExitCode = 0
$WEOutput = @{
    " Message" = $WEOutputMessage
    " ExitCode" = $WEExitCode
}
Return $WEOutput
}#endfunction
function WE-Invoke-BIOSUpdateLenovo{
    param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$WEBIOSPackageDetails 
        )  
$WEOutputMessage = " Dell not Implemented yet"
$WEExitCode = 0
$WEOutput = @{
    " Message" = $WEOutputMessage
    " ExitCode" = $WEExitCode
}
return $WEOutput
}#endfunction
function WE-Test-BIOSVersionHP{
param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [version]$WEBIOSApprovedVersion,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$WESystemID
    )  
    $WEOutput = @{}
    # Import HP Module 
    Import-Module HP.ClientManagement

    # Obtain current BIOS verison
    [version]$WECurrentBIOSVersion = Get-HPBIOSVersion

    # Inform current BIOS deployment state
    if ($WEBIOSApprovedVersion -gt $WECurrentBIOSVersion){
        $WEOutputMessage = " BIOS needs an update. Current version is $WECurrentBIOSVersion, available version is $WEBIOSApprovedVersion"
        $WEExitCode = 1
    } 
    elseif ($WEBIOSApprovedVersion -eq $WECurrentBIOSVersion) {
        $WEOutputMessage = " BIOS is current on version $WECurrentBIOSVersion"
        $WEExitCode = 0
    } 
    elseif ($WEBIOSApprovedVersion -lt $WECurrentBIOSVersion) {
        $WEOutputMessage = " BIOS is on a higher version than approved $WECurrentBIOSVersion. Approved version $WEBIOSApprovedVersion"
        $WEExitCode = 0
    } 
    
    $WEOutput = @{
            " Message" = $WEOutputMessage
            " ExitCode" = $WEExitCode
    }

    Return $WEOutput
}#endfunction
function WE-Test-BiosVersionDell{
    param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$WEBIOSPackageDetails 
        )
    $WEOutputMessage = " Dell Not implemented"
    $WEExitCode = 0
    $WEOutput = @{
        " Message" = $WEOutputMessage
        " ExitCode" = $WEExitCode
    }
    Return $WEOutput
}#endfunction
function WE-Test-BiosVersionLenovo{
    param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$WEBIOSPackageDetails 
        )  
    $WEOutputMessage = " Dell Not implemented"
    $WEExitCode = 0
    $WEOutput = @{
        " Message" = $WEOutputMessage
        " ExitCode" = $WEExitCode
    }
    Return $WEOutput
}#endfunction





[xml]$WEBIOSPackages = Invoke-WebRequest -Uri $WEDATUri -UseBasicParsing


$WEBIOSPackageDetails = $WEBIOSPackages.ArrayOfCMPackage.CMPackage


Add-NotificationApp -AppID $WEAppID -AppDisplayName $WEAppDisplayName -IconUri $WEIconUri | Out-Null
Add-ToastRebootProtocolHandler | Out-Null


if (-not (Test-Path $WEToastMediafolder)){
    New-Item -Path $WEToastMediafolder -ItemType Directory | Out-Null
}


switch -Wildcard ($WEManufacturer) { 
    {($WEPSItem -match " HP" ) -or ($WEPSItem -match " Hewlett-Packard" )}{
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Validated HP hardware check"
        $WEHPPreReq = [boolean](Get-InstalledModule | Where-Object {$_.Name -match " HPCMSL" } -ErrorAction SilentlyContinue -Verbose:$false)
        if ($WEHPPreReq){
            # Import module
            Import-Module HP.ClientManagement
            # Get matching identifier from baseboard
            $WESystemID = Get-HPDeviceProductID
            $WESupportedModel = $WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID}
            if (-not ([string]::IsNullOrEmpty($WESupportedModel))) {
                [version]$WEBIOSApprovedVersion = ($WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" " )[0] 
                $WEOEM = " HP"
                Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " $($WESupportedModel.Description) succesfully matched on SKU $($WESystemID)"
            } 
            else {
                Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " Model with SKU value $($WESystemID) not found in XML source. Exiting script"
                Write-Output " Model with SKU value $($WESystemID) not found in XML source. Exiting script"
                Exit 0
            }       
        } else { 
            # HP Prereq is missing. Exit script
            Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " HP CMSL Powershell Module is missing. Remediation not possible."
            Write-Output " HP Prereq missing. HPCMSL Powershell Module is missing. Remediation not possible."
            Exit 0
        }
    }
    {($WEPSItem -match " Lenovo" )}{
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message  " Validated Lenovo hardware check"
        $WELenovoPreReq = $true
        if ($WELenovoPreReq){
            # Get matching identifier from baseboard
            $WESystemID = " Something"
            $WESupportedModel = $WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID}
            if (-not ([string]::IsNullOrEmpty($WESupportedModel))) {
                [version]$WEBIOSApprovedVersion = ($WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" " )[0] 
                $WEOEM = " Lenovo"
            } 
            else {
                Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8001 -Source $WEEventLogSource -Message " Model $WEComputerModel with SKU value $WESystemSKU not found in XML source"
            }
        }
    }
    {($WEPSItem -match " Dell" )}{
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message  " Validated Dell hardware check"
        if ($WEDellPreReq){
            # Get matching identifier from baseboard
            $WESystemID = " Something"
            $WESupportedModel = $WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID}
            if (-not ([string]::IsNullOrEmpty($WESupportedModel))) {
                [version]$WEBIOSApprovedVersion = ($WEBIOSPackageDetails | Where-Object {$_.Description -match $WESystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" " )[0] 
                $WEOEM = " DELL"
            } 
            else {
                Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message  " Model $WEComputerModel with SKU value $WESystemSKU not found in XML source"
            }       
        }
    }
    default {
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message  " Incompatible Hardware. $($WEManufacturer) not supported"
        Write-Output " Incompatible Hardware. $($WEManufacturer) not supported"
        Exit 0
    }
}


if (-NOT(Test-Path -Path " $WERegPath\" )) {
    New-Item -Path " $WERegPath" -Force
    New-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateInprogress' -Value 0 -PropertyType 'DWORD'
    New-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateAttempts' -Value 0 -PropertyType 'DWORD'
    New-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateTime' -Value "" -PropertyType 'String'
    New-ItemProperty -Path " $WERegPath" -Name 'BIOSDeployedVersion' -Value "" -PropertyType 'String'
}


$WEBiosUpdateinProgress = Get-ItemPropertyValue -Path $WERegPath -Name " BIOSUpdateInprogress"
if ($WEBiosUpdateinProgress -ne 0){
    Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " BIOS Update already in Progress"
    # Check if computer has restarted since last try 
    [DateTime]$WEBIOSUpdateTime = Get-ItemPropertyValue -Path " $WERegPath" -Name 'BIOSUpdateTime'
    $WELastBootime = Get-Date (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)
    if ($WEBIOSUpdateTime -gt $WELastBootime){
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Computer pending reboot after BIOS staging. Checking for user session"
        # Computer not restarted - Invoke remediation to notify user to reboot
        if (Test-UserSession){
            #User is logged on - send toast to user to perform the reboot
            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " User session found - notify user to reboot with toast"
            Invoke-ToastNotification -ToastSettings $WEToastSettings -AppID $WEAppID -Scenario $WEScenario
            Write-Output  " Computer pending reboot after BIOS staging. User toast invoked"
        } else {
            #No user logged on - enforcing a reboot to finalize BIOS flashing                
            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " No user currenty logged on - restarting computer to finalize BIOS flashing"
            Write-Output  " Computer pending reboot after BIOS staging. No users session found - restarting"
            $WERestartCommand = 'C:\Windows\System32\shutdown.exe'
            $WERestartArguments = '-r -t 60 -c " Your computer will be restarted in 1 minute to complete the BIOS Update process." '
            Start-Process $WERestartCommand -ArgumentList $WERestartArguments -NoNewWindow
        }
        Exit 0
    }
    else {
        # Step 4 Computer restarted - Check BIOS Version
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Computer has restarted after flashing - validating bios version"
        #Check BIOS Version - if not updated - Check counter - if not met threshold exit 1 - if treshold exit 0 
        $WETestBiosCommand = " Test-BIOSVersion$($WEOEM) -BIOSApprovedVersion $($WEBIOSApprovedVersion) -SystemID $($WESystemID)"
        $WEBIOSCheck = Invoke-Expression $WETestBiosCommand
        
        #If updated OK - Cleanup
        if ($WEBIOSCheck.ExitCode -eq 0){
            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Update Completed"
            Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateInprogress' -Value 0
            Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateAttempts' -Value 0 
            Set-ItemProperty -Path " $WERegPath" -Name 'BIOSUpdateTime' -Value "" 
            Set-ItemProperty -Path " $WERegPath" -Name 'BIOSDeployedVersion' -Value "" 
            Write-Output " $($WEBIOSCheck.Message)"
            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " $($WEBIOSCheck.Message)"
            Exit 0
        }
        else {
            #Step 5 Computer restarted - BIOS not updated - Check counter
            [int]$WEAttempts = Get-ItemPropertyValue -Path $WERegPath -Name 'BIOSUpdateAttempts'
            Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " Attempt $($WEAttempts): BIOS not current after flashing and reboot"
            if ($WEAttempts -gt 3){
                # Give up after 3 attempts
                Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " Update not completed after reboot - giving up after $($WEAttempts) attempts"
                Write-Output " Update not completed after reboot - giving up after $($WEAttempts) attempts"
                Exit 0     
            } 
            else {
                Write-EventLog -LogName $WEEventLogName -EntryType Warning -EventId 8002 -Source $WEEventLogSource -Message " Checking for active users sessions"
                # Checking for user session                
                if (Test-UserSession){
                    #User is logged on - send toast to user to perform the reboot
                    Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " User session found - notify user to reboot with toast"
                    Invoke-ToastNotification -ToastSettings $WEToastSettings -AppID $WEAppID -Scenario $WEScenario
                    Write-Output  " Computer pending reboot after BIOS staging. User toast invoked"
                } else {
                    #No user logged on - enforcing a reboot to finalize BIOS flashing                
                    Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " No user currenty logged on - restarting computer to finalize BIOS flashing"
                    Write-Output  " Computer pending reboot after BIOS staging. No users session found - restarting"
                    $WERestartCommand = 'C:\Windows\System32\shutdown.exe'
                    $WERestartArguments = '-r -t 60 -c " Your computer will be restarted in 1 minute to complete the BIOS Update process." '
                    Start-Process $WERestartCommand -ArgumentList $WERestartArguments -NoNewWindow
                }
                Exit 0
            }         
        }
    }
}
else {
    # Step 6 BIOS Update not in progress - Check BIOS Version
    Write-Output " Validate bios version"
   ;  $WEUpdateBIOSCommand = " Invoke-BIOSUpdate$($WEOEM) -BIOSApprovedVersion $($WEBIOSApprovedVersion) -SystemID $($WESystemID)"
   ;  $WEBIOSUpdate = Invoke-Expression $WEUpdateBIOSCommand

    if ($WEBIOSUpdate.ExitCode -eq 1){
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " $($WEBIOSCheck.Message)"
        Write-Output " $($WEBIOSUpdate.Message)"
        Exit 1
    }
    else {
        Write-EventLog -LogName $WEEventLogName -EntryType Information -EventId 8001 -Source $WEEventLogSource -Message " $($WEBIOSCheck.Message)"
        Write-Output " $($WEBIOSUpdate.Message)"
        Exit 0
    } 
}





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================