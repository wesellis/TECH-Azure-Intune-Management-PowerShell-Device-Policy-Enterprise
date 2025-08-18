<#
.SYNOPSIS
    Set Lenovovantage

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
    We Enhanced Set Lenovovantage

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<# PSScriptInfo
    .NOTES
        Updated: 26/10/2018
        http://thinkdeploy.blogspot.com/2018/01/configuring-lenovo-vantage-with-mdm.html

        10/11/2018
        Aaron Parker, @stealthpuppy
        - Add check for Win32_ComputerSystem.Manufacturer = LENOVO

    .DESCRIPTION
        This script is designed to hide Vantage features that may not be appropriate
        for enterprise customers.  Each feature is commented out beside each GUID in
        each array.





$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$stampDate = Get-Date
$scriptName = ([System.IO.Path]::GetFileNameWithoutExtension($(Split-Path $script:MyInvocation.MyCommand.Path -Leaf)))
$logFile = " $env:ProgramData\IntuneScriptLogs\$scriptName-" + $stampDate.ToFileTimeUtc() + " .log"
Start-Transcript -Path $logFile -NoClobber
$WEVerbosePreference = " Continue"


If ($WEENV:PROCESSOR_ARCHITECTURE -eq " AMD64" ) {
    Try {
        &" $WEENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -File $WEPSCOMMANDPATH
    }
    Catch {
        Throw " Failed to start $WEPSCOMMANDPATH"
    }
    Exit
}


If ((Get-CimInstance -ClassName " Win32_ComputerSystem" ).Manufacturer -eq " LENOVO" ) {

    # Create Vantage registry key if it doesn't exist
    Write-Output " Creating policy registry key"
    $path = " HKLM:\SOFTWARE\Policies\Lenovo\E046963F.LenovoCompanion_k1h2ywk1493x8"
    If (!(Test-Path $path\Messaging)) {
        New-Item -Path $path\Messaging -Force > $null
    }


    # System Health and Support Section ###
    Write-Output " Configuring System Health and Support Section"
    $healthSupport = @('6674459E-60E2-49DE-A791-510247897877',  # Knowledge Base
                'CCCD4009-AAE7-4014-8F5D-5AEC2585F503',         # Hardware Scan
                'D65D67BF-8916-4928-9B07-35E3A9A0EDC3',         # Discussion Forum
                'bc690b89-77aa-4cc9-b217-73573202b94e',         # Tips & Tricks
                'C615AC2F-F818-4AF6-99CA-D95E6FF1BD18'
    )
    ForEach ($i in $healthSupport) {
        New-ItemProperty -Path $path -Name $i -Value 0 -PropertyType DWord -Force > $null
    }


    # Apps and Offers Section
    Write-Output " Configuring Apps and Offers Section"
    $appOffers = @('08EC2D60-1A14-4B27-AF71-FB62D301D236',                      # Accessories
                '0E101F47-9A6F-4915-8C5F-E577D3184E5D',                         # Offers & Deals
                '8A6263C0-490C-4AE6-9456-8BBD81379787',                         # Rewards
                'CD120116-1DE7-4BA2-905B-1149BB7A12E7',                         # Apps For You (Entire Feature)
                'CD120116-1DE7-4BA2-905B-1149BB7A12E7_UserDefaultPreference',   # Apps For You (User Default Preference)
                '41A76A93-E02F-4703-862F-5187D84E7D90',                         # Apps For You/Drop Box
                'ECD16265-0AE8-429E-BC0A-E62BADFE3708'                          # Apps For You/Connect2
    )
    ForEach ($i in $appOffers) {
        New-ItemProperty -Path $path -Name $i -Value 0 -PropertyType DWord -Force > $null
    }


    # Hardware Settings Section
    Write-Output " Configuring Hardware Settings Section"
    $hardware = @('10DF05AE-BA16-4808-A436-A40A925F6EF6',   # HubPage/Recommended Settings
                '6F486CF5-5D51-4AE8-ABA9-089B5CB96420'      # Wifi Security Settings
    )
    ForEach ($i in $hardware) {
        New-ItemProperty -Path $path -Name $i -Value 0 -PropertyType DWord -Force > $null
    }


    # Messaging Preferences
    Write-Output " Configuring Messaging Preferences"
    $messaging = @('6BBE64B3-0E60-4C88-B901-4EF86BC01031',  # App Features
                'B187E8D5-D2AB-4A8B-B27E-2AF878017008',     # Marketing
                'EB3D3705-FA1F-4833-A88D-2F49A2968A1A'      # Action Triggered
    )
    ForEach ($i in $messaging) {
        New-ItemProperty -Path $path -Name $i -Value 0 -PropertyType DWord -Force > $null
    }
    New-ItemProperty -Path $path\Messaging -Name Marketing -Value 1 -PropertyType DWord -Force > $null


    # Launch page and Preferences
    Write-Output " Setting Launch Page and Preferences"
   ;  $pagePrefs = @('2210FAAF-933B-4985-BC86-7E5C47EB2465',                      # Lenovo ID Welcome Page
                '2885591F-F5A8-477A-9744-D1B9F30B5B79',                         # Preferences & WiFi Security
                '349B8C6E-6AE4-4FF3-B8A0-25D398E75AAE',                         # Device Refresh
                '369C3066-08A0-415A-838C-9C56C5FBF5C4',                         # Welcome Page
                '41A76A93-E02F-4703-862F-5187D84E7D90_Help',                    # Location Tracking
                '422FDE50-51D5-4A5B-9A44-7B19BCD03A29',                         # Anonymous Usage Statistics (Entire Feature)
                '422FDE50-51D5-4A5B-9A44-7B19BCD03A29_UserConfigurable',        # Anonymous Usage Statistics (Allow User Configuration)
                '422FDE50-51D5-4A5B-9A44-7B19BCD03A29_UserDefaultPreference',   # Anonymous Usage Statistics (User Default Preference)
                '9023E851-DE40-42C4-8175-1AE5953DE624',                         # User Feedback
                'AE37F328-7A7B-4E2F-BE67-A5BBBC0F444A',                         # Vantage Toolbar
                'AE37F328-7A7B-4E2F-BE67-A5BBBC0F444A_UserDefaultPreference',   # Vantage Toolbar Default Preferences
                'E0DF659E-02A6-417C-8B39-DB116529BFDD'                          # Lenovo ID
    )
    ForEach ($i in $pagePrefs) {
        New-ItemProperty -Path $path -Name $i -Value 0 -PropertyType DWord -Force > $null
    }


    # System Update
    <#
    Write-Output " Disabling System Update Plugin"
   ;  $sUPlugin = " HKLM:\SOFTWARE\WOW6432Node\Policies\Lenovo\ImController\Plugins\LenovoSystemUpdatePlugin"
    If (!(Test-Path $sUPlugin)) {
        New-Item -Path $sUPlugin -Force > $null
    }
    New-ItemProperty -Path $sUPlugin -Name " Imc-Block" -Value 1 -Force > $null                        # System Update Plugin
    New-ItemProperty -Path $path -Name " E40B12CE-C5DD-4571-BBC6-7EA5879A8472" -Value 0 -Force > $null # System Update GUI
    #>

}
Else {

    # Local device is not from Lenovo
    Write-Output " Local system is not a Lenovo device. Exiting."
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================