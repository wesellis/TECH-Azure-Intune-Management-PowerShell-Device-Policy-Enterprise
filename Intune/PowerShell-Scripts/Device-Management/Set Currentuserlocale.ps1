<#
.SYNOPSIS
    Set Currentuserlocale

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
    We Enhanced Set Currentuserlocale

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
        Set locale settings for the current user.
        Use with PowerShell scripts

    .NOTES
 	    NAME: Set-CurrentUserLocale.ps1
	    VERSION: 1.0
	    AUTHOR: Aaron Parker
	    TWITTER: @stealthpuppy

    .LINK
        http://stealthpuppy.com



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(" PSAvoidUsingWriteHost" , "" , Justification = " Output required by Proactive Remediations." )]


function Write-WELog {
    param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
        [ValidateSet(" INFO" , " WARN" , " ERROR" , " SUCCESS" )]
        [string]$Level = " INFO"
    )
    
   ;  $timestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
   ;  $colorMap = @{
        " INFO" = " Cyan" ; " WARN" = " Yellow" ; " ERROR" = " Red" ; " SUCCESS" = " Green"
    }
    
    $logEntry = " $timestamp [WE-Enhanced] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

param(
    [System.String] $WELocale = " en-AU" ,
    [System.String] $WEPath = " $env:Temp"
)


switch ($WELocale) {
    " en-US" {
        # United States
        $WEGeoId = 244
        $WETimezone = " Pacific Standard Time"
        $WELanguageId = " 0409:00000409"
    }
    " en-GB" {
        # Great Britain
        $WEGeoId = 242
        $WETimezone = " GMT Standard Time"
        $WELanguageId = " 0809:00000809"
    }
    " en-AU" {
        # Australia
        $WEGeoId = 12
        $WETimezone = " AUS Eastern Standard Time"
        $WELanguageId = " 0c09:00000409"
    }
    Default {
        # Australia
        $WEGeoId = 12
        $WETimezone = " AUS Eastern Standard Time"  #" Cen. Australia Standard Time"
        $WELanguageId = " 0c09:00000409"
    }
}

; 
$languageXml = @"
    <gs:GlobalizationServices
        xmlns:gs=" urn:longhornGlobalizationUnattend" >
        <!--User List-->
        <gs:UserList>
            <gs:User UserID=" Current" CopySettingsToDefaultUserAcct=" false" CopySettingsToSystemAcct=" false" />
        </gs:UserList>
        <!-- user locale -->
        <gs:UserLocale>
            <gs:Locale Name=" $WELocale" SetAsCurrent=" true" />
        </gs:UserLocale>
        <!-- system locale -->
        <gs:SystemLocale Name=" $WELocale" />
        <!-- GeoID -->
        <gs:LocationPreferences>
            <gs:GeoID Value=" $WEGeoId" />
        </gs:LocationPreferences>
        <gs:MUILanguagePreferences>
            <gs:MUILanguage Value=" $WELocale" />
            <gs:MUIFallback Value=" en-US" />
        </gs:MUILanguagePreferences>
        <!-- input preferences -->
        <gs:InputPreferences>
            <gs:InputLanguageID Action=" add" ID=" $WELanguageId" Default=" true" />
        </gs:InputPreferences>
    </gs:GlobalizationServices>
" @



try {
    Import-Module -Name " International"
    Set-WinUserLanguageList -LanguageList $WELocale -Force
    Set-WinHomeLocation -GeoId $WEGeoId
    Set-TimeZone -Id $WETimezone
    Set-Culture -CultureInfo $WELocale
}
catch {
    Write-Error -Message $_.Exception.Message
    exit 1
}

try {
    If (!(Test-Path -Path $WEPath)) { New-Item -Path $WEPath -ItemType " Directory" }
   ;  $WEOutFile = Join-Path -Path $WEPath -ChildPath " language.xml"
    Out-File -FilePath $WEOutFile -InputObject $languageXml -Encoding ascii
}
catch {
    Write-Error -Message $_.Exception.Message
    exit 1
}

try {
    & $env:SystemRoot\System32\control.exe " intl.cpl,,/f:$WEOutFile"
}
catch {
    Write-Error -Message $_.Exception.Message
    exit 1
}


Write-WELog " Set regional settings to $WELocale and $WETimezone." " INFO"
exit 0



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================