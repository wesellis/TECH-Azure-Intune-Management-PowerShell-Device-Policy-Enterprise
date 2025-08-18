<#
.SYNOPSIS
    Validate Ndesconfiguration

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
    We Enhanced Validate Ndesconfiguration

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

.SYNOPSIS
Highlights configuration problems on an NDES server, as configured for use with Intune Standalone SCEP certificates.

.DESCRIPTION
Validate-NDESConfig looks at the configuration of your NDES server and ensures it aligns to the " Configure and manage SCEP 
certificates with Intune" article. 

.NOTE This script is used purely to validate the configuration. All remedial tasks will need to be carried out manually.
Where possible, a link and section description will be provided.

.EXAMPLE
.\Validate-NDESConfiguration -NDESServiceAccount Contoso\NDES_SVC.com -IssuingCAServerFQDN IssuingCA.contoso.com -SCEPUserCertTemplate SCEPGeneral

.EXAMPLE
.\Validate-NDESConfiguration -help

.LINK
https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure



[CmdletBinding(DefaultParameterSetName=" NormalRun" )]

param(
[parameter(Mandatory=$true,ParameterSetName=" NormalRun" )]
[alias(" sa" )]
[ValidateScript({
    if ($_ -match " .\\." ){

        $WETrue
    
    }

    else {

    Throw " Please use the format Domain\Username for the NDES Service Account variable."

    }

    $WEEnteredDomain = $_.split(" \" )
    $ads = New-Object -ComObject ADSystemInfo
    $WEDomain = $ads.GetType().InvokeMember('DomainShortName','GetProperty', $WENull, $ads, $WENull)
    
        if ($WEEnteredDomain -like " $WEDomain" ) {

        $WETrue

        }

        else {
   
        Throw " Incorrect Domain. Ensure domain is '$($WEDomain)\<USERNAME>'"

        }

    }
)]
[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WENDESServiceAccount,

[parameter(Mandatory=$true,ParameterSetName=" NormalRun" )]
[alias(" ca" )]
[ValidateScript({
    $WEDomain = (Get-CimInstance Win32_ComputerSystem).domain
        if ($_ -match $WEDomain) {

        $WETrue

        }

        else {
   
        Throw " The Network Device Enrollment Server and the Certificate Authority are not members of the same Active Directory domain. This is an unsupported configuration."

        }

    }
)]
[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEIssuingCAServerFQDN,

[parameter(Mandatory=$true,ParameterSetName=" NormalRun" )]
[alias(" t" )]
[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESCEPUserCertTemplate,

[parameter(ParameterSetName=" Help" )]
[alias(" h" ," ?" ," /?" )]
[switch]$help,

[parameter(ParameterSetName=" Help" )]
[alias(" u" )]
[switch]$usage  

    
)



Function Log-ScriptEvent {

[CmdletBinding()]
$ErrorActionPreference = "Stop"

param(
      [parameter(Mandatory=$WETrue)]
      [String]$WELogFilePath,

      [parameter(Mandatory=$WETrue)]
      [String]$WEValue,

      [parameter(Mandatory=$WETrue)]
      [String]$WEComponent,

      [parameter(Mandatory=$WETrue)]
      [ValidateRange(1,3)]
      [Single]$WESeverity
      )

$WEDateTime = New-Object -ComObject WbemScripting.SWbemDateTime 
$WEDateTime.SetVarDate($(Get-Date))
$WEUtcValue = $WEDateTime.Value
$WEUtcOffset = $WEUtcValue.Substring(21, $WEUtcValue.Length - 21)

$WELogLine =  " <![LOG[$WEValue]LOG]!>" +`
            " <time=`" $(Get-Date -Format HH:mm:ss.fff)$($WEUtcOffset)`" " +`
            " date=`" $(Get-Date -Format M-d-yyyy)`" " +`
            " component=`" $WEComponent`" " +`
            " context=`" $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
            " type=`" $WESeverity`" " +`
            " thread=`" $([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
            " file=`" `" >"

Add-Content -Path $WELogFilePath -Value $WELogLine

}



function WE-Show-Usage {

    Write-Host
    Write-WELog " -help                       -h         Displays the help." " INFO"
    Write-WELog " -usage                      -u         Displays this usage information." " INFO"
    Write-WELog " -NDESExternalHostname       -ed        External DNS name for the NDES server (SSL certificate subject will be checked for this. It should be in the SAN of the certificate if" " INFO" 
    write-host "                                       clients communicate directly with the NDES server)"
    Write-WELog " -NDESServiceAccount         -sa        Username of the NDES service account. Format is Domain\sAMAccountName, such as Contoso\NDES_SVC." " INFO"
    Write-WELog " -IssuingCAServerFQDN        -ca        Name of the issuing CA to which you'll be connecting the NDES server.  Format is FQDN, such as 'MyIssuingCAServer.contoso.com'." " INFO"
    Write-WELog " -SCEPUserCertTemplate       -t         Name of the SCEP Certificate template. Please note this is _not_ the display name of the template. Value should not contain spaces." " INFO" 
    Write-Host

}



function WE-Get-NDESHelp {

    Write-Host
    Write-WELog " Verifies if the NDES server meets all the required configuration. " " INFO"
    Write-Host
    Write-WELog " The NDES server role is required as back-end infrastructure for Intune Standalone for delivering VPN and Wi-Fi certificates via the SCEP protocol to mobile devices and desktop clients." " INFO"
    Write-WELog " See https://docs.microsoft.com/en-us/intune/certificates-scep-configure." " INFO"
    Write-Host

}



    if ($help){

        Get-NDESHelp
        break

    }

    if ($usage){

        Show-Usage
        break
    }







$parent = [System.IO.Path]::GetTempPath()
[string] $name = [System.Guid]::NewGuid()
New-Item -ItemType Directory -Path (Join-Path $parent $name) | Out-Null
$WETempDirPath = " $parent$name"
$WELogFilePath = " $($WETempDirPath)\Validate-NDESConfig.log"





    Write-Host
    Write-host " ......................................................."
    Write-Host
    Write-WELog " NDES Service Account = " " INFO" -NoNewline 
    Write-WELog " $($WENDESServiceAccount)" " INFO" -ForegroundColor Cyan
    Write-host
    Write-WELog " Issuing CA Server = " " INFO" -NoNewline
    Write-WELog " $($WEIssuingCAServerFQDN)" " INFO" -ForegroundColor Cyan
    Write-host
    Write-WELog " SCEP Certificate Template = " " INFO" -NoNewline
    Write-WELog " $($WESCEPUserCertTemplate)" " INFO" -ForegroundColor Cyan
    Write-Host
    Write-host " ......................................................."
    Write-Host
    Write-WELog " Proceed with variables? [Y]es, [N]o" " INFO"
    
    $confirmation = Read-Host





    if ($confirmation -eq 'y'){
    Write-Host
    Write-host " ......................................................."
    Log-ScriptEvent $WELogFilePath " Initializing log file $($WETempDirPath)\Validate-NDESConfig.log"  NDES_Validation 1
    Log-ScriptEvent $WELogFilePath " Proceeding with variables=YES"  NDES_Validation 1
    Log-ScriptEvent $WELogFilePath " NDESServiceAccount=$($WENDESServiceAccount)" NDES_Validation 1
    Log-ScriptEvent $WELogFilePath " IssuingCAServer=$($WEIssuingCAServerFQDN)" NDES_Validation 1
    Log-ScriptEvent $WELogFilePath " SCEPCertificateTemplate=$($WESCEPUserCertTemplate)" NDES_Validation 1





    if (-not (Get-WindowsFeature ADCS-Device-Enrollment).Installed){
    
    Write-WELog " Error: NDES Not installed" " INFO" -BackgroundColor Red
    write-host " Exiting....................."
    Log-ScriptEvent $WELogFilePath " NDES Not installed" NDES_Validation 3
    break

    }

Install-WindowsFeature RSAT-AD-PowerShell | Out-Null

Import-Module ActiveDirectory | Out-Null

    if (-not (Get-WindowsFeature Web-WebServer).Installed){

        $WEIISNotInstalled = $WETRUE
        Write-Warning " IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"
        Write-Host
        Log-ScriptEvent $WELogFilePath " IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"  NDES_Validation 2
    
    }

    else {

        Import-Module WebAdministration | Out-Null

    }






    
    Write-Host
    Write-host " Checking Windows OS version..." -ForegroundColor Yellow
    Write-host
    Log-ScriptEvent $WELogFilePath " Checking OS Version" NDES_Validation 1

$WEOSVersion = (Get-CimInstance -class Win32_OperatingSystem).Version
$WEMinOSVersion = " 6.3"

    if ([version]$WEOSVersion -lt [version]$WEMinOSVersion){
    
        Write-host " Error: Unsupported OS Version. NDES Requires 2012 R2 and above." -BackgroundColor Red
        Log-ScriptEvent $WELogFilePath " Unsupported OS Version. NDES Requires 2012 R2 and above." NDES_Validation 3
        
        } 
    
    else {
    
        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " OS Version " " INFO" -NoNewline
        write-host " $($WEOSVersion)" -NoNewline -ForegroundColor Cyan
        write-host " supported."
        Log-ScriptEvent $WELogFilePath " Server is version $($WEOSVersion)" NDES_Validation 1
    
    }




    


Write-host
Write-host " ......................................................."
Write-Host
Write-host " Checking NDES Service Account properties in Active Directory..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking NDES Service Account properties in Active Directory" NDES_Validation 1

$WEADUser = $WENDESServiceAccount.split(" \" )[1]

$WEADUserProps = (Get-ADUser $WEADUser -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut)

    if ($WEADUserProps.enabled -ne $WETRUE -OR $WEADUserProps.PasswordExpired -ne $false -OR $WEADUserProps.LockedOut -eq $WETRUE){
        
        Write-WELog " Error: Problem with the AD account. Please see output below to determine the issue" " INFO" -BackgroundColor Red
        Write-Host
        Log-ScriptEvent $WELogFilePath " Problem with the AD account. Please see output below to determine the issue"  NDES_Validation 3
        
    }
        
    else {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " NDES Service Account seems to be in working order:" " INFO"
        Log-ScriptEvent $WELogFilePath " NDES Service Account seems to be in working order"  NDES_Validation 1
        
    }


  
Get-ADUser $WEADUser -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut | fl SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut







Write-host " `n.......................................................`n"
Write-host " Checking if NDES server is the CA...`n" -ForegroundColor Yellow
Log-ScriptEvent $WELogFilePath " Checking if NDES server is the CA" NDES_Validation 1 

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$WECARoleInstalled = (Get-WindowsFeature ADCS-Cert-Authority).InstallState -eq " Installed"

    if ($hostname -match $WEIssuingCAServerFQDN){
    
        Write-host " Error: NDES is running on the CA. This is an unsupported configuration!" -BackgroundColor Red
        Log-ScriptEvent $WELogFilePath " NDES is running on the CA"  NDES_Validation 3
    
    }
    elseif($WECARoleInstalled)
    {
        Write-host " Error: NDES server has Certification Authority Role installed. This is an unsupported configuration!" -BackgroundColor Red
        Log-ScriptEvent $WELogFilePath " NDES server has Certification Authority Role installed"  NDES_Validation 3
    }
    else {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " NDES server is not running on the CA" " INFO"
        Log-ScriptEvent $WELogFilePath " NDES server is not running on the CA"  NDES_Validation 1 
    
    }







Write-host
Write-host " ......................................................."
Write-host
Write-host " Checking NDES Service Account local permissions..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking NDES Service Account local permissions" NDES_Validation 1 

   if ((net localgroup) -match " Administrators" ){

    $WELocalAdminsMember = ((net localgroup Administrators))

        if ($WELocalAdminsMember -like " *$WENDESServiceAccount*" ){
        
            Write-Warning " NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use IIS_IUSERS instead."
            Log-ScriptEvent $WELogFilePath " NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use IIS_IUSERS instead."  NDES_Validation 2

        }

        else {

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-WELog " NDES Service account is not a member of the Local Administrators group" " INFO"
            Log-ScriptEvent $WELogFilePath " NDES Service account is not a member of the Local Administrators group"  NDES_Validation 1
    
        }

    Write-host
    Write-WELog " Checking NDES Service account is a member of the IIS_IUSR group..." " INFO" -ForegroundColor Yellow
    Write-host

    if ((net localgroup) -match " IIS_IUSRS" ){

        $WEIIS_IUSRMembers = ((net localgroup IIS_IUSRS))

        if ($WEIIS_IUSRMembers -like " *$WENDESServiceAccount*" ){

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-WELog " NDES Service Account is a member of the local IIS_IUSR group" " INFO" -NoNewline
            Log-ScriptEvent $WELogFilePath " NDES Service Account is a member of the local IIS_IUSR group" NDES_Validation 1
    
        }
    
        else {

            Write-WELog " Error: NDES Service Account is not a member of the local IIS_IUSR group" " INFO" -BackgroundColor red
            Log-ScriptEvent $WELogFilePath " NDES Service Account is not a member of the local IIS_IUSR group"  NDES_Validation 3 

            Write-host
            Write-host " Checking Local Security Policy for explicit rights via gpedit..." -ForegroundColor Yellow
            Write-Host
            $WETempFile = [System.IO.Path]::GetTempFileName()
            & " secedit" " /export" " /cfg" " $WETempFile" | Out-Null
            $WELocalSecPol = Get-Content $WETempFile
            $WEADUserProps = Get-ADUser $WEADUser
            $WENDESSVCAccountSID = $WEADUserProps.SID.Value 
            $WELocalSecPolResults = $WELocalSecPol | Select-String $WENDESSVCAccountSID

                if ($WELocalSecPolResults -match " SeInteractiveLogonRight" -AND $WELocalSecPolResults -match " SeBatchLogonRight" -AND $WELocalSecPolResults -match " SeServiceLogonRight" ){
            
                    Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                    Write-WELog " NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly." " INFO"
                    Log-ScriptEvent $WELogFilePath " NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly." NDES_Validation 1
                    Write-Host
                    Write-WELog " Note:" " INFO" -BackgroundColor Red -NoNewline
                    Write-WELog " The Logon Locally is not required in normal runtime." " INFO"
                    Write-Host
                    Write-WELog " Note:" " INFO" -BackgroundColor Red -NoNewline
                    Write-Host 'Consider using the IIS_IUSERS group instead of explicit rights as documented under " Step 1 - Create an NDES service account" .'
                    write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            
                }
            
                else {

                    Write-WELog " Error: NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly_." " INFO" -BackgroundColor red 
                    Write-Host 'Please review " Step 1 - Create an NDES service account" .' 
                    write-host " https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
                    Log-ScriptEvent $WELogFilePath " NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly_." NDES_Validation 3
            
                }
    
        }

    }

    else {

        Write-WELog " Error: No IIS_IUSRS group exists. Ensure IIS is installed." " INFO" -BackgroundColor red 
        write-host 'Please review " Step 3.1 - Configure prerequisites on the NDES server" .' 
        write-host " https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " No IIS_IUSRS group exists. Ensure IIS is installed." NDES_Validation 3
    
    }

    }

   else {

        Write-Warning " No local Administrators group exists, likely due to this being a Domain Controller. It is not recommended to run NDES on a Domain Controller."
        Log-ScriptEvent $WELogFilePath " No local Administrators group exists, likely due to this being a Domain Controller. It is not recommended to run NDES on a Domain Controller." NDES_Validation 2
    
    }







Write-host
Write-Host
Write-host " ......................................................."
Write-host
Write-host " Checking Windows Features are installed..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking Windows Features are installed..." NDES_Validation 1

$WEWindowsFeatures = @(" Web-Filtering" ," Web-Net-Ext45" ," NET-Framework-45-Core" ," NET-WCF-HTTP-Activation45" ," Web-Metabase" ," Web-WMI" )

foreach($WEWindowsFeature in $WEWindowsFeatures){

$WEFeature =  Get-WindowsFeature $WEWindowsFeature
$WEFeatureDisplayName = $WEFeature.displayName

    if($WEFeature.installed){
    
        Write-host " Success:" -ForegroundColor Green -NoNewline
        write-host " $WEFeatureDisplayName Feature Installed"
        Log-ScriptEvent $WELogFilePath " $($WEFeatureDisplayName) Feature Installed"  NDES_Validation 1
    
    }

    else {

        Write-WELog " Error: $WEFeatureDisplayName Feature not installed!" " INFO" -BackgroundColor red 
        Write-Host 'Please review " Step 3.1b - Configure prerequisites on the NDES server" .' 
        write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " $($WEFeatureDisplayName) Feature not installed"  NDES_Validation 3
    
    }

}







$WEErrorActionPreference = " SilentlyContinue"

Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking NDES Install Paramaters..." " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking NDES Install Paramaters" NDES_Validation 1

$WEInstallParams = @(Get-WinEvent -LogName " Microsoft-Windows-CertificateServices-Deployment/Operational" | Where-Object {$_.id -eq " 105" }|
Where-Object {$_.message -match " Install-AdcsNetworkDeviceEnrollmentService" }| Sort-Object -Property TimeCreated -Descending | Select-Object -First 1)

    if ($WEInstallParams.Message -match '-SigningProviderName " Microsoft Strong Cryptographic Provider" ' -AND ($WEInstallParams.Message -match '-EncryptionProviderName " Microsoft Strong Cryptographic Provider" ')) {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        write-host " Correct CSP used in install parameters"
        Write-host
        Write-Host $WEInstallParams.Message
        Log-ScriptEvent $WELogFilePath " Correct CSP used in install parameters:"  NDES_Validation 1
        Log-ScriptEvent $WELogFilePath " $($WEInstallParams.Message)"  NDES_Eventvwr 1

    }

    else {

        Write-WELog " Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP." " INFO" -BackgroundColor red
        Write-Host
        Write-Host $WEInstallParams.Message
        Log-ScriptEvent $WELogFilePath " Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP"  NDES_Validation 3 
        Log-ScriptEvent $WELogFilePath " $($WEInstallParams.Message)"  NDES_Eventvwr 3
    }

$WEErrorActionPreference = " Continue"







Write-host
Write-host " ......................................................."
Write-host
Write-host " Checking IIS Application Pool health..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking IIS Application Pool health" NDES_Validation 1

    if (-not ($WEIISNotInstalled -eq $WETRUE)){

        # If SCEP AppPool Exists    
        if (Test-Path 'IIS:\AppPools\SCEP'){

        $WEIISSCEPAppPoolAccount = Get-Item 'IIS:\AppPools\SCEP' | select -expandproperty processmodel | select -Expand username
            
            if ((Get-WebAppPoolState " SCEP" ).value -match " Started" ){
            
                $WESCEPAppPoolRunning = $WETRUE
            
            }

        }

        else {

            Write-WELog " Error: SCEP Application Pool missing!" " INFO" -BackgroundColor red 
            Write-Host 'Please review " Step 3.1 - Configure prerequisites on the NDES server" '. 
            write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
            Log-ScriptEvent $WELogFilePath " SCEP Application Pool missing"  NDES_Validation 3
        
        }
    
        if ($WEIISSCEPAppPoolAccount -contains " $WENDESServiceAccount" ){
            
        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " Application Pool is configured to use " " INFO" -NoNewline
        Write-WELog " $($WEIISSCEPAppPoolAccount)" " INFO"
        Log-ScriptEvent $WELogFilePath " Application Pool is configured to use $($WEIISSCEPAppPoolAccount)"  NDES_Validation 1
            
        }
            
        else {

        Write-WELog " Error: Application Pool is not configured to use the NDES Service Account" " INFO" -BackgroundColor red 
        Write-Host 'Please review " Step 4.1 - Configure NDES for use with Intune" .' 
        write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
        Log-ScriptEvent $WELogFilePath " Application Pool is not configured to use the NDES Service Account"  NDES_Validation 3
            
        }
                
        if ($WESCEPAppPoolRunning){
                
            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-WELog " SCEP Application Pool is Started " " INFO" -NoNewline
            Log-ScriptEvent $WELogFilePath " SCEP Application Pool is Started"  NDES_Validation 1
                
        }
                
        else {

            Write-WELog " Error: SCEP Application Pool is stopped!" " INFO" -BackgroundColor red 
            Write-WELog " Please start the SCEP Application Pool via IIS Management Console. You should also review the Application Event log output for Errors" " INFO"
            Log-ScriptEvent $WELogFilePath " SCEP Application Pool is stopped"  NDES_Validation 3
                
        }

    }

    else {

        Write-WELog " IIS is not installed." " INFO" -BackgroundColor red
        Log-ScriptEvent $WELogFilePath " SCEP Application Pool is stopped"  NDES_Validation 3 

    }







Write-Host
Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking Request Filtering (Default Web Site -> Request Filtering -> Edit Feature Setting) has been configured in IIS..." " INFO" -ForegroundColor Yellow
Write-Host
Log-ScriptEvent $WELogFilePath " Checking Request Filtering" NDES_Validation 1

    if (-not ($WEIISNotInstalled -eq $WETRUE)){

        [xml]$WERequestFiltering = (c:\windows\system32\inetsrv\appcmd.exe list config " default web site" /section:requestfiltering)

        if ($WERequestFiltering.'system.webserver'.security.requestFiltering.requestLimits.maxQueryString -eq " 65534" ){
    
            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            write-host " MaxQueryString Set Correctly"
            Log-ScriptEvent $WELogFilePath " MaxQueryString Set Correctly"  NDES_Validation 1    
    
        }
    
        else {

            Write-WELog " MaxQueryString not set correctly!" " INFO" -BackgroundColor red 
            Write-Host 'Please review " Step 4.4 - Configure NDES for use with Intune" .'
            write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Log-ScriptEvent $WELogFilePath " MaxQueryString not set correctly"  NDES_Validation 3
    
        }

        if ($WERequestFiltering.'system.webserver'.security.requestFiltering.requestLimits.maxUrl -eq " 65534" ){
    
            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            write-host " MaxUrl Set Correctly"
            Log-ScriptEvent $WELogFilePath " MaxUrl Set Correctly"  NDES_Validation 1
    
        }

        else {
    
            Write-WELog " maxUrl not set correctly!" " INFO" -BackgroundColor red 
            Write-Host 'Please review " Step 4.4 - Configure NDES for use with Intune" .'
            write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure'"
            Log-ScriptEvent $WELogFilePath " maxUrl not set correctly"  NDES_Validation 3 

        }

     }

    else {

        Write-WELog " IIS is not installed." " INFO" -BackgroundColor red
        Log-ScriptEvent $WELogFilePath " IIS is not installed"  NDES_Validation 3 

    }







Write-host
Write-host " ......................................................."
Write-host
Write-Host 'Checking registry " HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters" has been set to allow long URLs...' -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking registry (HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters) has been set to allow long URLs" NDES_Validation 1

    if (-not ($WEIISNotInstalled -eq $WETRUE)){

        If ((Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength).MaxfieldLength -notmatch " 65534" ){

            Write-WELog " Error: MaxFieldLength not set to 65534 in the registry!" " INFO" -BackgroundColor red
            Write-Host 
            Write-Host 'Please review " Step 4.3 - Configure NDES for use with Intune" .'
            write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Log-ScriptEvent $WELogFilePath " MaxFieldLength not set to 65534 in the registry" NDES_Validation 3
        } 

        else {

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            write-host " MaxFieldLength set correctly"
            Log-ScriptEvent $WELogFilePath " MaxFieldLength set correctly"  NDES_Validation 1
    
        }
		
        if ((Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes).MaxRequestBytes -notmatch " 65534" ){

            Write-WELog " MaxRequestBytes not set to 65534 in the registry!" " INFO" -BackgroundColor red
            Write-Host 
            Write-Host 'Please review " Step 4.3 - Configure NDES for use with Intune" .'
            write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure'"
            Log-ScriptEvent $WELogFilePath " MaxRequestBytes not set to 65534 in the registry" NDES_Validation 3 

        }
        
        else {

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            write-host " MaxRequestBytes set correctly"
            Log-ScriptEvent $WELogFilePath " MaxRequestBytes set correctly"  NDES_Validation 1
        
        }

    }

    else {

        Write-WELog " IIS is not installed." " INFO" -BackgroundColor red
        Log-ScriptEvent $WELogFilePath " IIS is not installed." NDES_Validation 3

    }







Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking SPN has been set..." " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking SPN has been set" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname

$spn = setspn.exe -L $WEADUser

    if ($spn -match $hostname){
    
        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        write-host " Correct SPN set for the NDES service account:"
        Write-host
        Write-Host $spn -ForegroundColor Cyan
        Log-ScriptEvent $WELogFilePath " Correct SPN set for the NDES service account: $($spn)"  NDES_Validation 1
    
    }
    
    else {

        Write-WELog " Error: Missing or Incorrect SPN set for the NDES Service Account!" " INFO" -BackgroundColor red 
        Write-Host 'Please review " Step 3.1c - Configure prerequisites on the NDES server" .'
        write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " Missing or Incorrect SPN set for the NDES Service Account"  NDES_Validation 3 
    
    }






       
Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking there are no intermediate certs are in the Trusted Root store..." " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking there are no intermediate certs are in the Trusted Root store" NDES_Validation 1

$WEIntermediateCertCheck = Get-Childitem cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject}

    if ($WEIntermediateCertCheck){
    
        Write-WELog " Error: Intermediate certificate found in the Trusted Root store. This can cause undesired effects and should be removed." " INFO" -BackgroundColor red 
        Write-WELog " Certificates:" " INFO"
        Write-Host 
        Write-Host $WEIntermediateCertCheck
        Log-ScriptEvent $WELogFilePath " Intermediate certificate found in the Trusted Root store: $($WEIntermediateCertCheck)"  NDES_Validation 3
    
    }
    
    else {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " Trusted Root store does not contain any Intermediate certificates." " INFO"
        Log-ScriptEvent $WELogFilePath " Trusted Root store does not contain any Intermediate certificates."  NDES_Validation 1
    
    }







$WEErrorActionPreference = " Silentlycontinue"

Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking the EnrollmentAgentOffline and CEPEncryption are present..." " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking the EnrollmentAgentOffline and CEPEncryption are present" NDES_Validation 1

$certs = Get-ChildItem cert:\LocalMachine\My\

    # Looping through all certificates in LocalMachine Store
    Foreach ($item in $certs){
      
    $WEOutput = ($item.Extensions| where-object {$_.oid.FriendlyName -like " **" }).format(0).split(" ," )

        if ($WEOutput -match " EnrollmentAgentOffline" ){
        
            $WEEnrollmentAgentOffline = $WETRUE
        
        }
            
        if ($WEOutput -match " CEPEncryption" ){
            
            $WECEPEncryption = $WETRUE
            
        }

    } 
    
    # Checking if EnrollmentAgentOffline certificate is present
    if ($WEEnrollmentAgentOffline){
    
        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " EnrollmentAgentOffline certificate is present" " INFO"
        Log-ScriptEvent $WELogFilePath " EnrollmentAgentOffline certificate is present"  NDES_Validation 1
    
    }
    
    else {

        Write-WELog " Error: EnrollmentAgentOffline certificate is not present!" " INFO" -BackgroundColor red 
        Write-WELog " This can take place when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions." " INFO" 
        write-host 'Please review " Step 3.1 - Configure prerequisites on the NDES server" .' 
        write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " EnrollmentAgentOffline certificate is not present"  NDES_Validation 3 
    
    }
    
    # Checking if CEPEncryption is present
    if ($WECEPEncryption){
        
        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " CEPEncryption certificate is present" " INFO"
        Log-ScriptEvent $WELogFilePath " CEPEncryption certificate is present"  NDES_Validation 1
        
    }
        
    else {

        Write-WELog " Error: CEPEncryption certificate is not present!" " INFO" -BackgroundColor red 
        Write-WELog " This can take place when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions." " INFO" 
        write-host 'Please review " Step 3.1 - Configure prerequisites on the NDES server" .' 
        write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " CEPEncryption certificate is not present"  NDES_Validation 3
        
    }

$WEErrorActionPreference = " Continue"







Write-host
Write-host " ......................................................."
Write-host
Write-Host 'Checking registry " HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP" has been set with the SCEP certificate template name...' -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking registry (HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP) has been set with the SCEP certificate template name" NDES_Validation 1

    if (-not (Test-Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP)){

        Write-host " Error: Registry key does not exist. This can occur if the NDES role has been installed but not configured." -BackgroundColor Red
        Write-host 'Please review " Step 3 - Configure prerequisites on the NDES server" .'
        write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " MSCEP Registry key does not exist."  NDES_Validation 3 

    }

    else {

    $WESignatureTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name SignatureTemplate).SignatureTemplate
    $WEEncryptionTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name EncryptionTemplate).EncryptionTemplate
    $WEGeneralPurposeTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name GeneralPurposeTemplate).GeneralPurposeTemplate 
    $WEDefaultUsageTemplate = " IPSECIntermediateOffline"

        if ($WESignatureTemplate -match $WEDefaultUsageTemplate -AND $WEEncryptionTemplate -match $WEDefaultUsageTemplate -AND $WEGeneralPurposeTemplate -match $WEDefaultUsageTemplate){
        
            Write-WELog " Error: Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed." " INFO" -BackgroundColor red
            write-host 'Please review " Step 3.1 - Configure prerequisites on the NDES server" .' 
            write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Write-Host
            Log-ScriptEvent $WELogFilePath " Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed."  NDES_Validation 3
            $WEFurtherReading = $WEFALSE
        
        }

        else {

            Write-WELog " One or more default values have been changed." " INFO"
            Write-Host 
            write-host " Checking SignatureTemplate key..."
            Write-host
        
            if ($WESignatureTemplate -match $WESCEPUserCertTemplate){

                Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                write-host " SCEP certificate template '$($WESCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template."
                Write-host
                Log-ScriptEvent $WELogFilePath " SCEP certificate template $($WESCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key"  NDES_Validation 1

            }

            else {
        
                Write-Warning '" SignatureTemplate key does not match the SCEP certificate template name. Unless your template is explicitly set for the " Signature" purpose, this can safely be ignored." '
                Write-Host
                write-host " Registry value: " -NoNewline
                Write-host " $($WESignatureTemplate)" -ForegroundColor Cyan
                Write-Host
                write-host " SCEP certificate template value: " -NoNewline
                Write-host " $($WESCEPUserCertTemplate)" -ForegroundColor Cyan
                Write-Host
                Log-ScriptEvent $WELogFilePath " SignatureTemplate key does not match the SCEP certificate template name.Registry value=$($WESignatureTemplate)|SCEP certificate template value=$($WESCEPUserCertTemplate)"  NDES_Validation 2
        
            }
                
                Write-host " ......................."
                Write-Host
                Write-WELog " Checking EncryptionTemplate key..." " INFO"
                Write-host

                if ($WEEncryptionTemplate -match $WESCEPUserCertTemplate){
            
                    Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                    write-host " SCEP certificate template '$($WESCEPUserCertTemplate)' has been written to the registry under the _EncryptionTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template."
                    Write-host
                    Log-ScriptEvent $WELogFilePath " SCEP certificate template $($WESCEPUserCertTemplate) has been written to the registry under the _EncryptionTemplate_ key"  NDES_Validation 1

            
                }
            
                else {

                    Write-Warning '" EncryptionTemplate key does not match the SCEP certificate template name. Unless your template is explicitly set for the " Encryption" purpose, this can safely be ignored." '
                    Write-Host
                    write-host " Registry value: " -NoNewline
                    Write-host " $($WEEncryptionTemplate)" -ForegroundColor Cyan
                    Write-Host
                    write-host " SCEP certificate template value: " -NoNewline
                    Write-host " $($WESCEPUserCertTemplate)" -ForegroundColor Cyan
                    Write-Host
                    Log-ScriptEvent $WELogFilePath " EncryptionTemplate key does not match the SCEP certificate template name.Registry value=$($WEEncryptionTemplate)|SCEP certificate template value=$($WESCEPUserCertTemplate)"  NDES_Validation 2

            
                }
                
                    Write-host " ......................."
                    Write-Host
                    Write-WELog " Checking GeneralPurposeTemplate key..." " INFO"
                    Write-host

                    if ($WEGeneralPurposeTemplate -match $WESCEPUserCertTemplate){
                
                        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                        write-host " SCEP certificate template '$($WESCEPUserCertTemplate)' has been written to the registry under the _GeneralPurposeTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template"
                        Log-ScriptEvent $WELogFilePath " SCEP certificate template $($WESCEPUserCertTemplate) has been written to the registry under the _GeneralPurposeTemplate_ key"  NDES_Validation 1

                    }
                
                    else {

                        Write-Warning '" GeneralPurposeTemplate key does not match the SCEP certificate template name. Unless your template is set for the " Signature and Encryption" (General) purpose, this can safely be ignored." '
                        Write-Host
                        write-host " Registry value: " -NoNewline
                        Write-host " $($WEGeneralPurposeTemplate)" -ForegroundColor Cyan
                        Write-Host
                        write-host " SCEP certificate template value: " -NoNewline
                        Write-host " $($WESCEPUserCertTemplate)" -ForegroundColor Cyan
                        Write-Host
                        Log-ScriptEvent $WELogFilePath " GeneralPurposeTemplate key does not match the SCEP certificate template name.Registry value=$($WEGeneralPurposeTemplate)|SCEP certificate template value=$($WESCEPUserCertTemplate)"  NDES_Validation 2

                
                    }

        }

        if ($furtherreading-EQ $true){
        
            Write-host " ......................."
            Write-Host
            Write-host 'For further reading, please review " Step 4.2 - Configure NDES for use with Intune" .'
            write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"

        }

    }
        
$WEErrorActionPreference = " Continue"







Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking IIS SSL certificate is valid for use..." " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking IIS SSL certificate is valid for use" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$serverAuthEKU = " 1.3.6.1.5.5.7.3.1" # Server Authentication
$allSSLCerts = Get-ChildItem Cert:\LocalMachine\My
$WEBoundServerCert = netsh http show sslcert
    
    foreach ($WECert in $allSSLCerts) {       

    $WEServerCertThumb = $cert.Thumbprint

        if ($WEBoundServerCert -match $WEServerCertThumb){

            $WEBoundServerCertThumb = $WEServerCertThumb

        }

    }

$WEServerCertObject = Get-ChildItem Cert:\LocalMachine\My\$WEBoundServerCertThumb

    if ($WEServerCertObject.Issuer -match $WEServerCertObject.Subject){

        $WESelfSigned = $true

    }

    else {
    
        $WESelfSigned = $false
    
    }

        if ($WEServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU -AND (($WEServerCertObject.Subject -match $hostname) -or ($WEServerCertObject.DnsNameList -match $hostname)) -AND $WEServerCertObject.Issuer -notmatch $WEServerCertObject.Subject){

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            write-host " Certificate bound in IIS is valid:"
            Write-Host
            Write-WELog " Subject: " " INFO" -NoNewline
            Write-host " $($WEServerCertObject.Subject)" -ForegroundColor Cyan
            Write-Host
            Write-WELog " Thumbprint: " " INFO" -NoNewline
            Write-WELog " $($WEServerCertObject.Thumbprint)" " INFO" -ForegroundColor Cyan
            Write-Host
            Write-WELog " Valid Until: " " INFO" -NoNewline
            Write-WELog " $($WEServerCertObject.NotAfter)" " INFO" -ForegroundColor Cyan
            Write-Host
            Write-WELog " If this NDES server is in your perimeter network, please ensure the external hostname is shown below:" " INFO" -ForegroundColor Blue -BackgroundColor White
            $WEDNSNameList = $WEServerCertObject.DNSNameList.unicode
            Write-Host
            write-host " Internal and External hostnames: " -NoNewline
            Write-host " $($WEDNSNameList)" -ForegroundColor Cyan
            Log-ScriptEvent $WELogFilePath " Certificate bound in IIS is valid. Subject:$($WEServerCertObject.Subject)|Thumbprint:$($WEServerCertObject.Thumbprint)|ValidUntil:$($WEServerCertObject.NotAfter)|Internal&ExternalHostnames:$($WEDNSNameList)" NDES_Validation 1

            }
    
        else {

        Write-WELog " Error: The certificate bound in IIS is not valid for use. Reason:" " INFO" -BackgroundColor red 
        write-host
          

                if ($WEServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU) {
                
                    $WEEKUValid = $true

                }

                else {
                
                    $WEEKUValid = $false

                    write-host " Correct EKU: " -NoNewline
                    Write-WELog " $($WEEKUValid)" " INFO" -ForegroundColor Cyan
                    Write-Host
                
                }

                if ($WEServerCertObject.Subject -match $hostname) {
                
                    $WESubjectValid = $true

                }

                else {
                
                    $WESubjectValid = $false

                    write-host " Correct Subject: " -NoNewline
                    write-host " $($WESubjectValid)" -ForegroundColor Cyan
                    Write-Host
                
                }

                if ($WESelfSigned -eq $false){
               
                    Out-Null
                
                }

                else {
                
                    write-host " Is Self-Signed: " -NoNewline
                    write-host " $($WESelfSigned)" -ForegroundColor Cyan
                    Write-Host
                
                }

        Write-Host 'Please review " Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server" .'
        write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " The certificate bound in IIS is not valid for use. CorrectEKU=$($WEEKUValid)|CorrectSubject=$($WESubjectValid)|IsSelfSigned=$($WESelfSigned)"  NDES_Validation 3

}
        






Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking Client certificate (NDES Policy module) is valid for use..." " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking Client certificate (NDES Policy module) is valid for use" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$clientAuthEku = " 1.3.6.1.5.5.7.3.2" # Client Authentication
$WENDESCertThumbprint = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\Modules\NDESPolicy -Name NDESCertThumbprint).NDESCertThumbprint
$WEClientCertObject = Get-ChildItem Cert:\LocalMachine\My\$WENDESCertThumbprint

    if ($WEClientCertObject.Issuer -match $WEClientCertObject.Subject){

        $WEClientCertSelfSigned = $true

    }

    else {
    
        $WEClientCertSelfSigned = $false
    
    }

        if ($WEClientCertObject.EnhancedKeyUsageList -match $clientAuthEku -AND $WEClientCertObject.Subject -match $hostname -AND $WEClientCertObject.Issuer -notmatch $WEClientCertObject.Subject){

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            write-host " Client certificate bound to NDES Connector is valid:"
            Write-Host
            Write-WELog " Subject: " " INFO" -NoNewline
            Write-host " $($WEClientCertObject.Subject)" -ForegroundColor Cyan
            Write-Host
            Write-WELog " Thumbprint: " " INFO" -NoNewline
            Write-WELog " $($WEClientCertObject.Thumbprint)" " INFO" -ForegroundColor Cyan
            Write-Host
            Write-WELog " Valid Until: " " INFO" -NoNewline
            Write-WELog " $($WEClientCertObject.NotAfter)" " INFO" -ForegroundColor Cyan
            Log-ScriptEvent $WELogFilePath " Client certificate bound to NDES Connector is valid. Subject:$($WEClientCertObject.Subject)|Thumbprint:$($WEClientCertObject.Thumbprint)|ValidUntil:$($WEClientCertObject.NotAfter)"  NDES_Validation 1

        }
    
        else {

        Write-WELog " Error: The certificate bound to the NDES Connector is not valid for use. Reason:" " INFO" -BackgroundColor red 
        write-host  

                if ($WEClientCertObject.EnhancedKeyUsageList -match $clientAuthEku) {
                
                    $WEClientCertEKUValid = $true

                }

                else {
                
                    $WEClientCertEKUValid = $false

                    write-host " Correct EKU: " -NoNewline
                    Write-WELog " $($WEClientCertEKUValid)" " INFO" -ForegroundColor Cyan
                    Write-Host
                
                }

                if ($WEClientCertObject.Subject -match $hostname) {
                
                    $WEClientCertSubjectValid = $true

                }

                else {
                
                    $WEClientCertSubjectValid = $false

                    write-host " Correct Subject: " -NoNewline
                    write-host " $($WEClientCertSubjectValid)" -ForegroundColor Cyan
                    Write-Host
                
                }

                if ($WEClientCertSelfSigned -eq $false){
               
                    Out-Null
                
                }

                else {
                
                    write-host " Is Self-Signed: " -NoNewline
                    write-host " $($WEClientCertSelfSigned)" -ForegroundColor Cyan
                    Write-Host
                
                }

        Write-Host 'Please review " Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server" .'
        write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " The certificate bound to the NDES Connector is not valid for use. CorrectEKU=$($WEClientCertEKUValid)|CorrectSubject=$($WEClientCertSubjectValid)|IsSelfSigned=$($WEClientCertSelfSigned)"  NDES_Validation 3


}
        






Write-host
Write-host " ......................................................."
$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
Write-host
Write-WELog " Checking behaviour of internal NDES URL: " " INFO" -NoNewline -ForegroundColor Yellow
Write-WELog " https://$hostname/certsrv/mscep/mscep.dll" " INFO" -ForegroundColor Cyan
Write-host
Log-ScriptEvent $WELogFilePath " Checking behaviour of internal NDES URL" NDES_Validation 1
Log-ScriptEvent $WELogFilePath " Https://$hostname/certsrv/mscep/mscep.dll" NDES_Validation 1

$WEStatuscode = try {(Invoke-WebRequest -Uri https://$hostname/certsrv/mscep/mscep.dll).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

    if ($statuscode -eq " 200" ){

    Write-host " Error: https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or not being installed." -BackgroundColor Red
    Log-ScriptEvent $WELogFilePath " https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or not being installed"  NDES_Validation 3
    } 

    elseif ($statuscode -eq " 403" ){

    Write-WELog " Trying to retrieve CA Capabilitiess..." " INFO" -ForegroundColor Yellow
    Write-Host
    $WENewstatuscode = try {(Invoke-WebRequest -Uri " https://$hostname/certsrv/mscep/mscep.dll?operation=GetCACaps&message=test" ).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

        if ($WENewstatuscode -eq " 200" ){

       ;  $WECACaps = (Invoke-WebRequest -Uri " https://$hostname/certsrv/mscep?operation=GetCACaps&message=test" ).content

        }

            if ($WECACaps){

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            write-host " CA Capabilities retrieved:"
            Write-Host
            write-host $WECACaps
            Log-ScriptEvent $WELogFilePath " CA Capabilities retrieved:$WECACaps"  NDES_Validation 1
                
            }

    }
                    
    else {
    
        Write-host " Error: Unexpected Error code! This usually signifies an error with the Intune Connector registering itself or not being installed" -BackgroundColor Red
        Write-host " Expected value is a 403. We received a $($WEStatuscode). This could be down to a missing reboot post policy module install. Verify last boot time and module install time further down the validation."
        Log-ScriptEvent $WELogFilePath " Unexpected Error code. Expected:403|Received:$WEStatuscode"  NDES_Validation 3
    
   }
        






Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking Servers last boot time..." " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking Servers last boot time" NDES_Validation 1
; 
$WELastBoot = (Get-CimInstance win32_operatingsystem | select csname, @{LABEL='LastBootUpTime'
;EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).lastbootuptime

write-host " Server last rebooted: " -NoNewline
Write-WELog " $($WELastBoot). " " INFO" -ForegroundColor Cyan -NoNewline
Write-WELog " Please ensure a reboot has taken place _after_ all registry changes and installing the NDES Connector. IISRESET is _not_ sufficient." " INFO"
Log-ScriptEvent $WELogFilePath " LastBootTime:$WELastBoot"  NDES_Validation 1







Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking Intune Connector is installed..." " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking Intune Connector is installed" NDES_Validation 1 

    if ($WEIntuneConnector = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ? {$_.DisplayName -eq " Microsoft Intune Connector" }){

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " $($WEIntuneConnector.DisplayName) was installed on " " INFO" -NoNewline 
        Write-WELog " $($WEIntuneConnector.InstallDate) " " INFO" -ForegroundColor Cyan -NoNewline 
        write-host " and is version " -NoNewline
        Write-WELog " $($WEIntuneConnector.DisplayVersion)" " INFO" -ForegroundColor Cyan -NoNewline
        Write-host
        Log-ScriptEvent $WELogFilePath " ConnectorVersion:$WEIntuneConnector"  NDES_Validation 1

    }

    else {

        Write-WELog " Error: Intune Connector not installed" " INFO" -BackgroundColor red 
        Write-Host 'Please review " Step 5 - Enable, install, and configure the Intune certificate connector" .'
        write-host " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Write-Host
        Log-ScriptEvent $WELogFilePath " ConnectorNotInstalled"  NDES_Validation 3 
        
    }








Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking Intune Connector registry keys are intact" " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking Intune Connector registry keys are intact" NDES_Validation 1
$WEErrorActionPreference = " SilentlyContinue"

$WEKeyRecoveryAgentCertificate = " HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\KeyRecoveryAgentCertificate"
$WEPfxSigningCertificate = " HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\PfxSigningCertificate"
$WESigningCertificate = " HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\SigningCertificate"

    if (-not ($WEKeyRecoveryAgentCertificate)){

        Write-host " Error: KeyRecoveryAgentCertificate Registry key does not exist." -BackgroundColor Red
        Write-Host
        Log-ScriptEvent $WELogFilePath " KeyRecoveryAgentCertificate Registry key does not exist."  NDES_Validation 3 

    }

        else {

        $WEKeyRecoveryAgentCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name KeyRecoveryAgentCertificate).KeyRecoveryAgentCertificate

            if (-not ($WEKeyRecoveryAgentCertificatePresent)) {
    
                Write-Warning " KeyRecoveryAgentCertificate registry key exists but has no value"
                Log-ScriptEvent $WELogFilePath " KeyRecoveryAgentCertificate missing Value"  NDES_Validation 2

            }

            else {
    
                Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                Write-WELog " KeyRecoveryAgentCertificate registry key exists" " INFO"
                Log-ScriptEvent $WELogFilePath " KeyRecoveryAgentCertificate registry key exists"  NDES_Validation 1

            }



    }

    if (-not ($WEPfxSigningCertificate)){

        Write-host " Error: PfxSigningCertificate Registry key does not exist." -BackgroundColor Red
        Write-Host
        Log-ScriptEvent $WELogFilePath " PfxSigningCertificate Registry key does not exist."  NDES_Validation 3 


        }

        else {

        $WEPfxSigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name PfxSigningCertificate).PfxSigningCertificate

            if (-not ($WEPfxSigningCertificatePresent)) {
    
                Write-Warning " PfxSigningCertificate registry key exists but has no value"
                Log-ScriptEvent $WELogFilePath " PfxSigningCertificate missing Value"  NDES_Validation 2

            }

            else {
    
                Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                Write-WELog " PfxSigningCertificate registry keys exists" " INFO"
                Log-ScriptEvent $WELogFilePath " PfxSigningCertificate registry key exists"  NDES_Validation 1

        }



    }

    if (-not ($WESigningCertificate)){

        Write-host " Error: SigningCertificate Registry key does not exist." -BackgroundColor Red
        Write-Host
        Log-ScriptEvent $WELogFilePath " SigningCertificate Registry key does not exist"  NDES_Validation 3  

    }

        else {

        $WESigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name SigningCertificate).SigningCertificate

            if (-not ($WESigningCertificatePresent)) {
    
                Write-Warning " SigningCertificate registry key exists but has no value"
                Log-ScriptEvent $WELogFilePath " SigningCertificate registry key exists but has no value"  NDES_Validation 2


            }

            else {
    
                Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                Write-WELog " SigningCertificate registry key exists" " INFO"
                Log-ScriptEvent $WELogFilePath " SigningCertificate registry key exists"  NDES_Validation 1


            }



    }

$WEErrorActionPreference = " Continue"







$WEErrorActionPreference = " SilentlyContinue"
$WEEventLogCollDays = ((Get-Date).AddDays(-5)) #Number of days to go back in the event log

Write-host
Write-host " ......................................................."
Write-host
Write-WELog " Checking Event logs for pertinent errors..." " INFO" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $WELogFilePath " Checking Event logs for pertinent errors" NDES_Validation 1

    if (-not (Get-EventLog -LogName " Microsoft Intune Connector" -EntryType Error -After $WEEventLogCollDays -ErrorAction silentlycontinue)) {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        write-host " No errors found in the Microsoft Intune Connector"
        Write-host
        Log-ScriptEvent $WELogFilePath " No errors found in the Microsoft Intune Connector"  NDES_Validation 1

    }

    else {

        Write-Warning " Errors found in the Microsoft Intune Connector Event log. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Host
        $WEEventsCol1 = (Get-EventLog -LogName " Microsoft Intune Connector" -EntryType Error -After $WEEventLogCollDays -Newest 5 | select TimeGenerated,Source,Message)
        $WEEventsCol1 | fl
        Log-ScriptEvent $WELogFilePath " Errors found in the Microsoft Intune Connector Event log"  NDES_Eventvwr 3
       ;  $i = 0
       ;  $count = @($WEEventsCol1).count

        foreach ($item in $WEEventsCol1) {

            Log-ScriptEvent $WELogFilePath " $($WEEventsCol1[$i].TimeGenerated);$($WEEventsCol1[$i].Message);$($WEEventsCol1[$i].Source)"  NDES_Eventvwr 3
            $i++

            }
            
        }

            if (-not (Get-EventLog -LogName " Application" -EntryType Error -Source NDESConnector,Microsoft-Windows-NetworkDeviceEnrollmentService -After $WEEventLogCollDays -ErrorAction silentlycontinue)) {

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            write-host " No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector"
            Write-host
            Log-ScriptEvent $WELogFilePath " No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector"  NDES_Validation 1

            }

    else {

        Write-Warning " Errors found in the Application Event log for source NetworkDeviceEnrollmentService or NDESConnector. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Host
        $WEEventsCol2 = (Get-EventLog -LogName " Application" -EntryType Error -Source NDESConnector,Microsoft-Windows-NetworkDeviceEnrollmentService -After $WEEventLogCollDays -Newest 5 | select TimeGenerated,Source,Message)
        $WEEventsCol2 |fl
       ;  $i = 0
       ;  $count = @($WEEventsCol2).count

        foreach ($item in $WEEventsCol2) {

            Log-ScriptEvent $WELogFilePath " $($WEEventsCol2[$i].TimeGenerated);$($WEEventsCol2[$i].Message);$($WEEventsCol2[$i].Source)"  NDES_Eventvwr 3
            $i++

    }

}

$WEErrorActionPreference = " Continue"







Write-host
Write-host " ......................................................."
Write-host
Write-host " Log Files..." -ForegroundColor Yellow
Write-host 
write-host " Do you want to gather troubleshooting files? This includes IIS, NDES Connector, NDES Plugin, CRP, and MSCEP log files, in addition to the SCEP template configuration.  [Y]es, [N]o:"
$WELogFileCollectionConfirmation = Read-Host

    if ($WELogFileCollectionConfirmation -eq " y" ){

    $WEIISLogPath = (Get-WebConfigurationProperty " /system.applicationHost/sites/siteDefaults" -name logfile.directory).Value + " \W3SVC1" -replace " %SystemDrive%" ,$env:SystemDrive
    $WEIISLogs = Get-ChildItem $WEIISLogPath| Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $WENDESConnectorLogs = Get-ChildItem " C:\Program Files\Microsoft Intune\NDESConnectorSvc\Logs\Logs\NDESConnector*" | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $WENDESPluginLogs = Get-ChildItem " C:\Program Files\Microsoft Intune\NDESPolicyModule\Logs\NDESPlugin.log"
    $WEMSCEPLogs = Get-ChildItem " c:\users\*\mscep.log" | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $WECRPLogs = Get-ChildItem " C:\Program Files\Microsoft Intune\NDESConnectorSvc\Logs\Logs\CertificateRegistrationPoint*" | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3

    foreach ($WEIISLog in $WEIISLogs){

    Copy-Item -Path $WEIISLog.FullName -Destination $WETempDirPath

    }

    foreach ($WENDESConnectorLog in $WENDESConnectorLogs){

    Copy-Item -Path $WENDESConnectorLog.FullName -Destination $WETempDirPath

    }

    foreach ($WENDESPluginLog in $WENDESPluginLogs){

    Copy-Item -Path $WENDESPluginLog.FullName -Destination $WETempDirPath

    }

    foreach ($WEMSCEPLog in $WEMSCEPLogs){

    Copy-Item -Path $WEMSCEPLog.FullName -Destination $WETempDirPath

    }

    foreach ($WECRPLog in $WECRPLogs){

    Copy-Item -Path $WECRPLogs.FullName -Destination $WETempDirPath

    }

    $WESCEPUserCertTemplateOutputFilePath = " $($WETempDirPath)\SCEPUserCertTemplate.txt"
    certutil -v -template $WESCEPUserCertTemplate > $WESCEPUserCertTemplateOutputFilePath

    Log-ScriptEvent $WELogFilePath " Collecting server logs"  NDES_Validation 1

    Add-Type -assembly " system.io.compression.filesystem"
    $WECurrentlocation =  $env:temp
   ;  $date = Get-Date -Format ddMMyyhhmm
    [io.compression.zipfile]::CreateFromDirectory($WETempDirPath, " $($WECurrentlocation)\$($date)-Logs-$($hostname).zip" )

    Write-host
    Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
    write-host " Log files copied to $($WECurrentlocation)\$($date)-Logs-$($hostname).zip"
    Write-host

    }

    else {

    Log-ScriptEvent $WELogFilePath " Do not collect logs"  NDES_Validation 1
   ;  $WEWriteLogOutputPath = $WETrue

    }








Write-host
Write-host " ......................................................."
Write-host
Write-host " End of NDES configuration validation" -ForegroundColor Yellow
Write-Host

    if ($WEWriteLogOutputPath -eq $WETrue) {

        write-host " Log file copied to $($WELogFilePath)"
        Write-Host

    }
write-host " Ending script..." -ForegroundColor Yellow
Write-host 





}

else {

Write-Host
Write-host " ......................................................."
Write-Host
Write-host " Incorrect variables. Please run the script again..." -ForegroundColor Red
Write-Host
Write-WELog " Exiting................................................" " INFO"
Write-Host
exit

}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================