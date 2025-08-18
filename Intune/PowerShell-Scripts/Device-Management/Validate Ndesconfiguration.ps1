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


[CmdletBinding()]
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
    $WEDomain = (Get-CimInstance -ErrorAction Stop Win32_ComputerSystem).domain
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



[CmdletBinding()]
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



[CmdletBinding()]
function WE-Show-Usage {

    Write-Information Write-WELog " -help                       -h         Displays the help." " INFO"
    Write-WELog " -usage                      -u         Displays this usage information." " INFO"
    Write-WELog " -NDESExternalHostname       -ed        External DNS name for the NDES server (SSL certificate subject will be checked for this. It should be in the SAN of the certificate if" " INFO" 
    Write-Information "                                       clients communicate directly with the NDES server)"
    Write-WELog " -NDESServiceAccount         -sa        Username of the NDES service account. Format is Domain\sAMAccountName, such as Contoso\NDES_SVC." " INFO"
    Write-WELog " -IssuingCAServerFQDN        -ca        Name of the issuing CA to which you'll be connecting the NDES server.  Format is FQDN, such as 'MyIssuingCAServer.contoso.com'." " INFO"
    Write-WELog " -SCEPUserCertTemplate       -t         Name of the SCEP Certificate template. Please note this is _not_ the display name of the template. Value should not contain spaces." " INFO" 
    Write-Information }



[CmdletBinding()]
function WE-Get-NDESHelp -ErrorAction Stop {

    Write-Information Write-WELog " Verifies if the NDES server meets all the required configuration. " " INFO"
    Write-Information Write-WELog " The NDES server role is required as back-end infrastructure for Intune Standalone for delivering VPN and Wi-Fi certificates via the SCEP protocol to mobile devices and desktop clients." " INFO"
    Write-WELog " See https://docs.microsoft.com/en-us/intune/certificates-scep-configure." " INFO"
    Write-Information }



    if ($help){

        Get-NDESHelp -ErrorAction Stop
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





    Write-Information Write-Information " ......................................................."
    Write-Information Write-WELog " NDES Service Account = " " INFO" -NoNewline 
    Write-WELog " $($WENDESServiceAccount)" " INFO" -ForegroundColor Cyan
    Write-Information Write-WELog " Issuing CA Server = " " INFO" -NoNewline
    Write-WELog " $($WEIssuingCAServerFQDN)" " INFO" -ForegroundColor Cyan
    Write-Information Write-WELog " SCEP Certificate Template = " " INFO" -NoNewline
    Write-WELog " $($WESCEPUserCertTemplate)" " INFO" -ForegroundColor Cyan
    Write-Information Write-Information " ......................................................."
    Write-Information Write-WELog " Proceed with variables? [Y]es, [N]o" " INFO"
    
    $confirmation = Read-Host





    if ($confirmation -eq 'y'){
    Write-Information Write-Information " ......................................................."
    Log-ScriptEvent $WELogFilePath " Initializing log file $($WETempDirPath)\Validate-NDESConfig.log"  NDES_Validation 1
    Log-ScriptEvent $WELogFilePath " Proceeding with variables=YES"  NDES_Validation 1
    Log-ScriptEvent $WELogFilePath " NDESServiceAccount=$($WENDESServiceAccount)" NDES_Validation 1
    Log-ScriptEvent $WELogFilePath " IssuingCAServer=$($WEIssuingCAServerFQDN)" NDES_Validation 1
    Log-ScriptEvent $WELogFilePath " SCEPCertificateTemplate=$($WESCEPUserCertTemplate)" NDES_Validation 1





    if (-not (Get-WindowsFeature -ErrorAction Stop ADCS-Device-Enrollment).Installed){
    
    Write-WELog " Error: NDES Not installed" " INFO" -BackgroundColor Red
    Write-Information " Exiting....................."
    Log-ScriptEvent $WELogFilePath " NDES Not installed" NDES_Validation 3
    break

    }

Install-WindowsFeature RSAT-AD-PowerShell | Out-Null

Import-Module ActiveDirectory | Out-Null

    if (-not (Get-WindowsFeature -ErrorAction Stop Web-WebServer).Installed){

        $WEIISNotInstalled = $WETRUE
        Write-Warning " IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"
        Write-Information Log-ScriptEvent $WELogFilePath " IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"  NDES_Validation 2
    
    }

    else {

        Import-Module WebAdministration | Out-Null

    }






    
    Write-Information Write-Information " Checking Windows OS version..."
    Write-Information Log-ScriptEvent $WELogFilePath " Checking OS Version" NDES_Validation 1

$WEOSVersion = (Get-CimInstance -class Win32_OperatingSystem).Version
$WEMinOSVersion = " 6.3"

    if ([version]$WEOSVersion -lt [version]$WEMinOSVersion){
    
        Write-Information " Error: Unsupported OS Version. NDES Requires 2012 R2 and above." -BackgroundColor Red
        Log-ScriptEvent $WELogFilePath " Unsupported OS Version. NDES Requires 2012 R2 and above." NDES_Validation 3
        
        } 
    
    else {
    
        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " OS Version " " INFO" -NoNewline
        Write-Information " $($WEOSVersion)" -NoNewline
        Write-Information " supported."
        Log-ScriptEvent $WELogFilePath " Server is version $($WEOSVersion)" NDES_Validation 1
    
    }




    


Write-Information Write-Information " ......................................................."
Write-Information Write-Information " Checking NDES Service Account properties in Active Directory..."
Write-Information Log-ScriptEvent $WELogFilePath " Checking NDES Service Account properties in Active Directory" NDES_Validation 1

$WEADUser = $WENDESServiceAccount.split(" \" )[1]

$WEADUserProps = (Get-ADUser -ErrorAction Stop $WEADUser -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut)

    if ($WEADUserProps.enabled -ne $WETRUE -OR $WEADUserProps.PasswordExpired -ne $false -OR $WEADUserProps.LockedOut -eq $WETRUE){
        
        Write-WELog " Error: Problem with the AD account. Please see output below to determine the issue" " INFO" -BackgroundColor Red
        Write-Information Log-ScriptEvent $WELogFilePath " Problem with the AD account. Please see output below to determine the issue"  NDES_Validation 3
        
    }
        
    else {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " NDES Service Account seems to be in working order:" " INFO"
        Log-ScriptEvent $WELogFilePath " NDES Service Account seems to be in working order"  NDES_Validation 1
        
    }


  
Get-ADUser -ErrorAction Stop $WEADUser -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut | fl SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut







Write-Information " `n.......................................................`n"
Write-Information " Checking if NDES server is the CA...`n"
Log-ScriptEvent $WELogFilePath " Checking if NDES server is the CA" NDES_Validation 1 

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$WECARoleInstalled = (Get-WindowsFeature -ErrorAction Stop ADCS-Cert-Authority).InstallState -eq " Installed"

    if ($hostname -match $WEIssuingCAServerFQDN){
    
        Write-Information " Error: NDES is running on the CA. This is an unsupported configuration!" -BackgroundColor Red
        Log-ScriptEvent $WELogFilePath " NDES is running on the CA"  NDES_Validation 3
    
    }
    elseif($WECARoleInstalled)
    {
        Write-Information " Error: NDES server has Certification Authority Role installed. This is an unsupported configuration!" -BackgroundColor Red
        Log-ScriptEvent $WELogFilePath " NDES server has Certification Authority Role installed"  NDES_Validation 3
    }
    else {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " NDES server is not running on the CA" " INFO"
        Log-ScriptEvent $WELogFilePath " NDES server is not running on the CA"  NDES_Validation 1 
    
    }







Write-Information Write-Information " ......................................................."
Write-Information Write-Information " Checking NDES Service Account local permissions..."
Write-Information Log-ScriptEvent $WELogFilePath " Checking NDES Service Account local permissions" NDES_Validation 1 

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

    Write-Information Write-WELog " Checking NDES Service account is a member of the IIS_IUSR group..." " INFO"
    Write-Information if ((net localgroup) -match " IIS_IUSRS" ){

        $WEIIS_IUSRMembers = ((net localgroup IIS_IUSRS))

        if ($WEIIS_IUSRMembers -like " *$WENDESServiceAccount*" ){

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-WELog " NDES Service Account is a member of the local IIS_IUSR group" " INFO" -NoNewline
            Log-ScriptEvent $WELogFilePath " NDES Service Account is a member of the local IIS_IUSR group" NDES_Validation 1
    
        }
    
        else {

            Write-WELog " Error: NDES Service Account is not a member of the local IIS_IUSR group" " INFO" -BackgroundColor red
            Log-ScriptEvent $WELogFilePath " NDES Service Account is not a member of the local IIS_IUSR group"  NDES_Validation 3 

            Write-Information Write-Information " Checking Local Security Policy for explicit rights via gpedit..."
            Write-Information $WETempFile = [System.IO.Path]::GetTempFileName()
            & " secedit" " /export" " /cfg" " $WETempFile" | Out-Null
            $WELocalSecPol = Get-Content -ErrorAction Stop $WETempFile
            $WEADUserProps = Get-ADUser -ErrorAction Stop $WEADUser
            $WENDESSVCAccountSID = $WEADUserProps.SID.Value 
            $WELocalSecPolResults = $WELocalSecPol | Select-String $WENDESSVCAccountSID

                if ($WELocalSecPolResults -match " SeInteractiveLogonRight" -AND $WELocalSecPolResults -match " SeBatchLogonRight" -AND $WELocalSecPolResults -match " SeServiceLogonRight" ){
            
                    Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                    Write-WELog " NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly." " INFO"
                    Log-ScriptEvent $WELogFilePath " NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly." NDES_Validation 1
                    Write-Information Write-WELog " Note:" " INFO" -BackgroundColor Red -NoNewline
                    Write-WELog " The Logon Locally is not required in normal runtime." " INFO"
                    Write-Information Write-WELog " Note:" " INFO" -BackgroundColor Red -NoNewline
                    Write-Information \'Consider using the IIS_IUSERS group instead of explicit rights as documented under " Step 1 - Create an NDES service account" .\'
                    Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            
                }
            
                else {

                    Write-WELog " Error: NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly_." " INFO" -BackgroundColor red 
                    Write-Information \'Please review " Step 1 - Create an NDES service account" .\' 
                    Write-Information " https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
                    Log-ScriptEvent $WELogFilePath " NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly_." NDES_Validation 3
            
                }
    
        }

    }

    else {

        Write-WELog " Error: No IIS_IUSRS group exists. Ensure IIS is installed." " INFO" -BackgroundColor red 
        Write-Information \'Please review " Step 3.1 - Configure prerequisites on the NDES server" .\' 
        Write-Information " https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " No IIS_IUSRS group exists. Ensure IIS is installed." NDES_Validation 3
    
    }

    }

   else {

        Write-Warning " No local Administrators group exists, likely due to this being a Domain Controller. It is not recommended to run NDES on a Domain Controller."
        Log-ScriptEvent $WELogFilePath " No local Administrators group exists, likely due to this being a Domain Controller. It is not recommended to run NDES on a Domain Controller." NDES_Validation 2
    
    }







Write-Information Write-Host
Write-Information " ......................................................."
Write-Information Write-Information " Checking Windows Features are installed..."
Write-Information Log-ScriptEvent $WELogFilePath " Checking Windows Features are installed..." NDES_Validation 1

$WEWindowsFeatures = @(" Web-Filtering" ," Web-Net-Ext45" ," NET-Framework-45-Core" ," NET-WCF-HTTP-Activation45" ," Web-Metabase" ," Web-WMI" )

foreach($WEWindowsFeature in $WEWindowsFeatures){

$WEFeature =  Get-WindowsFeature -ErrorAction Stop $WEWindowsFeature
$WEFeatureDisplayName = $WEFeature.displayName

    if($WEFeature.installed){
    
        Write-Information " Success:" -NoNewline
        Write-Information " $WEFeatureDisplayName Feature Installed"
        Log-ScriptEvent $WELogFilePath " $($WEFeatureDisplayName) Feature Installed"  NDES_Validation 1
    
    }

    else {

        Write-WELog " Error: $WEFeatureDisplayName Feature not installed!" " INFO" -BackgroundColor red 
        Write-Information \'Please review " Step 3.1b - Configure prerequisites on the NDES server" .\' 
        Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " $($WEFeatureDisplayName) Feature not installed"  NDES_Validation 3
    
    }

}







$WEErrorActionPreference = " SilentlyContinue"

Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking NDES Install Paramaters..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking NDES Install Paramaters" NDES_Validation 1

$WEInstallParams = @(Get-WinEvent -LogName " Microsoft-Windows-CertificateServices-Deployment/Operational" | Where-Object {$_.id -eq " 105" }|
Where-Object {$_.message -match " Install-AdcsNetworkDeviceEnrollmentService" }| Sort-Object -Property TimeCreated -Descending | Select-Object -First 1)

    if ($WEInstallParams.Message -match '-SigningProviderName " Microsoft Strong Cryptographic Provider" ' -AND ($WEInstallParams.Message -match '-EncryptionProviderName " Microsoft Strong Cryptographic Provider" ')) {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-Information " Correct CSP used in install parameters"
        Write-Information Write-Information $WEInstallParams.Message
        Log-ScriptEvent $WELogFilePath " Correct CSP used in install parameters:"  NDES_Validation 1
        Log-ScriptEvent $WELogFilePath " $($WEInstallParams.Message)"  NDES_Eventvwr 1

    }

    else {

        Write-WELog " Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP." " INFO" -BackgroundColor red
        Write-Information Write-Information $WEInstallParams.Message
        Log-ScriptEvent $WELogFilePath " Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP"  NDES_Validation 3 
        Log-ScriptEvent $WELogFilePath " $($WEInstallParams.Message)"  NDES_Eventvwr 3
    }

$WEErrorActionPreference = " Continue"







Write-Information Write-Information " ......................................................."
Write-Information Write-Information " Checking IIS Application Pool health..."
Write-Information Log-ScriptEvent $WELogFilePath " Checking IIS Application Pool health" NDES_Validation 1

    if (-not ($WEIISNotInstalled -eq $WETRUE)){

        # If SCEP AppPool Exists    
        if (Test-Path 'IIS:\AppPools\SCEP'){

        $WEIISSCEPAppPoolAccount = Get-Item -ErrorAction Stop 'IIS:\AppPools\SCEP' | select -expandproperty processmodel | select -Expand username
            
            if ((Get-WebAppPoolState -ErrorAction Stop " SCEP" ).value -match " Started" ){
            
                $WESCEPAppPoolRunning = $WETRUE
            
            }

        }

        else {

            Write-WELog " Error: SCEP Application Pool missing!" " INFO" -BackgroundColor red 
            Write-Information \'Please review " Step 3.1 - Configure prerequisites on the NDES server" \'. 
            Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
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
        Write-Information \'Please review " Step 4.1 - Configure NDES for use with Intune" .\' 
        Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
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







Write-Information Write-host
Write-Information " ......................................................."
Write-Information Write-WELog " Checking Request Filtering (Default Web Site -> Request Filtering -> Edit Feature Setting) has been configured in IIS..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking Request Filtering" NDES_Validation 1

    if (-not ($WEIISNotInstalled -eq $WETRUE)){

        [xml]$WERequestFiltering = (c:\windows\system32\inetsrv\appcmd.exe list config " default web site" /section:requestfiltering)

        if ($WERequestFiltering.'system.webserver'.security.requestFiltering.requestLimits.maxQueryString -eq " 65534" ){
    
            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-Information " MaxQueryString Set Correctly"
            Log-ScriptEvent $WELogFilePath " MaxQueryString Set Correctly"  NDES_Validation 1    
    
        }
    
        else {

            Write-WELog " MaxQueryString not set correctly!" " INFO" -BackgroundColor red 
            Write-Information \'Please review " Step 4.4 - Configure NDES for use with Intune" .\'
            Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Log-ScriptEvent $WELogFilePath " MaxQueryString not set correctly"  NDES_Validation 3
    
        }

        if ($WERequestFiltering.'system.webserver'.security.requestFiltering.requestLimits.maxUrl -eq " 65534" ){
    
            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-Information " MaxUrl Set Correctly"
            Log-ScriptEvent $WELogFilePath " MaxUrl Set Correctly"  NDES_Validation 1
    
        }

        else {
    
            Write-WELog " maxUrl not set correctly!" " INFO" -BackgroundColor red 
            Write-Information \'Please review " Step 4.4 - Configure NDES for use with Intune" .\'
            Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure'"
            Log-ScriptEvent $WELogFilePath " maxUrl not set correctly"  NDES_Validation 3 

        }

     }

    else {

        Write-WELog " IIS is not installed." " INFO" -BackgroundColor red
        Log-ScriptEvent $WELogFilePath " IIS is not installed"  NDES_Validation 3 

    }







Write-Information Write-Information " ......................................................."
Write-Information Write-Information \'Checking registry " HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters" has been set to allow long URLs...\'
Write-Information Log-ScriptEvent $WELogFilePath " Checking registry (HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters) has been set to allow long URLs" NDES_Validation 1

    if (-not ($WEIISNotInstalled -eq $WETRUE)){

        If ((Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength).MaxfieldLength -notmatch " 65534" ){

            Write-WELog " Error: MaxFieldLength not set to 65534 in the registry!" " INFO" -BackgroundColor red
            Write-Information Write-Information \'Please review " Step 4.3 - Configure NDES for use with Intune" .\'
            Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Log-ScriptEvent $WELogFilePath " MaxFieldLength not set to 65534 in the registry" NDES_Validation 3
        } 

        else {

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-Information " MaxFieldLength set correctly"
            Log-ScriptEvent $WELogFilePath " MaxFieldLength set correctly"  NDES_Validation 1
    
        }
		
        if ((Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes).MaxRequestBytes -notmatch " 65534" ){

            Write-WELog " MaxRequestBytes not set to 65534 in the registry!" " INFO" -BackgroundColor red
            Write-Information Write-Information \'Please review " Step 4.3 - Configure NDES for use with Intune" .\'
            Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure'"
            Log-ScriptEvent $WELogFilePath " MaxRequestBytes not set to 65534 in the registry" NDES_Validation 3 

        }
        
        else {

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-Information " MaxRequestBytes set correctly"
            Log-ScriptEvent $WELogFilePath " MaxRequestBytes set correctly"  NDES_Validation 1
        
        }

    }

    else {

        Write-WELog " IIS is not installed." " INFO" -BackgroundColor red
        Log-ScriptEvent $WELogFilePath " IIS is not installed." NDES_Validation 3

    }







Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking SPN has been set..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking SPN has been set" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname

$spn = setspn.exe -L $WEADUser

    if ($spn -match $hostname){
    
        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-Information " Correct SPN set for the NDES service account:"
        Write-Information Write-Information $spn
        Log-ScriptEvent $WELogFilePath " Correct SPN set for the NDES service account: $($spn)"  NDES_Validation 1
    
    }
    
    else {

        Write-WELog " Error: Missing or Incorrect SPN set for the NDES Service Account!" " INFO" -BackgroundColor red 
        Write-Information \'Please review " Step 3.1c - Configure prerequisites on the NDES server" .\'
        Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " Missing or Incorrect SPN set for the NDES Service Account"  NDES_Validation 3 
    
    }






       
Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking there are no intermediate certs are in the Trusted Root store..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking there are no intermediate certs are in the Trusted Root store" NDES_Validation 1

$WEIntermediateCertCheck = Get-Childitem -ErrorAction Stop cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject}

    if ($WEIntermediateCertCheck){
    
        Write-WELog " Error: Intermediate certificate found in the Trusted Root store. This can cause undesired effects and should be removed." " INFO" -BackgroundColor red 
        Write-WELog " Certificates:" " INFO"
        Write-Information Write-Information $WEIntermediateCertCheck
        Log-ScriptEvent $WELogFilePath " Intermediate certificate found in the Trusted Root store: $($WEIntermediateCertCheck)"  NDES_Validation 3
    
    }
    
    else {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " Trusted Root store does not contain any Intermediate certificates." " INFO"
        Log-ScriptEvent $WELogFilePath " Trusted Root store does not contain any Intermediate certificates."  NDES_Validation 1
    
    }







$WEErrorActionPreference = " Silentlycontinue"

Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking the EnrollmentAgentOffline and CEPEncryption are present..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking the EnrollmentAgentOffline and CEPEncryption are present" NDES_Validation 1

$certs = Get-ChildItem -ErrorAction Stop cert:\LocalMachine\My\

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
        Write-Information \'Please review " Step 3.1 - Configure prerequisites on the NDES server" .\' 
        Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
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
        Write-Information \'Please review " Step 3.1 - Configure prerequisites on the NDES server" .\' 
        Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " CEPEncryption certificate is not present"  NDES_Validation 3
        
    }

$WEErrorActionPreference = " Continue"







Write-Information Write-Information " ......................................................."
Write-Information Write-Information \'Checking registry " HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP" has been set with the SCEP certificate template name...\'
Write-Information Log-ScriptEvent $WELogFilePath " Checking registry (HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP) has been set with the SCEP certificate template name" NDES_Validation 1

    if (-not (Test-Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP)){

        Write-Information " Error: Registry key does not exist. This can occur if the NDES role has been installed but not configured." -BackgroundColor Red
        Write-Information \'Please review " Step 3 - Configure prerequisites on the NDES server" .\'
        Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " MSCEP Registry key does not exist."  NDES_Validation 3 

    }

    else {

    $WESignatureTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name SignatureTemplate).SignatureTemplate
    $WEEncryptionTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name EncryptionTemplate).EncryptionTemplate
    $WEGeneralPurposeTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name GeneralPurposeTemplate).GeneralPurposeTemplate 
    $WEDefaultUsageTemplate = " IPSECIntermediateOffline"

        if ($WESignatureTemplate -match $WEDefaultUsageTemplate -AND $WEEncryptionTemplate -match $WEDefaultUsageTemplate -AND $WEGeneralPurposeTemplate -match $WEDefaultUsageTemplate){
        
            Write-WELog " Error: Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed." " INFO" -BackgroundColor red
            Write-Information \'Please review " Step 3.1 - Configure prerequisites on the NDES server" .\' 
            Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Write-Information Log-ScriptEvent $WELogFilePath " Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed."  NDES_Validation 3
            $WEFurtherReading = $WEFALSE
        
        }

        else {

            Write-WELog " One or more default values have been changed." " INFO"
            Write-Information Write-Information " Checking SignatureTemplate key..."
            Write-Information if ($WESignatureTemplate -match $WESCEPUserCertTemplate){

                Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                Write-Information " SCEP certificate template '$($WESCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template."
                Write-Information Log-ScriptEvent $WELogFilePath " SCEP certificate template $($WESCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key"  NDES_Validation 1

            }

            else {
        
                Write-Warning '" SignatureTemplate key does not match the SCEP certificate template name. Unless your template is explicitly set for the " Signature" purpose, this can safely be ignored." '
                Write-Information write-host " Registry value: " -NoNewline
                Write-Information " $($WESignatureTemplate)"
                Write-Information write-host " SCEP certificate template value: " -NoNewline
                Write-Information " $($WESCEPUserCertTemplate)"
                Write-Information Log-ScriptEvent $WELogFilePath " SignatureTemplate key does not match the SCEP certificate template name.Registry value=$($WESignatureTemplate)|SCEP certificate template value=$($WESCEPUserCertTemplate)"  NDES_Validation 2
        
            }
                
                Write-Information " ......................."
                Write-Information Write-WELog " Checking EncryptionTemplate key..." " INFO"
                Write-Information if ($WEEncryptionTemplate -match $WESCEPUserCertTemplate){
            
                    Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                    Write-Information " SCEP certificate template '$($WESCEPUserCertTemplate)' has been written to the registry under the _EncryptionTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template."
                    Write-Information Log-ScriptEvent $WELogFilePath " SCEP certificate template $($WESCEPUserCertTemplate) has been written to the registry under the _EncryptionTemplate_ key"  NDES_Validation 1

            
                }
            
                else {

                    Write-Warning '" EncryptionTemplate key does not match the SCEP certificate template name. Unless your template is explicitly set for the " Encryption" purpose, this can safely be ignored." '
                    Write-Information write-host " Registry value: " -NoNewline
                    Write-Information " $($WEEncryptionTemplate)"
                    Write-Information write-host " SCEP certificate template value: " -NoNewline
                    Write-Information " $($WESCEPUserCertTemplate)"
                    Write-Information Log-ScriptEvent $WELogFilePath " EncryptionTemplate key does not match the SCEP certificate template name.Registry value=$($WEEncryptionTemplate)|SCEP certificate template value=$($WESCEPUserCertTemplate)"  NDES_Validation 2

            
                }
                
                    Write-Information " ......................."
                    Write-Information Write-WELog " Checking GeneralPurposeTemplate key..." " INFO"
                    Write-Information if ($WEGeneralPurposeTemplate -match $WESCEPUserCertTemplate){
                
                        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
                        Write-Information " SCEP certificate template '$($WESCEPUserCertTemplate)' has been written to the registry under the _GeneralPurposeTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template"
                        Log-ScriptEvent $WELogFilePath " SCEP certificate template $($WESCEPUserCertTemplate) has been written to the registry under the _GeneralPurposeTemplate_ key"  NDES_Validation 1

                    }
                
                    else {

                        Write-Warning '" GeneralPurposeTemplate key does not match the SCEP certificate template name. Unless your template is set for the " Signature and Encryption" (General) purpose, this can safely be ignored." '
                        Write-Information write-host " Registry value: " -NoNewline
                        Write-Information " $($WEGeneralPurposeTemplate)"
                        Write-Information write-host " SCEP certificate template value: " -NoNewline
                        Write-Information " $($WESCEPUserCertTemplate)"
                        Write-Information Log-ScriptEvent $WELogFilePath " GeneralPurposeTemplate key does not match the SCEP certificate template name.Registry value=$($WEGeneralPurposeTemplate)|SCEP certificate template value=$($WESCEPUserCertTemplate)"  NDES_Validation 2

                
                    }

        }

        if ($furtherreading-EQ $true){
        
            Write-Information " ......................."
            Write-Information Write-Information \'For further reading, please review " Step 4.2 - Configure NDES for use with Intune" .\'
            Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"

        }

    }
        
$WEErrorActionPreference = " Continue"







Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking IIS SSL certificate is valid for use..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking IIS SSL certificate is valid for use" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$serverAuthEKU = " 1.3.6.1.5.5.7.3.1" # Server Authentication
$allSSLCerts = Get-ChildItem -ErrorAction Stop Cert:\LocalMachine\My
$WEBoundServerCert = netsh http show sslcert
    
    foreach ($WECert in $allSSLCerts) {       

    $WEServerCertThumb = $cert.Thumbprint

        if ($WEBoundServerCert -match $WEServerCertThumb){

            $WEBoundServerCertThumb = $WEServerCertThumb

        }

    }

$WEServerCertObject = Get-ChildItem -ErrorAction Stop Cert:\LocalMachine\My\$WEBoundServerCertThumb

    if ($WEServerCertObject.Issuer -match $WEServerCertObject.Subject){

        $WESelfSigned = $true

    }

    else {
    
        $WESelfSigned = $false
    
    }

        if ($WEServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU -AND (($WEServerCertObject.Subject -match $hostname) -or ($WEServerCertObject.DnsNameList -match $hostname)) -AND $WEServerCertObject.Issuer -notmatch $WEServerCertObject.Subject){

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-Information " Certificate bound in IIS is valid:"
            Write-Information Write-WELog " Subject: " " INFO" -NoNewline
            Write-Information " $($WEServerCertObject.Subject)"
            Write-Information Write-WELog " Thumbprint: " " INFO" -NoNewline
            Write-WELog " $($WEServerCertObject.Thumbprint)" " INFO" -ForegroundColor Cyan
            Write-Information Write-WELog " Valid Until: " " INFO" -NoNewline
            Write-WELog " $($WEServerCertObject.NotAfter)" " INFO" -ForegroundColor Cyan
            Write-Information Write-WELog " If this NDES server is in your perimeter network, please ensure the external hostname is shown below:" " INFO" -ForegroundColor Blue -BackgroundColor White
            $WEDNSNameList = $WEServerCertObject.DNSNameList.unicode
            Write-Information write-host " Internal and External hostnames: " -NoNewline
            Write-Information " $($WEDNSNameList)"
            Log-ScriptEvent $WELogFilePath " Certificate bound in IIS is valid. Subject:$($WEServerCertObject.Subject)|Thumbprint:$($WEServerCertObject.Thumbprint)|ValidUntil:$($WEServerCertObject.NotAfter)|Internal&ExternalHostnames:$($WEDNSNameList)" NDES_Validation 1

            }
    
        else {

        Write-WELog " Error: The certificate bound in IIS is not valid for use. Reason:" " INFO" -BackgroundColor red 
        Write-Information if ($WEServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU) {
                
                    $WEEKUValid = $true

                }

                else {
                
                    $WEEKUValid = $false

                    Write-Information " Correct EKU: " -NoNewline
                    Write-WELog " $($WEEKUValid)" " INFO" -ForegroundColor Cyan
                    Write-Information }

                if ($WEServerCertObject.Subject -match $hostname) {
                
                    $WESubjectValid = $true

                }

                else {
                
                    $WESubjectValid = $false

                    Write-Information " Correct Subject: " -NoNewline
                    Write-Information " $($WESubjectValid)"
                    Write-Information }

                if ($WESelfSigned -eq $false){
               
                    Out-Null
                
                }

                else {
                
                    Write-Information " Is Self-Signed: " -NoNewline
                    Write-Information " $($WESelfSigned)"
                    Write-Information }

        Write-Information \'Please review " Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server" .\'
        Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " The certificate bound in IIS is not valid for use. CorrectEKU=$($WEEKUValid)|CorrectSubject=$($WESubjectValid)|IsSelfSigned=$($WESelfSigned)"  NDES_Validation 3

}
        






Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking Client certificate (NDES Policy module) is valid for use..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking Client certificate (NDES Policy module) is valid for use" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$clientAuthEku = " 1.3.6.1.5.5.7.3.2" # Client Authentication
$WENDESCertThumbprint = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\Modules\NDESPolicy -Name NDESCertThumbprint).NDESCertThumbprint
$WEClientCertObject = Get-ChildItem -ErrorAction Stop Cert:\LocalMachine\My\$WENDESCertThumbprint

    if ($WEClientCertObject.Issuer -match $WEClientCertObject.Subject){

        $WEClientCertSelfSigned = $true

    }

    else {
    
        $WEClientCertSelfSigned = $false
    
    }

        if ($WEClientCertObject.EnhancedKeyUsageList -match $clientAuthEku -AND $WEClientCertObject.Subject -match $hostname -AND $WEClientCertObject.Issuer -notmatch $WEClientCertObject.Subject){

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-Information " Client certificate bound to NDES Connector is valid:"
            Write-Information Write-WELog " Subject: " " INFO" -NoNewline
            Write-Information " $($WEClientCertObject.Subject)"
            Write-Information Write-WELog " Thumbprint: " " INFO" -NoNewline
            Write-WELog " $($WEClientCertObject.Thumbprint)" " INFO" -ForegroundColor Cyan
            Write-Information Write-WELog " Valid Until: " " INFO" -NoNewline
            Write-WELog " $($WEClientCertObject.NotAfter)" " INFO" -ForegroundColor Cyan
            Log-ScriptEvent $WELogFilePath " Client certificate bound to NDES Connector is valid. Subject:$($WEClientCertObject.Subject)|Thumbprint:$($WEClientCertObject.Thumbprint)|ValidUntil:$($WEClientCertObject.NotAfter)"  NDES_Validation 1

        }
    
        else {

        Write-WELog " Error: The certificate bound to the NDES Connector is not valid for use. Reason:" " INFO" -BackgroundColor red 
        Write-Information if ($WEClientCertObject.EnhancedKeyUsageList -match $clientAuthEku) {
                
                    $WEClientCertEKUValid = $true

                }

                else {
                
                    $WEClientCertEKUValid = $false

                    Write-Information " Correct EKU: " -NoNewline
                    Write-WELog " $($WEClientCertEKUValid)" " INFO" -ForegroundColor Cyan
                    Write-Information }

                if ($WEClientCertObject.Subject -match $hostname) {
                
                    $WEClientCertSubjectValid = $true

                }

                else {
                
                    $WEClientCertSubjectValid = $false

                    Write-Information " Correct Subject: " -NoNewline
                    Write-Information " $($WEClientCertSubjectValid)"
                    Write-Information }

                if ($WEClientCertSelfSigned -eq $false){
               
                    Out-Null
                
                }

                else {
                
                    Write-Information " Is Self-Signed: " -NoNewline
                    Write-Information " $($WEClientCertSelfSigned)"
                    Write-Information }

        Write-Information \'Please review " Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server" .\'
        Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $WELogFilePath " The certificate bound to the NDES Connector is not valid for use. CorrectEKU=$($WEClientCertEKUValid)|CorrectSubject=$($WEClientCertSubjectValid)|IsSelfSigned=$($WEClientCertSelfSigned)"  NDES_Validation 3


}
        






Write-Information Write-Information " ......................................................."
$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
Write-Information Write-WELog " Checking behaviour of internal NDES URL: " " INFO" -NoNewline
Write-WELog " https://$hostname/certsrv/mscep/mscep.dll" " INFO" -ForegroundColor Cyan
Write-Information Log-ScriptEvent $WELogFilePath " Checking behaviour of internal NDES URL" NDES_Validation 1
Log-ScriptEvent $WELogFilePath " Https://$hostname/certsrv/mscep/mscep.dll" NDES_Validation 1

$WEStatuscode = try {(Invoke-WebRequest -Uri https://$hostname/certsrv/mscep/mscep.dll).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

    if ($statuscode -eq " 200" ){

    Write-Information " Error: https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or not being installed." -BackgroundColor Red
    Log-ScriptEvent $WELogFilePath " https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or not being installed"  NDES_Validation 3
    } 

    elseif ($statuscode -eq " 403" ){

    Write-WELog " Trying to retrieve CA Capabilitiess..." " INFO" -ForegroundColor Yellow
    Write-Information $WENewstatuscode = try {(Invoke-WebRequest -Uri " https://$hostname/certsrv/mscep/mscep.dll?operation=GetCACaps&message=test" ).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

        if ($WENewstatuscode -eq " 200" ){

       ;  $WECACaps = (Invoke-WebRequest -Uri " https://$hostname/certsrv/mscep?operation=GetCACaps&message=test" ).content

        }

            if ($WECACaps){

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-Information " CA Capabilities retrieved:"
            Write-Information Write-Information $WECACaps
            Log-ScriptEvent $WELogFilePath " CA Capabilities retrieved:$WECACaps"  NDES_Validation 1
                
            }

    }
                    
    else {
    
        Write-Information " Error: Unexpected Error code! This usually signifies an error with the Intune Connector registering itself or not being installed" -BackgroundColor Red
        Write-Information " Expected value is a 403. We received a $($WEStatuscode). This could be down to a missing reboot post policy module install. Verify last boot time and module install time further down the validation."
        Log-ScriptEvent $WELogFilePath " Unexpected Error code. Expected:403|Received:$WEStatuscode"  NDES_Validation 3
    
   }
        






Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking Servers last boot time..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking Servers last boot time" NDES_Validation 1
; 
$WELastBoot = (Get-CimInstance -ErrorAction Stop win32_operatingsystem | select csname, @{LABEL='LastBootUpTime'
;EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).lastbootuptime

Write-Information " Server last rebooted: " -NoNewline
Write-WELog " $($WELastBoot). " " INFO" -ForegroundColor Cyan -NoNewline
Write-WELog " Please ensure a reboot has taken place _after_ all registry changes and installing the NDES Connector. IISRESET is _not_ sufficient." " INFO"
Log-ScriptEvent $WELogFilePath " LastBootTime:$WELastBoot"  NDES_Validation 1







Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking Intune Connector is installed..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking Intune Connector is installed" NDES_Validation 1 

    if ($WEIntuneConnector = Get-ItemProperty -ErrorAction Stop HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ? {$_.DisplayName -eq " Microsoft Intune Connector" }){

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-WELog " $($WEIntuneConnector.DisplayName) was installed on " " INFO" -NoNewline 
        Write-WELog " $($WEIntuneConnector.InstallDate) " " INFO" -ForegroundColor Cyan -NoNewline 
        Write-Information " and is version " -NoNewline
        Write-WELog " $($WEIntuneConnector.DisplayVersion)" " INFO" -ForegroundColor Cyan -NoNewline
        Write-Information Log-ScriptEvent $WELogFilePath " ConnectorVersion:$WEIntuneConnector"  NDES_Validation 1

    }

    else {

        Write-WELog " Error: Intune Connector not installed" " INFO" -BackgroundColor red 
        Write-Information \'Please review " Step 5 - Enable, install, and configure the Intune certificate connector" .\'
        Write-Information " URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Write-Information Log-ScriptEvent $WELogFilePath " ConnectorNotInstalled"  NDES_Validation 3 
        
    }








Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking Intune Connector registry keys are intact" " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking Intune Connector registry keys are intact" NDES_Validation 1
$WEErrorActionPreference = " SilentlyContinue"

$WEKeyRecoveryAgentCertificate = " HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\KeyRecoveryAgentCertificate"
$WEPfxSigningCertificate = " HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\PfxSigningCertificate"
$WESigningCertificate = " HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\SigningCertificate"

    if (-not ($WEKeyRecoveryAgentCertificate)){

        Write-Information " Error: KeyRecoveryAgentCertificate Registry key does not exist." -BackgroundColor Red
        Write-Information Log-ScriptEvent $WELogFilePath " KeyRecoveryAgentCertificate Registry key does not exist."  NDES_Validation 3 

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

        Write-Information " Error: PfxSigningCertificate Registry key does not exist." -BackgroundColor Red
        Write-Information Log-ScriptEvent $WELogFilePath " PfxSigningCertificate Registry key does not exist."  NDES_Validation 3 


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

        Write-Information " Error: SigningCertificate Registry key does not exist." -BackgroundColor Red
        Write-Information Log-ScriptEvent $WELogFilePath " SigningCertificate Registry key does not exist"  NDES_Validation 3  

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

Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Checking Event logs for pertinent errors..." " INFO"
Write-Information Log-ScriptEvent $WELogFilePath " Checking Event logs for pertinent errors" NDES_Validation 1

    if (-not (Get-EventLog -LogName " Microsoft Intune Connector" -EntryType Error -After $WEEventLogCollDays -ErrorAction SilentlyContinue)) {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-Information " No errors found in the Microsoft Intune Connector"
        Write-Information Log-ScriptEvent $WELogFilePath " No errors found in the Microsoft Intune Connector"  NDES_Validation 1

    }

    else {

        Write-Warning " Errors found in the Microsoft Intune Connector Event log. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Information $WEEventsCol1 = (Get-EventLog -LogName " Microsoft Intune Connector" -EntryType Error -After $WEEventLogCollDays -Newest 5 | select TimeGenerated,Source,Message)
        $WEEventsCol1 | fl
        Log-ScriptEvent $WELogFilePath " Errors found in the Microsoft Intune Connector Event log"  NDES_Eventvwr 3
       ;  $i = 0
       ;  $count = @($WEEventsCol1).count

        foreach ($item in $WEEventsCol1) {

            Log-ScriptEvent $WELogFilePath " $($WEEventsCol1[$i].TimeGenerated);$($WEEventsCol1[$i].Message);$($WEEventsCol1[$i].Source)"  NDES_Eventvwr 3
            $i++

            }
            
        }

            if (-not (Get-EventLog -LogName " Application" -EntryType Error -Source NDESConnector,Microsoft-Windows-NetworkDeviceEnrollmentService -After $WEEventLogCollDays -ErrorAction SilentlyContinue)) {

            Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
            Write-Information " No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector"
            Write-Information Log-ScriptEvent $WELogFilePath " No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector"  NDES_Validation 1

            }

    else {

        Write-Warning " Errors found in the Application Event log for source NetworkDeviceEnrollmentService or NDESConnector. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Information $WEEventsCol2 = (Get-EventLog -LogName " Application" -EntryType Error -Source NDESConnector,Microsoft-Windows-NetworkDeviceEnrollmentService -After $WEEventLogCollDays -Newest 5 | select TimeGenerated,Source,Message)
        $WEEventsCol2 |fl
       ;  $i = 0
       ;  $count = @($WEEventsCol2).count

        foreach ($item in $WEEventsCol2) {

            Log-ScriptEvent $WELogFilePath " $($WEEventsCol2[$i].TimeGenerated);$($WEEventsCol2[$i].Message);$($WEEventsCol2[$i].Source)"  NDES_Eventvwr 3
            $i++

    }

}

$WEErrorActionPreference = " Continue"







Write-Information Write-Information " ......................................................."
Write-Information Write-Information " Log Files..."
Write-Information Write-Information " Do you want to gather troubleshooting files? This includes IIS, NDES Connector, NDES Plugin, CRP, and MSCEP log files, in addition to the SCEP template configuration.  [Y]es, [N]o:"
$WELogFileCollectionConfirmation = Read-Host

    if ($WELogFileCollectionConfirmation -eq " y" ){

    $WEIISLogPath = (Get-WebConfigurationProperty -ErrorAction Stop " /system.applicationHost/sites/siteDefaults" -name logfile.directory).Value + " \W3SVC1" -replace " %SystemDrive%" ,$env:SystemDrive
    $WEIISLogs = Get-ChildItem -ErrorAction Stop $WEIISLogPath| Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $WENDESConnectorLogs = Get-ChildItem -ErrorAction Stop " C:\Program Files\Microsoft Intune\NDESConnectorSvc\Logs\Logs\NDESConnector*" | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $WENDESPluginLogs = Get-ChildItem -ErrorAction Stop " C:\Program Files\Microsoft Intune\NDESPolicyModule\Logs\NDESPlugin.log"
    $WEMSCEPLogs = Get-ChildItem -ErrorAction Stop " c:\users\*\mscep.log" | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $WECRPLogs = Get-ChildItem -ErrorAction Stop " C:\Program Files\Microsoft Intune\NDESConnectorSvc\Logs\Logs\CertificateRegistrationPoint*" | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3

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

    Write-Information Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
    Write-Information " Log files copied to $($WECurrentlocation)\$($date)-Logs-$($hostname).zip"
    Write-Information }

    else {

    Log-ScriptEvent $WELogFilePath " Do not collect logs"  NDES_Validation 1
   ;  $WEWriteLogOutputPath = $WETrue

    }








Write-Information Write-Information " ......................................................."
Write-Information Write-Information " End of NDES configuration validation"
Write-Information if ($WEWriteLogOutputPath -eq $WETrue) {

        Write-Information " Log file copied to $($WELogFilePath)"
        Write-Information }
Write-Information " Ending script..."
Write-Information }

else {

Write-Information Write-Information " ......................................................."
Write-Information Write-Information " Incorrect variables. Please run the script again..."
Write-Information Write-WELog " Exiting................................................" " INFO"
Write-Information exit

}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================