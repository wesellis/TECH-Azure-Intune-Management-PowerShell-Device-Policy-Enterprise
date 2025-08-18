<#
.SYNOPSIS
    Validate Ndesurl

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
    We Enhanced Validate Ndesurl

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

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

.SYNOPSIS
Validate-NDESUrl will check that requests from devices enrolled in Microsoft Intune will get through all the network protections (such as a reverse proxy) and make it to the NDES server.

.DESCRIPTION
Since the certificate requests include a payload query string that is longer than what is allowed by default settings in Windows, IIS and some reverse proxy servers, those servers need to be configured to allow long query strings and web requests.
This tool will simulate a SCEP request with a large payload, allowing you to check the IIS logs on the NDES server to ensure that the request is not being blocked anywhere along the way.

.NOTE

.EXAMPLE
Validate-NDESUrl


[CmdletBinding(DefaultParameterSetName=" NormalRun" )]

[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
    [parameter(Mandatory=$true,ParameterSetName=" NormalRun" )]
    [alias(" s" )]
    [ValidateScript({
    if (!($_.contains(" /" ))){

        $WETrue
    
    }

    else {

    Throw " Please use the hostname FQDN and not the HTTPS URL. Example: 'scep-contoso.msappproxy.net'"

    }

    }
)]

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$server,
    
    [parameter(Mandatory=$true,ParameterSetName=" NormalRun" )]
    [alias(" q" )]
    [ValidateRange(1,31)] 
    [INT]$querysize,

    [parameter(ParameterSetName=" Help" )]
    [alias(" h" ," ?" ," /?" )]
    [switch]$help,
    
    [parameter(ParameterSetName=" Help" )]
    [alias(" u" )]
    [switch]$usage
    )



[CmdletBinding()]
function WE-Show-Usage{

    Write-Information Write-WELog " -help                       -h         Displays the help." " INFO"
    Write-WELog " -usage                      -u         Displays this usage information." " INFO"
    Write-WELog " -querysize                  -q         Specify the size of the query string payload to use as a number of kilobytes (i.e. 20 or 25). Maximum value is 31" " INFO"
    Write-WELog " -server                     -s         Specify NDES server public DNS name in the form FQDN. For example ExternalDNSName.Contoso.com" " INFO"
    Write-Information }



[CmdletBinding()]
function WE-Get-NDESURLHelp{

    Write-Information " Validate-NDESUrl will check that requests from devices enrolled in Microsoft Intune will get through all the network protections (such as a reverse proxy) and make it to the NDES server."
    Write-Information Write-Information " Since the certificate requests include a payload query string that is longer than what is allowed by default settings in Windows, IIS and some reverse proxy servers, those servers need to be configured to allow long query strings and web requests."
    Write-Information " This tool will simulate a SCEP request with a large payload, allowing you to check the IIS logs on the NDES server to ensure that the request is not being blocked anywhere along the way."
    Write-Information }



    if($help){

    Get-NDESURLHelp -ErrorAction Stop

    break

    }

    if($usage){

        Show-Usage 

        break
    }







    if ((Get-CimInstance -class Win32_OperatingSystem).ProductType -notlike " 1" ){

        if (Test-Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP) {
    
        Write-Information Write-WELog " Error: This appears to be the NDES server. Please run this script from a different machine. An external (guest) connection is best." " INFO" -BackgroundColor Red
        Write-Information " Exiting......................"
        break

        }
    }







Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Trying base NDES URI... " " INFO"
Write-Information if (resolve-dnsname $server -ErrorAction SilentlyContinue){


    $WENDESUrl = " https://$($server)/certsrv/mscep/mscep.dll"
    $WEBaseURLstatuscode = try {(Invoke-WebRequest -Uri $WENDESUrl).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

        if ($WEBaseURLstatuscode -eq " 200" ){

        Write-Warning " $($WENDESUrl) returns a status code 200 . This usually signifies an error with the Intune Connector registering itself or not being installed."
        Write-Information Write-WELog " This state will _not_ provide a working NDES infrastructure, although validation of long URI support can continue." " INFO"
        Write-Information }


        elseif ($WEBaseURLstatuscode -eq " 403" ){

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-Information " Proceeding with validation!"

        }

        else {
    
        Write-Warning " Unexpected Error code! This usually signifies an error with the Intune Connector registering itself or not being installed."
        Write-Information Write-Information " Expected value is a 403. We received a $($WEBaseURLstatuscode). This state will _not_ provide a working NDES infrastructure, although we can proceed with the validation included in this test"
    
        }

    }

    else {
    
    Write-Information " Error: Cannot resolve $($server)" -BackgroundColor Red
    Write-Information Write-WELog " Please ensure a DNS record is in place and name resolution is successful" " INFO"
    Write-Information Write-WELog " Exiting................................................" " INFO"
    Write-Information exit
    
    }










Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Trying to retrieve CA Capabilities... " " INFO"
Write-Information $WEGetCACaps = " $($WENDESUrl)?operation=GetCACaps&message=NDESLongUrlValidatorStep1of3"
$WECACapsStatuscode = try {(Invoke-WebRequest -Uri $WEGetCACaps).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

    if (-not ($WECACapsStatuscode -eq " 200" )){

    Write-Information " Retrieving the following URL: " -NoNewline
    Write-WELog " $WEGetCACaps" " INFO" -ForegroundColor Cyan
    Write-Information write-host " Error: Server returned a $WECACapsStatuscode error. " -BackgroundColor Red
    Write-Information Write-Information " For a list of IIS error codes, please visit the below link."
    Write-WELog " URL: https://support.microsoft.com/en-gb/help/943891/the-http-status-code-in-iis-7-0--iis-7-5--and-iis-8-0" " INFO"

    }

    else {

    Write-Information " Retrieving the following URL: " -NoNewline
    Write-WELog " $WEGetCACaps" " INFO" -ForegroundColor Cyan
    Write-Information $WECACaps = (Invoke-WebRequest -Uri $WEGetCACaps).content     

        if ($WECACaps) {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-Information " CA CApabilities retrieved:"
        Write-Information Write-Information $WECACaps

        }

        else {

        Write-Information " Error: Server is not returning CA Capabilities." -BackgroundColor Red
        Write-Information Write-Information " PLEASE NOTE: This is not a long URI issue. Please investigate the NDES configuration."
        Write-Information }

}







Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Trying to retrieve CA Certificates... " " INFO"
Write-Information $WEGetCACerts = " $($WENDESUrl)?operation=GetCACerts&message=NDESLongUrlValidatorStep2of3"
$WECACertsStatuscode = try {(Invoke-WebRequest -Uri $WEGetCACerts).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

    if (-not ($WECACertsStatuscode -eq " 200" )){

    Write-Information " Attempting to retrieve certificates from the following URL: " -NoNewline
    Write-WELog " $WEGetCACerts" " INFO" -ForegroundColor Cyan
    Write-Information write-host " Error: Server returned a $WECACertsStatuscode error. " -BackgroundColor Red
    Write-Information Write-Information " For a list of IIS error codes, please visit the below link."
    Write-WELog " URL: https://support.microsoft.com/en-gb/help/943891/the-http-status-code-in-iis-7-0--iis-7-5--and-iis-8-0" " INFO"

    }

    else {

    Write-Information " Attempting to retrieve certificates from the following URI: " -NoNewline
    Write-WELog " $WEGetCACerts" " INFO" -ForegroundColor Cyan
    Write-Information $WECACerts = (Invoke-WebRequest -Uri $WEGetCACerts).content

    if ($WECACerts) {

        Invoke-WebRequest -Uri $WEGetCACerts -ContentType " application/x-x509-ca-ra-cert" -OutFile " $env:temp\$server.p7b"
        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-Information " certificates retrieved. File written to disk: $env:temp\$server.p7b"

    }

    else {

        Write-Information " Error: Server is not returning CA certificates." -BackgroundColor Red
        Write-Information Write-Information " PLEASE NOTE: This is _not_ a long URI issue. Please investigate the NDES configuration."
        Write-Information }

}







Write-Information Write-Information " ......................................................."
Write-Information Write-WELog " Querying URI with simulated SCEP challenge... " " INFO"
Write-host; 
$WEChallengeUrlTemp = " $($WENDESUrl)?operation=PKIOperation&message=<SCEP CHALLENGE STRING>"
Write-Information " Retrieving the following URI: " -NoNewline
Write-WELog " $WEChallengeUrlTemp" " INFO" -ForegroundColor Cyan
Write-Information Write-WELog " Using a query size of $($querysize)KB... " " INFO"
Write-Host; 
$challengeBase = " NDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallenge" ;
$testChallenge = $null

    for ($i=1; $i -le $querySize; $i++){         

        $testChallenge = $testChallenge + $challengeBase + ($i + 1)

    }
; 
$WELongUrl = " $($WENDESUrl)?operation=PKIOperation&message=$($testChallenge)" ; 
$WELongUrlStatusCode = try {(Invoke-WebRequest -Uri $WELongUrl).statuscode} catch {$_.Exception.Response.StatusCode.Value__} 

    if ($WELongUrlStatusCode -eq " 414" ){

        Write-Information " Error: HTTP Error 414. The $($querysize)KB URI is too long. " -BackgroundColor Red
        Write-Information Write-WELog " Please ensure all servers and network devices support long URI's" " INFO"
        Write-Information }

    elseif (-not ($WELongUrlStatusCode -eq " 200" )) {

        Write-Information " Error: HTTP Error $($WELongUrlStatusCode)" -BackgroundColor Red
        Write-Information Write-WELog " Please check your network configuration." " INFO" -ForegroundColor Blue -BackgroundColor white
        Write-Information Write-Information " For a list of IIS error codes, please visit the below link."
        Write-WELog " URL: https://support.microsoft.com/en-gb/help/943891/the-http-status-code-in-iis-7-0--iis-7-5--and-iis-8-0" " INFO"

    }

    else {

        Write-WELog " Success: " " INFO" -ForegroundColor Green -NoNewline
        Write-Information " Server accepts a $($querysize)KB URI."

     }







Write-Information Write-Information " ......................................................."
Write-Information Write-Information " End of NDES URI validation"
Write-Information Write-Information " Ending script..."
Write-Information # Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================