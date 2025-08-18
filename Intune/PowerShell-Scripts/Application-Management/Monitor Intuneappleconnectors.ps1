<#
.SYNOPSIS
    Monitor Intuneappleconnectors

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
    We Enhanced Monitor Intuneappleconnectors

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
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    Monitor all Apple Connectors like Push Notification Certificate, VPP and DEP tokens. 
    This script is written to be used in an Azure Automation runbook to monitor your Intune deployment connectors. 
.DESCRIPTION
    Monitor all Apple Connectors like Push Notification Certificate, VPP and DEP tokens. 

.VARIABLES
All variables must be defines in Azure Automation 
    TenantName 
        Specify the *.onmicrosoft.com name for your tenant. 
    AppID
        Specify the ClientID of the Azure AD App used for unattended authentication to MS Graph API
    AppSecret (encrypted)
        Specify the secret key for authentication to the Azure AD App used for unattended authentication to MS Graph (never write that in side the script it self)
    ApplicationID
        Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.
    Uri
        The Uri for the webhook for the Microsoft Teams channel we are sending the alerts too. 

.EXAMPLE
    # Script runs unnatended from Azure Automation - all parameters should be defined in Automation account 
    Monitor-IntuneAppleConnectors.ps1

.NOTES
    FileName:    Monitor-IntuneAppleConnectors.ps1
    Author:      Jan Ketil Skanke
    Contact:     @JankeSkanke
    Created:     2020-01-04
    Updated:     2020-01-04

    Version history:
    1.0.0 - (2020-01-04) First release

    Required modules:
    " Microsoft.graph.intune"

$WEAppleMDMPushCertNotificationRange = '30'
$WEAppleVPPTokenNotificationRange = '30'
$WEAppleDEPTokenNotificationRange = '30'


$WETenantName = Get-AutomationVariable -Name 'TenantName'
$WEAppID = Get-AutomationVariable -Name " msgraph-clientcred-appid"
$WEAppSecret = Get-AutomationVariable -Name " msgraph-clientcred-appsecret"
$WEUri = Get-AutomationVariable -Name " TeamsChannelUri"
$WENow = Get-Date
Function Send-TeamsAlerts {
    [cmdletbinding()]
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$uri,
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEConnectorName,
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEExpirationStatus,
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAppleId,
        [string]$WEExpDateStr
        )

$body = @"
{
    " @type" : " MessageCard" ,
    " @context" : " https://schema.org/extensions" ,
    " summary" : " Intune Apple Notification" ,
    " themeColor" : " ffff00" ,
    " title" : " $WEExpirationStatus" ,
    " sections" : [
     {
            " activityTitle" : " Warning message" ,
            " activitySubtitle" : " $WENow" ,
            " activityImage" : " https://github.com/JankeSkanke/imagerepo/blob/master/warning.png?raw=true" ,
            " facts" : [
                {
                    " name" : " Connector:" ,
                    " value" : " $WEConnectorName"
                },
                {
                    " name" : " Status:" ,
                    " value" : " $WEExpirationStatus"
                },
                {
                    " name" : " AppleID:" ,
                    " value" : " $WEAppleID"
                },
                {
                    " name" : " Expiry Date:" ,
                    " value" : " $WEExpDateStr"
                }
            ],
            " text" : " Must be renewed by IT Admin before the expiry date."
        }
    ]
}
" @

Invoke-RestMethod -uri $uri -Method Post -body $body -ContentType 'application/json' | Out-Null
Write-Output $WEExpirationStatus
}

import-module " Microsoft.graph.intune"


Update-MSGraphEnvironment -SchemaVersion " beta" -AppId $WEAppId -AuthUrl " https://login.microsoftonline.com/$WETenantName" -Quiet
Connect-MSGraph -ClientSecret $WEAppSecret -Quiet


$WEApplePushCert = Get-IntuneApplePushNotificationCertificate
$WEApplePushCertExpDate = $WEApplePushCert.expirationDateTime
$WEApplePushIdentifier = $WEApplePushCert.appleIdentifier
$WEAPNExpDate = $WEApplePushCertExpDate.ToShortDateString()
    
if ($WEApplePushCertExpDate -lt (Get-Date)) {
    $WEAPNExpirationStatus = " MS Intune: Apple MDM Push certificate has already expired"
    Send-TeamsAlerts -uri $uri -ConnectorName " Apple Push Notification Certificate" -ExpirationStatus $WEAPNExpirationStatus -AppleId $WEApplePushIdentifier -ExpDateStr $WEAPNExpDate 
}
else {
    $WEAppleMDMPushCertDaysLeft = ($WEApplePushCertExpDate - (Get-Date))
    if ($WEAppleMDMPushCertDaysLeft.Days -le $WEAppleMDMPushCertNotificationRange) {
    $WEAPNExpirationStatus = " MSIntune: Apple MDM Push certificate expires in $($WEAppleMDMPushCertDaysLeft.Days) days"
    Send-TeamsAlerts -uri $uri -ConnectorName " Apple Push Notification Certificate" -ExpirationStatus $WEAPNExpirationStatus -AppleId $WEApplePushIdentifier -ExpDateStr $WEAPNExpDate 
    }
    else {
    $WEAPNExpirationStatus = " MSIntune: NOALERT"
    Write-Output " APN Certificate OK"
    }
}
    

$WEAppleVPPToken = Get-DeviceAppManagement_VppTokens
    
if($WEAppleVPPToken.Count -ne '0'){
    foreach ($token in $WEAppleVPPToken){
        $WEAppleVPPExpDate = $token.expirationDateTime
        $WEAppleVPPIdentifier = $token.appleId
        $WEAppleVPPState = $token.state
        $WEVPPExpDateStr = $WEAppleVPPExpDate.ToShortDateString()
        if ($WEAppleVPPState -ne 'valid') {
            $WEVPPExpirationStatus = " MSIntune: Apple VPP Token is not valid, new token required"
            Send-TeamsAlerts -uri $uri -ConnectorName " VPP Token" -ExpirationStatus $WEVPPExpirationStatus -AppleId $WEAppleVPPIdentifier -ExpDateStr $WEVPPExpDateStr
        }
        else {
        $WEAppleVPPTokenDaysLeft = ($WEAppleVPPExpDate - (Get-Date))
            if ($WEAppleVPPTokenDaysLeft.Days -le $WEAppleVPPTokenNotificationRange) {$WEVPPExpirationStatus = " MSIntune: Apple VPP Token expires in $($WEAppleVPPTokenDaysLeft.Days) days"
            Send-TeamsAlerts -uri $uri -ConnectorName " VPP Token" -ExpirationStatus $WEVPPExpirationStatus -AppleId $WEAppleVPPIdentifier -ExpDateStr $WEVPPExpDateStr
            }
            else {$WEVPPExpirationStatus = " MSIntune: NOALERT"
            Write-Output " Apple VPP Token OK"
            }
        }
    }
}


$WEAppleDEPToken = (Invoke-MSGraphRequest -Url 'https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings' -HttpMethod GET).value
if ($WEAppleDeptoken.Count -ne '0'){ 
    foreach ($token in $WEAppleDEPToken){
        $WEAppleDEPExpDate = $token.tokenExpirationDateTime
        $WEAppleDepID = $token.appleIdentifier
        $WEAppleDEPTokenDaysLeft = ($WEAppleDEPExpDate - (Get-Date))
        $WEDEPExpDateStr = $WEAppleDEPExpDate.ToShortDateString()
        if ($WEAppleDEPTokenDaysLeft.Days -le $WEAppleDEPTokenNotificationRange) {
           ;  $WEAppleDEPExpirationStatus = " MSIntune: Apple DEP Token expires in $($WEAppleDEPTokenDaysLeft.Days) days"
            Send-TeamsAlerts -uri $uri -ConnectorName " DEP Token" -ExpirationStatus $WEAppleDEPExpirationStatus -AppleId $WEAppleDEPId -ExpDateStr $WEDEPExpDateStr
        }
        else {
           ;  $WEAppleDEPExpirationStatus = " MSIntune: NOALERT"
            Write-Output " Apple DEP Token OK" 
            }
    }
}




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
