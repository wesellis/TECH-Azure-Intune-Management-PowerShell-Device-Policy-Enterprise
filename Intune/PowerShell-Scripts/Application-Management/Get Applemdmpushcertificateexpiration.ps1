<#
.SYNOPSIS
    Get Applemdmpushcertificateexpiration

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
    We Enhanced Get Applemdmpushcertificateexpiration

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

function WE-Send-O365MailMessage {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [parameter(Mandatory=$true)]
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WECredential,
        [parameter(Mandatory=$false)]  
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEBody,
        [parameter(Mandatory=$false)]  
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESubject,
        [parameter(Mandatory=$true)]  
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WERecipient,
        [parameter(Mandatory=$true)]  
        [string]$WEFrom
    )
    # Get Azure Automation credential for authentication  
    $WEPSCredential = Get-AutomationPSCredential -Name $WECredential

    # Construct the MailMessage object
    $WEMailMessage = New-Object -TypeName System.Net.Mail.MailMessage  
    $WEMailMessage.From = $WEFrom
    $WEMailMessage.ReplyTo = $WEFrom
    $WEMailMessage.To.Add($WERecipient)
    $WEMailMessage.Body = $WEBody
    $WEMailMessage.BodyEncoding = ([System.Text.Encoding]::UTF8)
    $WEMailMessage.IsBodyHtml = $true
    $WEMailMessage.SubjectEncoding = ([System.Text.Encoding]::UTF8)

    # Attempt to set the subject
    try {
        $WEMailMessage.Subject = $WESubject
    } 
    catch [System.Management.Automation.SetValueInvocationException] {
        Write-Warning -InputObject " An exception occurred while setting the message subject"
    }

    # Construct SMTP Client object
    $WESMTPClient = New-Object -TypeName System.Net.Mail.SmtpClient -ArgumentList @(" smtp.office365.com" , 587)
    $WESMTPClient.Credentials = $WEPSCredential 
    $WESMTPClient.EnableSsl = $true 

    # Send mail message
    $WESMTPClient.Send($WEMailMessage)
}


$WEAzureAutomationCredentialName = " MailUser"
$WEMailRecipient = " recipient@domain.com"
$WEMailFrom = " user@domain.com"


$WEAzureAutomationCredentialName = " MSIntuneAutomationUser"
$WEAzureAutomationVariableAppClientID = " AppClientID"
$WEAzureAutomationVariableTenantName = " TenantName"


$WEAppleMDMPushCertificateNotificationRange = 7

try {
    # Import required modules
    Write-Output -InputObject " Importing required modules"
    Import-Module -Name AzureAD -ErrorAction Stop
    Import-Module -Name PSIntuneAuth -ErrorAction Stop

    try {
        # Read credentials and variables
        Write-Output -InputObject " Reading automation variables"
        $WECredential = Get-AutomationPSCredential -Name $WEAzureAutomationCredentialName -ErrorAction Stop
        $WEAppClientID = Get-AutomationVariable -Name $WEAzureAutomationVariableAppClientID -ErrorAction Stop
        $WETenantName = Get-AutomationVariable -Name $WEAzureAutomationVariableTenantName -ErrorAction Stop

        try {
            # Retrieve authentication token
            Write-Output -InputObject " Attempting to retrieve authentication token"
            $WEAuthToken = Get-MSIntuneAuthToken -TenantName $WETenantName -ClientID $WEAppClientID -Credential $WECredential -ErrorAction Stop
            if ($WEAuthToken -ne $null) {
                Write-Output -InputObject " Successfully retrieved authentication token"

                try {
                    # Get Apple MDM Push certificates
                    $WEAppleMDMPushResource = " https://graph.microsoft.com/v1.0/devicemanagement/applePushNotificationCertificate"
                    $WEAppleMDMPushCertificate = Invoke-RestMethod -Uri $WEAppleMDMPushResource -Method Get -Headers $WEAuthToken -ErrorAction Stop

                    if ($WEAppleMDMPushCertificate -ne $null) {
                        Write-Output -InputObject " Successfully retrieved Apple MDM Push certificate"

                        # Parse the JSON date time string into an DateTime object
                       ;  $WEAppleMDMPushCertificateExpirationDate = [System.DateTime]::Parse($WEAppleMDMPushCertificate.expirationDateTime)
                    
                        # Validate that the MDM Push certificate has not already expired
                        if ($WEAppleMDMPushCertificateExpirationDate -lt (Get-Date)) {
                            Write-Output -InputObject " Apple MDM Push certificate has already expired, sending notification email"
                            Send-O365MailMessage -Credential $WEAzureAutomationCredentialName -Body " ACTION REQUIRED: Apple MDM Push certificate has expired" -Subject " MSIntune: IMPORTANT - Apple MDM Push certificate has expired" -Recipient $WEMailRecipient -From $WEMailFrom
                        }
                        else {
                           ;  $WEAppleMDMPushCertificateDaysLeft = ($WEAppleMDMPushCertificateExpirationDate - (Get-Date))
                            if ($WEAppleMDMPushCertificateDaysLeft.Days -le $WEAppleMDMPushCertificateNotificationRange) {
                                Write-Output -InputObject " Apple MDM Push certificate has not expired, but is within the given expiration notification range"
                                Send-O365MailMessage -Credential $WEAzureAutomationCredentialName -Body " Please take action before the Apple MDM Push certificate expires" -Subject " MSIntune: Apple MDM Push certificate expires in $($WEAppleMDMPushCertificateDaysLeft.Days) days" -Recipient $WEMailRecipient -From $WEMailFrom
                            }
                            else {
                                Write-Output -InputObject " Apple MDM Push certificate has not expired and is outside of the specified expiration notification range"
                            }
                        }
                    }
                    else {
                        Write-Output -InputObject " Query for Apple MDM Push certificates returned empty"
                    }    
                }
                catch [System.Exception] {
                    Write-Warning -Message " An error occurred. Error message: $($_.Exception.Message)"
                }
            }
            else {
                Write-Warning -Message " An error occurred while attempting to retrieve an authentication token"
            }
        }
        catch [System.Exception] {
            Write-Warning -Message " Failed to retrieve authentication token"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " Failed to read automation variables"
    }
}
catch [System.Exception] {
    Write-Warning -Message " Failed to import modules"
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================