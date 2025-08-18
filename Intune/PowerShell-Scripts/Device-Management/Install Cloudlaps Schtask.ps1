<#
.SYNOPSIS
    Install Cloudlaps Schtask

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
    We Enhanced Install Cloudlaps Schtask

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
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param([Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath)
    if (!(Test-Path $WEPath)) {
        Write-Warning " Required path not found: $WEPath"
        return $false
    }
    return $true
}

$WEScriptBlock = {
Install-CloudLAPSClient


$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$WEScriptBlock = {
    <#
.SYNOPSIS
    Proaction Remediation script for CloudLAPS solution used within Endpoint Analytics with Microsoft Endpoint Manager to rotate a local administrator password.

.DESCRIPTION
    This is the remediation script for a Proactive Remediation in Endpoint Analytics used by the CloudLAPS solution.
    
    It will create a new local administrator account if it doesn't already exist on the device and call an Azure Function API defined in the
    script that will generate a new password, update a Secret in a defined Azure Key Vault and respond back with password to be either set or
    updated on the defined local administrator account.

.NOTES
    FileName:    Remediate.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-09-14
    Updated:     2022-01-27

    Version history:
    1.0.0 - (2020-09-14) Script created
    1.0.1 - (2021-10-07) Updated with output for extended details in MEM portal
    1.0.2 - (2022-01-01) Updated virtual machine array with 'Google Compute Engine'
    1.1.0 - (2022-01-08) Added support for new SendClientEvent function to send client events related to passwor rotation
    1.1.1 - (2022-01-27) Added validation check to test if device is either AAD joined or Hybrid Azure AD joined
    #>

    Process {
        # Functions
        [CmdletBinding()]
Function CreateLog {
            <#
.SYNOPSIS
    Proaction Remediation script for CloudLAPS solution used within Endpoint Analytics with Microsoft Endpoint Manager to rotate a local administrator password.

.DESCRIPTION
    This is the detection script for a Proactive Remediation in Endpoint Analytics used by the CloudLAPS solution.
    
    It will create an event log named CloudLAPS-Client if it doesn't already exist and ensure the remediation script is always triggered.

.EXAMPLE
    .\Detection.ps1

.NOTES
    FileName:    Detection.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-09-14
    Updated:     2020-09-14

    Version history:
    1.0.0 - (2020-09-14) Script created

            Process {
                # Create new event log if it doesn't already exist
                $WEEventLogName = " CloudLAPS-Client"
                $WEEventLogSource = " CloudLAPS-Client"
                $WECloudLAPSEventLog = Get-WinEvent -LogName $WEEventLogName -ErrorAction SilentlyContinue
                if ($null -eq $WECloudLAPSEventLog) {
                    try {
                        New-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -ErrorAction Stop
                    }
                    catch [System.Exception] {
                        Write-Warning -Message " Failed to create new event log. Error message: $($_.Exception.Message)"
                    }
                }
            }
        }

        [CmdletBinding()]
function WE-Test-AzureADDeviceRegistration {
            <#
        .SYNOPSIS
            Determine if the device conforms to the requirement of being either Azure AD joined or Hybrid Azure AD joined.
        
        .DESCRIPTION
            Determine if the device conforms to the requirement of being either Azure AD joined or Hybrid Azure AD joined.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2022-01-27
            Updated:     2022-01-27
        
            Version history:
            1.0.0 - (2022-01-27) Function created
        #>
            Process {
                $WEAzureADJoinInfoRegistryKeyPath = " HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
                if (Test-Path -Path $WEAzureADJoinInfoRegistryKeyPath) {
                    return $true
                }
                else {
                    return $false
                }
            }
        }

        [CmdletBinding()]
function WE-Get-AzureADDeviceID -ErrorAction Stop {
            <#
        .SYNOPSIS
            Get the Azure AD device ID from the local device.
        
        .DESCRIPTION
            Get the Azure AD device ID from the local device.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-05-26
            Updated:     2021-05-26
        
            Version history:
            1.0.0 - (2021-05-26) Function created
        #>
            Process {
                # Define Cloud Domain Join information registry path
                $WEAzureADJoinInfoRegistryKeyPath = " HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

                # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
                $WEAzureADJoinInfoThumbprint = Get-ChildItem -Path $WEAzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty " PSChildName"
                if ($null -ne $WEAzureADJoinInfoThumbprint) {
                    # Retrieve the machine certificate based on thumbprint from registry key
                    $WEAzureADJoinCertificate = Get-ChildItem -Path " Cert:\LocalMachine\My" -Recurse | Where-Object { $WEPSItem.Thumbprint -eq $WEAzureADJoinInfoThumbprint }
                    if ($null -ne $WEAzureADJoinCertificate) {
                        # Determine the device identifier from the subject name
                        $WEAzureADDeviceID = ($WEAzureADJoinCertificate | Select-Object -ExpandProperty " Subject" ) -replace " CN=" , ""
                    
                        # Write event log entry with DeviceId
                        Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Information -EventId 51 -Message " CloudLAPS: Azure AD device identifier: $($WEAzureADDeviceID)"

                        # Handle return value
                        return $WEAzureADDeviceID
                    }
                }
            }
        }

        [CmdletBinding()]
function WE-Get-AzureADRegistrationCertificateThumbprint -ErrorAction Stop {
            <#
        .SYNOPSIS
            Get the thumbprint of the certificate used for Azure AD device registration.
        
        .DESCRIPTION
            Get the thumbprint of the certificate used for Azure AD device registration.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-06-03
            Updated:     2021-06-03
        
            Version history:
            1.0.0 - (2021-06-03) Function created
        #>
            Process {
                # Define Cloud Domain Join information registry path
                $WEAzureADJoinInfoRegistryKeyPath = " HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
    
                # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
                $WEAzureADJoinInfoThumbprint = Get-ChildItem -Path $WEAzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty " PSChildName"
    
                # Handle return value
                return $WEAzureADJoinInfoThumbprint
            }
        }
    
        [CmdletBinding()]
function WE-New-RSACertificateSignature -ErrorAction Stop {
            <#
        .SYNOPSIS
            Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
        
        .DESCRIPTION
            Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
            The certificate used must be available in the LocalMachine\My certificate store, and must also contain a private key.
    
        .PARAMETER Content
            Specify the content string to be signed.
    
        .PARAMETER Thumbprint
            Specify the thumbprint of the certificate.
        
        .NOTES
            Author:      Nickolaj Andersen / Thomas Kurth
            Contact:     @NickolajA
            Created:     2021-06-03
            Updated:     2021-06-03
        
            Version history:
            1.0.0 - (2021-06-03) Function created
    
            Credits to Thomas Kurth for sharing his original C# code.
        #>
            [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
                [parameter(Mandatory = $true, HelpMessage = " Specify the content string to be signed." )]
                [ValidateNotNullOrEmpty()]
                [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEContent,
    
                [parameter(Mandatory = $true, HelpMessage = " Specify the thumbprint of the certificate." )]
                [ValidateNotNullOrEmpty()]
                [string]$WEThumbprint
            )
            Process {
                # Determine the certificate based on thumbprint input
                $WECertificate = Get-ChildItem -Path " Cert:\LocalMachine\My" -Recurse | Where-Object { $WEPSItem.Thumbprint -eq $WECertificateThumbprint }
                if ($null -ne $WECertificate) {
                    if ($WECertificate.HasPrivateKey -eq $true) {
                        # Read the RSA private key
                        $WERSAPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($WECertificate)
                    
                        if ($null -ne $WERSAPrivateKey) {
                            if ($WERSAPrivateKey -is [System.Security.Cryptography.RSACng]) {
                                # Construct a new SHA256Managed object to be used when computing the hash
                                $WESHA256Managed = New-Object -TypeName " System.Security.Cryptography.SHA256Managed"
    
                                # Construct new UTF8 unicode encoding object
                                $WEUnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8
    
                                # Convert content to byte array
                                [byte[]]$WEEncodedContentData = $WEUnicodeEncoding.GetBytes($WEContent)
    
                                # Compute the hash
                                [byte[]]$WEComputedHash = $WESHA256Managed.ComputeHash($WEEncodedContentData)
    
                                # Create signed signature with computed hash
                                [byte[]]$WESignatureSigned = $WERSAPrivateKey.SignHash($WEComputedHash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    
                                # Convert signature to Base64 string
                                $WESignatureString = [System.Convert]::ToBase64String($WESignatureSigned)
                            
                                # Handle return value
                                return $WESignatureString
                            }
                        }
                    }
                }
            }
        }
    
        [CmdletBinding()]
function WE-Get-PublicKeyBytesEncodedString -ErrorAction Stop {
            <#
        .SYNOPSIS
            Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
        
        .DESCRIPTION
            Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
            The certificate used must be available in the LocalMachine\My certificate store.
    
        .PARAMETER Thumbprint
            Specify the thumbprint of the certificate.
        
        .NOTES
            Author:      Nickolaj Andersen / Thomas Kurth
            Contact:     @NickolajA
            Created:     2021-06-07
            Updated:     2021-06-07
        
            Version history:
            1.0.0 - (2021-06-07) Function created
    
            Credits to Thomas Kurth for sharing his original C# code.
        #>
            [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
                [parameter(Mandatory = $true, HelpMessage = " Specify the thumbprint of the certificate." )]
                [ValidateNotNullOrEmpty()]
                [string]$WEThumbprint
            )
            Process {
                # Determine the certificate based on thumbprint input
                $WECertificate = Get-ChildItem -Path " Cert:\LocalMachine\My" -Recurse | Where-Object { $WEPSItem.Thumbprint -eq $WEThumbprint }
                if ($null -ne $WECertificate) {
                    # Get the public key bytes
                    [byte[]]$WEPublicKeyBytes = $WECertificate.GetPublicKey()
    
                    # Handle return value
                    return [System.Convert]::ToBase64String($WEPublicKeyBytes)
                }
            }
        }

        [CmdletBinding()]
function WE-Get-ComputerSystemType -ErrorAction Stop {
            <#
        .SYNOPSIS
            Get the computer system type, either VM or NonVM.
        
        .DESCRIPTION
            Get the computer system type, either VM or NonVM.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-06-07
            Updated:     2022-01-01
        
            Version history:
            1.0.0 - (2021-06-07) Function created
            1.0.1 - (2022-01-01) Updated virtual machine array with 'Google Compute Engine'
        #>
            Process {
                # Check if computer system type is virtual
                $WEComputerSystemModel = Get-CimInstance -Class " Win32_ComputerSystem" | Select-Object -ExpandProperty " Model"
                if ($WEComputerSystemModel -in @(" Virtual Machine" , " VMware Virtual Platform" , " VirtualBox" , " HVM domU" , " KVM" , " VMWare7,1" , " Google Compute Engine" )) {
                    $WEComputerSystemType = " VM"
                }
                else {
                    $WEComputerSystemType = " NonVM"
                }

                # Handle return value
                return $WEComputerSystemType
            }
        }

        # Create Event Log
        CreateLog

        # Define the local administrator user name
        $WELocalAdministratorName = " LocalAdmin"

        # Construct the required URI for the Azure Function URL
        $WESetSecretURI = " <>"
        $WESendClientEventURI = " <>"

        # Control whether client-side events should be sent to Log Analytics workspace
        # Set to $true to enable this feature
        $WESendClientEvent = $true

        # Define event log variables
        $WEEventLogName = " CloudLAPS-Client"
        $WEEventLogSource = " CloudLAPS-Client"

        # Validate that device is either Azure AD joined or Hybrid Azure AD joined
        if (Test-AzureADDeviceRegistration -eq $true) {
            # Intiate logging
            Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Information -EventId 10 -Message " CloudLAPS: Local administrator account password rotation started"

            # Retrieve variables required to build request header
            $WESerialNumber = Get-CimInstance -Class " Win32_BIOS" | Select-Object -ExpandProperty " SerialNumber"
            $WEComputerSystemType = Get-ComputerSystemType -ErrorAction Stop
            $WEAzureADDeviceID = Get-AzureADDeviceID -ErrorAction Stop
            $WECertificateThumbprint = Get-AzureADRegistrationCertificateThumbprint -ErrorAction Stop
            $WESignature = New-RSACertificateSignature -Content $WEAzureADDeviceID -Thumbprint $WECertificateThumbprint
            $WEPublicKeyBytesEncoded = Get-PublicKeyBytesEncodedString -Thumbprint $WECertificateThumbprint

            # Construct SetSecret function request header
            $WESetSecretHeaderTable = [ordered]@{
                DeviceName   = $env:COMPUTERNAME
                DeviceID     = $WEAzureADDeviceID
                SerialNumber = if (-not([string]::IsNullOrEmpty($WESerialNumber))) { $WESerialNumber } else { $env:COMPUTERNAME } # fall back to computer name if serial number is not present
                Type         = $WEComputerSystemType
                Signature    = $WESignature
                Thumbprint   = $WECertificateThumbprint
                PublicKey    = $WEPublicKeyBytesEncoded
                ContentType  = " Local Administrator"
                UserName     = $WELocalAdministratorName
            }

            # Construct SendClientEvent request header
            $WESendClientEventHeaderTable = [ordered]@{
                DeviceName             = $env:COMPUTERNAME
                DeviceID               = $WEAzureADDeviceID
                SerialNumber           = if (-not([string]::IsNullOrEmpty($WESerialNumber))) { $WESerialNumber } else { $env:COMPUTERNAME } # fall back to computer name if serial number is not present
                Signature              = $WESignature
                Thumbprint             = $WECertificateThumbprint
                PublicKey              = $WEPublicKeyBytesEncoded        
                PasswordRotationResult = ""
                DateTimeUtc            = (Get-Date).ToUniversalTime().ToString()
                ClientEventMessage     = ""
            }

            # Initiate exit code variable with default value if not errors are caught
            $WEExitCode = 0

            # Initiate extended output variable
           ;  $WEExtendedOutput = [string]::Empty

            # Use TLS 1.2 connection when calling Azure Function
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            try {
                # Call Azure Function SetSecret to store new secret in Key Vault for current computer and have the randomly generated password returned
                Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Information -EventId 11 -Message " CloudLAPS: Calling Azure Function API for password generation and secret update"
               ;  $WEAPIResponse = Invoke-RestMethod -Method " POST" -Uri $WESetSecretURI -Body ($WESetSecretHeaderTable | ConvertTo-Json) -ContentType " application/json" -ErrorAction Stop

                if ([string]::IsNullOrEmpty($WEAPIResponse)) {
                    Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Error -EventId 13 -Message " CloudLAPS: Retrieved an empty response from Azure Function URL" ; $WEExitCode = 1
                }
                else {
                    # Convert password returned from Azure Function API call to secure string
                    $WESecurePassword = ConvertTo-SecureString -String $WEAPIResponse -AsPlainText -Force

                    # Check if existing local administrator user account exists
                    $WELocalAdministratorAccount = Get-LocalUser -Name $WELocalAdministratorName -ErrorAction SilentlyContinue
                    if ($null -eq $WELocalAdministratorAccount) {
                        # Create local administrator account
                        try {
                            Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Information -EventId 20 -Message " CloudLAPS: Local administrator account does not exist, attempt to create it"
                            New-LocalUser -Name $WELocalAdministratorName -Password $WESecurePassword -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword -ErrorAction Stop

                            try {
                                # Add to local built-in security groups: Administrators (S-1-5-32-544)
                                foreach ($WEGroup in @(" S-1-5-32-544" )) {
                                   ;  $WEGroupName = Get-LocalGroup -SID $WEGroup | Select-Object -ExpandProperty " Name"
                                    Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Information -EventId 22 -Message " CloudLAPS: Adding local administrator account to security group '$($WEGroupName)'"
                                    Add-LocalGroupMember -SID $WEGroup -Member $WELocalAdministratorName -ErrorAction Stop
                                }

                                # Handle output for extended details in MEM portal
                               ;  $WEExtendedOutput = " AdminAccountCreated"
                            }
                            catch [System.Exception] {
                                Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Error -EventId 23 -Message " CloudLAPS: Failed to add '$($WELocalAdministratorName)' user account as a member of local '$($WEGroupName)' group. Error message: $($WEPSItem.Exception.Message)" ; $WEExitCode = 1
                            }
                        }
                        catch [System.Exception] {
                            Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Error -EventId 21 -Message " CloudLAPS: Failed to create new '$($WELocalAdministratorName)' local user account. Error message: $($WEPSItem.Exception.Message)" ; $WEExitCode = 1
                        }
                    }
                    else {
                        # Local administrator account already exists, reset password
                        try {
                            Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Information -EventId 30 -Message " CloudLAPS: Local administrator account exists, updating password"

                            # Determine if changes are being made to the built-in local administrator account, if so don't attempt to set properties for password changes
                            if ($WELocalAdministratorAccount.SID -match " S-1-5-21-.*-500" ) {
                                Set-LocalUser -Name $WELocalAdministratorName -Password $WESecurePassword -PasswordNeverExpires $true -ErrorAction Stop
                            }
                            else {
                                Set-LocalUser -Name $WELocalAdministratorName -Password $WESecurePassword -PasswordNeverExpires $true -UserMayChangePassword $false -ErrorAction Stop
                            }
                        
                            # Handle output for extended details in MEM portal
                           ;  $WEExtendedOutput = " PasswordRotated"
                        }
                        catch [System.Exception] {
                            Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Error -EventId 31 -Message " CloudLAPS: Failed to rotate password for '$($WELocalAdministratorName)' local user account. Error message: $($WEPSItem.Exception.Message)" ; $WEExitCode = 1
                        }
                    }

                    if (($WESendClientEvent -eq $true) -and ($WEError.Count -eq 0)) {
                        # Amend header table with success parameters before sending client event
                        $WESendClientEventHeaderTable[" PasswordRotationResult" ] = " Success"
                        $WESendClientEventHeaderTable[" ClientEventMessage" ] = " Password rotation completed successfully"

                        try {
                            # Call Azure Functions SendClientEvent API to post client event
                           ;  $WEAPIResponse = Invoke-RestMethod -Method " POST" -Uri $WESendClientEventURI -Body ($WESendClientEventHeaderTable | ConvertTo-Json) -ContentType " application/json" -ErrorAction Stop
        
                            Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Information -EventId 50 -Message " CloudLAPS: Successfully sent client event to API. Message: $($WESendClientEventHeaderTable[" ClientEventMessage" ])"
                        }
                        catch [System.Exception] {
                            Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Error -EventId 51 -Message " CloudLAPS: Failed to send client event to API. Error message: $($WEPSItem.Exception.Message)" ; $WEExitCode = 1
                        }
                    }

                    # Final event log entry
                    Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Information -EventId 40 -Message " CloudLAPS: Local administrator account password rotation completed"
                }
            }
            catch [System.Exception] {
                switch ($WEPSItem.Exception.Response.StatusCode) {
                    " Forbidden" {
                        # Handle output for extended details in MEM portal
                        $WEFailureResult = " NotAllowed"
                       ;  $WEFailureMessage = " Password rotation not allowed"
                       ;  $WEExtendedOutput = $WEFailureResult

                        # Write to event log and set exit code
                        Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Warning -EventId 14 -Message " CloudLAPS: Forbidden, password was not allowed to be updated" ; $WEExitCode = 0
                    }
                    " BadRequest" {
                        # Handle output for extended details in MEM portal
                        $WEFailureResult = " BadRequest"
                       ;  $WEFailureMessage = " Password rotation failed with BadRequest"
                       ;  $WEExtendedOutput = $WEFailureResult

                        # Write to event log and set exit code
                        Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Error -EventId 15 -Message " CloudLAPS: BadRequest, failed to update password" ; $WEExitCode = 1
                    }
                    default {
                        # Handle output for extended details in MEM portal
                        $WEFailureResult = " Failed"
                       ;  $WEFailureMessage = " Password rotation failed with unknown reason"
                       ;  $WEExtendedOutput = $WEFailureResult

                        # Write to event log and set exit code
                        Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Error -EventId 12 -Message " CloudLAPS: Call to Azure Function URI failed. Error message: $($WEPSItem.Exception.Message)" ; $WEExitCode = 1
                    }
                }

                if ($WESendClientEvent -eq $true) {
                    # Amend header table with success parameters before sending client event
                    $WESendClientEventHeaderTable[" PasswordRotationResult" ] = $WEFailureResult
                    $WESendClientEventHeaderTable[" ClientEventMessage" ] = $WEFailureMessage

                    try {
                        # Call Azure Functions SendClientEvent API to post client event
                       ;  $WEAPIResponse = Invoke-RestMethod -Method " POST" -Uri $WESendClientEventURI -Body ($WESendClientEventHeaderTable | ConvertTo-Json) -ContentType " application/json" -ErrorAction Stop

                        Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Information -EventId 52 -Message " CloudLAPS: Successfully sent client event to API. Message: $($WEFailureMessage)"
                    }
                    catch [System.Exception] {
                        Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Error -EventId 53 -Message " CloudLAPS: Failed to send client event to API. Error message: $($WEPSItem.Exception.Message)" ; $WEExitCode = 1
                    }
                }        
            }
        }
        else {
            Write-EventLog -LogName $WEEventLogName -Source $WEEventLogSource -EntryType Error -EventId 1 -Message " CloudLAPS: Azure AD device registration failed, device is not Azure AD joined or Hybrid Azure AD joined" ; $WEExitCode = 1

            # Handle output for extended details in MEM portal
            $WEExtendedOutput = " DeviceRegistrationTestFailed"
        }

        # Write output for extended details in MEM portal
        Write-Output -InputObject $WEExtendedOutput

        # Handle exit code
        exit $WEExitCode
    }
}
[CmdletBinding()]
Function Install-CloudLAPSClient {

    <#
.SYNOPSIS
    Script to install Cloud LAPS Client Password Rotation saolution as a Scheduled Task

.DESCRIPTION
    This is the password rotation script, run from a Scheduled Task, used by the CloudLAPS solution.
    
    It takes the Detection and Remediation Script written by Nickolaj Andersen and saves them to a script block. 
    The script block is then saved as a .ps1 on the Client Device. 
    A scheduled task is created that runs daily to rotate the Local Admin Password.
    The destination of the script output should be " C:\ProgramData\CloudLAPS CLient" . " BUILTIN\Users" are denied Read permission on the script.
    
.NOTES
    FileName:    Install-CloudLAPS_SchTask.ps1
    Author:      Ben Whitmore
    Contact:     @byteben
    Credit:      Maurice Daly
    Created:     2020-09-14

    Version history:
    1.0.0 - (2022-03-11) Script created
    1.0.1 - (2022-04-19) Added Universal Language support for enumerating " USERS" when modifying the ACL of the script path. Thanks lucafabbri365


    # Initiate exit code variable with default value if not errors are caught
    $WEExitCode = 0

    $WECloudLAPSClientPath = " C:\ProgramData\CloudLAPS Client"
    $WECloudLAPSClientScript = " CLAPS_Client.ps1"
    $WECloudLAPSClientScriptPath = Join-Path -Path $WECloudLAPSClientPath -ChildPath $WECloudLAPSClientScript
    $WEBuiltinUsersSid = New-Object -ErrorAction Stop System.Security.Principal.SecurityIdentifier -ArgumentList @([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)
            
    #Create Local Path for Client Script
    If (-not(Test-Path -Path $WECloudLAPSClientPath)) {
        Try {
            New-Item -Path $WECloudLAPSClientPath -Type Directory -Force

        }
        Catch {
            Write-Error " Failed to Create Directory. Error message: $($WEPSItem.Exception.Message)"
            $WEExitCode = 1
        }
    }
    #Remove Inheritance from Client Script Folder
    Try {
        $WEACL = Get-ACL -Path $WECloudLAPSClientPath
        $WEACL.SetAccessRuleProtection($WETrue, $WETrue)
        Set-Acl -AclObject $WEACL -Path $WECloudLAPSClientPath
    }
    Catch {
        Write-Error " Failed to Set ACL on Cloud LAPS Client Path . Error message: $($WEPSItem.Exception.Message)"
        $WEExitCode = 1
    }

    #Output Script to Local Path
    $WEScriptBlock | Out-File $WECloudLAPSClientScriptPath -Width 4096

    #Remove Users from ACL
    Try {
        $WEACL2 = Get-ACL -Path $WECloudLAPSClientScriptPath
        $WEACL2.SetAccessRuleProtection($WETrue, $WETrue)
        Set-Acl -AclObject $WEACL2 -Path $WECloudLAPSClientScriptPath
        $WEACL2 = Get-ACL -Path $WECloudLAPSClientScriptPath
        $WEACE_Remove = New-Object -ErrorAction Stop system.security.AccessControl.FileSystemAccessRule($WEBuiltinUsersSid, " Read" , " Allow" )
        $WEACL2.RemoveAccessRuleAll($WEACE_Remove)
        Set-Acl -AclObject $WEACL2 -Path $WECloudLAPSClientScriptPath
    }
    Catch {
        Write-Error " Failed to Set ACL on Cloud LAPS Client Script. Error message: $($WEPSItem.Exception.Message)"
        $WEExitCode = 1
    }

    #Create Scheduled Task to run Client Script
    Try {
        $WETask_Trigger = New-ScheduledTaskTrigger -Daily -At 9AM -RandomDelay (New-TimeSpan -Hours 1)
        $WETask_Principal = New-ScheduledTaskPrincipal -UserID " NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $WETask_Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -StartWhenAvailable
        $WETask_Action = New-ScheduledTaskAction -Execute " C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Argument " -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -file "" $($WECloudLAPSClientScriptPath)"""
       ;  $WENew_Task = New-ScheduledTask -Description " CloudLAPS Rotation" -Action $WETask_Action -Principal $WETask_Principal -Trigger $WETask_Trigger -Settings $WETask_Settings
        Register-ScheduledTask -TaskName " CloudLAPS Rotation" -InputObject $WENew_Task -Force
        Start-ScheduledTask -TaskName " CloudLAPS Rotation"
    }
    Catch {
        Write-Error " Failed to setup Scheduled Task. Error message: $($WEPSItem.Exception.Message)"
       ;  $WEExitCode = 1
    }

    # Handle exit code
    exit $WEExitCode
}

Install-CloudLAPSClient


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================