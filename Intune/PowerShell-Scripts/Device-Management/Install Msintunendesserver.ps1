<#
.SYNOPSIS
    Install Msintunendesserver

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
    We Enhanced Install Msintunendesserver

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
    Prepare a Windows server for SCEP certificate distribution using NDES for Microsoft Intune.

.DESCRIPTION
    This script will prepare and configure a Windows server for SCEP certificate distribution using NDES for Microsoft Intune.
    For running this script, permissions to set service principal names are required including local administrator privileges on the server where the script is executed on.

.PARAMETER CertificateAuthorityConfig
    Define the Certificate Authority configuration using the following format: <IssuingCAFQDN>\<CACommonName>.

.PARAMETER NDESTemplateName
    Define the name of the certificate template that will be used by NDES to issue certificates to mobile devices. Don't specify the display name.
    
.PARAMETER NDESExternalFQDN
    Define the external FQDN of the NDES service published through an application proxy, e.g. ndes-tenantname.msappproxy.net.

.PARAMETER RegistrationAuthorityName
    Define the Registration Authority name information used by NDES.

.PARAMETER RegistrationAuthorityCompany
    Define the Registration Authority company information used by NDES.
    
.PARAMETER RegistrationAuthorityDepartment
    Define the Registration Authority department information used by NDES.

.PARAMETER RegistrationAuthorityCity
    Define the Registration Authority city information used by NDES.

.EXAMPLE
    # Install and configure NDES with verbose output:
    .\Install-MSIntuneNDESServer.ps1 -CertificateAuthorityConfig "CA01.domain.com\DOMAIN-CA01-CA" -NDESTemplateName " NDESIntune" -NDESExternalFQDN " ndes-tenantname.msappproxy.net" -RegistrationAuthorityName " Name" -RegistrationAuthorityCompany " CompanyName" -RegistrationAuthorityDepartment " Department" -RegistrationAuthorityCity " City" -Verbose

.NOTES
    FileName:    Install-MSIntuneNDESServer.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2018-06-17
    Updated:     2018-06-17
    
    Version history:
    1.0.0 - (2018-06-17) Script created

[CmdletBinding(SupportsShouldProcess=$true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory=$true, HelpMessage=" Define the Certificate Authority configuration using the following format: <IssuingCAFQDN>\<CACommonName>." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WECertificateAuthorityConfig,    

    [parameter(Mandatory=$true, HelpMessage=" Define the name of the certificate template that will be used by NDES to issue certificates to mobile devices. Don't specify the display name." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WENDESTemplateName,

    [parameter(Mandatory=$true, HelpMessage=" Define the external FQDN of the NDES service published through an application proxy, e.g. ndes-tenantname.msappproxy.net." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WENDESExternalFQDN,

    [parameter(Mandatory=$true, HelpMessage=" Define the Registration Authority name information used by NDES." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WERegistrationAuthorityName,

    [parameter(Mandatory=$true, HelpMessage=" Define the Registration Authority company information used by NDES." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WERegistrationAuthorityCompany,
    
    [parameter(Mandatory=$true, HelpMessage=" Define the Registration Authority department information used by NDES." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WERegistrationAuthorityDepartment,

    [parameter(Mandatory=$true, HelpMessage=" Define the Registration Authority city information used by NDES." )]
    [ValidateNotNullOrEmpty()]
    [string]$WERegistrationAuthorityCity
)
Begin {
    # Ensure that running PowerShell version is 5.1
    #Requires -Version 5.1

    # Init verbose logging for environment gathering process phase
    Write-Verbose -Message " Initiating environment gathering process phase"

    # Add additional variables required for installation and configuration
    Write-Verbose -Message " - Configuring additional variables required for installation and configuration"
    $WEServerFQDN = -join($env:COMPUTERNAME, " ." , $env:USERDNSDOMAIN.ToLower())
    Write-Verbose -Message " - Variable ServerFQDN has been assigned value: $($WEServerFQDN)"
   ;  $WEServerNTAccountName = -join($env:USERDOMAIN.ToUpper(), " \" , $env:COMPUTERNAME, " $" )
    Write-Verbose -Message " - Variable ServerNTAccountName has been assigned value: $($WEServerNTAccountName)"

    # Get Server Authentication certificate for IIS binding
    try {
       ;  $WEServerAuthenticationCertificate = Get-ChildItem -Path " Cert:\LocalMachine\My" -ErrorAction Stop | Where-Object { ($_.Subject -match $WENDESExternalFQDN) -and ($_.Extensions[" 2.5.29.37" ].EnhancedKeyUsages.FriendlyName.Contains(" Server Authentication" )) }
        if ($null -eq $WEServerAuthenticationCertificate) {
            Write-Warning -Message " Unable to locate required Server Authentication certificate matching external NDES FQDN" ; break
        }
        else {
            Write-Verbose -Message " - Successfully located required Server Authentication certificate matching external NDES FQDN"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to locate required Server Authentication certificate matching external NDES FQDN" ; break
    }

    # Get Client Authentication certifcate for Intune Certificate Connector
    try {
        $WEClientAuthenticationCertificate = Get-ChildItem -Path " Cert:\LocalMachine\My" -ErrorAction Stop | Where-Object { ($_.Subject -match $WEServerFQDN) -and ($_.Extensions[" 2.5.29.37" ].EnhancedKeyUsages.FriendlyName.Contains(" Client Authentication" )) }
        if ($null -eq $WEClientAuthenticationCertificate) {
            Write-Warning -Message " Unable to locate required Client Authentication certificate matching internal NDES server FQDN" ; break
        }
        else {
            Write-Verbose -Message " - Successfully located required Client Authentication certificate matching internal NDES server FQDN"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to locate required Client Authentication certificate matching internal NDES server FQDN" ; break
    }

    # Completed verbose logging for environment gathering process phase
    Write-Verbose -Message " Completed environment gathering process phase"
}
Process {
    # Functions
    [CmdletBinding()]
function WE-Test-PSCredential {
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Management.Automation.PSCredential]$WECredential
        )
        Process {
            $WEErrorActionPreference = " Stop"
            try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
                $WEContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $WEPrincipalContext = New-Object -ErrorAction Stop System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $WEContextType, $env:USERDNSDOMAIN.ToLower()
                $WEContextOptions = [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate            
                if (-not($WEPrincipalContext.ValidateCredentials($WECredential.GetNetworkCredential().UserName, $WECredential.GetNetworkCredential().Password)) -eq $true) {
                    return $false
                }
                else {
                    return $true
                }
            }
            catch [System.Exception] {
                if (-not($WEPrincipalContext.ValidateCredentials($WECredential.GetNetworkCredential().UserName, $WECredential.GetNetworkCredential().Password, $WEContextOptions)) -eq $true) {
                    return $false
                } 
                else {
                    return $true
                }
            }
        }
    }

    # Configure main script error action preference
   ;  $WEErrorActionPreference = " Stop"    

    # Initiate main script function
    Write-Verbose -Message " Initiating main script engine to install and configure NDES on server: $($env:COMPUTERNAME)"

    # Init verbose logging for credentials phase
    Write-Verbose -Message " Initiating credentials gathering process phase"

    # Get local administrator credential
    Write-Verbose -Message " - Prompting for credential input for Enterprise Administrator domain credential"
   ;  $WEAdministratorPSCredential = (Get-Credential -Message " Specify a Enterprise Administrator domain credential with the following formatting 'DOMAIN\useraccount'" )
    if (-not(Test-PSCredential -Credential $WEAdministratorPSCredential)) {
        Write-Warning -Message " Unable to validate specified Enterprise Administrator domain credentials" ; break
    }
    else {
        # Validate local administrator privileges
        Write-Verbose -Message " - Given credentials was validated successfully, checking for Enterprise Administrator privileges for current user"
        if (-not([Security.Principal.WindowsIdentity]::GetCurrent().Groups | Select-String -Pattern " S-1-5-32-544" )) {
            Write-Warning -Message " Current user context is not a local administrator on this server" ; break
        }
    }

    # Get service account credential
    Write-Verbose -Message " - Prompting for credential input for NDES service account domain credential"
    $WENDESServiceAccountCredential = (Get-Credential -Message " Specify the NDES service account domain credential with the following formatting 'DOMAIN\useraccount'" )
    if (-not(Test-PSCredential -Credential $WENDESServiceAccountCredential)) {
        Write-Warning -Message " Unable to validate specified NDES service account domain credentials" ; break
    }
    $WENDESServiceAccountName = -join($WENDESServiceAccountCredential.GetNetworkCredential().Domain, " \" ,$WENDESServiceAccountCredential.GetNetworkCredential().UserName)
    $WENDESServiceAccountPassword = $WENDESServiceAccountCredential.GetNetworkCredential().SecurePassword
    Write-Verbose -Message " - Successfully gathered NDES service account credentials"

    # Completed verbose logging for credentials phase
    Write-Verbose -Message " Completed credentials gathering process phase"

    # Init verbose logging for pre-configuration phase
    Write-Verbose -Message " Initiating pre-configuration phase"
    
    # Give computer account read permissions on Client Authentication certificate private key
    try {
        Write-Verbose -Message " - Attempting to give the NDES server computer account permissions on the Client Authentication certificate private key"
        $WEClientAuthenticationKeyContainerName = $WEClientAuthenticationCertificate.PrivateKey.CspKeyContainerInfo.KeyContainerName
        $WEClientAuthenticationKeyFilePath = Join-Path -Path $env:ProgramData -ChildPath " Microsoft\Crypto\RSA\MachineKeys\$($WEClientAuthenticationKeyContainerName)"
        Write-Verbose -Message " - Retrieving existing access rules for private key container"
        $WEClientAuthenticationACL = Get-Acl -Path $WEClientAuthenticationKeyFilePath

        # Check if existing ACL exist matching computer account with read permissions
        $WEServerAccessRule = $WEClientAuthenticationACL.Access | Where-Object { ($_.IdentityReference -like $WEServerNTAccountName) -and ($_.FileSystemRights -match " Read" ) }
        if ($null -eq $WEServerAccessRule) {
            Write-Verbose -Message " - Could not find existing access rule for computer account with read permission on private key, attempting to delegate permissions"
           ;  $WENTAccountUser = New-Object -TypeName System.Security.Principal.NTAccount($WEServerNTAccountName) -ErrorAction Stop
           ;  $WEFileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($WENTAccountUser, " Read" , " None" , " None" , " Allow" ) -ErrorAction Stop
            $WEClientAuthenticationACL.AddAccessRule($WEFileSystemAccessRule)
            Set-Acl -Path $WEClientAuthenticationKeyFilePath -AclObject $WEClientAuthenticationACL -ErrorAction Stop
            Write-Verbose -Message " - Successfully delegated the NDES server computer account permissions on the Client Authentication certificate private key"
        }
        else {
            Write-Verbose -Message " - Found an existing access rule for computer account with read permission on private key, will skip configuration"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to give the NDES server computer account permissions on the Client Authentication certificate private key" ; break
    }

    try {
        # Configure service account SPN for local server
        Write-Verbose -Message " - Attempting to configure service princal names for NDES service account: $($WENDESServiceAccountName)"
        Write-Verbose -Message " - Configuring service principal name HTTP/$($WEServerFQDN) on $($WENDESServiceAccountName)"
        $WEServerFQDNInvocation = Invoke-Expression -Command " cmd.exe /c setspn.exe -s HTTP/$($WEServerFQDN) $($WENDESServiceAccountName)" -ErrorAction Stop
        if ($WEServerFQDNInvocation -match " Updated object" ) {
            Write-Verbose -Message " - Successfully configured service principal name for NDES service account"    
        }
        Write-Verbose -Message " - Configuring service principal name HTTP/$($env:COMPUTERNAME) on $($WENDESServiceAccountName)"
       ;  $WEServerInvocation = Invoke-Expression -Command " cmd.exe /c setspn.exe -s HTTP/$($env:COMPUTERNAME) $($WENDESServiceAccountName)" -ErrorAction Stop
        if ($WEServerInvocation -match " Updated object" ) {
            Write-Verbose -Message " - Successfully configured service principal name for NDES service account"    
        }        
        Write-Verbose -Message " - Successfully configured service principal names for NDES service account"
    }
    catch [System.Exception] {
        Write-Warning -Message " Failed to configure service princal names for NDES service account" ; break
    }

    # Completed verbose logging for pre-configuration phase
    Write-Verbose -Message " Completed pre-configuration phase"

    # Init verbose logging for Windows feature installation phase
    Write-Verbose -Message " Initiating Windows feature installation phase"    

    # Install required Windows features for NDES
    $WENDESWindowsFeatures = @(" ADCS-Device-Enrollment" , " Web-Filtering" , " Web-Asp-Net" , " NET-Framework-Core" , " NET-HTTP-Activation" , " Web-Asp-Net45" , " NET-Framework-45-Core" , " NET-Framework-45-ASPNET" , " NET-WCF-HTTP-Activation45" , " Web-Metabase" , " Web-WMI" , " Web-Mgmt-Console" , " NET-Non-HTTP-Activ" )
    foreach ($WEWindowsFeature in $WENDESWindowsFeatures) {
        Write-Verbose -Message " - Checking installation state for feature: $($WEWindowsFeature)"
        if (((Get-WindowsFeature -Name $WEWindowsFeature -Verbose:$false).InstallState -ne " Installed" )) {
            Write-Verbose -Message " - Attempting to install Windows feature: $($WEWindowsFeature)"
            Add-WindowsFeature -Name $WEWindowsFeature -ErrorAction Stop -Verbose:$false | Out-Null
            Write-Verbose -Message " - Successfully installed Windows feature: $($WEWindowsFeature)"
        }
        else {
            Write-Verbose -Message " - Windows feature is already installed: $($WEWindowsFeature)"
        }
    }

    # Completed verbose logging for Windows feature installation phase
    Write-Verbose -Message " Completed Windows feature installation phase"

    # Init verbose logging for NDES server role installation phase
    Write-Verbose -Message " Initiating NDES server role installation phase"

    # Add NDES service account to the IIS_IUSRS group
    try {
        Write-Verbose -Message " - Checking if NDES service account is a member of the IIS_IUSRS group"
       ;  $WEIISIUSRSMembers = Get-LocalGroupMember -Group " IIS_IUSRS" -Member $WENDESServiceAccountName -ErrorAction SilentlyContinue
        if ($null -eq $WEIISIUSRSMembers) {
            Write-Verbose -Message " - Attempting to add NDES service account to the IIS_IUSRS group"
            Add-LocalGroupMember -Group " IIS_IUSRS" -Member $WENDESServiceAccountName -ErrorAction Stop
            Write-Verbose -Message " - Successfully added NDES service account to the IIS_IUSRS group"
        }
        else {
            Write-Verbose -Message " - NDES service account is already a member of the IIS_IUSRS group"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred when attempting to add NDES service account to the IIS_IUSRS group" ; break
    }    

    # Set NDES install parameters
    $WEInstallNDESParams = @{
        " Credential" = $WEAdministratorPSCredential
        " CAConfig" = $WECertificateAuthorityConfig
        " RAName" = $WERegistrationAuthorityName
        " RACompany" = $WERegistrationAuthorityCompany
        " RADepartment" = $WERegistrationAuthorityDepartment
        " RACity" = $WERegistrationAuthorityCity
        " ServiceAccountName" = $WENDESServiceAccountName
        " ServiceAccountPassword" = $WENDESServiceAccountPassword
    }

    # Install and configure NDES server role
    try {
        Write-Verbose -Message " - Starting NDES server role installation, this could take some time"
        Install-AdcsNetworkDeviceEnrollmentService @InstallNDESParams -Force -ErrorAction Stop -Verbose:$false | Out-Null
        Write-Verbose -Message " - Successfully installed and configured NDES server role"
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred. Error message: $($_.Exception.Message)" ; break
    }

    # Completed verbose logging for NDES server role installation phase
    Write-Verbose -Message " Completed NDES server role installation phase"

    # Init verbose logging for NDES server role post-installation phase
    Write-Verbose -Message " Initiating NDES server role post-installation phase"

    # Configure NDES certificate template in registry
    try {
        Write-Verbose -Message " - Attempting to configure EncryptionTemplate registry name with value: $($WENDESTemplateName)"
        Set-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP" -Name " EncryptionTemplate" -Value $WENDESTemplateName -ErrorAction Stop
        Write-Verbose -Message " - Successfully configured EncryptionTemplate registry name"
        Write-Verbose -Message " - Attempting to configure GeneralPurposeTemplate registry name with value: $($WENDESTemplateName)"
        Set-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP" -Name " GeneralPurposeTemplate" -Value $WENDESTemplateName -ErrorAction Stop
        Write-Verbose -Message " - Successfully configured GeneralPurposeTemplate registry name"
        Write-Verbose -Message " - Attempting to configure SignatureTemplate registry name with value: $($WENDESTemplateName)"
        Set-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP" -Name " SignatureTemplate" -Value $WENDESTemplateName -ErrorAction Stop
        Write-Verbose -Message " - Successfully configured SignatureTemplate registry name"
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while configuring NDES certificate template in registry" ; break
    }    

    # Completed verbose logging for NDES server role installation phase
    Write-Verbose -Message " Completed NDES server role post-installation phase"

    # Init verbose logging for IIS configuration phase
    Write-Verbose -Message " Initiating IIS configuration phase"

    # Import required IIS module
    try {
        Write-Verbose -Message " - Import required IIS module"
        Import-Module -Name " WebAdministration" -ErrorAction Stop -Verbose:$false
        Write-Verbose -Message " - Successfully imported required IIS module"
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while importing the required IIS module" ; break
    }

    # Configure HTTP parameters in registry
    try {
        Write-Verbose -Message " - Attempting to configure HTTP parameters in registry, setting MaxFieldLength to value: 65534"
        Set-ItemProperty -Path " HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name " MaxFieldLength" -Value 65534 -ErrorAction Stop
        Write-Verbose -Message " - Successfully configured HTTP parameter in registry for MaxFieldLength"
        Write-Verbose -Message " - Attempting to configure HTTP parameters in registry, setting MaxRequestBytes to value: 65534"
        Set-ItemProperty -Path " HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name " MaxRequestBytes" -Value 65534 -ErrorAction Stop
        Write-Verbose -Message " - Successfully configured HTTP parameter in registry for MaxRequestBytes"
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while configuring HTTP parameters in registry" ; break
    }    

    # Add new HTTPS binding for Default Web Site
    try {
        Write-Verbose -Message " - Attempting to create new HTTPS binding for Default Web Site"
        $WEHTTPSWebBinding = Get-WebBinding -Name " Default Web Site" -IPAddress " *" -Port 443 -ErrorAction Stop
        if ($null -eq $WEHTTPSWebBinding) {
            New-WebBinding -Name " Default Web Site" -IPAddress " *" -Port 443 -Protocol Https -ErrorAction Stop | Out-Null
            Write-Verbose -Message " - Successfully creating new HTTPS binding for Default Web Site"
            Write-Verbose -Message " - Attempting to set Server Authentication certificate for HTTPS binding"
            $WEServerAuthenticationCertificate | New-Item -Path " IIS:\SslBindings\*!443" -ErrorAction Stop | Out-Null
            Write-Verbose -Message " - Successfully set Server Authentication certificate for HTTPS binding"
        }
        else {
            Write-Verbose -Message " - Existing HTTPS binding found for Default Web Site, attempting to set Server Authentication certificate"
            if (-not(Get-Item -Path " IIS:\SslBindings\*!443" -ErrorAction SilentlyContinue)) {
                $WEServerAuthenticationCertificate | New-Item -Path " IIS:\SslBindings\*!443" -ErrorAction Stop | Out-Null
                Write-Verbose -Message " - Successfully set Server Authentication certificate for HTTPS binding"
            }
            else {
                Write-Verbose -Message " - Existing HTTPS binding already has a certificate selected, removing it"
                Remove-Item -Path " IIS:\SslBindings\*!443" -Force -ErrorAction Stop | Out-Null
                Write-Verbose -Message " - Successfully removed certificate for existing HTTPS binding"
                Write-Verbose -Message " - Attempting to set new Server Authentication certificate for HTTPS binding"
                $WEServerAuthenticationCertificate | New-Item -Path " IIS:\SslBindings\*!443" -ErrorAction Stop | Out-Null
                Write-Verbose -Message " - Successfully set Server Authentication certificate for HTTPS binding"
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to create new or update existing HTTPS binding and set certificate selection for Default Web Site" ; break
    }

    # Configure Default Web Site to require SSL
    try {
        Write-Verbose -Message " - Attempting to set Default Web Site to require SSL"
        Set-WebConfigurationProperty -PSPath " IIS:\" -Filter " /system.webServer/security/access" -Name " sslFlags" -Value " Ssl" -Location " Default Web Site" -ErrorAction Stop
        Write-Verbose -Message " - Successfully set Default Web Site to require SSL"
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to set Default Web Site to require SSL" ; break
    }

    # Set Default Web Site request limits
    try {
        Write-Verbose -Message " - Attempting to set Default Web Site request filtering maximum URL length with value: 65534"
        Set-WebConfiguration -PSPath " IIS:\Sites\Default Web Site" -Filter " /system.webServer/security/requestFiltering/requestLimits/@maxUrl" -Value 65534 -ErrorAction Stop
        Write-Verbose -Message " - Successfully set Default Web Site request filtering maximum URL length"
        Write-Verbose -Message " - Attempting to set Default Web Site request filtering maximum query string with value: 65534"
        Set-WebConfiguration -PSPath " IIS:\Sites\Default Web Site" -Filter " /system.webServer/security/requestFiltering/requestLimits/@maxQueryString" -Value 65534 -ErrorAction Stop
        Write-Verbose -Message " - Successfully set Default Web Site request filtering maximum query string"
        Write-Verbose -Message " - Attempting to set Default Web Site request filtering for double escaping with value: False"
        Set-WebConfiguration -PSPath " IIS:\Sites\Default Web Site" -Filter " /system.webServer/security/requestFiltering/@allowDoubleEscaping" -Value " False" -ErrorAction Stop
        Write-Verbose -Message " - Successfully set Default Web Site request filtering for double escaping"
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to set Default Web Site request filtering configuration" ; break
    }

    # Configure Default Web Site authentication
    try {
        # Enable anonymous authentication
        Write-Verbose -Message " - Attempting to set Default Web Site anonymous authentication to: Enabled"
        Set-WebConfiguration -Location " Default Web Site" -Filter " /system.webServer/security/authentication/anonymousAuthentication/@Enabled" -Value " True" -ErrorAction Stop
        Write-Verbose -Message " - Successfully set Default Web Site anonymous authentication"

        # Disable windows authentication
        Write-Verbose -Message " - Attempting to set Default Web Site Windows authentication to: Disabled"
        Set-WebConfiguration -Location " Default Web Site" -Filter " /system.webServer/security/authentication/windowsAuthentication/@Enabled" -Value " False" -ErrorAction Stop
        Write-Verbose -Message " - Successfully set Default Web Site Windows authentication"
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to set Default Web Site authentication configuration" ; break
    }

    # Disable IE Enhanced Security Configuration for administrators
    try {
        Write-Verbose -Message " - Attempting to disable IE Enhanced Security Configuration for administrators"
        Set-ItemProperty -Path " HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name " IsInstalled" -Value 0 -ErrorAction Stop
        Write-Verbose -Message " - Successfully disabled IE Enhanced Security Configuration for administrators"
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to disable IE Enhanced Security Configuration for administrators" ; break
    }

    # Completed verbose logging for IIS configuration phase
    Write-Verbose -Message " Completed IIS configuration phase"
    Write-Verbose -Message " Successfully installed and configured this server with NDES for Intune Certificate Connector to be installed"
    Write-Verbose -Message " IMPORTANT: Restart the server at this point before installing the Intune Certificate Connector"
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================