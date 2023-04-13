# Install the AzureAD module if not already installed
Install-Module -Name AzureAD -Force

# Connect to Azure AD
Connect-AzureAD

# Get the SSO settings policy for the domain
$ssoPolicy = Get-AzureADPolicy -Id "AuthenticationPolicy"

# Check if SSO is enabled for the domain
if ($ssoPolicy.AuthenticationType -eq "CloudSSO") {
    Write-Host "Single sign-on is enabled for the domain."
} else {
    Write-Host "Single sign-on is not enabled for the domain."
}
