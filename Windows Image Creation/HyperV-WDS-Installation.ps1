# Install Hyper-V
Write-Output "Installing Hyper-V..."
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools

# Configure firewall rules
Write-Output "Configuring firewall rules for Hyper-V and WDS..."
Set-NetFirewallRule -Name "Remote Desktop - User Mode (TCP-In)" -Enabled True
Set-NetFirewallRule -Name "Remote Desktop - User Mode (UDP-In)" -Enabled True
Set-NetFirewallRule -Name "Remote Event Log Management (RPC)" -Enabled True
Set-NetFirewallRule -Name "Windows Deployment Services Management (HTTP-In)" -Enabled True
Set-NetFirewallRule -Name "Windows Deployment Services Management (HTTPS-In)" -Enabled True
Set-NetFirewallRule -Name "Windows Deployment Services PXE (UDP-In)" -Enabled True

# Install Windows Deployment Services
Write-Output "Installing Windows Deployment Services..."
Install-WindowsFeature -Name WDS -IncludeManagementTools

# Configure Windows Deployment Services
Write-Output "Configuring Windows Deployment Services..."
Add-WindowsFeature WDS-Deployment
Add-WindowsFeature WDS-TransportServer
Initialize-WDSServer -Force -Verbose

# Restart the computer
Write-Output "Restarting the computer..."
Restart-Computer -Force
