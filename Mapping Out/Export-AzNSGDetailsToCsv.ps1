# Connect to Azure account
Connect-AzAccount

# Get list of all NSGs in subscription
$nsgList = Get-AzNetworkSecurityGroup

# Create an array to store NSG details
$nsgDetails = @()

# Loop through each NSG and add details to array
ForEach ($nsg in $nsgList) {
    $subnetIds = $nsg.Subnets | ForEach-Object { $_.Id }
    $interfaceIds = $nsg.NetworkInterfaces | ForEach-Object { $_.Id }
    $vmIds = $nsg.VirtualMachines | ForEach-Object { $_.Id }
    $ruleNames = $nsg.SecurityRules | ForEach-Object { $_.Name }
    
    $nsgDetails += [PSCustomObject]@{
        Name = $nsg.Name
        ResourceGroupName = $nsg.ResourceGroupName
        Location = $nsg.Location
        AssociatedSubnets = ($subnetIds -join "; ")
        AssociatedNetworkInterfaces = ($interfaceIds -join "; ")
        AssociatedVMs = ($vmIds -join "; ")
        Rules = ($ruleNames -join "; ")
    }
}

# Export NSG details to CSV file
$nsgDetails | Export-Csv -Path "C:\NSGDetails.csv" -NoTypeInformation
