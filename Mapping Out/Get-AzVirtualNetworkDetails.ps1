# Connect to Azure account
Connect-AzAccount

# Get list of all VNETs in subscription
$vnetList = Get-AzVirtualNetwork -ErrorAction Stop

# Create an array to store VNET details
$vnetDetails = @()

# Loop through each VNET and add details to array
ForEach ($vnet in $vnetList) {
    $subnetNames = $vnet.Subnets | ForEach-Object { $_.Name }
    $subnetNames = $subnetNames -join "; "
    
    $peeringNames = $vnet.VirtualNetworkPeerings | ForEach-Object { $_.Name }
    $peeringNames = $peeringNames -join "; "
    
    $vnetDetails += [PSCustomObject]@{
        Name = $vnet.Name
        ResourceGroupName = $vnet.ResourceGroupName
        AddressPrefixes = ($vnet.AddressSpace.AddressPrefixes -join "; ")
        Subnets = $subnetNames
        PeeringNames = $peeringNames
    }
}

# Export VNET details to CSV file
$vnetDetails | Export-Csv -Path "C:\VNETDetails.csv" -NoTypeInformation
