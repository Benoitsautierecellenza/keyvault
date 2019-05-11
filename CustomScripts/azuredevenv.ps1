#
# Initialize all new disks (not yet initialized)
#
$disk = Get-Disk | Where-Object {$_.partitionStyle -eq 'RAW'}
If([string]::IsNullOrEmpty($disk)-eq $false)
{
    #
    # Initialize Disks in RAW mode
    #
    Initialize-Disk -InputObject $disk -PartitionStyle MBR
    #
    # Create partitions
    #
    $disk | New-Partition -AssignDriveLetter -UseMaximumSize
    $partitions = get-partition |  Where-Object {$_.disknumber -ge 2}
    #
    # Format all volumes
    #
format-volume -Partition $partitions -FileSystem NTFS
}
#
# Call a Bootstrap WebHook for final configuration
#
$Metadata = curl -H @{'Metadata'='true'} http://169.254.169.254/metadata/instance?api-version=2019-02-01 -UseBasicParsing | select -ExpandProperty Content
$ComputeMetadata = $metadata  | convertfrom-json
$ResourceGroupName = $ComputeMetadata.compute.resourceGroupName
$SubscriptionID =  $ComputeMetadata.compute.subscriptionId
$VMName = $ComputeMetadata.compute.name
$url = "https://s2events.azure-automation.net/webhooks?token=JH24Ta0gZInBmbzl0qNWN9kPzJ4lm3yVggfRoOP6lhM%3d"
$postParams = @{"SubscriptionId"=$SubscriptionID;"ResourceGroupName"=$ResourceGroupName;"VMName"= $VMName}
$params = @{
    ContentType = 'application/json'
    Headers = @{'from' = 'Bastion'}
    Body = ($postParams | convertto-json)
    Method = 'Post'
    URI = $url
}
Invoke-WebRequest @params -UseBasicParsing
#
# Install Chocolatey
#
Set-ExecutionPolicy Bypass -Scope Process -Force
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
#
# Create a list of packages to be processed
#

#$Packages = ("git", "vscode", "DotNet4.5.2" ,"azcopy", "armclient", "git-credential-manager-for-windows", "winscp", "vscode-powershell", "vscode-azurerm-tools", "vscode-markdownlint")
$Packages = ("git", "DotNet4.5.2", "vscode" ,"azcopy", "armclient", "git-credential-manager-for-windows" , "winscp", "vscode-powershell", "vscode-azurerm-tools", "vscode-markdownlint")
#
# Process eack package for installation
#
ForEach ($PackageName in $Packages)
{choco install $PackageName -y}
