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