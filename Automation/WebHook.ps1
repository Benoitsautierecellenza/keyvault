$postParams = @{SubscriptionId='me';RGName='qwerty'}
$url = "https://s2events.azure-automation.net/webhooks?token=BNCIntNoDawOV4nZhm3fRWN%2fKIsqWYEh%2fjTAfU2ECfc%3d"
Invoke-WebRequest -Uri $url -Method POST -usebasicparsing -Body $postParams