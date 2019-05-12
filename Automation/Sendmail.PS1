#$connectionName = "AzureRunAsConnection"
#try
#{
#    # Get the connection "AzureRunAsConnection "
#    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         
#
#    "Logging in to Azure..."
#    Add-AzureRmAccount `
#        -ServicePrincipal `
#        -TenantId $servicePrincipalConnection.TenantId `
#        -ApplicationId $servicePrincipalConnection.ApplicationId `
#        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
#}
#catch {
#    if (!$servicePrincipalConnection)
#    {
#        $ErrorMessage = "Connection $connectionName not found."
#        throw $ErrorMessage
#    } else{
#        Write-Error -Message $_.Exception
#        throw $_.Exception
#    }
#}
#
# Retriving Azure Automation variables & credentials
#
$vmname = "build"
$owner = 'benoit@simplebydesign.Fr'
$IPaddress = "192.168.0.4"
$vmduration = 168
$autostoppolicy = "8PM"
$autostartpolicy = "8AM"
$RebuildPolicy = "Yes"
$StartWehbookUrl = "https://123"
$StopWebHookUrl = "https://124"
$RebootWebHookUrl = "https://125"

$MailDetail = New-Object -TypeName psobject -Property @{
    mailto = $owner
    vmname = $vmname
    IPaddress = $IPaddress
    vmduration = $vmduration
    autostoppolicy = $autostoppolicy
    autostartpolicy = $autostartpolicy
    RebuildPolicy = $RebuildPolicy
    StartWehbookUrl = $StartWehbookUrl
    StopWebHookUrl = $StopWebHookUrl
    RebootWebHookUrl = $RebootWebHookUrl
}
$ManagedApplicationResourceGroupName = "ManagedApplication"
$ManagedApplicationAutomationInstancename = "ManagedApplication"
$SendgridEmailFrom = (Get-AzAutomationVariable -ResourceGroupName $ManagedApplicationResourceGroupName -AutomationAccountName $ManagedApplicationAutomationInstancename -Name "SendgridEmailFrom").value
$SendGridAutomationSecret = (Get-AzAutomationVariable -ResourceGroupName $ManagedApplicationResourceGroupName -AutomationAccountName $ManagedApplicationAutomationInstancename -Name "SendGridAutomationSecret").value
$SMTPServer = (Get-AzAutomationVariable -ResourceGroupName $ManagedApplicationResourceGroupName -AutomationAccountName $ManagedApplicationAutomationInstancename -Name "SendGridSMTPServer").value
$Password = ConvertTo-SecureString $SendGridAutomationSecret -AsPlainText -Force 
$credential = New-Object System.Management.Automation.PSCredential "apikey", $Password 
$Subject = "[Bastion] - Mise à disposition machine virtuelle %vmname" 
$body = "Bonjour,`n`nVotre machine virtuelle Bastion %vmname est maintenant opérationnelle.`nCelle-ci est joignable à l'adresse IP %ipaddress`nConformément à la politique de sécurité, vous disposez des prérogatives suivantes :`n"
$body += "-La durée de vie de la machine virtuelle est limitée à %vmduration heures.`n"
$body += "-La machine virtuelle est associée à la politique d'arrêt automatique %autostoppolicy.`n"
$body += "-La machine virtuelle est associée à la politique de démarrage %autostartpolicy.`n"
$body += "-La politique de rebuild automatique est : %rebuildpolicy.`n"

$subject = $subject.Replace("%vmname",$MailDetail.vmname)
$body = $body.Replace("%vmname",$MailDetail.vmname)
$body = $body.Replace("%vmduration",$MailDetail.vmduration)
$body = $body.Replace("%ipaddress",$MailDetail.IPaddress)
$body = $body.Replace("%autostoppolicy",$MailDetail.autostoppolicy)
$body = $body.Replace("%autostartpolicy",$MailDetail.autostartpolicy)
$body = $body.Replace("%rebuildpolicy",$MailDetail.rebuiltpolicy)
If([string]::IsNullOrEmpty($MailDetail.StartWehbookUrl) -eq $False) 
{
    $body += "-Vous disposez de l'URL webHook suivante pour assurer le démarrage de votre machine virtuelle : $($MailDetail.StartWehbookUrl).`n"
}
If([string]::IsNullOrEmpty($MailDetail.StopWebHookUrl) -eq $False) 
{
    $body += "-Vous disposez de l'URL webHook suivante pour assurer l'arrêt de votre machine virtuelle : $($MailDetail.StopWebHookUrl).`n"
}
If([string]::IsNullOrEmpty($MailDetail.RebootWebHookUrl) -eq $False) 
{
    $body += "-Vous disposez de l'URL webHook suivante pour assurer le redémarrage de votre machine virtuelle : $($MailDetail.RebootWebHookUrl).`n"
}
$body += "`n"
$body += "Bastion as a Service"

Send-MailMessage -smtpServer $SMTPServer -Credential $credential -Usessl -Port 587 -from $SendgridEmailFrom -to $SendgridEmailFrom -subject $Subject -Body $body -BodyAsHtml 

