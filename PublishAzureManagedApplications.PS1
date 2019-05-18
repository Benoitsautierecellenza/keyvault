#
# Build
#
[String]$ResourceGroupname = "ManagedApplication"
[String]$ApplicationName = "BastionBuild"
[String]$ApplicationDisplayName = "Bastion (Build)"
[string]$ApplicationDescription = "Bastion Build version 1.0"
$rg = Get-Azresourcegroup -Name $ResourceGroupname 
$RebuildTag = @{"ServiceType"= "Bastion"}
$PrincipalID = "80b404f2-4892-480c-abd9-aecc30c975db"
$RoleDefinitionID = (Get-AzRoleDefinition -Name Owner).id
$Authorization = $PrincipalID+ ":" + $RoleDefinitionID
$ApplicationURL = "https://raw.githubusercontent.com/Benoitsautierecellenza/keyvault/master/BuildBastion.zip"
New-AzManagedApplicationDefinition -Name $ApplicationName `
    -ResourceGroupName $ResourceGroupname `
    -DisplayName $ApplicationDisplayName `
    -Description $ApplicationDescription `
    -Location $rg.location `
    -LockLevel ReadOnly `
    -PackageFileUri $ApplicationURL `
    -Authorization $Authorization `
    -Tag @{"ServiceType"= "Bastion"}
#
# Rebuild
#
[String]$ResourceGroupname = "ManagedApplication"
[String]$ApplicationName = "BastionReBuild"
[String]$ApplicationDisplayName = "Bastion (ReBuild)"
[string]$ApplicationDescription = "Bastion ReBuild version 1.0"
$PrincipalID = "80b404f2-4892-480c-abd9-aecc30c975db"
$RoleDefinitionID = (Get-AzRoleDefinition -Name Owner).id
$Authorization = $PrincipalID+ ":" + $RoleDefinitionID
$ApplicationURL = "https://raw.githubusercontent.com/Benoitsautierecellenza/keyvault/master/REBuildBastion.zip"
New-AzManagedApplicationDefinition -Name $ApplicationName `
    -ResourceGroupName $ResourceGroupname `
    -DisplayName $ApplicationDisplayName `
    -Description $ApplicationDescription `
    -Location $rg.location `
    -LockLevel ReadOnly `
    -PackageFileUri $ApplicationURL `
    -Authorization $Authorization `
    -Tag @{"ServiceType"= "Bastion"; "Rebuild" = "BastionBuild,BastionReBuild"}
