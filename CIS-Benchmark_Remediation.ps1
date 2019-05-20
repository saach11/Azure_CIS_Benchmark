Connect-MsolService
Login-AzureRmAccount
$msol_users_guest = Get-MsolUser | where {$_.usertype -eq "Guest"}
$msol_users_all = Get-MsolUser
$all_roles = Get-AzureRmRoleDefinition
$all_storage_accounts = Get-AzureRmStorageAccount
az login


#Delete Guest Endava Users
foreach ($user in $msol_users_guest)
    {
        if ($user.SignInName -match "@endava.com")
            {
                Write-Host "Removing " $user.SignInName -ForegroundColor Green
                Remove-MsolUser -UserPrincipalName $user.userprincipalname -Force
            }
    }

#Enforce MFA for all users
$all_ms_users_not_mfa = Get-MsolUser | where {$_.StrongAuthenticationRequirements.count -eq 0}

### MFA from web
#$UserCredential = Get-Credential
#Import-Module MSOnline
#Connect-MsolService –Credential $UserCredential

$auth = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$auth.RelyingParty = "*"
$auth.State = "Enabled"
$auth.RememberDevicesNotIssuedBefore = (Get-Date)

Set-MsolUser -UserPrincipalName cristina.paraschiv@justbe.co.uk -StrongAuthenticationRequirements $auth

Get-MsolUser –All | Foreach{ Set-MsolUser -UserPrincipalName $_.UserPrincipalName -StrongAuthenticationRequirements $auth}

### MFA from web
