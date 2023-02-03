Write-Host "`n"
Import-Module ActiveDirectory

#Clear any previous data
$accountToUpdate = $newPassword = $confirmNewPassword = $null

#Query AD for a list of all domain computers
#Get-ADObject -LDAPFilter "(objectClass=computer)" -Properties Description | 
#Where-Object { $_.Name -notlike "PCNVS*" -and $_.Name -notlike "DEVVS*" -and $_.Name -notlike "PCNVC*" -and $_.Description -notlike "*Domain Controller*" } | 
#Select-Object -ExpandProperty Name | sort-object name | Set-Variable -Name Computers

#To set computers manually, comment out the previous three lines, uncomment the line below and add comma separated machine names after the '=' character.
$computers = "SELWINSPC13"

#Get username and password to update
$accountToUpdate = Read-Host "Enter Username For Password Update"

Do {
    $newPassword = Read-Host "Enter New Password" -AsSecureString
    If((New-Object PSCredential '.', $newPassword).GetNetworkCredential().Password -eq 'q') { exit }
    $confirmNewPassword = Read-Host "Confirm New Password" -AsSecureString
    If((New-Object PSCredential '.', $confirmNewPassword).GetNetworkCredential().Password -eq 'q') { exit }
    If((New-Object PSCredential '.', $newPassword).GetNetworkCredential().Password -ne `
        (New-Object PSCredential '.', $confirmNewPassword).GetNetworkCredential().Password) {  
        Write-Host "Passwords Entered Do Not Match. Please Try Again or Enter 'q' to quit." 
    }
} While ($newPassword -eq $null -or (New-Object PSCredential '.', $newPassword).GetNetworkCredential().Password `
                                  -ne (New-Object PSCredential '.', $confirmNewPassword).GetNetworkCredential().Password)

#Initialize lists for results and errors output
$results = New-Object System.Collections.Generic.List[System.Object]

Write-Host "`nRunning...Please Wait..."

ForEach($computer in $computers) {  
    Try {
        Test-Connection $computer -Count 2 -ErrorAction Stop > $null
        $adminUser = [ADSI]("WinNT://$computer/$accountToUpdate,user")  
        #$adminUser.psbase.invoke("setpassword",$newPassword)
        $adminUser.SetPassword((New-Object PSCredential '.', $newPassword).GetNetworkCredential().Password)
        $results.Add([PSCustomObject]@{'Hostname'=$computer ; 'Result' = "Password Updated Successfully"})
    }
    Catch { $results.Add([PSCustomObject]@{'Hostname'=$computer ; 'Result' = $_.Exception.Message}) }
}  

$results | Export-CSV ".\LocalUser_$($accountToUpdate)_PasswordUpdateResults-$(Get-Date -Format MMddyyyy_HHmmss).csv" -NoTypeInformation
$results | Format-Table -AutoSize

$newPassword = $confirmNewPassword = $null

# References
# https://stackoverflow.com/questions/38901752/verify-passwords-match-in-windows-powershell
# https://serverfault.com/questions/929362/resetting-local-admin-password-for-a-remote-computer-using-powershell
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring?view=powershell-7.2
# https://stackoverflow.com/questions/28352141/convert-a-secure-string-to-plain-text
