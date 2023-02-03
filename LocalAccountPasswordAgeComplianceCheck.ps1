#Import Active Directory Module. (Requires prior installation. See here: https://www.varonis.com/blog/powershell-active-directory-module)
Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue

function Test-Credential { 
    <#
    .SYNOPSIS
        Takes a PSCredential object and validates it

    .DESCRIPTION
        Takes a PSCredential object and validates it against a domain or local machine

        Borrows from a variety of sources online, don't recall which - apologies!

    .PARAMETER Credential
        A PScredential object with the username/password you wish to test. Typically this is generated using the Get-Credential cmdlet. Accepts pipeline input.

    .PARAMETER Context
        An optional parameter specifying what type of credential this is. Possible values are 'Domain','Machine',and 'ApplicationDirectory.' The default is 'Domain.'

    .PARAMETER ComputerName
        If Context is machine, test local credential against this computer.

    .PARAMETER Domain
        If context is domain (default), test local credential against this domain. Default is current user's

    .OUTPUTS
        A boolean, indicating whether the credentials were successfully validated.

    .EXAMPLE
        #I provide my AD account credentials
        $cred = get-credential

        #Test credential for an active directory account
        Test-Credential $cred

    .EXAMPLE
        #I provide local credentials here
        $cred = get-credential

        #Test credential for a local account
        Test-Credential -ComputerName SomeComputer -Credential $cred

    .EXAMPLE
        #I provide my AD account credentials for domain2
        $cred = get-credential

        #Test credential for an active directory account
        Test-Credential -Credential $cred -Domain domain2.com

    .FUNCTIONALITY
        Active Directory

    #>
    [cmdletbinding(DefaultParameterSetName = 'Domain')]
    param(
        [parameter(ValueFromPipeline=$true)]
        [System.Management.Automation.PSCredential]$Credential = $( Get-Credential -Message "Please provide credentials to test" ),

        [validateset('Domain','Machine', 'ApplicationDirectory')]
        [string]$Context = 'Domain',
        
        [parameter(ParameterSetName = 'Machine')]
        [string]$ComputerName,

        [parameter(ParameterSetName = 'Domain')]
        [string]$Domain = $null
    )
    Begin
    {
        Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`nPSBoundParameters: $($PSBoundParameters | Out-String)"
        Try
        {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        }
        Catch
        {
            Throw "Could not load assembly: $_"
        }
        
        #create principal context with appropriate context from param. If either comp or domain is null, thread's user's domain or local machine are used
        if ($Context -eq 'ApplicationDirectory' )
        {
            #Name=$null works for machine/domain, not applicationdirectory
            $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$Context)
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Domain')
        {
            $Context = $PSCmdlet.ParameterSetName
            $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$Context, $Domain)
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Machine')
        {
            $Context = $PSCmdlet.ParameterSetName
            $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$Context, $ComputerName)
        }

    }
    Process
    {
        #Validate provided credential
        $DS.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().password)
    }
    End
    {
        $DS.Dispose()
    }
}

#Clear/Reset all variables
$compsInput = $compsFilePath = $readFileOrManualEntryOrAllNodes = $outputMode = 
$defaultOutFileName = $userPassedOutputFileName = $localhostErrors = $currentDomain = $defaultCredential = $null
$inputCancelled = $localMachineOnly = $false

#Initialize object for list of comps
$comps = New-Object System.Collections.Generic.List[System.Object]

#Initialize object for list of results and errors
$results = New-Object System.Collections.Generic.List[System.Object]
$errors = New-Object System.Collections.Generic.List[System.Object]

write-output "`n"
write-output "`t`t  *$*$*  Local Account Password Age Checker *$*$*`n"

do {
    $readFileOrManualEntryOrAllNodes = read-host -prompt "Node Selection: Read Input From File (1) or Manual Entry (2) or All Nodes (3) [Default = Localhost Only ; q = Quit]"
    If ($readFileOrManualEntryOrAllNodes -eq 'Q') { Exit }
    If (!$readFileOrManualEntryOrAllNodes) { 
        $localMachineOnly = $true
        $comps.Add($ENV:Computername)
    }
} 
while ($readFileOrManualEntryOrAllNodes -ne 1 -and $readFileOrManualEntryOrAllNodes -ne 2 -and 
       $readFileOrManualEntryOrAllNodes -ne 3 -and $localMachineOnly -eq $false)

##If inputting nodes as a text file...
If ($readFileOrManualEntryOrAllNodes -eq 1) {
    do {
        $compsFilePath = read-host -prompt "Hostname Input File"
        If ($compsFilePath -eq 'Q') { Exit }
        if (![string]::IsNullOrEmpty($compsFilePath) -and $compsFilePath -ne "Q") { 
            $fileNotFound = $(!$(test-path $compsFilePath -PathType Leaf))
            if ($fileNotFound) { write-output "`n`tFile '$compsFilePath' Not Found or Path Specified is a Directory!`n" }
        }
        if($fileNotFound) {
            write-output "`n** Remember To Enter Fully Qualified Filenames If Files Are Not In Current Directory **" 
            write-output "`n`tFile must contain one hostname per line.`n"
        }
    }
    while (([string]::IsNullOrEmpty($compsFilePath) -or $fileNotFound) -and 
            $compsFilePath -ne "B" -and $compsFilePath -ne "Q")
    $comps = Get-Content $compsFilePath -ErrorAction Stop
}

##Else if inputting nodes manually...
Elseif ($readFileOrManualEntryOrAllNodes -eq 2) {
    $compCount = 0
    write-output "`n`nEnter 'f' once finished. Minimum 1 entry. (Enter 'q' to exit.)`n"
    do {
        $compsInput = read-host -prompt "Hostname ($($compCount + 1))"
        If ($compsInput -eq 'Q') { Exit }
        if ($compsInput -ne "F" -and ![string]::IsNullOrEmpty($compsInput)) {
            if ($compsInput -eq 'localhost') { $compsInput = $ENV:Computername }
            $comps.Add($compsInput)
            $compCount++
            }
    }
    while (($compsInput -ne "F") -or ($compCount -lt 1))
}
##Else if all domain nodes, query for objectClass=computer and filter out domain controllers (as there are no local accounts on domain controllers).
Elseif ($readFileOrManualEntryOrAllNodes -eq 3) {
    Get-ADObject -LDAPFilter "(objectClass=computer)" | Where-Object { $_.DistinguishedName -notlike "*Domain Controllers*" } | 
    Select-Object Name | sort-object name | Set-Variable -Name compsTemp
    $compsTemp | ForEach-Object { $comps.Add($_.Name) }
}

#Determine if updates are only requested for the local machine...
If ($comps.Count -eq 1 -and $comps[0] -eq $ENV:Computername) { $localMachineOnly = $true }

#Determine Output Mode
do { 
    $outputMode = read-host -prompt "`nSave To File (1), Console Output (2), or Both (3) [Default=2]"
    if (!$outputMode) { $outputMode = 2 }
}
while ($outputMode -ne 1 -and $outputMode -ne 2 -and $outputMode -ne 3 -and
        $outputMode -ne "Q" -and $outputMode -ne "B")
if ($outputMode -eq "Q") { exit }

#If output is to include a file...
$defaultOutFileName = "LocalUserAccountsOutput-$(Get-Date -Format MMddyyyy_HHmmss).csv"

if ($outputMode -eq 1 -or $outputMode -eq 3) {
                
    Write-Output "`n* To save to any directory other than the current, enter fully qualified path name. *"
    Write-Output   "*              Leave this entry blank to use the default file name of               *"
    Write-Output   "*                  '$defaultOutFileName',                   *"
    Write-Output   "*                which will save to the current working directory.                  *"
    Write-Output   "*                                                                                   *"
    Write-Output   "*  THE '.csv' EXTENSION WILL BE APPENDED AUTOMATICALLY TO THE FILENAME SPECIFIED.   *`n"

    Do { 
        $fileName = read-host -prompt "Save As [Default=$defaultOutFileName]" 

        If ($fileName -and $fileName -eq "Q") { exit }

        $pathIsValid = $true
        $overwriteConfirmed = "Y"

        If (![string]::IsNullOrEmpty($fileName)) {

            $fileName += ".csv"
                                        
            $pathIsValid = Test-Path -Path $fileName -IsValid

            If ($pathIsValid) {
                        
                $fileAlreadyExists = Test-Path -Path $fileName

                If ($fileAlreadyExists) {

                    Do {

                        $overWriteConfirmed = Read-Host -prompt "File '$fileName' Already Exists. Overwrite (Y) or Cancel (N)"       
                        if ($overWriteConfirmed -eq "Q") { exit }
                        if ($overWriteConfirmed -eq "N") { $userPassedOutputFileName = $false }

                    } While ($overWriteConfirmed -ne "Y" -and $overWriteConfirmed -ne "N" -and $overWriteConfirmed -ne "B")
                }
            }

            Else { 
                Write-Output "* Path is not valid. Try again. ('b' to return to main, 'q' to quit.) *"
                $userPassedOutputFileName = $false
            }
        }
        Else { $fileName = $defaultOutFileName }
    }
    while (!$pathIsValid -or $overWriteConfirmed -eq "N")
}

If(!$localMachineOnly) {
    #Prompt if default (caller) credentials should be used for remote connectivity
    do { 
        $defaultCredential = read-host -prompt "`nUse Default (Caller) Credentials? (Y/N) [Default=Y]"
        if (!$defaultCredential) { $defaultCredential = "Y" }
    }
    while ($defaultCredential -ne "Y" -and $defaultCredential -ne "N" -and $defaultCredential -ne "Q")
    If ($defaultCredential -eq "Q") { exit }
}
If($defaultCredential -eq "N" -and !$localMachineOnly) {
    #Get Credential for Remote Connectivity:
    Do {
        $Credential = Get-Credential -Message "Input Credentials for Remote Connectivity.`r`n`r`nClick Cancel to Quit." -ErrorAction SilentlyContinue
        If ($Credential) {
        #Test for valid credentials
            $validRemotingCred = Test-Credential -Credential $Credential
            If (!$validRemotingCred) {
                $wshell = New-Object -ComObject Wscript.Shell
                $wshell.Popup("Invalid Credentials. Please Try Again.",0,"Invalid Credentials",0x0) >$null
            }
        }
        Else { Write-Output "`nUser cancelled credential input. Exiting..." ; Exit }
    }
    While (!$validRemotingCred)
}

#Scriptblock for Invoke-Command below...
$scriptblock1 = {
    Get-LocalUser | 
        ForEach-Object { 
            $user = $_
            return [PSCustomObject]@{ 
                "User"   = $user.Name
                "PasswordLastSet" = $user.PasswordLastSet
                "Groups" = Get-LocalGroup | Where-Object {  $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID") } | Select-Object -ExpandProperty "Name"
        } 
    }
}

Write-Output "`nPlease Wait. Processing..."

$comps | ForEach-Object { 
    $thisComp = $_
    If(!$defaultCredential -eq "N") { $thisResult = Invoke-Command -ComputerName $thisComp -Credential $Credential -ScriptBlock $scriptblock1 -ErrorVariable errmsg 2>$null }
    Else { $thisResult = Invoke-Command -ComputerName $thisComp -ScriptBlock $scriptblock1 -ErrorVariable errmsg 2>$null }
    If($thisResult) { $thisResult | ForEach-Object { $results.Add($_) } }
    If($errmsg) { $errmsg | ForEach-Object { $errors.Add([PSCustomObject]@{'Hostname' = $thisComp ; 'Exception' = $_.Exception.Message } ) } }
    #If(!$thisResult -and !$errmsg) { $errors.Add( [PSCustomObject]@{ 'Hostname' = $thisComp; 'Exception' = "No local users found on $thisComp" } ) } 
}

#Determine if there are localhost related errors...
If($errors) { $localhostErrors = $errors | Where-Object { $_.Hostname -eq $ENV:Computername } }

If ($results -and ($outputMode -eq 2 -or $outputMode -eq 3)) {
    Write-Output "`n`n*Local User Query Results:"
    $results | Select-Object @{n = 'Hostname' ; e = { $_.PSComputerName }}, 
                             @{n = 'Username' ; e = { $_.User }},
                             @{n = 'Password Last Set' ; e = { 
                             If($_.PasswordLastSet) { $_.PasswordLastSet} Else { "{NULL}"}
                             }},
                             @{n = 'Is Admin?' ; e = { If ("Administrators" -in $_.Groups) { "YES" } Else { "NO" } }},
                             @{n = 'Is Password Age Compliant?' ; e = { 
                                 If($_.PasswordLastSet) {
                                 If ("Administrators" -in $_.Groups) { 
                                     If((New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date).AddDays(-90)).Days -lt 90) { "YES" } Else { "NO" } 
                                 }
                                 Else {
                                     If((New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date).AddDays(-365)).Days -lt 365) { "YES" } Else { "NO" }
                                 }
                                 }
                                 Else { "{N/A}" }
                             }},
                             @{n = 'Days Expired (+) or Until Expiration(-)' ; e = { 
                                 If("Administrators" -in $_.Groups) {
                                     If($_.PasswordLastSet) {
                                         (New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date).AddDays(-90)).Days
                                     }
                                     Else { "{N/A}" }
                                 } 
                                Else {
                                     If($_.PasswordLastSet) {
                                         (New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date).AddDays(-365)).Days
                                     }
                                     Else { "{N/A}" }
                                 }
                              } 
                            },
                             @{n = 'Group Membership' ; e = { $_.Groups }} | Sort-Object -Property @{e='Hostname'},@{e='Days Expired (+) or Until Expiration(-)' ; descending=$true} | 
                                                                             Format-Table -AutoSize
}

If ($errors -and ($outputMode -eq 2 -or $outputMode -eq 3)) {
    Write-Output "`n**Errors Attempting to Query Local Users on the Following Machines:"
    $errors | Format-Table -AutoSize Hostname, @{n = 'Exception' ; e = { $_.Exception }}
    If ($localhostErrors) { Write-Output "Try running script as administrator to address permissions issues on localhost update attempts." }
}

If ($outputMode -eq 1 -or $outputMode -eq 3 -and $results) {
    $outputString = "** Local User Query Results:  **"
    Add-Content -Path $fileName -Value $outputString
    $results | Select-Object @{n = 'Hostname' ; e = { $_.PSComputerName }}, 
                             @{n = 'Username' ; e = { $_.User }},
                             @{n = 'Password Last Set' ; e = { 
                             If($_.PasswordLastSet) { $_.PasswordLastSet} Else { "{NULL}"}
                             }},
                             @{n = 'Is Admin?' ; e = { If ("Administrators" -in $_.Groups) { "YES" } Else { "NO" } }},
                             @{n = 'Is Password Age Compliant?' ; e = { 
                                 If($_.PasswordLastSet) {
                                 If ("Administrators" -in $_.Groups) { 
                                     If((New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date).AddDays(-90)).Days -lt 90) { "YES" } Else { "NO" } 
                                 }
                                 Else {
                                     If((New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date).AddDays(-365)).Days -lt 365) { "YES" } Else { "NO" }
                                 }
                                 }
                                 Else { "{N/A}" }
                             }},
                             @{n = 'Days Expired (+) or Until Expiration(-)' ; e = { 
                                 If("Administrators" -in $_.Groups) {
                                     If($_.PasswordLastSet) {
                                         (New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date).AddDays(-90)).Days
                                     }
                                     Else { "{N/A}" }
                                 } 
                                Else {
                                     If($_.PasswordLastSet) {
                                         (New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date).AddDays(-365)).Days
                                     }
                                     Else { "{N/A}" }
                                 }
                              } 
                            },
                             @{n = 'Group Membership' ; e = { $_.Groups }} | 
               Sort-Object -Property @{e='Hostname'},@{e='Days Expired (+) or Until Expiration(-)' ; descending=$true} | 
               ConvertTo-CSV -NoTypeInformation | Add-Content -Path $fileName
}
If ($outputMode -eq 1 -or $outputMode -eq 3 -and $errors) {
    $outputString = "`r`n** Errors: **"
    Add-Content -Path $fileName -Value $outputString
    $errors | Select-Object @{ n = 'Hostname' ; e = {$_.Hostname}},
                            @{ n = 'Exception' ; e = {$_.Exception}} |
              Sort-Object "Hostname" | ConvertTo-CSV -NoTypeInformation | Add-Content -Path $fileName
    If ($localhostErrors) { 
        $outputString = "`r`nTry running script as administrator to address permissions issues on localhost update attempts."
        Add-Content -Path $fileName -Value $outputString
    }
}

## References
## https://stackoverflow.com/questions/4548476/powershell-list-local-users-and-their-groups
# https://stackoverflow.com/questions/36200749/how-do-you-add-more-property-values-to-a-custom-object
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-member?view=powershell-7.3
# https://mikefrobbins.com/2019/05/09/sort-powershell-results-in-both-ascending-and-descending-order/
# https://techstronghold.com/scripting/@rudolfvesely/powershell-tip-convert-script-block-to-string-or-string-to-script-block/
# https://serverfault.com/questions/1043188/update-task-scheduler-job-password-on-multiple-machines
# https://devblogs.microsoft.com/scripting/powertip-use-powershell-to-display-pop-up-window/
# https://www.powershellgallery.com/packages/WFTools/0.1.39/Content/Test-Credential.ps1