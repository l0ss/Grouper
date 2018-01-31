# Grouper - Get-GPOReport XML Parser

<#
.SYNOPSIS
    Consumes a Get-GPOReport XML formatted report and outputs potentially vulnerable settings.
.DESCRIPTION
    GPP cpassword decryption function stolen shamelessly from @harmj0y
    Other small snippets and ideas stolen shamelessly from @sysop_host
.EXAMPLE
    So first you need to generate a report on a machine with the Group Policy PS module installed. Do that like this:

    "Get-GPOReport -All -ReportType XML -Path C:\temp\gporeport.xml"

    Then import this module and:

    "Invoke-AuditGPOReport -Path C:\temp\gporeport.xml"

    -showDisabled or else by default we just filter out policy objects that aren't enabled or linked anywhere.

    -Level (1, 2, or 3) - adjusts whether to show everything (1) or only interesting (2) or only definitely vulnerable (3) settings. Defaults to 2.

    -lazyMode (without -Path) will run the initial generation of the GPOReport for you but will need to be running as a domain user on a domain-joined machine.
.NOTES
     Author     : Mike Loss - mike@mikeloss.net
#>

# TODO ADD TO THIS LIST
$Global:intPrivLocalGroups = @()
$Global:intPrivLocalGroups += "Administrators"
$Global:intPrivLocalGroups += "Backup Operators"
$Global:intPrivLocalGroups += "Hyper-V Administrators"
$Global:intPrivLocalGroups += "Power Users"
$Global:intPrivLocalGroups += "Print Operators"
$Global:intPrivLocalGroups += "Remote Desktop Users"
$Global:intPrivLocalGroups += "Remote Management Users"

# TODO ADD TO THIS LIST
$Global:intLowPrivDomGroups = @()
$Global:intLowPrivDomGroups += "Domain Users"
$Global:intLowPrivDomGroups += "Authenticated Users"
$Global:intLowPrivDomGroups += "Everyone"

# TODO ADD TO THIS LIST
$Global:intLowPrivLocalGroups = @()
$Global:intLowPrivLocalGroups = "Users"

# TODO ADD TO THIS LIST
$Global:intLowPrivGroups = @()
$Global:intLowPrivGroups += "Domain Users"
$Global:intLowPrivGroups += "Authenticated Users"
$Global:intLowPrivGroups += "Everyone"
$Global:intLowPrivGroups += "Users"

# TODO ADD TO THIS LIST
$Global:intPrivDomGroups = @()
$Global:intPrivDomGroups = "Domain Admins"
$Global:intPrivDomGroups = "Administrators"
$Global:intPrivDomGroups = "DNS Admins"

# THIS ONE IS FINE
$Global:intRights = @()
$Global:intRights += "SeTrustedCredManAccessPrivilege"
$Global:intRights += "SeTcbPrivilege"
$Global:intRights += "SeMachineAccountPrivilege"
$Global:intRights += "SeBackupPrivilege"
$Global:intRights += "SeCreateTokenPrivilege"
$Global:intRights += "SeAssignPrimaryTokenPrivilege"
$Global:intRights += "SeRestorePrivilege"
$Global:intRights += "SeDebugPrivilege"
$Global:intRights += "SeTakeOwnershipPrivilege"
$Global:intRights += "SeCreateGlobalPrivilege"
$Global:intRights += "SeLoadDriverPrivilege"
$Global:intRights += "SeRemoteInteractiveLogonRight"

#____________________ GPO Check functions _______________

# There's a whole pile of these functions. Each one consumes a single <GPO> object from a Get-GPOReport XML report,
# then depending on the -Level parameter it should output interesting/vulnerable/any policy it can process.

Function Get-GPOUsers {
    [cmdletbinding()]
    # Consumes a single <GPO> object from a Get-GPOReport XML report.

    ######
    # Description: Checks for changes made to local users.
    # Vulnerable: Only show instances where a password has been set, i.e. GPP Passwords.
    # Interesting: All users and all changes.
    # Boring: All users and all changes.
    ######

    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    $GPOisinteresting = 0
    $GPOisvulnerable = 0

    # Grab an array of the settings we're interested in from the GPO.
    $settingsUsers = ($polXml.ExtensionData.Extension.LocalUsersAndGroups.User | Sort-Object GPOSettingOrder)

    # Check if there's actually anything in the array.
    if ($settingsUsers) {
        $output = @{}

        # Iterate over array of settings, writing out only those we care about.
        foreach ($setting in $settingsUsers) {

            #see if we have any stored encrypted passwords
            $cpasswordcrypt = $setting.properties.cpassword
            if ($cpasswordcrypt) {
                $GPOisvulnerable = 1

                # decrypt it with harmj0y's function
                $cpasswordclear = Get-DecryptedCpassword -Cpassword $cpasswordcrypt
            }
            #if so, or if we're showing boring, show the rest of the setting
            if (($cpasswordcrypt) -Or ($level -le 2)) {
                $GPOisinteresting = 1
                $output = @{}
                $output.Add("Name", $setting.Name)
                $output.Add("New Name", $setting.properties.NewName)
                $output.Add("Description", $setting.properties.Description)
                $output.Add("changeLogon", $setting.properties.changeLogon)
                $output.Add("noChange", $setting.properties.noChange)
                $output.Add("neverExpires", $setting.properties.neverExpires)
                $output.Add("Disabled", $setting.properties.acctDisabled)
                $output.Add("UserName", $setting.properties.userName)
                $output.Add("Password", $($cpasswordclear, "Password Not Set" -ne $null)[0])

                Write-Output $output "`r`n"
            }
        }
    }

    if ($GPOisinteresting -eq 1) {
        $Global:interestingPolSettings += 1
    }
    if ($GPOisvulnerable -eq 1) {
        $Global:vulnerablePolSettings += 1
    }
}

Function Get-GPOGroups {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for changes made to local groups.
    # Vulnerable: If Domain Users, Everyone, Authenticated Users get added to 'interesting groups'.
    # Interesting: Show changes to groups that grant meaningful security-relevant access.
    # Boring: All groups and all changes.
    ######

    $GPOIsInteresting = 0
    $GPOIsVulnerable = 0

    $settingsGroups = ($polXml.ExtensionData.Extension.LocalUsersAndGroups.Group | Sort-Object GPOSettingOrder)

    if ($settingsGroups) {
	    foreach ($setting in $settingsGroups) {
            $settingIsInteresting = 0
            $settingIsVulnerable = 0
            $groupIsInteresting = 0

            # check if the group being modified is one of the high-priv local groups array,
            $groupName = $setting.properties.groupName
            if ($Global:intPrivLocalGroups -Contains $groupName) {
                $GPOIsInteresting = 1
                $settingIsInteresting = 1
                $groupIsInteresting = 1
            }

            # if it's in that array AND a member being modified is a low-priv domain group, we flag the setting as vulnerable.
            $groupmembers = $setting.properties.members.member
            foreach ($groupmember in $groupmembers) {
                $groupMemberName = $groupmember.name
                foreach ($lowPrivDomGroup in $Global:intLowPrivDomGroups) {
                    if (($groupMemberName -match $lowPrivDomGroup) -And ($groupIsInteresting -eq 1)){
                        $settingIsVulnerable = 1
                        $GPOIsVulnerable = 1
                    }
                }
            }

            if ((($settingIsVulnerable -eq 1) -And ($level -le 3)) -Or (($settingIsInteresting -eq 1) -And ($level -le 2)) -Or ($level -eq 1)) {
                $output = @{}
                $output.Add("Name", $setting.Name)
                $output.Add("NewName", $setting.properties.NewName)
                $output.Add("Description", $setting.properties.Description)
                $output.Add("Group Name", $groupName)
                Write-Output $output

                foreach ($member in $setting.properties.members.member) {
                    $output = @{}
                    $output.Add("Name", $member.name)
                    $output.Add("Action", $member.action)
                    $output.Add("UserName", $member.userName)
                    Write-Output $output 

                }
                "`r`n"
            }
        }
    }

    if ($GPOisinteresting -eq 1) {
        $Global:interestingPolSettings += 1
    }
    if ($GPOIsVulnerable -eq 1) {
        $Global:vulnerablePolSettings += 1
    }
}

Function Get-GPOUserRights {
    [cmdletbinding()]

    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for user rights granted to users and groups.
    # Vulnerable: Only show "Interesting" rights, i.e. those that can be used for local privilege escalation or remote access,
    #             and only if they've been assigned to Domain Users, Authenticated Users, or Everyone.
    # Interesting: Only show "Interesting" rights, i.e. those that can be used for local privilege escalation or remote access.
    # Boring: All non-default.
    ######

    $GPOIsInteresting = 0
    $GPOIsVulnerable = 0

    $uraSettings = ($polXml.Computer.ExtensionData.Extension.UserRightsAssignment)

    $uraSettings = ($uraSettings | ? {$_}) #Strips null elements from array - nfi why I was getting so many of these.

    if ($uraSettings) {
        foreach ($setting in $uraSettings) {
            $settingIsInteresting = 0
            $settingIsVulnerable = 0
            $rightIsInteresting = 0

            $userRight = $setting.Name

            $members = @()
            foreach ($member in $setting.Member) {
                $members += ($member.Name.Innertext)
            }

            # if the right being assigned is in our array of interesting rights, the setting is interesting.
            if ($Global:intRights -contains $userRight) {
                $GPOisinteresting = 1
                $settingIsInteresting = 1
                $rightIsInteresting = 1
            }

            # then we construct an array of trustees being granted the right to see if they are in any of our interesting low priv groups.
            if ($rightIsInteresting) {
                foreach ($lowPrivGroup in $Global:intLowPrivGroups) {
                    foreach ($member in $members) {
                        if ($member -match $lowPrivGroup) {
                            $GPOIsVulnerable = 1
                            $settingIsVulnerable = 1
                        }
                    }
                }
            }

            if ((($settingIsVulnerable -eq 1) -And ($level -le 3)) -Or (($settingIsInteresting) -And ($level -le 2)) -Or ($level -eq 1)) {
                $output = @{}
                $output.Add("Right", $userRight)
                $output.Add("Members", $members)
                Write-Output $output "`r`n"
            }
        }
    }

    if ($GPOisinteresting -eq 1) {
        $Global:interestingPolSettings += 1
    }

    if ($GPOIsVulnerable -eq 1) {
        $Global:vulnerablePolSettings += 1
    }
}

Function Get-GPOSchedTasks {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for scheduled tasks being configured on a host.
    # Vulnerable: Only show instances where a password has been set.
    # Interesting: TODO If a password has been set or the thing being run is non-local or there are arguments set.
    # Boring: All scheduled tasks.
    ######

    $GPOisinteresting = 0
    $GPOisvulnerable = 0

    $settingsSchedTasks = ($polXml.Computer.ExtensionData.Extension.ScheduledTasks.Task | Sort-Object GPOSettingOrder)

    if ($settingsSchedTasks) {
        foreach ($setting in $settingsSchedTasks) {
            #see if we have any stored encrypted passwords
            $cpasswordcrypt = $setting.properties.cpassword
            if ($cpasswordcrypt) {
                $GPOisvulnerable = 1
                $GPOisinteresting = 1

                # decrypt it with harmj0y's function
                $cpasswordclear = Get-DecryptedCpassword -Cpassword $cpasswordcrypt
            }
            #see if any arguments have been set
            $taskArgs = $setting.Properties.args
            if ($taskArgs) {
                $GPOisinteresting = 1
            }

            #if so, or if we're showing everything, or if there are args and we're at level 2, show the setting.
            if ((($cpasswordcrypt) -And ($level -le 3)) -Or (($taskArgs) -And ($level -le 2)) -Or ($level -eq 1)) {
                $output = @{}
                $output.Add("Name", $setting.Properties.name)
                $output.Add("runAs", $setting.Properties.runAs)
                $output.Add("Password", $($cpasswordclear, "Password Not Set" -ne $null)[0])
                $output.Add("Action", $setting.Properties.action)
                $output.Add("appName", $setting.Properties.appName)
                $output.Add("args", $setting.Properties.args)
                $output.Add("startIn", $setting.Properties.startIn)
                Write-Output $output

                if ($setting.Properties.Triggers) {
                    $output = @{}
                    foreach ($trigger in $setting.Properties.Triggers) {
                         $output.Add("type", $trigger.Trigger.type)
                         $output.Add("startHour", $trigger.Trigger.startHour)
                         $output.Add("startMinutes", $trigger.Trigger.startMinutes)
                         Write-Output $output "`r`n"
                    }
                }
            }
        }
    }

    if ($GPOisinteresting -eq 1) {
        $Global:interestingPolSettings += 1
    }

    if ($GPOisvulnerable -eq 1) {
        $Global:vulnerablePolSettings += 1
    }
}

Function Get-GPOMSIInstallation {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for MSI installers being used to install software.
    # Vulnerable: TODO Only show instances where the file is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Interesting: TODO Also show instances where any user/group other than the usual default Domain/Enterprise Admins has 'Full Control'.
    # Boring: All MSI installations.
    ######

	$computerMSIInstallation = ($polXml.Computer.ExtensionData.Extension.MsiApplication | Sort-Object GPOSettingOrder)

    if ($computerMSIInstallation) {
 	    foreach ($setting in $computerMSIInstallation) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Name", $setting.Name)
                $output.Add("Path", $setting.Path)
                Write-Output $output "`r`n"
            }
        }
    }
}

Function Get-GPOScripts {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for startup/shutdown/logon/logoff scripts.
    # Vulnerable: TODO Only show instances where the file is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Interesting: TODO Also show instances where any user/group other than the usual default Domain/Enterprise Admins has 'Full Control' or where 'Parameters' is set.
    # Boring: All scripts.
    ######

	$settingsScripts = ($polXml.ExtensionData.Extension.Script | Sort-Object GPOSettingOrder)

    if ($settingsScripts) {
	    foreach ($setting in $settingsScripts) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Command", $setting.Command)
                $output.Add("Type", $setting.Type)
                $output.Add("Parameters", $setting.Parameters)
                Write-Output $output "`r`n"
            }
        }
    }
}

Function Get-GPOFileUpdate {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for MSI installers being used to install software.
    # Vulnerable: TODO Only show instances where the 'fromPath' file is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Interesting: TODO Also show instances where any user/group other than the usual default Domain/Enterprise Admins has 'Full Control' of the 'fromPath' file.
    # Boring: All File Updates.
    ######

	$settingsFiles = ($polXml.ExtensionData.Extension.FilesSettings | Sort-Object GPOSettingOrder)

    if ($settingsFiles) {
 	    foreach ($setting in $settingsFiles.File) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Name", $setting.name)
                $output.Add("Action", $setting.Properties.action)
                $output.Add("fromPath", $setting.Properties.fromPath)
                $output.Add("targetPath", $setting.Properties.targetPath)
                Write-Output $output "`r`n"
            }
        }
    }
}

Function Get-GPOFilePerms {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for changes to local file permissions.
    # Vulnerable: TODO Only show instances where the file is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Interesting: TODO Also show instances where any user/group other than the usual default Domain/Enterprise Admins has 'Full Control'.
    # Boring: All file permission changes.
    ######

	$settingsFilePerms = ($polXml.Computer.ExtensionData.Extension.File | Sort-Object GPOSettingOrder)

    if ($settingsFilePerms) {
 	    foreach ($setting in $settingsFilePerms) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Path", $setting.Path)
                $output.Add("SDDL", $setting.SecurityDescriptor.SDDL.innertext)
                Write-Output $output "`r`n"
            }
        }
    }
}

Function Get-GPOSecurityOptions {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for potentially vulnerable "Security Options" settings.
    # Vulnerable: TODO.
    # Interesting: Show everything that matches $intKeyNames or $intSysAccPolName.
    # Boring: All settings.
    ######

    $GPOisinteresting = 0

	$settingsSecurityOptions = ($polXml.Computer.ExtensionData.Extension.SecurityOptions | Sort-Object GPOSettingOrder)

    if ($settingsSecurityOptions) {

        $intKeyNames = @()
        $intKeyNames += "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares"
        $intKeyNames += "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess"

        $intSysAccPolNames = @()
        $intSysAccPolNames += "EnableGuestAccount"
        $intSysAccPolNames += "EnableAdminAccount"
        $intSysAccPolNames += "LSAAnonymousNameLookup"
        $intSysAccPolNames += "NewAdministratorName"
        $intSysAccPolNames += "NewGuestName"

 	    foreach ($setting in $settingsSecurityOptions) {

            #Check if it's a registry based option
            if ($setting.KeyName) {

                $keyname = $setting.KeyName
                $keynameisint = 0

                #Check if it's one of the ones we care about
                if ($intKeyNames -contains $KeyName) {
                  #if it is, don't bother checking the rest
                  $keynameisint = 1
                  break
                  $GPOisinteresting = 1
                }

                # if it's interesting, grab the text we want to know from the setting and add it to our output array
                if ((($keynameisint -eq 1) -And ($level -le 2)) -Or ($level -eq 1)) {
                    $output = @{}
                    $output.Add("Name", $setting.Display.Name)
                    $output.Add("KeyName", $setting.KeyName)

                    $values = @{}
                    $dispunits = $setting.Display.DisplayUnits
                    if ($dispunits) {
                        $values.Add("DisplayUnits", $setting.Display.DisplayUnits)
                    }

                    $dispbool = $setting.Display.DisplayBoolean
                    if ($dispbool) {
                        $values.Add("DisplayBoolean", $setting.Display.DisplayBoolean)
                    }

                    $dispnum = $setting.Display.DisplayNumber
                    if ($dispnum) {
                        $values.Add("DisplayNumber", $setting.Display.DisplayNumber)
                    }

                    $dispstrings = $setting.Display.DisplayStrings.Value
                    if ($dispstrings) {
                        $i = 0
                        foreach ($dispstring in $dispstrings) {
                           $values.Add("DisplayString$i", $dispstring)
                           $i = ($i + 1)
                        }
                    }
                    Write-Output $output
                    Write-Output $values.GetEnumerator() | sort -Property Name
                    "`r`n"
                }
            }

            if ($setting.SystemAccessPolicyName) {
                if ($intSysAccPolNames -Contains $setting.SystemAccessPolicyName) {
                    $GPOisinteresting = 1
                }
                if ((($intSysAccPolNames -Contains $setting.SystemAccessPolicyName) -And ($level -le 2)) -Or ($level -eq 1)) {
                    $output = @{}
                    $output.Add("Name", $setting.SystemAccessPolicyName)
                    if ($setting.SettingNumber) {
                        $output.Add("SettingNumber", $setting.SettingNumber)
                    }
                    if ($setting.SettingString) {
                        $output.Add("SettingString", $setting.SettingString)
                    }
                    Write-Output $output "`r`n"
                }
            }
        }
    }

    if ($GPOisinteresting -eq 1) {
        $Global:interestingPolSettings += 1
    }
}

Function Get-GPORegKeys {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for registry keys being set that may contain sensitive information.
    # Vulnerable: Any key that matches '$intKeys'.
    # Interesting: TODO Also show instances containing the strings 'pass', 'pwd', 'cred', or 'vnc'.
    # Boring: All Registry Keys
    ######

    $GPOisinteresting = 0
    $GPOisvulnerable = 0

	$settingsRegKeys = ($polXml.ExtensionData.Extension.RegistrySettings.Registry | Sort-Object GPOSettingOrder)

    $vulnKeys = @()
    $vulnKeys += "Software\Network Associates\ePolicy Orchestrator"
    $vulnKeys += "SOFTWARE\FileZilla Server"
    $vulnKeys += "SOFTWARE\Wow6432Node\FileZilla Server"
    $vulnKeys += "Software\Wow6432Node\McAfee\DesktopProtection - McAfee VSE"
    $vulnKeys += "Software\McAfee\DesktopProtection - McAfee VSE"
    $vulnKeys += "Software\ORL\WinVNC3"
    $vulnKeys += "Software\ORL\WinVNC3\Default"
    $vulnKeys += "Software\ORL\WinVNC\Default"
    $vulnKeys += "Software\RealVNC\WinVNC4"
    $vulnKeys += "Software\RealVNC\Default"
    $vulnKeys += "Software\TightVNC\Server"
    $vulnKeys += "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    $intWords = @()
    $intWords += "vnc"
    $intWords += "vpn"
    $intWords += "pwd"
    $intWords += "cred"
    $intWords += "key"
    $intWords += "pass"


    if ($settingsRegKeys) {
        foreach ($setting in $settingsRegKeys) {
            $settingkey = $setting.Properties.key
            $settingisInteresting = 0
            $settingisVulnerable = 0

            if ($vulnKeys -Contains $settingkey) {
                $GPOisvulnerable = 1
                $settingisVulnerable = 1
            }

            foreach ($intWord in $intWords) {
                # if either key or value include our interesting words as a substring, mark the setting as interesting
                if (($settingkey -match $intWord) -Or ($settingValue -match $intWord)) {
                    $GPOisinteresting = 1
                    $settingIsInteresting = 1
                }
            }

            # if setting matches any of our criteria for printing (combined interest level + output level)
            if ((($settingisVulnerable -eq 1) -And ($level -le 3)) -Or (($settingisInteresting -eq 1) -And ($level -le 2)) -Or ($level -eq 1)) {
                $output = @{}
                $output.Add("Key", $settingkey)
                $output.Add("Action", $setting.Properties.action)
                $output.Add("Hive", $setting.Properties.hive)
                $output.Add("Name", $setting.Properties.name)
                $output.Add("Value", $setting.Properties.value)
                Write-Output $output "`r`n"
            }
        }
    }

    # update the global counters
    if ($GPOisivulnerable -eq 1) {
        $Global:vulnerablePolSettings += 1
    }

    if ($GPOisinteresting -eq 1) {
        $Global:interestingPolSettings += 1
    }

}

Function Get-GPOFolderRedirection {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for user Folder redirections.
    # Vulnerable: TODO Only show instances where DestPath is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Interesting: TODO Also show instances where any user/group other than the usual default Domain/Enterprise Admins has 'Full Control'.
    # Boring: All Folder Redirection.
    ######

	$settingsFolderRedirection = ($polXml.User.ExtensionData.Extension.Folder | Sort-Object GPOSettingOrder)

    if ($settingsFolderRedirection) {
 	    foreach ($setting in $settingsFolderRedirection) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("DestPath", $setting.Location.DestinationPath)
                $output.Add("Target Group", $setting.Location.SecurityGroup.Name.innertext)
                $output.Add("Target SID", $setting.Location.SecurityGroup.SID.innertext)
                $output.Add("ID", $setting.Id)
                Write-Output $output "`r`n"
            }
        }
    }
}

Function Get-GPOAccountSettings {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for Account Settings.
    # Vulnerable: TODO
    # Interesting: TODO Add to list of 'interesting' settings. - only has one so far
    # Boring: All Account Settings.
    ######

	$settingsAccount = ($polXml.Computer.ExtensionData.Extension.Account | Sort-Object GPOSettingOrder)

    $GPOisinteresting = 0

    $intAccSettings = @()
    $intAccSettings += "ClearTextPassword"

    if ($settingsAccount) {
	    foreach ($setting in $settingsAccount) {
            $settingName = $setting.Name
            $settingisInteresting = 0

            if ($intAccSettings -Contains $settingName) {
                $settingisInteresting = 1
                $GPOisInteresting = 1
            }

            if (($level -eq 1) -Or (($settingisInteresting -eq 1) -And ($level -le 2))) {
                $output = @{}
                $output.Add("Name", $settingName)
                if ($setting.SettingBoolean) {
                    $output.Add("SettingBoolean", $setting.SettingBoolean)
                }
                if ($setting.SettingNumber) {
                    $output.Add("SettingNumber", $setting.SettingNumber)
                }
                $output.Add("Type", $setting.Type)
                Write-Output $output "`r`n"
            }
        }
    }

    # update the global counters

    if ($GPOisinteresting -eq 1) {
        $Global:interestingPolSettings += 1
    }
}

Function Get-GPOFolders {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for creation/renaming of local folders
    # Vulnerable: TODO
    # Interesting: TODO Need to generate a list of 'interesting' settings.
    # Boring: All folders changes.
    ######

	$settingsFolders = ($polXml.ExtensionData.Extension.Folders.Folder | Sort-Object GPOSettingOrder)

    if ($settingsFolders) {
	    foreach ($setting in $settingsFolders) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Name", $setting.name)
                $output.Add("Action", $setting.Properties.action)
                $output.Add("Path", $setting.Properties.path)
                Write-Output $output "`r`n"
            }
        }
    }
}

Function Get-GPONetworkShares {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for Network Shares being created on hosts.
    # Vulnerable: TODO
    # Interesting: All Network Shares.
    # Boring: All Network Shares.
    ######

    $GPOisinteresting = 0

	$settingsNetShares = ($polXml.Computer.ExtensionData.Extension.NetworkShares.Netshare | Sort-Object GPOSettingOrder)

    if ($settingsNetShares) {
	    foreach ($setting in $settingsNetShares) {
            if ($level -le 2) {
                $GPOisinteresting = 1
                $output = @{}
                $output.Add("Name", $setting.name)
                $output.Add("Action", $setting.Properties.action)
                $output.Add("PropName", $setting.Properties.name)
                $output.Add("Path", $setting.Properties.path)
                $output.Add("Comment", $setting.Properties.comment)
                Write-Output $output "`r`n"
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:interestingPolSettings += 1
    }

}

Function Get-GPOIniFiles {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for changes to .INI files.
    # Vulnerable: TODO
    # Interesting: TODO Need to generate a list of 'interesting' settings.
    # Boring: All .INI file changes.
    ######

    $settingsIniFiles = ($polXml.ExtensionData.Extension.IniFiles.Ini | Sort-Object GPOSettingOrder)

    if ($settingsIniFiles) {

	    foreach ($setting in $settingsIniFiles) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Name", $setting.name)
                $output.Add("Path", $setting.Properties.path)
                $output.Add("Section", $setting.Properties.section)
                $output.Add("Value", $setting.Properties.value)
                $output.Add("Property", $setting.Properties.property)
                $output.Add("Action", $setting.Properties.action)
                Write-Output $output "`r`n"
            }
        }
    }
}

Function Get-GPOEnvVars {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for environment variables being set.
    # Vulnerable: TODO
    # Interesting: TODO Need to generate a list of 'interesting' settings.
    # Boring: All environment variables.
    ######

	$settingsEnvVars = ($polXml.ExtensionData.Extension.EnvironmentVariables.EnvironmentVariable | Sort-Object GPOSettingOrder)

    if ($settingsEnvVars) {
	    foreach ($setting in $settingsEnvvars) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Name", $setting.name)
                $output.Add("Status", $setting.status)
                $output.Add("Value", $setting.properties.value)
                $output.Add("Action", $setting.properties.action)
                Write-Output $output "`r`n"
            }
        }
    }
}

Function Get-GPORegSettings {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for "Registry Settings" i.e. a bunch of Windows options that are defined via the registry.
    # Vulnerable: TBD.
    # Interesting: Need to generate a list of 'interesting' settings.
    # Boring: All Registry Settings.
    ######

	$settingsRegSettings = ($polXml.ExtensionData.Extension.Policy | Sort-Object GPOSettingOrder)

    if ($settingsRegSettings) {

        # I hate this nested looping shit more than anything I've ever written.
        foreach ($setting in $settingsRegSettings) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Name", $setting.Name)
                $output.Add("State", $setting.State)
                $output.Add("Supported", $setting.Supported)
                $output.Add("Category", $setting.Category)
                $output.Add("Explain", $setting.Explain)
                Write-Output $output "`r`n"

                foreach ($thing in $setting.EditText) {
                    $output = @{}
                    $output.Add("Name", $thing.Name)
                    $output.Add("Value", $thing.Value)
                    $output.Add("State", $thing.State)
                    Write-Output $output "`r`n"
                }

                foreach ($thing in $setting.DropDownList) {
                    $output = @{}
                    $output.Add("Name", $thing.Name)
                    $output.Add("Value", $thing.Value)
                    $output.Add("State", $thing.State)
                    Write-Output $output "`r`n"
                }

                foreach ($thing in $setting.ListBox) {
                    $output = @{}
                    $output.Add("Name", $thing.Name)
                    $output.Add("ExplicitValue", $thing.ExplicitValue)
                    $output.Add("State", $thing.State)
                    $output.Add("Additive", $thing.Additive)
                    $output.Add("ValuePrefix", $thing.ValuePrefix)
                    $data = @()
                    foreach ($subthing in $thing.Value) {
                        foreach ($subsubthing in $subthing.Element) {
                            $data += $subsubthing.Data
                        }
                    }
                    $output.Add("Data", $data)
                    Write-Output $output "`r`n"
                }

                foreach ($thing in $setting.Checkbox) {
                    $output = @{}
                    $output.Add("Value", $thing.Name)
                    $output.Add("State", $thing.State)
                    Write-Output $output "`r`n"
                }

                foreach ($thing in $setting.Numeric) {
                    $output = @{}
                    $output.Add("Name", $thing.Name)
                    $output.Add("Value", $thing.Value)
                    $output.Add("State", $thing.State)
                    Write-Output $output "`r`n"
                }
            }
        }
    }
}
Function Get-GPOShortcuts {
    [cmdletbinding()]
    # Consumes a single <GPO> object from a Get-GPOReport XML report.

    ######
    # Description: Checks for changes made to shortcuts or new shortcuts added.
    # Vulnerable: TODO Only show instances where current user can write to target of shortcut.
    # Interesting: TODO As above, plus where Domain Users, Authenticated Users, or Everyone can write to taret of shortcut.
    # Boring: All shortcut settings.
    ######

    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    # Grab an array of the settings we're interested in from the GPO.
    $settingsShortcuts = ($polXml.ExtensionData.Extension.ShortcutSettings.Shortcut | Sort-Object GPOSettingOrder)
    # Check if there's actually anything in the array.
    if ($settingsShortcuts) {
        # Iterate over array of settings, writing out only those we care about.
        foreach ($setting in $settingsShortcuts) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Name", $setting.name)
                $output.Add("Status", $setting.status)
                $output.Add("targetType", $setting.properties.targetType)
                $output.Add("Action", $setting.properties.Action)
                $output.Add("comment", $setting.properties.comment)
                $output.Add("startIn", $setting.properties.startIn)
                $output.Add("arguments", $setting.properties.arguments)
                $output.Add("targetPath", $setting.properties.targetPath)
                $output.Add("iconPath", $setting.properties.iconPath)
                $output.Add("shortcutPath", $setting.properties.shortcutPath)
                Write-Output $output "`r`n"
            }
        }
    }
}

# Here endeth the gross GPO check functions

#__________________________GPP decryption helper function stolen from PowerUp.ps1 by @harmjoy__________________
function Get-DecryptedCpassword {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $Cpassword
    )

    try {
        # Append appropriate padding based on string length
        $Mod = ($Cpassword.length % 4)

        switch ($Mod) {
            '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
            '2' {$Cpassword += ('=' * (4 - $Mod))}
            '3' {$Cpassword += ('=' * (4 - $Mod))}
        }

        $Base64Decoded = [Convert]::FromBase64String($Cpassword)

        # Create a new AES .NET Crypto Object
        $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                             0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

        # Set IV to all nulls to prevent dynamic generation of IV value
        $AesIV = New-Object Byte[]($AesObject.IV.Length)
        $AesObject.IV = $AesIV
        $AesObject.Key = $AesKey
        $DecryptorObject = $AesObject.CreateDecryptor()
        [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

        return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
    }

    catch {
      Write-Error $Error[0]
    }
}

Function Write-Title {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Text,
        [Parameter(Mandatory=$false)][ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White', ignorecase=$true)] [string]$Color = $host.ui.RawUI.ForegroundColor,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][string]$DividerChar = "-"
    )

    $DefForegroundColor = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = $Color
    Write-Output $Text
    $divider = $DividerChar * $Text.Length
    Write-Output $divider
    $host.ui.RawUI.ForegroundColor = $DefForegroundColor
}
#_____________________________________________________________________
Function Invoke-AuditGPO {
    [cmdletbinding()]
    # Consumes <GPO> objects from a Get-GPOReport xml report.
    Param (
        [Parameter(Mandatory=$true)][System.Xml.XmlElement]$xmlgpo,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    #check the GPO is even enabled
    $gpoisenabled = $xmlgpo.LinksTo.Enabled
    #and if it's not, increment our count of GPOs that don't do anything
    if (($gpoisenabled -ne "true") -And ($Global:showdisabled -eq 0)) {
        $Global:unlinkedpols += 1
        return $null
    }

    #check if it's linked somewhere
    $gpopath = $xmlgpo.LinksTo.SOMName
    #and if it's not, increment our count of GPOs that don't do anything
    if ((-Not $gpopath) -And ($Global:showdisabled -eq 0)) {
        $Global:unlinkedpols += 1
        return $null
    }

    # Define settings groups so we can send through both if the same type of policy settings can appear in either.
    $computerSettings = $xmlgpo.Computer
    $userSettings = $xmlgpo.User

    # Build an array of all our Get-GPO* check scriptblocks
    $polchecks = @()
    $polchecks += {Get-GPORegKeys -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPORegKeys -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOUsers -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOUsers -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPOGroups -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOGroups -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPOScripts -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOScripts -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPOFileUpdate -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOFileUpdate -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPOMSIInstallation -Level $level -polXML $xmlgpo}
    $polchecks += {Get-GPOUserRights -Level $level -polXML $xmlgpo}
    $polchecks += {Get-GPOSchedTasks -Level $level -polXML $xmlgpo}
    $polchecks += {Get-GPOFolderRedirection -Level $level -polXML $xmlgpo}
    $polchecks += {Get-GPOFilePerms -Level $level -polXML $xmlgpo}
    $polchecks += {Get-GPOSecurityOptions -Level $level -polXML $xmlgpo}
    $polchecks += {Get-GPOAccountSettings -Level $level -polXML $xmlgpo}
    $polchecks += {Get-GPONetworkShares -Level $level -polXml $xmlgpo}
    $polchecks += {Get-GPOFolders -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOFolders -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPORegSettings -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPORegSettings -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOIniFiles -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPOIniFiles -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOEnvVars -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPOEnvVars -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOShortcuts -Level $level -polXml $userSettings}
    $polchecks += {Get-GPOShortcuts -Level $level -polXml $computerSettings}

    # Write a pretty green header with the report name and some other nice details
    $headers = @()
    $headers += {'==============================================================='}
    $headers += {'Policy UID: {0}' -f $xmlgpo.Identifier.Identifier.InnerText}
    $headers += {'Policy created on: {0:d}' -f $xmlgpo.CreatedTime}
    $headers += {'Policy last modified: {0:d}' -f $xmlgpo.ModifiedTime}
    $headers += {'Policy owner: {0}' -f $xmlgpo.SecurityDescriptor.Owner.Name.InnerText}
    $headers += {'Linked OU: {0}' -f $gpopath}
    $headers += {'Link enabled: {0}' -f $gpoisenabled}
    $headers += {'==============================================================='}

    # In each GPO we parse, iterate through the list of checks to see if any of them return anything.
    $headerprinted = 0
    foreach ($polcheck in $polchecks) {
        $finding = & $polcheck # run the check and store the output
        if ($finding) {
            # the first time one of the checks returns something, show the user the header with the policy name and so on
            if ($headerprinted -ne 1) {
                # Increment the total counter of displayed policies.
                $Global:displayedPols += 1
                # Write the title of the GPO in nice green text
                Write-Title -DividerChar "*" -Color "Green" -Text $xmlgpo.Name
                # Write the headers from above
                foreach ($header in $headers) {
                    & $header
                }

                # Parse and print out the GPO's Permissions
                $GPOPermissions = $xmlgpo.SecurityDescriptor.Permissions.TrusteePermissions
                # an array of permissions that aren't exciting
                $boringPerms = @()
                $boringPerms += "Read"
                $boringPerms += "Apply Group Policy"
                # an array of users who have RW permissions on GPOs by default, so they're boring too.
                $boringTrustees = @()
                $boringTrustees += "Domain Admins"
                $boringTrustees += "Enterprise Admins"
                $boringTrustees += "ENTERPRISE DOMAIN CONTROLLERS"
                $boringTrustees += "SYSTEM"

                $permOutput = @{}

                # iterate over each permission entry for the GPO
                foreach ($GPOACE in $GPOPermissions) {
                    $ACEType = $GPOACE.Standard.GPOGroupedAccessEnum # allow v deny
                    $trusteeName = $GPOACE.Trustee.Name.InnerText # who does it apply to
                    $trusteeSID = $GPOACE.Trustee.SID.InnerText # SID of the account/group it applies to
                    $ACEInteresting = 1 # ACEs are default interesting unless proven boring.

                    # check if our trustee is a 'boring' default one
                    if ($trusteeName) {
                        foreach ($boringTrustee in $boringTrustees) {
                            if ($trusteeName -match $boringTrustee) {
                                $ACEInteresting = 0
                            }
                        }
                    }
                    # check if our permission is boring
                    if (($boringPerms -Contains $ACEType) -Or ($GPOACE.Type.PermissionType -eq "Deny")){
                        $ACEInteresting = 0
                    }

                    # if it's still interesting,
                    if ($ACEInteresting -eq 1) {
                        #if we have a valid trustee name, add it to the output
                        if ($trusteeName) {
                            $permOutput.Add("Trustee",$trusteeName)
                        }
                        #if we have a SID, add it to the output
                        elseif ($trusteeSID) {
                            $permOutput.Add("Trustee SID", $trusteeSID)
                        }
                        #add our other stuff to the output
                        $permOutput.Add("Type", $GPOACE.Type.PermissionType)
                        $permOutput.Add("Access", $GPOACE.Standard.GPOGroupedAccessEnum)
                    }
                }

                if ($permOutput.Count -gt 0) {
                    Write-Title -DividerChar "#" -Color "Yellow" -Text "GPO Permissions"
                    Write-Output $permOutput "`r`n"
                }

                # then we set $headerprinted to 1 so we don't print it all again
                $headerprinted = 1
           }
            # Then for each actual finding we write the name of the check function that found something.
            $polcheckbits = ($polcheck.ToString()).split(' ')
            $polchecktitle = $polcheckbits[0]

            Switch ($polcheckbits[4])
            {
             '$computerSettings' { $polchecktype = 'Computer Policy'; break }
             '$userSettings' { $polchecktype = 'User Policy'; break }
             '$xmlgpo' { $polchecktype = 'All Policy'; break }
             default {''; break}
            }

            $polchecktitle = "$polchecktitle - $polchecktype"
            Write-Title -DividerChar "#" -Color "Yellow" -Text $polchecktitle
            # Write out the actual finding
            $finding
        }
    }
	[System.GC]::Collect()
}

Function Invoke-AuditGPOReport {
    [cmdletbinding(DefaultParameterSetName='WithoutFile')]
    param(
        [Parameter(
          ParameterSetName='WithFile', Mandatory=$true
        )]
        [ValidateScript({if(Test-Path $_ -PathType 'Leaf'){$true}else{Throw "Invalid path given: $_"}})]
        [ValidateScript({if($_ -Match '\.xml'){$true}else{Throw "Supplied file is not XML: $_"}})]
        [System.IO.FileInfo]$Path,

        [Parameter(
          ParameterSetName='WithFile', Mandatory=$false
        )]
        [Parameter(
          ParameterSetName='WithoutFile', Mandatory=$false
        )]
        [switch]$showDisabled, # if not set, we filter out GPOs that aren't linked anywhere

        [Parameter(
          ParameterSetName='WithoutFile', Mandatory=$false
        )]
        [switch]$lazyMode = $true, # if you enable this I'll do the Get-GPOReport thing for you.

        [Parameter(
          ParameterSetName='WithFile', Mandatory=$false
        )]
        [Parameter(
          ParameterSetName='WithoutFile', Mandatory=$false
        )]
        [ValidateSet(1,2,3)]
        [int]$level = 2
    )

    if ($PSCmdlet.ParameterSetName -eq 'WithFile') {
        $lazyMode = $false
    }

    # couple of counters for the stats at the end
    $Global:unlinkedpols = 0
    $Global:interestingPolSettings = 0
    $Global:vulnerablePolSettings = 0
    $Global:displayedpols = 0

    #handle our arguments
    $Global:showDisabled = 0
    if ($showDisabled) {
        $Global:showDisabled = 1
    }

    if ($lazyMode) {
        $requiredModules = @('GroupPolicy')
        $requiredModules | Import-Module -Verbose:$false -ErrorAction SilentlyContinue
        if (($requiredModules | Get-Module) -eq $null) {
          Write-Warning ('[!] Could not import required modules, confirm the following modules exist on this host: {0}' -f $($requiredModules -join ', '))
          Break
        }

        $reportPath = "$($pwd)\gporeport.xml"
        Get-GPOReport -All -ReportType xml -Path $reportPath
        [xml]$xmldoc = get-content $reportPath
    }
    elseif ($Path){
        # get the contents of the report file
        [xml]$xmldoc = get-content $Path
    }

    # get all the GPOs into an array
    $xmlgpos = $xmldoc.report.GPO

    # iterate over them running the selected checks
    foreach ($xmlgpo in $xmlgpos) {
        Invoke-AuditGPO -xmlgpo $xmlgpo -Level $level

        if ($gpoaudit -ne $false) {
            $gpoaudit
        }
    }

    $gpocount = ($xmlgpos.Count, 1 -ne $null)[0]

    Write-Title -Color "Green" -DividerChar "*" -Text "Stats"
    $stats = @()
    $stats += ('Display Level: {0}' -f $level)
    $stats += ('Displayed GPOs: {0}' -f $Global:displayedPols)
    $stats += ('Unlinked GPOs: {0}' -f $Global:unlinkedPols)
    $stats += ('Interesting Policy Settings: {0}' -f $Global:interestingPolSettings)
    $stats += ('Vulnerable Policy Settings: {0}' -f $Global:vulnerablePolSettings)
    $stats += ('Total GPOs: {0}' -f $gpocount)
    Write-Output $stats
}
