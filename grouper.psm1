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

# Some arrays of group names that are 'interesting', either because they are canonically 'low-priv' and huge numbers of accounts will be in them
# or because they are high-priv enough that members are very likely to have privileged access to a host, whole domain or a number of hosts.

# TODO ADD TO THIS LIST
$intPrivLocalGroups = @()
$intPrivLocalGroups += "Administrators"
$intPrivLocalGroups += "Backup Operators"
$intPrivLocalGroups += "Hyper-V Administrators"
$intPrivLocalGroups += "Power Users"
$intPrivLocalGroups += "Print Operators"
$intPrivLocalGroups += "Remote Desktop Users"
$intPrivLocalGroups += "Remote Management Users"

# TODO ADD TO THIS LIST?
$intLowPrivDomGroups = @()
$intLowPrivDomGroups += "Domain Users"
$intLowPrivDomGroups += "Authenticated Users"
$intLowPrivDomGroups += "Everyone"

# TODO ADD TO THIS LIST?
$intLowPrivLocalGroups = @()
$intLowPrivLocalGroups += "Users"
$intLowPrivLocalGroups += "Everyone"
$intLowPrivLocalGroups += "Authenticated Users"

# TODO ADD TO THIS LIST?
$intLowPrivGroups = @()
$intLowPrivGroups += "Domain Users"
$intLowPrivGroups += "Authenticated Users"
$intLowPrivGroups += "Everyone"
$intLowPrivGroups += "Users"

# TODO ADD TO THIS LIST
$intPrivDomGroups = @()
$intPrivDomGroups += "Domain Admins"
$intPrivDomGroups += "Administrators"
$intPrivDomGroups += "DNS Admins"
$intPrivDomGroups += "Backup Operators"
$intPrivDomGroups += "Enterprise Admins"
$intPrivDomGroups += "Schema Admins"
$intPrivDomGroups += "Server Operators"
$intPrivDomGroups += "Account Operators"

# THIS ONE IS FINE
$intRights = @()
$intRights += "SeTrustedCredManAccessPrivilege"
$intRights += "SeTcbPrivilege"
$intRights += "SeMachineAccountPrivilege"
$intRights += "SeBackupPrivilege"
$intRights += "SeCreateTokenPrivilege"
$intRights += "SeAssignPrimaryTokenPrivilege"
$intRights += "SeRestorePrivilege"
$intRights += "SeDebugPrivilege"
$intRights += "SeTakeOwnershipPrivilege"
$intRights += "SeCreateGlobalPrivilege"
$intRights += "SeLoadDriverPrivilege"
$intRights += "SeRemoteInteractiveLogonRight"

$boringTrustees = @()
$boringTrustees += "BUILTIN\Administrators"
$boringTrustees += "NT AUTHORITY\SYSTEM"

#____________________ GPO Check functions _______________

# There's a whole pile of these functions. Each one consumes a single <GPO> object from a Get-GPOReport XML report,
# then depending on the -Level parameter it should output interesting/vulnerable/any policy it can process.
# The rule of thumb for whether a check function should exist at all is "Does this class of policy have any possible settings with security impact?"
# The rule of thumb for whether a setting is "Vulnerable" enough for Level 3 is "If it is likely to result in large numbers of users or the current user
# being able to get a shell or an RDP session on a host".
# The rule of thumb for whether a setting is "Interesting" enough for Level 2 is "if it could meet the criteria for Level 3 but Grouper can't tell
# whether it does without user intervention."
# At the moment Level 1 is pretty much just showing all the settings that Grouper can parse, but in the future it should filter out settings that
# have been configured 'securely', where there is a clear best-practice option.

Function Get-GPOUsers {
    [cmdletbinding()]
    # Consumes a single <GPO> object from a Get-GPOReport XML report.

    ######
    # Description: Checks for changes made to local users.
    # Level 3: Only show instances where a password has been set, i.e. GPP Passwords.
    # Level 2: All users and all changes.
    # Level 1: All users and all changes.
    ######

    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    $GPOisinteresting = $false
    $GPOisvulnerable = $false

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
                $GPOisvulnerable = $true

                # decrypt it with harmj0y's function
                $cpasswordclear = Get-DecryptedCpassword -Cpassword $cpasswordcrypt
            }
            #if so, or if we're showing boring, show the rest of the setting
            if (($cpasswordcrypt) -Or ($level -le 2)) {
                $GPOisinteresting = $true
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
                Write-NoEmpties -output $output
                "`r`n"
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
    }
    if ($GPOisvulnerable) {
        $Global:GPOsWithVulnSettings += 1
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
    # Level 3: If Domain Users, Everyone, Authenticated Users get added to 'interesting groups'.
    # Level 2: Show changes to groups that grant meaningful security-relevant access.
    # Level 1: All groups and all changes.
    ######

    $GPOIsInteresting = $false
    $GPOIsVulnerable = $false

    $settingsGroups = ($polXml.ExtensionData.Extension.LocalUsersAndGroups.Group | Sort-Object GPOSettingOrder)

    if ($settingsGroups) {
	    foreach ($setting in $settingsGroups) {
            $settingIsInteresting = $false
            $settingIsVulnerable = $false
            $groupIsInteresting = $false

            # check if the group being modified is one of the high-priv local groups array,
            $groupName = $setting.properties.groupName
            if ($intPrivLocalGroups -Contains $groupName) {
                $GPOIsInteresting = $true
                $settingIsInteresting = $true
                $groupIsInteresting = $true
            }

            # if it's in that array AND a member being modified is a low-priv domain group, we flag the setting as vulnerable.
            $groupmembers = $setting.properties.members.member
            foreach ($groupmember in $groupmembers) {
                $groupMemberName = $groupmember.name
                foreach ($lowPrivDomGroup in $intLowPrivDomGroups) {
                    if (($groupMemberName -match $lowPrivDomGroup) -And ($groupIsInteresting)){
                        $settingIsVulnerable = $true
                        $GPOIsVulnerable = $true
                    }
                }
            }

            if ((($settingIsVulnerable) -And ($level -le 3)) -Or (($settingIsInteresting) -And ($level -le 2)) -Or ($level -eq 1)) {
                $output = @{}
                $output.Add("Name", $setting.Name)
                $output.Add("NewName", $setting.properties.NewName)
                $output.Add("Description", $setting.properties.Description)
                $output.Add("Group Name", $groupName)
                Write-NoEmpties -output $output

                foreach ($member in $setting.properties.members.member) {
                    $output = @{}
                    $output.Add("Name", $member.name)
                    $output.Add("Action", $member.action)
                    $output.Add("UserName", $member.userName)
                    Write-NoEmpties -output $output
                }
                "`r`n"
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
    }
    if ($GPOIsVulnerable) {
        $Global:GPOsWithVulnSettings += 1
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
    # Level 3: Only show "Interesting" rights, i.e. those that can be used for local privilege escalation or remote access,
    #             and only if they've been assigned to Domain Users, Authenticated Users, or Everyone.
    # Level 2: Only show "Interesting" rights, i.e. those that can be used for local privilege escalation or remote access.
    # Level 1: All non-default.
    ######

    $GPOIsInteresting = $false
    $GPOIsVulnerable = $false

    $uraSettings = ($polXml.Computer.ExtensionData.Extension.UserRightsAssignment)

    $uraSettings = ($uraSettings | ? {$_}) #Strips null elements from array - nfi why I was getting so many of these.

    if ($uraSettings) {
        foreach ($setting in $uraSettings) {
            $settingIsInteresting = $false
            $settingIsVulnerable = $false
            $rightIsInteresting = $false

            $userRight = $setting.Name

            $members = @()
            foreach ($member in $setting.Member) {
                $members += ($member.Name.Innertext)
            }

            # if the right being assigned is in our array of interesting rights, the setting is interesting.
            if ($intRights -contains $userRight) {
                $GPOisinteresting = $true
                $settingIsInteresting = $true
                $rightIsInteresting = $true
            }

            # then we construct an array of trustees being granted the right, so we can see if they are in any of our interesting low priv groups.
            if ($rightIsInteresting) {
                foreach ($lowPrivGroup in $intLowPrivGroups) {
                    foreach ($member in $members) {
                        if ($member -match $lowPrivGroup) {
                            $GPOIsVulnerable = $true
                            $settingIsVulnerable = $true
                        }
                    }
                }
            }

            if ((($settingIsVulnerable) -And ($level -le 3)) -Or (($settingIsInteresting) -And ($level -le 2)) -Or ($level -eq 1)) {
                $output = @{}
                $output.Add("Right", $userRight)
                $output.Add("Members", $members -join ',')
                Write-NoEmpties -output $output
                "`r`n"
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
    }

    if ($GPOIsVulnerable) {
        $Global:GPOsWithVulnSettings += 1
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
    # Level 3: Only show instances where a password has been set.
    # Level 2: TODO If a password has been set or the thing being run is non-local or there are arguments set.
    # Level 1: All scheduled tasks.
    ######

    $GPOisinteresting = $false
    $GPOisvulnerable = $false

    $settingsSchedTasks = ($polXml.Computer.ExtensionData.Extension.ScheduledTasks.Task | Sort-Object GPOSettingOrder)

    if ($settingsSchedTasks) {
        foreach ($setting in $settingsSchedTasks) {
            #see if we have any stored encrypted passwords
            $cpasswordcrypt = $setting.properties.cpassword
            if ($cpasswordcrypt) {
                $GPOisvulnerable = $true
                $GPOisinteresting = $true

                # decrypt it with harmj0y's function
                $cpasswordclear = Get-DecryptedCpassword -Cpassword $cpasswordcrypt
            }
            #see if any arguments have been set
            $taskArgs = $setting.Properties.args
            if ($taskArgs) {
                $GPOisinteresting = $true
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
                Write-NoEmpties -output $output

                if ($setting.Properties.Triggers) {
                    foreach ($trigger in $setting.Properties.Triggers) {
                        $output = @{}
                        $output.Add("type", $trigger.Trigger.type)
                        $output.Add("startHour", $trigger.Trigger.startHour)
                        $output.Add("startMinutes", $trigger.Trigger.startMinutes)
                        Write-NoEmpties -output $output
                        "`r`n"
                    }
                }
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
    }

    if ($GPOisvulnerable) {
        $Global:GPOsWithVulnSettings += 1
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
    # Level 3: TODO Only show instances where the file is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Level 2: All MSI installations.
    # Level 1: All MSI installations.
    ######

	$MSIInstallation = ($polXml.ExtensionData.Extension.MsiApplication | Sort-Object GPOSettingOrder)

    if ($MSIInstallation) {
        $GPOisinteresting = $true
        $GPOisvulnerable = $false

 	    foreach ($setting in $MSIInstallation) {
            $output = @{}
            $MSIPath = $setting.Path
            $output.Add("Name", $setting.Name)
            $output.Add("Path", $MSIPath)

            if ($Global:onlineChecks) {
                if ($MSIPath.StartsWith("\\")) {
                    $ACLData = Find-IntACL -Path $MSIPath
                    $output.Add("Owner",$ACLData["Owner"])
                    if ($ACLData["Vulnerable"] -eq "True") {
                        $settingIsVulnerable = $true
                        $GPOisvulnerable = $true
                        $output.Add("[!]", "Source file writable by current user!")
                    }
                    $MSIPathAccess = $ACLData["Trustees"]
                }
            }

            if (($level -le 2) -Or (($level -le 3) -And ($settingisVulnerable))) {
                Write-NoEmpties -output $output
                ""
                if ($MSIPathAccess) {
                    Write-Title -Text "Permissions on source file:" -DividerChar "-"
                    Write-Output $MSIPathAccess
                    ""
                }
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
    }
    if ($GPOisvulnerable) {
        $Global:GPOsWithVulnSettings += 1
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
    # Level 3: TODO Only show instances where the file is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Level 2: All scripts.
    # Level 1: All scripts.
    ######

	$settingsScripts = ($polXml.ExtensionData.Extension.Script | Sort-Object GPOSettingOrder)

    if ($settingsScripts) {
        $GPOisinteresting = $true
        $GPOisvulnerable = $false

        foreach ($setting in $settingsScripts) {
            $commandPath = $setting.Command
            $output = @{}
            $output.Add("Command", $commandPath)
            $output.Add("Type", $setting.Type)
            $output.Add("Parameters", $setting.Parameters)
            $settingIsVulnerable = $false

            if ($Global:onlineChecks) {
                if ($commandPath.StartsWith("\\")) {
                    $ACLData = Find-IntACL -Path $commandPath
                    $output.Add("Owner",$ACLData["Owner"])
                    if ($ACLData["Vulnerable"] -eq "True") {
                        $settingIsVulnerable = $true
                        $GPOisvulnerable = $true
                        $output.Add("[!]", "Source file writable by current user!")
                    }
                    $commandPathAccess = $ACLData["Trustees"]
                }
            }

            if (($level -le 2) -Or (($level -le 3) -And ($settingisVulnerable))) {
                Write-NoEmpties -output $output
                ""
                if ($commandPathAccess) {
                    Write-Title -Text "Permissions on source file:" -DividerChar "-"
                    Write-Output $commandPathAccess
                    ""
                }
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
    }
    if ($GPOisvulnerable) {
        $Global:GPOsWithVulnSettings += 1
    }

}

Function Get-GPOFileUpdate {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    ######
    # Description: Checks for files being copied/updated/whatever.
    # Level 3: TODO Only show instances where the 'fromPath' file is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Level 2: All File Updates where FromPath is a network share
    # Level 1: All File Updates.
    ######

	$settingsFiles = ($polXml.ExtensionData.Extension.FilesSettings | Sort-Object GPOSettingOrder)

    if ($settingsFiles) {
        $GPOisinteresting = $true
        $GPOisvulnerable = $false
 	    foreach ($setting in $settingsFiles.File) {
            $fromPath = $setting.Properties.fromPath
            $targetPath = $setting.Properties.targetPath
            $output = @{}
            $output.Add("Name", $setting.name)
            $output.Add("Action", $setting.Properties.action)
            $output.Add("fromPath", $fromPath)
            $output.Add("targetPath", $targetPath)
            $settingIsVulnerable = $false

            if ($Global:onlineChecks) {
                if ($fromPath.StartsWith("\\")) {
                    $ACLData = Find-IntACL -Path $fromPath
                    $output.Add("Owner",$ACLData["Owner"])
                    if ($ACLData["Vulnerable"] -eq "True") {
                        $settingIsVulnerable = $true
                        $GPOisvulnerable = $true
                        $output.Add("[!]", "Source file writable by current user!")
                    }
                    $fromPathAccess = $ACLData["Trustees"]
                }
            }

            if (($level -le 2) -Or (($level -le 3) -And ($settingisVulnerable))) {
                Write-NoEmpties -output $output
                ""
                if ($fromPathAccess) {
                    Write-Title -Text "Permissions on source file:" -DividerChar "-"
                    Write-Output $fromPathAccess
                    ""
                }
            }
        }
    }
    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
    }
    if ($GPOisvulnerable) {
        $Global:GPOsWithVulnSettings += 1
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
    # Level 3: TODO Only show instances where the file is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Level 2: TODO Also show instances where any user/group other than the usual default Domain/Enterprise Admins has 'Full Control'.
    # Level 1: All file permission changes.
    ######

	$settingsFilePerms = ($polXml.Computer.ExtensionData.Extension.File | Sort-Object GPOSettingOrder)

    if ($settingsFilePerms) {
 	    foreach ($setting in $settingsFilePerms) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Path", $setting.Path)
                $output.Add("SDDL", $setting.SecurityDescriptor.SDDL.innertext)
                Write-NoEmpties -output $output
                "`r`n"
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
    # Level 3: TODO.
    # Level 2: Show everything that matches $intKeyNames or $intSysAccPolName.
    # Level 1: All settings.
    ######

    $GPOisinteresting = $false
	$settingsSecurityOptions = ($polXml.Computer.ExtensionData.Extension.SecurityOptions | Sort-Object GPOSettingOrder)

    if ($settingsSecurityOptions) {
        if ($level -le 2) {
            $intKeyNameBools = @{}
            $intKeyNameBools.Add("MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds", "false")
            $intKeyNameBools.Add("MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous", "true")
            $intKeyNameBools.Add("MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse", "false")
            $intKeyNameBools.Add("MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash", "false")
            $intKeyNameBools.Add("MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous", "false")
            $intKeyNameBools.Add("MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM", "false")
            $intKeyNameBools.Add("MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl", "true")
            $intKeyNameBools.Add("MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId", "true")
            $intKeyNameBools.Add("MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers", "false")

            $intKeyNameLists = @()
            $intKeyNameLists += "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine"
            $intKeyNameLists += "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine"
            $intKeyNameLists += "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes"
            $intKeyNameLists += "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares"
            $intKeyNameLists += "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess"

            $intSysAccPolBools = @{}
            $intSysAccPolBools.Add("EnableGuestAccount", 1)
            $intSysAccPolBools.Add("EnableAdminAccount", 1)
            $intSysAccPolBools.Add("LSAAnonymousNameLookup", 1)

            $intSysAccPolStrings = @{}
            $intSysAccPolStrings.Add("NewAdministratorName", "")
            $intSysAccPolStrings.Add("NewGuestName", "")

     	    foreach ($setting in $settingsSecurityOptions) {
            #Check if it's a registry based option
                if ($setting.KeyName) {
                    $keyname = $setting.KeyName
                    $output = @{}
                    $values = @{}
                    $foundit = 0
                    if ($foundit -eq 0) {
                        if ($intKeyNameLists -contains $keyname) {
                            $GPOisinteresting = $true
                            $foundit = 1
                            $output.Add("Name", $setting.Display.Name)
                            $output.Add("KeyName", $setting.KeyName)
                            $dispstrings = $setting.Display.DisplayStrings.Value
                            #here we have to iterate over the list of values
                            $i = 0
                            foreach ($dispstring in $dispstrings) {
                                $values.Add("Path/Pipe$i", $dispstring)
                                $i += 1
                            }
                            Write-NoEmpties -output $output
                            Write-NoEmpties -output $values
                            "`r`n"
                        }
                    }
                    if ($foundit -eq 0) {
                        foreach ($intKeyNameBool in $intKeyNamesBools) {
                            if (($keyNameBool.ContainsKey($keyname)) -And ($keyNameBool.ContainsValue($setting.Display.DisplayBoolean))) {
                                $GPOIsInteresting =1
                                $foundit = 1
                                $output.Add("Name", $setting.Display.Name)
                                $output.Add("KeyName", $setting.KeyName)
                                $values.Add("DisplayBoolean", $setting.Display.Displayboolean)
                                Write-NoEmpties -output $output
                                Write-NoEmpties -output $values
                                "`r`n"
                            }
                        }
                    }
                }
                # or a 'system access policy name'
                elseif ($setting.SystemAccessPolicyName) {
                    $output = @{}
                    foreach ($SAP in $intSysAccPolBools) {
                        if (($SAP.ContainsKey($setting.SystemAccessPolicyName)) -And ($SAP.ContainsValue($setting.SettingNumber))) {
                            $output.Add("Name", $setting.SystemAccessPolicyName)
                            $output.Add("SettingNumber",$setting.SettingNumber)
                            $GPOisinteresting = $true
                            Write-NoEmpties -output $output
                            "`r`n"
                        }
                    }
                    foreach ($SAP in $intSysAccPolStrings) {
                        if ($SAP.ContainsKey($setting.SystemAccessPolicyName)) {
                            $output.Add("Name", $setting.SystemAccessPolicyName)
                            $output.Add("SettingString",$setting.SettingString)
                            $GPOisinteresting = $true
                            Write-NoEmpties -output $output
                            "`r`n"
                        }
                    }
                }
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
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
    # Level 3: Any key that matches '$intKeys'.
    # Level 2: TODO Also show instances containing the strings 'pass', 'pwd', 'cred', or 'vnc'.
    # Level 1: All Registry Keys
    ######

    $GPOisinteresting = $false
    $GPOisvulnerable = $false

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
            $settingisInteresting = $false
            $settingIsVulnerable = $false

            if ($vulnKeys -Contains $settingkey) {
                $GPOisvulnerable = $true
                $settingIsVulnerable = $true
            }

            foreach ($intWord in $intWords) {
                # if either key or value include our interesting words as a substring, mark the setting as interesting
                if (($settingkey -match $intWord) -Or ($settingValue -match $intWord)) {
                    $GPOisinteresting = $true
                    $settingisInteresting = $true
                }
            }

            # if setting matches any of our criteria for printing (combined interest level + output level)
            if ((($settingisVulnerable) -And ($level -le 3)) -Or (($settingisInteresting) -And ($level -le 2)) -Or ($level -eq 1)) {
                $output = @{}
                $output.Add("Key", $settingkey)
                $output.Add("Action", $setting.Properties.action)
                $output.Add("Hive", $setting.Properties.hive)
                $output.Add("Name", $setting.Properties.name)
                $output.Add("Value", $setting.Properties.value)
                Write-NoEmpties -output $output
                "`r`n"
            }
        }
    }

    # update the global counters
    if ($GPOisivulnerable) {
        $Global:GPOsWithVulnSettings += 1
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
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
    # Level 3: TODO Only show instances where DestPath is writable by the current user or 'Everyone' or 'Domain Users' or 'Authenticated Users'.
    # Level 2: TODO Also show instances where any user/group other than the usual default Domain/Enterprise Admins has 'Full Control'.
    # Level 1: All Folder Redirection.
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
                Write-NoEmpties -output $output
                "`r`n"
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
    # Level 3: TODO
    # Level 2: If it matches our list of interesting settings - undecided if i want to include weak password policy here.
    # Level 1: All Account Settings.
    ######

	$settingsAccount = ($polXml.Computer.ExtensionData.Extension.Account | Sort-Object GPOSettingOrder)

    $GPOisinteresting = $false

    $intAccSettingBools = @{}
    $intAccSettingBools.Add("ClearTextPassword","true")

    if ($settingsAccount) {
	    foreach ($setting in $settingsAccount) {
            $settingName = $setting.Name
            $settingisInteresting = $false

            foreach ($intAccSetting in $intAccSettingBools) {
                if (($intAccSetting.ContainsKey($settingName)) -And ($intAccSetting.containsValue($setting.SettingBoolean))) {
                    $settingisInteresting = $true
                    $GPOisinteresting = $true
                }
            }

            if (($level -eq 1) -Or (($settingisInteresting) -And ($level -le 2))) {
                $output = @{}
                $output.Add("Name", $settingName)
                if ($setting.SettingBoolean) {
                    $output.Add("SettingBoolean", $setting.SettingBoolean)
                }
                if ($setting.SettingNumber) {
                    $output.Add("SettingNumber", $setting.SettingNumber)
                }
                $output.Add("Type", $setting.Type)
                Write-NoEmpties -output $output
                "`r`n"
            }
        }
    }

    # update the global counters
    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
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
    # Level 3: TODO
    # Level 2: TODO Need to generate a list of 'interesting' settings.
    # Level 1: All folders changes.
    ######

	$settingsFolders = ($polXml.ExtensionData.Extension.Folders.Folder | Sort-Object GPOSettingOrder)

    if ($settingsFolders) {
	    foreach ($setting in $settingsFolders) {
            if ($level -eq 1) {
                $output = @{}
                $output.Add("Name", $setting.name)
                $output.Add("Action", $setting.Properties.action)
                $output.Add("Path", $setting.Properties.path)
                Write-NoEmpties -output $output
                "`r`n"
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
    # Level 3: TODO
    # Level 2: All Network Shares.
    # Level 1: All Network Shares.
    ######

    $GPOisinteresting = $false

	$settingsNetShares = ($polXml.Computer.ExtensionData.Extension.NetworkShares.Netshare | Sort-Object GPOSettingOrder)

    if ($settingsNetShares) {
	    foreach ($setting in $settingsNetShares) {
            if ($level -le 2) {
                $GPOisinteresting = $true
                $output = @{}
                $output.Add("Name", $setting.name)
                $output.Add("Action", $setting.Properties.action)
                $output.Add("PropName", $setting.Properties.name)
                $output.Add("Path", $setting.Properties.path)
                $output.Add("Comment", $setting.Properties.comment)
                Write-NoEmpties -output $output
                "`r`n"
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
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
    # Level 3: TODO
    # Level 2: TODO Need to generate a list of 'interesting' settings.
    # Level 1: All .INI file changes.
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
                Write-NoEmpties -output $output
                "`r`n"
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
    # Level 3: TODO
    # Level 2: TODO Need to generate a list of 'interesting' settings.
    # Level 1: All environment variables.
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
                Write-NoEmpties -output $output
                "`r`n"
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
    # Level 3: TBD.
    # Level 2: Need to generate a list of 'interesting' settings.
    # Level 1: All Registry Settings.
    ######

	$settingsRegSettings = ($polXml.ExtensionData.Extension.Policy | Sort-Object GPOSettingOrder)

    if ($settingsRegSettings) {

        $intRegSettings = @()
        $intRegSettings += "Allow CredSSP authentication"
        $intRegSettings += "Allow Basic Authentication"
        $intRegSettings += "Set the default source path for Update-Help"
        $intRegSettings += "Default Source Path"
        $intRegSettings += "Allow remote server management through WinRM"
        $intRegSettings += "Specify intranet Microsoft update service location"
        $intRegSettings += "Set the intranet update service for detecting updates:"
        $intRegSettings += "Set the intranet statistics server:"
        $intRegSettings += "Allow Remote Shell Access"
        $intRegSettings += "Allow unencrypted traffic"
        $intRegSettings += "Sign-in last interactive user automatically after a system-initiated restart"
        $intRegSettings += "Intranet proxy servers for  apps"
        $intRegSettings += "Type a proxy server IP address for the intranet"
        $intRegSettings += "Internet proxy servers for apps"
        $intRegSettings += "Domain Proxies"
        $intRegSettings += "Restrict Unauthenticated RPC clients"
        $intRegSettings += "RPC Runtime Unauthenticated Client Restriction to Apply"
        $intRegSettings += "Enable RPC Endpoint Mapper Client Authentication"
        $intRegSettings += "Always install with elevated privileges"
        $intRegSettings += "Specify communities"
        $intRegSettings += "Communities"
        $intRegSettings += "Allow non-administrators to install drivers for these device setup classes"
        $intRegSettings += "Allow Users to install device drivers for these classes:"

        $vulnRegSettings = @()
        $vulnRegSettings += "Always install with elevated privileges"
        $vulnRegSettings += "Specify communities"
        $vulnRegSettings += "Communities"
        $vulnRegSettings += "Allow non-administrators to install drivers for these device setup classes"
        $vulnRegSettings += "Allow Users to install device drivers for these classes:"


        # I hate this nested looping shit more than anything I've ever written.
        foreach ($setting in $settingsRegSettings) {
            if ($true) {
                $output = @{}
                $output.Add("Setting Name", $setting.Name)
                $output.Add("State", $setting.State)
                $output.Add("Supported", $setting.Supported)
                $output.Add("Category", $setting.Category)
                $output.Add("Explain", $setting.Explain)

                if (($level -eq 1) -Or (($level -eq 2) -And ($intRegSettings -Contains $setting.Name)) -Or (($level -eq 3) -And ($vulnRegSettings -Contains $setting.Name))) {
                    Write-NoEmpties -output $output

                    foreach ($thing in $setting.EditText) {
                        $output = @{}
                        $output.Add("Name", $thing.Name)
                        $output.Add("Value", $thing.Value)
                        $output.Add("State", $thing.State)
                        Write-NoEmpties -output $output
                    }

                    foreach ($thing in $setting.DropDownList) {
                        $output = @{}
                        $output.Add("Name", $thing.Name)
                        $output.Add("Value", $thing.Value.Name)
                        $output.Add("State", $thing.State)
                        Write-NoEmpties -output $output
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
                        Write-NoEmpties -output $output
                    }

                    foreach ($thing in $setting.Checkbox) {
                        $output = @{}
                        $output.Add("Value", $thing.Name)
                        $output.Add("State", $thing.State)
                        Write-NoEmpties -output $output
                    }

                    foreach ($thing in $setting.Numeric) {
                        $output = @{}
                        $output.Add("Name", $thing.Name)
                        $output.Add("Value", $thing.Value)
                        $output.Add("State", $thing.State)
                        Write-NoEmpties -output $output
                    }
                    Write-Output "`r`n"
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
    # Level 3: Only show instances where current user can write to target of shortcut.
    # Level 2: All shortcut settings that reference a network path.
    # Level 1: All shortcut settings.
    ######

    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    # Grab an array of the settings we're interested in from the GPO.
    $settingsShortcuts = ($polXml.ExtensionData.Extension.ShortcutSettings.Shortcut | Sort-Object GPOSettingOrder)
    # Check if there's actually anything in the array.
    if ($settingsShortcuts) {
        $GPOisinteresting = $false
        $GPOisvulnerable = $false
        # Iterate over array of settings, writing out only those we care about.
        foreach ($setting in $settingsShortcuts) {
            $settingisInteresting = $false
            $targetPath = $setting.properties.targetPath
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
            if ($Global:onlineChecks) {
                if ($targetPath.StartsWith("\\")) {
                    $settingisInteresting = $true
                    $GPOisinteresting = $true
                    $ACLData = Find-IntACL -Path $targetPath
                    $output.Add("Owner",$ACLData["Owner"])
                    if ($ACLData["Vulnerable"] -eq "True") {
                        $settingIsVulnerable = $true
                        $GPOisvulnerable = $true
                        $output.Add("[!]", "Source file writable by current user!")
                    }
                    $targetPathAccess = $ACLData["Trustees"]
                }
            }

            if (($level -eq 1) -Or (($level -le 2) -And ($settingisInteresting)) -Or (($level -le 3) -And ($settingisVulnerable))) {
                Write-NoEmpties -output $output
                ""
                if ($targetPathAccess) {
                    Write-Title -Text "Permissions on source file:" -DividerChar "-"
                    Write-Output $targetPathAccess
                    "`r`n"
                }
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
    }
    if ($GPOisvulnerable) {
        $Global:GPOsWithVulnSettings += 1
    }
}

#################################
#
#
#
#
#   Here endeth the gross GPO check functions!
#
#
#
#
#
#################################

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

Function Write-NoEmpties {
    Param (
        $output
    )
    # this function literally just prints hash tables but skips any with an empty value.
    Foreach ($outpair in $output.GetEnumerator()) {
                    if (-Not (("", $null) -Contains $outpair.Value)) {
                        Write-Output ($outpair)
                    }
                }
}

Function Write-ColorText {
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Text,
        [Parameter(Mandatory=$false)][ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White', ignorecase=$true)] [string]$Color = $host.ui.RawUI.ForegroundColor
    )
    # does what it says on the tin - writes text in colour.
    $DefForegroundColor = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = $Color
    Write-Output $Text
    $host.ui.RawUI.ForegroundColor = $DefForegroundColor
}

Function Write-Title {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Text,
        [Parameter(Mandatory=$false)][ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White', ignorecase=$true)] [string]$Color = $host.ui.RawUI.ForegroundColor,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][string]$DividerChar = "-"
    )
    Write-ColorText -Text $Text -Color $Color
    $divider = $DividerChar * $Text.Length
    Write-ColorText -Text $divider -Color $Color
}

Function Write-Banner {

    $barf = @'
  .,-:::::/ :::::::..       ...      ...    :::::::::::::. .,:::::: :::::::..
,;;-'````'  ;;;;``;;;;   .;;;;;;;.   ;;     ;;; `;;;```.;;;;;;;'''' ;;;;``;;;;
[[[   [[[[[[/[[[,/[[['  ,[[     \[[,[['     [[[  `]]nnn]]'  [[cccc   [[[,/[[['
"$$c.    "$$ $$$$$$c    $$$,     $$$$$      $$$   $$$""     $$""""   $$$$$$c
 `Y8bo,,,o88o888b "88bo,"888,_ _,88P88    .d888   888o      888oo,__ 888b "88bo,
   `'YMUP"YMMMMMM   "W"   "YMMMMMP"  "YmmMMMM""   YMMMb     """"YUMMMMMMM   "W"
                                                            github.com/mikeloss
                                                            @mikeloss
'@ -split "`n"

    $Pattern = ('White','Yellow','Red','Red','DarkRed','DarkRed','White','White')
    ""
    ""
    $i = 0
    foreach ($barfline in $barf) {
        Write-ColorText -Text $barfline -Color $Pattern[$i]
        $i += 1
    }
}

Function Find-IntACL {
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Path
    )
    # Consumes a file path, returns a hash table containing the owner, a hash table of trustees, and a value for
    # "Vulnerable" to show if current user can write the target file, determined by attempting to open the target
    # file for writing, then immediately closing it.
    $ACLData = @{}
    try {
        $targetPathACL = Get-ACL $Path -ErrorAction Stop
        $targetPathOwner = $targetPathACL.Owner
        $targetPathAccess = $targetPathACL.Access | Where-Object {-Not ($boringTrustees -Contains $_.IdentityReference)} | select FileSystemRights,AccessControlType,IdentityReference
        $ACLData.Add("Owner", $targetPathOwner)
        $ACLData.Add("Trustees", $targetPathAccess)
        Try {
            [io.file]::OpenWrite($targetPath).close()
            $ACLData.Add("Vulnerable","True")
        }
        Catch {
            $ACLData.Add("Vulnerable","False")
        }
    }
    catch [System.Exception] {
        $ACLData.Add("Vulnerable","Error")
    }
    return $ACLData
}

#_____________________________________________________________________
Function Invoke-AuditGPO {
    [cmdletbinding()]
    # Consumes <GPO> objects from a Get-GPOReport xml report and returns findings based on the $level filter.
    Param (
        [Parameter(Mandatory=$true)][System.Xml.XmlElement]$xmlgpo,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )

    #check the GPO is even enabled
    $gpoisenabled = $xmlgpo.LinksTo.Enabled
    #and if it's not, increment our count of GPOs that don't do anything
    if (($gpoisenabled -ne "true") -And (!$Global:showdisabled)) {
        $Global:unlinkedPols += 1
        return $null
    }

    #check if it's linked somewhere
    $gpopath = $xmlgpo.LinksTo.SOMName
    #and if it's not, increment our count of GPOs that don't do anything
    if ((-Not $gpopath) -And (!$Global:showdisabled)) {
        $Global:unlinkedPols += 1
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
    $polchecks += {Get-GPOMSIInstallation -Level $level -polXML $userSettings}
    $polchecks += {Get-GPOMSIInstallation -Level $level -polXML $computerSettings}
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
    $headers += {'Policy created on: {0:G}' -f ([DateTime]$xmlgpo.CreatedTime)}
    $headers += {'Policy last modified: {0:G}' -f ([DateTime]$xmlgpo.ModifiedTime)}
    $headers += {'Policy owner: {0}' -f $xmlgpo.SecurityDescriptor.Owner.Name.InnerText}
    $headers += {'Linked OU: {0}' -f $gpopath}
    $headers += {'Link enabled: {0}' -f $gpoisenabled}
    $headers += {'==============================================================='}

    # In each GPO we parse, iterate through the list of checks to see if any of them return anything.
    $headerprinted = $false
    foreach ($polcheck in $polchecks) {
        $finding = & $polcheck # run the check and store the output
        if ($finding) {
            # the first time one of the checks returns something, show the user the header with the policy name and so on
            if (!$headerprinted) {
                # Increment the total counter of displayed policies.
                $Global:displayedPols += 1
                # Write the title of the GPO in nice green text
                Write-ColorText -Color "Green" -Text $xmlgpo.Name
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
                    $ACEInteresting = $true # ACEs are default interesting unless proven boring.

                    # check if our trustee is a 'boring' default one
                    if ($trusteeName) {
                        foreach ($boringTrustee in $boringTrustees) {
                            if ($trusteeName -match $boringTrustee) {
                                $ACEInteresting = $false
                            }
                        }
                    }
                    # check if our permission is boring
                    if (($boringPerms -Contains $ACEType) -Or ($GPOACE.Type.PermissionType -eq "Deny")){
                        $ACEInteresting = $false
                    }

                    # if it's still interesting,
                    if ($ACEInteresting) {
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
                # then print out the GPO's permissions
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
    [cmdletbinding(DefaultParameterSetName='NoArgs')]
    param(
        [Parameter(ParameterSetName='WithFile', Mandatory=$true, HelpMessage="Path to XML GPO report")]
        [Parameter(ParameterSetName='OnlineDomain', Mandatory=$false, HelpMessage="Path to XML GPO report")]
        [ValidateScript({if(Test-Path $_ -PathType 'Leaf'){$true}else{Throw "Invalid path given: $_"}})]
        [ValidateScript({if($_ -Match '\.xml'){$true}else{Throw "Supplied file is not XML: $_"}})]
        [System.IO.FileInfo]$Path,

        [Parameter(ParameterSetName='WithFile', Mandatory=$false, HelpMessage="Toggle filtering GPOs that aren't linked anywhere")]
        [Parameter(ParameterSetName='WithoutFile', Mandatory=$false, HelpMessage="Toggle filtering GPOs that aren't linked anywhere")]
        [Parameter(ParameterSetName='OnlineDomain', Mandatory=$false, HelpMessage="Toggle filtering GPOs that aren't linked anywhere")]
        [switch]$showDisabled,

        [Parameter(ParameterSetName='WithFile', Mandatory=$false, HelpMessage="Set verbosity level (1 = most verbose, 3 = only show things that are definitely bad)")]
        [Parameter(ParameterSetName='WithoutFile', Mandatory=$false, HelpMessage="Set verbosity level (1 = most verbose, 3 = only show things that are definitely bad)")]
        [Parameter(ParameterSetName='OnlineDomain', Mandatory=$false, HelpMessage="Set verbosity level (1 = most verbose, 3 = only show things that are definitely bad)")]
        [ValidateSet(1,2,3)]
        [int]$level = 2,

        [Parameter(ParameterSetName='OnlineDomain', Mandatory=$true, HelpMessage="Perform online checks by actively contacting DCs within the target domain")]
        [switch]$online,

        [Parameter(ParameterSetName='OnlineDomain', Mandatory=$false, HelpMessage="FQDN for the domain to target for online checks")]
        [ValidateNotNullOrEmpty()]
        [string]$domain = $env:UserDomain
    )

    # This sucker actually consumes the file, does the stuff, this is the guy, you know?

    Write-Banner

    if ($PSVersionTable.PSVersion.Major -le 2) {
        Write-ColorText -Color "Red" -Text "Sorry, Grouper is not yet compatible with PowerShell 2.0."
        break
    }

    #check if an xml report is specified, otherwise try to generate the report using Get-GPOReport
    if ($Path -eq $null) {
        $lazyMode = $true
    }

    # couple of counters for the stats at the end
    $Global:unlinkedPols = 0
    $Global:GPOsWithIntSettings = 0
    $Global:GPOsWithVulnSettings = 0
    $Global:displayedPols = 0

    #handle our arguments
    $Global:showDisabled = $false
    if ($showDisabled) {
        $Global:showDisabled = $true
    }

    # quick and dirty check to make sure that if the user said to do 'online' checks that we can actually reach the domain.
    $Global:onlineChecks = $false
    if ($online) {
        if ((Test-Path "\\$($domain)\SYSVOL") -eq $true) {
            Write-ColorText -Text "`r`n[i] Confirmed connectivity to AD domain $domain, including online-only checks.`r`n" -Color "Green"
            $Global:onlineChecks = $true
        }
        else {
            Write-ColorText -Text "`r`n[!] Couldn't talk to the domain $domain, falling back to offline mode.`r`n" -Color "Red"
            $Global:onlineChecks = $False
        }
    }

    # if the user set $lazyMode, confirm that the relevant module is available, then generate a gporeport using some default settings.
    if ($lazyMode) {
        $requiredModules = @('GroupPolicy')
        $requiredModules | Import-Module -Verbose:$false -ErrorAction SilentlyContinue
        if (($requiredModules | Get-Module) -eq $null) {
          Write-Warning ('[!] Could not import required modules, confirm the following modules exist on this host: {0}' -f $($requiredModules -join ', '))
          Break
        }

        if ($PSBoundParameters.Domain) {
          $reportPath = "$($pwd)\$($domain)_gporeport.xml"
          Get-GPOReport -All -ReportType xml -Path $reportPath -Domain $domain
        }
        else {
          $reportPath = "$($pwd)\gporeport.xml"
          Get-GPOReport -All -ReportType xml -Path $reportPath
        }
        [xml]$xmldoc = get-content $reportPath
    }
    # and if the user didn't set $lazyMode, get the contents of the report they asked us to look at
    elseif ($Path){
        # get the contents of the report file
        [xml]$xmldoc = get-content $Path
    }

    # get all the GPOs into an array
    $xmlgpos = $xmldoc.report.GPO

    # iterate over them running the selected checks
    foreach ($xmlgpo in $xmlgpos) {
        Invoke-AuditGPO -xmlgpo $xmlgpo -Level $level
    }

    $gpocount = ($xmlgpos.Count, 1 -ne $null)[0]

    Write-Title -Color "Green" -DividerChar "*" -Text "Stats"
    $stats = @()
    $stats += ('Display Level: {0}' -f $level)
    $stats += ('Online Checks Performed: {0}' -f $Global:onlineChecks)
    $stats += ('Displayed GPOs: {0}' -f $Global:displayedPols)
    $stats += ('Unlinked GPOs: {0}' -f $Global:unlinkedPols)
    $stats += ('Interesting Settings: {0}' -f $Global:GPOsWithIntSettings)
    $stats += ('Vulnerable Settings: {0}' -f $Global:GPOsWithVulnSettings)
    $stats += ('Total GPOs: {0}' -f $gpocount)
    Write-Output $stats
}

Export-ModuleMember -Function 'Invoke-AuditGPOReport'
