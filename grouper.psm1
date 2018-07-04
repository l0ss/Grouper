# Grouper - Get-GPOReport XML Parser

<#
.SYNOPSIS
    Consumes a Get-GPOReport XML formatted report and outputs potentially vulnerable settings.
.DESCRIPTION
    Consumes a Get-GPOReport XML formatted report and outputs potentially vulnerable settings.
    GPP cpassword decryption function stolen shamelessly from @harmj0y
    Lots of assist from @sysop_host
.EXAMPLE
    So first you need to generate a report on a machine with the Group Policy PS module installed. Do that like this:

    "Get-GPOReport -All -ReportType XML -Path C:\temp\gporeport.xml"

    Then import this module and:

    "Invoke-AuditGPOReport -Path C:\temp\gporeport.xml"

    -hideDisabled or else by default we just filter out policy objects that aren't enabled or linked anywhere.

    -Level (1, 2, or 3) - adjusts whether to show everything (1) or only interesting (2) or only definitely vulnerable (3) settings. Defaults to 2.

    -lazyMode (without -Path) will run the initial generation of the GPOReport for you but will need to be running as a domain user on a domain-joined machine.

    -blurb will provide a little extra description on why you should care about what you're seeing and what you might want to do with it.
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

# TODO ADD TO THIS LIST?
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

# The blurbs for each check displayed if you run with -blurb enabled.
$blurbs = @{}
$blurbs.Add("Get-GPOEnvVars", "Environment variables being set. Might find something dumb like an API key or a VM.")
$blurbs.Add("Get-GPORegSettings", "A bunch more 'misc' security settings, including all the MS Office settings around macros etc.")
$blurbs.Add("Get-GPOShortcuts", "Creates shortcuts which could provide useful intel on internal applications. Alternatively, if you can modify the target of a shortcut you might be able to replace it with /nasty.")
$blurbs.Add("Get-GPOPerms", "These are the permissions on the Group Policy Object itself. If you have modify rights here, you can take over any user or computer that the policy applies to.")
$blurbs.Add("Get-GPOUsers", "Entries in here add, change, or remove local users from hosts. If you see a password in here that's probably bad.")
$blurbs.Add("Get-GPOGroups", "These entries make changes to local groups on the hosts. If someone has been added to a highly privileged group that might be useful to you?")
$blurbs.Add("Get-GPOUserRights", "This is where you'll see users and groups being assigned interesting privileges on hosts. Google the name of the right being assigned if you wanna know what it does.")
$blurbs.Add("Get-GPOSchedTasks", "These are scheduled tasks being pushed to hosts. Sometimes they have credentials and stuff in them?")
$blurbs.Add("Get-GPOMSIInstallation", "These are MSI files that are being installed via group policy. If you can replace one of them with something nasty you could probably do something evil?")
$blurbs.Add("Get-GPOScripts", "These are startup and shutdown scripts, that kind of thing. If you can edit one you can probably have a nice time?")
$blurbs.Add("Get-GPOFileUpdate", "These are all changes being made to files on the target system, either adding new ones, removing existing ones, or updating existing ones. If you can modify the source files you o have a nice time, depending on the file type, if it ever gets executed, etc.")
$blurbs.Add("Get-GPOFilePerms", "These entries modify file permissions on the target host's file system. Could be useful for identifying privesc vulns, that kind of thing.")
$blurbs.Add("Get-GPOSecurityOptions", "A lot of these are kind of 'misc' security settings, you'll need to google individual items to understand what each means. If you want Grouper to provide more detail, I eagerly ll request.")
$blurbs.Add("Get-GPORegKeys", "These are reg keys that are being pushed to target hosts. If they show up in -Level 3 or 2 they're worth a closer look as they probably contain credentials. If you think this ore detail... I eagerly await your pull request.")
$blurbs.Add("Get-GPONetworkShares", "Defines file shares that should be created on target hosts. Handy recon data basically.")
$blurbs.Add("Get-GPOFWSettings", "Windows Firewall settings. Might be useful for identifying why a payload isn't working, or which servers are hosting what apps if that's otherwise difficult.")
$blurbs.Add("Get-GPOIniFiles", "Ini files are an old timey way of doing Windows app configs. You might find some creds in here?")
$blurbs.Add("Get-GPOAccountSettings", "These are all the settings that define stuff like password policy, some options for how passwords are stored, that kind of thing.")

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

    $tasktypes = @()
    $tasktypes += $polXml.ExtensionData.Extension.ScheduledTasks.Task
    $tasktypes += $polXml.ExtensionData.Extension.ScheduledTasks.ImmediateTask
    $tasktypes += $polXml.ExtensionData.Extension.ScheduledTasks.TaskV2

    $settingsSchedTasks = $tasktypes | Sort-Object GPOSettingOrder

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
            if ((($cpasswordcrypt) -And ($level -le 3)) -Or ($level -le 2)) {
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
                        }
                    }
                    foreach ($SAP in $intSysAccPolStrings) {
                        if ($SAP.ContainsKey($setting.SystemAccessPolicyName)) {
                            $output.Add("Name", $setting.SystemAccessPolicyName)
                            $output.Add("SettingString",$setting.SettingString)
                            $GPOisinteresting = $true
                            Write-NoEmpties -output $output
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
            }
        }
    }

    if ($GPOisinteresting) {
        $Global:GPOsWithIntSettings += 1
    }

}

Function Get-GPOFWSettings {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Xml.XmlElement]$polXML,
        [Parameter(Mandatory=$true)][ValidateSet(1,2,3)][int]$level
    )
 
    ######
    # Description: Checks for changes to Firewall Rules.
    # Level 3: TODO
    # Level 2: TODO
    # Level 1: Show all Firewall settings
    ######
    if ($level -le 2) {
        if ($polXml.Computer.ExtensionData.Extension.PrivateProfile.EnableFirewall -ne $null) {
            $output = [ordered]@{}
            $output.Add("Firewall Profile","PrivateProfile")
            $output.Add("DefaultInboundAction",$polXml.Computer.ExtensionData.Extension.PrivateProfile.DefaultInboundAction.Value)
            $output.Add("DefaultOutboundAction",$polXml.Computer.ExtensionData.Extension.PrivateProfile.DefaultOutboundAction.Value)
            $output.Add("EnableFirewall",$polXml.Computer.ExtensionData.Extension.PrivateProfile.EnableFirewall.Value)
            Write-NoEmpties -output $output
            ""
        }

        if ($polXml.Computer.ExtensionData.Extension.PublicProfile.EnableFirewall -ne $null) {
            $output = [ordered]@{}
            $output.Add("Firewall Profile","PublicProfile")
            $output.Add("DefaultInboundAction",$polXml.Computer.ExtensionData.Extension.PublicProfile.DefaultInboundAction.Value)
            $output.Add("DefaultOutboundAction",$polXml.Computer.ExtensionData.Extension.PublicProfile.DefaultOutboundAction.Value)
            $output.Add("EnableFirewall",$polXml.Computer.ExtensionData.Extension.PublicProfile.EnableFirewall.Value)
            Write-NoEmpties -output $output
            ""
        }

        if ($polXml.Computer.ExtensionData.Extension.DomainProfile.EnableFirewall -ne $null) {
            $output = [ordered]@{}
            $output.Add("Firewall Profile","DomainProfile")
            $output.Add("DefaultInboundAction",$polXml.Computer.ExtensionData.Extension.DomainProfile.DefaultInboundAction.Value)
            $output.Add("DefaultOutboundAction",$polXml.Computer.ExtensionData.Extension.DomainProfile.DefaultOutboundAction.Value)
            $output.Add("EnableFirewall",$polXml.Computer.ExtensionData.Extension.DomainProfile.EnableFirewall.Value)
            Write-NoEmpties -output $output
            ""
        }

        if ($level -eq 1) {
            $settingsInbound = $polXml.Computer.ExtensionData.Extension.InboundFirewallRules
             $settingsInbound = ($settingsInbound | ? {$_}) 
            if ($settingsInbound -ne $null) {
                foreach ($setting in $settingsInbound) {
                    $output = [ordered]@{}
                    $output.Add("Inbound Rule Name",$setting.Name)
                    $output.Add("Action",$setting.Action)
                    $output.Add("Dir",$setting.Dir)
                    $output.Add("Profile",$setting.Profile)
                    $output.Add("Lport",$setting.Lport)
                    $output.Add("Protocol",$setting.Protocol)
                    $output.Add("Active",$setting.Active)
                    $output.Add("App",$setting.App)
                    $output.Add("Svc",$setting.Svc)
                    $output.Add("EmbedCtxt",$setting.EmbedCtxt)
                    Write-NoEmpties -output $output
                    ""
                    }
            }

            $settingsOutbound = $polXml.Computer.ExtensionData.Extension.OutboundFirewallRules
            $settingsOutbound = ($settingsOutbound | ? {$_}) 
            if ($settingsOutbound -ne $null) {
                foreach ($setting in $settingsOutbound) {
                    $output = [ordered]@{}
                    $output.Add("Outbound Rule Name",$setting.Name)
                    $output.Add("Action",$setting.Action)
                    $output.Add("Dir",$setting.Dir)
                    $output.Add("Profile",$setting.Profile)
                    $output.Add("Lport",$setting.Rport)
                    $output.Add("Protocol",$setting.Protocol)
                    $output.Add("Active",$setting.Active)
                    $output.Add("App",$setting.App)
                    $output.Add("Svc",$setting.Svc)
                    $output.Add("EmbedCtxt",$setting.EmbedCtxt)
                    Write-NoEmpties -output $output
                    ""
                }
            }
        }
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
    # Level 3: Shows settings that (if enabled) are going to severely impact the security of a host.
    # Level 2: Shows 'Interesting' settings, regardless of state.
    # Level 1: All Registry Settings.
    ######

    $settingsRegSettings = ($polXml.ExtensionData.Extension.RegistrySetting | Sort-Object GPOSettingOrder)

    if (($settingsRegSettings) -And ($level -eq 1)) {
        foreach ($setting in $settingsRegSettings) {
            $output = @{}
            $output.Add("KeyPath", $setting.KeyPath)
            $output.Add("AdmSetting", $setting.AdmSetting)
            $output.Add($setting.Value.Name, $setting.Value.Number)
            Write-NoEmpties -output $output
        }
    }

	$settingsPolicies = ($polXml.ExtensionData.Extension.Policy | Sort-Object GPOSettingOrder)

    if ($settingsPolicies) {

        $intRegPolicies = @()
        $intRegPolicies += "Allow CredSSP authentication"
        $intRegPolicies += "Allow Basic Authentication"
        $intRegPolicies += "Set the default source path for Update-Help"
        $intRegPolicies += "Default Source Path"
        $intRegPolicies += "Allow remote server management through WinRM"
        $intRegPolicies += "Specify intranet Microsoft update service location"
        $intRegPolicies += "Set the intranet update service for detecting updates:"
        $intRegPolicies += "Set the intranet statistics server:"
        $intRegPolicies += "Allow Remote Shell Access"
        $intRegPolicies += "Allow unencrypted traffic"
        $intRegPolicies += "Sign-in last interactive user automatically after a system-initiated restart"
        $intRegPolicies += "Intranet proxy servers for  apps"
        $intRegPolicies += "Type a proxy server IP address for the intranet"
        $intRegPolicies += "Internet proxy servers for apps"
        $intRegPolicies += "Domain Proxies"
        $intRegPolicies += "Restrict Unauthenticated RPC clients"
        $intRegPolicies += "RPC Runtime Unauthenticated Client Restriction to Apply"
        $intRegPolicies += "Enable RPC Endpoint Mapper Client Authentication"
        $intRegPolicies += "Always install with elevated privileges"
        $intRegPolicies += "Specify communities"
        $intRegPolicies += "Communities"
        $intRegPolicies += "Allow non-administrators to install drivers for these device setup classes"
        $intRegPolicies += "Allow Users to install device drivers for these classes:"
        #MS Office settings starts here
        $intRegPolicies += "Add-ons"
        $intRegPolicies += "Add-on Management"
        $intRegPolicies += "Allow background open of web pages"
        $intRegPolicies += "Allow file extensions for OLE embedding"
        $intRegPolicies += "Allow in-place activation of embedded OLE objects"
        $intRegPolicies += "Allow scripts in one-off Outlook forms"
        $intRegPolicies += "Allow storage of user passwords"
        $intRegPolicies += "Allow Trusted Locations not on the computer"
        $intRegPolicies += "Allow Trusted Locations on the network"
        $intRegPolicies += "Apply macro security settings to macros, add-ins and additional actions"
        $intRegPolicies += "Apply macro security settings to macros, add-ins, and SmartTags"
        $intRegPolicies += "Authentication with Exchange Server"
        $intRegPolicies += "Authentication with Exchange Server"
        $intRegPolicies += "Authentication with Exchange Server"
        $intRegPolicies += "Automatically download content for e-mail from people in Safe Senders and Safe Recipients Lists"
        $intRegPolicies += "Block additional file extensions for OLE embedding"
        $intRegPolicies += "Block all unmanaged add-ins"
        $intRegPolicies += "Block application add-ins loading"
        $intRegPolicies += "Block macros from running in Office files from the Internet"
        $intRegPolicies += "Chart Templates Server Location"
        $intRegPolicies += "Configure Add-In Trust Level"
        $intRegPolicies += "Configure SIP security mode"
        $intRegPolicies += "Disable 'Remember password' for Internet e-mail accounts"
        $intRegPolicies += "Disable all application add-ins"
        $intRegPolicies += "Disable user name and password"
        $intRegPolicies += "Disable all trusted locations"
        $intRegPolicies += "Disable Password Caching"
        $intRegPolicies += "Disable e-mail forms from the Full Trust security zone"
        $intRegPolicies += "Disable e-mail forms from the Internet security zone"
        $intRegPolicies += "Disable e-mail forms from the Intranet security zone"
        $intRegPolicies += "Disable e-mail forms running in restricted security level"
        $intRegPolicies += "Disable fully trusted solutions full access to computer"
        $intRegPolicies += "Disable hyperlink warnings"
        $intRegPolicies += "Disable opening forms with managed code from the Internet security zone"
        $intRegPolicies += "Disable VBA for Office applications"
        $intRegPolicies += "Do not allow attachment previewing in Outlook"
        $intRegPolicies += "Do not allow Outlook object model scripts to run for public folders"
        $intRegPolicies += "Do not open files from the Internet zone in Protected View"
        $intRegPolicies += "Do not open files in unsafe locations in Protected View"
        $intRegPolicies += "Do not permit download of content from safe zones"
        $intRegPolicies += "Embedded Files Blocked Extensions"
        $intRegPolicies += "Excel add-in files"
        $intRegPolicies += "File Previewing"
        $intRegPolicies += "Hide warnings about suspicious names in e-mail addresses"
        $intRegPolicies += "Include Internet in Safe Zones for Automatic Picture Download"
        $intRegPolicies += "Include Intranet in Safe Zones for Automatic Picture Download"
        $intRegPolicies += "Junk E-mail protection level"
        $intRegPolicies += "List of managed add-ins"
        $intRegPolicies += "Location of Backup Folder"
        $intRegPolicies += "Local Machine Zone Lockdown Security"
        $intRegPolicies += "Open files on local Intranet UNC in Protected View"
        $intRegPolicies += "Path to DAV server"
        $intRegPolicies += "Personal tempaltes path for Excel"
        $intRegPolicies += "Personal templates path for Access"
        $intRegPolicies += "Personal templates path for PowerPoint"
        $intRegPolicies += "Personal templates path for Project"
        $intRegPolicies += "Personal templates path for Publisher"
        $intRegPolicies += "Personal templates path for Visio"
        $intRegPolicies += "Personal templates path for Word"
        $intRegPolicies += "Prevent saving credentials for Basic Authentication policy"
        $intRegPolicies += "Prevent Word and Excel from loading managed code extensions"
        $intRegPolicies += "Protection From Zone Elevation"
        $intRegPolicies += "Require that application add-ins are signed by Trusted Publisher"
        $intRegPolicies += "Require that application add-ins are signed by Trusted Publisher"
        $intRegPolicies += "Require logon credentials"
        $intRegPolicies += "Run Programs"
        $intRegPolicies += "Scan encrypted macros in Excel Open XML workbooks"
        $intRegPolicies += "Scan encrypted macros in PowerPoint Open XML presentations"
        $intRegPolicies += "Scan encrypted macros in Word Open XML documents"
        $intRegPolicies += "Security setting for macros"
        $intRegPolicies += "Security setting for macros"
        $intRegPolicies += "Specify server"
        $intRegPolicies += "Start-up"
        $intRegPolicies += "Templates"
        $intRegPolicies += "Tools"
        $intRegPolicies += "Trusted Domain List"
        $intRegPolicies += "Trusted Location #1"
        $intRegPolicies += "Trusted Location #10"
        $intRegPolicies += "Trusted Location #11"
        $intRegPolicies += "Trusted Location #12"
        $intRegPolicies += "Trusted Location #13"
        $intRegPolicies += "Trusted Location #14"
        $intRegPolicies += "Trusted Location #15"
        $intRegPolicies += "Trusted Location #16"
        $intRegPolicies += "Trusted Location #17"
        $intRegPolicies += "Trusted Location #18"
        $intRegPolicies += "Trusted Location #19"
        $intRegPolicies += "Trusted Location #2"
        $intRegPolicies += "Trusted Location #20"
        $intRegPolicies += "Trusted Location #3"
        $intRegPolicies += "Trusted Location #4"
        $intRegPolicies += "Trusted Location #5"
        $intRegPolicies += "Trusted Location #6"
        $intRegPolicies += "Trusted Location #7"
        $intRegPolicies += "Trusted Location #8"
        $intRegPolicies += "Trusted Location #9"
        $intRegPolicies += "Turn off Protected View for attachments opened from Outlook"
        $intRegPolicies += "Turn off Trusted Documents on the network"
        $intRegPolicies += "Turn off Trusted Documents on the network"
        $intRegPolicies += "Turn off trusted documents"
        $intRegPolicies += "Turn off trusted documents"
        $intRegPolicies += "Unblock automatic download of linked images"
        $intRegPolicies += "User queries path"
        $intRegPolicies += "User templates path"
        $intRegPolicies += "User Templates"
        $intRegPolicies += "User Templates"
        $intRegPolicies += "VBA Macro Notification Settings"
        $intRegPolicies += "VBA Macro Warning Settings"
        $intRegPolicies += "Workgroup templates path"
        #MS Office Settings End Here

        $vulnRegPolicies = @()
        $vulnRegPolicies += "Always install with elevated privileges"
        $vulnRegPolicies += "Specify communities"
        $vulnRegPolicies += "Communities"
        $vulnRegPolicies += "Allow non-administrators to install drivers for these device setup classes"
        $vulnRegPolicies += "Allow Users to install device drivers for these classes:"

        # I hate this nested looping shit more than anything I've ever written.
        foreach ($setting in $settingsPolicies) {
            if ($true) {
                $output = @{}
                $output.Add("Setting Name", $setting.Name)
                $output.Add("State", $setting.State)
                $output.Add("Supported", $setting.Supported)
                $output.Add("Category", $setting.Category)
                $output.Add("Explain", $setting.Explain)

                if (($level -eq 1) -Or (($level -eq 2) -And ($intRegPolicies -Contains $setting.Name)) -Or (($level -eq 3) -And ($vulnRegPolicies -Contains $setting.Name))) {
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
        $targetPathAccess = $targetPathACL.Access | Where-Object {-Not ($boringTrustees -Contains $_.IdentityReference)} | Select-Object FileSystemRights,AccessControlType,IdentityReference
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

Function Get-GPOPermissions {
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$GPOPerms
    )
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

    $permBannerPrinted = 0
    # iterate over each permission entry for the GPO
    foreach ($GPOACE in $GPOPerms) {
        $permOutput = @{}
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
        if (($boringPerms -Contains $ACEType) -Or ($GPOACE.Type.PermissionType -eq "Deny")) {
            $ACEInteresting = $false
        }
        # if it's still interesting,
        if ($ACEInteresting) {
            #if we have a valid trustee name, add it to the output
            if ($trusteeName) {
                $permOutput.Add("Trustee", $trusteeName)
            }
            #if we have a SID, add it to the output
            elseif ($trusteeSID) {
                $permOutput.Add("Trustee SID", $trusteeSID)
            }
            #add our other stuff to the output
            $permOutput.Add("Type", $GPOACE.Type.PermissionType)
            $permOutput.Add("Access", $GPOACE.Standard.GPOGroupedAccessEnum)
        }
        if ($permOutput.Count -gt 0) {
            if ($permBannerPrinted -eq 0) {
                Write-Title -DividerChar "#" -Color "Yellow" -Text "GPO Permissions"
                if ($blurb) {
                    Write-Title -DividerChar "-" -Color "Magenta" -Text "But what does that actually mean?"
                    Write-Output $blurbs['Get-GPOPerms']
                    "`r`n"
                } 
                $permBannerPrinted = 1
            }
            Write-Output $permOutput
        }
    }
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
    if (($gpoisenabled -ne "true") -And ($Global:hideDisabled)) {
        $Global:unlinkedPols += 1
        return $null
    }

    #check if it's linked somewhere
    $gpopath = $xmlgpo.LinksTo.SOMName
    #and if it's not, increment our count of GPOs that don't do anything
    if ((-Not $gpopath) -And ($Global:hideDisabled)) {
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
    $polchecks += {Get-GPOSchedTasks -Level $level -polXML $computerSettings}
    $polchecks += {Get-GPOSchedTasks -Level $level -polXML $userSettings}
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
    $polchecks += {Get-GPOFWSettings -Level $level -polXml $xmlgpo}

    if ($xmlgpo.SecurityDescriptor.Owner.Name.InnerText) {
        $owner = $xmlgpo.SecurityDescriptor.Owner.Name.InnerText
    }
    else {
        $owner = $xmlgpo.SecurityDescriptor.Owner.SID.InnerText
    }

    # Construct a pretty green header with the report name and some other nice details
    $headers = @()
    $headers += {'==============================================================='}
    $headers += {'Policy UID: {0}' -f $xmlgpo.Identifier.Identifier.InnerText}
    $headers += {'Policy created on: {0:G}' -f ([DateTime]$xmlgpo.CreatedTime)}
    $headers += {'Policy last modified: {0:G}' -f ([DateTime]$xmlgpo.ModifiedTime)}
    $headers += {'Policy owner: {0}' -f $owner}
    $headers += {'Linked OU: {0}' -f $gpopath}
    $headers += {'Link enabled: {0}' -f $gpoisenabled}
    $headers += {'==============================================================='}

    # Write the title of the GPO in nice green text
    "`r`n"
    Write-ColorText -Color "Green" -Text $xmlgpo.Name
    # Write the headers from above
    foreach ($header in $headers) {
        & $header
    }

    # Parse and print out the GPO's Permissions
    $GPOPerms = $xmlgpo.SecurityDescriptor.Permissions.TrusteePermissions
    Get-GPOPermissions -GPOPerms $GPOPerms

    # In each GPO we parse, iterate through the list of checks to see if any of them return anything.
    foreach ($polcheck in $polchecks) {
        $finding = & $polcheck # run the check and store the output
        if ($finding) {
            
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
            if ($blurb) {
                Write-Title -DividerChar "-" -Color "Magenta" -Text "But what does that actually mean?"
                $polname = $polcheckbits[0]
                Write-Output $blurbs[$polname]
                "`r`n"
            } 
            # Write out the actual finding
            $finding
            Write-Output "`r`n"
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
        [switch]$Global:hideDisabled,

        [Parameter(ParameterSetName='WithFile', Mandatory=$false, HelpMessage="Set verbosity level (1 = most verbose, 3 = only show things that are definitely bad)")]
        [Parameter(ParameterSetName='WithoutFile', Mandatory=$false, HelpMessage="Set verbosity level (1 = most verbose, 3 = only show things that are definitely bad)")]
        [Parameter(ParameterSetName='OnlineDomain', Mandatory=$false, HelpMessage="Set verbosity level (1 = most verbose, 3 = only show things that are definitely bad)")]
        [ValidateSet(1,2,3)]
        [int]$level = 2,

        [Parameter(ParameterSetName='WithFile', Mandatory=$false, HelpMessage="Provide extra words to tell users wtf all this output means and what they might want to do with it.")]
        [Parameter(ParameterSetName='WithoutFile', Mandatory=$false, HelpMessage="Provide extra words to tell users wtf all this output means and what they might want to do with it.")]
        [Parameter(ParameterSetName='OnlineDomain', Mandatory=$false, HelpMessage="Provide extra words to tell users wtf all this output means and what they might want to do with it.")]
        [switch]$blurb,

        [Parameter(ParameterSetName='OnlineDomain', Mandatory=$true, HelpMessage="Perform online checks by actively contacting DCs within the target domain")]
        [switch]$online,

        [Parameter(ParameterSetName='OnlineDomain', Mandatory=$false, HelpMessage="FQDN for the domain to target for online checks")]
        [ValidateNotNullOrEmpty()]
        [string]$domain = $env:UserDomain
    )

    # This sucker actually consumes the file, does the stuff, this is the one, you know?

    Write-Banner

    if ($PSVersionTable.PSVersion.Major -le 2) {
        Write-ColorText -Color "Red" -Text "[!] Sorry, Grouper is not yet compatible with PowerShell 2.0."
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
    $Global:hideDisabled = $false
    if ($hideDisabled) {
        $Global:hideDisabled = $true
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
    #$stats += ('Displayed GPOs: {0}' -f $Global:displayedPols)
    #$stats += ('Unlinked GPOs: {0}' -f $Global:unlinkedPols)
    #$stats += ('Interesting Settings: {0}' -f $Global:GPOsWithIntSettings)
    #$stats += ('Vulnerable Settings: {0}' -f $Global:GPOsWithVulnSettings)
    $stats += ('Total GPOs: {0}' -f $gpocount)
    Write-Output $stats
}

Export-ModuleMember -Function 'Invoke-AuditGPOReport'
