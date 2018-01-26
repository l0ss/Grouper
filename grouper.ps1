# Grouper - Get-GPOReport XML Parser

<# 
.SYNOPSIS
    Consumes a Get-GPOReport XML formatted report and outputs potentially vulnerable settings.
.DESCRIPTION
    Cpassword decryption function stolen shamelessly from @harmj0y
    Other small snippets and ideas stolen shamelessly from @sysophost
.EXAMPLE
    So first you need to generate a report on a machine with the Group Policy PS module installed. Do that like this:

    "Get-GPOReport -All -ReportType XML -Path C:\temp\gporeport.xml"

    Then import this module and:

    "Invoke-AuditGPReport -Path C:\temp\gporeport.xml"

    -showDisabled or else by default we just filter out policy objects that aren't enabled or linked anywhere.

    -showLessInteresting will (among other things) show you:
        * ALL the user rights that have been assigned, not just the ones likely to get you admin.
        * ALL the users that have been created by group policy preferences, not just the ones that have GPP Passwords set.
    
    -lazyMode will run the initial generation of the GPOReport for you but will need to be running as a domain user on a domain-joined machine.
.NOTES
     Author     : Mike Loss - mike@mikeloss.net
#>


#____________________ GPO Check functions _______________

#There's a whole pile of these functions so I'm only properly commenting this one, 
#and any others that diverge significantly from the 'template'.

Function Get-GPOUsers {
    [cmdletbinding()]
    # Consumes a single <GPO> object from a Get-GPOReport XML report.
    Param ($polXml, $PolicyType)
    
    # Grab an array of the settings we're interested in from the GPO.
    $settingsUsers = ($polXml.LocalUsersAndGroups.User | Sort-Object GPOSettingOrder)    

    # Check if there's actually anything in the array.
    if ($settingsUsers) {
        $output = @{}

        # Iterate over array of settings, writing out only those we care about.
        foreach ($setting in $settingsUsers) {

            #see if we have any stored encrypted passwords
            $cpasswordcrypt = $setting.properties.cpassword
            #if so, or if we're showing boring, show the rest of the setting
            if (($cpasswordcrypt) -Or ($Global:showBoring -eq 1)) {
                $output = @{}
                $output.Add("Name", $setting.Name)
                $output.Add("New Name", $setting.properties.NewName)
                $output.Add("Description", $setting.properties.Description)
                $output.Add("changeLogon", $setting.properties.changeLogon)
                $output.Add("noChange", $setting.properties.noChange)
                $output.Add("neverExpires", $setting.properties.neverExpires)
                $output.Add("Disabled", $setting.properties.acctDisabled)
                $output.Add("UserName", $setting.properties.userName)

                # decrypt it with harmj0y's function
                $cpasswordclear = Get-DecryptedCpassword -Cpassword $cpasswordcrypt
                # write it out
                $output.Add("Password", $cpasswordclear)

                $output
                ""
            }
        }
    }
}

Function Get-GPOGroups {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
	$settingsGroups = ($polXml.LocalUsersAndGroups.Group | Sort-Object GPOSettingOrder)
    if ($settingsGroups) {
	    foreach ($setting in $settingsGroups) {
            $output = @{}
            $output.Add("Name", $setting.Name)
            $output.Add("NewName", $setting.properties.NewName)
            $output.Add("Description", $setting.properties.Description)
            $output.Add("Group Name", $setting.properties.groupName)
            $output
            
            foreach ($member in $setting.properties.members.member) {
                $output = @{}
                $output.Add("Name", $member.name)
                $output.Add("Action", $member.action)
                $output.Add("UserName", $member.userName)
                $output
                
            }
            ""
        }
    }
}

Function Get-GPOUserRights {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)

    $uraSettings = ($polXml.Computer.ExtensionData.Extension.UserRightsAssignment)

    $uraSettings = ($uraSettings | ? {$_}) #Strips null elements from array - nfi why I was getting so many of these.

    $interestingrights = @()
    $interestingrights += "SeTrustedCredManAccessPrivilege"
    $interestingrights += "SeTcbPrivilege"
    $interestingrights += "SeMachineAccountPrivilege"
    $interestingrights += "SeBackupPrivilege"
    $interestingrights += "SeCreateTokenPrivilege"
    $interestingrights += "SeAssignPrimaryTokenPrivilege"
    $interestingrights += "SeRestorePrivilege"
    $interestingrights += "SeDebugPrivilege"
    $interestingrights += "SeTakeOwnershipPrivilege"
    $interestingrights += "SeCreateGlobalPrivilege"
    $interestingrights += "SeLoadDriverPrivilege"
    $interestingrights += "SeRemoteInteractiveLogonRight"

    if ($uraSettings) {
        foreach ($setting in $uraSettings) {
            $output = @{}
            $userRight = $setting.Name
            if (($interestingrights -contains $userRight) -Or ($Global:showBoring -eq 1)) {
                 $output.Add("Right", $userRight)
                $members = @()
                foreach ($member in $setting.Member) {
                   $members += ($member.Name.Innertext)
                }
                $output.Add("Members", $members)
                $output
                ""
            }
        }
    }
}

Function Get-GPOSchedTasks {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
    $settingsSchedTasks = ($polXml.Computer.ExtensionData.Extension.ScheduledTasks.Task | Sort-Object GPOSettingOrder)    

    if ($settingsSchedTasks) {
        foreach ($setting in $settingsSchedTasks) {
            #see if we have any stored encrypted passwords
            $cpasswordcrypt = $setting.properties.cpassword

            #if so, or if we're showing boring, show the rest of the setting
            if (($cpasswordcrypt) -Or ($Global:showBoring -eq 1)) {
            $output = @{}
               $output.Add("Name", $setting.Properties.name)
               $output.Add("runAs", $setting.Properties.runAs)
               $cpasswordclear = Get-DecryptedCpassword -Cpassword $cpasswordcrypt
               $output.Add("Password", $cpasswordclear)
               $output.Add("Action", $setting.Properties.action)
               $output.Add("appName", $setting.Properties.appName)
               $output.Add("args", $setting.Properties.args)
               $output.Add("startIn", $setting.Properties.startIn)
               $output
               if ($setting.Properties.Triggers) {
                   $output = @{}
                   foreach ($trigger in $setting.Properties.Triggers) {
                        $output.Add("type", $trigger.Trigger.type)
                        $output.Add("startHour", $trigger.Trigger.startHour)
                        $output.Add("startMinutes", $trigger.Trigger.startMinutes)
                        $output
                        ""
                   }

               }
            }
        }
    }
}

Function Get-GPOMSIInstallation {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)

	$computerMSIInstallation = ($polXml.Computer.ExtensionData.Extension.MsiApplication | Sort-Object GPOSettingOrder)

    if ($computerMSIInstallation) {
 	    foreach ($setting in $computerMSIInstallation) {
            $output = @{}
            $output.Add("Name", $setting.Name)
            $output.Add("Path", $setting.Path)
            $output
            ""
        }
    }
}

Function Get-GPOScripts {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)

	$settingsScripts = ($polXml.Script | Sort-Object GPOSettingOrder)

    if ($settingsScripts) {
	    foreach ($setting in $settingsScripts) {
            $output = @{}
            $output.Add("Command", $setting.Command)
            $output.Add("Type", $setting.Type)
            $output.Add("Parameters", $setting.Parameters)
            $output
        }
        ""
    }
}

Function Get-GPOFileUpdate {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
	$settingsFiles = ($polXml.FilesSettings | Sort-Object GPOSettingOrder)

    if ($settingsFiles) {
 	    foreach ($setting in $settingsFiles.File) {
            $output = @{}
            $output.Add("Name", $setting.name)
            $output.Add("Action", $setting.Properties.action)
            $output.Add("fromPath", $setting.Properties.fromPath)
            $output.Add("targetPath", $setting.Properties.targetPath)
            $output
            ""
        }
    }
}

Function Get-GPOFilePerms {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
	$settingsFilePerms = ($polXml.Computer.ExtensionData.Extension.File | Sort-Object GPOSettingOrder)

    if ($settingsFilePerms) {
 	    foreach ($setting in $settingsFilePerms) {
            $output = @{}
            $output.Add("Path", $setting.Path)
            $output.Add("SDDL", $setting.SecurityDescriptor.SDDL.innertext)
            $output
            ""
        }
    }
}

Function Get-GPOSecurityOptions {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
	$settingsSecurityOptions = ($polXml.Computer.ExtensionData.Extension.SecurityOptions | Sort-Object GPOSettingOrder)

    if ($settingsSecurityOptions) {
        
        #KeyName
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

        #<q1:SystemAccessPolicyName>
        $intSysAccPolName = @()
        $intSysAccPolName += "EnableGuestAccount"
        $intSysAccPolName += "EnableAdminAccount"
        $intSysAccPolName += "LSAAnonymousNameLookup"
        $intSysAccPolName += "NewAdministratorName"
        $intSysAccPolName += "NewGuestName"

 	    foreach ($setting in $settingsSecurityOptions) {

            #Check if it's a registry based option
            if ($setting.KeyName) {

                $keyname = $setting.KeyName
                $keynameisint = 0

                #Check if it's one of the ones we care about
                foreach ($intKeyName in $intKeyNames) {
                    if ($intKeyName -eq $keyname ) {
                        #if it is, don't bother checking the rest
                        $keynameisint = 1
                        break
                    }
                }
                # if it's interesting, grab the text we want to know from the setting and add it to our output array
                if (($keynameisint -eq 1) -Or ($showBoring -eq 1)) {
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
                    $output
                    $values.GetEnumerator() | sort -Property Name
                    ""
                }
            }

            if ($setting.SystemAccessPolicyName) {
                foreach ($intSysAccPolName in $intSysAccPolName) {
                    if (($setting.SystemAccessPolicyName -eq $intSysAccPolName) -Or ($showBoring)) {
                        $output = @{}
                        $output.Add("Name", $setting.SystemAccessPolicyName)
                        if ($setting.SettingNumber) {
                            $output.Add("SettingNumber", $setting.SettingNumber)
                        }
                        if ($setting.SettingString) {
                            $output.Add("SettingString", $setting.SettingString)
                        }
                        $output
                        ""
                    } 
                }
            }
        }
    }
}

Function Get-GPORegKeys {
    [cmdletbinding()]
    Param ($polXML, $PolicyType)

    $otherkeys = 0 # this gets set to 1 if reg keys we don't give a shit about are found, so we can let the user know there were other keys that weren't shown.

	$settingsRegKeys = ($polXml.RegistrySettings.Registry | Sort-Object GPOSettingOrder)

    $interestingkeys = @()
    $interestingkeys += "Software\Network Associates\ePolicy Orchestrator"
    $interestingkeys += "SOFTWARE\FileZilla Server"
    $interestingkeys += "SOFTWARE\Wow6432Node\FileZilla Server"
    $interestingkeys += "Software\Wow6432Node\McAfee\DesktopProtection - McAfee VSE"
    $interestingkeys += "Software\McAfee\DesktopProtection - McAfee VSE"
    $interestingkeys += "Software\ORL\WinVNC3"
    $interestingkeys += "Software\ORL\WinVNC3\Default"
    $interestingkeys += "Software\ORL\WinVNC\Default"
    $interestingkeys += "Software\RealVNC\WinVNC4"
    $interestingkeys += "Software\RealVNC\Default"
    $interestingkeys += "Software\TightVNC\Server"
    $interestingkeys += "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $interestingkeys += "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"

    if ($settingsRegKeys) {
        foreach ($setting in $settingsRegKeys) {
            $output = @{}
            $output.Add("Key", $setting.Properties.key)
            $output.Add("Action", $setting.Properties.action)
            $output.Add("Hive", $setting.Properties.hive)
            $output.Add("Name", $setting.Properties.name)
            $output.Add("Value", $setting.Properties.value)

           if ($interestingkeys -contains $output["Key"]) {
                $output
                ""
           }

            else {
                $otherkeys = 1
            }
        }

        if ($otherkeys -eq 1) {
            $output = @()
            $output += "... and other registry keys that didn't match any interesting patterns." 
            $output += "Check the policy manually if you're desperate."
            $output
            ""
        }
    }
}

Function Get-GPOFolderRedirection {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)

	$settingsFolderRedirection = ($polXml.User.ExtensionData.Extension.Folder | Sort-Object GPOSettingOrder)

    if ($settingsFolderRedirection) {
 	    foreach ($setting in $settingsFolderRedirection) {
            $output = @{}
            $output.Add("DestPath", $setting.Location.DestinationPath)
            $output.Add("Target Group", $setting.Location.SecurityGroup.Name.innertext)
            $output.Add("Target SID", $setting.Location.SecurityGroup.SID.innertext)
            $output.Add("ID", $setting.Id)
            $output
            ""
        }
    }
}

Function Get-GPOAccountSettings {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
	$settingsAccount = ($polXml.Computer.ExtensionData.Extension.Account | Sort-Object GPOSettingOrder)

    if ($settingsAccount) {
	    foreach ($setting in $settingsAccount) {
            $output = @{}
            $output.Add("Name", $setting.Name)
            if ($setting.SettingBoolean) {
                $output.Add("SettingBoolean", $setting.SettingBoolean)
            }
            if ($setting.SettingNumber) {
                $output.Add("SettingNumber", $setting.SettingNumber)
            }
            $output.Add("Type", $setting.Type)
            $output
            ""
        }
    }
}

Function Get-GPOFolders {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
	$settingsFolders = ($polXml.Folders.Folder | Sort-Object GPOSettingOrder)

    if ($settingsFolders) {
	    foreach ($setting in $settingsFolders) {
            $output = @{}
            $output.Add("Name", $setting.name)
            $output.Add("Action", $setting.Properties.action)
            $output.Add("Path", $setting.Properties.path)
            $output
            ""
        }
    }
}

Function Get-GPONetworkShares {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
	$settingsNetShares = ($polXml.Computer.ExtensionData.Extension.NetworkShares.Netshare | Sort-Object GPOSettingOrder)
    
    if ($settingsNetShares) {
	    foreach ($setting in $settingsNetShares) {
            $output = @{}
            $output.Add("Name", $setting.name)
            $output.Add("Action", $setting.Properties.action)
            $output.Add("PropName", $setting.Properties.name)
            $output.Add("Path", $setting.Properties.path)
            $output.Add("Comment", $setting.Properties.comment)
            $output
            ""
        }
    }
}

Function Get-GPOIniFiles {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
    $settingsIniFiles = ($polXml.IniFiles.Ini | Sort-Object GPOSettingOrder)
    
    if ($settingsIniFiles) {

	    foreach ($setting in $settingsIniFiles) {
            $output = @{}
            $output.Add("Name", $setting.name)
            $output.Add("Path", $setting.Properties.path)
            $output.Add("Section", $setting.Properties.section)
            $output.Add("Value", $setting.Properties.value)
            $output.Add("Property", $setting.Properties.property)
            $output.Add("Action", $setting.Properties.action)
            $output
            ""
        }
    }
}

Function Get-GPOEnvVars {
    [cmdletbinding()]
    Param ($polXml, $PolicyType)
    
	$settingsEnvVars = ($polXml.EnvironmentVariables.EnvironmentVariable | Sort-Object GPOSettingOrder)
    
    if ($settingsEnvVars) {

	    foreach ($setting in $settingsEnvvars) {
            $output = @{}
            $output.Add("Name", $setting.name)
            $output.Add("Status", $setting.status)
            $output.Add("Value", $setting.properties.value)
            $output.Add("Action", $setting.properties.action)
            $output
            ""
        }
    }
}

Function Get-GPORegSettings {
    [cmdletbinding()]
    Param ($polXML, $PolicyType)

	$settingsRegSettings = ($polXml.Computer.ExtensionData.Extension.Policy | Sort-Object GPOSettingOrder)
    
    if ($settingsRegSettings) {

        # I hate this nested looping shit more than anything I've ever written.
        foreach ($setting in $settingsRegSettings) {
            $output = @{}
            $outverb = @{}

            $output.Add("Name", $setting.Name)
            $output.Add("State", $setting.State)
            $output.Add("Supported", $setting.Supported)
            $output.Add("Category", $setting.Category)
            $output.Add("Explain", $setting.Explain)
            $output
            ""
            
            foreach ($thing in $setting.EditText) {
                $output = @{}
                $output.Add("Name", $thing.Name)
                $output.Add("Value", $thing.Value)
                $output.Add("State", $thing.State)
                $output
                ""
            }

            foreach ($thing in $setting.DropDownList) {
                $output = @{}
                $output.Add("Name", $thing.Name)
                $output.Add("Value", $thing.Value)
                $output.Add("State", $thing.State)
                $output
                ""
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
                $output
                ""
            }

            foreach ($thing in $setting.Checkbox) {
                $output = @{}
                $output.Add("Value", $thing.Name)
                $output.Add("State", $thing.State)
                $output
                ""
            }

            foreach ($thing in $setting.Numeric) {
                $output = @{}
                $output.Add("Name", $thing.Name)
                $output.Add("Value", $thing.Value)
                $output.Add("State", $thing.State)
                $output
                ""
            }
        }
    }
}
# Here endeth the gross GPO check functions

#__________________________GPP decryption helper function stolen from PowerUp.ps1 by @harmjoy__________________
function Get-DecryptedCpassword {
    [CmdletBinding()]
    Param (
        [string] $Cpassword 
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
    
    catch {Write-Error $Error[0]}
}   

Function Write-Title {
    [cmdletbinding()]
    Param (
        $Text,
        $Color,
        $DividerChar
    )

    $DefForegroundColor = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = $Color
    ""
    $Text
    $divider = $DividerChar * $Text.Length
    $divider
    $host.ui.RawUI.ForegroundColor = $DefForegroundColor
}

#_____________________________________________________________________

Function Invoke-AuditGPO {
    [cmdletbinding()]
    # Consumes <GPO> objects from a Get-GPOReport xml report.
    Param (
        $xmlgpo
    )
    
    #check the GPO is even enabled
    $gpoisenabled = $xmlgpo.LinksTo.Enabled
    #and if it's not, increment our count of GPOs that don't do anything
    if (($gpoisenabled -ne "true") -And ($Global:showdisabled -eq 0)) {
        $Global:unlinkedgpos += 1
        return $null
    }

    #check if it's linked somewhere
    $gpopath = $xmlgpo.LinksTo.SOMName
    #and if it's not, increment our count of GPOs that don't do anything
    if ((-Not $gpopath) -And ($Global:showdisabled -eq 0)) {
        $Global:unlinkedgpos += 1
        return $null
    }

    # Build an array of all our Get-GPO* check scriptblocks
    $polchecks = @()
    $polchecks += {Get-GPORegKeys -polXML $computerSettings -PolicyType "Computer"}
    $polchecks += {Get-GPORegKeys -polXML $userSettings -PolicyType "User"}
    $polchecks += {Get-GPOUsers -polXML $userSettings -PolicyType "User"}
    $polchecks += {Get-GPOUsers -polXML $computerSettings -PolicyType "Computer"}
    $polchecks += {Get-GPOGroups -polXML $userSettings -PolicyType "User"}
    $polchecks += {Get-GPOGroups -polXML $computerSettings -PolicyType "Computer"}
    $polchecks += {Get-GPOScripts -polXML $userSettings -PolicyType "User"}
    $polchecks += {Get-GPOScripts -polXML $computerSettings -PolicyType "Computer"}
    $polchecks += {Get-GPOFileUpdate -polXML $userSettings -PolicyType "User"}
    $polchecks += {Get-GPOFileUpdate -polXML $computerSettings -PolicyType "Computer"}
    $polchecks += {Get-GPOMSIInstallation -polXML $xmlgpo}
    $polchecks += {Get-GPOUserRights -polXML $xmlgpo}
    $polchecks += {Get-GPOSchedTasks -polXML $xmlgpo}
    $polchecks += {Get-GPOFolderRedirection -polXML $xmlgpo}
    $polchecks += {Get-GPOFilePerms -polXML $xmlgpo}
    $polchecks += {Get-GPOSecurityOptions -polXML $xmlgpo}
    $polchecks += {Get-GPOAccountSettings -polXML $xmlgpo}
    $polchecks += {Get-GPONetworkShares -polXml $xmlgpo}
    $polchecks += {Get-GPOFolders -polXML $userSettings -PolicyType "User"}
    $polchecks += {Get-GPOFolders -polXML $computerSettings -PolicyType "Computer"}
    $polchecks += {Get-GPORegSettings -polXML $computerSettings -PolicyType "Computer"}
    $polchecks += {Get-GPORegSettings -polXML $userSettings -PolicyType "User"}
    $polchecks += {Get-GPOIniFiles -polXML $computerSettings -PolicyType "Computer"}
    $polchecks += {Get-GPOIniFiles -polXML $userSettings -PolicyType "User"}
    $polchecks += {Get-GPOEnvVars -polXML $computerSettings -PolicyType "Computer"}
    $polchecks += {Get-GPOEnvVars -polXML $userSettings -PolicyType "User"}
    #Get-GPOShortcuts -polXml $xmlgpo
    

    # Writes a pretty green header with the report name and some other nice details
    $headers = @()
    $headers += {'==============================================================='}
    $headers += {'Policy UID: {0}' -f $xmlgpo.Identifier.Identifier.InnerText}
    $headers += {'Policy created on: {0:d}' -f $xmlgpo.CreatedTime}
    $headers += {'Policy last modified: {0:d}' -f $xmlgpo.ModifiedTime}
    $headers += {'Policy owner: {0}' -f $xmlgpo.SecurityDescriptor.Owner.Name.InnerText}
    $headers += {'Linked OU: {0}' -f $gpopath}
    $headers += {'Link enabled: {0}' -f $gpoisenabled}
    $headers += {'==============================================================='}
       
    # in each GPO we parse, iterate through the list of checks to see if any of them return anything.
    $headerprinted = 0
    foreach ($polcheck in $polchecks) {
        $finding = & $polcheck # run the check and store the output
        if ($finding) {
            # the first time one of the checks returns something, show the user the header with the policy name and so on
            if ($headerprinted -ne 1) {
                # Write the title of the GPO in nice green text
                Write-Title -DividerChar "*" -Color "Green" -Text $xmlgpo.Name
                # Write the headers from above
                foreach ($header in $headers) {
                    & $header
                }
                # Parse and print out the GPO's Permissions
                Write-Title -DividerChar "#" -Color "Yellow" -Text "GPO Permissions"


                $GPOPermissions = $xmlgpo.SecurityDescriptor.Permissions.TrusteePermissions
                
                # an array of permission strings that we just don't care about
                $boringPerms = @()
                $boringPerms += "Read"
                $boringPerms += "Apply Group Policy"

                # an array of users who have RW permissions on GPOs by default, so they're boring too.
                $boringTrustees = @()
                $boringTrustees += "Domain Admins"
                $boringTrustees += "Enterprise Admins"
                $boringTrustees += "ENTERPRISE DOMAIN CONTROLLERS"
                $boringTrustees += "SYSTEM"

                #grab the name of the owner user from the GPO
                $owner = $xmlgpo.SecurityDescriptor.Owner.Name.InnerText
                #strip off the domain name so we can check it against the $boringtrustees array.
                $ownershort = ($owner -Split "\\")[1]
                
                # check if our owner is interesting. If not, add to $owner hash table
                if (-Not ($boringTrustees -contains $ownershort)) {
                    $ownerOutput = @{}
                    $ownerOutput.Add("Owner", $xmlgpo.SecurityDescriptor.Owner.Name.InnerText)
                    $ownerOutput
                }

                # iterate over each permission entry for the GPO
                foreach ($GPOACE in $GPOPermissions) {
                    $ACEType = $GPOACE.Standard.GPOGroupedAccessEnum # allow v deny
                    $trusteeName = $GPOACE.Trustee.Name.InnerText # who does it apply to
                    $trusteeShortName = ($trusteeName -Split "\\")[1] # strip the domain name off the account so we can compare to boringtrustees.
                    $trusteeSID = $GPOACE.Trustee.SID.InnerText # SID of the account/group it applies to
                    $ACEInteresting = 1 # ACEs are default interesting unless proven boring.
                    $permOutput = @{}

                    # check if our trustee is a default one
                    if ($trusteeName) {
                        if ($boringTrustees -Contains $trusteeShortName) {
                            $ACEInteresting = 0
                        }
                    }

                    # check if our permission type is boring
                    if ($boringPerms -Contains $ACEType) {
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
                $permOutput
                }
                # then we set $headerprinted so we don't print it all again
                $headerprinted = 1
                # add one to our tally of policies that were interesting for our final report
                $Global:interestingpols += 1
           }
            # Then for each actual finding we write the name of the check function that found something.
            $polchecktitle = ($polcheck.ToString()).split(" ")[0]
            Write-Title -DividerChar "#" -Color "Yellow" -Text $polchecktitle
            # Write out the actual finding
            $finding
        }
    }

	[System.GC]::Collect()
}

Function Invoke-AuditGPReport {
    [cmdletbinding()]
    param(
        [string]$Path,
        [switch]$showDisabled, # if not set, we filter out GPOs that aren't linked anywhere
        [switch]$showLessInteresting, # if not set, we filter out a bunch of stuff that is less likely to be abusable
        [switch]$lazyMode # if you enable this I'll do the Get-GPOReport thing for you.
        )

    # couple of counters for the stats at the end
    $Global:unlinkedgpos = 0
    $Global:interestingpols = 0
    $Global:vinterestingpols = 0

    #handle our arguments
    $Global:showBoring = 0
    if ($showLessInteresting) {
        $Global:showBoring = 1
    }

    $Global:showWhereApplied = 0
    if ($whereApplied) {
        $Global:showWhereApplied = 1
    }

    $Global:showdisabled = 0 
    if ($showDisabled) {
        $Global:showdisabled = 1
    }
    if ($Path) {
        $gpreportpath = $Path
    }

    if ($lazyMode) {
        Get-GPOReport -All -ReportType xml -Path $pwd\gporeport.xml
        [xml]$xmldoc = get-content $pwd\gporeport.xml
    }
    else {
        # get the contents of the report file
        [xml]$xmldoc = get-content $Path
    }

    # get all the GPOs into an array
    $xmlgpos = $xmldoc.report.GPO

    # iterate over them running the selected checks
    foreach ($xmlgpo in $xmlgpos) {
        Invoke-AuditGPO -xmlgpo $xmlgpo

        if ($gpoaudit -ne $false) {
            $gpoaudit
        }
    }
    
    Write-Title -Color "Green" -DividerChar "*" -Text "Stats"
    $stats = @()
    $stats += ('Total GPOs: {0}' -f $xmlgpos.Count)
    $stats += ('Unlinked GPOs: {0}' -f $unlinkedgpos)
    $stats += ('Interesting GPOs: {0}' -f $interestingpols)
    $stats
    ""
}
