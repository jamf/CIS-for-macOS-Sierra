#!/bin/bash

####################################################################################################
#
# Copyright (c) 2017, Jamf, LLC.  All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are met:
#               * Redistributions of source code must retain the above copyright
#                 notice, this list of conditions and the following disclaimer.
#               * Redistributions in binary form must reproduce the above copyright
#                 notice, this list of conditions and the following disclaimer in the
#                 documentation and/or other materials provided with the distribution.
#               * Neither the name of the JAMF Software, LLC nor the
#                 names of its contributors may be used to endorse or promote products
#                 derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY JAMF SOFTWARE, LLC "AS IS" AND ANY
#       EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#       WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#       DISCLAIMED. IN NO EVENT SHALL JAMF SOFTWARE, LLC BE LIABLE FOR ANY
#       DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#       (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#       LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#       ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#       SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
####################################################################################################

# written by Katie English, Jamf October 2016
# updated for 10.12 CIS benchmarks by Katie English, Jamf February 2017
# github.com/jamfprofessionalservices

# USAGE
# Reads from plist at /Library/Application Support/SecurityScoring/org_security_score.plist by default.
# For "true" items, runs query for current computer/user compliance.
# Non-compliant items are logged to /Library/Application Support/SecurityScoring/org_audit

plistlocation="/Library/Application Support/SecurityScoring/org_security_score.plist"
auditfilelocation="/Library/Application Support/SecurityScoring/org_audit"

if [[ ! -e $plistlocation ]]; then
	echo "No scoring file present"
	exit 0
fi

# Cleanup audit file to start fresh
[ -f "$auditfilelocation" ] && rm "$auditfilelocation"
touch "$auditfilelocation"

# Other variables
currentUser=$( ls -l /dev/console | cut -d " " -f4 )
hardwareUUID=$( /usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | awk -F ": " '{print $2}' | xargs )

# 1.1 Verify all Apple provided software is current
# Verify organizational score
Audit1_1="$(defaults read "$plistlocation" OrgScore1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_1" = "1" ]; then
	countAvailableSUS="$(softwareupdate -l | grep "*" | wc -l | tr -d ' ')"
	# If client fails, then note category in audit file
	if [ "$countAvailableSUS" = "0" ]; then
		echo "1.1 passed"; else
		echo "* 1.1 Verify all Apple provided software is current" >> "$auditfilelocation"
	fi
fi

# 1.2 Enable Auto Update
# Verify organizational score
Audit1_2="$(defaults read "$plistlocation" OrgScore1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_2" = "1" ]; then
	# Check to see if the preference and key exist. If not, write to audit log. Presuming: Unset = not secure state.
	if [ "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate | grep -c AutomaticCheckEnabled)" = 0 ]; then
		echo "* 1.2 Enable Auto Update" >> "$auditfilelocation"
	else
		if [ "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate | grep -c AutomaticCheckEnabled)" = 1 ]; then
			automaticUpdates="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled)"
			# If client fails, then note category in audit file
			if [ "$automaticUpdates" = "1" ]; then
				echo "1.2 passed"; else
				echo "* 1.2 Enable Auto Update" >> "$auditfilelocation"
			fi	
		fi
	fi
fi

# 1.3 Enable app update installs
# Verify organizational score
Audit1_3="$(defaults read "$plistlocation" OrgScore1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_3" = "1" ]; then
	if [ "$(defaults read /Library/Preferences/com.apple.commerce | grep -c AutoUpdate)" = 0 ]; then
		echo "* 1.3 Enable app update installs" >> "$auditfilelocation"
	else
		automaticAppUpdates="$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate)"
		# If client fails, then note category in audit file
		if [ "$automaticAppUpdates" = "1" ]; then
			echo "1.3 passed"; else
			echo "* 1.3 Enable app update installs" >> "$auditfilelocation"
		fi
	fi
fi

# 1.4 Enable system data files and security update installs 
# Verify organizational score
Audit1_4="$(defaults read "$plistlocation" OrgScore1_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_4" = "1" ]; then
		if [ "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate | grep -c ConfigDataInstall)" = 0 ]; then
		echo "* 1.4 Enable system data files and security update installs" >> "$auditfilelocation"
	else
		criticalUpdates="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall)"
		# If client fails, then note category in audit file
		if [ "$criticalUpdates" = "1" ]; then
			echo "1.4 passed"; else
			echo "* 1.4 Enable system data files and security update installs" >> "$auditfilelocation"
		fi
	fi
fi

# 1.5 Enable OS X update installs 
# Verify organizational score
Audit1_5="$(defaults read "$plistlocation" OrgScore1_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_5" = "1" ]; then
		if [ "$(defaults read /Library/Preferences/com.apple.commerce | grep -c AutoUpdateRestartRequired)" = 0 ]; then
		echo "* 1.5 Enable OS X update installs" >> "$auditfilelocation"
	else
		updateRestart="$(defaults read /Library/Preferences/com.apple.commerce AutoUpdateRestartRequired)"
		# If client fails, then note category in audit file
		if [ "$updateRestart" = "1" ]; then
			echo "1.5 passed"; else
			echo "* 1.5 Enable OS X update installs" >> "$auditfilelocation"
		fi
	fi
fi


# 2.1.1 Turn off Bluetooth, if no paired devices exist
# Verify organizational score
Audit2_1_1="$(defaults read "$plistlocation" OrgScore2_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_1_1" = "1" ]; then
	btPowerState="$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState)"
	# If client fails, then note category in audit file
	if [ "$btPowerState" = "0" ]; then
		echo "2.1.1 passed"; else
		connectable=$(system_profiler SPBluetoothDataType | grep Connectable | awk '{print $2}' | head -1 )
		if [ "$connectable" = "Yes" ]; then
			echo "2.1.1 passed"; else
			echo "* 2.1.1 Turn off Bluetooth, if no paired devices exist" >> "$auditfilelocation"
		fi
	fi
fi


# 2.1.3 Show Bluetooth status in menu bar
# Verify organizational score
Audit2_1_3="$(defaults read "$plistlocation" OrgScore2_1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_1_3" = "1" ]; then
	btMenuBar="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.systemuiserver menuExtras | grep -c Bluetooth.menu)"
	# If client fails, then note category in audit file
	if [ "$btMenuBar" = "0" ]; then
		echo "* 2.1.3 Show Bluetooth status in menu bar" >> "$auditfilelocation"; else
		echo "2.1.3 passed"
	fi
fi

# 2.2.2 Ensure time set is within appropriate limits
# Not audited - only enforced if identified as priority
# Verify organizational score
Audit2_2_2="$(defaults read "$plistlocation" OrgScore2_2_2)"
# If organizational score is 1 or true, check status of client
# if [ "$Audit2_2_2" = "1" ]; then
# sync time 
# fi

# 2.2.3 Restrict NTP server to loopback interface
# Verify organizational score
Audit2_2_3="$(defaults read "$plistlocation" OrgScore2_2_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_2_3" = "1" ]; then
	restrictNTP=$(cat /etc/ntp-restrict.conf | grep -c "restrict lo")
	# If client fails, then note category in audit file
	if [ "$restrictNTP" = "0" ]; then
		echo "* 2.2.3 Restrict NTP server to loopback interface" >> "$auditfilelocation"; else
		echo "2.2.3 passed"
	fi
fi

# 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver 
# Verify organizational score
Audit2_3_1="$(defaults read "$plistlocation" OrgScore2_3_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_3_1" = "1" ]; then
	screenSaverTime="$(defaults read /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.screensaver.$hardwareUUID.plist idleTime)"
	# If client fails, then note category in audit file
	if [ "$screenSaverTime" -le "1200" ]; then
		echo "2.3.1 passed"; else
		echo "* 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver" >> "$auditfilelocation"
	fi
fi

# 2.3.2 Secure screen saver corners 
# Verify organizational score
Audit2_3_2="$(defaults read "$plistlocation" OrgScore2_3_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_3_2" = "1" ]; then
	bl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)
	tl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)
	tr_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)
	br_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)
	# If client fails, then note category in audit file
	if [ "$bl_corner" = "6" ] || [ "$tl_corner" = "6" ] || [ "$tr_corner" = "6" ] || [ "$br_corner" = "6" ]; then
		echo "* 2.3.2 Secure screen saver corners" >> "$auditfilelocation"; else
		echo "2.3.2 passed"
	fi
fi


# 2.3.4 Set a screen corner to Start Screen Saver 
# Verify organizational score
Audit2_3_4="$(defaults read "$plistlocation" OrgScore2_3_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_3_4" = "1" ]; then
	# If client fails, then note category in audit file
	bl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)
	tl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)
	tr_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)
	br_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)
	if [ "$bl_corner" = "5" ] || [ "$tl_corner" = "5" ] || [ "$tr_corner" = "5" ] || [ "$br_corner" = "5" ]; then
		echo "2.3.4 passed"; else
		echo "* 2.3.4 Set a screen corner to Start Screen Saver" >> "$auditfilelocation"
	fi
fi

# 2.4.1 Disable Remote Apple Events 
# Verify organizational score
Audit2_4_1="$(defaults read "$plistlocation" OrgScore2_4_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_1" = "1" ]; then
	remoteAppleEvents=$(systemsetup -getremoteappleevents | awk '{print $4}')
	# If client fails, then note category in audit file
	if [ "$remoteAppleEvents" = "Off" ]; then
	 	echo "2.4.1 passed"; else
		echo "* 2.4.1 Disable Remote Apple Events" >> "$auditfilelocation"
	fi
fi

# 2.4.2 Disable Internet Sharing 
# Verify organizational score
Audit2_4_2="$(defaults read "$plistlocation" OrgScore2_4_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then note category in audit file
if [ "$Audit2_4_2" = "1" ]; then
	if [ -e /Library/Preferences/SystemConfiguration/com.apple.nat.plist ]; then
		natAirport=$(/usr/libexec/PlistBuddy -c "print :NAT:AirPort:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist)
		natEnabled=$(/usr/libexec/PlistBuddy -c "print :NAT:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist)
		natPrimary=$(/usr/libexec/PlistBuddy -c "print :NAT:PrimaryInterface:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist)
		if [ "$natAirport" = "true" ] || [ "$natEnabled" = "true" ] || [ "$natPrimary" = "true" ]; then
			echo "* 2.4.2 Disable Internet Sharing"  >> "$auditfilelocation"; else
			echo "2.4.2 passed"
		fi; else
		echo "2.4.2 passed"
	fi
fi

# 2.4.3 Disable Screen Sharing 
# Verify organizational score
Audit2_4_3="$(defaults read "$plistlocation" OrgScore2_4_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_3" = "1" ]; then
	# If client fails, then note category in audit file
	screenSharing=$(defaults read /System/Library/LaunchDaemons/com.apple.screensharing Disabled)
	if [ "$screenSharing" = "1" ]; then
	 	echo "2.4.3 passed"; else
		echo "* 2.4.3 Disable Screen Sharing" >> "$auditfilelocation"
	fi
fi

# 2.4.4 Disable Printer Sharing 
# Verify organizational score
Audit2_4_4="$(defaults read "$plistlocation" OrgScore2_4_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_4" = "1" ]; then
	# If client fails, then note category in audit file
	printerSharing=$(system_profiler SPPrintersDataType | grep -c "Shared: Yes")
	if [ "$printerSharing" = "0" ]; then
	 	echo "2.4.4 passed"; else
		echo "* 2.4.4 Disable Printer Sharing" >> "$auditfilelocation"
	fi
fi

# 2.4.5 Disable Remote Login 
# Verify organizational score
Audit2_4_5="$(defaults read "$plistlocation" OrgScore2_4_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_5" = "1" ]; then
	remoteLogin=$(systemsetup -getremotelogin | awk '{print $3}')
	# If client fails, then note category in audit file
	if [ "$remoteLogin" = "Off" ]; then
	 	echo "2.4.5 passed"; else
		echo "* 2.4.5 Disable Remote Login" >> "$auditfilelocation"
	fi
fi

# 2.4.6 Disable DVD or CD Sharing 
# Verify organizational score
Audit2_4_6="$(defaults read "$plistlocation" OrgScore2_4_6)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_6" = "1" ]; then
	discSharing=$(launchctl list | egrep ODSAgent)
	# If client fails, then note category in audit file
	if [ "$discSharing" = "" ]; then
	 	echo "2.4.6 passed"; else
		echo "* 2.4.6 Disable DVD or CD Sharing" >> "$auditfilelocation"
	fi
fi


# 2.4.7 Disable Bluetooth Sharing
# Verify organizational score
Audit2_4_7="$(defaults read "$plistlocation" OrgScore2_4_7)"
# If organizational score is 1 or true, check status of client and user
if [ "$Audit2_4_7" = "1" ]; then
	btSharing="$(/usr/libexec/PlistBuddy -c "print :PrefKeyServicesEnabled"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth.$hardwareUUID.plist)"
	# If client fails, then note category in audit file
	if [ "$btSharing" = "false" ]; then
	 	echo "2.4.7 passed"; else
		echo "* 2.4.7 Disable Bluetooth Sharing" >> "$auditfilelocation"
	fi
fi

# 2.4.8 Disable File Sharing
# Verify organizational score
Audit2_4_8="$(defaults read "$plistlocation" OrgScore2_4_8)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_8" = "1" ]; then
	afpEnabled=$(launchctl list | egrep AppleFileServer)
	smbEnabled=$(launchctl list | egrep smbd)
	# If client fails, then note category in audit file
	if [ "$afpEnabled" = "" ] && [ "$smbEnabled" = "" ]; then
 		echo "2.4.8 passed"; else
		echo "* 2.4.8 Disable File Sharing" >> "$auditfilelocation"
	fi
fi

# 2.4.9 Disable Remote Management
# Verify organizational score
Audit2_4_9="$(defaults read "$plistlocation" OrgScore2_4_9)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_9" = "1" ]; then
	remoteManagement=$(ps -ef | egrep ARDAgent | grep -c "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent")
	# If client fails, then note category in audit file
	if [ "$remoteManagement" = "1" ]; then
 		echo "2.4.9 passed"; else
		echo "* 2.4.9 Disable Remote Management" >> "$auditfilelocation"
	fi
fi

# 2.5.1 Disable "Wake for network access"
# Verify organizational score
Audit2_5_1="$(defaults read "$plistlocation" OrgScore2_5_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_1" = "1" ]; then
	wompEnabled=$(pmset -g | grep womp | awk '{print $2}')
	# If client fails, then note category in audit file
	if [ "$wompEnabled" = "0" ]; then
	 	echo "2.5.1 passed"; else
		echo "* 2.5.1 Disable Wake for network access" >> "$auditfilelocation"
	fi
fi

# 2.5.2 Disable sleeping the computer when connected to power 
# Verify organizational score
Audit2_5_2="$(defaults read "$plistlocation" OrgScore2_5_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_2" = "1" ]; then
	disksleepEnabled=$(pmset -g | grep disksleep | awk '{print $2}')
	# If client fails, then note category in audit file
	if [ "$disksleepEnabled" = "0" ]; then
	 	echo "2.5.2 passed"; else
		echo "* 2.5.2 Disable sleeping the computer when connected to power" >> "$auditfilelocation"
	fi
fi

# 2.6.1 Enable FileVault 
# Verify organizational score
Audit2_6_1="$(defaults read "$plistlocation" OrgScore2_6_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_1" = "1" ]; then
	filevaultEnabled=$(fdesetup status | awk '{print $3}')
	# If client fails, then note category in audit file
	if [ "$filevaultEnabled" = "Off." ]; then
		echo "* 2.6.1 Enable FileVault" >> "$auditfilelocation"; else
		echo "2.6.1 passed"	
	fi
fi

# 2.6.2 Enable Gatekeeper 
# Verify organizational score
Audit2_6_2="$(defaults read "$plistlocation" OrgScore2_6_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_2" = "1" ]; then
	gatekeeperEnabled=$(spctl --status | grep -c "assessments enabled")
	# If client fails, then note category in audit file
	if [ "$gatekeeperEnabled" = "1" ]; then
		echo "2.6.2 passed"; else
		echo "* 2.6.2 Enable Gatekeeper" >> "$auditfilelocation"
	fi
fi

# 2.6.3 Enable Firewall 
# Verify organizational score
Audit2_6_3="$(defaults read "$plistlocation" OrgScore2_6_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_3" = "1" ]; then
	firewallEnabled=$(defaults read /Library/Preferences/com.apple.alf globalstate)
	# If client fails, then note category in audit file
	if [ "$firewallEnabled" = "0" ]; then
		echo "* 2.6.3 Enable Firewall" >> "$auditfilelocation"; else
	 	echo "2.6.3 passed"
	fi
fi

# 2.6.4 Enable Firewall Stealth Mode 
# Verify organizational score
Audit2_6_4="$(defaults read "$plistlocation" OrgScore2_6_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_4" = "1" ]; then
	stealthEnabled=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | awk '{print $3}')
	# If client fails, then note category in audit file
	if [ "$stealthEnabled" = "enabled" ]; then
		echo "2.6.4 passed"; else
		echo "* 2.6.4 Enable Firewall Stealth Mode" >> "$auditfilelocation"
	fi
fi

# 2.6.5 Review Application Firewall Rules
# Verify organizational score
Audit2_6_5="$(defaults read "$plistlocation" OrgScore2_6_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_5" = "1" ]; then
	appsInbound=$(/usr/libexec/ApplicationFirewall/socketfilterfw --listapps | grep ALF | awk '{print $7}')
	# If client fails, then note category in audit file
	if [ "$appsInbound" -le "10" ] || [ -z "$appsInbound" ]; then
		echo "2.6.5 passed"; else
		echo "* 2.6.5 Review Application Firewall Rules" >> "$auditfilelocation"
	fi
fi

# 2.7.4 iCloud Drive Document sync
# Verify organizational score
Audit2_7_4="$(defaults read "$plistlocation" OrgScore2_7_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_7_4" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /Users/"$currentUser"/Library/Mobile\ Documents/com~apple~CloudDocs/Documents/ ]; then
			icloudDriveDocSync=$( ls /Users/"$currentUser"/Library/Mobile\ Documents/com~apple~CloudDocs/Documents/ | wc -l )
				if [ "$icloudDriveDocSync" = "0" ]; then
				echo "2.7.4 passed"; else
				echo "* 2.7.4 iCloud Drive Document sync" >> "$auditfilelocation"
				fi
	else
	echo "2.7.4 passed"
	fi
fi

# 2.7.5 iCloud Drive Desktop sync
# Verify organizational score
Audit2_7_5="$(defaults read "$plistlocation" OrgScore2_7_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_7_5" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /Users/"$currentUser"/Library/Mobile\ Documents/com~apple~CloudDocs/Desktop/ ]; then
			icloudDriveDeskSync=$( ls /Users/"$currentUser"/Library/Mobile\ Documents/com~apple~CloudDocs/Desktop/ | wc -l )
				if [ "$icloudDriveDeskSync" = "0" ]; then
				echo "2.7.5 passed"; else
				echo "* 2.7.5 iCloud Drive Desktop sync" >> "$auditfilelocation"
				fi
	else
	echo "2.7.5 passed"
	fi
fi

# 2.8.1 Time Machine Auto-Backup
# Verify organizational score
Audit2_8_1="$(defaults read "$plistlocation" OrgScore2_8_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_8_1" = "1" ]; then
	timeMachineAuto=$( defaults read /Library/Preferences/com.apple.TimeMachine.plist AutoBackup )
	# If client fails, then note category in audit file
	if [ "$timeMachineAuto" != "1" ]; then
		echo "* 2.8.1 Time Machine Auto-Backup" >> "$auditfilelocation"; else
		echo "2.8.1 passed"
	fi
fi


# 2.9 Pair the remote control infrared receiver if enabled
# Verify organizational score
Audit2_9="$(defaults read "$plistlocation" OrgScore2_9)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_9" = "1" ]; then
	IRPortDetect=$(system_profiler SPUSBDataType | egrep "IR Receiver" -c)
	# If client fails, then note category in audit file
	if [ "$IRPortDetect" = "0" ]; then
		echo "2.9 passed"; else
		echo "* 2.9 Pair the remote control infrared receiver if enabled" >> "$auditfilelocation"
	fi
fi

# 2.10 Enable Secure Keyboard Entry in terminal.app 
# Verify organizational score
Audit2_10="$(defaults read "$plistlocation" OrgScore2_10)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_10" = "1" ]; then
	secureKeyboard=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.Terminal SecureKeyboardEntry)
	# If client fails, then note category in audit file
	if [ "$secureKeyboard" = "1" ]; then
		echo "2.10 passed"; else
		echo "* 2.10 Enable Secure Keyboard Entry in terminal.app" >> "$auditfilelocation"
	fi
fi

# 2.11 Java 6 is not the default Java runtime 
# Verify organizational score
Audit2_11="$(defaults read "$plistlocation" OrgScore2_11)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_11" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -f "/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Enabled.plist" ] ; then
		javaVersion=$( defaults read "/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Enabled.plist" CFBundleVersion )
		javaMajorVersion=$(echo "$javaVersion" | awk -F'.' '{print $2}')	
		if [ "$javaMajorVersion" -lt "7" ]; then
			echo "* 2.11 Java 6 is not the default Java runtime" >> "$auditfilelocation"; else
			echo "2.11 passed"
		fi
	fi
	if [ ! -f "/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Enabled.plist" ] ; then
		echo "2.11 passed"
	fi
fi

# 3.1.1 Retain system.log for 90 or more days 
# Verify organizational score
Audit3_1_1="$(defaults read "$plistlocation" OrgScore3_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_1_1" = "1" ]; then
	sysRetention=$(grep "system.log" /etc/asl.conf | grep "ttl" | awk -F'ttl=' '{print $2}')
	# If client fails, then note category in audit file
	if [ "$sysRetention" -lt "90" ] || [ "$sysRetention" = "" ]; then
		echo "* 3.1.1 Retain system.log for 90 or more days" >> "$auditfilelocation"; else
		echo "3.1.1 passed"
	fi
fi

# 3.1.2 Retain appfirewall.log for 90 or more days 
# Verify organizational score
Audit3_1_2="$(defaults read "$plistlocation" OrgScore3_1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_1_2" = "1" ]; then
	alfRetention=$(grep "appfirewall.log" /etc/asl.conf | grep "ttl" | awk -F'ttl=' '{print $2}')
	# If client fails, then note category in audit file
	if [ "$alfRetention" -lt "90" ] || [ "$alfRetention" = "" ]; then
		echo "* 3.1.2 Retain appfirewall.log for 90 or more days" >> "$auditfilelocation"; else
		echo "3.1.2 passed"
	fi
fi

# 3.1.3 Retain authd.log for 90 or more days
# Verify organizational score
Audit3_1_3="$(defaults read "$plistlocation" OrgScore3_1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_1_3" = "1" ]; then
	authdRetention=$(grep -i ttl /etc/asl/com.apple.authd | awk -F'ttl=' '{print $2}')
	# If client fails, then note category in audit file
	if [ "$authdRetention" = "" ] || [ "$authdRetention" -lt "90" ]; then
		echo "* 3.1.3 Retain authd.log for 90 or more days" >> "$auditfilelocation"; else
		echo "3.1.3 passed"
	fi
fi

# 3.2 Enable security auditing
# Verify organizational score
Audit3_2="$(defaults read "$plistlocation" OrgScore3_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_2" = "1" ]; then
	auditdEnabled=$(launchctl list | grep -c auditd)
	# If client fails, then note category in audit file
	if [ "$auditdEnabled" -gt "0" ]; then
		echo "3.2 passed"; else
		echo "* 3.2 Enable security auditing" >> "$auditfilelocation"
	fi
fi

# 3.3 Configure Security Auditing Flags
# Verify organizational score
Audit3_3="$(defaults read "$plistlocation" OrgScore3_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_3" = "1" ]; then
	auditFlags=$(egrep "^flags:" /etc/security/audit_control)
	# If client fails, then note category in audit file
	if [[ ${auditFlags} != *"ad"* ]];then
		echo "* 3.3 Configure Security Auditing Flags" >> "$auditfilelocation"; else
		echo "3.3 passed"
	fi
fi

# 3.5 Retain install.log for 365 or more days 
# Verify organizational score
Audit3_5="$(defaults read "$plistlocation" OrgScore3_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_5" = "1" ]; then
	installRetention=$(grep -i ttl /etc/asl/com.apple.install | awk -F'ttl=' '{print $2}')
	# If client fails, then note category in audit file
	if [ "$installRetention" = "" ] || [ "$installRetention" -lt "365" ]; then
		echo "* 3.5 Retain install.log for 365 or more days" >> "$auditfilelocation"; else
		echo "3.5 passed"
	fi
fi

# 4.1 Disable Bonjour advertising service 
# Verify organizational score
Audit4_1="$(defaults read "$plistlocation" OrgScore4_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit4_1" = "1" ]; then
	bonjourAdvertise=$( defaults read /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements )
	# If client fails, then note category in audit file
	if [ "$bonjourAdvertise" != "1" ]; then
		echo "* 4.1 Disable Bonjour advertising service" >> "$auditfilelocation"; else
		echo "4.1 passed"
	fi
fi

# 4.2 Enable "Show Wi-Fi status in menu bar" 
# Verify organizational score
Audit4_2="$(defaults read "$plistlocation" OrgScore4_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit4_2" = "1" ]; then
	wifiMenuBar="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.systemuiserver menuExtras | grep -c AirPort.menu)"
	# If client fails, then note category in audit file
	if [ "$wifiMenuBar" = "0" ]; then
		echo "* 4.2 Enable Show Wi-Fi status in menu bar" >> "$auditfilelocation"; else
		echo "4.2 passed"
	fi
fi

# 4.4 Ensure http server is not running 
# Verify organizational score
Audit4_4="$(defaults read "$plistlocation" OrgScore4_4)"
# If organizational score is 1 or true, check status of client
# Code fragment from https://github.com/krispayne/CIS-Settings/blob/master/ElCapitan_CIS.sh
if [ "$Audit4_4" = "1" ]; then
	if /bin/launchctl list | egrep httpd > /dev/null; then
		echo "* 4.4 Ensure http server is not running" >> "$auditfilelocation"; else
		echo "4.4 passed"
	fi
fi

# 4.5 Ensure ftp server is not running 
# Verify organizational score
Audit4_5="$(defaults read "$plistlocation" OrgScore4_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit4_5" = "1" ]; then
	ftpEnabled=$(launchctl list | egrep ftp | grep -c "com.apple.ftpd")
	# If client fails, then note category in audit file
	if [ "$ftpEnabled" -lt "1" ]; then
		echo "4.5 passed"; else
		echo "* 4.5 Ensure ftp server is not running" >> "$auditfilelocation"
	fi
fi

# 4.6 Ensure nfs server is not running
# Verify organizational score
Audit4_6="$(defaults read "$plistlocation" OrgScore4_6)"
# If organizational score is 1 or true, check status of client
if [ "$Audit4_6" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /etc/exports  ]; then
		echo "4.6 Ensure nfs server is not running" >> "$auditfilelocation"; else
		echo "4.6 passed"
	fi
fi

# 5.1.1 Secure Home Folders
# Verify organizational score
Audit5_1_1="$(defaults read "$plistlocation" OrgScore5_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_1_1" = "1" ]; then
	homeFolders=$(find /Users -mindepth 1 -maxdepth 1 -type d -perm -1 | grep -v "Shared" | grep -v "Guest" | wc -l | xargs)
	# If client fails, then note category in audit file
	if [ "$homeFolders" = "0" ]; then
		echo "5.1.1 passed"; else
		echo "* 5.1.1 Secure Home Folders" >> "$auditfilelocation"
	fi
fi

# 5.1.2 Check System Wide Applications for appropriate permissions
# Verify organizational score
Audit5_1_2="$(defaults read "$plistlocation" OrgScore5_1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_1_2" = "1" ]; then
	appPermissions=$(find /Applications -iname "*\.app" -type d -perm -2 -ls | wc -l | xargs)
	# If client fails, then note category in audit file
	if [ "$appPermissions" = "0" ]; then
		echo "5.1.2 passed"; else
		echo "* 5.1.2 Check System Wide Applications for appropriate permissions" >> "$auditfilelocation"
	fi
fi

# 5.1.3 Check System folder for world writable files
# Verify organizational score
Audit5_1_3="$(defaults read "$plistlocation" OrgScore5_1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_1_3" = "1" ]; then
	sysPermissions=$(find /System -type d -perm -2 -ls | grep -v "Public/Drop Box" | wc -l | xargs)
	# If client fails, then note category in audit file
	if [ "$sysPermissions" = "0" ]; then
		echo "5.1.3 passed"; else
		echo "* 5.1.3 Check System folder for world writable files" >> "$auditfilelocation"
	fi
fi

# 5.1.4 Check Library folder for world writable files
# Verify organizational score
Audit5_1_4="$(defaults read "$plistlocation" OrgScore5_1_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_1_4" = "1" ]; then
	libPermissions=$(find /Library -type d -perm -2 -ls | grep -v Caches | wc -l | xargs)
	# If client fails, then note category in audit file
	if [ "$libPermissions" = "0" ]; then
		echo "5.1.4 passed"; else
		echo "* 5.1.4 Check Library folder for world writable files" >> "$auditfilelocation"
	fi
fi

# 5.3 Reduce the sudo timeout period
# Verify organizational score
Audit5_3="$(defaults read "$plistlocation" OrgScore5_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_3" = "1" ]; then
	sudoTimeout=$(cat /etc/sudoers | grep timestamp)
	# If client fails, then note category in audit file
	if [ "$sudoTimeout" = "" ]; then
		echo "* 5.3 Reduce the sudo timeout period" >> "$auditfilelocation"; else
		echo "5.3 passed"
	fi
fi

# 5.4 Automatically lock the login keychain for inactivity
# Verify organizational score
Audit5_4="$(defaults read "$plistlocation" OrgScore5_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_4" = "1" ]; then
	keyTimeout=$(security show-keychain-info /Users/"$currentUser"/Library/Keychains/login.keychain 2>&1 | grep -c "no-timeout")
	# If client fails, then note category in audit file
	if [ "$keyTimeout" -gt 0 ]; then
		echo "* 5.4 Automatically lock the login keychain for inactivity" >> "$auditfilelocation"; else
		echo "5.4 passed"
	fi
fi


# 5.5 Ensure login keychain is locked when the computer sleeps
# Verify organizational score
Audit5_5="$(defaults read "$plistlocation" OrgScore5_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_5" = "1" ]; then
	lockSleep=$(security show-keychain-info /Users/"$currentUser"/Library/Keychains/login.keychain 2>&1 | grep -c "lock-on-sleep")
	# If client fails, then note category in audit file
	if [ "$lockSleep" = 0 ]; then
		echo "* 5.5 Ensure login keychain is locked when the computer sleeps" >> "$auditfilelocation"; else
		echo "5.5 passed"
	fi
fi

# 5.6 Enable OCSP and CRL certificate checking
# Verify organizational score
Audit5_6="$(defaults read "$plistlocation" OrgScore5_6)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_6" = "1" ]; then
	certificateCheckOCSP=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation OCSPStyle)
	certificateCheckCRL=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation CRLStyle)
	# If client fails, then note category in audit file
	if [ "$certificateCheckOCSP" != "RequireIfPresent" ] || [ "$certificateCheckCRL" != "RequireIfPresent" ]; then
		echo "* 5.6 Enable OCSP and CRL certificate checking" >> "$auditfilelocation"; else
		echo "5.6 passed"
	fi
fi

# 5.7 Do not enable the "root" account
# Verify organizational score
Audit5_7="$(defaults read "$plistlocation" OrgScore5_7)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_7" = "1" ]; then
	rootEnabled=$(dscl . -read /Users/root AuthenticationAuthority 2>&1 | grep -c "No such key")
	# If client fails, then note category in audit file
	if [ "$rootEnabled" = "1" ]; then
		echo "5.7 passed"; else
		echo "* 5.7 Do not enable the root account" >> "$auditfilelocation"
	fi
fi

# 5.8 Disable automatic login
# Verify organizational score
Audit5_8="$(defaults read "$plistlocation" OrgScore5_8)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_8" = "1" ]; then
	autologinEnabled=$(defaults read /Library/Preferences/com.apple.loginwindow | grep autoLoginUser)
	# If client fails, then note category in audit file
	if [ "$autologinEnabled" = "" ]; then
		echo "5.8 passed"; else
		echo "* 5.8 Disable automatic login" >> "$auditfilelocation"
	fi
fi

# 5.9 Require a password to wake the computer from sleep or screen saver
# Verify organizational score
Audit5_9="$(defaults read "$plistlocation" OrgScore5_9)"
# If organizational score is 1 or true, check status of client
# If client fails, then note category in audit file
if [ "$Audit5_9" = "1" ]; then
	screensaverPwd=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.screensaver askForPassword)
	if [ "$screensaverPwd" = "1" ]; then
		echo "5.9 passed"; else
		echo "* 5.9 Require a password to wake the computer from sleep or screen saver" >> "$auditfilelocation"
	fi
fi

# 5.10 Require an administrator password to access system-wide preferences
# Verify organizational score
Audit5_10="$(defaults read "$plistlocation" OrgScore5_10)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_10" = "1" ]; then
	adminSysPrefs=$(security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep -E '(true|false)' | grep -c "true")
	# If client fails, then note category in audit file
	if [ "$adminSysPrefs" = "1" ]; then
		echo "* 5.10 Require an administrator password to access system-wide preferences" >> "$auditfilelocation"; else
		echo "5.10 passed"
	fi
fi

# 5.11 Disable ability to login to another user's active and locked session
# Verify organizational score
Audit5_11="$(defaults read "$plistlocation" OrgScore5_11)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_11" = "1" ]; then
	screensaverGroups=$(grep -c "group=admin,wheel fail_safe" /etc/pam.d/screensaver)
	# If client fails, then note category in audit file
	if [ "$screensaverGroups" = "1" ]; then
		echo "* 5.11 Disable ability to login to another user's active and locked session" >> "$auditfilelocation"; else
		echo "5.11 passed"
	fi
fi

# 5.12 Create a custom message for the Login Screen
# Verify organizational score
Audit5_12="$(defaults read "$plistlocation" OrgScore5_12)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_12" = "1" ]; then
	loginMessage=$(defaults read /Library/Preferences/com.apple.loginwindow.plist LoginwindowText)
	# If client fails, then note category in audit file
	if [ "$loginMessage" = "" ]; then
		echo "* 5.12 Create a custom message for the Login Screen" >> "$auditfilelocation"; else
		echo "5.12 passed"
	fi
fi

# 5.13 Create a Login window banner
# Verify organizational score
Audit5_13="$(defaults read "$plistlocation" OrgScore5_13)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_13" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /Library/Security/PolicyBanner.txt ] || [ -e /Library/Security/PolicyBanner.rtf ] || [ -e /Library/Security/PolicyBanner.rtfd ]; then
		echo "5.13 passed"; else
		echo "* 5.13 Create a Login window banner" >> "$auditfilelocation"
	fi
fi

# 5.18 System Integrity Protection status
# Verify organizational score
Audit5_18="$(defaults read "$plistlocation" OrgScore5_18)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_18" = "1" ]; then
	sipEnabled=$(/usr/bin/csrutil status | awk '{print $5}')
	# If client fails, then note category in audit file
	if [ "$sipEnabled" = "enabled." ]; then
		echo "5.18 passed"; else
		echo "* 5.18 System Integrity Protection status" >> "$auditfilelocation"
	fi
fi

# 6.1.1 Display login window as name and password
# Verify organizational score
Audit6_1_1="$(defaults read "$plistlocation" OrgScore6_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_1" = "1" ]; then
	loginwindowFullName=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME)
	# If client fails, then note category in audit file
	if [ "$loginwindowFullName" != "1" ]; then
		echo "* 6.1.1 Display login window as name and password" >> "$auditfilelocation"; else
		echo "6.1.1 passed"
	fi
fi

# 6.1.2 Disable "Show password hints"
# Verify organizational score
Audit6_1_2="$(defaults read "$plistlocation" OrgScore6_1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_2" = "1" ]; then
	passwordHints=$(defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint)
	# If client fails, then note category in audit file
	if [ "$passwordHints" -gt 0 ]; then
		echo "* 6.1.2 Disable Show password hints" >> "$auditfilelocation"; else
		echo "6.1.2 passed"
	fi
fi

# 6.1.3 Disable guest account
# Verify organizational score
Audit6_1_3="$(defaults read "$plistlocation" OrgScore6_1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_3" = "1" ]; then
	guestEnabled=$(defaults read /Library/Preferences/com.apple.loginwindow.plist GuestEnabled)
	# If client fails, then note category in audit file
	if [ "$guestEnabled" = 1 ]; then
		echo "* 6.1.3 Disable guest account" >> "$auditfilelocation"; else
		echo "6.1.3 passed"
	fi
fi

# 6.1.4 Disable "Allow guests to connect to shared folders"
# Verify organizational score
Audit6_1_4="$(defaults read "$plistlocation" OrgScore6_1_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_4" = "1" ]; then
	afpGuestEnabled=$(defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess)
	smbGuestEnabled=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess)
	# If client fails, then note category in audit file
	if [ "$afpGuestEnabled" = "1" ] || [ "$smbGuestEnabled" = "1" ]; then
		echo "* 6.1.4 Disable Allow guests to connect to shared folders" >> "$auditfilelocation"; else
		echo "6.1.4 passed"
	fi
fi

# 6.1.5 Remove Guest home folder
# Verify organizational score
Audit6_1_5="$(defaults read "$plistlocation" OrgScore6_1_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_5" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /Users/Guest ]; then
		echo "* 6.1.5 Remove Guest home folder" >> "$auditfilelocation"; else
		echo "6.1.5 passed"
	fi
fi

# 6.2 Turn on filename extensions
# Verify organizational score
Audit6_2="$(defaults read "$plistlocation" OrgScore6_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_2" = "1" ]; then
	filenameExt=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.finder AppleShowAllExtensions)
	# If client fails, then note category in audit file
	if [ "$filenameExt" = "1" ]; then
		echo "6.2 passed"; else
		echo "* 6.2 Turn on filename extensions" >> "$auditfilelocation"
	fi
fi

# 6.3 Disable the automatic run of safe files in Safari
# Verify organizational score
Audit6_3="$(defaults read "$plistlocation" OrgScore6_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_3" = "1" ]; then
	safariSafe=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads)
	# If client fails, then note category in audit file
	if [ "$safariSafe" = "1" ]; then
		echo "* 6.3 Disable the automatic run of safe files in Safari" >> "$auditfilelocation"; else
		echo "6.3 passed"
	fi
fi

exit 0
