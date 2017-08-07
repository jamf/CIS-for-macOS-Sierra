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
currentUser=$( ls -l /dev/console | cut -d " " -f4 )
hardwareUUID=$(/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | awk -F ": " '{print $2}' | xargs)

logFile="/Library/Application Support/SecurityScoring/remediation.log"
echo $(date -u) "Beginning remediation" > "$logFile"


if [[ ! -e $plistlocation ]]; then
	echo "No scoring file present"
	exit 0
fi

# 1.1 Verify all Apple provided software is current
# Verify organizational score
Audit1_1="$(defaults read "$plistlocation" OrgScore1_1)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_1" = "1" ]; then
echo $(date -u) "Checking 1.1" | tee -a "$logFile"
countAvailableSUS="$(softwareupdate -l | grep "*" | wc -l | tr -d ' ')"
if [ "$countAvailableSUS" = "0" ]; then
	echo $(date -u) "1.1 passed" | tee -a "$logFile"; else
	# NOTE: INSTALLS ALL RECOMMENDED SOFTWARE UPDATES FROM CLIENT'S CONFIGURED SUS SERVER
	softwareupdate -i -r
fi
fi

# 1.2 Enable Auto Update
# Verify organizational score
Audit1_2="$(defaults read "$plistlocation" OrgScore1_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_2" = "1" ]; then
echo $(date -u) "Checking 1.2" | tee -a "$logFile"
automaticUpdates="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled)"
if [ "$automaticUpdates" = "1" ]; then
	echo $(date -u) "1.2 passed" | tee -a "$logFile"; else
	defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -int 1
	echo $(date -u) "1.2 remediated" | tee -a "$logFile"
fi
fi

# 1.3 Enable app update installs
# Verify organizational score
Audit1_3="$(defaults read "$plistlocation" OrgScore1_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_3" = "1" ]; then
echo $(date -u) "Checking 1.3" | tee -a "$logFile"
automaticAppUpdates="$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate)"
if [ "$automaticAppUpdates" = "1" ]; then
	echo $(date -u) "1.3 passed" | tee -a "$logFile"; else
	defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true
	echo $(date -u) "1.3 remediated" | tee -a "$logFile"
fi
fi

# 1.4 Enable system data files and security update installs 
# Verify organizational score
Audit1_4="$(defaults read "$plistlocation" OrgScore1_4)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_4" = "1" ]; then
echo $(date -u) "Checking 1.4" | tee -a "$logFile"
criticalUpdates="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall)"
if [ "$criticalUpdates" = "1" ]; then
	echo $(date -u) "1.4 passed" | tee -a "$logFile"; else
	defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true
	defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
	echo $(date -u) "1.4 remediated" | tee -a "$logFile"
fi
fi

# 1.5 Enable OS X update installs 
# Verify organizational score
Audit1_5="$(defaults read "$plistlocation" OrgScore1_5)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_5" = "1" ]; then
echo $(date -u) "Checking 1.5" | tee -a "$logFile"
updateRestart="$(defaults read /Library/Preferences/com.apple.commerce AutoUpdateRestartRequired)"
if [ "$updateRestart" = "1" ]; then
	echo $(date -u) "1.5 passed" | tee -a "$logFile"; else
	defaults write /Library/Preferences/com.apple.commerce AutoUpdateRestartRequired -bool true
	echo $(date -u) "1.5 remediated" | tee -a "$logFile"
fi
fi

# 2.1.1 Turn off Bluetooth, if no paired devices exist
# Verify organizational score
Audit2_1_1="$(defaults read "$plistlocation" OrgScore2_1_1)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_1_1" = "1" ]; then
echo $(date -u) "Checking 2.1.1" | tee -a "$logFile"
btPowerState="$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState)"
if [ "$btPowerState" = "0" ]; then
	echo $(date -u) "2.1.1 passed" | tee -a "$logFile"; else
	connectable=$( system_profiler SPBluetoothDataType | grep Connectable | awk '{print $2}' | head -1 )
	echo $(date -u) "2.1.1 remediated" | tee -a "$logFile"
if [ "$connectable" = "Yes" ]
	then
echo $(date -u) "2.1.1 passed" | tee -a "$logFile"; else
	defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0
	killall -HUP blued
	echo $(date -u) "2.1.1 remediated" | tee -a "$logFile"
fi
fi
fi

# 2.1.3 Show Bluetooth status in menu bar
# Verify organizational score
Audit2_1_3="$(defaults read "$plistlocation" OrgScore2_1_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_1_3" = "1" ]; then
echo $(date -u) "Checking 2.1.3" | tee -a "$logFile"
btMenuBar="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.systemuiserver menuExtras | grep -c Bluetooth.menu)"
if [ "$btMenuBar" -gt "0" ]; then
	echo $(date -u) "2.1.3 passed" | tee -a "$logFile"; else
		open "/System/Library/CoreServices/Menu Extras/Bluetooth.menu"
		echo $(date -u) "2.1.3 remediated" | tee -a "$logFile"
fi
fi

# 2.2.2 Ensure time set is within appropriate limits
# Not audited - only enforced if identified as priority
# Verify organizational score
Audit2_2_2="$(defaults read "$plistlocation" OrgScore2_2_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_2_2" = "1" ]; then
	echo $(date -u) "Checking 2.2.2" | tee -a "$logFile"
	timeServer=$(systemsetup -getnetworktimeserver | awk '{print $4}')
	ntpdate -sv "$timeServer"
	echo $(date -u) "2.2.2 enforced" | tee -a "$logFile"
fi

# 2.2.3 Restrict NTP server to loopback interface
# Verify organizational score
Audit2_2_3="$(defaults read "$plistlocation" OrgScore2_2_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_2_3" = "1" ]; then
	echo $(date -u) "Checking 2.2.3" | tee -a "$logFile"
	restrictNTP=$(cat /etc/ntp-restrict.conf | grep -c "restrict lo")
	if [ "$restrictNTP" = "0" ]; then
		cp /etc/ntp-restrict.conf /etc/ntp-restrict_old.conf
		echo -n "restrict lo interface ignore wildcard interface listen lo" >> /etc/ntp-restrict.conf
		echo $(date -u) "2.2.3 remediated" | tee -a "$logFile"; else
		echo $(date -u) "2.2.3 passed" | tee -a "$logFile"
	fi
fi

# 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver 
# Verify organizational score
Audit2_3_1="$(defaults read "$plistlocation" OrgScore2_3_1)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_3_1" = "1" ]; then
	echo $(date -u) "Checking 2.3.1" | tee -a "$logFile"
	screenSaverTime="$(defaults read /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.screensaver."$hardwareUUID" idleTime)"
	if [ "$screenSaverTime" -le "1200" ]; then
	echo $(date -u) "2.3.1 passed" | tee -a "$logFile"; else
	defaults write /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.screensaver."$hardwareUUID".plist idleTime -int 1200
	echo $(date -u) "2.3.1 remediated" | tee -a "$logFile"
	fi
fi

# 2.3.2 Secure screen saver corners 
# Verify organizational score
Audit2_3_2="$(defaults read "$plistlocation" OrgScore2_3_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_3_2" = "1" ]; then
	echo $(date -u) "Checking 2.3.2" | tee -a "$logFile"
	bl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)
	tl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)
	tr_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)
	br_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)
		
	if [ "$bl_corner" != "6" ] && [ "$tl_corner" != "6" ] && [ "$tr_corner" != "6" ] && [ "$br_corner" != "6" ]; then
		echo $(date -u) "2.3.2 passed" | tee -a "$logFile"
	fi		
		
	if [ "$bl_corner" = "6" ]; then
	echo "Disabling hot corner"
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner 1
	echo $(date -u) "2.3.2 remediated" | tee -a "$logFile"
	fi

	if [ "$tl_corner" = "6" ]; then
	echo "Disabling hot corner"
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner 1
	echo $(date -u) "2.3.2 remediated" | tee -a "$logFile"
	fi

	if [ "$tr_corner" = "6" ]; then
	echo "Disabling hot corner"
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner 1
	echo $(date -u) "2.3.2 remediated" | tee -a "$logFile"
	fi

	if [ "$br_corner" = "6" ]; then
	echo "Disabling hot corner"
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner 1
	echo $(date -u) "2.3.2 remediated" | tee -a "$logFile"
	fi
fi



# 2.3.4 Set a screen corner to Start Screen Saver 
# Verify organizational score
Audit2_3_4="$(defaults read "$plistlocation" OrgScore2_3_4)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_3_4" = "1" ]; then
echo $(date -u) "Checking 2.3.4" | tee -a "$logFile"
bl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)
tl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)
tr_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)
br_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)
if [ "$bl_corner" = "5" ] || [ "$tl_corner" = "5" ] || [ "$tr_corner" = "5" ] || [ "$br_corner" = "5" ]; then
	echo $(date -u) "2.3.4 passed" | tee -a "$logFile"; else
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner 5
	echo $(date -u) "2.3.4 remediated" | tee -a "$logFile"
fi
fi

# 2.4.1 Disable Remote Apple Events 
# Verify organizational score
Audit2_4_1="$(defaults read "$plistlocation" OrgScore2_4_1)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_1" = "1" ]; then
echo $(date -u) "Checking 2.4.1" | tee -a "$logFile"
remoteAppleEvents=$(systemsetup -getremoteappleevents | awk '{print $4}')
if [ "$remoteAppleEvents" = "Off" ]; then
 	echo $(date -u) "2.4.1 passed" | tee -a "$logFile"; else
	systemsetup -setremoteappleevents off
	echo $(date -u) "2.4.1 remediated" | tee -a "$logFile"
fi
fi


# 2.4.2 Disable Internet Sharing 
# Verify organizational score
Audit2_4_2="$(defaults read "$plistlocation" OrgScore2_4_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_2" = "1" ]; then
echo $(date -u) "Checking 2.4.2" | tee -a "$logFile"
if [ -e /Library/Preferences/SystemConfiguration/com.apple.nat.plist ]; then
	/usr/libexec/PlistBuddy -c "Delete :NAT:AirPort:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Add :NAT:AirPort:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Delete :NAT:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Add :NAT:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Delete :NAT:PrimaryInterface:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Add :NAT:PrimaryInterface:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	echo $(date -u) "2.4.2 enforced" | tee -a "$logFile"; else
		echo $(date -u) "2.4.2 passed" | tee -a "$logFile"
	fi
fi

# 2.4.3 Disable Screen Sharing 
# Verify organizational score
Audit2_4_3="$(defaults read "$plistlocation" OrgScore2_4_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_3" = "1" ]; then
echo $(date -u) "Checking 2.4.3" | tee -a "$logFile"
screenSharing=$(defaults read /System/Library/LaunchDaemons/com.apple.screensharing Disabled)
if [ "$screenSharing" = "1" ]; then
 	echo $(date -u) "2.4.3 passed" | tee -a "$logFile"; else
	defaults write /System/Library/LaunchDaemons/com.apple.screensharing Disabled -bool true
	echo $(date -u) "2.4.3 remediated" | tee -a "$logFile"
fi
fi

# 2.4.5 Disable Remote Login 
# Verify organizational score
Audit2_4_5="$(defaults read "$plistlocation" OrgScore2_4_5)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_5" = "1" ]; then
echo $(date -u) "Checking 2.4.5" | tee -a "$logFile"
remoteLogin=$(systemsetup -getremotelogin | awk '{print $3}')
if [ "$remoteLogin" = "Off" ]; then
 	echo $(date -u) "2.4.5 passed" | tee -a "$logFile"; else
	systemsetup -f -setremotelogin off
	echo $(date -u) "2.4.5 remediated" | tee -a "$logFile"
fi
fi

# 2.4.6 Disable DVD or CD Sharing 
# Verify organizational score
Audit2_4_6="$(defaults read "$plistlocation" OrgScore2_4_6)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_6" = "1" ]; then
	echo $(date -u) "Checking 2.4.6" | tee -a "$logFile"
	discSharing=$(launchctl list | egrep ODSAgent)
	if [ "$discSharing" = "" ]; then
	 	echo $(date -u) "2.4.6 passed" | tee -a "$logFile"; else
		launchctl unload -w /System/Library/LaunchDaemons/com.apple.ODSAgent.plist
		echo $(date -u) "2.4.6 remediated" | tee -a "$logFile"
	fi
fi

# 2.4.7 Disable Bluetooth Sharing
# Verify organizational score
Audit2_4_7="$(defaults read "$plistlocation" OrgScore2_4_7)"
# If organizational score is 1 or true, check status of client and user
# If client fails, then remediate
if [ "$Audit2_4_7" = "1" ]; then
echo $(date -u) "Checking 2.4.7" | tee -a "$logFile"
btSharing=$(/usr/libexec/PlistBuddy -c "print :PrefKeyServicesEnabled"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist)
if [ "$btSharing" = "false" ]; then
 	echo $(date -u) "2.4.7 passed" | tee -a "$logFile"; else
	/usr/libexec/PlistBuddy -c "Delete :PrefKeyServicesEnabled"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist
	/usr/libexec/PlistBuddy -c "Add :PrefKeyServicesEnabled bool false"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist
	echo $(date -u) "2.4.7 remediated" | tee -a "$logFile"
fi
fi

# 2.4.8 Disable File Sharing
# Verify organizational score
Audit2_4_8="$(defaults read "$plistlocation" OrgScore2_4_8)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_8" = "1" ]; then
echo $(date -u) "Checking 2.4.8" | tee -a "$logFile"
afpEnabled=$(launchctl list | egrep AppleFileServer)
smbEnabled=$(launchctl list | egrep smbd)
if [ "$afpEnabled" = "" ] && [ "$smbEnabled" = "" ]; then
 	echo $(date -u) "2.4.8 passed" | tee -a "$logFile"; else
	launchctl unload -w /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist
	launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist
	echo $(date -u) "2.4.8 remediated" | tee -a "$logFile"
fi
fi

# 2.4.9 Disable Remote Management
# Verify organizational score
Audit2_4_9="$(defaults read "$plistlocation" OrgScore2_4_9)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_9" = "1" ]; then
echo $(date -u) "Checking 2.4.9" | tee -a "$logFile"
remoteManagement=$(ps -ef | egrep ARDAgent | grep -c "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent")
if [ "$remoteManagement" = "1" ]; then
 	echo $(date -u) "2.4.9 passed" | tee -a "$logFile"; else
	/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -configure -access -off
	echo $(date -u) "2.4.9 remediated" | tee -a "$logFile"
fi
fi

# 2.5.1 Disable "Wake for network access"
# Verify organizational score
Audit2_5_1="$(defaults read "$plistlocation" OrgScore2_5_1)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_5_1" = "1" ]; then
echo $(date -u) "Checking 2.5.1" | tee -a "$logFile"
wompEnabled=$(pmset -g | grep womp | awk '{print $2}')
if [ "$wompEnabled" = "0" ]; then
 	echo $(date -u) "2.5.1 passed" | tee -a "$logFile"; else
	pmset -a womp 0
	echo $(date -u) "2.5.1 remediated" | tee -a "$logFile"
fi
fi

# 2.5.2 Disable sleeping the computer when connected to power 
# Verify organizational score
Audit2_5_2="$(defaults read "$plistlocation" OrgScore2_5_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_5_2" = "1" ]; then
echo $(date -u) "Checking 2.5.2" | tee -a "$logFile"
disksleepEnabled=$(pmset -g | grep disksleep | awk '{print $2}')
if [ "$disksleepEnabled" = "0" ]; then
 	echo $(date -u) "2.5.2 passed" | tee -a "$logFile"; else
	pmset -c disksleep 0
	pmset -c sleep 0
	echo $(date -u) "2.5.2 remediated" | tee -a "$logFile"
fi
fi

# 2.6.2 Enable Gatekeeper 
# Verify organizational score
Audit2_6_2="$(defaults read "$plistlocation" OrgScore2_6_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_6_2" = "1" ]; then
	echo $(date -u) "Checking 2.6.2" | tee -a "$logFile"
	gatekeeperEnabled=$(spctl --status | grep -c "assessments enabled")
	if [ "$gatekeeperEnabled" = "1" ]; then
		echo $(date -u) "2.6.2 passed" | tee -a "$logFile"; else
		spctl --master-enable
		echo $(date -u) "2.6.2 remediated" | tee -a "$logFile"
	fi
fi

# 2.6.3 Enable Firewall 
# Verify organizational score
Audit2_6_3="$(defaults read "$plistlocation" OrgScore2_6_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_6_3" = "1" ]; then
echo $(date -u) "Checking 2.6.3" | tee -a "$logFile"
firewallEnabled=$(defaults read /Library/Preferences/com.apple.alf globalstate)
if [ "$firewallEnabled" = "0" ]; then
	defaults write /Library/Preferences/com.apple.alf globalstate -int 2
	echo $(date -u) "2.6.3 remediated" | tee -a "$logFile"; else
 	echo $(date -u) "2.6.3 passed" | tee -a "$logFile"
fi
fi

# 2.6.4 Enable Firewall Stealth Mode 
# Verify organizational score
Audit2_6_4="$(defaults read "$plistlocation" OrgScore2_6_4)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_6_4" = "1" ]; then
echo $(date -u) "Checking 2.6.4" | tee -a "$logFile"
stealthEnabled=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | awk '{print $3}')
if [ "$stealthEnabled" = "enabled" ]; then
	echo $(date -u) "2.6.4 passed" | tee -a "$logFile"; else
	/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
	echo $(date -u) "2.6.4 remediated" | tee -a "$logFile"
fi
fi

# 2.6.5 Review Application Firewall Rules
# Verify organizational score
Audit2_6_5="$(defaults read "$plistlocation" OrgScore2_6_5)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_6_5" = "1" ]; then
echo $(date -u) "Checking 2.6.5" | tee -a "$logFile"
appsInbound=$(/usr/libexec/ApplicationFirewall/socketfilterfw --listapps | grep ALF | awk '{print $7}')
if [ "$appsInbound" -le "10" ] || [ -z "$appsInbound" ]; then
	echo $(date -u) "2.6.5 passed" | tee -a "$logFile"; else
	echo $(date -u) "2.6.5 not remediated" | tee -a "$logFile"
fi
fi

# 2.8.1 Time Machine Auto-Backup
# Verify organizational score
Audit2_8_1="$(defaults read "$plistlocation" OrgScore2_8_1)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_8_1" = "1" ]; then
echo $(date -u) "Checking 2.8.1" | tee -a "$logFile"
	timeMachineAuto=$( defaults read /Library/Preferences/com.apple.TimeMachine.plist AutoBackup )
	if [ "$timeMachineAuto" != "1" ]; then
		defaults write /Library/Preferences/com.apple.TimeMachine.plist AutoBackup 1
		echo $(date -u) "2.8.1 remediated" | tee -a "$logFile"; else
		echo $(date -u) "2.8.1 passed" | tee -a "$logFile"
	fi
fi

# 2.9 Pair the remote control infrared receiver if enabled
# Verify organizational score
Audit2_9="$(defaults read "$plistlocation" OrgScore2_9)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_9" = "1" ]; then
echo $(date -u) "Checking 2.9" | tee -a "$logFile"
IRPortDetect=$(system_profiler SPUSBDataType | egrep "IR Receiver" -c)
if [ "$IRPortDetect" = "0" ]; then
	echo $(date -u) "2.9 passed" | tee -a "$logFile"; else
	defaults write /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled -bool false
	echo $(date -u) "2.9 remediated" | tee -a "$logFile"
fi
fi


# 2.10 Enable Secure Keyboard Entry in terminal.app 
# Verify organizational score
Audit2_10="$(defaults read "$plistlocation" OrgScore2_10)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_10" = "1" ]; then
echo $(date -u) "Checking 2.10" | tee -a "$logFile"
secureKeyboard=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.Terminal SecureKeyboardEntry)
if [ "$secureKeyboard" = "1" ]; then
	echo $(date -u) "2.10 passed" | tee -a "$logFile"; else
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.Terminal SecureKeyboardEntry -bool true
	echo $(date -u) "2.10 remediated" | tee -a "$logFile"
fi
fi

# 3.1.1 Retain system.log for 90 or more days 
# Verify organizational score
Audit3_1_1="$(defaults read "$plistlocation" OrgScore3_1_1)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_1_1" = "1" ]; then
	echo $(date -u) "Checking 3.1.1" | tee -a "$logFile"
	sysRetention=$(grep "system.log" /etc/asl.conf | grep "ttl" | awk -F'ttl=' '{print $2}')
	if [ "$sysRetention" -gt "89" ]; then
	echo $(date -u) "3.1.1 passed" | tee -a "$logFile"; else
		if [ "$sysRetention" = "" ]; then
			mv /etc/asl.conf /etc/asl_sys_old.conf
			awk '/system\.log /{$0=$0 " ttl=90"}1' /etc/asl_sys_old.conf >  /etc/asl.conf
			chmod 644 /etc/asl.conf
			chown root:wheel /etc/asl.conf
			echo $(date -u) "3.1.1 remediated" | tee -a "$logFile"; else
		if [ "$sysRetention" -lt "90" ]; then
			mv /etc/asl.conf /etc/asl_sys_old.conf
			sed "s/"ttl=$sysRetention"/"ttl=90"/g" /etc/asl_sys_old.conf >  /etc/asl.conf
			chmod 644 /etc/asl.conf
			chown root:wheel /etc/asl.conf
			echo $(date -u) "3.1.1 remediated" | tee -a "$logFile"
		fi
		fi
	fi
fi



# 3.1.2 Retain appfirewall.log for 90 or more days 
# Verify organizational score
Audit3_1_2="$(defaults read "$plistlocation" OrgScore3_1_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_1_2" = "1" ]; then
	echo $(date -u) "Checking 3.1.2" | tee -a "$logFile"
	alfRetention=$(grep "appfirewall.log" /etc/asl.conf | grep "ttl" | awk -F'ttl=' '{print $2}')
	if [ "$alfRetention" -gt "89" ]; then
	echo $(date -u) "3.1.2 passed" | tee -a "$logFile"; else
		if [ "$alfRetention" = "" ]; then
			mv /etc/asl.conf /etc/asl_alf_old.conf
			awk '/appfirewall\.log /{$0=$0 " ttl=90"}1' /etc/asl_alf_old.conf >  /etc/asl.conf
			chmod 644 /etc/asl.conf
			chown root:wheel /etc/asl.conf
			echo $(date -u) "3.1.2 remediated" | tee -a "$logFile"; else
		if [ "$alfRetention" -lt "90" ]; then
			mv /etc/asl.conf /etc/asl_alf_old.conf
			sed "s/"ttl=$alfRetention"/"ttl=90"/g" /etc/asl_alf_old.conf >  /etc/asl.conf
			chmod 644 /etc/asl.conf
			chown root:wheel /etc/asl.conf
			echo $(date -u) "3.1.2 remediated" | tee -a "$logFile"
		fi
		fi
	fi
fi

# 3.1.3 Retain authd.log for 90 or more days
# Verify organizational score
Audit3_1_3="$(defaults read "$plistlocation" OrgScore3_1_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_1_3" = "1" ]; then
	echo $(date -u) "Checking 3.1.3" | tee -a "$logFile"
	authdRetention=$(grep -i ttl /etc/asl/com.apple.authd | awk -F'ttl=' '{print $2}')
	if [ "$authdRetention" -gt "89" ]; then
	echo $(date -u) "3.1.3 passed" | tee -a "$logFile"; else
		if [ "$authdRetention" = "" ]; then
			mv /etc/asl/com.apple.authd /etc/asl/com.apple.authd.old
			sed "s/"all_max=20M"/"all_max=20M\ ttl=90"/g" /etc/asl/com.apple.authd.old >  /etc/asl/com.apple.authd
			chmod 644 /etc/asl/com.apple.authd
			chown root:wheel /etc/asl/com.apple.authd
			echo $(date -u) "3.1.3 remediated" | tee -a "$logFile"; else
		if [ "$authdRetention" -lt "90"  ]; then
			mv /etc/asl/com.apple.authd /etc/asl/com.apple.authd.old
			sed "s/"ttl=$authdRetention"/"ttl=90"/g" /etc/asl/com.apple.authd.old >  /etc/asl/com.apple.authd
			chmod 644 /etc/asl/com.apple.authd
			chown root:wheel /etc/asl/com.apple.authd
			echo $(date -u) "3.1.3 remediated" | tee -a "$logFile"
		fi
		fi
	fi
fi

# 3.2 Enable security auditing
# Verify organizational score
Audit3_2="$(defaults read "$plistlocation" OrgScore3_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_2" = "1" ]; then
	echo $(date -u) "Checking 3.2" | tee -a "$logFile"
	auditdEnabled=$(launchctl list | grep -c auditd)
	if [ "$auditdEnabled" -gt "0" ]; then
		echo $(date -u) "3.1.3 passed" | tee -a "$logFile"; else
		launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
		echo $(date -u) "3.2 remediated" | tee -a "$logFile"
	fi
fi

# 3.3 Configure Security Auditing Flags
# Verify organizational score
Audit3_3="$(defaults read "$plistlocation" OrgScore3_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_3" = "1" ]; then
	echo $(date -u) "Checking 3.3" | tee -a "$logFile"
	auditFlags=$(egrep "^flags:" /etc/security/audit_control)
	if [[ ${auditFlags} != *"ad"* ]];then
			cp /etc/security/audit_control /etc/security/audit_control_old
			sed "s/"flags:lo,aa"/"flags:lo,ad,fd,fm,-all"/g" /etc/security/audit_control_old > /etc/security/audit_control
			chmod 644 /etc/security/audit_control
			chown root:wheel /etc/security/audit_control
			echo $(date -u) "3.3 remediated" | tee -a "$logFile"; else
		echo $(date -u) "3.3 passed" | tee -a "$logFile"
	fi
fi

# 3.5 Retain install.log for 365 or more days 
# Verify organizational score
Audit3_5="$(defaults read "$plistlocation" OrgScore3_5)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_5" = "1" ]; then
echo $(date -u) "Checking 3.5" | tee -a "$logFile"
installRetention=$(grep -i ttl /etc/asl/com.apple.install | awk -F'ttl=' '{print $2}')
	if [ "$installRetention" -gt "364" ]; then
		echo $(date -u) "3.5 passed" | tee -a "$logFile"
	fi
if [ "$installRetention" = "" ] || [ "$installRetention" -lt "365" ]; then
	if [ "$installRetention" = "" ]; then
		mv /etc/asl/com.apple.install /etc/asl/com.apple.install.old
		sed "s/"format=bsd"/"format=bsd\ ttl=365"/g" /etc/asl/com.apple.install.old >  /etc/asl/com.apple.install
		chmod 644 /etc/asl/com.apple.install
		chown root:wheel /etc/asl/com.apple.install
		echo $(date -u) "3.5 remediated" | tee -a "$logFile"
	fi

installRetention=$(grep -i ttl /etc/asl/com.apple.install | awk -F'ttl=' '{print $2}')
	if [ "$installRetention" -lt "365"  ]; then
		mv /etc/asl/com.apple.install /etc/asl/com.apple.install.old
		sed "s/"ttl=$installRetention"/"ttl=365"/g" /etc/asl/com.apple.install.old >  /etc/asl/com.apple.install
		chmod 644 /etc/asl/com.apple.install
		chown root:wheel /etc/asl/com.apple.install
		echo $(date -u) "3.5 remediated" | tee -a "$logFile"
	fi
fi
fi

# 4.1 Disable Bonjour advertising service 
# Verify organizational score
Audit4_1="$(defaults read "$plistlocation" OrgScore4_1)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit4_1" = "1" ]; then
echo $(date -u) "Checking 4.1" | tee -a "$logFile"
bonjourAdvertise=$(defaults read /Library/Preferences/com.apple.alf globalstate)
if [ "$bonjourAdvertise" = "0" ]; then
	defaults read /Library/Preferences/com.apple.alf globalstate -int 1
	echo $(date -u) "4.1 remediated" | tee -a "$logFile"; else
	echo $(date -u) "4.1 passed" | tee -a "$logFile"
fi
fi

# 4.2 Enable "Show Wi-Fi status in menu bar" 
# Verify organizational score
Audit4_2="$(defaults read "$plistlocation" OrgScore4_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit4_2" = "1" ]; then
echo $(date -u) "Checking 4.2" | tee -a "$logFile"
wifiMenuBar="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.systemuiserver menuExtras | grep -c AirPort.menu)"
if [ "$wifiMenuBar" = "0" ]; then
	open "/System/Library/CoreServices/Menu Extras/AirPort.menu"
	echo $(date -u) "4.2 remediated" | tee -a "$logFile"; else
	echo $(date -u) "4.2 passed" | tee -a "$logFile"
fi
fi

# 4.4 Ensure http server is not running 
# Verify organizational score
Audit4_4="$(defaults read "$plistlocation" OrgScore4_4)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit4_4" = "1" ]; then
	echo $(date -u) "Checking 4.4" | tee -a "$logFile"
	if /bin/launchctl list | egrep httpd > /dev/null; then
		apachectl stop
		defaults write /System/Library/LaunchDaemons/org.apache.httpd Disabled -bool true
		echo $(date -u) "4.4 remediated" | tee -a "$logFile"; else
		echo $(date -u) "4.4 passed" | tee -a "$logFile"
	fi
fi

# 4.5 Ensure ftp server is not running 
# Verify organizational score
Audit4_5="$(defaults read "$plistlocation" OrgScore4_5)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit4_5" = "1" ]; then
echo $(date -u) "Checking 4.5" | tee -a "$logFile"
ftpEnabled=$(launchctl list | egrep ftp | grep -c "com.apple.ftpd")
if [ "$ftpEnabled" -lt "1" ]; then
	echo $(date -u) "4.5 passed" | tee -a "$logFile"; else
	launchctl unload -w /System/Library/LaunchDaemons/ftp.plist
	echo $(date -u) "4.5 remediated" | tee -a "$logFile"
fi
fi

# 4.6 Ensure nfs server is not running
# Verify organizational score
Audit4_6="$(defaults read "$plistlocation" OrgScore4_6)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit4_6" = "1" ]; then
echo $(date -u) "Checking 4.6" | tee -a "$logFile"
if [ -e /etc/exports  ]; then
	nfsd disable
	rm /etc/export
	echo $(date -u) "4.6 remediated" | tee -a "$logFile"; else
	echo $(date -u) "4.6 passed" | tee -a "$logFile"
fi
fi

# 5.1.1 Secure Home Folders
# Verify organizational score
Audit5_1_1="$(defaults read "$plistlocation" OrgScore5_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_1_1" = "1" ]; then
echo $(date -u) "Checking 5.1.1" | tee -a "$logFile"
# If client fails, then remediate
	for userDirs in $( find /Users -mindepth 1 -maxdepth 1 -type d -perm -1 | grep -v "Shared" | grep -v "Guest" ); do
		chmod -R og-rwx "$userDirs"
	done
	echo $(date -u) "5.1.1 enforced" | tee -a "$logFile"
fi

# 5.1.2 Check System Wide Applications for appropriate permissions
# Verify organizational score
Audit5_1_2="$(defaults read "$plistlocation" OrgScore5_1_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_1_2" = "1" ]; then
echo $(date -u) "Checking 5.1.2" | tee -a "$logFile"
for apps in $( find /Applications -iname "*\.app" -type d -perm -2 -ls ); do
            chmod -R o-w "$apps"
        done
        echo $(date -u) "5.1.2 enforced" | tee -a "$logFile"
fi

# 5.1.3 Check System folder for world writable files
# Verify organizational score
Audit5_1_3="$(defaults read "$plistlocation" OrgScore5_1_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_1_3" = "1" ]; then
echo $(date -u) "Checking 5.1.3" | tee -a "$logFile"
for sysPermissions in $( find /System -type d -perm -2 -ls | grep -v "Public/Drop Box" ); do
            chmod -R o-w "$sysPermissions"
        done
        echo $(date -u) "5.1.3 enforced" | tee -a "$logFile"
fi

# 5.1.4 Check Library folder for world writable files
# Verify organizational score
Audit5_1_4="$(defaults read "$plistlocation" OrgScore5_1_4)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_1_4" = "1" ]; then
echo $(date -u) "Checking 5.1.4" | tee -a "$logFile"
# Exempts Adobe files by default!
# for libPermissions in $( find /Library -type d -perm -2 -ls | grep -v Caches ); do
for libPermissions in $( find /Library -type d -perm -2 -ls | grep -v Caches | grep -v Adobe); do
            chmod -R o-w "$libPermissions"
        done
        echo $(date -u) "5.1.4 enforced" | tee -a "$logFile"
fi

# 5.3 Reduce the sudo timeout period
# Verify organizational score
Audit5_3="$(defaults read "$plistlocation" OrgScore5_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_3" = "1" ]; then
echo $(date -u) "Checking 5.3" | tee -a "$logFile"
sudoTimeout=$(cat /etc/sudoers | grep timestamp)
if [ "$sudoTimeout" = "" ]; then
	echo "Defaults timestamp_timeout=0" >> /etc/sudoers
	echo $(date -u) "5.3 remediated" | tee -a "$logFile"; else
	echo $(date -u) "5.3 passed" | tee -a "$logFile"
fi
fi

# 5.4 Automatically lock the login keychain for inactivity
# Verify organizational score
Audit5_4="$(defaults read "$plistlocation" OrgScore5_4)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_4" = "1" ]; then
echo $(date -u) "Checking 5.4" | tee -a "$logFile"
keyTimeout=$(security show-keychain-info /Users/"$currentUser"/Library/Keychains/login.keychain 2>&1 | grep -c "no-timeout")
	if [ "$keyTimeout" -gt 0 ]; then
	security set-keychain-settings -u -t 21600s /Users/"$currentUser"/Library/Keychains/login.keychain
	echo $(date -u) "5.4 remediated" | tee -a "$logFile"; else
	echo $(date -u) "5.4 passed" | tee -a "$logFile"
fi
fi

# 5.5 Ensure login keychain is locked when the computer sleeps
# Verify organizational score
Audit5_5="$(defaults read "$plistlocation" OrgScore5_5)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_5" = "1" ]; then
echo $(date -u) "Checking 5.5" | tee -a "$logFile"
	lockSleep=$(security show-keychain-info /Users/"$currentUser"/Library/Keychains/login.keychain 2>&1 | grep -c "lock-on-sleep")
	if [ "$lockSleep" = 0 ]; then
		security set-keychain-settings -l /Users/"$currentUser"/Library/Keychains/login.keychain
		echo $(date -u) "5.5 remediated" | tee -a "$logFile"; else
		echo $(date -u) "5.5 passed" | tee -a "$logFile"
	fi
fi

# 5.6 Enable OCSP and CRL certificate checking
# Verify organizational score
Audit5_6="$(defaults read "$plistlocation" OrgScore5_6)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_6" = "1" ]; then
	echo $(date -u) "Checking 5.6" | tee -a "$logFile"
	certificateCheckOCSP=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation OCSPStyle)
	certificateCheckCRL=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation CRLStyle)
	# If client fails, then note category in audit file
	if [ "$certificateCheckOCSP" != "RequireIfPresent" ] || [ "$certificateCheckCRL" != "RequireIfPresent" ]; then
		defaults write com.apple.security.revocation OCSPStyle -string RequireIfPresent
		defaults write com.apple.security.revocation CRLStyle -string RequireIfPresent
		defaults write /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation OCSPStyle -string RequireIfPresent
		defaults write /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation CRLStyle -string RequireIfPresent
		echo $(date -u) "5.6 remediated" | tee -a "$logFile"
		else
		echo $(date -u) "5.6 passed" | tee -a "$logFile"
	fi
fi

# 5.7 Do not enable the "root" account
# Verify organizational score
Audit5_7="$(defaults read "$plistlocation" OrgScore5_7)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_7" = "1" ]; then
echo $(date -u) "Checking 5.7" | tee -a "$logFile"
rootEnabled=$(dscl . -read /Users/root AuthenticationAuthority 2>&1 | grep -c "No such key")
if [ "$rootEnabled" = "1" ]; then
	echo $(date -u) "5.7 passed" | tee -a "$logFile"; else
	dscl . -create /Users/root UserShell /usr/bin/false
	echo $(date -u) "5.7 remediated" | tee -a "$logFile"
fi
fi

# 5.8 Disable automatic login
# Verify organizational score
Audit5_8="$(defaults read "$plistlocation" OrgScore5_8)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_8" = "1" ]; then
echo $(date -u) "Checking 5.8" | tee -a "$logFile"
autologinEnabled=$(defaults read /Library/Preferences/com.apple.loginwindow | grep autoLoginUser)
if [ "$autologinEnabled" = "" ]; then
	echo $(date -u) "5.8 passed" | tee -a "$logFile"; else
	defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser
	echo $(date -u) "5.8 remediated" | tee -a "$logFile"
fi
fi

# 5.9 Require a password to wake the computer from sleep or screen saver
# Verify organizational score
Audit5_9="$(defaults read "$plistlocation" OrgScore5_9)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_9" = "1" ]; then
echo $(date -u) "Checking 5.9" | tee -a "$logFile"
screensaverPwd=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.screensaver askForPassword)
if [ "$screensaverPwd" = "1" ]; then
	echo $(date -u) "5.9 passed" | tee -a "$logFile"; else
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.screensaver askForPassword -int 1
	echo $(date -u) "5.9 remediated" | tee -a "$logFile"
fi
fi

# 5.10 Require an administrator password to access system-wide preferences
# Verify organizational score
Audit5_10="$(defaults read "$plistlocation" OrgScore5_10)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_10" = "1" ]; then
echo $(date -u) "Checking 5.10" | tee -a "$logFile"
adminSysPrefs=$(security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep -E '(true|false)' | grep -c "true")
if [ "$adminSysPrefs" = "1" ]; then
	security authorizationdb read system.preferences > /tmp/system.preferences.plist
	/usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist
	security authorizationdb write system.preferences < /tmp/system.preferences.plist
	echo $(date -u) "5.10 remediated" | tee -a "$logFile"; else
	echo $(date -u) "5.10 passed" | tee -a "$logFile"
fi
fi

# 5.11 Disable ability to login to another user's active and locked session
# Verify organizational score
Audit5_11="$(defaults read "$plistlocation" OrgScore5_11)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_11" = "1" ]; then
echo $(date -u) "Checking 5.11" | tee -a "$logFile"
	screensaverGroups=$(grep -c "group=admin,wheel fail_safe" /etc/pam.d/screensaver)
	if [ "$screensaverGroups" = "1" ]; then
			cp /etc/pam.d/screensaver /etc/pam.d/screensaver_old
			sed "s/"group=admin,wheel\ fail_safe"/"group=wheel\ fail_safe"/g" /etc/pam.d/screensaver_old >  /etc/pam.d/screensaver
			chmod 644 /etc/pam.d/screensaver
			chown root:wheel /etc/pam.d/screensaver
			echo $(date -u) "5.11 remediated" | tee -a "$logFile"; else
		echo $(date -u) "5.11 passed" | tee -a "$logFile"
	fi
fi

# 5.18 System Integrity Protection status
# Verify organizational score
Audit5_18="$(defaults read "$plistlocation" OrgScore5_18)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_18" = "1" ]; then
echo $(date -u) "Checking 5.18" | tee -a "$logFile"
sipEnabled=$(/usr/bin/csrutil status | awk '{print $5}')
if [ "$sipEnabled" = "enabled." ]; then
	echo $(date -u) "5.18 passed" | tee -a "$logFile"; else
	/usr/bin/csrutil enable
	echo $(date -u) "5.18 remediated" | tee -a "$logFile"
fi
fi

# 6.1.1 Display login window as name and password
# Verify organizational score
Audit6_1_1="$(defaults read "$plistlocation" OrgScore6_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_1" = "1" ]; then
echo $(date -u) "Checking 6.1.1" | tee -a "$logFile"
	loginwindowFullName=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME)
	# If client fails, then remediate
	if [ "$loginwindowFullName" != "1" ]; then
		defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -int 1
		echo $(date -u) "6.1.1 remediated" | tee -a "$logFile"; else
		echo $(date -u) "6.1.1 passed" | tee -a "$logFile"
	fi
fi

# 6.1.2 Disable "Show password hints"
# Verify organizational score
Audit6_1_2="$(defaults read "$plistlocation" OrgScore6_1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_2" = "1" ]; then
echo $(date -u) "Checking 6.1.2" | tee -a "$logFile"
	passwordHints=$(defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint)
	# If client fails, then remediate
	if [ "$passwordHints" -gt 0 ]; then
		defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0
		echo $(date -u) "6.1.2 remediated" | tee -a "$logFile"; else
		echo $(date -u) "6.1.2 passed" | tee -a "$logFile"
	fi
fi

# 6.1.3 Disable guest account
# Verify organizational score
Audit6_1_3="$(defaults read "$plistlocation" OrgScore6_1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_3" = "1" ]; then
echo $(date -u) "Checking 6.1.3" | tee -a "$logFile"
	guestEnabled=$(defaults read /Library/Preferences/com.apple.loginwindow.plist GuestEnabled)
	# If client fails, then remediate
	if [ "$guestEnabled" = 1 ]; then
		defaults write /Library/Preferences/com.apple.loginwindow.plist GuestEnabled -bool false
		echo $(date -u) "6.1.3 remediated" | tee -a "$logFile"; else
		echo $(date -u) "6.1.3 passed" | tee -a "$logFile"
	fi
fi

# 6.1.4 Disable "Allow guests to connect to shared folders"
# Verify organizational score
Audit6_1_4="$(defaults read "$plistlocation" OrgScore6_1_4)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit6_1_4" = "1" ]; then
echo $(date -u) "Checking 6.1.4" | tee -a "$logFile"
	afpGuestEnabled=$(defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess)
	smbGuestEnabled=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess)
	if [ "$afpGuestEnabled" = "0" ] && [ "$smbGuestEnabled" = "0" ]; then
		echo $(date -u) "6.1.4 passed" | tee -a "$logFile"
	fi
	if [ "$afpGuestEnabled" = "1" ]; then
		defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool no
		echo $(date -u) "6.1.4 remediated" | tee -a "$logFile";
	fi
	if [ "$smbGuestEnabled" = "1" ]; then
		defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool no
		echo $(date -u) "6.1.4 remediated" | tee -a "$logFile";
	fi
fi

# 6.1.5 Remove Guest home folder
# Verify organizational score
Audit6_1_5="$(defaults read "$plistlocation" OrgScore6_1_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_5" = "1" ]; then
echo $(date -u) "Checking 6.1.5" | tee -a "$logFile"
	# If client fails, then remediate
	if [ -e /Users/Guest ]; then
		rm /Users/Guest
		echo $(date -u) "6.1.5 remediated" | tee -a "$logFile"; else
		echo $(date -u) "6.1.5 passed" | tee -a "$logFile"
	fi
fi

# 6.2 Turn on filename extensions
# Verify organizational score
Audit6_2="$(defaults read "$plistlocation" OrgScore6_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit6_2" = "1" ]; then
echo $(date -u) "Checking 6.2" | tee -a "$logFile"
filenameExt=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.finder AppleShowAllExtensions)
if [ "$filenameExt" = "1" ]; then
	echo $(date -u) "6.2 passed" | tee -a "$logFile"; else
	sudo -u "$currentUser" defaults write NSGlobalDomain AppleShowAllExtensions -bool true
	pkill -u "$currentUser" Finder
	echo $(date -u) "6.2 remediated" | tee -a "$logFile"
	# defaults write /Users/"$currentUser"/Library/Preferences/.GlobalPreferences.plist AppleShowAllExtensions -bool true
fi
fi

# 6.3 Disable the automatic run of safe files in Safari
# Verify organizational score
Audit6_3="$(defaults read "$plistlocation" OrgScore6_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit6_3" = "1" ]; then
echo $(date -u) "Checking 6.3" | tee -a "$logFile"
safariSafe=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads)
if [ "$safariSafe" = "1" ]; then
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads -bool false
	echo $(date -u) "6.3 remediated" | tee -a "$logFile"; else
	echo $(date -u) "6.3 passed" | tee -a "$logFile"
fi
fi

echo $(date -u) "Remediation complete" | tee -a "$logFile"
exit 0
