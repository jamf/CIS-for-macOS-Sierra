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

# Change History:
# 2018/01/03  ol    Changed current user method to allow for running when nobody is logged in. 
#                   Moved logging to a function to shorten the script.
#                   Added a preference for each scored item to say if it should be remediated. 
#                   Misc. formatting
#                   Added killall cfprefsd to end to reset prefs cache. 

# USAGE
# Reads from plist at /Library/Application Support/SecurityScoring/org_security_score.plist.
# For remediate="true" items, runs query for current computer/user compliance and attempts
#  to update settings as needed.

plistlocation="/Library/Application Support/SecurityScoring/org_security_score.plist"


jamfReportedUser=$3
loggedInUser=$(/usr/bin/python -c 'from SystemConfiguration import SCDynamicStoreCopyConsoleUser; import sys; username = (SCDynamicStoreCopyConsoleUser(None, None, None) or [None])[0]; username = [username,""][username in [u"loginwindow", None, u""]]; sys.stdout.write(username + "\n");')
# We're trying the python way above because the below common ways don't work as well when multiple consoles are in use with fast user switching. 
# loggedInUser=$(stat -f "%Su" /dev/console)
# loggedInUser=$( ls -l /dev/console | cut -d " " -f4 )
mostFrequentUser=$( last | cut -f 1 -d ' ' | sort | grep -vE "reboot|shutdown|root|_.*|wtmp|^$|jamfadmin" | uniq -c | sort -nr | cut -f 3 -d ' ' )

# Some preferences are user-level, not system level. Which user should we run this for? 
if [[ $(ps aux | grep "[S]elf Service" | wc -l) -gt 0 ]]; then
    # Self Service is running
    currentUser="$jamfReportedUser"
elif [[ ! -z "$loggedInUser" ]]; then
    currentUser="$loggedInUser"
else
    # If nobody is logged in...
    currentUser="$mostFrequentUser"
fi


# If you wanted to run this for the currently logged-in user, you could use this. 
# This would be a good way if you have this script in self-service, for example...
# This is more complicated but figures out the username based on who's been logging in the most. 
# It works even if nobody is currently logged in...


hardwareUUID=$(/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | awk -F ": " '{print $2}' | xargs)

logFile="/Library/Application Support/SecurityScoring/remediation.log"


##############################################################
## functions
##############################################################

writelog () {
    writelog "$1"
}

remediateRequested () {
    # The initial run of the "Set Organization Priorities" script created a plist with 
    # key-value pairs that indicate which items should be scored, and, of those, which 
    # should be remediated. 
    
    # E.g.:
    #  OrgScore6_1_5="true"         <= The item will be scored/reported
    #  OrgRemediate6_1_5="true"     <= The item will be remediated
    
    # To help prevent mistakes, we will not remediate un-scored items
    
    # If organizational score is 1 or true, check status of client
    # If client fails, then remediate
    
    cisNumber="$1"
    local isScored = "$(defaults read ${plistlocation} \"$cisNumber\")"
    local isRemediated = "$(defaults read ${plistlocation} \"$cisNumber\")"

    if [["$isScored" = "1" && "$isRemediated" = "1" ]]; then
        writelog "Checking $cisNumber"
        return 0
    else
        return 1    
    fi
}


##############################################################
## code
##############################################################

writelog "Beginning remediation"

if [[ ! -e $plistlocation ]]; then
	echo "Error: No scoring file present"
	exit -1
fi


# 1.1 Verify all Apple provided software is current
if [[ remediateRequested "1_1" ]]; then
    countAvailableSUS="$(softwareupdate -l | grep "*" | wc -l | tr -d ' ')"
    if [ "$countAvailableSUS" = "0" ]; then
        writelog "1.1 passed";
    else
        # NOTE: INSTALLS ALL RECOMMENDED SOFTWARE UPDATES FROM CLIENT'S CONFIGURED SUS SERVER
        softwareupdate -i -r
    fi
fi

# 1.2 Enable Auto Update
if [[ remediateRequested "1_2" ]]; then
    automaticUpdates="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled)"
    if [ "$automaticUpdates" = "1" ]; then
        writelog "1.2 passed";
    else
        defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -int 1
        writelog "1.2 remediated"
    fi
fi

# 1.3 Enable app update installs
if [[ remediateRequested "1_3" ]]; then
	automaticAppUpdates="$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate)"
    if [ "$automaticAppUpdates" = "1" ]; then
        writelog "1.3 passed";
    else
        defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true
        writelog "1.3 remediated"
    fi
fi

# 1.4 Enable system data files and security update installs 
if [[ remediateRequested "1_4" ]]; then
	criticalUpdates="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall)"
    if [ "$criticalUpdates" = "1" ]; then
        writelog "1.4 passed";
    else
        defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
        writelog "1.4 remediated"
    fi
fi

# 1.5 Enable OS X update installs 
if [[ remediateRequested "1_5" ]]; then
	updateRestart="$(defaults read /Library/Preferences/com.apple.commerce AutoUpdateRestartRequired)"
    if [ "$updateRestart" = "1" ]; then
        writelog "1.5 passed";
    else
        defaults write /Library/Preferences/com.apple.commerce AutoUpdateRestartRequired -bool true
        writelog "1.5 remediated"
    fi
fi

# 2.1.1 Turn off Bluetooth if no paired devices exist
###
if [[ remediateRequested "2_1_1" ]]; then
	btPowerState="$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState)"
    connectable=$( system_profiler SPBluetoothDataType | grep Connectable | awk '{print $2}' | head -1 )
    if [[ "$btPowerState" = "0" || "$connectable" = "Yes" ]]; then
        writelog "2.1.1 passed"; 
    else
        defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0
        killall -HUP blued
        writelog "2.1.1 remediated"
    fi
fi

# 2.1.3 Show Bluetooth status in menu bar
if [[ remediateRequested "2_1_3" ]]; then
	btMenuBar="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.systemuiserver menuExtras | grep -c Bluetooth.menu)"
    if [ "$btMenuBar" -gt "0" ]; then
        writelog "2.1.3 passed";
	else
        open "/System/Library/CoreServices/Menu Extras/Bluetooth.menu"
        writelog "2.1.3 remediated"
    fi
fi

# 2.2.2 Ensure time set is within appropriate limits
# Not audited - only enforced if identified as priority
if [[ remediateRequested "2_2_2" ]]; then
	timeServer=$(systemsetup -getnetworktimeserver | awk '{print $4}')
	ntpdate -sv "$timeServer"
	writelog "2.2.2 enforced"
fi

# 2.2.3 Restrict NTP server to loopback interface
if [[ remediateRequested "2_2_3" ]]; then
	restrictNTP=$(cat /etc/ntp-restrict.conf | grep -c "restrict lo")
	if [ "$restrictNTP" = "0" ]; then
		cp /etc/ntp-restrict.conf /etc/ntp-restrict_old.conf
		echo -n "restrict lo interface ignore wildcard interface listen lo" >> /etc/ntp-restrict.conf
		writelog "2.2.3 remediated";
	else
		writelog "2.2.3 passed"
	fi
fi

# 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver 
if [[ remediateRequested "2_3_1" ]]; then
	screenSaverTime="$(defaults read /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.screensaver."$hardwareUUID" idleTime)"
	if [ "$screenSaverTime" -le "1200" ]; then
        writelog "2.3.1 passed";
	else
        defaults write /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.screensaver."$hardwareUUID".plist idleTime -int 1200
        writelog "2.3.1 remediated"
	fi
fi

# 2.3.2 Secure screen saver corners 
if [[ remediateRequested "2_3_2" ]]; then
	bl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)
	tl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)
	tr_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)
	br_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)
		
	if [ "$bl_corner" != "6" ] && [ "$tl_corner" != "6" ] && [ "$tr_corner" != "6" ] && [ "$br_corner" != "6" ]; then
		writelog "2.3.2 passed"
	fi		
		
	if [ "$bl_corner" = "6" ]; then
        echo "Disabling hot corner"
        defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner 1
        writelog "2.3.2 remediated"
	fi

	if [ "$tl_corner" = "6" ]; then
        echo "Disabling hot corner"
        defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner 1
        writelog "2.3.2 remediated"
	fi

	if [ "$tr_corner" = "6" ]; then
        echo "Disabling hot corner"
        defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner 1
        writelog "2.3.2 remediated"
	fi

	if [ "$br_corner" = "6" ]; then
        echo "Disabling hot corner"
        defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner 1
        writelog "2.3.2 remediated"
	fi
fi



# 2.3.4 Set a screen corner to Start Screen Saver 
if [[ remediateRequested "2_3_4" ]]; then
	bl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)
    tl_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)
    tr_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)
    br_corner=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)
    if [ "$bl_corner" = "5" ] || [ "$tl_corner" = "5" ] || [ "$tr_corner" = "5" ] || [ "$br_corner" = "5" ]; then
        writelog "2.3.4 passed";
    else
        defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner 5
        writelog "2.3.4 remediated"
    fi
fi

# 2.4.1 Disable Remote Apple Events 
if [[ remediateRequested "2_4_1" ]]; then
	remoteAppleEvents=$(systemsetup -getremoteappleevents | awk '{print $4}')
    if [ "$remoteAppleEvents" = "Off" ]; then
        writelog "2.4.1 passed";
        else
        systemsetup -setremoteappleevents off
        writelog "2.4.1 remediated"
    fi
fi


# 2.4.2 Disable Internet Sharing 
if [[ remediateRequested "2_4_2" ]]; then
	if [ -e /Library/Preferences/SystemConfiguration/com.apple.nat.plist ]; then
        /usr/libexec/PlistBuddy -c "Delete :NAT:AirPort:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
        /usr/libexec/PlistBuddy -c "Add :NAT:AirPort:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
        /usr/libexec/PlistBuddy -c "Delete :NAT:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
        /usr/libexec/PlistBuddy -c "Add :NAT:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
        /usr/libexec/PlistBuddy -c "Delete :NAT:PrimaryInterface:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
        /usr/libexec/PlistBuddy -c "Add :NAT:PrimaryInterface:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
        writelog "2.4.2 enforced";
	else
		writelog "2.4.2 passed"
	fi
fi

# 2.4.3 Disable Screen Sharing 
if [[ remediateRequested "2_4_3" ]]; then
	screenSharing=$(defaults read /System/Library/LaunchDaemons/com.apple.screensharing Disabled)
    if [ "$screenSharing" = "1" ]; then
        writelog "2.4.3 passed";
        else
        defaults write /System/Library/LaunchDaemons/com.apple.screensharing Disabled -bool true
        writelog "2.4.3 remediated"
    fi
fi

# 2.4.5 Disable Remote Login 
if [[ remediateRequested "2_4_5" ]]; then
	remoteLogin=$(systemsetup -getremotelogin | awk '{print $3}')
    if [ "$remoteLogin" = "Off" ]; then
        writelog "2.4.5 passed";
        else
        systemsetup -f -setremotelogin off
        writelog "2.4.5 remediated"
    fi
fi

# 2.4.6 Disable DVD or CD Sharing 
if [[ remediateRequested "2_4_6" ]]; then
	discSharing=$(launchctl list | egrep ODSAgent)
	if [ "$discSharing" = "" ]; then
	 	writelog "2.4.6 passed";
	else
		launchctl unload -w /System/Library/LaunchDaemons/com.apple.ODSAgent.plist
		writelog "2.4.6 remediated"
	fi
fi

# 2.4.7 Disable Bluetooth Sharing
# If organizational score is 1 or true, check status of client and user
if [[ remediateRequested "2_4_7" ]]; then
	btSharing=$(/usr/libexec/PlistBuddy -c "print :PrefKeyServicesEnabled"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist)
    if [ "$btSharing" = "false" ]; then
        writelog "2.4.7 passed";
        else
        /usr/libexec/PlistBuddy -c "Delete :PrefKeyServicesEnabled"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist
        /usr/libexec/PlistBuddy -c "Add :PrefKeyServicesEnabled bool false"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist
        writelog "2.4.7 remediated"
    fi
fi

# 2.4.8 Disable File Sharing
if [[ remediateRequested "2_4_8" ]]; then
	afpEnabled=$(launchctl list | egrep AppleFileServer)
    smbEnabled=$(launchctl list | egrep smbd)
    if [ "$afpEnabled" = "" ] && [ "$smbEnabled" = "" ]; then
        writelog "2.4.8 passed";
        else
        launchctl unload -w /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist
        launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist
        writelog "2.4.8 remediated"
    fi
fi

# 2.4.9 Disable Remote Management
if [[ remediateRequested "2_4_9" ]]; then
	remoteManagement=$(ps -ef | egrep ARDAgent | grep -c "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent")
    if [ "$remoteManagement" = "1" ]; then
        writelog "2.4.9 passed";
        else
        /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -configure -access -off
        writelog "2.4.9 remediated"
    fi
fi

# 2.5.1 Disable "Wake for network access"
if [[ remediateRequested "2_5_1" ]]; then
	wompEnabled=$(pmset -g | grep womp | awk '{print $2}')
    if [ "$wompEnabled" = "0" ]; then
        writelog "2.5.1 passed";
        else
        pmset -a womp 0
        writelog "2.5.1 remediated"
    fi
fi

# 2.5.2 Disable sleeping the computer when connected to power 
if [[ remediateRequested "2_5_2" ]]; then
	disksleepEnabled=$(pmset -g | grep disksleep | awk '{print $2}')
    if [ "$disksleepEnabled" = "0" ]; then
        writelog "2.5.2 passed";
        else
        pmset -c disksleep 0
        pmset -c sleep 0
        writelog "2.5.2 remediated"
    fi
fi

# 2.6.2 Enable Gatekeeper 
if [[ remediateRequested "2_6_2" ]]; then
		gatekeeperEnabled=$(spctl --status | grep -c "assessments enabled")
	if [ "$gatekeeperEnabled" = "1" ]; then
		writelog "2.6.2 passed";
	else
		spctl --master-enable
		writelog "2.6.2 remediated"
	fi
fi

# 2.6.3 Enable Firewall 
if [[ remediateRequested "2_6_3" ]]; then
	firewallEnabled=$(defaults read /Library/Preferences/com.apple.alf globalstate)
    if [ "$firewallEnabled" = "0" ]; then
        defaults write /Library/Preferences/com.apple.alf globalstate -int 2
        writelog "2.6.3 remediated";
        else
        writelog "2.6.3 passed"
    fi
fi

# 2.6.4 Enable Firewall Stealth Mode 
if [[ remediateRequested "2_6_4" ]]; then
	stealthEnabled=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | awk '{print $3}')
    if [ "$stealthEnabled" = "enabled" ]; then
        writelog "2.6.4 passed";
        else
        /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
        writelog "2.6.4 remediated"
    fi
fi

# 2.6.5 Review Application Firewall Rules
if [[ remediateRequested "2_6_5" ]]; then
	appsInbound=$(/usr/libexec/ApplicationFirewall/socketfilterfw --listapps | grep ALF | awk '{print $7}')
    if [ "$appsInbound" -le "10" ] || [ -z "$appsInbound" ]; then
        writelog "2.6.5 passed";
        else
        writelog "2.6.5 not remediated"
    fi
fi

# 2.8.1 Time Machine Auto-Backup
if [[ remediateRequested "2_8_1" ]]; then
	timeMachineAuto=$( defaults read /Library/Preferences/com.apple.TimeMachine.plist AutoBackup )
	if [ "$timeMachineAuto" != "1" ]; then
		defaults write /Library/Preferences/com.apple.TimeMachine.plist AutoBackup 1
		writelog "2.8.1 remediated";
	else
		writelog "2.8.1 passed"
	fi
fi

# 2.9 Pair the remote control infrared receiver if enabled
if [[ remediateRequested "2_9" ]]; then
	IRPortDetect=$(system_profiler SPUSBDataType | egrep "IR Receiver" -c)
    if [ "$IRPortDetect" = "0" ]; then
        writelog "2.9 passed";
        else
        defaults write /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled -bool false
        writelog "2.9 remediated"
    fi
fi


# 2.10 Enable Secure Keyboard Entry in terminal.app 
if [[ remediateRequested "2_10" ]]; then
	secureKeyboard=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.Terminal SecureKeyboardEntry)
    if [ "$secureKeyboard" = "1" ]; then
        writelog "2.10 passed";
        else
        defaults write /Users/"$currentUser"/Library/Preferences/com.apple.Terminal SecureKeyboardEntry -bool true
        writelog "2.10 remediated"
    fi
fi

# 3.1.1 Retain system.log for 90 or more days 
if [[ remediateRequested "3_1_1" ]]; then
	sysRetention=$(grep "system.log" /etc/asl.conf | grep "ttl" | awk -F'ttl=' '{print $2}')
	if [ "$sysRetention" -gt "89" ]; then
    	writelog "3.1.1 passed";
	elif [ "$sysRetention" = "" ]; then
			mv /etc/asl.conf /etc/asl_sys_old.conf
			awk '/system\.log /{$0=$0 " ttl=90"}1' /etc/asl_sys_old.conf >  /etc/asl.conf
			chmod 644 /etc/asl.conf
			chown root:wheel /etc/asl.conf
			writelog "3.1.1 remediated";
	elif [ "$sysRetention" -lt "90" ]; then
			mv /etc/asl.conf /etc/asl_sys_old.conf
			sed "s/"ttl=$sysRetention"/"ttl=90"/g" /etc/asl_sys_old.conf >  /etc/asl.conf
			chmod 644 /etc/asl.conf
			chown root:wheel /etc/asl.conf
			writelog "3.1.1 remediated"
	fi
fi



# 3.1.2 Retain appfirewall.log for at least 90 days 
if [[ remediateRequested "3_1_2" ]]; then
	alfRetention=$(grep "appfirewall.log" /etc/asl.conf | grep "ttl" | awk -F'ttl=' '{print $2}')
	if [ "$alfRetention" -gt "89" ]; then
    	writelog "3.1.2 passed"; 
    else
		mv /etc/asl.conf /etc/asl_alf_old.conf
		if [ "$alfRetention" = "" ]; then
			awk '/appfirewall\.log /{$0=$0 " ttl=90"}1' /etc/asl_alf_old.conf >  /etc/asl.conf
        elif [ "$alfRetention" -lt "90" ]; then
            sed "s/"ttl=$alfRetention"/"ttl=90"/g" /etc/asl_alf_old.conf >  /etc/asl.conf
		fi
        chmod 644 /etc/asl.conf
        chown root:wheel /etc/asl.conf
        writelog "3.1.2 remediated"
	fi
fi

# 3.1.3 Retain authd.log for 90 or more days
if [[ remediateRequested "3_1_3" ]]; then
	authdRetention=$(grep -i ttl /etc/asl/com.apple.authd | awk -F'ttl=' '{print $2}')
	if   [ "$authdRetention" -gt "89" ]; then
	writelog "3.1.3 passed";
	elif [ "$authdRetention" = "" ]; then
        mv /etc/asl/com.apple.authd /etc/asl/com.apple.authd.old
        sed "s/"all_max=20M"/"all_max=20M\ ttl=90"/g" /etc/asl/com.apple.authd.old >  /etc/asl/com.apple.authd
        chmod 644 /etc/asl/com.apple.authd
        chown root:wheel /etc/asl/com.apple.authd
        writelog "3.1.3 remediated"; 
	elif [ "$authdRetention" -lt "90"  ]; then
        mv /etc/asl/com.apple.authd /etc/asl/com.apple.authd.old
        sed "s/"ttl=$authdRetention"/"ttl=90"/g" /etc/asl/com.apple.authd.old >  /etc/asl/com.apple.authd
        chmod 644 /etc/asl/com.apple.authd
        chown root:wheel /etc/asl/com.apple.authd
        writelog "3.1.3 remediated"
    fi
fi

# 3.2 Enable security auditing
if [[ remediateRequested "3_2" ]]; then
	auditdEnabled=$(launchctl list | grep -c auditd)
	if [ "$auditdEnabled" -gt "0" ]; then
		writelog "3.1.3 passed";
	else
		launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
		writelog "3.2 remediated"
	fi
fi

# 3.3 Configure Security Auditing Flags
if [[ remediateRequested "3_3" ]]; then
	auditFlags=$(egrep "^flags:" /etc/security/audit_control)
	if [[ ${auditFlags} != *"ad"* ]];then
        cp /etc/security/audit_control /etc/security/audit_control_old
        sed "s/"flags:lo,aa"/"flags:lo,ad,fd,fm,-all"/g" /etc/security/audit_control_old > /etc/security/audit_control
        chmod 644 /etc/security/audit_control
        chown root:wheel /etc/security/audit_control
        writelog "3.3 remediated";
	else
		writelog "3.3 passed"
	fi
fi

# 3.5 Retain install.log for at least 365 days 
if [[ remediateRequested "3_5" ]]; then
	installRetention=$(grep -i ttl /etc/asl/com.apple.install | awk -F'ttl=' '{print $2}')
	if [ "$installRetention" -gt "364" ]; then
		writelog "3.5 passed"
	fi
    if [ "$installRetention" = "" ] || [ "$installRetention" -lt "365" ]; then
    	if [ "$installRetention" = "" ]; then
            mv /etc/asl/com.apple.install /etc/asl/com.apple.install.old
            sed "s/"format=bsd"/"format=bsd\ ttl=365"/g" /etc/asl/com.apple.install.old >  /etc/asl/com.apple.install
            chmod 644 /etc/asl/com.apple.install
            chown root:wheel /etc/asl/com.apple.install
            writelog "3.5 remediated"
        fi
        # if it still doesn't pass, try this...
        installRetention=$(grep -i ttl /etc/asl/com.apple.install | awk -F'ttl=' '{print $2}')
        if [ "$installRetention" -lt "365"  ]; then
            mv /etc/asl/com.apple.install /etc/asl/com.apple.install.old
            sed "s/"ttl=$installRetention"/"ttl=365"/g" /etc/asl/com.apple.install.old >  /etc/asl/com.apple.install
            chmod 644 /etc/asl/com.apple.install
            chown root:wheel /etc/asl/com.apple.install
            writelog "3.5 remediated"
        fi
    fi
fi

# 4.1 Disable Bonjour advertising service 
if [[ remediateRequested "4_1" ]]; then
	bonjourAdvertise=$(defaults read /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements)
    if [ "$bonjourAdvertise" != "1" ]; then
	    defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -int 1
	    writelog "4.1 remediated";
	else
	    writelog "4.1 passed"
    fi
fi

# 4.2 Enable "Show Wi-Fi status in menu bar" 
if [[ remediateRequested "4_2" ]]; then
	wifiMenuBar="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.systemuiserver menuExtras | grep -c AirPort.menu)"
    if [ "$wifiMenuBar" = "0" ]; then
        open "/System/Library/CoreServices/Menu Extras/AirPort.menu"
        writelog "4.2 remediated";
	else
        writelog "4.2 passed"
    fi
fi

# 4.4 Ensure http server is not running 
if [[ remediateRequested "4_4" ]]; then
		if /bin/launchctl list | egrep httpd > /dev/null; then
		apachectl stop
		defaults write /System/Library/LaunchDaemons/org.apache.httpd Disabled -bool true
		writelog "4.4 remediated";
	else
		writelog "4.4 passed"
	fi
fi

# 4.5 Ensure ftp server is not running 
if [[ remediateRequested "4_5" ]]; then
	ftpEnabled=$(launchctl list | egrep ftp | grep -c "com.apple.ftpd")
    if [ "$ftpEnabled" -lt "1" ]; then
        writelog "4.5 passed";
	else
        launchctl unload -w /System/Library/LaunchDaemons/ftp.plist
        writelog "4.5 remediated"
    fi
fi

# 4.6 Ensure nfs server is not running
if [[ remediateRequested "4_6" ]]; then
	if [ -e /etc/exports  ]; then
        nfsd disable
        rm /etc/export
        writelog "4.6 remediated";
	else
        writelog "4.6 passed"
    fi
fi

# 5.1.1 Secure Home Folders
if [[ remediateRequested "5_1_1" ]]; then
		for userDirs in $( find /Users -mindepth 1 -maxdepth 1 -type d -perm -1 | grep -v "Shared" | grep -v "Guest" ); do
		chmod -R og-rwx "$userDirs"
	done
	writelog "5.1.1 enforced"
fi

# 5.1.2 Check System Wide Applications for appropriate permissions
if [[ remediateRequested "5_1_2" ]]; then
	for apps in $( find /Applications -iname "*\.app" -type d -perm -2 -ls ); do
        chmod -R o-w "$apps"
    done
    writelog "5.1.2 enforced"
fi

# 5.1.3 Check System folder for world writable files
if [[ remediateRequested "5_1_3" ]]; then
	for sysPermissions in $( find /System -type d -perm -2 -ls | grep -v "Public/Drop Box" ); do
        chmod -R o-w "$sysPermissions"
    done
    writelog "5.1.3 enforced"
fi

# 5.1.4 Check Library folder for world writable files
if [[ remediateRequested "5_1_4" ]]; then
	# Exempts Adobe files by default!
    # for libPermissions in $( find /Library -type d -perm -2 -ls | grep -v Caches ); do
    for libPermissions in $( find /Library -type d -perm -2 -ls | grep -v Caches | grep -v Adobe); do
        chmod -R o-w "$libPermissions"
    done
    writelog "5.1.4 enforced"
fi

# 5.3 Reduce the sudo timeout period
if [[ remediateRequested "5_3" ]]; then
	sudoTimeout=$(cat /etc/sudoers | grep timestamp)
    if [ "$sudoTimeout" = "" ]; then
        echo "Defaults timestamp_timeout=0" >> /etc/sudoers
        writelog "5.3 remediated";
	else
        writelog "5.3 passed"
    fi
fi

# 5.4 Automatically lock the login keychain for inactivity
if [[ remediateRequested "5_4" ]]; then
	keyTimeout=$(security show-keychain-info /Users/"$currentUser"/Library/Keychains/login.keychain 2>&1 | grep -c "no-timeout")
	if [ "$keyTimeout" -gt 0 ]; then
    	security set-keychain-settings -u -t 21600s /Users/"$currentUser"/Library/Keychains/login.keychain
    	writelog "5.4 remediated";
	else
    	writelog "5.4 passed"
    fi
fi

# 5.5 Ensure login keychain is locked when the computer sleeps
if [[ remediateRequested "5_5" ]]; then
		lockSleep=$(security show-keychain-info /Users/"$currentUser"/Library/Keychains/login.keychain 2>&1 | grep -c "lock-on-sleep")
	if [ "$lockSleep" = 0 ]; then
		security set-keychain-settings -l /Users/"$currentUser"/Library/Keychains/login.keychain
		writelog "5.5 remediated";
	else
		writelog "5.5 passed"
	fi
fi

# 5.6 Enable OCSP and CRL certificate checking
if [[ remediateRequested "5_6" ]]; then
		certificateCheckOCSP=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation OCSPStyle)
	certificateCheckCRL=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation CRLStyle)
	# If client fails, then note category in audit file
	if [ "$certificateCheckOCSP" != "RequireIfPresent" ] || [ "$certificateCheckCRL" != "RequireIfPresent" ]; then
		defaults write com.apple.security.revocation OCSPStyle -string RequireIfPresent
		defaults write com.apple.security.revocation CRLStyle -string RequireIfPresent
		defaults write /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation OCSPStyle -string RequireIfPresent
		defaults write /Users/"$currentUser"/Library/Preferences/com.apple.security.revocation CRLStyle -string RequireIfPresent
		writelog "5.6 remediated"
	else
		writelog "5.6 passed"
	fi
fi

# 5.7 Do not enable the "root" account
if [[ remediateRequested "5_7" ]]; then
	rootEnabled=$(dscl . -read /Users/root AuthenticationAuthority 2>&1 | grep -c "No such key")
    if [ "$rootEnabled" = "1" ]; then
        writelog "5.7 passed";
	else
        dscl . -create /Users/root UserShell /usr/bin/false
        writelog "5.7 remediated"
    fi
fi

# 5.8 Disable automatic login
if [[ remediateRequested "5_8" ]]; then
	autologinEnabled=$(defaults read /Library/Preferences/com.apple.loginwindow | grep autoLoginUser)
    if [ "$autologinEnabled" = "" ]; then
        writelog "5.8 passed";
	else
        defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser
        writelog "5.8 remediated"
    fi
fi

# 5.9 Require a password to wake the computer from sleep or screen saver
if [[ remediateRequested "5_9" ]]; then
	screensaverPwd=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.screensaver askForPassword)
    if [ "$screensaverPwd" = "1" ]; then
        writelog "5.9 passed";
	else
        defaults write /Users/"$currentUser"/Library/Preferences/com.apple.screensaver askForPassword -int 1
        writelog "5.9 remediated"
    fi
fi

# 5.10 Require an administrator password to access system-wide preferences
if [[ remediateRequested "5_10" ]]; then
	adminSysPrefs=$(security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep -E '(true|false)' | grep -c "true")
    if [ "$adminSysPrefs" = "1" ]; then
        security authorizationdb read system.preferences > /tmp/system.preferences.plist
        /usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist
        security authorizationdb write system.preferences < /tmp/system.preferences.plist
        writelog "5.10 remediated";
	else
        writelog "5.10 passed"
    fi
fi

# 5.11 Disable ability to login to another user's active and locked session
if [[ remediateRequested "5_11" ]]; then
		screensaverGroups=$(grep -c "group=admin,wheel fail_safe" /etc/pam.d/screensaver)
	if [ "$screensaverGroups" = "1" ]; then
        cp /etc/pam.d/screensaver /etc/pam.d/screensaver_old
        sed "s/"group=admin,wheel\ fail_safe"/"group=wheel\ fail_safe"/g" /etc/pam.d/screensaver_old >  /etc/pam.d/screensaver
        chmod 644 /etc/pam.d/screensaver
        chown root:wheel /etc/pam.d/screensaver
        writelog "5.11 remediated";
    else
		writelog "5.11 passed"
	fi
fi

# 5.18 System Integrity Protection status
if [[ remediateRequested "5_18" ]]; then
	sipEnabled=$(/usr/bin/csrutil status | awk '{print $5}')
    if [ "$sipEnabled" = "enabled." ]; then
        writelog "5.18 passed";
    else
        /usr/bin/csrutil enable
        writelog "5.18 remediated"
    fi
fi

# 6.1.1 Display login window as name and password
if [[ remediateRequested "6_1_1" ]]; then
	loginwindowFullName=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME)
		if [ "$loginwindowFullName" != "1" ]; then
		defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -int 1
		writelog "6.1.1 remediated";
    else
		writelog "6.1.1 passed"
	fi
fi

# 6.1.2 Disable "Show password hints"
if [[ remediateRequested "6_1_2" ]]; then
	passwordHints=$(defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint)
		if [ "$passwordHints" -gt 0 ]; then
		defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0
		writelog "6.1.2 remediated";
    else
		writelog "6.1.2 passed"
	fi
fi

# 6.1.3 Disable guest account
if [[ remediateRequested "6_1_3" ]]; then
	guestEnabled=$(defaults read /Library/Preferences/com.apple.loginwindow.plist GuestEnabled)
		if [ "$guestEnabled" = 1 ]; then
		defaults write /Library/Preferences/com.apple.loginwindow.plist GuestEnabled -bool false
		writelog "6.1.3 remediated";
    else
		writelog "6.1.3 passed"
	fi
fi

# 6.1.4 Disable "Allow guests to connect to shared folders"
if [[ remediateRequested "6_1_4" ]]; then
	afpGuestEnabled=$(defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess)
	smbGuestEnabled=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess)
	if [ "$afpGuestEnabled" = "0" ] && [ "$smbGuestEnabled" = "0" ]; then
		writelog "6.1.4 passed"
	fi
	if [ "$afpGuestEnabled" = "1" ]; then
		defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool no
		writelog "6.1.4 remediated";
	fi
	if [ "$smbGuestEnabled" = "1" ]; then
		defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool no
		writelog "6.1.4 remediated";
	fi
fi

# 6.1.5 Remove Guest home folder
if [[ remediateRequested "6_1_5" ]]; then
    if [ -e /Users/Guest ]; then
		rm /Users/Guest
		writelog "6.1.5 remediated";
    else
		writelog "6.1.5 passed"
	fi
fi

# 6.2 Turn on filename extensions
if [[ remediateRequested "6_2" ]]; then
    filenameExt=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.finder AppleShowAllExtensions)
    if [ "$filenameExt" = "1" ]; then
        writelog "6.2 passed";
    else
        sudo -u "$currentUser" defaults write NSGlobalDomain AppleShowAllExtensions -bool true
        pkill -u "$currentUser" Finder
        writelog "6.2 remediated"
        # defaults write /Users/"$currentUser"/Library/Preferences/.GlobalPreferences.plist AppleShowAllExtensions -bool true
    fi
fi

# 6.3 Disable the automatic run of safe files in Safari
if [[ remediateRequested "6_3" ]]; then
    safariSafe=$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads)
    if [ "$safariSafe" = "1" ]; then
        defaults write /Users/"$currentUser"/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads -bool false
        writelog "6.3 remediated";
    else
        writelog "6.3 passed"
    fi
fi

# Reset the preference caching process...
killall cfprefsd
# There may be times when cfprefsd will have written over the changes we just made here 
# and the changes won't take. It may take a few times through this script before everything
# is remedited takes. 


writelog "Remediation complete"
exit 0
