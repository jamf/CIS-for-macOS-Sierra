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
# updated for 10.12 CIS benchmarks by Katie English, Jamf May 2017
# github.com/jamfprofessionalservices

# USAGE
# Admins set organizational compliance for each listed item, which gets written to plist.
# Values default to "true," and must be commented to "false" to disregard as an organizational priority.
# Writes to /Library/Application Support/SecurityScoring/org_security_score.plist by default.

# Create the Scoring file destination directory if it does not already exist

dir="/Library/Application Support/SecurityScoring"

if [[ ! -e "$dir" ]]; then
    mkdir "$dir"
fi
plistlocation="$dir/org_security_score.plist"


##################################################################
############### ADMINS DESIGNATE ORG VALUES BELOW ################
##################################################################

# 1.1 Verify all Apple provided software is current
# OrgScore1_1="true"
OrgScore1_1="false"

# 1.2 Enable Auto Update 
OrgScore1_2="true"
# OrgScore1_2="false"

# 1.3 Enable app update installs 
OrgScore1_3="true"
# OrgScore1_3="false"

# 1.4 Enable system data files and security update installs 
OrgScore1_4="true"
# OrgScore1_4="false"

# 1.5 Enable OS X update installs 
OrgScore1_5="true"
# OrgScore1_5="false"

# 2.1.1 Turn off Bluetooth, if no paired devices exist 
OrgScore2_1_1="true"
# OrgScore2_1_1="false"

# 2.1.3 Show Bluetooth status in menu bar 
OrgScore2_1_3="true"
# OrgScore2_1_3="false"

# 2.2.2 Ensure time set is within appropriate limits 
OrgScore2_2_2="true"
# OrgScore2_2_2="false"

# 2.2.3 Restrict NTP server to loopback interface
OrgScore2_2_3="true"
# OrgScore2_2_3="false"

# 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver 
OrgScore2_3_1="true"
# OrgScore2_3_1="false"

# 2.3.2 Secure screen saver corners 
OrgScore2_3_2="true"
# OrgScore2_3_2="false"

# 2.3.4 Set a screen corner to Start Screen Saver 
OrgScore2_3_4="true"
# OrgScore2_3_4="false"

# 2.4.1 Disable Remote Apple Events 
OrgScore2_4_1="true"
# OrgScore2_4_1="false"

# 2.4.2 Disable Internet Sharing 
OrgScore2_4_2="true"
# OrgScore2_4_2="false"

# 2.4.3 Disable Screen Sharing 
OrgScore2_4_3="true"
# OrgScore2_4_3="false"

# 2.4.4 Disable Printer Sharing
OrgScore2_4_4="true"
# OrgScore2_4_4="false"

# 2.4.5 Disable Remote Login 
OrgScore2_4_5="true"
# OrgScore2_4_5="false"

# 2.4.6 Disable DVD or CD Sharing
OrgScore2_4_6="true"
# OrgScore2_4_6="false"

# 2.4.7 Disable Bluetooth Sharing 
OrgScore2_4_7="true"
# OrgScore2_4_7="false"

# 2.4.8 Disable File Sharing 
OrgScore2_4_8="true"
# OrgScore2_4_8="false"

# 2.4.9 Disable Remote Management 
OrgScore2_4_9="true"
# OrgScore2_4_9="false"

# 2.5.1 Disable "Wake for network access" 
OrgScore2_5_1="true"
# OrgScore2_5_1="false"

# 2.5.2 Disable sleeping the computer when connected to power 
OrgScore2_5_2="true"
# OrgScore2_5_2="false"

# 2.6.1 Enable FileVault
OrgScore2_6_1="true"
# OrgScore2_6_1="false"

# 2.6.2 Enable Gatekeeper
OrgScore2_6_2="true"
# OrgScore2_6_2="false"

# 2.6.3 Enable Firewall 
OrgScore2_6_3="true"
# OrgScore2_6_3="false"

# 2.6.4 Enable Firewall Stealth Mode 
OrgScore2_6_4="true"
# OrgScore2_6_4="false"

# 2.6.5 Review Application Firewall Rules 
OrgScore2_6_5="true"
# OrgScore2_6_5="false"

# 2.7.4 iCloud Drive Document sync
OrgScore2_7_4="true"
# OrgScore2_7_4="false"

# 2.7.5 iCloud Drive Desktop sync
OrgScore2_7_5="true"
# OrgScore2_7_5="false"

# 2.8.1 Time Machine Auto-Backup
OrgScore2_8_1="true"
# OrgScore2_8_1="false"

# 2.9 Pair the remote control infrared receiver if enabled
OrgScore2_9="true"
# OrgScore2_9="false"

# 2.10 Enable Secure Keyboard Entry in terminal.app 
OrgScore2_10="true"
# OrgScore2_10="false"

# 2.11 Java 6 is not the default Java runtime 
OrgScore2_11="true"
# OrgScore2_11="false"

# 3.1.1 Retain system.log for 90 or more days 
OrgScore3_1_1="true"
# OrgScore3_1_1="false"

# 3.1.2 Retain appfirewall.log for 90 or more days 
OrgScore3_1_2="true"
# OrgScore3_1_2="false"

# 3.1.3 Retain authd.log for 90 or more days 
OrgScore3_1_3="true"
# OrgScore3_1_3="false"

# 3.2 Enable security auditing
OrgScore3_2="true"
# OrgScore3_2="false"

# 3.3 Configure Security Auditing Flags
OrgScore3_3="true"
# OrgScore3_3="false"

# 3.5 Retain install.log for 365 or more days 
OrgScore3_5="true"
# OrgScore3_5="false"

# 4.1 Disable Bonjour advertising service 
OrgScore4_1="true"
# OrgScore4_1="false"

# 4.2 Enable "Show Wi-Fi status in menu bar" 
OrgScore4_2="true"
# OrgScore4_2="false"

# 4.4 Ensure http server is not running 
OrgScore4_4="true"
# OrgScore4_4="false"

# 4.5 Ensure ftp server is not running
OrgScore4_5="true"
# OrgScore4_5="false"

# 4.6 Ensure nfs server is not running
OrgScore4_6="true"
# OrgScore4_6="false"

# 5.1.1 Secure Home Folders
OrgScore5_1_1="true"
# OrgScore5_1_1="false"

# 5.1.2 Check System Wide Applications for appropriate permissions
OrgScore5_1_2="true"
# OrgScore5_1_2="false"

# 5.1.3 Check System folder for world writable files
OrgScore5_1_3="true"
# OrgScore5_1_3="false"

# 5.1.4 Check Library folder for world writable files
OrgScore5_1_4="true"
# OrgScore5_1_4="false"

# 5.3 Reduce the sudo timeout period
OrgScore5_3="true"
# OrgScore5_3="false"

# 5.4 Automatically lock the login keychain for inactivity
OrgScore5_4="true"
# OrgScore5_4="false"

# 5.5 Ensure login keychain is locked when the computer sleeps
OrgScore5_5="true"
# OrgScore5_5="false"

# 5.6 Enable OCSP and CRL certificate checking
# OrgScore5_6="true"
OrgScore5_6="false"

# 5.7 Do not enable the "root" account
OrgScore5_7="true"
# OrgScore5_7="false"

# 5.8 Disable automatic login
OrgScore5_8="true"
# OrgScore5_8="false"

# 5.9 Require a password to wake the computer from sleep or screen saver
OrgScore5_9="true"
# OrgScore5_9="false"

# 5.10 Require an administrator password to access system-wide preferences
OrgScore5_10="true"
# OrgScore5_10="false"

# 5.11 Disable ability to login to another user's active and locked session
OrgScore5_11="true"
# OrgScore5_11="false"

# 5.12 Create a custom message for the Login Screen
OrgScore5_12="true"
# OrgScore5_12="false"

# 5.13 Create a Login window banner
OrgScore5_13="true"
# OrgScore5_13="false"

# 5.18 System Integrity Protection status
OrgScore5_18="true"
# OrgScore5_18="false"

# 5.19 Install an approved tokend for smartcard authentication
OrgScore5_19="true"
# OrgScore5_19="false"

# 6.1.1 Display login window as name and password
OrgScore6_1_1="true"
# OrgScore6_1_1="false"

# 6.1.2 Disable "Show password hints"
OrgScore6_1_2="true"
# OrgScore6_1_2="false"

# 6.1.3 Disable guest account
OrgScore6_1_3="true"
# OrgScore6_1_3="false"

# 6.1.4 Disable "Allow guests to connect to shared folders"
OrgScore6_1_4="true"
# OrgScore6_1_4="false"

# 6.1.5 Remove Guest home folder
OrgScore6_1_5="true"
# OrgScore6_1_5="false"

# 6.2 Turn on filename extensions
OrgScore6_2="true"
# OrgScore6_2="false"

# 6.3 Disable the automatic run of safe files in Safari
OrgScore6_3="true"
# OrgScore6_3="false"




##################################################################
############# DO NOT MODIFY ANYTHING BELOW THIS LINE #############
##################################################################
# Write org_security_score values to local plist

cat << EOF > "$plistlocation"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>		
		<key>OrgScore1_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore1_2</key>
		<${OrgScore1_2}/>
		<key>OrgScore1_3</key>
		<${OrgScore1_3}/>
		<key>OrgScore1_4</key>
		<${OrgScore1_4}/>
		<key>OrgScore1_5</key>
		<${OrgScore1_5}/>
		<key>OrgScore2_1_1</key>
		<${OrgScore2_1_1}/>
		<key>OrgScore2_1_3</key>
		<${OrgScore2_1_3}/>
		<key>OrgScore2_2_2</key>
		<${OrgScore2_2_2}/>
		<key>OrgScore2_2_3</key>
		<${OrgScore2_2_3}/>
		<key>OrgScore2_3_1</key>
		<${OrgScore2_3_1}/>
		<key>OrgScore2_3_2</key>
		<${OrgScore2_3_2}/>
		<key>OrgScore2_3_4</key>
		<${OrgScore2_3_4}/>
		<key>OrgScore2_4_1</key>
		<${OrgScore2_4_1}/>
		<key>OrgScore2_4_2</key>
		<${OrgScore2_4_2}/>
		<key>OrgScore2_4_3</key>
		<${OrgScore2_4_3}/>
		<key>OrgScore2_4_4</key>
		<${OrgScore2_4_4}/>
		<key>OrgScore2_4_5</key>
		<${OrgScore2_4_5}/>
		<key>OrgScore2_4_6</key>
		<${OrgScore2_4_6}/>
		<key>OrgScore2_4_7</key>
		<${OrgScore2_4_7}/>
		<key>OrgScore2_4_8</key>
		<${OrgScore2_4_8}/>
		<key>OrgScore2_4_9</key>
		<${OrgScore2_4_9}/>
		<key>OrgScore2_5_1</key>
		<${OrgScore2_5_1}/>
		<key>OrgScore2_5_2</key>
		<${OrgScore2_5_2}/>
		<key>OrgScore2_6_1</key>
		<${OrgScore2_6_1}/>
		<key>OrgScore2_6_2</key>
		<${OrgScore2_6_2}/>
		<key>OrgScore2_6_3</key>
		<${OrgScore2_6_3}/>
		<key>OrgScore2_6_4</key>
		<${OrgScore2_6_4}/>
		<key>OrgScore2_6_5</key>
		<${OrgScore2_6_5}/>
		<key>OrgScore2_7_4</key>
		<${OrgScore2_7_4}/>
		<key>OrgScore2_7_5</key>
		<${OrgScore2_7_5}/>
		<key>OrgScore2_8_1</key>
		<${OrgScore2_8_1}/>
		<key>OrgScore2_9</key>
		<${OrgScore2_9}/>
		<key>OrgScore2_10</key>
		<${OrgScore2_10}/>
		<key>OrgScore2_11</key>
		<${OrgScore2_11}/>
		<key>OrgScore3_1_1</key>
		<${OrgScore3_1_1}/>
		<key>OrgScore3_1_2</key>
		<${OrgScore3_1_2}/>
		<key>OrgScore3_1_3</key>
		<${OrgScore3_1_3}/>
		<key>OrgScore3_2</key>
		<${OrgScore3_2}/>
		<key>OrgScore3_3</key>
		<${OrgScore3_3}/>
		<key>OrgScore3_5</key>
		<${OrgScore3_5}/>
		<key>OrgScore4_1</key>
		<${OrgScore4_1}/>
		<key>OrgScore4_2</key>
		<${OrgScore4_2}/>
		<key>OrgScore4_4</key>
		<${OrgScore4_4}/>
		<key>OrgScore4_5</key>
		<${OrgScore4_5}/>
		<key>OrgScore4_6</key>
		<${OrgScore4_6}/>
		<key>OrgScore5_1_1</key>
		<${OrgScore5_1_1}/>
		<key>OrgScore5_1_2</key>
		<${OrgScore5_1_2}/>
		<key>OrgScore5_1_3</key>
		<${OrgScore5_1_3}/>
		<key>OrgScore5_1_4</key>
		<${OrgScore5_1_4}/>
		<key>OrgScore5_3</key>
		<${OrgScore5_3}/>
		<key>OrgScore5_4</key>
		<${OrgScore5_4}/>
		<key>OrgScore5_5</key>
		<${OrgScore5_5}/>
		<key>OrgScore5_6</key>
		<${OrgScore5_6}/>
		<key>OrgScore5_7</key>
		<${OrgScore5_7}/>
		<key>OrgScore5_8</key>
		<${OrgScore5_8}/>
		<key>OrgScore5_9</key>
		<${OrgScore5_9}/>
		<key>OrgScore5_10</key>
		<${OrgScore5_10}/>
		<key>OrgScore5_11</key>
		<${OrgScore5_11}/>
		<key>OrgScore5_12</key>
		<${OrgScore5_12}/>
		<key>OrgScore5_13</key>
		<${OrgScore5_13}/>
		<key>OrgScore5_18</key>
		<${OrgScore5_18}/>
		<key>OrgScore5_19</key>
		<${OrgScore5_19}/>
		<key>OrgScore6_1_1</key>
		<${OrgScore6_1_1}/>
		<key>OrgScore6_1_2</key>
		<${OrgScore6_1_2}/>
		<key>OrgScore6_1_3</key>
		<${OrgScore6_1_3}/>
		<key>OrgScore6_1_4</key>
		<${OrgScore6_1_4}/>
		<key>OrgScore6_1_5</key>
		<${OrgScore6_1_5}/>
		<key>OrgScore6_2</key>
		<${OrgScore6_2}/>
		<key>OrgScore6_3</key>
		<${OrgScore6_3}/>
</dict>
</plist>
EOF