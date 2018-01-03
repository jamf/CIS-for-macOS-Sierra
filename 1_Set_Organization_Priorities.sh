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

# Note that the remediations script does not handle all items, but we have included a pref
#  for them in case you want to add your own remediation code. 

# 1.1 Verify all Apple provided software is current
# Default setting for 1_1: Score "true", Remediate "false"
OrgScore1_1="true"
OrgRemediate1_1="false"

# 1.2 Enable Auto Update 
# Default setting for 1_2: "true"
OrgScore1_2="true"
OrgRemediate1_2="true"

# 1.3 Enable app update installs 
# Default setting for 1_3: "true"
OrgScore1_3="true"
OrgRemediate1_3="true"

# 1.4 Enable system data files and security update installs 
# Default setting for 1_4: "true"
OrgScore1_4="true"
OrgRemediate1_4="true"

# 1.5 Enable OS X update installs 
# Default setting for 1_5: "true"
OrgScore1_5="true"
OrgRemediate1_5="true"

# 2.1.1 Turn off Bluetooth, if no paired devices exist 
# Default setting for 2_1_1: "true"
OrgScore2_1_1="true"
OrgRemediate2_1_1="true"

# 2.1.3 Show Bluetooth status in menu bar 
# Default setting for 2_1_3: "true"
OrgScore2_1_3="true"
OrgRemediate2_1_3="true"

# 2.2.2 Ensure time set is within appropriate limits 
# Default setting for 2_2_2: "true"
OrgScore2_2_2="true"
OrgRemediate2_2_2="true"

# 2.2.3 Restrict NTP server to loopback interface
# Default setting for 2_2_3: "true"
OrgScore2_2_3="true"
OrgRemediate2_2_3="true"

# 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver 
# Default setting for 2_3_1: "true"
OrgScore2_3_1="true"
OrgRemediate2_3_1="true"

# 2.3.2 Secure screen saver corners 
# Default setting for 2_3_2: "true"
OrgScore2_3_2="true"
OrgRemediate2_3_2="true"

# 2.3.4 Set a screen corner to Start Screen Saver 
# Default setting for 2_3_4: "true"
OrgScore2_3_4="true"
OrgRemediate2_3_4="true"

# 2.4.1 Disable Remote Apple Events 
# Default setting for 2_4_1: "true"
OrgScore2_4_1="true"
OrgRemediate2_4_1="true"

# 2.4.2 Disable Internet Sharing 
# Default setting for 2_4_2: "true"
OrgScore2_4_2="true"
OrgRemediate2_4_2="true"

# 2.4.3 Disable Screen Sharing 
# Default setting for 2_4_3: "true"
OrgScore2_4_3="true"
OrgRemediate2_4_3="true"

# 2.4.4 Disable Printer Sharing
# Default setting for 2_4_4: "true"
OrgScore2_4_4="true"
OrgRemediate2_4_4="true"

# 2.4.5 Disable Remote Login 
# Default setting for 2_4_5: "true"
OrgScore2_4_5="true"
OrgRemediate2_4_5="true"

# 2.4.6 Disable DVD or CD Sharing
# Default setting for 2_4_6: "true"
OrgScore2_4_6="true"
OrgRemediate2_4_6="true"

# 2.4.7 Disable Bluetooth Sharing 
# Default setting for 2_4_7: "true"
OrgScore2_4_7="true"
OrgRemediate2_4_7="true"

# 2.4.8 Disable File Sharing 
# Default setting for 2_4_8: "true"
OrgScore2_4_8="true"
OrgRemediate2_4_8="true"

# 2.4.9 Disable Remote Management 
# Default setting for 2_4_9: "true"
OrgScore2_4_9="true"
OrgRemediate2_4_9="true"

# 2.5.1 Disable "Wake for network access" 
# Default setting for 2_5_1: "true"
OrgScore2_5_1="true"
OrgRemediate2_5_1="true"

# 2.5.2 Disable sleeping the computer when connected to power 
# Default setting for 2_5_2: "true"
OrgScore2_5_2="true"
OrgRemediate2_5_2="true"

# 2.6.1 Enable FileVault
# Default setting for 2_6_1: Score "true", Remediate "false"
OrgScore2_6_1="true"
OrgRemediate2_6_1="false"

# 2.6.2 Enable Gatekeeper
# Default setting for 2_6_2: "true"
OrgScore2_6_2="true"
OrgRemediate2_6_2="true"

# 2.6.3 Enable Firewall 
# Default setting for 2_6_3: "true"
OrgScore2_6_3="true"
OrgRemediate2_6_3="true"

# 2.6.4 Enable Firewall Stealth Mode 
# Default setting for 2_6_4: "true"
OrgScore2_6_4="true"
OrgRemediate2_6_4="true"

# 2.6.5 Review Application Firewall Rules 
# Default setting for 2_6_5: "true"
OrgScore2_6_5="true"
OrgRemediate2_6_5="true"

# 2.7.4 iCloud Drive Document sync
# Default setting for 2_7_4: "true"
OrgScore2_7_4="true"
OrgRemediate2_7_4="true"

# 2.7.5 iCloud Drive Desktop sync
# Default setting for 2_7_5: "true"
OrgScore2_7_5="true"
OrgRemediate2_7_5="true"

# 2.8.1 Time Machine Auto-Backup
# Default setting for 2_8_1: "true"
OrgScore2_8_1="true"
OrgRemediate2_8_1="true"

# 2.9 Pair the remote control infrared receiver if enabled
# Default setting for 2_9: "true"
OrgScore2_9="true"
OrgRemediate2_9="true"

# 2.10 Enable Secure Keyboard Entry in terminal.app 
# Default setting for 2_10: "true"
OrgScore2_10="true"
OrgRemediate2_10="true"

# 2.11 Java 6 is not the default Java runtime 
# Default setting for 2_11: "true"
OrgScore2_11="true"
OrgRemediate2_11="true"

# 3.1.1 Retain system.log for 90 or more days 
# Default setting for 3_1_1: "true"
OrgScore3_1_1="true"
OrgRemediate3_1_1="true"

# 3.1.2 Retain appfirewall.log for 90 or more days 
# Default setting for 3_1_2: "true"
OrgScore3_1_2="true"
OrgRemediate3_1_2="true"

# 3.1.3 Retain authd.log for 90 or more days 
# Default setting for 3_1_3: "true"
OrgScore3_1_3="true"
OrgRemediate3_1_3="true"

# 3.2 Enable security auditing
# Default setting for 3_2: "true"
OrgScore3_2="true"
OrgRemediate3_2="true"

# 3.3 Configure Security Auditing Flags
# Default setting for 3_3: "true"
OrgScore3_3="true"
OrgRemediate3_3="true"

# 3.5 Retain install.log for 365 or more days 
# Default setting for 3_5: "true"
OrgScore3_5="true"
OrgRemediate3_5="true"

# 4.1 Disable Bonjour advertising service 
# Default setting for 4_1: "true"
OrgScore4_1="true"
OrgRemediate4_1="true"

# 4.2 Enable "Show Wi-Fi status in menu bar" 
# Default setting for 4_2: "true"
OrgScore4_2="true"
OrgRemediate4_2="true"

# 4.4 Ensure http server is not running 
# Default setting for 4_4: "true"
OrgScore4_4="true"
OrgRemediate4_4="true"

# 4.5 Ensure ftp server is not running
# Default setting for 4_5: "true"
OrgScore4_5="true"
OrgRemediate4_5="true"

# 4.6 Ensure nfs server is not running
# Default setting for 4_6: "true"
OrgScore4_6="true"
OrgRemediate4_6="true"

# 5.1.1 Secure Home Folders
# Default setting for 5_1_1: "true"
OrgScore5_1_1="true"
OrgRemediate5_1_1="true"

# 5.1.2 Check System Wide Applications for appropriate permissions
# Default setting for 5_1_2: "true"
OrgScore5_1_2="true"
OrgRemediate5_1_2="true"

# 5.1.3 Check System folder for world writable files
# Default setting for 5_1_3: "true"
OrgScore5_1_3="true"
OrgRemediate5_1_3="true"

# 5.1.4 Check Library folder for world writable files
# Default setting for 5_1_4: "true"
OrgScore5_1_4="true"
OrgRemediate5_1_4="true"

# 5.3 Reduce the sudo timeout period
# Default setting for 5_3: "true"
OrgScore5_3="true"
OrgRemediate5_3="true"

# 5.4 Automatically lock the login keychain for inactivity
# Default setting for 5_4: "true"
OrgScore5_4="true"
OrgRemediate5_4="true"

# 5.5 Ensure login keychain is locked when the computer sleeps
# Default setting for 5_5: "true"
OrgScore5_5="true"
OrgRemediate5_5="true"

# 5.6 Enable OCSP and CRL certificate checking
# Default setting for 5_6: Score "true", Remediate "false"
OrgScore5_6="true"
OrgRemediate5_6="false"

# 5.7 Do not enable the "root" account
# Default setting for 5_7: "true"
OrgScore5_7="true"
OrgRemediate5_7="true"

# 5.8 Disable automatic login
# Default setting for 5_8: "true"
OrgScore5_8="true"
OrgRemediate5_8="true"

# 5.9 Require a password to wake the computer from sleep or screen saver
# Default setting for 5_9: "true"
OrgScore5_9="true"
OrgRemediate5_9="true"

# 5.10 Require an administrator password to access system-wide preferences
# Default setting for 5_10: "true"
OrgScore5_10="true"
OrgRemediate5_10="true"

# 5.11 Disable ability to login to another user's active and locked session
# Default setting for 5_11: "true"
OrgScore5_11="true"
OrgRemediate5_11="true"

# 5.12 Create a custom message for the Login Screen
# Default setting for 5_12: "true"
OrgScore5_12="true"
OrgRemediate5_12="true"

# 5.13 Create a Login window banner
# Default setting for 5_13: "true"
OrgScore5_13="true"
OrgRemediate5_13="true"

# 5.18 System Integrity Protection status
# Default setting for 5_18: "true"
OrgScore5_18="true"
OrgRemediate5_18="true"

# 5.19 Install an approved tokend for smartcard authentication
# Default setting for 5_19: "true"
OrgScore5_19="true"
OrgRemediate5_19="true"

# 6.1.1 Display login window as name and password
# Default setting for 6_1_1: "true"
OrgScore6_1_1="true"
OrgRemediate6_1_1="true"

# 6.1.2 Disable "Show password hints"
# Default setting for 6_1_2: "true"
OrgScore6_1_2="true"
OrgRemediate6_1_2="true"

# 6.1.3 Disable guest account
# Default setting for 6_1_3: "true"
OrgScore6_1_3="true"
OrgRemediate6_1_3="true"

# 6.1.4 Disable "Allow guests to connect to shared folders"
# Default setting for 6_1_4: "true"
OrgScore6_1_4="true"
OrgRemediate6_1_4="true"

# 6.1.5 Remove Guest home folder
# Default setting for 6_1_5: "true"
OrgScore6_1_5="true"
OrgRemediate6_1_5="true"

# 6.2 Turn on filename extensions
# Default setting for 6_2: "true"
OrgScore6_2="true"
OrgRemediate6_2="true"

# 6.3 Disable the automatic run of safe files in Safari
# Default setting for 6_3: "true"
OrgScore6_3="true"
OrgRemediate6_3="true"




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
		<key>OrgRemediate1_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore1_2</key>
		<${OrgScore1_2}/>
		<key>OrgRemediate1_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore1_3</key>
		<${OrgScore1_3}/>
		<key>OrgRemediate1_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore1_4</key>
		<${OrgScore1_4}/>
		<key>OrgRemediate1_4</key>
		<${OrgScore1_1}/>
		<key>OrgScore1_5</key>
		<${OrgScore1_5}/>
		<key>OrgRemediate1_5</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_1_1</key>
		<${OrgScore2_1_1}/>
		<key>OrgRemediate2_1_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_1_3</key>
		<${OrgScore2_1_3}/>
		<key>OrgRemediate2_1_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_2_2</key>
		<${OrgScore2_2_2}/>
		<key>OrgRemediate2_2_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_2_3</key>
		<${OrgScore2_2_3}/>
		<key>OrgRemediate2_2_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_3_1</key>
		<${OrgScore2_3_1}/>
		<key>OrgRemediate2_3_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_3_2</key>
		<${OrgScore2_3_2}/>
		<key>OrgRemediate2_3_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_3_4</key>
		<${OrgScore2_3_4}/>
		<key>OrgRemediate2_3_4</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_4_1</key>
		<${OrgScore2_4_1}/>
		<key>OrgRemediate2_4_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_4_2</key>
		<${OrgScore2_4_2}/>
		<key>OrgRemediate2_4_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_4_3</key>
		<${OrgScore2_4_3}/>
		<key>OrgRemediate2_4_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_4_4</key>
		<${OrgScore2_4_4}/>
		<key>OrgRemediate2_4_4</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_4_5</key>
		<${OrgScore2_4_5}/>
		<key>OrgRemediate2_4_5</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_4_6</key>
		<${OrgScore2_4_6}/>
		<key>OrgRemediate2_4_6</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_4_7</key>
		<${OrgScore2_4_7}/>
		<key>OrgRemediate2_4_7</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_4_8</key>
		<${OrgScore2_4_8}/>
		<key>OrgRemediate2_4_8</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_4_9</key>
		<${OrgScore2_4_9}/>
		<key>OrgRemediate2_4_9</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_5_1</key>
		<${OrgScore2_5_1}/>
		<key>OrgRemediate2_5_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_5_2</key>
		<${OrgScore2_5_2}/>
		<key>OrgRemediate2_5_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_6_1</key>
		<${OrgScore2_6_1}/>
		<key>OrgRemediate2_6_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_6_2</key>
		<${OrgScore2_6_2}/>
		<key>OrgRemediate2_6_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_6_3</key>
		<${OrgScore2_6_3}/>
		<key>OrgRemediate2_6_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_6_4</key>
		<${OrgScore2_6_4}/>
		<key>OrgRemediate2_6_4</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_6_5</key>
		<${OrgScore2_6_5}/>
		<key>OrgRemediate2_6_5</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_7_4</key>
		<${OrgScore2_7_4}/>
		<key>OrgRemediate2_7_4</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_7_5</key>
		<${OrgScore2_7_5}/>
		<key>OrgRemediate2_7_5</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_8_1</key>
		<${OrgScore2_8_1}/>
		<key>OrgRemediate2_8_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_9</key>
		<${OrgScore2_9}/>
		<key>OrgRemediate2_9</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_10</key>
		<${OrgScore2_10}/>
		<key>OrgRemediate2_10</key>
		<${OrgScore1_1}/>
		<key>OrgScore2_11</key>
		<${OrgScore2_11}/>
		<key>OrgRemediate2_11</key>
		<${OrgScore1_1}/>
		<key>OrgScore3_1_1</key>
		<${OrgScore3_1_1}/>
		<key>OrgRemediate3_1_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore3_1_2</key>
		<${OrgScore3_1_2}/>
		<key>OrgRemediate3_1_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore3_1_3</key>
		<${OrgScore3_1_3}/>
		<key>OrgRemediate3_1_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore3_2</key>
		<${OrgScore3_2}/>
		<key>OrgRemediate3_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore3_3</key>
		<${OrgScore3_3}/>
		<key>OrgRemediate3_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore3_5</key>
		<${OrgScore3_5}/>
		<key>OrgRemediate3_5</key>
		<${OrgScore1_1}/>
		<key>OrgScore4_1</key>
		<${OrgScore4_1}/>
		<key>OrgRemediate4_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore4_2</key>
		<${OrgScore4_2}/>
		<key>OrgRemediate4_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore4_4</key>
		<${OrgScore4_4}/>
		<key>OrgRemediate4_4</key>
		<${OrgScore1_1}/>
		<key>OrgScore4_5</key>
		<${OrgScore4_5}/>
		<key>OrgRemediate4_5</key>
		<${OrgScore1_1}/>
		<key>OrgScore4_6</key>
		<${OrgScore4_6}/>
		<key>OrgRemediate4_6</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_1_1</key>
		<${OrgScore5_1_1}/>
		<key>OrgRemediate5_1_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_1_2</key>
		<${OrgScore5_1_2}/>
		<key>OrgRemediate5_1_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_1_3</key>
		<${OrgScore5_1_3}/>
		<key>OrgRemediate5_1_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_1_4</key>
		<${OrgScore5_1_4}/>
		<key>OrgRemediate5_1_4</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_3</key>
		<${OrgScore5_3}/>
		<key>OrgRemediate5_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_4</key>
		<${OrgScore5_4}/>
		<key>OrgRemediate5_4</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_5</key>
		<${OrgScore5_5}/>
		<key>OrgRemediate5_5</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_6</key>
		<${OrgScore5_6}/>
		<key>OrgRemediate5_6</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_7</key>
		<${OrgScore5_7}/>
		<key>OrgRemediate5_7</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_8</key>
		<${OrgScore5_8}/>
		<key>OrgRemediate5_8</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_9</key>
		<${OrgScore5_9}/>
		<key>OrgRemediate5_9</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_10</key>
		<${OrgScore5_10}/>
		<key>OrgRemediate5_10</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_11</key>
		<${OrgScore5_11}/>
		<key>OrgRemediate5_11</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_12</key>
		<${OrgScore5_12}/>
		<key>OrgRemediate5_12</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_13</key>
		<${OrgScore5_13}/>
		<key>OrgRemediate5_13</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_18</key>
		<${OrgScore5_18}/>
		<key>OrgRemediate5_18</key>
		<${OrgScore1_1}/>
		<key>OrgScore5_19</key>
		<${OrgScore5_19}/>
		<key>OrgRemediate5_19</key>
		<${OrgScore1_1}/>
		<key>OrgScore6_1_1</key>
		<${OrgScore6_1_1}/>
		<key>OrgRemediate6_1_1</key>
		<${OrgScore1_1}/>
		<key>OrgScore6_1_2</key>
		<${OrgScore6_1_2}/>
		<key>OrgRemediate6_1_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore6_1_3</key>
		<${OrgScore6_1_3}/>
		<key>OrgRemediate6_1_3</key>
		<${OrgScore1_1}/>
		<key>OrgScore6_1_4</key>
		<${OrgScore6_1_4}/>
		<key>OrgRemediate6_1_4</key>
		<${OrgScore1_1}/>
		<key>OrgScore6_1_5</key>
		<${OrgScore6_1_5}/>
		<key>OrgRemediate6_1_5</key>
		<${OrgScore1_1}/>
		<key>OrgScore6_2</key>
		<${OrgScore6_2}/>
		<key>OrgRemediate6_2</key>
		<${OrgScore1_1}/>
		<key>OrgScore6_3</key>
		<${OrgScore6_3}/>
		<key>OrgRemediate6_3</key>
		<${OrgScore1_1}/>
</dict>
</plist>
EOF