INFO:

Refers to document CIS_Apple_OSX_10.12_Benchmark_v1.0.0.pdf, available at https://benchmarks.cisecurity.org


USAGE:

#Script: 1\_Set\_Organization\_Priorities

**Description:** 

Policy: Generally run with a "Once per computer" frequency. Can be re-run as needed if organizational values change.

This creates a settings plist file used by the other CIS scripts which will run on the client. Edit the file to indicate which CIS items you wish to score and, optionally, remediate. 

The script writes to /Library/Application Support/SecurityScoring/org_security_score.plist by default.

**Settings:** 

Admins set organizational compliance preferences for each listed item. The values should be set to true when you wish to consider any given item and false to disregard that item. 

**Example 1:** 

	OrgScore6_1_5="true"
	OrgRemediate6_1_5="true"

CIS 6.1.5 will be scored and remediated. 

**Example 2:** 

	OrgScore6_1_5="true"
	OrgRemediate6_1_5="false"

CIS 6\_1_5 will be audited but will not be remediated. Another policy or profile may be implemented separately to remediate this item. Note: The script will not attempt to remediate any item unless it is also being scored. 

When the defaul settins are used, the following items are scored but will not be remediated: 

* Item "1.1 Verify all Apple provided software is current".
* Item "5.6 Enable OCSP and CRL certificate checking".


#Script:  2\_Security\_Audit\_Compliance

Policy: Some recurring trigger to track compliance over time.

Reads the plist at /Library/Application Support/SecurityScoring/org_security_score.plist. For items prioritized (listed as "true,") the script queries against the current computer/user environment to determine compliance against each item.

Non-compliant items are recorded at /Library/Application Support/SecurityScoring/org_audit

#Script:  2.5\_Audit\_List Extension Attribute

Set as Data Type "String."

Reads contents of /Library/Application Support/SecurityScoring/org_audit file and records to Jamf Pro inventory record.

#Script:  2.6\_Audit\_Count Extension Attribute

Set as Data Type "Integer." 

Reads contents of /Library/Application Support/SecurityScoring/org\_audit file and records count of items to Jamf Pro inventory record. Usable with smart group logic (2.6\_Audit\_Count greater than 0) to immediately determine computers not in compliance.

#Script:  3\_Security\_Remediation

Policy: Some recurring trigger to enforce compliance over time.

Reads the plist at /Library/Application Support/SecurityScoring/org_security_score.plist. For items prioritized (listed as "true,") the script applies recommended remediation actions for the client/user.

SCORED CIS EXCEPTIONS:

- Does not implement pwpolicy commands (5.2.1 - 5.2.8)
- Audits but does not actively remediate (Typicall, other Jamf Pro profile/policy functionality is ued to manages these items):
* 2.4.4 Disable Printer Sharing
* 2.6.1 Enable FileVault
* 2.7.4 iCloud Drive Document sync
* 2.7.5 iCloud Drive Desktop sync
* 2.11 Java 6 is not the default Java runtime
* 5.12 Create a custom message for the Login Screen
* 5.13 Create a Login window banner
