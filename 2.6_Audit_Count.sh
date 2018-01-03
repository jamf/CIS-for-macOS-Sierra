#!/bin/bash

# Security Reporting - Count Risks

auditfile='/Library/Application Support/SecurityScoring/org_audit'
$result=$(cat "$auditfile" | grep "*" | wc -l | tr -d '[:space:]')
echo "<result>${result}</result>"
