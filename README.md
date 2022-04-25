# NX-LR-Inventory
Compares assets automatically scanned for and seen from a Nexpose vulnerability scanning tool against hosts recorded in a LogRhythm SIEM. Returns a report showing the differences.

First, the tool queries Nexpose's API for all assets, and does some filtering on OS, IP address and hostname. It then compares the filtered Nexpose assets against the hosts found in the LogRhythm SIEM's SQL databases. A CSV report is the output. 

During initial filtering of Nexpose assets, a new object is created for each asset. This acts to strip unnecessary information not required to be held in memory during comparison, and also begins to form the basis of the report output.

# Restart LogRhythm Agent - SmartResponse

This is a SmartResponse plugin for use with LogRhythm SIEM. It is designed to start the LogRhythm agent software if it fails to report that it is online.
This particular SmartResponse is able to communicate with Logrhythm agents on other Active Directory domains. It does this by first querying a central Jenkins API, which in turn makes calls into the other Active Directory domains. 

## Contents:
* LogRhythm SmartResponse plugin:
    * Restart-LRAgent-SRP.ps1 - Script that runs on LogRhythm to query the Jenkins API
    * actions.xml - Configuration file
* Restart-LRAgent-Jenkins.ps1 - Jenkins job script that runs from Jenkins

## Features:
* Regex parsing and group matching.
* Variable API interaction.
* Job feedback output to SIEM analyst.
* Job objects for use in timing out failed jobs and supplying job status info after run.

