Copyright (C) 2005-2012 Splunk Inc. All Rights Reserved.

Add-on:			Splunk for Cisco IPS
Current Version:	2.0.0
Last Modified:		2012-07-21
Splunk Version:		4.0.x, 4.1.x, 4.2.x, and 4.3.x
Author:			Splunk

The Splunk for Cisco IPS SDEE add-on allows you to consume, analyze, and report on Cisco IPS data that conforms to the Security Device Event Exchange (SDEE) standard. This add-on includes a scripted input to bring your IPS data into Splunk and knowledge objects (source type definition, field extractions, event types, and tags) to help you view and interpret that data. The Cisco IPS add-on is designed to work with the Splunk Cisco Security Suite; install these together to access reports and dashboards that give you visual insight into your Cisco IPS data.

##### What's New #####
2.0.0 (2012-08-21)
- All IPS device credentials are now encrypted and stored in app.conf instead of clear-text in inputs.conf. This changed the syntax of the script options in inputs.conf. But, the Python script is setup to be backwards compatible with previous versions of script parameter syntaxes. See examples in inputs.conf.example.txt.
NOTE: It is highly recommended that all existing IPS device inputs be removed and re-added using the setup screen.
- Removed code that removes newlines from trigger packets. Now the trigger packet data will be recorded with the event, but in the original multi-line format.
- Summary event eventid field now set to id of original event. Added summary_alert field for summary events. This allows original alerts and summary alerts to be easily joined in Splunk as a transaction.

1.1.1 (2012-06-29)
- Added an additional field passed to get_ips_feed.py that causes the script to wait a specified ammount of time (in seconds) in between polls of the IPS. If the value is not passed, it will default to 15 seconds (for backwards compatibility). If a value of 0 is specified, it will poll continuously (like previous versions).
- Changed date/time stamp in the alert to be a human-readable format. Alert time from the IPS is sent as "time in nanoseconds from 1970-01-01T00:00:00Z". So, the time showed as a large integer such as 1339900639985884000. Changed to to display as YYYY-MM- DD HH:MM:SS instead.

1.1.0 (2012-05-29)
- Made MARS Category field optional. If IPS provides it, it will be included, if not, it won't. Resolves bug where Splunk for Cisco IPS app crashes on IPS version 7.x.
- Removed redundant protocol entry in output
- Added context field that will be present if IPS device provides it. This is common if running the IPS in a multi-context ASA.
- Changed packet data to remove new-line characters so it will all fit on one line instead of being spread out over many lines. And included the packet data into one big event instead of a separate one.
- Removed isDropped field. Not necessary any more, see next item.
- Added the following values that will be present if the following actions were taken.
	ipLoggingActivated
	shunRequested
	droppedPacket
	deniedAttacker
	blockConnectionRequested
	logAttackerPacketsActivated
	logVictimPacketsActivated
	logPairPacketsActivated
	snmpTrapRequested
	deniedAttackerServicePair
	deniedAttackerVictimPair
- Added actions field that will contain a comma separated list of all actions taken from list above
- Added summary_count and initial_alert for summary alerts.

1.0.4 (2012-02-14)
- Minor bugs fixed in get_ips_feed.py and idsmxml.py.

1.0.3 (2012-02-06)
- Resolved an issue with MarsCategory field by removing it.

1.0.2 (2011-05-22)
Resolved the following issues:
- Cisco IPS get_ips_feed.py script fails on Windows when package extracted using Winzip (SOLN-949)
- Cisco IPS setup fails to configure scripted inputs with appropriate OS path separators (SOLN-925)

1.0.1 (2011-03-22)
- Resolved critical issue (SOLN-829) where Cisco IPS scripts referred to incorrect folder name.

1.0.0 (2011-02-23)
- Add-on officially supported by Splunk, Inc.
- Updated to provide compatibility with Splunk 4.2
- Updated to provide compatibility with Enterprise Security Suite and other solutions that conform to the Common Information Model
- Added a new setup to provide automated configuration of the scripted input for each IPS sensor

##### Technology Add-on Details ######

Sourcetype(s):				cisco_ips
Supported Technologies:		Cisco IPS sensors that use the SDEE data format	
Compatible Solutions:		Cisco Security Suite
							Enterprise Security Suite

###### Installation Instructions ######

The Cisco IPS add-on can be downloaded, installed, and a connection made to your Cisco IPS sensor(s) by either using the Splunk app setup screen or by manually installing and configuring the add-on.  Instructions for both methods are described.

+++ Automated setup using the add-on setup +++

The automated setup is designed to walk you through the configuration of the Cisco IPS add-on once the add-on is installed on your Splunk deployment.  The setup screen can be accessed in one of the following ways:

1. Click the "Setup" button on the add-on from within the Splunk Home page.
2. Click the Welcome > Add data > Cisco device logs
3. Click Manager > Apps > Cisco IPS > "Set up" 

The setup of the app will require the IP Address or hostname of the sensor you wish to configure and the username/password that will be used to connect to the sensor and pull the data.  You also have an option to specify a local file source input for the data.  Once the desired configuration options are selected, click the "Save" button.  The setup program will create and/or update the inputs.conf file to include the desired input configuration.

+++ Manual setup and configuration +++

1. Open the inputs.conf file located at $SPLUNK_HOME/etc/apps/Splunk_CiscoIPS/local/inputs.conf
2. Modify the inputs.conf file to include the following stanza for each IPS sensor that needs to be configured

[script://$SPLUNK_HOME/etc/apps/Splunk_CiscoIPS/bin/get_ips_feed.py  <user> <pass> <sensor_ip>]
sourcetype = cisco_ips_syslog
source = SDEE
disabled = false
interval = 1

3. Save the changes made to the inputs.conf file.

Splunk requires a restart before the scripted input will take effect.  

This add-on has been renamed from previous versions (namely "_addon" has been removed).  Optionally you may choose to manually remove the "cisco_ips_addon" add-on from the file system.  If any changes exist in local they will need to be manually migrated over to this add-on.

###### Troubleshooting the add-on ######

The scripted input creates a sensor_ip.run file in the $SPLUNK_HOME/etc/apps/Splunk_CiscoIPS/var/run directory.  This file is updated each time Splunk attempts to connect to a sensor.  If you are having issues connecting to a sensor or you are not seeing IPS data in Splunk, use the following search to see if any data has been collected:

	index="_internal" sourcetype="sdee_connection"

The real time and overview dashboards and other searches and reports in this add-on rely on the search - eventtype=cisco_ips - to report on Cisco IPS data.

###### Using summary indexing with the Cisco IPS add-on ######

+++ Enabling summary indexing for this add-on +++

The Cisco IPS add-on includes a single scheduled search.  This search will run automatically every 6 hours and will create a summary stash each time it runs.  Customers that have an enterprise license can use this summary index feature, but it must be enabled.  To enable summary index reporting on your dashboard, create the following stanza in the $SPLUNK_HOME/etc/apps/Splunk_CiscoIPS/local/macros.conf file:

[cisco_ips]
definition = index=summary marker=cisco_ips

+++ Changing the default schedule +++

To change the schedule for the scheduled search that is used to generate the summary index, find the "Cisco IPS - DataCube - Summary Index" from within Manager > Searches and Reports.

###### Getting Help ######

* Additional information regarding the installation and configuration of the Cisco IPS add-on can be found here:
http://answers.splunk.com/questions/3364/how-do-i-install-the-cisco-ips-add-on

* See Splunk Answers to view existing questions and answers regarding the Cisco IPS add-on or to ask a question yourself:
http://answers.splunk.com/questions/tagged/app-ciscoips-splunk

* Alternatively, contact Splunk technical support: support@splunk.com
