Copyright (C) 2005-2012 Splunk Inc. All Rights Reserved.

Add-on:			Splunk for Cisco IPS
Current Version:	2.0
Last Modified:		2012-04-01
Splunk Version:		4.3 and higher
Author:			Splunk

The Splunk for Cisco IPS SDEE add-on allows you to consume, analyze, and report on Cisco IPS data that conforms to the Security Device Event Exchange (SDEE) standard. This add-on includes a scripted input to bring your IPS data into Splunk and knowledge objects (source type definition, field extractions, event types, and tags) to help you view and interpret that data. The Cisco IPS add-on is designed to work with the Splunk Cisco Security Suite; install these together to access reports and dashboards that give you visual insight into your Cisco IPS data.

##### What's New #####
2.0 (2012-04-01)
- Major updaate to the app.
- Completely change the look and feel of the app.
- Refactor the code base.

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

Sourcetype(s):			cisco_ips
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

1. Open the config.ini file located at $SPLUNK_HOME/etc/apps/Splunk_CiscoIPS/default/config.ini
2. Modify the config.ini file to include a username, a password and an IP address or hostname of IPS sensor that needs to be configured:

[login]
host = ip_or_hostname_of_cisco_ips
username = your_username
password = your_password

3. Save the changes made to the config.ini file.

Splunk requires a restart before the new settings and the scripted input will take effect.

This add-on has been renamed from previous versions (namely "_addon" has been removed).  Optionally you may choose to manually remove the "cisco_ips_addon" add-on from the file system.  If any changes exist in local they will need to be manually migrated over to this add-on.

###### Troubleshooting the add-on ######

The scripted input creates a sensor_ip.run file in the $SPLUNK_HOME/var/run/Splunk_CiscoIPS/ directory.  This file is updated each time Splunk attempts to connect to a sensor.  If you are having issues connecting to a sensor or you are not seeing IPS data in Splunk, use the following search to see if any data has been collected:

	index="_internal" sourcetype="sdee_connection"

The real time and overview dashboards and other searches and reports in this add-on rely on the search - eventtype=cisco_ips - to report on Cisco IPS data.

###### Using summary indexing with the Cisco IPS add-on ######

+++ Changing the default schedule +++

To change the schedule for the scheduled search that is used to generate the summary index, find the "Cisco IPS - DataCube - Summary Index" from within Manager > Searches and Reports.

###### Getting Help ######

* Additional information regarding the installation and configuration of the Cisco IPS add-on can be found here:
http://splunk-base.splunk.com/answers/3364/how-do-i-install-the-cisco-ips-add-on

* See Splunk Answers to view existing questions and answers regarding the Cisco IPS add-on or to ask a question yourself:
http://splunk-base.splunk.com/search/?q=cisco+ips&Submit=search

* Alternatively, contact Splunk technical support: support@splunk.com
