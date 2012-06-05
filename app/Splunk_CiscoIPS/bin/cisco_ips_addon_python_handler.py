import splunk.entity as en
import splunk.admin as admin
import os.path
import re
import shutil

'''
Copyright (C) 2005-2011 Splunk Inc. All Rights Reserved.
'''

class ConfigCiscoIPSApp(admin.MConfigHandler):
	'''
	Set up supported arguments
	'''
	def setup(self):
		if self.requestedAction == admin.ACTION_EDIT:
			for arg in ['cisco_ips_sensor_enable','cisco_ips_sensor_ip','cisco_ips_sensor_username','cisco_ips_sensor_password','cisco_ips_file','cisco_ips_file_enable']:
				self.supportedArgs.addOptArg(arg)
				
	'''
	Lists configurable parameters
	'''
	def handleList(self, confInfo):
		confDict = self.readConf("cisco_ips_addon")
		if None != confDict:
			for stanza, settings in confDict.items():
				for key, val in settings.items():
					if key in ['cisco_ips_sensor_ip','cisco_ips_sensor_username','cisco_ips_sensor_password','cisco_ips_file'] and val == None:
						val = ''
					confInfo[stanza].append(key, val)


	''' 
	flip the bit
 	'''
	def invert(self, value):
		if value == 0:
			return 1
		else:
			return 0

					
	'''
	Controls parameters
	'''
	def handleEdit(self, confInfo):
		name = self.callerArgs.id
		args = self.callerArgs

		# INIT Input fields to empty string instead of null
		if self.callerArgs.data['cisco_ips_file'][0] == None:
			self.callerArgs.data['cisco_ips_file'][0] = ''

		if self.callerArgs.data['cisco_ips_sensor_ip'][0] == None:
			self.callerArgs.data['cisco_ips_sensor_ip'][0] = ''	

		if self.callerArgs.data['cisco_ips_sensor_username'][0] == None:
			self.callerArgs.data['cisco_ips_sensor_username'][0] = ''	

		if self.callerArgs.data['cisco_ips_sensor_password'][0] == None:
			self.callerArgs.data['cisco_ips_sensor_password'][0] = ''	


		numericAddressRegex = re.compile("^[0-9\.]*$")
		thisNumericAddress = re.search(numericAddressRegex, self.callerArgs.data['cisco_ips_sensor_ip'][0])

		validIpAddressRegex = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
		thisIpAddress = re.search(validIpAddressRegex, self.callerArgs.data['cisco_ips_sensor_ip'][0])
		
		validHostnameRegex = re.compile("^(([a-zA-Z0-9\-\_]+)\.)*([A-Za-z0-9\-\_]+)$")
		thisHostname = re.search(validHostnameRegex, self.callerArgs.data['cisco_ips_sensor_ip'][0])
		
		invalidUsernameRegex = re.compile("\s+")
		thisInvalidUsername = re.search(invalidUsernameRegex, self.callerArgs.data['cisco_ips_sensor_username'][0])

		# INPUT VALIDATION
		# 	Scripted input is enabled, IP validation criteria 
		if (int(self.callerArgs.data['cisco_ips_sensor_enable'][0]) == 1 and thisNumericAddress):
			if (thisIpAddress in [None, '']):
				raise admin.ArgValidationException, "CISCO_IPS_SDEE-SETUP-INPUT_ERROR-100: Invalid IP address specified for IPS device"

		# 	Scripted input is enabled, hostname fails validation criteria 
		if (int(self.callerArgs.data['cisco_ips_sensor_enable'][0]) == 1 and (thisHostname in [None, ''])):
			raise admin.ArgValidationException, "CISCO_IPS_SDEE-SETUP-INPUT_ERROR-101: Invalid hostname specified for IPS device"

		#	Scripted input is enabled, username fails validation criteria, cannot contain whitespace
		if (int(self.callerArgs.data['cisco_ips_sensor_enable'][0]) == 1 and (not thisInvalidUsername == None)):
			raise admin.ArgValidationException, "CISCO_IPS_SDEE-SETUP-INPUT_ERROR-102: Invalid username specified for IPS device, username cannot contain whitespace"

		# Scripted Input NOT checked, hostname inputs exists
		if (int(self.callerArgs.data['cisco_ips_sensor_enable'][0]) == 0 and str(self.callerArgs.data['cisco_ips_sensor_ip'][0]) != ''):
			raise admin.ArgValidationException, "CISCO_IPS_SDEE-SETUP-INPUT_ERROR-103: To add a scripted input, supply hostname/username/password and check 'Create scripted input'"

		# Scripted Input checked, hostname inputs does NOT exist
		if (int(self.callerArgs.data['cisco_ips_sensor_enable'][0]) == 1 and str(self.callerArgs.data['cisco_ips_sensor_ip'][0]) == ''):
			raise admin.ArgValidationException, "CISCO_IPS_SDEE-SETUP-INPUT_ERROR-104: To add a scripted input, supply hostname/username/password and check 'Create scripted input'"

		# File monitor checked, invalid file path specified
		if (int(self.callerArgs.data['cisco_ips_file_enable'][0]) == 1 and self.callerArgs.data['cisco_ips_file'][0] in [None, '']):
			raise admin.ArgValidationException, "CISCO_IPS_SDEE-SETUP-INPUT_ERROR-105: To enable File Monitor, you must specify a valid file path"

		# File monitor checked, file path does not exist
		if (int(self.callerArgs.data['cisco_ips_file_enable'][0]) == 1 and not os.path.exists(self.callerArgs.data['cisco_ips_file'][0])):
			raise admin.ArgValidationException, "CISCO_IPS_SDEE-SETUP-INPUT_ERROR-106: The specified file path does not exist"

		# File monitor NOT checked, file path exists
		if (int(self.callerArgs.data['cisco_ips_file_enable'][0]) == 0 and str(self.callerArgs.data['cisco_ips_file'][0]) != ''):
			raise admin.ArgValidationException, "CISCO_IPS_SDEE-SETUP-INPUT_ERROR-107: To enable File Monitor, supply a file location and check 'Create local file monitor'"
		
		'''
		Since we are using a conf file to store parameters, write them to the [setupentity] stanza
		in <appname>/local/myappsetup.conf  
		'''

		# fix6: don't invert enable, use inverting function instead
		if int(self.callerArgs.data['cisco_ips_sensor_enable'][0]) == 1:
			scriptStanzaItems = {"index":"main", "sourcetype":"cisco_ips_syslog", "disabled":self.invert(int(self.callerArgs.data['cisco_ips_sensor_enable'][0])), "interval":"1", "source":"SDEE"}
			scriptPath = os.path.join("$SPLUNK_HOME","etc","apps","Splunk_CiscoIPS","bin","get_ips_feed.py")
			self.writeConf('inputs', 'script://' + scriptPath + ' "' + str(self.callerArgs.data['cisco_ips_sensor_username'][0]) + '" "' + str(self.callerArgs.data['cisco_ips_sensor_password'][0]) + '" "' + str(self.callerArgs.data['cisco_ips_sensor_ip'][0]) + '"', scriptStanzaItems)

		
		if int(self.callerArgs.data['cisco_ips_file_enable'][0]) == 1:
			fileStanzaItems = {"index":"main", "sourcetype":"cisco_ips_syslog", "disabled":self.invert(int(self.callerArgs.data['cisco_ips_file_enable'][0]))}		
			self.writeConf('inputs', 'monitor://' + str(self.callerArgs.data['cisco_ips_file'][0]), fileStanzaItems)
		
		# Refresh Splunk for Cisco Security App, otherwise the IPS Overview dashboard will not display under the IPS navigation from main Cisco app
		sk = self.getSessionKey()
		en.getEntities('apps/local/Splunk_CiscoSecuritySuite/_reload', sessionKey = sk)

# initialize the handler
admin.init(ConfigCiscoIPSApp, admin.CONTEXT_NONE)
