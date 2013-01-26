import splunk.entity as entity
import splunk.admin as admin
import re

APPNAME = 'Splunk_CiscoIPS'

def is_valid_ip(ip):
	return is_valid_ipv4(ip) or is_valid_ipv6(ip)

def is_valid_ipv4(ip):
	pattern = re.compile(r"""
			^
			(?:
				# Dotted variants:
				(?:
					# Decimal 1-255 (no leading 0's)
					[3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
				|
					0x0*[0-9a-f]{1,2}	# Hexadecimal 0x0 - 0xFF (possible leading 0's)
				|
					0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
				)
				(?:									# Repeat 0-3 times, separated by a dot
					\.
					(?:
						[3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
					|
						0x0*[0-9a-f]{1,2}
					|
						0+[1-3]?[0-7]{0,2}
					)
				){0,3}
			|
				0x0*[0-9a-f]{1,8}		# Hexadecimal notation, 0x0 - 0xffffffff
			|
				0+[0-3]?[0-7]{0,10}	# Octal notation, 0 - 037777777777
			|
				# Decimal notation, 1-4294967295:
				429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
				42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
				4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
			)
			$
	""", re.VERBOSE | re.IGNORECASE)
	return pattern.match(ip) is not None

def is_valid_ipv6(ip):
	pattern = re.compile(r"""
			^
			\s*
			(?!.*::.*::)
			(?:(?!:)|:(?=:))
			(?:
					[0-9a-f]{0,4}
					(?:(?<=::)|(?<!::):)
			){6}
			(?:
					[0-9a-f]{0,4}
					(?:(?<=::)|(?<!::):)
					[0-9a-f]{0,4}
					(?: (?<=::)
					 |	(?<!:)
					 |	(?<=:) (?<!::) :
					 )
			 |
					(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
					(?: \.
							(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
					){3}
			)
			\s*
			$
	""", re.VERBOSE | re.IGNORECASE | re.DOTALL)
	return pattern.match(ip) is not None

class ConfigApp(admin.MConfigHandler):
	def setup(self):
		if self.requestedAction == admin.ACTION_EDIT:
			for arg in ['cisco_ips_sensor_ip','cisco_ips_sensor_username','cisco_ips_sensor_password','cisco_ips_sensor_interval']:
				self.supportedArgs.addOptArg(arg)

	def handleList(self, confInfo):
		confDict = self.readConf("cisco_ips_setup")
		if None != confDict:
			for stanza, settings in confDict.items():
				for key, val in settings.items():
					if key in ['cisco_ips_sensor_ip','cisco_ips_sensor_username','cisco_ips_sensor_password','cisco_ips_sensor_interval'] and val == None:
						val = ''
					confInfo[stanza].append(key, val)

	def handleEdit(self, confInfo):
		# INIT Input fields to empty string instead of null
		if self.callerArgs.data['cisco_ips_sensor_ip'][0] == None:
			sensor_ip = ''
		else:
			sensor_ip = self.callerArgs.data['cisco_ips_sensor_ip'][0]

		if self.callerArgs.data['cisco_ips_sensor_username'][0] == None:
			sensor_username = ''
		else:
			sensor_username = self.callerArgs.data['cisco_ips_sensor_username'][0]

		if self.callerArgs.data['cisco_ips_sensor_password'][0] == None:
			sensor_password = ''
		else:
			sensor_password = self.callerArgs.data['cisco_ips_sensor_password'][0]

		if self.callerArgs.data['cisco_ips_sensor_interval'][0] == None:
			sensor_interval = ''
		else:
			sensor_interval = self.callerArgs.data['cisco_ips_sensor_interval'][0]

		# INPUT VALIDATION
		# Hostname or IP Address: make sure it is a valid IPv4 or IPv6 address or a hostname
		validHostnameRegex = re.compile("^(([a-zA-Z0-9\-\_]+)\.)*([A-Za-z0-9\-\_]+)$")
		validHostname = re.search(validHostnameRegex, sensor_ip)
		if not (is_valid_ip(sensor_ip) or validHostname):
			raise admin.ArgValidationException, "CISCO_IPS_SETUP-INPUT_ERROR-xxx: Invalid Hostname or IP address specified for IPS device. Must be valid IPv4 or IPv6 or hostname."

		# Username: make sure it is a string with no spaces
		containsSpaceRegex = re.compile("\s+")
		invalidUsername = re.search(containsSpaceRegex, sensor_username)
		if invalidUsername or len(sensor_username) < 1:
			raise admin.ArgValidationException, "CISCO_IPS_SETUP-INPUT_ERROR-xxx: Invalid username specified for IPS device. Must be a string without spaces."

		# Password: make sure it is a string with no spaces
		invalidPassword = re.search(containsSpaceRegex, sensor_password)
		if invalidPassword or len(sensor_password) < 1:
			raise admin.ArgValidationException, "CISCO_IPS_SETUP-INPUT_ERROR-xxx: Invalid password specified for IPS device. Must be a string without spaces."

		# Polling Interval: make sure it is a number between 0 and 3600
		if not (sensor_interval.isdigit() and int(sensor_interval) >= 0 and int(sensor_interval) <= 3600):
			raise admin.ArgValidationException, "CISCO_IPS_SETUP-INPUT_ERROR-xxx: Invalid Poling Interval entered. Must be an number between 0 and 3600 seconds."


		# Get session key so we can talk to REST API
		sessionKey = self.getSessionKey()

		# Check to make sure Cisco IPS Sensor script does not already exist in inputs.conf via REST API
		try:
			entities = entity.getEntities('data/inputs/script', search="\" " + sensor_ip + " \"", sessionKey=sessionKey)
		except:
			raise admin.ArgValidationException, "Failed to search for existing Cisco IPS Sensor script in inputs.conf!"
		if len(entities.items()) != 0:
			raise admin.ArgValidationException, "Cisco IPS Sensor script for " + sensor_ip + " already exists in inputs.conf. Remove it, restart Splunk, and try again."

		# Check to make sure Cisco IPS Sensor cedential does not already exist in app.conf via REST API
		try:
			entities = entity.getEntities('storage/passwords', search="realm=\"" + sensor_ip + "\"", sessionKey=sessionKey)
		except:
			raise admin.ArgValidationException, "Failed to search for existing Cisco IPS Sensor credential in app.conf!"
		if len(entities.items()) != 0:
			raise admin.ArgValidationException, "Cisco IPS Sensor credential for " + sensor_ip + " already exists in app.conf. Remove it, restart Splunk, and try again."

		# Create Scripted Input in inputs.conf via REST API
		try:
			script = entity.getEntity('/data/inputs/script/','_new', sessionKey=sessionKey)
			script["interval"] = '1'
			script["name"] = os.path.join('$SPLUNK_HOME', 'etc', 'apps', 'Splunk_CiscoIPS','bin','get_ips_feed.py') + ' ' + sensor_ip + ' ' + sensor_interval
			script["passAuth"] = 'splunk-system-user'
			script["source"] = 'SDEE'
			script["sourcetype"] = 'cisco_ips_syslog'
			script.namespace = APPNAME
			entity.setEntity(script, sessionKey=sessionKey)
		except:
			raise admin.ArgValidationException, "Failed to create scripted input!"

		# Create Encrypted Credential in app.conf via REST API
		try:
			creds = entity.getEntity('/storage/passwords/','_new', sessionKey=sessionKey)
			creds["name"] = sensor_username
			creds["password"] = sensor_password
			creds["realm"] = sensor_ip
			creds.namespace = APPNAME
			entity.setEntity(creds, sessionKey=sessionKey)
		except:
			raise admin.ArgValidationException, "Failed to create credential!"




admin.init(ConfigApp, admin.CONTEXT_NONE)