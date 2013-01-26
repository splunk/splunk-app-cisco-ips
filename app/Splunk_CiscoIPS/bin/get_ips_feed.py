import sys
import os
import time
import base64
import binascii
import traceback
import ConfigParser
import splunk.entity as entity
from SplunkLogger import SplunkLogger
from pysdee.pySDEE import SDEE
from pysdee import idsmxml

APPNAME        = 'Splunk_CiscoIPS'
SPLUNK_LOG_DIR = os.path.join(os.environ['SPLUNK_HOME'], 'var', 'log', 'splunk')
APP_DIR        = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APPNAME)
RUN_DIR        = os.path.join(APP_DIR, 'var', 'run')
LOG_DIR        = os.path.join(APP_DIR, 'var', 'log')
DEBUG_DIR      = os.path.join(APP_DIR, 'var', 'debug')
SDEE_OUTFILE   = os.path.join(SPLUNK_LOG_DIR, 'sdee_get.log')
IPS_OUTFILE    = os.path.join(LOG_DIR, 'ips_sdee.log')
CONFIG_FILE    = os.path.join(APP_DIR, 'default', 'config.ini')

# Read config file
Config = ConfigParser.ConfigParser()
Config.read(CONFIG_FILE)
MAX_BYTES    = Config.getint('logging', 'maxBytes')
BACKUP_COUNT = Config.getint('logging', 'backupCount')

connection_log = open(SDEE_OUTFILE, 'a')

# Function used to log SDEE Connection messages
def logger(string):
	connection_log.write(time.asctime() + ' - ' + string + "\n")
	connection_log.flush()
	return 0

# Function to decode base64 data
def decode(data):
	try:
		decode = base64.b64decode(data)
		return binascii.b2a_qp(decode)
	except:
		return "-"

# Function to access the saved credentials
def getIPSCredentials(sessionKey,host):
	try:
		entities = entity.getEntities(['storage', 'passwords'], namespace=APPNAME, owner='nobody', sessionKey=sessionKey)
	except:
		exception = traceback.format_exc().splitlines()[-1]
		logger('Could not get IPS ' + host + ' credentials from splunk: ' + exception)
		time.sleep(300)
		sys.exit()

	for i, c in entities.items():
		if c['realm'] == host:
			return c['username'], c['clear_password']
	
	logger('No credentials for IPS ' + host + ' were found!')
	time.sleep(300)
	sys.exit()

# Main Function
def run(user, password, host, sleep, method, force):
	ipsLogger = SplunkLogger(IPS_OUTFILE + '.' + host, MAX_BYTES, BACKUP_COUNT)
	
	if os.path.exists(os.path.join(RUN_DIR, host + '.run')):
		logger("INFO - Checking for exsisting SubscriptionID on host: "+host)
		SUBID = open(os.path.join(RUN_DIR, host + '.run'), 'r').read()
		if len(SUBID) < 3:
			SUBID = 'NULL'
			logger("INFO - No exsisting SubscriptionID for host: "+host)
		else:
			logger("INFO - SubscriptionID: "+SUBID+" found for host: "+host)
	else:
		open(os.path.join(RUN_DIR, host + '.run'), 'w').close()
		logger("INFO - No exsisting SubscriptionID for host: "+host)
		SUBID = 'NULL'

	try:
		logger("INFO - Attempting to connect to sensor: " + host)
		sdee = SDEE(user=user,password=password,host=host,method=method,force=force)
		logger("INFO - Successfully connected to: "+host)
		if SUBID != "NULL":
			sdee._subscriptionid = SUBID
		else:
			sdee.open()
			logger("INFO - Successfully connected to: "+host)
			logger('INFO - host="'+host+'" SessionID="'+ sdee._sessionid + '" SubscriptionID="'+sdee._subscriptionid+'"')
		open(os.path.join(RUN_DIR, host + '.run'), 'w').writelines(sdee._subscriptionid)
	except:
		exception = traceback.format_exc().splitlines()[-1]
		logger('ERROR - Connecting to sensor - '+host+': '+exception)
		time.sleep(300)
		sys.exit()		

	while 1:
		# Sleep for a bit so we don't overwhelm the IPS
		if sleep != 0:
			time.sleep(float(sleep))
		#logger('DEBUG - Connecting to sensor: '+host)
		#print('DEBUG - Connecting to sensor: '+host)
		try:
			sdee.get()
		except:
			exception = traceback.format_exc().splitlines()[-1]
			logger('ERROR - Exception thrown in sdee.get(): '+exception)
			logger('ERROR - Attempting to re-connect to the sensor: '+host)
			sdee._subscriptionid = ""
			sdee.open()
			logger("INFO - Successfully connected to: "+host)
			logger('INFO - host="'+host+'" SessionID="'+ sdee._sessionid + '" SubscriptionID="'+sdee._subscriptionid+'"')
			open(os.path.join(RUN_DIR, host + '.run'), 'w').writelines(sdee._subscriptionid)
			continue;
		try:
			result_xml = sdee.data() 
			alert_obj_list = idsmxml.parse_alerts( result_xml )
		except:
			ts = str(time.time())
			exception = traceback.format_exc()
			logger("ERROR - Exception thrown while parsing SDEE payload: " + exception)

## Un Comment for easy debug of raw xml feeds. 
#		ts = str(time.time())
#		open(os.path.join(DEBUG_DIR,host+"_"+ts+".xml"),'w').write(result_xml)
#		print result_xml
##########
		for alerts in alert_obj_list:
			target_list = []
			alert_dict = {}
			for target in alerts.target_list:
				target_list.append((target.addr,target.port,target.locality))
			
			alert_dict["target_list"] = target_list

			if alerts.globalCorrelationScore != "NULL":
				alert_dict["gc_score"] =  alerts.globalCorrelationScore
				alert_dict["gc_riskdelta"] =  alerts.globalCorrelationRiskDelta 
				alert_dict["gc_riskrating"] = alerts.globalCorrelationModifiedRiskRating
				alert_dict["gc_deny_packet"] = alerts.globalCorrelationDenyPacket
				alert_dict["gc_deny_attacker"] = alerts.globalCorrelationDenyAttacker
			else:
				alert_dict["gc_score"] = "NULL"
			
			alert_dict["alert_time"] = alerts.alert_time
			alert_dict["eventid"]=alerts.eventid
			alert_dict["hostId"]=alerts.originator
			alert_dict["severity"]=alerts.severity
			alert_dict["app_name"] = alerts.appname
			
			alert_dict["appInstanceId"] = alerts.appInstanceId
			alert_dict["signature"]=alerts.signature.sigid
			alert_dict["subSigid"]=alerts.signature.subsig
			alert_dict["description"]=alerts.signature.sigdetail
			alert_dict["sig_version"]=alerts.signature.sigversion
			alert_dict["sig_created"] = alerts.signature.sigcreated
			alert_dict["sig_type"] = alerts.signature.sigtype
	
			alert_dict["mars_category"]=alerts.signature.marsCategory
			alert_dict["attacker"]=alerts.attacker.addr
			alert_dict["attacker_locality"]=alerts.attacker.locality
			alert_dict["attacker_port"]=str(alerts.attacker.port)
			alert_dict["protocol"]=alerts.protocol
			alert_dict["risk_rating"]=str(alerts.riskrating)
			alert_dict["threat_rating"]=str(alerts.threatrating)
			alert_dict["target_value_rating"]= str(alerts.targetvaluerating)
			
			alert_dict["attack_relevance_rating"] =  str(alerts.attackrelevancerating)
			alert_dict["vlan"]= alerts.vlan
			alert_dict["interface"]= alerts.interface
			alert_dict["interface_group"] = alerts.intgroup

			alert_dict["context"] = alerts.context
			alert_dict["actions"] = alerts.actions
			alert_dict["ipLoggingActivated"] = alerts.ipLoggingActivated
			alert_dict["shunRequested"] = alerts.shunRequested
			alert_dict["droppedPacket"] = alerts.droppedPacket
			alert_dict["deniedAttacker"] = alerts.deniedAttacker
			alert_dict["blockConnectionRequested"] = alerts.blockConnectionRequested
			alert_dict["logAttackerPacketsActivated"] = alerts.logAttackerPacketsActivated
			alert_dict["logVictimPacketsActivated"] = alerts.logVictimPacketsActivated
			alert_dict["logPairPacketsActivated"] = alerts.logPairPacketsActivated
			alert_dict["snmpTrapRequested"] = alerts.snmpTrapRequested
			alert_dict["deniedAttackerServicePair"] = alerts.deniedAttackerServicePair
			alert_dict["deniedAttackerVictimPair"] = alerts.deniedAttackerVictimPair
			alert_dict["summaryCount"] = alerts.summaryCount
			alert_dict["initialAlert"] = alerts.initialAlert

			target_list_string = ""
			packet_info = ""
			try:
				if alerts.triggerpacket!="NULL":
					trigger_packet_details = decode(alerts.triggerpacket)
					packet_info = ' trigger_packet="'+alerts.triggerpacket+'" trigger_packet_details="'+trigger_packet_details+'"'
				if alerts.fromtarget!="NULL":
					fromTarget_details = decode(alerts.fromtarget)
					packet_info = packet_info +  ' fromTarget="'+alerts.fromtarget+'" fromTarget_details="'+fromTarget_details+'"'
				if alerts.fromattacker!="NULL":
					fromAttacker_details = decode(alerts.fromattacker)
					packet_info = packet_info +  ' fromAttacker="'+alerts.fromattacker+'" fromAttacker_details="'+fromAttacker_details+'"'
			except:
				ts = str(time.time())
				exception = traceback.format_exc()
				logger("ERROR -  exception caught while getting trigger_packet")
				logger(exception)
			try:
				for target in alert_dict["target_list"]:
					target_list_string = target_list_string + ' target="'+target[0]+'" target_port="'+str(target[1])+'" target_locality="'+str(target[2])+'"'

				syslog_msg = alert_dict["alert_time"]

				if alert_dict["initialAlert"] != "NULL":
					syslog_msg = syslog_msg + ' eventid="' + alert_dict["initialAlert"]
				else:
					syslog_msg = syslog_msg + ' eventid="' + alert_dict["eventid"]

				syslog_msg = syslog_msg + '" hostId="' + alert_dict["hostId"] + '" sig_created="' + alert_dict["sig_created"] + \
					'" sig_type="' + alert_dict["sig_type"] + '" severity="' + alert_dict["severity"] + \
					'" app_name="' + alert_dict["app_name"] + '" appInstanceId="' + alert_dict["appInstanceId"] + \
					'" signature="' + alert_dict["signature"] + '" subSigid="' + alert_dict["subSigid"] + \
					'" description="' + alert_dict["description"] + '" sig_version="' + alert_dict["sig_version"] + \
					'" attacker="' + alert_dict["attacker"] + \
					'" attacker_port="' + alert_dict["attacker_port"] + '" attacker_locality="' + alert_dict["attacker_locality"] + \
					'"' + target_list_string + ' protocol="' + alert_dict["protocol"] + \
					'" attack_relevance_rating="' + alert_dict["attack_relevance_rating"] + \
					'" risk_rating="' + alert_dict["risk_rating"] + '" threat_rating="' + alert_dict["threat_rating"] + \
					'" target_value_rating="' + alert_dict["target_value_rating"] + '" interface="' + alert_dict["interface"] + \
					'" interface_group="' + alert_dict["interface_group"] + '" vlan="' + alert_dict["vlan"] + '"'

				if alert_dict["mars_category"] != "NULL":
					syslog_msg = syslog_msg +' mars_category="'+alert_dict["mars_category"]+'"'

				if alert_dict["context"] != "NULL":
					syslog_msg = syslog_msg +' context="'+alert_dict["context"]+'"'

				if alert_dict["actions"] != "NULL":
					syslog_msg = syslog_msg +' actions="'+alert_dict["actions"]+'"'
				if alert_dict["ipLoggingActivated"] != "NULL":
					syslog_msg = syslog_msg +' ipLoggingActivated="'+alert_dict["ipLoggingActivated"]+'"'
				if alert_dict["shunRequested"] != "NULL":
					syslog_msg = syslog_msg +' shunRequested="'+alert_dict["shunRequested"]+'"'
				if alert_dict["droppedPacket"] != "NULL":
					syslog_msg = syslog_msg +' droppedPacket="'+alert_dict["droppedPacket"]+'"'
				if alert_dict["deniedAttacker"] != "NULL":
					syslog_msg = syslog_msg +' deniedAttacker="'+alert_dict["deniedAttacker"]+'"'
				if alert_dict["blockConnectionRequested"] != "NULL":
					syslog_msg = syslog_msg +' blockConnectionRequested="'+alert_dict["blockConnectionRequested"]+'"'
				if alert_dict["logAttackerPacketsActivated"] != "NULL":
					syslog_msg = syslog_msg +' logAttackerPacketsActivated="'+alert_dict["logAttackerPacketsActivated"]+'"'
				if alert_dict["logVictimPacketsActivated"] != "NULL":
					syslog_msg = syslog_msg +' logVictimPacketsActivated="'+alert_dict["logVictimPacketsActivated"]+'"'
				if alert_dict["logPairPacketsActivated"] != "NULL":
					syslog_msg = syslog_msg +' logPairPacketsActivated="'+alert_dict["logPairPacketsActivated"]+'"'
				if alert_dict["snmpTrapRequested"] != "NULL":
					syslog_msg = syslog_msg +' snmpTrapRequested="'+alert_dict["snmpTrapRequested"]+'"'
				if alert_dict["deniedAttackerServicePair"] != "NULL":
					syslog_msg = syslog_msg +' deniedAttackerServicePair="'+alert_dict["deniedAttackerServicePair"]+'"'
				if alert_dict["deniedAttackerVictimPair"] != "NULL":
					syslog_msg = syslog_msg +' deniedAttackerVictimPair="'+alert_dict["deniedAttackerVictimPair"]+'"'

				if alert_dict["summaryCount"] != "NULL":
					syslog_msg = syslog_msg +' summary_count="'+alert_dict["summaryCount"]+'"'
				if alert_dict["initialAlert"] != "NULL":
					syslog_msg = syslog_msg +' summary_eventid="'+alert_dict["eventid"]+'"'

				if alert_dict["gc_score"] != "NULL":
					syslog_msg = syslog_msg +' gc_score="'+alert_dict["gc_score"]+  '" gc_riskdelta="'+ alert_dict["gc_riskdelta"] + '" gc_riskrating="'+alert_dict["gc_riskrating"]+'" gc_deny_packet="'+alert_dict["gc_deny_packet"]+'" gc_deny_attacker="'+alert_dict["gc_deny_attacker"]+'"'
				if len(packet_info)>150:
#					packet_info = packet_info.replace("\r\n", " ")
#					packet_info = packet_info.replace("\n", " ")
					syslog_msg = syslog_msg + packet_info

			except:
				ts = str(time.time())
				exception = traceback.format_exc()
				logger("ERROR -  exception caught while writing event")
				logger(exception)

			ipsLogger.info(syslog_msg)

	### Commen/Uncomment to write to stdout
	#		print syslog_msg +"\n"


# BEGIN #
if (len(sys.argv) == 5): # get_ips_feed.py USERNAME PASSWORD HOST INTERVAL
	#print "Found 4 command-line arguments. Assuming version 1.1.1 style syntax."
	#print "Executing: run("+sys.argv[1]+","+sys.argv[2]+","+sys.argv[3]+","+sys.argv[4]+",https,yes)"
	run(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],"https","yes")
elif (len(sys.argv) == 4): # get_ips_feed.py USERNAME PASSWORD HOST
	#print "Found 3 command-line arguments. Assuming version 1.0.x style syntax."
	#print "Executing: run("+sys.argv[1]+","+sys.argv[2]+","+sys.argv[3]+",15,https,yes)"
	run(sys.argv[1],sys.argv[2],sys.argv[3],"15","https","yes")
elif (len(sys.argv) == 3): # get_ips_feed.py HOST INTERVAL
	#print "Found 2 command-line arguments. Assuming version 2.0.0+ style syntax."
	sessionKey = sys.stdin.readline().strip()
	if len(sessionKey) == 0:
		logger('Did not receive a session key from splunkd. Please enable passAuth in inputs.conf for this script.')
		time.sleep(300)
		sys.exit()
	username, password = getIPSCredentials(sessionKey,sys.argv[1])
	#print "Executing: run("+username+","+password+","+sys.argv[1]+","+sys.argv[2]+",https,yes)"
	run(username,password,sys.argv[1],sys.argv[2],"https","yes")
else:
	#print "ERROR - Invalid command-line arguments"
	logger('ERROR - Invalid command-line arguments')
	time.sleep(300)
	sys.exit()