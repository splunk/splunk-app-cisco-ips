import sys
import os
import time
import base64
import binascii
import traceback
import ConfigParser

from SplunkLogger import SplunkLogger
from pysdee.pySDEE import SDEE
from pysdee import idsmxml

#APPNAME        = 'Splunk_CiscoIPS'
#SPLUNK_LOG_DIR = os.path.join(os.environ['SPLUNK_HOME'], 'var', 'log', 'splunk')
#APP_DIR        = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APPNAME)
#RUN_DIR        = os.path.join(APP_DIR, 'var', 'run')
#LOG_DIR        = os.path.join(APP_DIR, 'var', 'log')
#SDEE_OUTFILE   = os.path.join(SPLUNK_LOG_DIR, 'sdee_get.log')
#IPS_OUTFILE    = os.path.join(LOG_DIR, 'ips_sdee.log')
#CONFIG_FILE    = os.path.join(APP_DIR, 'default', 'config.ini')

SPLUNK_LOG_DIR = os.path.join(os.environ['SPLUNK_HOME'], 'var', 'log')
APP_DIR = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..'))
APPNAME = os.path.basename(APP_DIR)
# This is where the .run files with the subscription ID is held.
RUN_DIR = os.path.join(os.environ['SPLUNK_HOME'], 'var', 'run', APPNAME)
# This is where the SDEE events will be written.
LOG_DIR = os.path.join(SPLUNK_LOG_DIR, APPNAME)
# Connection log file
SDEE_OUTFILE = os.path.join(SPLUNK_LOG_DIR, 'splunk', 'sdee_get.log')
# SDEE events file
IPS_OUTFILE = os.path.join(LOG_DIR, 'ips_sdee.log')
CONFIG_FILE = os.path.join(APP_DIR, 'default', 'config.ini')

# Read config file
Config = ConfigParser.ConfigParser()
Config.read(CONFIG_FILE)
# Get Cisco IPS hostname or ip
HOST = Config.get('login', 'host')
USERNAME = Config.get('login', 'username')
PASSWORD = Config.get('login', 'password')
# Get polling settings
POLLING_INTERVAL = Config.getint('polling', 'interval')
POLLING_METHOD = Config.get('polling', 'method')
POLLING_IS_FORCE = Config.get('polling', 'is_force')
# Get log rotation settings
MAX_BYTES = Config.getint('logging', 'maxBytes')
BACKUP_COUNT = Config.getint('logging', 'backupCount')

sdeeLogger = SplunkLogger(SDEE_OUTFILE, MAX_BYTES, BACKUP_COUNT, 'connection_log')

# Make sure our run and log directories exist:
try:
	if not os.path.exists(RUN_DIR):
		os.makedirs(RUN_DIR)
	if not os.path.exists(LOG_DIR):
		os.makedirs(LOG_DIR)
except:
	e = traceback.format_exc().splitlines()[-1]
	sdeeLogger.error("Unable to create log/run director: %s" % e)
	sys.exit()

def decode(data):
	try:
		decode = base64.b64decode(data)
		return binascii.b2a_qp(decode)
	except:
		return "-"

# Fix to add a true interval polling (don't just poll them continously)
#def run(user, password, host, method, force):
def run(user='', password='', host='', interval=10, method="https", force="yes"):
	ipsLogger = SplunkLogger(IPS_OUTFILE + '.' + host, MAX_BYTES, BACKUP_COUNT, 'sdee_events')
	
	if os.path.exists(os.path.join(RUN_DIR, host + '.run')):
		sdeeLogger.info("Checking for exsisting SubscriptionID on host: %s" % host)
		SUBID = open(os.path.join(RUN_DIR, host + '.run'), 'r').read()
		if len(SUBID) < 3:
			SUBID = "NULL"
			sdeeLogger.info("No exsisting SubscriptionID for host: %s" % host)
		else:
			sdeeLogger.info("SubscriptionID: %s found for host: %s" % (SUBID, host))
	else:
		open(os.path.join(RUN_DIR, host + '.run'), 'w').close()
		sdeeLogger.info("No exsisting SubscriptionID for host: %s" % host)
		SUBID = "NULL"

	try:
		sdeeLogger.info("Attempting to connect to sensor: %s" % host)
		sdee = SDEE(user=user,password=password,host=host,method=method,force=force)
		sdeeLogger.info("Successfully connected to: %s" % host)
		if SUBID != "NULL":
			sdee._subscriptionid = SUBID
		else:
			sdee.open()
			sdeeLogger.info("Successfully connected to: %s" % host)
			sdeeLogger.info('host="%s" SessionID="%s" SubscriptionID="%s"' % (host, sdee._sessionid, sdee._subscriptionid))
		open(os.path.join(RUN_DIR, host + '.run'), 'w').writelines(sdee._subscriptionid)
	except:
		exception = traceback.format_exc().splitlines()[-1]
		sdeeLogger.error("Connecting to sensor - %s: %s" % (host,exception))
		time.sleep(300)
		sys.exit()		
	
	while 1:
		try:
			sdee.get()
			time.sleep(int(interval))
		except:
			exception = traceback.format_exc().splitlines()[-1]
			sdeeLogger.error("Exception thrown in sdee.get(): %s" % exception)
			sdeeLogger.error("Attempting to re-connect to the sensor: %s" % host)
			sdee._subscriptionid = ""
			sdee.open()
			sdeeLogger.info("Successfully connected to: %s" % host)
			sdeeLogger.info('host="%s" SessionID="%s" SubscriptionID="%s"' % (host, sdee._sessionid, sdee._subscriptionid))
			open(os.path.join(RUN_DIR, host + '.run'), 'w').writelines(sdee._subscriptionid)
			continue;
		try:
			result_xml = sdee.data() 
			alert_obj_list = idsmxml.parse_alerts( result_xml )
		except:
			ts = str(time.time())
			exception = traceback.format_exc()
			sdeeLogger.info("Exception thrown while parsing SDEE payload: %s" % exception)

## Un Comment for easy debug of raw xml feeds. 
#		ts = str(time.time())
#		open(os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', 'Splunk_CiscoIPS','var','debug',host+"_"+ts+".core"),'w').write(result_xml)
#		print result_xml
##########
		for alerts in alert_obj_list:
			target_list = []
			alert_dict = {}
			for target in alerts.target_list:
				target_list.append((target.addr,target.port,target.locality))
			
			alert_dict["target_list"] = target_list

			#if alerts.isDropped != "NULL":
			#	alert_dict["isDropped"] = alerts.isDropped
			#else:	
			#	alert_dict["isDropped"] = "NULL"

			if alerts.globalCorrelationScore != "NULL":
				alert_dict["gc_score"] =  alerts.globalCorrelationScore
				alert_dict["gc_riskdelta"] =  alerts.globalCorrelationRiskDelta 
				alert_dict["gc_riskrating"] = alerts.globalCorrelationModifiedRiskRating
				alert_dict["gc_deny_packet"] = alerts.globalCorrelationDenyPacket
				alert_dict["gc_deny_attacker"] = alerts.globalCorrelationDenyAttacker
			else:
				alert_dict["gc_score"] = "NULL"
			
			alert_dict["alert_time"] = alerts.alert_time
			alert_dict["eventid"] = alerts.eventid
			alert_dict["hostId"] = alerts.originator
			alert_dict["severity"] = alerts.severity
			alert_dict["app_name"] = alerts.appname
			
			alert_dict["appInstanceId"] = alerts.appInstanceId
			alert_dict["signature"] =alerts.signature.sigid
			alert_dict["subSigid"] = alerts.signature.subsig
			#alert_dict["description"]=alerts.signature.sigdetail
			alert_dict["description"] = alerts.signature.description
			alert_dict["sig_details"] = alerts.signature.sigdetail
			alert_dict["sig_version"] = alerts.signature.sigversion
			alert_dict["sig_created"] = alerts.signature.sigcreated
			alert_dict["sig_type"] = alerts.signature.sigtype
	
			alert_dict["mars_category"] = alerts.signature.marsCategory
			alert_dict["attacker"] = alerts.attacker.addr
			alert_dict["attacker_locality"] = alerts.attacker.locality
			alert_dict["attacker_port"] = str(alerts.attacker.port)
			alert_dict["protocol"] = alerts.protocol
			alert_dict["risk_rating"] = str(alerts.riskrating)
			alert_dict["threat_rating"] = str(alerts.threatrating)
			alert_dict["target_value_rating"] = str(alerts.targetvaluerating)
			
			alert_dict["attack_relevance_rating"] = str(alerts.attackrelevancerating)
			alert_dict["vlan"] = alerts.vlan
			alert_dict["interface"] = alerts.interface
			alert_dict["interface_group"] = alerts.intgroup
			
			# Add context and actions.
			# Credited to Andrew Garvin.
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
				if alerts.triggerpacket != "NULL":
					trigger_packet_details = decode(alerts.triggerpacket)
					#packet_info = ' trigger_packet="'+alerts.triggerpacket+'" trigger_packet_details="'+trigger_packet_details+'"'
					packet_info = ' trigger_packet="%s" trigger_packet_details="%s"' % (alerts.triggerpacket, trigger_packet_details)
				if alerts.fromtarget != "NULL":
					fromTarget_details = decode(alerts.fromtarget)
					#packet_info = packet_info +  ' fromTarget="'+alerts.fromtarget+'" fromTarget_details="'+fromTarget_details+'"'
					packet_info += ' fromTarget="%s" fromTarget_details="%s"' % (alerts.fromtarget, fromTarget_details)
				if alerts.fromattacker != "NULL":
					fromAttacker_details = decode(alerts.fromattacker)
					#packet_info = packet_info +  ' fromAttacker="'+alerts.fromattacker+'" fromAttacker_details="'+fromAttacker_details+'"'
					packet_info += ' fromAttacker="%s" fromAttacker_details="%s"' % (alerts.fromattacker, fromAttacker_details)
			except:
				ts = str(time.time())
				exception = traceback.format_exc()
				sdeeLogger.error("Exception caught while getting trigger_packet: %s" % exception)
			
			try:
				for target in alert_dict["target_list"]:
					#target_list_string += ' target="'+target[0]+'" target_port="'+str(target[1])+'" target_locality="'+str(target[2])+'" '
					target_list_string += ' target="%s" target_port="%s" target_locality="%s" ' % (target[0], target[1], target[2])
				
				#syslog_msg = alert_dict["alert_time"] + ' eventid="' + alert_dict["eventid"] + \
				#	'" hostId="' + alert_dict["hostId"] + '" sig_created="' + alert_dict["sig_created"] + \
				#	'" sig_type="' + alert_dict["sig_type"] + '" severity="' + alert_dict["severity"] + \
				#	'" app_name="' + alert_dict["app_name"] + '" appInstanceId="' + alert_dict["appInstanceId"] + \
				#	'" signature="' + alert_dict["signature"] + '" subSigid="' + alert_dict["subSigid"] + \
				#	'" description="' + alert_dict["description"] + '" sigDetails="' + alert_dict["sig_details"] + \
				#	'" sig_version="' + alert_dict["sig_version"] + \
				#	'" attacker="' + alert_dict["attacker"] + \
				#	'" attacker_port="' + alert_dict["attacker_port"] + '" attacker_locality="' + alert_dict["attacker_locality"] + \
				#	'" ' + target_list_string + ' protocol="' + alert_dict["protocol"] + \
				#	'" attack_relevance_rating="' + alert_dict["attack_relevance_rating"] + \
				#	'"  risk_rating="' + alert_dict["risk_rating"] + '" threat_rating="' + alert_dict["threat_rating"] + \
				#	'" target_value_rating="' + alert_dict["target_value_rating"] + '" interface="' + alert_dict["interface"] + \
				#	'" interface_group="' + alert_dict["interface_group"] + '" vlan="' + alert_dict["vlan"] + '"'
				
				syslog_msg = '%s eventid="%s" hostId="%s" sig_created="%s" sig_type="%s" severity="%s" app_name="%s" appInstanceId="%s" signature="%s" subSigid="%s" description="%s" sigDetails="%s" sig_version="%s" attacker="%s" attacker_port="%s" attacker_locality="%s" %s protocol="%s" attack_relevance_rating="%s" risk_rating="%s" threat_rating="%s" target_value_rating="%s" interface="%s" interface_group="%s" vlan="%s"' \
					% (alert_dict["alert_time"], alert_dict["eventid"], alert_dict["hostId"], alert_dict["sig_created"],
					alert_dict["sig_type"], alert_dict["severity"], alert_dict["app_name"], alert_dict["appInstanceId"],
					alert_dict["signature"], alert_dict["subSigid"], alert_dict["description"], alert_dict["sig_details"],
					alert_dict["sig_version"], alert_dict["attacker"], alert_dict["attacker_port"], alert_dict["attacker_locality"],
					target_list_string, alert_dict["protocol"], alert_dict["attack_relevance_rating"], alert_dict["risk_rating"],
					alert_dict["threat_rating"],alert_dict["target_value_rating"], alert_dict["interface"], alert_dict["interface_group"],
					alert_dict["vlan"])
				
				# Make mars_category optional.
				# Add optional context and actions.
				# Credited to Andrew Garvin.
				if alert_dict["mars_category"] != "NULL": syslog_msg += ' mars_category="%s"' % alert_dict["mars_category"]
				if alert_dict["context"] != "NULL": syslog_msg += ' context="%s"' % alert_dict["context"]
				if alert_dict["actions"] != "NULL": syslog_msg += ' actions="%s"' % alert_dict["actions"]
				if alert_dict["ipLoggingActivated"] != "NULL": syslog_msg += ' ipLoggingActivated="%s"' % alert_dict["ipLoggingActivated"]
				if alert_dict["shunRequested"] != "NULL": syslog_msg += ' shunRequested="%s"' % alert_dict["shunRequested"]
				if alert_dict["droppedPacket"] != "NULL": syslog_msg += ' droppedPacket="%s"' % alert_dict["droppedPacket"]
				if alert_dict["deniedAttacker"] != "NULL": syslog_msg += ' deniedAttacker="%s"' % alert_dict["deniedAttacker"]
				if alert_dict["blockConnectionRequested"] != "NULL": syslog_msg += ' blockConnectionRequested="%s"' % alert_dict["blockConnectionRequested"]
				if alert_dict["logAttackerPacketsActivated"] != "NULL": syslog_msg += ' logAttackerPacketsActivated="%s"' % alert_dict["logAttackerPacketsActivated"]
				if alert_dict["logVictimPacketsActivated"] != "NULL": syslog_msg += ' logVictimPacketsActivated="%s"' % alert_dict["logVictimPacketsActivated"]
				if alert_dict["logPairPacketsActivated"] != "NULL": syslog_msg += ' logPairPacketsActivated="%s"' % alert_dict["logPairPacketsActivated"]
				if alert_dict["snmpTrapRequested"] != "NULL": syslog_msg += ' snmpTrapRequested="%s"' % alert_dict["snmpTrapRequested"]
				if alert_dict["deniedAttackerServicePair"] != "NULL": syslog_msg += ' deniedAttackerServicePair="%s"' % alert_dict["deniedAttackerServicePair"]
				if alert_dict["deniedAttackerVictimPair"] != "NULL": syslog_msg += ' deniedAttackerVictimPair="%s"' % alert_dict["deniedAttackerVictimPair"]
				if alert_dict["summaryCount"] != "NULL": syslog_msg += ' summary_count="%s"' % alert_dict["summaryCount"]
				if alert_dict["initialAlert"] != "NULL": syslog_msg += ' initial_alert="%s"' % alert_dict["initialAlert"]
				if alert_dict["gc_score"] != "NULL":
					syslog_msg += ' gc_score="%s" gc_riskdelta="%s" gc_riskrating="%s" gc_deny_packet="%s" gc_deny_attacker="%s"\n' \
						% (alert_dict["gc_score"], alert_dict["gc_riskdelta"], alert_dict["gc_riskrating"], alert_dict["gc_deny_packet"], alert_dict["gc_deny_attacker"])
				
				if len(packet_info) > 150:
					# Remove newlines in packet captures, so they show up as one line in Splunk,
					# instead of several lines and include packet data in one event.
					# Credited to Andrew Garvin.
					packet_info = packet_info.replace("\n", " ")
					syslog_msg += packet_info
					#syslog_msg = syslog_msg + "\n" + alert_dict["alert_time"]+ ' eventid="'+alert_dict["eventid"]+'" '+ packet_info
			except:
				ts = str(time.time())
				exception = traceback.format_exc()
				sdeeLogger.error("Exception caught while writing event: %s" % exceptoin)

			ipsLogger.info(syslog_msg)

def test(result_xml):
	''' Function for testing parsers '''
	print("Starting test():\n\tresult_xml = %s\n" % result_xml)
	alert_obj_list = idsmxml.parse_alerts(result_xml)
	print("alert_obj_list = %s" % alert_obj_list)
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
		#alert_dict["description"]=alerts.signature.sigdetail
		alert_dict["description"] = alerts.signature.description
		alert_dict["sig_details"] = alerts.signature.sigdetail
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
			if alerts.triggerpacket != "NULL":
				trigger_packet_details = decode(alerts.triggerpacket)
				#packet_info = ' trigger_packet="'+alerts.triggerpacket+'" trigger_packet_details="'+trigger_packet_details+'"'
				packet_info = ' trigger_packet="%s" trigger_packet_details="%s"' % (alerts.triggerpacket, trigger_packet_details)
			if alerts.fromtarget != "NULL":
				fromTarget_details = decode(alerts.fromtarget)
				#packet_info = packet_info +  ' fromTarget="'+alerts.fromtarget+'" fromTarget_details="'+fromTarget_details+'"'
				packet_info += ' fromTarget="%s" fromTarget_details="%s"' % (alerts.fromtarget, fromTarget_details)
			if alerts.fromattacker != "NULL":
				fromAttacker_details = decode(alerts.fromattacker)
				#packet_info = packet_info +  ' fromAttacker="'+alerts.fromattacker+'" fromAttacker_details="'+fromAttacker_details+'"'
				packet_info += ' fromAttacker="%s" fromAttacker_details="%s"' % (alerts.fromattacker, fromAttacker_details)
		except:
			ts = str(time.time())
			exception = traceback.format_exc()
			print("Exception caught while getting trigger_packet: %s" % exception)
		
		try:
			for target in alert_dict["target_list"]:
				target_list_string += ' target="%s" target_port="%s" target_locality="%s" ' % (target[0], target[1], target[2])
			
			syslog_msg = '%s eventid="%s" hostId="%s" sig_created="%s" sig_type="%s" severity="%s" app_name="%s" appInstanceId="%s" signature="%s" subSigid="%s" description="%s" sigDetails="%s" sig_version="%s" attacker="%s" attacker_port="%s" attacker_locality="%s" %s protocol="%s" attack_relevance_rating="%s" risk_rating="%s" threat_rating="%s" target_value_rating="%s" interface="%s" interface_group="%s" vlan="%s"' \
					% (alert_dict["alert_time"], alert_dict["eventid"], alert_dict["hostId"], alert_dict["sig_created"],
					alert_dict["sig_type"], alert_dict["severity"], alert_dict["app_name"], alert_dict["appInstanceId"],
					alert_dict["signature"], alert_dict["subSigid"], alert_dict["description"], alert_dict["sig_details"],
					alert_dict["sig_version"], alert_dict["attacker"], alert_dict["attacker_port"], alert_dict["attacker_locality"],
					target_list_string, alert_dict["protocol"], alert_dict["attack_relevance_rating"], alert_dict["risk_rating"],
					alert_dict["threat_rating"],alert_dict["target_value_rating"], alert_dict["interface"], alert_dict["interface_group"],
					alert_dict["vlan"])
				
			# Make mars_category optional.
			# Add optional context and actions.
			# Credited to Andrew Garvin.
			if alert_dict["mars_category"] != "NULL": syslog_msg += ' mars_category="%s"' % alert_dict["mars_category"]
			if alert_dict["context"] != "NULL": syslog_msg += ' context="%s"' % alert_dict["context"]
			if alert_dict["actions"] != "NULL": syslog_msg += ' actions="%s"' % alert_dict["actions"]
			if alert_dict["ipLoggingActivated"] != "NULL": syslog_msg += ' ipLoggingActivated="%s"' % alert_dict["ipLoggingActivated"]
			if alert_dict["shunRequested"] != "NULL": syslog_msg += ' shunRequested="%s"' % alert_dict["shunRequested"]
			if alert_dict["droppedPacket"] != "NULL": syslog_msg += ' droppedPacket="%s"' % alert_dict["droppedPacket"]
			if alert_dict["deniedAttacker"] != "NULL": syslog_msg += ' deniedAttacker="%s"' % alert_dict["deniedAttacker"]
			if alert_dict["blockConnectionRequested"] != "NULL": syslog_msg += ' blockConnectionRequested="%s"' % alert_dict["blockConnectionRequested"]
			if alert_dict["logAttackerPacketsActivated"] != "NULL": syslog_msg += ' logAttackerPacketsActivated="%s"' % alert_dict["logAttackerPacketsActivated"]
			if alert_dict["logVictimPacketsActivated"] != "NULL": syslog_msg += ' logVictimPacketsActivated="%s"' % alert_dict["logVictimPacketsActivated"]
			if alert_dict["logPairPacketsActivated"] != "NULL": syslog_msg += ' logPairPacketsActivated="%s"' % alert_dict["logPairPacketsActivated"]
			if alert_dict["snmpTrapRequested"] != "NULL": syslog_msg += ' snmpTrapRequested="%s"' % alert_dict["snmpTrapRequested"]
			if alert_dict["deniedAttackerServicePair"] != "NULL": syslog_msg += ' deniedAttackerServicePair="%s"' % alert_dict["deniedAttackerServicePair"]
			if alert_dict["deniedAttackerVictimPair"] != "NULL": syslog_msg += ' deniedAttackerVictimPair="%s"' % alert_dict["deniedAttackerVictimPair"]
			if alert_dict["summaryCount"] != "NULL": syslog_msg += ' summary_count="%s"' % alert_dict["summaryCount"]
			if alert_dict["initialAlert"] != "NULL": syslog_msg += ' initial_alert="%s"' % alert_dict["initialAlert"]
			if alert_dict["gc_score"] != "NULL":
				syslog_msg += ' gc_score="%s" gc_riskdelta="%s" gc_riskrating="%s" gc_deny_packet="%s" gc_deny_attacker="%s"\n' \
					% (alert_dict["gc_score"], alert_dict["gc_riskdelta"], alert_dict["gc_riskrating"], alert_dict["gc_deny_packet"], alert_dict["gc_deny_attacker"])
			
			if len(packet_info)>150:
				# Remove newlines in packet captures, so they show up as one line in Splunk,
				# instead of several lines and include packet data in one event.
				# Credited to Andrew Garvin.
				packet_info = packet_info.replace("\n", " ")
				syslog_msg += packet_info
				#syslog_msg = syslog_msg + "\n" + alert_dict["alert_time"]+ ' eventid="'+alert_dict["eventid"]+'" '+ packet_info
		except:
			ts = str(time.time())
			exception = traceback.format_exc()
			print("Exception caught while writing event: %s" % exception)
		# Print output for testing
		print(syslog_msg)

#run(sys.argv[1],sys.argv[2],sys.argv[3],"https","yes")
run(USERNAME, PASSWORD, HOST, POLLING_INTERVAL, POLLING_METHOD, POLLING_IS_FORCE)

# For testing/debugging, uncomment the following block:
#if __name__ == '__main__':
#	xml_file = file(sys.argv[1], 'r').read()
#	test(xml_file)
#	sys.exit()