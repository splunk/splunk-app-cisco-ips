
import xml.dom.minidom,sys,datetime

class Participant:

	def __init__(self, **kwargs):

		try: self.xml = kwargs['xml']
		except: self.xml = ''

		try: self.addr = kwargs['addr']
		except: self.addr = ''

		try: self.locality = kwargs['locality']
		except: self.locality = ''

		try: self.port = kwargs['port']
		except: self.port = 0

class Signature:

	def __init__(self, **kwargs):

		try: self.xml = kwargs['xml']
		except: self.xml = ''
	
		try: self.id = kwargs['sigid'] 	
		except: self.id = 0

		try: self.version = kwargs['sigversion']
		except: self.version = ''

		try: self.subsig = kwargs['subsig']
		except: self.subsig = 0

		try: self.sigdetail = kwargs['sigdetail']
		except: self.sigdetail = ''

		try: self.marsCategory = kwargs['marsCategory']
		except: self.marsCategory = ''

class Alert:

	def __init__(self, **kwargs):

		try: self.xml = kwargs['xml']
		except: self.xml = ''

		try: self.eventid = kwargs['eventid']
		except: self.eventid = 0

		try: self.severity = kwargs['severity']
		except: self.severity = ''

		try: self.originator = kwargs['originator']
		except: self.originator = ''

		try: self.appname = kwargs['appName']
		except: self.appname = ''

		try: self.appInstanceId = kwargs['appInstanceId']
		except: self.appInstanceId = ''

		try: self.alert_time = kwargs['alert_time']
		except: self.alert_time = 0

		try: self.signature = kwargs['signature']
		except: self.signature = Signature()

		try: self.attacker = kwargs['attacker']
		except: self.attacker = Participant()

		try: self.target_list = kwargs['target_list']
		except: self.target_list = []

		try: self.riskrating = kwargs['taget_locality']
		except: self.riskrating = []

		try: self.riskrating = kwargs['riskrating']
		except: self.riskrating = 0

		try: self.threatrating = kwargs['threatrating']
		except: self.threatrating = 0

		try: self.targetValueRating = kwargs['targetValueRating']
		except: self.targetValueRating = 0
		
		try: self.attackrelevancerating = kwargs['attackrelevancerating']
		except: self.attackrelevancerating = " "
		
		try: self.interface = kwargs['interface']
		except: self.interface = ''

		try: self.protocol = kwargs['protocol']
		except: self.protocol = ''

		try: self.intgroup = kwargs['interfaceGroup']

		except: self.intgroup = ''

		try: self.intgroup = kwargs['vlan']
		except: self.intgroup = ''

		try: self.triggerpacket = kwargs['triggerpacket']
		except: self.triggerpacket = 'NULL'

		try: self.fromattacker = kwargs['fromattacker']
		except: self.fromattacker = 'NULL'

		try: self.fromtarget = kwargs['fromtarget']
		except: self.fromtarget = 'NULL'

		try: self.globalcorrelation = kwargs['globalCorrelation']
		except:	self.globalcorrelation = ''

		try: self.context = kwargs['context']
		except: self.context = 'NULL'

		try: self.actions = kwargs['actions']
		except: self.actions = 'NULL'

		try: self.ipLoggingActivated = kwargs['ipLoggingActivated']
		except: self.ipLoggingActivated = 'NULL'

		try: self.shunRequested = kwargs['shunRequested']
		except: self.shunRequested = 'NULL'

		try: self.droppedPacket = kwargs['droppedPacket']
		except: self.droppedPacket = 'NULL'

		try: self.deniedAttacker = kwargs['deniedAttacker']
		except: self.deniedAttacker = 'NULL'

		try: self.blockConnectionRequested = kwargs['blockConnectionRequested']
		except: self.blockConnectionRequested = 'NULL'

		try: self.logAttackerPacketsActivated = kwargs['logAttackerPacketsActivated']
		except: self.logAttackerPacketsActivated = 'NULL'

		try: self.logVictimPacketsActivated = kwargs['logVictimPacketsActivated']
		except: self.logVictimPacketsActivated = 'NULL'

		try: self.logPairPacketsActivated = kwargs['logPairPacketsActivated']
		except: self.logPairPacketsActivated = 'NULL'

		try: self.snmpTrapRequested = kwargs['snmpTrapRequested']
		except: self.snmpTrapRequested = 'NULL'

		try: self.deniedAttackerServicePair = kwargs['deniedAttackerServicePair']
		except: self.deniedAttackerServicePair = 'NULL'

		try: self.deniedAttackerVictimPair = kwargs['deniedAttackerVictimPair']
		except: self.deniedAttackerVictimPair = 'NULL'

		try: self.summaryCount = kwargs['summaryCount']
		except: self.summaryCount = 'NULL'

		try: self.initialAlert = kwargs['initialAlert']
		except: self.initialAlert = 'NULL'

def build_global(node):

	alert = Alert()
	alert.xml = node.toxml()
	alert.eventid = node.attributes['eventId'].nodeValue

	alert.severity = node.attributes['severity'].nodeValue
	alert.vendor = node.attributes['vendor'].nodeValue
	alert.originator = node.getElementsByTagName('sd:originator')[0].getElementsByTagName('sd:hostId')[0].firstChild.wholeText
	alert.appname = node.getElementsByTagName('sd:originator')[0].getElementsByTagName('cid:appName')[0].firstChild.wholeText
	alert.appInstanceId = node.getElementsByTagName('sd:originator')[0].getElementsByTagName('cid:appInstanceId')[0].firstChild.wholeText

	#alert.alert_time = node.getElementsByTagName('sd:time')[0].firstChild.wholeText
	alert.alert_time = str(datetime.datetime.fromtimestamp(int(node.getElementsByTagName('sd:time')[0].firstChild.wholeText)/1000000000))
	alert.riskrating = node.getElementsByTagName('cid:riskRatingValue')[0].firstChild.wholeText
	alert.threatrating = node.getElementsByTagName('cid:threatRatingValue')[0].firstChild.wholeText
	alert.targetvaluerating = node.getElementsByTagName('cid:riskRatingValue')[0].attributes['targetValueRating'].nodeValue

	alert.interface = node.getElementsByTagName('cid:interface')[0].firstChild.wholeText
	alert.protocol = node.getElementsByTagName('cid:protocol')[0].firstChild.wholeText
	alert.intgroup = node.getElementsByTagName('sd:interfaceGroup')[0].firstChild.wholeText
	alert.vlan = node.getElementsByTagName('sd:vlan')[0].firstChild.wholeText

	try:
		alert.context = node.getElementsByTagName('cid:interface')[0].attributes['context'].nodeValue
	except:	alert.context = "NULL"

	try:
		alert.ipLoggingActivated = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('sd:ipLoggingActivated')[0].firstChild.wholeText
	except: alert.ipLoggingActivated = "NULL"

	try:
		alert.shunRequested = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('sd:shunRequested')[0].firstChild.wholeText
	except: alert.shunRequested = "NULL"

	try:
		alert.droppedPacket = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('sd:droppedPacket')[0].firstChild.wholeText
	except: alert.droppedPacket = "NULL"

	try:
		alert.deniedAttacker = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('cid:deniedAttacker')[0].firstChild.wholeText
	except: alert.deniedAttacker = "NULL"

	try:
		alert.blockConnectionRequested = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('cid:blockConnectionRequested')[0].firstChild.wholeText
	except: alert.blockConnectionRequested = "NULL"

	try:
		alert.logAttackerPacketsActivated = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('cid:logAttackerPacketsActivated')[0].firstChild.wholeText
	except: alert.logAttackerPacketsActivated = "NULL"

	try:
		alert.logVictimPacketsActivated = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('cid:logVictimPacketsActivated')[0].firstChild.wholeText
	except: alert.logVictimPacketsActivated = "NULL"

	try:
		alert.logPairPacketsActivated = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('cid:logPairPacketsActivated')[0].firstChild.wholeText
	except: alert.logPairPacketsActivated = "NULL"

	try:
		alert.snmpTrapRequested = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('cid:snmpTrapRequested')[0].firstChild.wholeText
	except: alert.snmpTrapRequested = "NULL"

	try:
		alert.deniedAttackerServicePair = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('cid:deniedAttackerServicePair')[0].firstChild.wholeText
	except: alert.deniedAttackerServicePair = "NULL"

	try:
		alert.deniedAttackerVictimPair = node.getElementsByTagName('sd:actions')[0].getElementsByTagName('cid:deniedAttackerVictimPair')[0].firstChild.wholeText
	except: alert.deniedAttackerVictimPair = "NULL"

	try:
		actionsList = []
		if alert.ipLoggingActivated!="NULL":
			actionsList.append("ipLoggingActivated")
		if alert.shunRequested!="NULL":
			actionsList.append("shunRequested")
		if alert.droppedPacket!="NULL":
			actionsList.append("droppedPacket")
		if alert.deniedAttacker!="NULL":
			actionsList.append("deniedAttacker")
		if alert.logAttackerPacketsActivated!="NULL":
			actionsList.append("logAttackerPacketsActivated")
		if alert.logVictimPacketsActivated!="NULL":
			actionsList.append("logVictimPacketsActivated")
		if alert.logPairPacketsActivated!="NULL":
			actionsList.append("logPairPacketsActivated")
		if alert.snmpTrapRequested!="NULL":
			actionsList.append("snmpTrapRequested")
		if alert.blockConnectionRequested!="NULL":
			actionsList.append("blockConnectionRequested")
		if alert.deniedAttackerServicePair!="NULL":
			actionsList.append("deniedAttackerServicePair")
		if alert.deniedAttackerVictimPair!="NULL":
			actionsList.append("deniedAttackerVictimPair")
		if len(actionsList) != 0:
			alert.actions = ",".join(actionsList)
	except: alert.actions = "NULL"

	try:
		alert.summaryCount = node.getElementsByTagName('cid:summary')[0].firstChild.wholeText
	except: alert.summaryCount = "NULL"

	try:
		alert.initialAlert = node.getElementsByTagName('cid:summary')[0].attributes['cid:initialAlert'].nodeValue
	except: alert.initialAlert = "NULL"

	try: 
		alert.triggerpacket = node.getElementsByTagName('cid:triggerPacket')[0].firstChild.wholeText
	except: alert.triggerpacket = "NULL"
	
	try:
		alert.fromtarget = node.getElementsByTagName('cid:context')[0].getElementsByTagName('cid:fromTarget')[0].firstChild.wholeText
	except:	alert.fromtarget = "NULL"

	try:
		alert.fromattacker = node.getElementsByTagName('cid:context')[0].getElementsByTagName('cid:fromAttacker')[0].firstChild.wholeText
	except:	alert.fromattacker = "NULL"

	try:
		alert.attackrelevancerating = node.getElementsByTagName('cid:riskRatingValue')[0].attributes['attackRelevanceRating'].nodeValue
		alert.globalCorrelationScore = node.getElementsByTagName('cid:globalCorrelation')[0].getElementsByTagName('cid:globalCorrelationScore')[0].firstChild.wholeText
		alert.globalCorrelationRiskDelta = node.getElementsByTagName('cid:globalCorrelation')[0].getElementsByTagName('cid:globalCorrelationRiskDelta')[0].firstChild.wholeText
		alert.globalCorrelationModifiedRiskRating = node.getElementsByTagName('cid:globalCorrelation')[0].getElementsByTagName('cid:globalCorrelationModifiedRiskRating')[0].firstChild.wholeText
		alert.globalCorrelationDenyPacket = node.getElementsByTagName('cid:globalCorrelation')[0].getElementsByTagName('cid:globalCorrelationDenyPacket')[0].firstChild.wholeText
		alert.globalCorrelationDenyAttacker = node.getElementsByTagName('cid:globalCorrelation')[0].getElementsByTagName('cid:globalCorrelationDenyAttacker')[0].firstChild.wholeText
		alert.globalCorrelationOtherOverrides = node.getElementsByTagName('cid:globalCorrelation')[0].getElementsByTagName('cid:globalCorrelationOtherOverrides')[0].firstChild.wholeText
		alert.globalCorrelationAuditMode = node.getElementsByTagName('cid:globalCorrelation')[0].getElementsByTagName('cid:globalCorrelationAuditMode')[0].firstChild.wholeText				
	except: alert.globalCorrelationScore = "NULL"

	return alert


def build_sig(node):
	signature = Signature()
	signature.xml = node.toxml()	
	signature.sigid = node.attributes['id'].nodeValue
	signature.sigversion = node.attributes['cid:version'].nodeValue
	signature.sigcreated = node.attributes['cid:created'].nodeValue
	signature.sigtype = node.attributes['cid:type'].nodeValue
	signature.subsig = node.getElementsByTagName('cid:subsigId')[0].firstChild.wholeText
	
	try:
		signature.marsCategory = node.getElementsByTagName('marsCategory')[0].firstChild.wholeText
	except:
		signature.marsCategory = "NULL"

	try:
		signature.sigdetail = node.getElementsByTagName('cid:sigDetails')[0].firstChild.wholeText
	except:
		signature.sigdetail = node.attributes['description'].nodeValue

	return signature

def build_participant(node):

	targetlist = node.getElementsByTagName('sd:target')
	attacklist = node.getElementsByTagName('sd:attacker')
	if len(attacklist) == 0:
		attacker = Participant()
		target = Participant()
		return attacker, [target]

	if len(attacklist) == 1:
		attacker = Participant(xml=attacklist[0].toxml())

		try:
			attacker.addr = attacklist[0].getElementsByTagName('sd:addr')[0].firstChild.wholeText
			attacker.locality = attacklist[0].getElementsByTagName('sd:addr')[0].attributes['cid:locality'].nodeValue

			attacker.port = attacker.getElementsByTagName('sd:port')[0].firstChild.wholeText
		except:
			attacker.port = '0'
	targetlist = []
	nodelist = node.getElementsByTagName('sd:target')
	for item in nodelist:
		target = Participant(xml=item.toxml())
		target.addr = item.getElementsByTagName('sd:addr')[0].firstChild.wholeText
		target.locality = item.getElementsByTagName('sd:addr')[0].attributes['cid:locality'].nodeValue
		try:
			target.port = item.getElementsByTagName('sd:port')[0].firstChild.wholeText
		except:
			target.port = '0'
		
		targetlist.append(target)

	return attacker, targetlist	

def parse_alerts(xmldata):

	doc = xml.dom.minidom.parseString(xmldata)
	alertlist = doc.getElementsByTagName('sd:evIdsAlert')

	alert_obj_list = []	
	for alert in alertlist:
	
		alert_obj = build_global(alert)
		
		sig = alert.getElementsByTagName('sd:signature')
		alert_obj.signature = build_sig(sig[0])

		participants = alert.getElementsByTagName('sd:participants')
		alert_obj.attacker, alert_obj.target_list = build_participant(participants[0])
	
		alert_obj_list.append(alert_obj)	

	
#	for alerts in alert_obj_list:
#		print "alert_time: %s, severity: %s, signature: %s, description: %s, attacker: %s, targets: %i" % (alerts.alert_time, 
#					alerts.severity, alerts.signature.id, alerts.signature.sigdetail, alerts.attacker.addr, len(alerts.target_list) )
	
	return alert_obj_list
	
