#!/usr/bin/env python

from sys import *
from OTXv2 import OTXv2
import ConfigParser
import datetime
import sys

config = ConfigParser.ConfigParser()
config.read('config.cfg')

HEADER = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\n"
#HEADER = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\tmeta.if_in\n"

api = OTXv2(config.get('otx2', 'api_key'))

MAP = {"IPv4":"Intel::ADDR",
	   "IPv6":"Intel::ADDR",
	   "domain":"Intel::DOMAIN",
	   "hostname":"Intel::DOMAIN",
	   "email":"Intel::EMAIL",
	   "URL":"Intel::URL",
	   "URI":"Intel::URL",
	   "FileHash-MD5":"Intel::FILE_HASH",
	   "FileHash-SHA1":"Intel::FILE_HASH",
	   "FileHash-SHA256":"Intel::FILE_HASH"}


def pulseToBRO(pulse):
	source = "Alienvault OTX - %s - %s" % (pulse["name"].encode('utf-8').replace("\t", ""), pulse["id"])
	do_notice = "F"
	if config.getboolean('otx2', 'do_notice') == True:
		do_notice = "T"
	pulses = HEADER

	for indicator in pulse["indicators"]:
		pulse_type = MAP.get(indicator["type"], None)
		if pulse_type:
			itype = MAP[indicator["type"]]
			pulses = pulses + "%s\t%s\t%s\t%s\t%s\n" % (indicator["indicator"], itype, source, "%spulse/%s" % (config.get('otx2', 'otx_base_url'), pulse["id"]), do_notice)

	return pulses

def saveTimestamp(timestamp=None):
	mtimestamp = timestamp
	if not timestamp:
		mtimestamp = datetime.datetime.now().isoformat()

	fname = "%s/OTX-Apps-Bro-IDS/timestamp" % config.get('otx2', 'base_path')
	f = open(fname, "w")
	f.write(mtimestamp)
	f.close()

def readTimestamp():
	fname = "%s/OTX-Apps-Bro-IDS/timestamp" % config.get('otx2', 'base_path')
	f = open(fname, "r")
	mtimestamp = f.read()
	f.close()
	return mtimestamp

def firstRun():
	#Check if local.bro contains the reference
	blocal = False
	with open("%s/local.bro" % (config.get('otx2', 'base_path')),'r') as f:
		data = f.read()
		f.close()
		if data.find("@load alienvault-otx") != -1:
			blocal = True

	if not blocal:
		print "load not present"
		with open("%s/local.bro" % (config.get('otx2', 'base_path')),'ab') as f:
			f.write("\n@load alienvault-otx\n")

	#Check if API is empty
	pulses = api.getall()
	mtimestamp = None
	files = []
	for p in pulses:
		content = pulseToBRO(p)
		fname = "%s/OTX-Apps-Bro-IDS/pulses/%s.intel" % (config.get('otx2', 'base_path'), p["id"])
		f = open(fname, "w")
		f.write(content)
		f.close()
		print "%s/OTX-Apps-Bro-IDS/pulses/%s.intel saved" % (config.get('otx2', 'base_path'), p["id"])
		files.append(p["id"])
	if len(pulses) > 0:
		mtimestamp = pulses[0]["modified"]
	saveTimestamp(mtimestamp)
	createBroScript(files)
	print "%d new pulses" % len(pulses)

def createBroScript(files):
	print "Creating __load__.bro"	
	fname = "%s/OTX-Apps-Bro-IDS/__load__.bro" % config.get('otx2', 'base_path')
	f = open(fname, "r")
	bro = f.read()
	f.close()
	data = ""
	for f in files:
		data = data + 'fmt("%%s/pulses/%s.intel", @DIR),' % f
	bro = bro.replace("PULSES" , data[:-1])
	f = open(fname, "w")
	f.write(bro)
	f.close()
	

def updateBroScript(files):
	print "Updating __load__.bro"	
	fname = "%s/OTX-Apps-Bro-IDS/__load__.bro" % config.get('otx2', 'base_path')
	f = open(fname, "r")
	bro = f.read()
	f.close()
	data = ","
	for f in files:
		if bro.find(f) == -1:
			data = data + 'fmt("%%s/pulses/%s.intel", @DIR),' % f
	bro = bro.replace("};" , data[:-1] + "};")
	f = open(fname, "w")
	f.write(bro)
	f.close()


def getNewPulses():
	mtimestamp = readTimestamp()
	pulses = api.getsince(mtimestamp)
	files = []
	for p in pulses:
		content = pulseToBRO(p)
		fname = "%s/OTX-Apps-Bro-IDS/pulses/%s.intel" % (config.get('otx2', 'base_path'), p["id"])
		f = open(fname, "w")
		f.write(content)
		f.close()
		print "%s/OTX-Apps-Bro-IDS/pulses/%s.intel saved" % (config.get('otx2', 'base_path'), p["id"])
		files.append(p["id"])
	if len(pulses) > 0:
		mtimestamp = pulses[0]["modified"]
	saveTimestamp(mtimestamp)
	if len(pulses) > 0:
		updateBroScript(files)
	print "%d new pulses" % len(pulses)


def usage():
	print "Usage:\n\totxv2-bro.py [first_run|check_new]"
	sys.exit(0)
	
if __name__ == "__main__":
	try:
		op = argv[1]
	except:
		usage()
	if op == "first_run":
		firstRun()
	elif op == "check_new":
		getNewPulses()
	else:
		usage()

