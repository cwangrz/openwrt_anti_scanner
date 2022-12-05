#!/usr/bin/python3

import subprocess
import re
import time
from datetime import datetime

THRESH_HOLD = 1
CHAIN_NAME = 'ABUSERS'
LOG_FILE = 'abusers.log'
BAN_LIST = 'banlist.txt'
LOG_START = '..START..'
LOG_END = '..END..'
FILTER_TOKENS = ['Exit before auth','Bad password attempt']

logger = open(LOG_FILE,'a')
ipPattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
syslog = subprocess.check_output(['logread']).decode('utf-8')
logbyrow = syslog.split('\n')


def chain_exists():
	p = subprocess.Popen(f"iptables -N {CHAIN_NAME}",shell=True,stdout=subprocess.PIPE)
	p.communicate()
	rc = p.returncode
	p.terminate()
	return rc == 1

def log(msg):
	if msg == LOG_START:
		logger.write('----------------------------SCRIPT STARTS----------------------------\n')
		logger.write(str(datetime.now().replace(microsecond=0))+'\n')
	elif msg == LOG_END:
		logger.write('----------------------------SCRIPT ENDS----------------------------\n')
	else:
		logger.write(msg+'\n')

def filter_ips():
	log('Filtering new abusers from system log')
	ips={}
	for row in logbyrow:
		for token in FILTER_TOKENS:
			if token in row:
				abuserIP = ipPattern.search(row)[0]
				ips[abuserIP] = ips.get(abuserIP,0)+1
				break
	return ips

log(LOG_START)
if not chain_exists():
	log(f'{CHAIN_NAME} chain does not exist. Recreating the chain.')
	subprocess.run('iptables -I INPUT -j ABUSERS',shell=True)
	log(f'Referencing {CHAIN_NAME} chain in INPUT chain.')
	
	blist = open(BAN_LIST,'r')
	ips = blist.readlines()
	log(f'Adding all ips in banlist back to {CHAIN_NAME} chain...')
	for ip in ips:
		subprocess.run(f'iptables -I ABUSERS -s {ip.strip()} -j DROP',shell=True)
	log(f'All ips in banlist added back to {CHAIN_NAME} chain.')
	blist.close()
	log(f'Reinstatement complete.')
	log('\n')


ips=filter_ips()
blist = open(BAN_LIST,'a')
for ip in ips:
	if ips[ip] > THRESH_HOLD:
		p = subprocess.Popen(f"iptables-save|grep {ip}",shell=True,stdout=subprocess.PIPE)
		p.communicate()
		if p.returncode == 1: #not in chain
			log(f'Found new abuser {ip} with {ips[ip]} attemps.')
			subprocess.run(f'iptables -I {CHAIN_NAME} -s {ip} -j DROP',shell=True)
			blist.write(ip+"\n")
			log(f'{ip} added to {CHAIN_NAME} chain and to banlist.')
log(f'Filter complete.')
log(LOG_END)

p.terminate()
logger.close()
blist.close()
