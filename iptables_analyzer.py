#!/usr/bin/python
#Version 0.2
#Author: Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz
import subprocess
import re


"""
	Extracts amount of bytes and packets in mangle table
"""
def parse_from_line(string):
	split = string.split(" ")
	output = []
	for item in split:
		if len(item) > 0:
			output.append(item)
	return (output[0], output[1])

def process_honeypots():
	print "ACTIVE HONEYPOT PORTS:"
	chains = subprocess.Popen('iptables -vnL -t nat', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
	input_list = chains[0].split("Chain")


	for item in input_list:
		parsed = parse_chain(item)
		if parsed:
			for rule in parsed["rules"]:
				if len(rule) > 10:
					#print "Rule: " + parsed["name"]
					#is the port open?
					if len(subprocess.Popen('netstat -anp | grep '+ rule[10], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()[0]):
						data = (rule[0], rule[1])
						if rule [10] != '22': #skipp real SSH
							#get amount of packets
							packets = rule[0]
							#get amount of bytes
							bytes = rule[1]
							if rule[9] != '22':
								#get info from MANGLE TABLE and add it to the NAT data
								data = parse_from_line(subprocess.Popen('iptables -vnL -t mangle| grep -w '+ rule[9], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()[0])
								packets += data[0]
								bytes += rule[1]
							#get amount of packets
							packets = data[0]
							#get amount of bytes
							bytes = data[1]
							print "\tPORT: {}, REDIRECTED TO: {}, PROTOCOL: {} (pkts: {}, bytes: {})".format(rule[9], rule[10], rule[3], packets, bytes)
						

"""
	This function parses nat table of IPTABLES and extracts ports being redirected
"""
def parse_chain(chain):
	if len(chain) > 0:
		lines = chain.split("\n")
		name = lines[0].strip()
		headers =[]
		data = []
		#parse headers
		headers_row = lines[1].strip()
		for column_header in headers_row.split(" "):
			column_header = column_header.strip()
			if len(column_header) > 0:
				headers.append(column_header)
		#parse data
		for i in range(2,len(lines)):
			data_piece = []
			for j in lines[i].split(" "):
				j = j.strip()
				if len(j) > 0:
					data_piece.append(j)
			data_parsed = []
			rest = "";
			for i in range(0,len(data_piece)):
				if i < len(headers):
					data_parsed.append(data_piece[i]);
				else:
					rest += " "+data_piece[i]
			rest = re.sub("/\*.*\*/", "",rest).strip()
			if len(rest) > 0:
				dport_search = re.search("dpt:(\w+)", rest)
				rport_search = re.search("redir ports (\w+)", rest)
				if dport_search:
					data_parsed.append(dport_search.group(1))
				if rport_search:
					data_parsed.append(rport_search.group(1))
			if len(data_parsed) > 0:
				data.append(data_parsed)

		#return if there is at least one rule
		if len(data) > 0:
			return {'name':name, 'headers':headers, 'rules':data}
		else:
			return None
def process_production_ports():
	print "\nACTIVE PRODUCTION PORTS:"
	chains = subprocess.Popen('iptables -vnL -t nat | grep DNAT', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
	rules = parse_DNAT_chain(chains[0])
	for rule in rules:
		print "\tPORT: {}, REDIRECTED TO: {}, PROTOCOL: {} (pkts: {}, bytes: {})".format(rule[10], rule[11], rule[3], rule[0], rule[1])

def parse_DNAT_chain(chain):
	#check if not empty
	if len(chain) > 0:
		lines = chain.split("\n")
		rules = []
		#parse data in each line
		for line in lines:
			parsed = []
			for piece in line.split(" "):
				#discard empty splits
				if len(piece) > 0:
					parsed.append(piece.strip())
			if len(parsed) > 0: #check that we added sth in the output
				rport_search = re.search("to:([\w.+]*:\w+)", parsed[11])
				dport_search = re.search("dpt:(\w+)", parsed[10])
				if dport_search:
					parsed[10] = dport_search.group(1)
				if rport_search:
					parsed[11] = rport_search.group(1)
				rules.append(parsed)
		return rules
	else:
		return None


def process_accepted_ports():
	print "\nACCEPTED PORTS:"
	chains = subprocess.Popen('iptables -vnL -t filter', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
	input_list = chains[0].split("Chain")
	for item in input_list:
		parsed = parse_chain(item)
		if parsed:
			if "zone_wan_input" in parsed['name']:
				for rule in parsed["rules"]:
					if rule[2] == "accept" and len(rule) > 9:
						print "\tPORT: {},PROTOCOL: {} (pkts: {}, bytes: {})".format(rule[-1], rule[3], rule[0], rule[1])
if __name__ == '__main__':
	#get data from Honeypots
	process_honeypots()
	#get data from production ports (ports being redirected to the locat network)
	process_production_ports()
	#get data from accepted ports
	process_accepted_ports()
	
	



