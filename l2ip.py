#!/usr/bin/python
from __future__ import print_function
import requests, sys, argparse, re

# Eventually may move to a separate config file
LOG_PORT = 9200
API_URL = "http://example.com:{port}/logstash-{date}/iptables/{id}"
IPTABLES_COMMAND = "IPTABLES -A INPUT -p {proto} -m {proto} -s {source} --dport {dport} -m state --state NEW -j ACCEPT"

# ---- End config ---- 

def retrieveMessageJson(date, id):
	resp = requests.get(API_URL.format(date=date, id=id, port=LOG_PORT))
	if resp.status_code == 404:
		print("No such messageID {} on {}".format(id, date), file=sys.stderr)
		exit(1)

	return resp.json()

def main():
	parser = argparse.ArgumentParser(description="Parses logs from elasticsearch into iptables commands.")
	parser.add_argument("-d", dest="date", required=True, help="The date to pass to elasticsearch")
	parser.add_argument("-i", dest="id", required=True, help="The elastisearch messageID")
	args = parser.parse_args()

	logMessage = retrieveMessageJson(args.date, args.id)["_source"]["message"]
	extractor = re.compile("SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?PROTO=(TCP|UDP).*?DPT=(\d{1,4})")
	match = extractor.search(logMessage)
	if match is None:
		print("Couldn't match the data returned from ElasticSearch.", file=sys.stderr)
		exit(1)

	print(IPTABLES_COMMAND.format(source=match.group(1), proto=match.group(2), dport=match.group(3)))


if __name__ == "__main__":
	main()