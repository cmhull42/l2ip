#!/usr/bin/python
from __future__ import print_function
import requests, sys, argparse, re

class ElasticSearchMessage:
	IPTABLES_COMMAND = "IPTABLES -A INPUT -p {proto} -m {proto} -s {source} --dport {dport} -m state --state NEW -j ACCEPT"
	""" represents a message returned from elasticsearch"""
	def __init__(self, message):
		self.message = message


	def toIptables(self):
		"""returns the iptables command or None if the message doesn't contain the required information"""

		extractor = re.compile("SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?PROTO=(TCP|UDP).*?DPT=(\d{1,4})")
		match = extractor.search(self.message["_source"]["message"])
		if match is None:
			return None

		return self.IPTABLES_COMMAND.format(source=match.group(1), proto=match.group(2), dport=match.group(3))

class LogRetriever:
	"""handles querying elasticsearch for messages. apiUrl should have named format groups date, id, and port
		 see API_URL for an example"""
	def __init__(self, port, apiUrl):
		self.port = port
		self.apiUrl = apiUrl

	def retrieveMessageJson(self, date, id):
		"""makes a request to apiUrl for the given date and id
			 returns the response as JSON or None if not found"""
		resp = requests.get(self.apiUrl.format(date=date, id=id, port=self.port))
		if resp.status_code == 404:
			return None

		return resp.json()


def main():
	parser = argparse.ArgumentParser(description="Parses logs from elasticsearch into iptables commands.")
	parser.add_argument("-d", dest="date", required=True, help="The date to pass to elasticsearch")
	parser.add_argument("-i", dest="id", required=True, help="The elastisearch messageID")
	args = parser.parse_args()

	logRetriever = LogRetriever(LOG_PORT, API_URL)
	fullMessage = logRetriever.retrieveMessageJson(args.date, args.id)
	match = ElasticSearchMessage(fullMessage).toIptables()

	if match is None:
		print("Couldn't match the data returned from ElasticSearch.", file=sys.stderr)
		exit(1)

	print(match)


if __name__ == "__main__":
	LOG_PORT = 80
	API_URL = "http://demo4341911.mockable.io:{port}/logstash-{date}/iptables/{id}"
	main()