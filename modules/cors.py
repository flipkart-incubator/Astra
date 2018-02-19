import requests
import time
import utils.logger as logger
import utils.logs as logs
import base64

from urlparse import urlparse
from utils.db import Database_update


dbupdate = Database_update()
api_logger = logger.logger()


def cors_check(origin,resheaders):
	# This function check if the API is vulnerable to Cross domain attack. 
	result = {}
	for key,value in resheaders.items():
		if key == 'Access-Control-Allow-Origin':
			if origin.lower() == value.lower() or origin.lower() == key[key.find('://')+3:].lower():
				result.update({"Access-Control-Allow-Origin" : value})
		 	elif 'Access-Control-Allow-Origin' == '*':
				result.update({"Access-Control-Allow-Origin" : '*'})

		elif key == 'Access-Control-Allow-Credentials':
			if value.lower() == 'true':
				result.update({"Access-Control-Allow-Credentials" : "True"})
	
	if result:
		if "Access-Control-Allow-Origin" and "Access-Control-Allow-Credentials" in result:
			result.update({"impact" : "High"})
		elif "Access-Control-Allow-Origin" in result:
			# if Access-Control-Allow-Credentials is not present in http response then browser won't send cookie value therefore the impact is low. 
			result.update({"impact" : "low"})

		return result

def check_custom_header(url, header_name):
	# Check if custom header is allowed to send. 
	request_header = {'Access-Control-Request-Headers' : header_name}
	req_custom_header = requests.options(url, header_name,verify=False)
	try:
		if req_custom_header.headers['Access-Control-Allow-Headers'] == header_name:
			return True
		else:
			return False
	except:
		return False


def generate_origin(url):
	# This function deals with generating different possible origin URLS. 
	origin_headers = []
	protocol = url[:url.find(':')]
	if protocol == 'http':
		origin = protocol+'://attackersite.com'
	if protocol == 'https':
	    origin = protocol+'://attackersite.com'

	domain_name = urlparse(url).hostname
	postfixurl = domain_name+'.attackersite.com'
	origin_headers.append(origin)
	origin_headers.append(postfixurl)
	return origin_headers

def cors_main(url,method,headers,body,scanid=None):
	origin_headers = generate_origin(url)
	logs.logging.info("List of origin headers: %s",origin_headers)
	for origin in origin_headers:
		origin_header = {"origin" : origin}
		headers.update(origin_header)
		if method.upper() == 'GET' or method.upper() == 'POST' or method.upper() == "PUT":
			''' If request method is POST then browser usually sends preflight request '''
			option_response = requests.options(url,headers=headers,verify=False)
			result = cors_check(origin,option_response.headers)
			if result:	
				print "%s[+]{0} is vulnerable to cross domain attack %s ".format(url)% (api_logger.G, api_logger.W)
				attack_result = {
						 "id" : 1,
						 "scanid" : scanid,
						 "url" : url,
						 "alert": "CORS Misconfiguration",
						 "impact": result['impact'],
						 "req_headers": headers,
						 "req_body" : body,
						 "res_headers": option_response.headers,
						 "res_body" : "NA"

				}

				dbupdate.insert_record(attack_result)
				break

	logs.logging.info("Scan completed for cross domain attack: %s",url)
