import requests
import time
import utils.logger as logger
import utils.logs as logs
import base64
from . import sendrequest as req

from urllib.parse import urlparse
from utils.db import Database_update
from celery_app import app

dbupdate = Database_update()
api_logger = logger.logger()

def cors_check(origin,resheaders):
	# This function check if the API is vulnerable to Cross domain attack. 
	result = {}
	if all (k in resheaders for k in ("Access-Control-Allow-Origin","Access-Control-Allow-Credentials")):
		allow_origin_header = resheaders['Access-Control-Allow-Origin']
		if origin.lower() == allow_origin_header.lower() or origin.lower() == allow_origin_header[allow_origin_header.find('://')+3:].lower():
			if resheaders['Access-Control-Allow-Credentials'] == 'true':
				result.update({"impact" : "High"})
			else:
				result.update({"impact" : "Low"})
		elif allow_origin_header == '*':
			result.update({"impact" : "Low"})

	elif 'Access-Control-Allow-Origin' in resheaders:
		result.update({"impact" : "Low"})

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
	origin = 'http://attackersite.com'
	if protocol == 'https':
	    origin = 'https://attackersite.com'

	domain_name = urlparse(url).hostname
	postfixurl = domain_name+'.attackersite.com'
	origin_headers.append(origin)
	origin_headers.append(postfixurl)
	logs.logging.info("Origin headers: %s",origin_headers)
	return origin_headers

@app.task
def cors_main(url,method,headers,body,scanid=None):
	temp_headers = {}
	temp_headers.update(headers)
	origin_headers = generate_origin(url)
	logs.logging.info("List of origin headers: %s",origin_headers)
	for origin in origin_headers:
		origin_header = {"origin" : origin}
		temp_headers.update(origin_header)
		if method.upper() == 'GET' or method.upper() == 'POST' or method.upper() == "PUT":
			''' If request method is POST then browser usually sends preflight request '''
			try:
				response = req.api_request(url, "OPTIONS", temp_headers)
			except:
				response = req.api_request(url, method.upper(), temp_headers)
			result = cors_check(origin,response.headers)
			if result:	
				print("%s[+]{0} is vulnerable to cross domain attack %s ".format(url)% (api_logger.G, api_logger.W))
				attack_result = {"id" : 1, "scanid" : scanid, "url" : url, "alert": "CORS Misconfiguration", "impact": result['impact'], "req_headers": temp_headers, "req_body" : body, "res_headers": response.headers, "res_body" : "NA"}
				dbupdate.insert_record(attack_result)
				break
			
	logs.logging.info("Scan completed for cross domain attack: %s",url)
