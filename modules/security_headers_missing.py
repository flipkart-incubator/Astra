import re

from utils.logger import logger
from utils.db import Database_update
from . import sendrequest as req
from celery_app import app

dbupdate = Database_update()
api_logger = logger()

def csp_check(url, method, req_headers, req_body, scan_id, res_headers, res_body):
	# checks if csp header is implemented
	if 'Content-Security-Policy' not in res_headers:
		attack_result = { "id" : 15, "scanid" : scan_id, "url" : url, "alert": "CSP Header Missing", "impact": "Low", "req_headers": req_headers, "req_body": req_body, "res_headers": res_headers ,"res_body": res_body}
		dbupdate.insert_record(attack_result)
	    
def xss_protection_check(url, method, req_headers, req_body, scan_id, res_headers, res_body):
	# checks if xss-protection is enabled and configured correctly
	if 'X-XSS-Protection' not in res_headers:
		attack_result = { "id" : 16, "scanid" : scan_id, "url" : url, "alert": "X-XSS-Protection Header Missing", "impact": "Low", "req_headers": req_headers, "req_body": req_body, "res_headers": res_headers ,"res_body": res_body}
		dbupdate.insert_record(attack_result)
	else:
		xss_protection = res_headers['X-XSS-Protection']
		xss_protection = str(xss_protection.replace(" ", "")) # remove space
		if xss_protection == "0":
			attack_result = { "id" : 17, "scanid" : scan_id, "url" : url, "alert": "X-XSS-Protection Header Disabled", "impact": "Low", "req_headers": req_headers, "req_body": req_body, "res_headers": res_headers ,"res_body": res_body}
			dbupdate.insert_record(attack_result)
		elif xss_protection != "1;mode=block": 
			attack_result = { "id" : 18, "scanid" : scan_id, "url" : url, "alert": "X-XSS-Protection Header not securly implemented", "impact": "Low", "req_headers": req_headers, "req_body": req_body, "res_headers": res_headers ,"res_body": res_body}
			dbupdate.insert_record(attack_result)

def x_frame_options_check(url, method, req_headers, req_body, scan_id, res_headers, res_body):
	# check if X-Frame-Options header is present
	if 'X-Frame-Options' not in res_headers:
		attack_result = { "id" : 19, "scanid" : scan_id, "url" : url, "alert": "X-Frame-Options Header Missing", "impact": "Low", "req_headers": req_headers, "req_body": req_body, "res_headers": res_headers ,"res_body": res_body}
		dbupdate.insert_record(attack_result)
'''
def x_content_type_options_check(url, method, req_headers, req_body, scan_id, res_headers, res_body):
	# check if Content-Type-Options header is present
	if 'X-Content-Type-Options' not in res_headers:
		attack_result = { "id" : 20, "scanid" : scan_id, "url" : url, "alert": "X-Content-Type-Options Header Missing", "impact": "Low", "req_headers": req_headers, "req_body": req_body, "res_headers": res_headers ,"res_body": res_body}
		dbupdate.insert_record(attack_result)
'''
def hsts_check(url, method, req_headers, req_body, scan_id, res_headers, res_body):
	# check if Strict-Transport-Security header is present
	if 'Strict-Transport-Security' not in res_headers:
		attack_result = { "id" : 21, "scanid" : scan_id, "url" : url, "alert": "Strict-Transport-Security Header Missing", "impact": "Low", "req_headers": req_headers, "req_body": req_body, "res_headers": res_headers ,"res_body": res_body}
		dbupdate.insert_record(attack_result)
	
def cookies_check(cookies, url, method, req_headers, req_body, scan_id, res_headers, res_body):
	# check if cookies are marked secure and httponly
	for cookie in cookies:
		if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
			attack_result = { "id" : 22, "scanid" : scan_id, "url" : url, "alert": "Cookie not marked secure or httponly", "impact": "Low", "req_headers": req_headers, "req_body": req_body, "res_headers": res_headers ,"res_body": res_body}
			dbupdate.insert_record(attack_result)
			break

def check_version_disclosure(url, method, req_headers, req_body, scan_id, res_headers, res_body):
	# check if any of the headers in the list discloses version information
	version_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
	for each_version_header in version_headers:
		if each_version_header in res_headers:
			header_value = res_headers[each_version_header]
			if bool(re.search('\d', header_value)):    #checks if the header has any digit.  
				attack_result = { "id" : 23, "scanid" : scan_id, "url" : url, "alert": "Server Version Disclosure", "impact": "Low", "req_headers": req_headers, "req_body": req_body, "res_headers": res_headers ,"res_body": res_body}
				dbupdate.insert_record(attack_result)
				break

@app.task
def security_headers_missing(url, method, headers, body, scan_id=None):
	# checks if a security header is missing
	resp = req.api_request(url, method, headers, body)
	res_headers = resp.headers
	res_body = resp.text
	cookies =  resp.cookies
	csp_check(url, method, headers, body, scan_id, res_headers, res_body)
	xss_protection_check(url, method, headers, body, scan_id, res_headers, res_body)
	x_frame_options_check(url, method, headers, body, scan_id, res_headers, res_body)
	#x_content_type_options_check(url, method, headers, body, scan_id, res_headers, res_body)
	hsts_check(url, method, headers, body, scan_id, res_headers, res_body)
	cookies_check(cookies, url, method, headers, body, scan_id, res_headers, res_body)
	check_version_disclosure(url, method, headers, body, scan_id, res_headers, res_body)
	

