import requests
import os
from urllib.parse import urlparse
import urllib.parse
from utils.db import Database_update
from . import sendrequest as req
from celery_app import app

dbupdate = Database_update()


def fetch_crlf_payload():   
    # This function fetch the payloads from text file.               
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/crlf.txt'
    else:
        path = 'Payloads/crlf.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list



def crlf_post_method(uri,method,headers,body,scanid=None):            
    # This function checks CRLF through POST method.
    temp_body = {}
    for key,value in list(body.items()):
        crlf_payloads = fetch_crlf_payload()
        for payload in crlf_payloads:
            temp_body.update(body)
            temp_body[key] = payload
            crlf_post_request = req.api_request(uri, "POST", headers, temp_body)
            for name in crlf_post_request.headers:
                if "CRLF-Test" in name:
                    attack_result = { "id" : 13, "scanid" : scanid, "url" : uri, "alert": "CRLF injection", "impact": "High", "req_headers": headers, "req_body": temp_body, "res_headers": crlf_post_request.headers ,"res_body": crlf_post_request.text}
                    dbupdate.insert_record(attack_result)
                    print("[+]{0} is vulnerable to CRLF injection".format(uri))
                    return



def crlf_get_uri_method(uri,method,headers,scanid=None):
    # This function checks CRLF through GET URI method.
    par_key = {}
    url_query = urllib.parse.urlparse(uri)
    parsed_query = urllib.parse.parse_qs(url_query.query)
    for key,value in list(parsed_query.items()):
        crlf_payloads = fetch_crlf_payload()
        for payload in crlf_payloads:
            par_key.update(parsed_query)
            par_key[key] = payload
            parsed_uri = urllib.parse.urlparse(uri).scheme+"://"+urllib.parse.urlparse(uri).netloc+urllib.parse.urlparse(uri).path+"?"+urllib.parse.urlparse(uri).query.replace(value[0], payload)
            crlf_get_method = req.api_request(parsed_uri, "GET", headers)
            for name in crlf_get_method.headers:
                if "CRLF-Test" in name:
                    attack_result = { "id" : 13, "scanid" : scanid, "url" : parsed_uri, "alert": "CRLF injection", "impact": "High", "req_headers": headers, "req_body":"NA", "res_headers": crlf_get_method.headers ,"res_body": crlf_get_method.text}
                    dbupdate.insert_record(attack_result)
                    print("[+]{0} is vulnerable to CRLF injection".format(parsed_uri))
                    return



def crlf_get_url_method(uri,headers,scanid=None):
    # This function checks CRLF through GET URL method.
    crlf_payloads = fetch_crlf_payload()
    for payload in crlf_payloads:
        parsed_uri = urllib.parse.urlparse(uri).scheme+"://"+urllib.parse.urlparse(uri).netloc+urllib.parse.urlparse(uri).path+"/"+payload
        crlf_get_method = req.api_request(parsed_uri, "GET", headers)
        for name in crlf_get_method.headers:
            if "CRLF-Test" in name:
                attack_result = { "id" : 13, "scanid" : scanid, "url" : parsed_uri, "alert": "CRLF injection", "impact": "High", "req_headers": headers, "req_body":"NA", "res_headers": crlf_get_method.headers ,"res_body": crlf_get_method.text}
                dbupdate.insert_record(attack_result)
                print("[+]{0} is vulnerable to CRLF injection".format(parsed_uri))
                return

@app.task
def crlf_check(uri,method,headers,body,scanid):
     # Main function for CRLF attack
    if method == 'GET' or method == 'DEL':
        crlf_get_uri_method(uri,method,headers,scanid)
        crlf_get_url_method(uri,headers,scanid)

    if method == 'POST' or method == 'PUT':
        crlf_post_method(uri,method,headers,body,scanid)
             