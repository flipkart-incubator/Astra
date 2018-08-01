import requests
import os
from urlparse import urlparse
import urlparse
from utils.db import Database_update
import sendrequest as req

dbupdate = Database_update()


def fetch_crlf_payload():   
    #This function fetch the payloads from text file.               
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/crlf.txt'
    else:
        path = '../Payloads/crlf.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list



def crlf_post_method(uri,method,headers,body,scanid=None):            
    # This function checks CRLF through POST method.
    temp_body = {}
    post_vul_param = ''
    db_update = ''
    for key,value in body.items():
        crlf_payloads = fetch_crlf_payload()
        for payload in crlf_payloads:
            temp_body.update(body)
            temp_body[key] = payload
            crlf_post_request = req.api_request(uri, "POST", headers, temp_body)
            #print temp_body
            for name in crlf_post_request.headers:
                if "CRLF-Test" in name:
                    attack_result = { "id" : 13, "scanid" : scanid, "url" : uri, "alert": "CRLF injection", "impact": "High", "req_headers": headers, "req_body": temp_body, "res_headers": crlf_post_request.headers ,"res_body": crlf_post_request.text}
                    dbupdate.insert_record(attack_result)
                    print "[+] Vulnerable: %s, Body: %s" %(uri, temp_body)
                    return
             
    print "\n scan is completed-1 \n"



def crlf_get_uri_method(uri,method,headers,scanid=None):
    # This function checks CRLF through GET URI imethod.
    par_key = {}
    url_query = urlparse.urlparse(uri)
    parsed_query = urlparse.parse_qs(url_query.query)
    for key,value in parsed_query.items():
        crlf_payloads = fetch_crlf_payload()
        for payload in crlf_payloads:
            par_key.update(parsed_query)
            par_key[key] = payload
            parsed_uri_1 = urlparse.urlparse(uri).scheme+"://"+urlparse.urlparse(uri).netloc+urlparse.urlparse(uri).path+"?"+urlparse.urlparse(uri).query.replace(value[0], payload)
            crlf_get_method = req.api_request(parsed_uri_1, "GET", headers)
            for name in crlf_get_method.headers:
                if "CRLF-Test" in name:
                    attack_result = { "id" : 13, "scanid" : scanid, "url" : parsed_uri_1, "alert": "CRLF injection", "impact": "High", "req_headers": headers, "req_body":"NA", "res_headers": crlf_get_method.headers ,"res_body": crlf_get_method.text}
                    dbupdate.insert_record(attack_result)
                    print "[+] Vulnerable: %s, query: %s" % (uri, par_key)
                    return
             
    print "\n scan is completed-2 \n"



def crlf_get_url_method(uri,headers,scanid=None):
    #This function checks CRLF through GET URL imethod.
    crlf_payloads = fetch_crlf_payload()
    for payload in crlf_payloads:
        parsed_uri = urlparse.urlparse(uri).scheme+"://"+urlparse.urlparse(uri).netloc+urlparse.urlparse(uri).path+"/"+payload
        crlf_get_method = req.api_request(parsed_uri, "GET", headers)
        print("\n")
        for name in crlf_get_method.headers:
            if "CRLF-Test" in name:
                attack_result = { "id" : 13, "scanid" : scanid, "url" : parsed_uri, "alert": "CRLF injection", "impact": "High", "req_headers": headers, "req_body":"NA", "res_headers": crlf_get_method.headers ,"res_body": crlf_get_method.text}
                dbupdate.insert_record(attack_result)
                print "[+] Vulnerable: %s" % (parsed_uri)
                return
             
    print "\n scan is completed-3 \n"



def crlf_check(uri,method,headers,body,scanid):
     # Main function for CRLF attack
    if method == 'GET' or method == 'DEL':
        crlf_get_uri_method(uri,method,headers,scanid)
        crlf_get_url_method(uri,headers,scanid)

    if method == 'POST' or method == 'PUT':
        crlf_post_method(uri,method,headers,body,scanid)
     

        