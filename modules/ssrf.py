import time
import requests
import json
from . import sendrequest as req
import utils.logs as logs
import subprocess
import sys
import os
import tempfile
import re
from urllib.parse import urlparse
from urllib.parse import parse_qs
from celery_app import app
from utils.logger import logger
from utils.db import Database_update

dbupdate = Database_update()
api_logger = logger()

def fetch_ssrf_payload():   
    # This function fetch the payloads from text file.               
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/ssrf.txt'
    else:
        path = 'Payloads/ssrf.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list


def parse_ssrfmap(output):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    output = output.decode("unicode-escape")
    result = ansi_escape.sub('', output)
    log = []
    for line in result.split("\n"):
        if 'open' in line:
            log.append(line)
        if 'Reading file' in line:
            log.append(line) 
    return log

def create_file_content(parsed_url, method, headers, body):
    path = parsed_url.path
    base_url = parsed_url.netloc
    query = parsed_url.query
    lines = []
    if query:
        lines.append(f"{method} {path}?{query} HTTP/1.1\n")
    else:
        lines.append(f"{method} {path} HTTP/1.1\n")
    lines.append(f"Host: {base_url}\n")
    for i,j in headers.items():
        lines.append(f"{i}: {j}\n")
    lines.append(str(body))
    return lines

@app.task
def ssrf_check(url,method,headers,body,scanid=None):
    try:
        parsed_url = urlparse(url)
        common_params = fetch_ssrf_payload()
        vuln_param = 'url'
        if method == 'GET':
            params = list(parse_qs(parsed_url.query).keys())
        else:
            params = list(body.keys())
        if params:
            vuln_param = params[0]
            for param in params:
                if param in common_params:
                    vuln_param = param
                    break
        content = create_file_content(parsed_url, method, headers, body)
        with tempfile.NamedTemporaryFile(mode="w+") as temp_file:
            temp_file.writelines(content)
            temp_file.seek(0)
            fname = temp_file.name
            if parsed_url.scheme == 'https':
                # python ssrfmap.py -r data/request.txt -p url -m portscan --ssl
                logs.logging.info("SSRFmap - Scan started.")
                proc = subprocess.Popen(['python3','ssrfmap.py','-r', fname,'-p',vuln_param,'-m','portscan,readfiles'],stdout=subprocess.PIPE,cwd='./SSRFmap')
                out, err = proc.communicate(timeout=900)
                result = parse_ssrfmap(out)
                if len(result) > 0:
                    print("%s[+]{0} is vulnerable to SSRF attacks%s".format(url)% (api_logger.R, api_logger.W))
                    attack_result = { "id" : 24, "scanid" : scanid, "url" : url, "alert": "Server-side request forgery", "impact": "High", "req_headers": headers, "req_body":body, "res_headers": "NA" ,"res_body": "NA", "log" : "\n".join(result)}
                    dbupdate.insert_record(attack_result)
            else:
                                # python ssrfmap.py -r data/request.txt -p url -m portscan --ssl
                print(os.getcwd())
                f = open("./logs/ssrf.log","w+")
                logs.logging.info("SSRFmap - Scan started.")
                proc = subprocess.Popen(['python3','ssrfmap.py','-r', fname,'-p',vuln_param,'-m','portscan,readfiles'],stdout=f,cwd='./SSRFmap')
                _, err = proc.communicate(timeout=900)
                f.close()
                if err:
                    raise Exception('SSRF Exception')
                f = open("./logs/ssrf.log","rb")
                out = f.read()
                result = parse_ssrfmap(out)
                if len(result) > 0:
                    print("%s[+]{0} is vulnerable to SSRF attacks%s".format(url)% (api_logger.R, api_logger.W))
                    attack_result = { "id" : 24, "scanid" : scanid, "url" : url, "alert": "Server-side request forgery", "impact": "High", "req_headers": headers, "req_body":body, "res_headers": "NA" ,"res_body": "NA", "log" : "\n".join(result)}
                    dbupdate.insert_record(attack_result)
    
    except Exception as e:
        raise e
        logs.logging.info(e)
        
