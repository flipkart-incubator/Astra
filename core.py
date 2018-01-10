import argparse
import base64
import json
import requests
import time
import ast
import utils.logger as logger
import utils.logs as logs

from apiscan import *
from core.parsers import *
from utils.logger import *
from core.login import APILogin
from utils.logger import logger
from utils.config import update_value,get_value,get_allvalues
from modules.cors import cors_main
from modules.auth import auth_check
from modules.rate_limit import rate_limit
from modules.csrf import csrf_check
from core.zap_config import zap_start


def parse_collection(collection_name,collection_type):
    if collection_type == 'Postman':
        parse_data.postman_parser(collection_name)
    elif collection_type == 'Swagger':
        print collection_type
    else:
        print "[-]Failed to Parse collection"
        sys.exit(1)

def add_headers(headers):
    # This function deals with adding custom header and auth value .
    get_auth = get_value('config.property','login','auth_type')
    if get_auth == 'cookie':
        cookie = get_value('config.property','login','auth')
        cookie_dict = ast.literal_eval(cookie)
        cookie_header = {'Cookie': cookie_dict['cookie']}
        headers.update(cookie_header)
    try:
        custom_header = get_value('config.property','login','headers')
        custom_header = ast.literal_eval(custom_header)
        headers.update(custom_header)
    except:
        pass

    return headers

def generate_report():
    # Generating report once the scan is complete.
    result = api_scan.generate_report()
    if result is True:
        print "%s[+]Report is generated successfully%s"% (api_logger.G, api_logger.W)
    else:
        print "%s[-]Failed to generate a report%s"% (api_logger.R, api_logger.W)

def scan_core(collection_type,collection_name,url,Headers,data,method,login_require):
    #Scan API through different engines
    if collection_type and collection_name is not None:
        parse_collection(collection_name,collection_type)
        if login_require is True:
            api_login.verify_login(parse_data.api_lst)
        msg = True
        for data in parse_data.api_lst:
            try:
                url = data['url']['raw']
            except:
                url = data['url']
            headers,method,body = data['headers'],data['method'],''
            if headers:
                try:
                    headhers = add_headers(headers)
                except:
                    #Failed to add header 
                    pass

            if data['body'] != '':
                body = json.loads(base64.b64decode(data['body']))

            scan_policy = get_value('scan.property','scan-policy','attack')
            attack = ast.literal_eval(scan_policy)
            print attack
            # Scanning API using different engines

            # check if the ZAP is started properly 
            #if status is True:
            #    api_scan.start_scan(url,method,headers,body)
                
            if attack['cors'] == 'Y' or attack['cors'] == 'y':
                cors_main(url,method,headers,body)
            if attack['Broken auth'] == 'Y' or attack['Broken auth'] == 'y':
                auth_check(url,method,headers,body)
            if attack['Rate limit'] == 'Y' or attack['Rate limit'] == 'y':
                rate_limit(url,method,headers,body)
            if attack['csrf'] == 'Y' or attack['csrf'] == 'y':
                csrf_check(url,method,headers,body)
            
            #auth_check(url,method,headers,body)

            
    elif url:
        api_scan.start_scan(url,method,Headers,data)
    else:
        print "%s [-]Invalid Collection. Please recheck collection Type/Name %s" %(api_logger.G, api_logger.W)
    #generate_report()

def get_arg(args=None):
        parser = argparse.ArgumentParser(description='REST API Security testing Framework')
        parser.add_argument('-c', '--collection_type',
                            help='Type of API collection',
                            default='Postman',choices=('Postman', 'Swagger'))
        parser.add_argument('-n', '--collection_name',
                            help='Type of API collection')
        parser.add_argument('-u', '--url',
                            help='URL of target API')
        parser.add_argument('-l', '--loginurl',
                            help='URL of login API')
        parser.add_argument('-H', '--loginheaders',
                            help='Headers should be in a dictionary format. Example: {"accesstoken" : "axzvbqdadf"}')
        parser.add_argument('-d', '--logindata',
                            help='login data of API')
        parser.add_argument('-headers', '--headers',
                            help='Custom headers.Example: {"token" : "123"}')
        parser.add_argument('-m', '--loginmethod',
                            help='HTTP request method',
                            default='GET',choices=('GET', 'POST'))
       
        results = parser.parse_args(args)
        return (results.collection_type,
                results.collection_name,
                results.loginurl,
                results.loginheaders,
                results.logindata,
                results.loginmethod,
                results.headers)

def main():
    collection_type,collection_name,loginurl,loginheaders,logindata,loginmethod,headers = get_arg(sys.argv[1:])
    if loginheaders is None:
            loginheaders = {'Content-Type' : 'application/json'}
    if collection_type and collection_name and loginurl and loginmethod and logindata:
        # Login data is given as an input. 
        api_login.fetch_logintoken(loginurl,loginmethod,loginheaders,logindata)
        login_require = False
    elif collection_type and collection_name and loginurl:
        # This will first find the given loginurl from collection and it will fetch auth token. 
        parse_collection(collection_name,collection_type)
        try:
            loginurl,lognheaders,loginmethod,logidata = api_login.parse_logindata(loginurl)
        except:
           print "[-]%s Failed to detect login API from collection %s " %(api_logger.R, api_logger.W)
           sys.exit(1)
        api_login.fetch_logintoken(loginurl,loginmethod,loginheaders,logindata)
        login_require = False
    elif loginurl and loginmethod:
        api_login.fetch_logintoken(loginurl,loginmethod,loginheaders,logindata)
        login_require = False
    elif collection_type and collection_name and headers:
        #Custom headers
        update_value('login','header',headers)
        login_require = False
    else:
        login_require = True

    # Configuring ZAP before starting a scan
    global status
    status = zap_start()

    scan_core(collection_type,collection_name,loginurl,loginheaders,logindata,loginmethod,login_require) 


if __name__ == '__main__':
    
    api_scan = zap_scan()
    api_login = APILogin()
    parse_data = PostmanParser()
    api_logger = logger()
    api_logger.banner()
    main()