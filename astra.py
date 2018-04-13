import argparse
import base64
import json
import requests
import time
import ast
import utils.logger as logger
import utils.logs as logs
import urlparse


from core.zapscan import *
from core.parsers import *
from utils.logger import *
from core.login import APILogin
from utils.logger import logger
from utils.config import update_value,get_value,get_allvalues
from modules.cors import cors_main
from modules.auth import auth_check
from modules.rate_limit import rate_limit
from modules.csrf import csrf_check
from modules.jwt_attack import jwt_check
from modules.sqli import sqli_check
from modules.xss import xss_check
from modules.redirect import open_redirect_check
from core.zap_config import zap_start
from multiprocessing import Process
from utils.db import Database_update

dbupdate = Database_update()

def parse_collection(collection_name,collection_type):
    if collection_type == 'Postman':
        parse_data.postman_parser(collection_name)
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


def read_scan_policy():
    try:
        scan_policy = get_value('scan.property','scan-policy','attack')
        attack = ast.literal_eval(scan_policy)

    except Exception as e:
        print e
        print "Failed to parse scan property file."

    return attack

def update_scan_status(scanid, module_name=None, count=None):
    #Update scanning status and total scan of module into DB.
    time.sleep(3)
    if count is not None:
        dbupdate.update_scan_record({"scanid": scanid}, {"$set" : {"total_scan" : count}})
    else:
        dbupdate.update_scan_record({"scanid": scanid}, {"$set" : {module_name : "Y"}})


def modules_scan(url,method,headers,body,scanid=None):
    '''Scanning API using different engines '''
    attack = read_scan_policy()
    if attack is None:
        print "Failed to start scan."
        sys.exit(1)

    if scanid is not None:
        count = 0
        for key,value in attack.items():
            if value == 'Y' or value =='y':
                count += 1
        update_scan_status(scanid,"",count)


    if attack['zap'] == "Y" or attack['zap'] == "y":
        api_scan = zap_scan()
        status = zap_start()
        if status is True:
            api_scan.start_scan(url,method,headers,body,scanid)
    # Custom modules scan
    if attack['cors'] == 'Y' or attack['cors'] == 'y':
        cors_main(url,method,headers,body,scanid)
        update_scan_status(scanid, "cors")
    if attack['Broken auth'] == 'Y' or attack['Broken auth'] == 'y':
        auth_check(url,method,headers,body,scanid)
        update_scan_status(scanid, "auth")
    if attack['Rate limit'] == 'Y' or attack['Rate limit'] == 'y':
        rate_limit(url,method,headers,body,scanid)
        update_scan_status(scanid, "Rate limit")
    if attack['csrf'] == 'Y' or attack['csrf'] == 'y':
        csrf_check(url,method,headers,body,scanid)
        update_scan_status(scanid, "csrf")
    if attack['jwt'] == 'Y' or attack['jwt'] == 'y':
        jwt_check(url,method,headers,body,scanid)
        update_scan_status(scanid, "jwt")
    if attack['sqli'] == 'Y' or attack['sqli'] == 'y':
        sqli_check(url,method,headers,body,scanid)
        update_scan_status(scanid, "sqli")
    if attack['xss'] == 'Y' or attack['xss'] == 'y':
        xss_check(url,method,headers,body,scanid)
        update_scan_status(scanid, "xss")
    if attack['open-redirection'] == 'Y' or attack['open-redirection'] == 'y':
        open_redirect_check(url,method,headers,body,scanid)
        update_scan_status(scanid, "open-redirection") 


def validate_data(url,method):
    ''' Validate HTTP request data and return boolean value'''
    validate_url = urlparse.urlparse(url)
    http_method = ['GET','POST','DEL','OPTIONS','PUT']
    if method in http_method and bool(validate_url.scheme) is True:
        validate_result = True
    else:
        validate_result = False

    return validate_result

def scan_single_api(url, method, headers, body, api, scanid=None):
    ''' This function deals with scanning a single API. '''
    if headers is None or headers == '':
            headers = {'Content-Type' : 'application/json'}
    if type(headers) is not dict:
        headers = ast.literal_eval(headers)
    if method == '':
        method = 'GET'

    result = validate_data(url, method)
    if result is False:
        print "[-]Invalid Arguments"
        return False

    p = Process(target=modules_scan,args=(url,method,headers,body,scanid),name='module-scan')
    p.start()
    if api == "Y":
        return True


def scan_core(collection_type,collection_name,url,headers,method,body,loginurl,loginheaders,logindata,login_require):
    ''' Scan API through different engines ''' 
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
                    pass

            if data['body'] != '':
                body = json.loads(base64.b64decode(data['body']))

            
            modules_scan(url,method,headers,body,scanid)        

    else:
        print "%s [-]Invalid Collection. Please recheck collection Type/Name %s" %(api_logger.G, api_logger.W)
    #generate_report()

def get_arg(args=None):
        parser = argparse.ArgumentParser(description='Astra - REST API Security testing Framework')
        parser.add_argument('-c', '--collection_type',
                            help='Type of API collection',
                            default='Postman')
        parser.add_argument('-n', '--collection_name',
                            help='Type of API collection')
        parser.add_argument('-u', '--url',
                            help='URL of target API')
        parser.add_argument('-headers', '--headers',
                            help='Custom headers.Example: {"token" : "123"}')
        parser.add_argument('-method', '--method',
                            help='HTTP request method',
                            default='GET',choices=('GET', 'POST', 'PUT','DELETE'))
        parser.add_argument('-b', '--body',
                            help='Request body of API')
        parser.add_argument('-l', '--loginurl',
                            help='URL of login API')
        parser.add_argument('-H', '--loginheaders',
                            help='Headers should be in a dictionary format. Example: {"accesstoken" : "axzvbqdadf"}')
        parser.add_argument('-d', '--logindata',
                            help='login data of API')
    

        results = parser.parse_args(args)
        if len(args) == 0:
            print "%sAt least one argument is needed to procced.\nFor further information check help: %spython astra.py --help%s"% (api_logger.R, api_logger.G, api_logger.W)
            sys.exit(1)

        return (results.collection_type,
                results.collection_name,
                results.url,
                results.headers,
                results.method,
                results.body,
                results.loginurl,
                results.loginheaders,
                results.logindata,
                )

def main():
    collection_type,collection_name,url,headers,method,body,loginurl,loginheaders,logindata = get_arg(sys.argv[1:])
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
    elif url and collection_name and headers:
        #Custom headers
        update_value('login','header',headers)
        login_require = False
    elif url:
        if headers is None:
            headers = {'Content-Type' : 'application/json'}
        if method is None:
            method = "GET"
       
        login_require = False
    else:
        login_require = True

    if body:
        body = ast.literal_eval(body)

    # Configuring ZAP before starting a scan
    get_auth = get_value('config.property','login','auth_type')

    if collection_type and collection_name is not None:
        scan_core(collection_type,collection_name,url,headers,method,body,loginurl,loginheaders,logindata,login_require) 
    else:
        scan_single_api(url, method, headers, body, "False")


if __name__ == '__main__':
    api_login = APILogin()
    parse_data = PostmanParser()
    api_logger = logger()
    api_logger.banner()
    main()