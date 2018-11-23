import ast
import os
import json
import sys
import hashlib
import time
import json
import threading
import logging
import requests
import socket
import urlparse
import re

from dbconnection import db_connect
from scanstatus import check_scan_status, scan_status

sys.path.append('../')

from flask import Flask, render_template, send_from_directory
from flask import Response, make_response
from flask import request
from flask import Flask
from flask import jsonify
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError



from utils.vulnerabilities import alerts
#from utils.sendemail import send_email
from jinja2 import utils
from utils.email_cron import send_email_notification


if os.getcwd().split('/')[-1] == 'API':
    from astra import scan_single_api, scan_postman_collection


app = Flask(__name__, template_folder='../Dashboard/templates', static_folder='../Dashboard/static')


class ServerThread(threading.Thread):

  def __init__(self):
    threading.Thread.__init__(self)

  def run(self):
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port= 8094)


db_object = db_connect()
global db
db = db_object.apiscan


############################# Start scan API ######################################
def generate_hash():
    # Return md5 hash value of current timestmap 
    scanid = hashlib.md5(str(time.time())).hexdigest()
    return scanid

def xss_filter(data):
    data = str(data)
    # Filter special chars to prevent XSS
    filterd_data =  data.replace("<","&lt;").replace(">","&gt;")
    try:
        filterd_data = ast.literal_eval(filterd_data)
    except:
        pass

    return filterd_data

# Start the scan and returns the message
@app.route('/scan/', methods = ['POST'])
def start_scan():
    scanid = generate_hash()
    content = request.get_json()
    try:
        name = content['appname']
        url = str(content['url'])
        headers = str(content['headers'])
        body = str(content['body'])
        method = content['method']
        api = "Y"
        scan_status = scan_single_api(url, method, headers, body, api, scanid)
        if scan_status is True:
            # Success
            msg = {"status" : scanid}
            try:
                db.scanids.insert({"scanid" : scanid, "name" : name, "url" : url})
            except:
                print "Failed to update DB"
        else:
            msg = {"status" : "Failed"}
    
    except:
        msg = {"status" : "Failed"} 
    
    return jsonify(msg)


@app.route('/scan/scanids/', methods=['GET'])
def fetch_scanids():
    scanids = []
    records = db.scanids.find({})
    if records:
        for data in records:
            data.pop('_id')
            try:
                data =  ast.literal_eval(json.dumps(data))
                scan_status = check_scan_status(data)
                if data['scanid']:
                    if data['scanid'] not in scanids:
                        url = xss_filter(data['url'])
                        scanids.append({"scanid" : data['scanid'], "name" : xss_filter(data['name']), "url" : url, "scan_status" : scan_status}) 
            except:
                pass

        return jsonify(scanids)

############################# Alerts API ##########################################

# Returns vulnerbilities identified by tool 
def fetch_records(scanid):
    # Return alerts identified by the tool
    vul_list = []
    records = db.vulnerabilities.find({"scanid":scanid})
    if records:
        for data in records:  
            if data['req_body'] == None:
                data['req_body'] = "NA" 

            data.pop('_id')
            try:
                data =  ast.literal_eval(json.dumps(data))
            except Exception as e:
                print "Falied to parse",e
            
            try:
                if data['id'] == "NA":
                    all_data = {'url' : data['url'], 'impact' : data['impact'], 'name' : data['name'], 'req_headers' : data['req_headers'], 'req_body' : data['req_body'], 'res_headers' : data['res_headers'], 'res_body' : data['res_body'], 'Description' : data['Description'], 'remediation' : data['remediation']}
                    vul_list.append(all_data)

                if data['id']:
                    for vul in alerts:
                        if data['id'] == vul['id']:
                            #print "response body",data['req_headers'],type(data['req_headers'])
                            all_data = {
                                        'url' : xss_filter(data['url']),
                                        'impact' : data['impact'],
                                        'name' : xss_filter(data['alert']),
                                        'req_headers' : data['req_headers'],
                                        'req_body' : xss_filter(data['req_body']),
                                        'res_headers' : xss_filter(data['res_headers']),
                                        'res_body' : xss_filter(data['res_body']),
                                        'Description' : vul['Description'],
                                        'remediation' : vul['remediation']
                                        }
                            vul_list.append(all_data)
                            break

            except:
                pass

        return vul_list        

@app.route('/alerts/<scanid>', methods=['GET'])
def return_alerts(scanid):
    result = fetch_records(scanid)
    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

#############################Dashboard#########################################

@app.route('/', defaults={'page': 'scan.html'})
@app.route('/<page>')
def view_dashboard(page):
    return render_template('{}'.format(page))

def start_server():
    app.run(host='0.0.0.0', port= 8094)


############################Postman collection################################

def postman_collection_download(url):
    # Download postman collection from URL
    postman_req = requests.get(url,allow_redirects=True, verify=False)
    try:
        filename = url[url.rfind("/")+1:]+"_"+generate_hash()
        open("../Files/"+filename, 'wb').write(postman_req.content)
        return "../Files/"+filename
    except:
        return False


def verify_email(email):
    # credit : www.scottbrady91.com
    match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)
    return match


@app.route('/scan/postman/', methods = ['POST'])
def scan_postman():
    content = request.get_json()
    try:
        # mandatory inputs
        appname = content['appname']
        postman_url = content['postman_url']
        env_type = content['env_type']
        if "email" in content.keys():
            email_verify_result = verify_email(content['email'])
            if email_verify_result == None:
                # Not a valid email id
                email = "NA"
            else:
                email = content['email']
        else:
            email = "NA"

        try:
            # IP address param is optional.
            url = "NA"
            if "ip" in content.keys():
                url = content['ip']
                if urlparse.urlparse(url).scheme == "http" or urlparse.urlparse(url).scheme == "https":
                    ip = urlparse.urlparse(url).netloc
                    socket.inet_aton(ip)
                    ip_result = 1

            else:
                ip_result = 0
        except:
            print "Missing Arugument or invalid IP address!"
            ip_result = 0


        result = postman_collection_download(postman_url)

        if result is False:
            msg = {"status" : "Failed to Download Postman collection"}
            return msg
        else:
            try:
                scan_id = generate_hash()
                db.scanids.insert({"scanid" : scan_id, "name" : appname, "url" : postman_url,"env_type": env_type, "url" : url,"email" : email})
                if ip_result == 1:
                    scan_result = scan_postman_collection(result,scan_id,url)
                else:
                    scan_result = scan_postman_collection(result,scan_id)
            except:
                #Failed to update the DB
                pass

            if scan_result == True:
                 # Update the email notification collection 
                db.email.insert({"email" : email, "scanid" : scan_id, "to_email" : email, "email_notification" : 'N'})
                msg = {"status" : "Success", "scanid" : scan_id}
            else:
                msg = {"status" : "Failed!"}
            

    except:
        msg = {"status" "Failed. Application name and postman URL is required!"}

    return jsonify(msg)

def main():
    if os.getcwd().split('/')[-1] == 'API':
        start_server()
    else:
        thread = ServerThread()
        thread.daemon = True
        thread.start()


@app.route('/robots.txt', methods=['GET'])
def robots():
    return send_from_directory(app.static_folder, "robots.txt")

main()