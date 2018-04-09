import ast
import json
import sys
import hashlib
import time

sys.path.append('../')

from flask import Flask, render_template
from flask import Response, make_response
from flask import request
from flask import Flask
from astra import scan_single_api
from flask import jsonify
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from utils.vulnerabilities import alerts

app = Flask(__name__, template_folder='../Dashboard/templates', static_folder='../Dashboard/static')

# Mongo DB connection
maxSevSelDelay = 1
try:
    client = MongoClient('localhost', 27017, serverSelectionTimeoutMS=maxSevSelDelay)
    client.server_info()
except ServerSelectionTimeoutError as err:
    exit("DB not connected Please Install Mongo")

global db
db = client.apiscan


############################# Start scan API ######################################
def generate_hash():
    # Return md5 hash value of current timestmap 
    scanid = hashlib.md5(str(time.time())).hexdigest()
    return scanid

# Start the scan and returns the message
@app.route('/scan/', methods = ['POST'])
def start_scan():
    scanid = generate_hash()
    content = request.get_json()
    try:
        name = content['appname']
        url = content['url']
        headers = content['headers']
        body = content['body']
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


#############################  Fetch ScanID API #########################################
def check_scan_status(data):
    # Return the Scan status
    total_scan = data['total_scan']
    count = 0
    for key,value in data.items():
        print key,value
        if value == 'Y' or value == 'y':
            count += 1

    if total_scan == count:
        return "Completed"
    else:
        return "In progress"

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
                        scanids.append({"scanid" : data['scanid'], "name" : data['name'], "url" : data['url'], "scan_status" : scan_status}) 
            except:
                pass

        return jsonify(scanids)
############################# Alerts API ##########################################

# Returns vulnerbilities identified by tool 
def fetch_records(scanid):
    # Return alerts identified by the tool
    vul_list = []
    records = db.vulnerabilities.find({"scanid":scanid})
    print "Records are ",records
    if records:
        for data in records:  
            print "Data is",data
            if data['req_body'] == None:
                data['req_body'] = "NA" 

            data.pop('_id')
            try:
                data =  ast.literal_eval(json.dumps(data))
            except:
                print "Falied to parse"

            try:
                if data['id'] == "NA":
                    all_data = {'url' : data['url'], 'impact' : data['impact'], 'name' : data['name'], 'req_headers' : data['req_headers'], 'req_body' : data['req_body'], 'res_headers' : data['res_headers'], 'res_body' : data['res_body'], 'Description' : data['Description'], 'remediation' : data['remediation']}
                    vul_list.append(all_data)

                if data['id']:
                    for vul in alerts:
                        if data['id'] == vul['id']:
                            all_data = {
                                        'url' : data['url'],
                                        'impact' : data['impact'],
                                        'name' : data['alert'],
                                        'req_headers' : data['req_headers'],
                                        'req_body' : data['req_body'],
                                        'res_headers' : data['res_headers'],
                                        'res_body' : data['res_body'],
                                        'Description' : vul['Description'],
                                        'remediation' : vul['remediation']
                                        }
                            vul_list.append(all_data)
                            break

            except:
                pass

        print vul_list
        return vul_list        

@app.route('/alerts/<scanid>', methods=['GET'])
def return_alerts(scanid):
    print "ScanID is ",scanid
    result = fetch_records(scanid)
    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

#############################Dashboard#########################################

@app.route('/', defaults={'page': 'scan.html'})
@app.route('/<page>')
def view_dashboard(page):
    return render_template('{}'.format(page))

app.run(host='0.0.0.0', port= 8094,debug=True)

