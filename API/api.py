import ast
import json
import sys

sys.path.append('../')

from flask import Flask
from flask import request
from flask import Flask
from apiscan import scan_single_api
from flask import jsonify
from pymongo import MongoClient
from utils.vulnerabilities import alerts
 
app = Flask(__name__)
 
# Mongo DB connection 
client = MongoClient('localhost',27017)
global db
db = client.apiscan

############################# Start scan API ######################################
# Start the scan and returns the message
@app.route('/scan/', methods = ['POST'])
def start_scan():
    content = request.get_json()
    try:
        url = content['url']
        headers = content['headers']
        body = content['body']
        method = content['method']
        api = "Y"
        scan_status = scan_single_api(url, method, headers, body, api)
        if scan_status is True:
            # Success
            msg = {"status" : "success"}
        else:
            msg = {"status" : "Failed"}
    
    except:
        msg = {"status" : "Failed"} 
    
    return jsonify(msg)


############################# Alerts API ##########################################

# Returns vulnerbilities identified by tool 
def fetch_records():
    vul_list = []
    records = db.vulnerbilities.find({})
    if records:
        for data in records:  
            if data['req_body'] == None:
                data['req_body'] = "NA" 

            data.pop('_id')
            try:
                data =  ast.literal_eval(json.dumps(data))
            except:
                print "Falied to parse"

            print "Data",data
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
        

@app.route('/alerts/', methods=['GET'])
def return_alerts():
    result = fetch_records()
    return jsonify(result)


app.run(host='0.0.0.0', port= 8099)
