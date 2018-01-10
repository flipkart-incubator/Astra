import ast
import json
import sys

sys.path.append('../')

from pymongo import MongoClient
from utils.vulnerabilities import test
from flask import Flask, jsonify

app = Flask(__name__)

def db_connect():
		client = MongoClient('localhost',27017)
		global db
		db = client.apiscan

def fetch_records():
		db_connect()
		vul_list = []
		records = db.vulnerbilities.find({})
		if records:
			for data in records:
				data.pop('_id')
				data =  ast.literal_eval(json.dumps(data))
				try:
					if data['id']:
						for vul in test:
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

			return vul_list

@app.route('/alerts/', methods=['GET'])
def return_alerts():
	result = fetch_records()
	return jsonify(result)

app.run(debug=True,port=3234)
