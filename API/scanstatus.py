import ast
import json

from dbconnection import db_connect

db_object = db_connect()
global db
db = db_object.apiscan

def check_scan_status(data):
    # Return the Scan status
    total_scan = data['total_scan']
    count = 0
    for key,value in list(data.items()):
        if value == 'Y' or value == 'y':
            count += 1

    if total_scan == count:
        return "Completed"
    else:
        return "In progress"

def scan_status(scan_id):
    # Return scan status based on scan id
    data = db.scanids.find({"scanid": scan_id})
    data = data[0]
    data.pop('_id')
    scan_result = check_scan_status(ast.literal_eval(json.dumps(data)))
    return scan_result