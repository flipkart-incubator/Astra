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
import urllib.parse
import re
from reportlab.platypus import SimpleDocTemplate, Spacer
from reportlab.lib.pagesizes import letter, inch
from reportlab.platypus import Table , TableStyle , Paragraph, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT, TA_CENTER
from io import StringIO

from dbconnection import db_connect
from scanstatus import check_scan_status, scan_status

sys.path.append('../')

from flask import Flask, render_template, send_from_directory
from flask import Response, make_response, send_file
from flask import request
from flask import Flask
from flask import jsonify
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from apscheduler.schedulers.background import BackgroundScheduler


from utils.vulnerabilities import alerts
#from utils.sendemail import send_email
from jinja2 import utils
# from utils.email_cron import send_email_notification

SCRIPT_PATH= os.path.split(os.path.realpath(__file__))[0]
sys.path.append(os.path.join(SCRIPT_PATH,'..'))
# import scan_single_api, scan_postman_collection
from astra import *

app = Flask(__name__, template_folder='../Dashboard/templates', static_folder='../Dashboard/static')


class ServerThread(threading.Thread):

  def __init__(self):
    threading.Thread.__init__(self)

  def run(self):
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port= 8094, debug=True)


db_object = db_connect()
global db
db = db_object.apiscan


############################# Start scan API ######################################

def get_auth_from_url():
    resp = requests.post(os.environ['auth_url'])
    os.environ['auth_header'] = resp.text

def update_auth():
    scheduler = BackgroundScheduler()
    scheduler.add_job(get_auth_from_url, 'interval', minutes=20, id='update_auth')


def generate_hash():
    # Return md5 hash value of current timestmap 
    scanid = hashlib.md5(str(time.time()).encode('utf-8')).hexdigest()
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
        url = content['url']
        headers = content['headers']
        body = content['body']
        method = content['method']
        auth_header = content['auth_header']
        auth_url = content['auth_url']
        if auth_url:
            os.environ["auth_url"] = auth_url
            update_auth()
        if headers and auth_header:
            headers += auth_header
        api = "Y"
        scan_status = scan_single_api(url, method, headers, body, api, scanid)
        if scan_status is True:
            # Success
            msg = {"status" : scanid}
            try:
                db.scanids.insert_one({"scanid" : scanid, "name" : name, "url" : url})
            except:
                print("Failed to update DB")
        else:
            print("SCAN WAS FALSE")
            msg = {"status" : "Failed"}
    
    except Exception as e:
        print(e)
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

def make_table(data):
    table = Table(data)
    table._argW[0]=1.5*inch
    for k in range(len(data)):
        ts = TableStyle([('BACKGROUND', (0,0),(0,k), colors.lightsteelblue), ('ALIGN',(0,0),(0,k),'LEFT'),])
    table.setStyle(ts)
    ts = TableStyle([('BOX',(0,0),(-1,-1),1,colors.black),
        ('GRID',(0,0),(-1,-1),1,colors.black),])
    table.setStyle(ts)
    return table

# Returns vulnerbilities identified by tool 
def fetch_records(scanid):
    # Return alerts identified by the tool
    vul_list = []
    records = db.vulnerabilities.find({"scanid":scanid})
    if records:
        for data in records:  
            if 'req_body' in data.keys():
                if data['req_body'] == None:
                    data['req_body'] = "NA" 

            data.pop('_id')
            try:
                data =  ast.literal_eval(json.dumps(data))
            except Exception as e:
                print("Falied to parse",e)
            
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

def format_data(data, styl):
    fdetails = []
    for i in data:
        if i == 'name':
            fdetails.append(["Title", Paragraph(str(data[i]), styl)])
        if i == 'url':
            fdetails.append(["URL", data[i]])
        if i == 'impact':
            fdetails.append(["Severity", data[i]])
        if i == 'Description':
            fdetails.append(["Description", Paragraph(str(data[i]), styl)])
        if i == 'req_headers':
            fdetails.append(["Req_Headers", Paragraph(str(data[i]), styl)])
        if i == 'req_body':
            fdetails.append(["Req_Body", Paragraph(str(data[i]), styl)])
        if i == 'remediation':
            fdetails.append(["Remediation", Paragraph(str(data[i]), styl)])
    return fdetails

@app.route('/alerts/<scanid>', methods=['GET'])
def return_alerts(scanid):
    result = fetch_records(scanid)
    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route('/reports/<scanid>', methods=['GET'])
def report_alerts(scanid):
    result = fetch_records(scanid)
    styles = getSampleStyleSheet()
    story = []
    styleT = styles['Title']
    styleB = styles["BodyText"]
    styleB.alignment = TA_LEFT
    pTitle = Paragraph('<font size="18" color="darkblue">API Vulnerabilities Report</font>', styleT)
    story.append(pTitle)
    story.append(Spacer(0.5, .25*inch))
    story.append(Paragraph("<font size='14' color='darkblue'><b>Vulnerability Details</b></font>", styleB))
    story.append(Spacer(1, .5*inch))

    fileName = str(scanid)+'.pdf'
    pdf = SimpleDocTemplate(
        fileName, title="API Security Vulnerabilities",
        pagesize=letter
    )
    
    for i in result:
        fdata = format_data(i, styleB)
        vtab = make_table(fdata)
        story.append(vtab)
        story.append(Spacer(1, .5*inch))
    
    output = StringIO()
    pdf.build(story)
    pdf_out = output.getvalue()
    output.close()
    return send_file(str(scanid)+".pdf", as_attachment=True)

#############################Dashboard#########################################

@app.route('/', defaults={'page': 'scan.html'})
@app.route('/<page>')
def view_dashboard(page):
    return render_template('{}'.format(page))

def start_server():
    app.run(host='0.0.0.0', port= 8094, debug=True)


############################Postman collection################################

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ['json','txt']

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
def get_postman():
    appname = request.form['appname']
    url = request.form['url']
    auth_token =request.form['authheader']
    print(url)
    if not url:
        return jsonify({"status" : "Failed! (add URL)"})
    # print(request.files)
    os.environ["auth_url"] = request.form['auth_url']
    if 'file' not in request.files:
        msg = {"status" : "Failed!"}
        return jsonify(msg)
    file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
    if file.filename == '':
        msg = {"status" : "Failed!"}
        return jsonify(msg)
    try:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(os.getcwd(), filename))
        else:
            msg = {"status" : "Failed!"}
            return jsonify(msg)
    except:
        msg = {"status" : "Failed!"}
        return jsonify(msg)
    try:
        scan_id = generate_hash()
        db.scanids.insert({"scanid" : scan_id, "name" : appname, "url" : url})
        scan_result = scan_postman_collection(filename,scan_id,auth_token,url)
        print(scan_result)
    except Exception as e:
        raise e
        #Failed to update the DB
        print("DB ERROR?")
        msg = {"status" : "Failed!"}
        return jsonify(msg)
    if scan_result == True:
            # Update the email notification collection 
        # db.email.insert({"email" : email, "scanid" : scan_id, "to_email" : email, "email_notification" : 'N'})
        msg = {"status" : "Success", "scanid" : scan_id}
    else:

        msg = {"status" : "Failed!"}

    return jsonify(msg)

@app.route('/postman/', methods = ['POST'])
def scan_postman():
    content = request.get_json()
    try:
        # mandatory inputs
        appname = content['appname']
        postman_url = content['postman_url']
        env_type = content['env_type']
        if "email" in list(content.keys()):
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
            if "ip" in list(content.keys()):
                url = content['ip']
                if urllib.parse.urlparse(url).scheme == "http" or urllib.parse.urlparse(url).scheme == "https":
                    ip = urllib.parse.urlparse(url).netloc
                    socket.inet_aton(ip)
                    ip_result = 1

            else:
                ip_result = 0
        except:
            print("Missing Arugument or invalid IP address!")
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

if __name__ == '__main__':
    main()
