import subprocess
from subprocess import call
from celery_app import app
import utils.logger as logger
import utils.logs as logs
from utils.db import Database_update
api_logger = logger.logger()
dbupdate = Database_update()

def template_injection_post(uri, body, scanid):
    pass

def template_injection_url(uri, scanid):
   result = subprocess.check_output(["python3","./tplmap/tplmap.py","-u",uri], text=True)
   output = str(result)
   if "not injectable" in output.lower():
       print("Endpoint is not vulnerable")
   else:
       newoutput = result.split("\n" )
       for line in newoutput:
           if "Capabilities:" in line:
                attack_result = {"id" : 25,
                    "scanid": scanid,
                            "url" : uri,
                            "alert": "Template Injection",
                            "impact" : "High", 
                            "req_headers" : "NA",
                            "req_body" : "NA",
                            "res_headers" : "NA",
                            "res_body" : "NA"
                        }
                dbupdate.insert_record(attack_result)
                print(line)
                break

@app.task
def template_injection_check(uri,method,headers,body,scanid):
    # Main function for Template Injection attack
   template_injection(uri,scanid)
