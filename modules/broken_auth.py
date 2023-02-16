from urllib.parse import urlparse

from utils.db import Database_update
from utils.config import get_value,get_allvalues
dbupdate = Database_update()
import utils.logger as logger
import utils.logs as logs
api_logger = logger.logger()
 
def check_session_hijacking(uri, thisList, username, password, scanid):
   for keyword in thisList:
       if (keyword in uri):
            attack_result = {"id" : 5,
                            "scanid": scanid,
                                    "url" : uri,
                                    "alert": "Session Fixation",
                                    "impact" : "High", 
                                    "req_headers" : "NA",
                                    "req_body" : "NA",
                                    "res_headers" : "NA",
                                    "res_body" : "NA"
                                }

            dbupdate.insert_record(attack_result)
            print("Url is vulnerable to session hijacking")
       else:
           check(username,password,scanid, uri)
 
def check(username, password, scanid, uri):
   if (password in username):
        attack_result = {"id" : 25,
                "scanid": scanid,
                        "url" : uri,
                        "alert": "Weak Password",
                        "impact" : "High", 
                        "req_headers" : "NA",
                        "req_body" : "NA",
                        "res_headers" : "NA",
                        "res_body" : "NA"
                    }
        dbupdate.insert_record(attack_result)
   else:
       check_weak_password(password, scanid, uri)
 
def check_weak_password(password, scanid, uri):
   l, u, p, d = 0, 0, 0, 0
   s = password
   if (len(s) >= 8):
       for i in s:
  
           # counting lowercase alphabets
           if (i.islower()):
               l+=1          
  
           # counting uppercase alphabets
           if (i.isupper()):
               u+=1          
  
           # counting digits
           if (i.isdigit()):
               d+=1          
  
           # counting the mentioned special characters
           if(i=='@'or i=='$' or i=='_'):
               p+=1         
   if (l>=1 and u>=1 and p>=1 and d>=1 and l+p+u+d==len(s)):
       print("Valid Password")
   else:
        attack_result = {"id" : 25,
                "scanid": scanid,
                        "url" : uri,
                        "alert": "Weak Password",
                        "impact" : "High", 
                        "req_headers" : "NA",
                        "req_body" : "NA",
                        "res_headers" : "NA",
                        "res_body" : "NA"
                    }
        dbupdate.insert_record(attack_result)
 
def broken_auth_check(uri,method,headers,body,scanid):
    # Main function for Broken Authentication attack
   thisList = ["sessionid=","id=","key="]
   parsed = urlparse(uri)
   username = parsed.username
   password = parsed.password
   check_session_hijacking(uri, thisList, username, password, scanid)