import threading
import time
import sys
import utils.logs as logs
import time

import os
from utils.sendemail import send_email
from utils.config import get_value
from utils.db import Database_update

try:
    from API.scanstatus import scan_status
except Exception as e:
    SCRIPT_PATH= os.path.split(os.path.realpath(__file__))[0]
    sys.path.append(os.path.join(SCRIPT_PATH,'..','API'))
    from scanstatus import scan_status

email_db = Database_update()
emails = send_email()


def send_email_notification():
     time.sleep(20)
     while True:
        try:
            schedule = get_value('config.property','SMTP','email_schedule')
            records = email_db.db.email.find({})
            for data in records:
                notification = data['email_notification']
                scan_id = data['scanid']
                scan_result = scan_status(scan_id)
                if notification == 'N'  and scan_result == 'Completed':
                    try:
                        email = data['to_email']
                        email_result = emails.main_email(scan_id,email)
                        if email_result is False:
                            print("failed to connect to SMTP server")
                            return
                        email_db.db.email.update({'email_notification' : 'N'},{"$set" : {'email_notification' : 'Y'}})
                    except:
                        pass

            time.sleep(int(schedule))

        except Exception as e:
            logs.logging.info("Invalid email schedule argument "+str(e))
            sys.exit(1)


def email_start_cron():
    email_notification = get_value('config.property','SMTP','email_notification')
    if email_notification == "y" or email_notification == "Y":
        # Start the thread
        #time.sleep(20)
        t = threading.Thread(target=send_email_notification)
        t.deamon = True
        t.start()
        logs.logging.info("started")
    else:
        logs.logging.info("Email notification is not enabled")