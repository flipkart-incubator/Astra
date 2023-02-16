import utils.logs as logs
import smtplib
import socket

from utils.config import get_value
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class send_email:
    def __init__(self):
        self.host = get_value('config.property','SMTP','ip')
        self.email_subject = get_value('config.property','SMTP','email_subject')
        self.email_message = get_value('config.property','SMTP','email_message')
        self.email_from = get_value('config.property','SMTP','email_from')
        # optional
        try:
            self.email_cc = get_value('config.property','SMTP','email_cc')
        except:
            pass

    def smtp_connect(self):
        # Connect to SMTP server
        try:
            self.server = smtplib.SMTP(self.host)
            return True
        except Exception as e:
            print("Failed to connect to SMTP server",e)
            logs.logging.info("Failed to connect to SMTP server"+str(e))
            return False

    def send_success_email(self, scan_id, to_email=None):
       # host = socket.gethostbyname(socket.gethostname())
        msg = MIMEMultipart()
        msg['From'] = self.email_from
        msg['To'] = to_email
        msg['Subject'] = self.email_subject
        if self.email_cc:
            msg['Cc'] = self.email_cc
        body = self.email_message+":http://"+str(socket.gethostbyname(socket.gethostname()))+":8094/reports.html#"+scan_id
        msg.attach(MIMEText(body, 'html'))
        text = msg.as_string()
        self.server.sendmail(self.email_from, to_email, text)

    def main_email(self, scan_id, to_email=None):
        connect_result = self.smtp_connect()
        if connect_result is True:
            self.send_success_email(scan_id, to_email)
            return True
        else:
            return False