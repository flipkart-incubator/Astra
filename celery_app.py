from celery import Celery
from utils.db import Database_update
import time 
import sys
import os

sys.path.append(os.getcwd())
app = Celery('celery_app', broker='amqp://guest@rabbit//')
# app.conf.task_serializer = 'pickle'
# app.conf.result_serializer = 'pickle'
# app.conf.accept_content = ['application/json', 'application/x-python-serialize']
app.autodiscover_tasks(['astra.modules_scan'])
app.conf.task_eager_propagates = True

# dbupdate = Database_update()

# def update_scan_status(scanid, module_name=None, count=None):
#     #Update scanning status and total scan of module into DB.
#     time.sleep(1)
#     if count is not None:
#         dbupdate.update_scan_record({"scanid": scanid}, {"$set" : {"total_scan" : count}})
#     else:
#         dbupdate.update_scan_record({"scanid": scanid}, {"$set" : {module_name : "Y"}})

# @app.task
# def handleException(method, module_name, scanid):
#     try:
#         #raise Exception("handle exception")
#         method()
#     except Exception:
#         print("exception in", module_name)
#     finally:
#         update_scan_status(scanid, module_name)

# @app.task
# def add(a,b):
#     time.sleep(2)
#     print(a+b)

# @app.task
# def test():
#     attack_group = []
#     for i in range(10):
#         attack_group.append(add.s(i,i))
#     g = group(attack_group)
#     g()
