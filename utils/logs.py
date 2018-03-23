import logging
import os

if os.getcwd().split('/')[-1] == 'API':
        path = '../logs/scan.log'
else:
        path = 'logs/scan.log'

logging.basicConfig(filename=path, level=logging.INFO)