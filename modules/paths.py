import sys
import os

print os.getcwd()
sys.path.append('../')

from utils.config import get_value

print get_value("config.property","login","auth_type")
