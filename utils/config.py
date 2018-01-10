import ConfigParser
from utils.config import *

def get_allvalues(section):
	Config = ConfigParser.ConfigParser()
	Config.read('utils/config.property')
	return dict(Config.items(section))

def get_value(section,name):
	Config = ConfigParser.ConfigParser()
	Config.read('utils/config.property')
	return Config.get(section,name)

def update_value(section,name,value):
	config= ConfigParser.RawConfigParser()
	config.read('utils/config.property')
	config.set(section,name,value)
	with open('utils/config.property', 'wb') as configfile:
		config.write(configfile)