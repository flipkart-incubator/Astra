import os
import platform


os_name = platform.system()

def os_dependencies():
	try:
		if os_name == "linux" or os_name == "linux2":
			os.system("sudo apt-get install curl")
			os.system("sudo apt-get install python-pip")
			os.system("sudo apt-get install openjdk-8-jre-headless")

		os.system("pip install -r requirements.txt")

	except Exception as e:
		print "Failed to install dependencies"

def install_zap():
	try:
		os_name = platform.system()
		if os_name == "linux" or os_name == "linux2":
			os.system('curl -L https://github.com/zaproxy/zaproxy/releases/download/2.7.0/ZAP_2.7.0_Crossplatform.zip --output zap.zip')
			os.system('sudo unzip zap.zip')
			os.system('sudo mv ZAP_2.7.0 core/')

	except Exception as e:
		print "Failed to install ZAP. Please install it manually",e
	

def install_mongo():
		os_name = platform.system()
		if os_name == "linux" or os_name == "linux2":
			os.system("sudo apt-get install mongodb-server")

		elif os_name == "Darwin":
			os.system("brew update")
			os.system("brew install mongodb")

		os.system("sudo mkdir -p /data/db/")
		os.system("sudo nohup mongod &")

		#Check if mongodb is started successfully
		try:
			from pymongo import MongoClient
			mongo_connect = MongoClient('localhost',27017)
			collections_list = mongo_connect.db.collection_names()  
		except:
			print "Failed to install mongodb. Please install it manually."
	
def main():
	os_dependencies()
	install_zap()
	install_mongo()

if __name__ == '__main__':
    main()
