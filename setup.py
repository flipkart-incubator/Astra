import os
import platform

def os_dependencies():
	try:
		os.system("pip install -r requirements.txt")
	except Exception as e:
		print "Failed to install dependencies"

def install_zap():
	try:
		os.system('curl -L https://github.com/zaproxy/zaproxy/releases/download/2.7.0/ZAP_2.7.0_Crossplatform.zip --output zap.zip')
		os.system('sudo unzip zap.zip')
		os.system('sudo mv -R zap core/')
	except Exception as e:
		print "Failed to install ZAP. Please install it manually",e
	

def install_mongo():

		os_name = platform.system()
		if os_name == "linux" or os_name == "linux2":
			os.system("sudo apt-get install python-pip")
			os.system("sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927")
			os.system('echo "deb http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.2 multiverse"\ | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list')
			os.system("sudo apt-get update && sudo apt-get install -y mongodb-org")
			os.system("sudo cp /mongodb.service /etc/systemd/system/mongodb.service")
			os.system("sudo systemctl start mongodb && sudo systemctl enable mongodb")

		elif os_name == "darwin":
			os.system("brew update")
			os.system("brew install mongodb")
			os.system(mongod)

def main():
	os_dependencies()
	install_zap()
	install_mongo()

if __name__ == '__main__':
    main()
