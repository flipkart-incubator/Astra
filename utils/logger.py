class logger(object):
	
	def __init__(self):
		self.G = '\033[92m'
		self.Y = '\033[93m'
		self.B = '\033[94m'
		self.R = '\033[91m'
		self.W = '\033[0m'  

	
	def banner(self):
	    print '''%s
     	    	    _   ____ ___ ____                  
		   / \  |  _ \_ _/ ___|  ___ __ _ _ __  
		  / _ \ | |_) | |\___ \ / __/ _` | '_ \ 
		 / ___ \|  __/| | ___) | (_| (_| | | | |
		/_/   \_\_|  |___|____/ \___\__,_|_| |_|
              %s'''% (self.G,self.W)