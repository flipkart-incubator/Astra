## APIScan

REST API penetration testing is complex due to continuous changes in existing APIs and newly added APIs.  Security engineers or developers can use APIScan as an integral part of their process, so they can detect and patch vulnerabilities early during development cycle. API collection can be given as an input so this can be easily integrated into CICD pipeline. Following are the checks performed by APIScan. 

- SQL injection
- Cross site scripting
- LFI and RFI
- Information Leakage
- Broken Authentication and session management
- CSRF (including Blind CSRF)
- Rate limit
- CORS misonfiguration (including CORS bypass techniques)

## Coming soon
- XXE 
- JWT attack 
- CSP misconfiguration


## Installation

```
git clone -b apiscan https://github.com/flipkart-incubator/apiscan

cd apiscan

pyhton setup.py

```

## Dependencies

```
- requests
- logger
- pymongo
- ConfigParser
```

## Usage 

```

$ python apiscan.py --help

     	    	    _   ____ ___ ____
		   / \  |  _ \_ _/ ___|  ___ __ _ _ __
		  / _ \ | |_) | |\___ \ / __/ _` | '_ \
		 / ___ \|  __/| | ___) | (_| (_| | | | |
		/_/   \_\_|  |___|____/ \___\__,_|_| |_|

usage: core.py [-h] [-c {Postman,Swagger}] [-n COLLECTION_NAME] [-u URL]
               [-l LOGINURL] [-H LOGINHEADERS] [-d LOGINDATA]
               [-headers HEADERS] [-m {GET,POST}]

REST API Security testing Framework

optional arguments:
  -h, --help            show this help message and exit
  -c {Postman,Swagger}, --collection_type {Postman,Swagger}
                        Type of API collection
  -n COLLECTION_NAME, --collection_name COLLECTION_NAME
                        Type of API collection
  -u URL, --url URL     URL of target API
  -l LOGINURL, --loginurl LOGINURL
                        URL of login API
  -H LOGINHEADERS, --loginheaders LOGINHEADERS
                        Headers should be in a dictionary format. Example:
                        {"accesstoken" : "axzvbqdadf"}
  -d LOGINDATA, --logindata LOGINDATA
                        login data of API
  -headers HEADERS, --headers HEADERS
                        Custom headers.Example: {"token" : "123"}
  -m {GET,POST}, --loginmethod {GET,POST}
                        HTTP request method

```

