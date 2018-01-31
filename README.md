## APIScan

REST API penetration testing is complex due to continuous changes in existing APIs and newly added APIs. APIScan can be used by security engineers or developers as an integral part of their process, so they can detect and patch vulnerabilities early during development cycle. APIScan can automatically detect and test login & logout (Authentication API), so it's easy for anyone to integrate this into CICD pipeline. APIScan can take API collection as an input so this can also be used for testing apis in standalone mode.

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
git clone https://github.com/flipkart-incubator/apiscan

cd apiscan

python setup.py

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

![alt text](https://raw.githubusercontent.com/flipkart-incubator/apiscan/7539de1beefb7941d4224bf9b15c584592a0cd81/utils/report.png)

## Lead Developers
- Sagar Popat (@popat_sagar) 

## Project Contributors
- Harsh Grover
