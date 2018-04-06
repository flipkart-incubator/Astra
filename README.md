[![Github Release Version](https://img.shields.io/badge/release-V1.0-blue.svg)](https://github.com/flipkart-incubator/Astra)
[![Github Release Version](https://img.shields.io/badge/python-2.7-blue.svg)](https://github.com/flipkart-incubator/Astra)

## Astra
![alt text](https://raw.githubusercontent.com/flipkart-incubator/Astra/dev/Dashboard/static/astra.png)

REST API penetration testing is complex due to continuous changes in existing APIs and newly added APIs. Astra can be used by security engineers or developers as an integral part of their process, so they can detect and patch vulnerabilities early during development cycle. Astra can automatically detect and test login & logout (Authentication API), so it's easy for anyone to integrate this into CICD pipeline. Astra can take API collection as an input so this can also be used for testing apis in standalone mode.

- SQL injection
- Cross site scripting
- Information Leakage
- Broken Authentication and session management
- CSRF (including Blind CSRF)
- Rate limit
- CORS misonfiguration (including CORS bypass techniques)
- JWT attack

## Coming soon
- XXE 
- CSP misconfiguration

## Requirement
- Python 2.7
- mongoDB

## Installation

```
$ git clone https://github.com/flipkart-incubator/Astra

$ cd Astra

$ sudo pip install -r requirements.txt

```

## Dependencies

```
- requests
- logger
- pymongo
- ConfigParser
- pyjwt
- flask
```

## Usage: CLI

```
$ python astra.py --help

                      _
        /\       | |
       /  \   ___| |_ _ __ __ _
      / /\ \ / __| __| '__/ _` |
     / ____ \__ \ |_| | | (_| |
    /_/    \_\___/\__|_|  \__,_|



usage: astra.py [-h] [-c {Postman,Swagger}] [-n COLLECTION_NAME] [-u URL]
                [-headers HEADERS] [-method {GET,POST}] [-b BODY]
                [-l LOGINURL] [-H LOGINHEADERS] [-d LOGINDATA]

REST API Security testing Framework

optional arguments:
  -h, --help            show this help message and exit
  -c {Postman,Swagger}, --collection_type {Postman,Swagger}
                        Type of API collection
  -n COLLECTION_NAME, --collection_name COLLECTION_NAME
                        Type of API collection
  -u URL, --url URL     URL of target API
  -headers HEADERS, --headers HEADERS
                        Custom headers.Example: {"token" : "123"}
  -method {GET,POST}, --method {GET,POST}
                        HTTP request method
  -b BODY, --body BODY  Request body of API
  -l LOGINURL, --loginurl LOGINURL
                        URL of login API
  -H LOGINHEADERS, --loginheaders LOGINHEADERS
                        Headers should be in a dictionary format. Example:
                        {"accesstoken" : "axzvbqdadf"}
  -d LOGINDATA, --logindata LOGINDATA
                        login data of API

```
## Usage: Web interface
Run the api.py and access the web interface at http://127.0.0.1:8094
```
$ cd API
$ python api.py

```
## Screenshots 
### New scan
![alt text](https://raw.githubusercontent.com/flipkart-incubator/Astra/dev/Dashboard/static/new%20scan.png)

### Scan Reports
![alt text](https://raw.githubusercontent.com/flipkart-incubator/Astra/dev/Dashboard/static/Reports.png)

![alt text](https://raw.githubusercontent.com/flipkart-incubator/Astra/dev/Dashboard/static/scan-report.png)
### Detailed Report
![alt text](https://raw.githubusercontent.com/flipkart-incubator/Astra/dev/Dashboard/static/Detailed-report.png)


## Lead Developer
- Sagar Popat (@popat_sagar) 

## Credits
- Harsh Grover
- Prajal Kulkarani
- Ankur Bhargava
- Mohan Kallepalli
- Pardeep battu
- Anirudh Anand
- Divya Salu John
