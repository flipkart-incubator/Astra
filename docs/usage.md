Once you have set up astra, you can use either CLI or web interface to start a scan.
## ** Astra CLI **
```
$ python astra.py --help
                        _
            /\       | |
           /  \   ___| |_ _ __ __ _
          / /\ \ / __| __| '__/ _` |
         / ____ \__ \ |_| | | (_| |
        /_/    \_\___/\__|_|  \__,_|



usage: astra.py [-h] [-c COLLECTION_TYPE] [-n COLLECTION_NAME] [-u URL]
                [-headers HEADERS] [-method {GET,POST,PUT,DELETE}] [-b BODY]
                [-l LOGINURL] [-H LOGINHEADERS] [-d LOGINDATA]

Astra - REST API Security testing Framework

optional arguments:
  -h, --help            show this help message and exit
  -c COLLECTION_TYPE, --collection_type COLLECTION_TYPE
                        Type of API collection
  -n COLLECTION_NAME, --collection_name COLLECTION_NAME
                        Type of API collection
  -u URL, --url URL     URL of target API
  -headers HEADERS, --headers HEADERS
                        Custom headers.Example: {"token" : "123"}
  -method {GET,POST,PUT,DELETE}, --method {GET,POST,PUT,DELETE}
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
You can use above arguments as per your need.  
**Example 1:** In order to start a scan for GET api, use the following command.   
``` $python astra.py -u http://localhost```<br>  
**Example 2:** In order to start a scan for POST api with request headers, use the following command.   
``` $python astra.py -u http://localhost -m POST --headers '{"token" : "123456789"}' --body '{"name" : "astra"}'```<br><br>
**Example 3:** Astra also provides a feature to scan all the apis using ```Postman``` collection. Astra automatically detects login and logout apis and prompts the user to verify the apis.  

```
$ python astra.py -n test
                        _
            /\       | |
           /  \   ___| |_ _ __ __ _
          / /\ \ / __| __| '__/ _` |
         / ____ \__ \ |_| | | (_| |
        /_/    \_\___/\__|_|  \__,_|

Is it a correct login URL(y/n),http://127.0.0.1/api/login.php: y
[+]Login successful

```
Astra stores api login & logout information in ```utils/config.property``` file.  
**Note:** Postman allows you to export apis as a collection and you can pass this collection to astra to start the scan. As of now, only command line interface supports API security testing via ```Postman``` collection.
## ** Configuring Astra** 
You can configure the attacks using ```utils/scan.property```.  
```
[scan-policy]
attack = {
          "cors" : "n",
          "Broken auth" : "n",
          "Rate limit" : "n",
          "csrf" : 'n',
          "zap" : 'n',
          "jwt" : 'y',
          "sqli" : 'n',
          "xss" : 'n',
          "open-redirection" : "y"
         }


[modules]
csrftoken-names = csrf,csrftoken,xsrftoken,token,
open-redirection-names = url,redirect,login,logout,uri,redirection,next,returnto, return_to, origin,callback,authorize_callback, target,link
jwt_brute = Y
```
## ** Web Interface **
Run the api.py and access the web interface at http://127.0.0.1:8094
```
$ cd API
$ python api.py
```