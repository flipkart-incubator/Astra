Installing Astra is very straightforward. You can clone the github repo and use pip to install all the required dependencies. Or you can use docker.

## ** Requirement **
As of now, Astra can be installed only on Linux and MacOS. Please make sure that your system meets the following requirements.
```
- Linux or MacOS
- Python 2.7
- MongoDB
```
## ** Dependencies **
```
- requests
- logger
- pymongo
- ConfigParser
- pyjwt
- flask
- sqlmap
- celery
```

## ** Steps **
Follow these steps to install Astra:
```
$ git clone https://github.com/flipkart-incubator/Astra
$ cd Astra
$ sudo pip install -r requirements.txt
$ sudo rabbitmq-server
$ celery -A worker -loglevel=INFO
$ cd API
$ python3 api.py
```

## Docker Installation

### Run Mongo Container:

```
$ docker pull mongo
$ docker run --name astra-mongo -d mongo
```

### Installing GUI Docker: 

```
$ git clone https://github.com/flipkart-incubator/Astra.git
$ cd Astra
$ docker build -t astra .
$ docker run --rm -it --link astra-mongo:mongo -p 8094:8094 astra
```

### Installing CLI Docker :

```
$ git clone -b docker-cli https://github.com/flipkart-incubator/Astra.git
$ cd Astra
$ docker build -t astra-cli .
$ docker run --rm -it --link astra-mongo:mongo astra-cli 
```

Installing and launching Astra:

<iframe width="600" height="400" src="https://www.youtube.com/embed/EzT9jJlaK9k" frameborder="0" allowfullscreen></iframe>

**Note:**  
1. Upgrade your ```pip``` to the latest version.  
2. After installing ```MongoDB```, create this directory ```/data/db/```. For more information, please refer this doc: [https://docs.mongodb.com/manual/administration/install-community/](https://docs.mongodb.com/manual/administration/install-community/)
