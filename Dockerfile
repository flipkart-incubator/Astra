FROM mongo:latest
LABEL maintainer="txt3rob@gmail.com"

# update
RUN apt-get update && apt-get install git python python-pip python-dev build-essential gcc -y

# clone and setup astra API
WORKDIR /root/
RUN git clone https://github.com/flipkart-incubator/Astra
WORKDIR /root/Astra/
RUN pip install -r requirements.txt
WORKDIR /root/Astra/API/
EXPOSE 8094
CMD ["python", "/root/Astra/API/api.py"]
