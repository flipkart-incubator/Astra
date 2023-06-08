
FROM mcr.microsoft.com/devcontainers/python:0-3.11

ENV app /app

RUN mkdir $app
WORKDIR $app
COPY requirements.txt $app

RUN pip install -r requirements.txt && rm requirements.txt
WORKDIR $app/API/

EXPOSE 8094
CMD ["tail -f /app/logs/scan.log"]