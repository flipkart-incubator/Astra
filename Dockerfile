FROM python:2-alpine

ENV app /app

RUN mkdir $app
WORKDIR $app
COPY . $app

RUN pip install -r requirements.txt

WORKDIR API/

EXPOSE 8094
ENTRYPOINT ["python", "./api.py"]
CMD ["tail -f /app/logs/scan.log"]

