FROM python:2-alpine

ENV app /app

RUN mkdir $app
WORKDIR $app
COPY . $app

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "./astra.py"]
CMD ["--help"]