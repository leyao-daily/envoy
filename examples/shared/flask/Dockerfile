FROM python:3.11.2-slim-bullseye@sha256:0f77466c3a5168a797b7923b80a03816061ab2fc87d889e3e4e04fb37594b100

ADD requirements.txt /tmp/flask-requirements.txt
RUN pip3 install -qr /tmp/flask-requirements.txt
RUN mkdir /code

ENTRYPOINT ["python3", "/code/service.py"]
