FROM python:3.12.3-slim-bullseye

ENV PYTHONUNBUFFERED 1
RUN mkdir /web_django
WORKDIR /web_django

COPY requirements.txt /web_django/
RUN apt update
RUN pip install --upgrade pip && pip install -r requirements.txt

ADD . ./web_django/
RUN chmod 777 ./web_django/
