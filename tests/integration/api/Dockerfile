FROM python:3.8-slim-buster
MAINTAINER Václav Brůžek <vaclav.bruzek@whalebone.io>

RUN pip3 --no-cache-dir install requests gunicorn falcon gevent redis

RUN mkdir -p /opt/sink/
WORKDIR /opt/sink/
COPY . .

#CMD ["gunicorn", "-b", "0.0.0.0:8000", "--worker-class", "gevent", "--access-logfile", "-", "api:app"]
CMD ["gunicorn", "-b", "0.0.0.0:8000", "--worker-class", "gevent", "api:app"]