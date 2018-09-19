FROM ubuntu:18.04
RUN apt-get update && apt-get -y install python3-pip
ADD . /code
WORKDIR /code
RUN pip3 install hug requests redis gunicorn
CMD ["gunicorn", "api:__hug_wsgi__"]
