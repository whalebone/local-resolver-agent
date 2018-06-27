FROM python:3.6
ADD . /code
WORKDIR /code
RUN pip install hug requests redis gunicorn
CMD ["gunicorn", "api:__hug_wsgi__"]
