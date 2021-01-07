FROM python:3.9-slim-buster
RUN pip3 install requests redis pyyaml docker dnspython websockets
ADD . /code
WORKDIR /code
CMD ["python3", "tester.py"]
