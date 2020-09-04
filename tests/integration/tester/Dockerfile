FROM python:3.8-slim-buster
#RUN apt-get update && apt-get -y install python3-pip
WORKDIR /root/
#RUN git clone https://github.com/secdev/scapy.git
#WORKDIR /root/scapy/
#RUN python setup.py install
RUN pip3 install requests redis pyyaml docker dnspython websockets
ADD . /code
WORKDIR /code
CMD ["python3", "tester.py"]
