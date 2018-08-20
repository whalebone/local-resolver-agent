FROM python:3.6
#RUN apt-get update && apt-get install git
WORKDIR /root/
#RUN git clone https://github.com/secdev/scapy.git
#WORKDIR /root/scapy/
#RUN python setup.py install
RUN pip install requests redis pyyaml docker dnspython websockets asyncio
ADD . /code
WORKDIR /code
CMD ["python", "tester.py"]
