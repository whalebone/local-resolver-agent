FROM ubuntu:20.04

RUN apt-get update -y && \
    apt-get install -y python3-pip nano net-tools

RUN pip3 install --no-cache-dir "docker==3.0.1" psutil "websockets==8.0.2" pyaml netifaces dnspython cryptography requests

#HEALTHCHECK CMD netstat -tupan | grep "159.100.255.126:443" | grep python3
HEALTHCHECK --interval=60s CMD python3 docker_healthcheck.py || kill `pidof python3`

RUN mkdir -p /opt/agent/certs /etc/whalebone/logs /etc/whalebone/compose /etc/whalebone/cli/
WORKDIR /opt/agent/
COPY . .

CMD ["/opt/agent/lr_agent.sh"]
