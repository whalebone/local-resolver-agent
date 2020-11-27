FROM ubuntu:20.04
RUN apt-get update -y && \
    apt-get install -y python3-pip nano net-tools

RUN pip3 --no-cache-dir install "docker==3.0.1" psutil "websockets==8.0.2" pyaml netifaces dnspython cryptography requests aiodocker

HEALTHCHECK --interval=60s CMD python3 docker_healthcheck.py || kill `pidof python3`

RUN mkdir -p /opt/agent/certs /etc/whalebone/logs /etc/whalebone/compose /etc/whalebone/cli/
WORKDIR /opt/whalebone/
COPY . .

CMD ["/opt/whalebone/lr_agent.sh"]