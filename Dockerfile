FROM ubuntu:20.04

ENV GOSU_URL https://github.com/tianon/gosu/releases/download/1.12/gosu

RUN apt-get update -y && \
    apt-get install -y python3-pip nano net-tools ca-certificates curl gpg && \
    gpg --keyserver ha.pool.sks-keyservers.net --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 && \
    curl -o /usr/local/bin/gosu -SL "$GOSU_URL-$(dpkg --print-architecture)" && \
    curl -o /usr/local/bin/gosu.asc -SL "$GOSU_URL-$(dpkg --print-architecture).asc" && \
    gpg --verify /usr/local/bin/gosu.asc && \
    rm /usr/local/bin/gosu.asc && \
    rm -rf /var/lib/apt/lists/* && \
    chmod +x /usr/local/bin/gosu

RUN mkdir -p /opt/agent/certs /etc/whalebone/logs /etc/whalebone/compose /etc/whalebone/cli/

#USER agent

RUN pip3 install --no-cache-dir "docker==3.0.1" psutil "websockets==8.0.2" pyaml netifaces dnspython cryptography requests

#HEALTHCHECK CMD netstat -tupan | grep "159.100.255.126:443" | grep python3
HEALTHCHECK --interval=60s CMD python3 docker_healthcheck.py || kill `pidof python3`

WORKDIR /opt/agent/
COPY . .

ENTRYPOINT ["sh", "/opt/agent/entrypoint.sh"]
CMD ["bash","/opt/agent/lr_agent.sh"]
