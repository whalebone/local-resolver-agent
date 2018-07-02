#FROM python:3.6

FROM ubuntu:18.04
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y python3-pip build-essential python3-dev nano


RUN useradd -s /sbin/nologin -G staff whalebone
RUN mkdir -p /opt/whalebone/ && chown whalebone /opt/whalebone/ && chgrp whalebone /opt/whalebone/ && chmod ug+rwxs /opt/whalebone/
RUN mkdir -p /etc/whalebone/logs && chown whalebone /etc/whalebone/logs && chgrp whalebone /etc/whalebone/logs && chmod ug+rwxs /etc/whalebone/logs
RUN mkdir -p /etc/whalebone/compose && chown whalebone /etc/whalebone/compose && chgrp whalebone /etc/whalebone/compose && chmod ug+rwxs /etc/whalebone/compose

WORKDIR /opt/whalebone/

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .
RUN chown whalebone /opt/whalebone/ -R && chgrp whalebone /opt/whalebone/ -R && chmod g+s /opt/whalebone/ -R

RUN mkdir /etc/whalebone/cli
RUN cp cli.sh /etc/whalebone/cli/cli.sh

#USER whalebone
CMD ["/opt/whalebone/lr_agent.sh"]
