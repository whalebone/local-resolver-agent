FROM ubuntu:18.04
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y python3-pip nano net-tools

RUN mkdir -p /opt/whalebone/ /etc/whalebone/logs /etc/whalebone/compose /etc/whalebone/cli/

RUN pip3 install "docker==3.0.1" psutil "websockets==4.0.1" pyaml netifaces dnspython cryptography requests

#RUN mkdir -p /opt/whalebone/ /etc/whalebone/logs /etc/whalebone/compose /etc/whalebone/cli/
#RUN useradd -s /sbin/nologin -G staff whalebone
#RUN mkdir -p /opt/whalebone/ && chown whalebone /opt/whalebone/ && chgrp whalebone /opt/whalebone/ && chmod ug+rwxs /opt/whalebone/
#RUN mkdir -p /etc/whalebone/logs && chown whalebone /etc/whalebone/logs && chgrp whalebone /etc/whalebone/logs && chmod ug+rwxs /etc/whalebone/logs
#RUN mkdir -p /etc/whalebone/compose && chown whalebone /etc/whalebone/compose && chgrp whalebone /etc/whalebone/compose && chmod ug+rwxs /etc/whalebone/compose

WORKDIR /opt/whalebone/

COPY . .
#RUN chown whalebone /opt/whalebone/ -R && chgrp whalebone /opt/whalebone/ -R && chmod g+s /opt/whalebone/ -R

#RUN mkdir /etc/whalebone/cli/
COPY cli.sh /etc/whalebone/cli/cli.sh

#USER whalebone
CMD ["/opt/whalebone/lr_agent.sh"]
