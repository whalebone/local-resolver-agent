FROM python:3.5

RUN useradd -s /sbin/nologin -G staff whalebone
RUN mkdir -p /opt/whalebone && chown whalebone /opt/whalebone && chgrp whalebone /opt/whalebone && chmod ug+rwxs /opt/whalebone
RUN mkdir -p /etc/whalebone/logs && chown whalebone /etc/whalebone/logs && chgrp whalebone /etc/whalebone/logs && chmod ug+rwxs /etc/whalebone/logs
RUN mkdir -p /etc/whalebone/kresd && chown whalebone /etc/whalebone/kresd && chgrp whalebone /etc/whalebone/kresd && chmod ug+rwxs /etc/whalebone/kresd
RUN mkdir -p /etc/whalebone/compose && chown whalebone /etc/whalebone/compose && chgrp whalebone /etc/whalebone/compose && chmod ug+rwxs /etc/whalebone/compose

WORKDIR /opt/whalebone

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown whalebone /opt/whalebone/ -R && chgrp whalebone /opt/whalebone/ -R && chmod g+s /opt/whalebone/ -R

#USER whalebone
CMD ["/opt/whalebone/lr_agent.sh"]
