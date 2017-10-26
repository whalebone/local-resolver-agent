FROM python:3

RUN useradd -s /sbin/nologin -G staff whalebone
RUN mkdir -p /opt/whalebone && chown whalebone /opt/whalebone && chgrp whalebone /opt/whalebone && chmod ug+rwxs /opt/whalebone

WORKDIR /opt/whalebone

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown whalebone /opt/whalebone/ -R && chgrp whalebone /opt/whalebone/ -R && chmod g+s /opt/whalebone/ -R

USER whalebone
CMD ["/opt/whalebone/lr_agent.sh"]