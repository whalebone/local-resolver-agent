curl -s https://releases.rancher.com/install-docker/19.03.sh | sh
docker login harbor.whalebone.io
apt-get install -y docker-compose
rm /etc/resolv.conf
ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl disable systemd-resolved.service
service systemd-resolved stop
docker-compose up -d