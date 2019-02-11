FROM ubuntu:14.04

# install depdencies
RUN apt-get update && apt-get install -y \
  python-crypto \
  python-dpkt \
  python-ipy \
  python-pypcap \
  python-pip \
  python-geoip2 \
  wget \
  git

# Download the latest version of the code from GitHub
WORKDIR /opt/
RUN git clone https://github.com/USArmyResearchLab/Dshell.git

# download and untar GeoIP files
WORKDIR /opt/Dshell/share/GeoIP/
RUN wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz
RUN wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz
RUN tar -zxf GeoLite2-Country.tar.gz
RUN tar -zxf GeoLite2-ASN.tar.gz
RUN GeoLite2-Country*/GeoLite2-Country.mmdb .
RUN GeoLite2-ASN*/GeoLite2-ASN.mmdb .

# make Dshell
WORKDIR /opt/Dshell/
RUN make

# Used to mount pcap from a host OS directory
VOLUME ["/mnt/pcap"]

CMD ["/opt/Dshell/dshell"]
