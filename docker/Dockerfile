FROM ubuntu:14.04

# install depdencies
RUN apt-get update && apt-get install -y \
  python-crypto \
  python-dpkt \
  python-ipy \ 
  python-pypcap \
  python-pip \
  wget \
  git

RUN pip install pygeoip

# Download the latest version of the code from GitHub
WORKDIR /opt/
RUN git clone https://github.com/USArmyResearchLab/Dshell.git

# download and gunzip GeoIP files
WORKDIR /opt/Dshell/share/GeoIP/
RUN wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
RUN wget http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
RUN wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
RUN wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz
RUN gunzip *.gz

# make Dshell
WORKDIR /opt/Dshell/
RUN make

# Used to mount pcap from a host OS directory
VOLUME ["/mnt/pcap"]

CMD ["/opt/Dshell/dshell"]
