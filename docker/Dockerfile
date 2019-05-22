FROM ubuntu:18.04

ENV DEBIAN_FRONTEND="noninteractive"

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
RUN git -C /opt clone https://github.com/USArmyResearchLab/Dshell.git

# download and untar GeoIP files
WORKDIR /opt/Dshell/share/GeoIP/
RUN wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz \
    && wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz \
    && tar -zxf GeoLite2-Country.tar.gz \
    && tar -zxf GeoLite2-ASN.tar.gz \
    && ln -s GeoLite2-Country*/GeoLite2-Country.mmdb . \
    && ln -s GeoLite2-ASN*/GeoLite2-ASN.mmdb . \
    && rm -rf /var/lib/apt/lists/*

# make Dshell
WORKDIR /opt/Dshell/
RUN make

# Used to mount pcap from a host OS directory
VOLUME ["/mnt/pcap"]

ENTRYPOINT ["/opt/Dshell/dshell"]
