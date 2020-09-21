FROM ubuntu:18.04

ENV DEBIAN_FRONTEND="noninteractive"

ARG packages=" \
  git \
  make \
  python-crypto \
  python-dpkt \
  python-geoip2 \
  python-ipy \
  python-pip \
  python-pypcap \
  wget \
"

# install depdencies
RUN apt-get update && apt-get install -qq --no-install-recommends ${packages} \
    && rm -rf /var/lib/apt/lists/*

# Download the and build latest version of the code from GitHub
RUN git -C /opt clone 'https://github.com/USArmyResearchLab/Dshell.git' \
    && cd /opt/Dshell \
    && make

# Used to mount pcap from a host OS directory
VOLUME ["/mnt/pcap"]

WORKDIR /mnt/pcap

ENTRYPOINT ["/opt/Dshell/dshell"]
