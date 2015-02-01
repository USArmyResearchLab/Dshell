#!/bin/bash

pkgs=""

if `python -c 'import dpkt'`; 
then echo "dpkt is installed"
else
	echo "dshell requires dpkt"
	pkgs="$pkgs python-dpkt"
fi

if `python -c 'from IPy import IP'`; 
then echo "IPy is installed"
else
	echo "dshell requires IPy"
	pkgs="$pkgs python-ipy"
fi

if `python -c 'from pcap import pcap'`; 
then echo "pypcap is installed"
else
	echo "dshell requires pypcap"
	pkgs="$pkgs python-pypcap"
fi

cmd="sudo apt-get install $pkgs"
if [ "$pkgs" ]; then 
	echo 
	echo $cmd
	echo
	$cmd; 
fi

make all
