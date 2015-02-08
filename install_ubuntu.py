#!/usr/bin/env python

'''
    script for installation on Ubuntu
'''

from pkgutil import iter_modules
from subprocess import call

DEPENDENCIES = {
    "Crypto": "crypto",
    "dpkt": "dpkt",
    "IPy": "ipy",
    "pcap": "pypcap"
}

INSTALLED, MISSING_PKGS = [pkg[1] for pkg in iter_modules()], []

for module, pkg in DEPENDENCIES.items():
    if module not in INSTALLED:
        print "dshell requires {}".format(module)
        MISSING_PKGS.append("python-{}".format(pkg))
    else:
        print "{} is INSTALLED".format(module)

if MISSING_PKGS:
    CMD = ["sudo", "apt-get", "install"] + MISSING_PKGS

    print " ".join(CMD)
    call(CMD)

call(["make", "all"])
