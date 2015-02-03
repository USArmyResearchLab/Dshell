#!/usr/bin/env python

from pkgutil import iter_modules
from subprocess import call

dependencies = {
    "Crypto": "crypto",
    "dpkt": "dpkt",
    "IPy": "ipy",
    "pcap": "pypcap"
}

installed, missing_pkgs = [pkg[1] for pkg in iter_modules()], []

for module, pkg in dependencies.items():
    if module not in installed:
        print("dshell requires {}".format(module))
        missing_pkgs.append("python-{}".format(pkg))
    else:
        print("{} is installed".format(module))

if missing_pkgs:
    cmd = ["sudo", "apt-get", "install"] + missing_pkgs

    print(" ".join(cmd))
    call(cmd)

call(["make", "all"])
