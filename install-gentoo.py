#!/usr/bin/env python

from pkgutil import iter_modules
from subprocess import call

dependencies = {
    "Crypto": "dev-python/pycrypto",
    "dpkt": "dev-python/dpkt",
    "IPy": "dev-python/ipy",
    "pcap": "dev-python/pypcap"
    "pygeoip" : "dev-python/pygeoip"
 }

installed, missing_pkgs = [pkg[1] for pkg in iter_modules()], []

for module, pkg in dependencies.items():
    if module not in installed:
        print("dshell requires {}".format(module))
        missing_pkgs.append("python-{}".format(pkg))
    else:
        print("{} is installed".format(module))

if missing_pkgs:
    cmd = ["emerge-sync && emerge -v",] + missing_pkgs  #  Emerge -av --ask --verbose else emerge foo --quiet to shut up build/emerge messages

    print(" ".join(cmd))
    call(cmd)

call(["make", "rc"]) ## Gentoo way is hell NO! , make all but docs, 
call(["make", "initpy"]) ## Gentoo way is hell NO! , make all but docs, 
### Give user Choice Add the dependency for Pydocs epyoc , Fine package controls Is the Gentoo way, 
 Docs= input('Would You Like DSHELL DOCS?')
if Docs == 'yes' or 'Yes':
    dependencies = {
        "pydoc":"dev-python/epydoc"
        }
 call(["make", "pydoc"])
else:
  print ("Sorry for asking...")
