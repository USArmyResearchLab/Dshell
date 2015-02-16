#!/usr/bin/env python

from pkgutil import iter_modules
from subprocess import call
import urllib
import os
import gzip

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

#get current path
path = os.path.dirname(os.path.realpath(__file__))

dshellrc = os.path.isfile(path+'/.dshellrc')
dshell = os.path.isfile(path+'/dshell')
dshell_decode = os.path.isfile(path+'/dshell-decode')

#checks if files exist if not continues
if not dshell and not dshellrc and  not dshell_decode:
    call(["make", "all"])


#used to download GeoIP Files
geoFiles = [['GeoIP.dat','http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz'],
            ['GeoIPv6.dat','http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz'],
            ['GeoIPASNum.dat','http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz'],
            ['GeoIPASNumv6.dat','http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz']]

#append to directory
path += '/share/GeoIP/'


for geoFile,link in geoFiles:
    #if file does not exist
    if not os.path.isfile(path+geoFile+'.gz'):
        try:
            #download file
            urllib.urlretrieve(link,path+geoFile+'.gz')
            #open compressed file
            inF = gzip.GzipFile(path+geoFile+'.gz','rb')
            #read in compressed file
            s = inF.read()
            #close file
            inF.close()

            #open output file
            outF = file(path+geoFile, 'wb')
            #write output file
            outF.write(s)
            #close output file
            outF.close()
            #remove compressed file (just a little clean up!!)
            os.remove(path+geoFile+'.gz')
        except:
            pass