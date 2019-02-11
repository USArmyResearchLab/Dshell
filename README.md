# Dshell

An extensible network forensic analysis framework.  Enables rapid development of plugins to support the dissection of network packet captures.

Key features:


* Robust stream reassembly
* IPv4 and IPv6 support
* Custom output handlers
* Chainable decoders

## Prerequisites

* Linux (developed on Ubuntu 12.04)
* Python 2.7
* [geoip2](https://github.com/maxmind/GeoIP2-python), Apache License, Version 2.0
  * [MaxMind GeoIP datasets](https://dev.maxmind.com/geoip/geoip2/geolite2/)
* [PyCrypto](https://pypi.python.org/pypi/pycrypto), custom license
* [dpkt](https://code.google.com/p/dpkt/), New BSD License
* [IPy](https://github.com/haypo/python-ipy), BSD 2-Clause License
* [pypcap](https://code.google.com/p/pypcap/), New BSD License
* [elasticsearch-py](https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/index.html), Apache License, Version 2.0 - optional, used only with Dshell's elasticout output module

## Installation

1. Install all of the necessary Python modules listed above. Many of them are available via pip and/or apt-get.

  * `sudo pip install geoip2 pycrypto dpkt IPy pypcap`

2. Configure GeoIP by moving the MaxMind data files (GeoLite2-Country.mmdb, GeoLite2-ASN.mmdb) to &lt;install-location&gt;/share/GeoIP/

2. Run `make`. This will build Dshell.

3. Run `./dshell`. This is Dshell. If you get a Dshell> prompt, you're good to go!

## Basic usage

* `decode -l`
  * This will list all available decoders alongside basic information about them
* `decode -h`
  * Show generic command-line flags available to most decoders
* `decode -d <decoder>`
  * Display information about a decoder, including available command-line flags
* `decode -d <decoder> <pcap>`
  * Run the selected decoder on a pcap file

## Development
* [Using Dshell With PyCharm](doc/UsingDshellWithPyCharm.md)

## Recent Major Updates

* Feb 2019 - Removed deprecated pygeoip dependency, and replaced it with geoip2. This requires the use of new GeoIP data files, listed in the Prerequisites and Installation sections above.

## Partners

Below are repositories from partners Dshell has worked together with.

* [DeKrych/Dshell-plugins](https://github.com/DeKrych/Dshell-plugins)
* [terry-wen/Network-Visualization-Project](https://github.com/terry-wen/Network-Visualization-Project)

## Usage Examples

Showing DNS lookups in [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted)

```
Dshell> decode -d dns ~/pcap/dns.cap
dns 2005-03-30 03:47:46    192.168.170.8:32795 ->   192.168.170.20:53    ** 39867 PTR? 66.192.9.104 / PTR: 66-192-9-104.gen.twtelecom.net **
dns 2005-03-30 03:47:46    192.168.170.8:32795 ->   192.168.170.20:53    ** 30144 A? www.netbsd.org / A: 204.152.190.12 (ttl 82159s) **
dns 2005-03-30 03:47:46    192.168.170.8:32795 ->   192.168.170.20:53    ** 61652 AAAA? www.netbsd.org / AAAA: 2001:4f8:4:7:2e0:81ff:fe52:9a6b (ttl 86400s) **
dns 2005-03-30 03:47:46    192.168.170.8:32795 ->   192.168.170.20:53    ** 32569 AAAA? www.netbsd.org / AAAA: 2001:4f8:4:7:2e0:81ff:fe52:9a6b (ttl 86340s) **
dns 2005-03-30 03:47:46    192.168.170.8:32795 ->   192.168.170.20:53    ** 36275 AAAA? www.google.com / CNAME: www.l.google.com **
dns 2005-03-30 03:47:46    192.168.170.8:32795 ->   192.168.170.20:53    ** 9837 AAAA? www.example.notginh / NXDOMAIN **
dns 2005-03-30 03:52:17    192.168.170.8:32796 <-   192.168.170.20:53    ** 23123 PTR? 127.0.0.1 / PTR: localhost **
dns 2005-03-30 03:52:25   192.168.170.56:1711  <-      217.13.4.24:53    ** 30307 A? GRIMM.utelsystems.local / NXDOMAIN **
dns 2005-03-30 03:52:17   192.168.170.56:1710  <-      217.13.4.24:53    ** 53344 A? GRIMM.utelsystems.local / NXDOMAIN **
```

Following and reassembling a stream in [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted)

```
Dshell> decode -d followstream ~/pcap/v6-http.cap
Connection 1 (TCP)
Start: 2007-08-05 19:16:44.189852 UTC
  End: 2007-08-05 19:16:44.204687 UTC
2001:6f8:102d:0:2d0:9ff:fee3:e8de:59201 -> 2001:6f8:900:7c0::2:80 (240 bytes)
2001:6f8:900:7c0::2:80 -> 2001:6f8:102d:0:2d0:9ff:fee3:e8de:59201 (2259 bytes)

GET / HTTP/1.0
Host: cl-1985.ham-01.de.sixxs.net
Accept: text/html, text/plain, text/css, text/sgml, */*;q=0.01
Accept-Encoding: gzip, bzip2
Accept-Language: en
User-Agent: Lynx/2.8.6rel.2 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8b

HTTP/1.1 200 OK
Date: Sun, 05 Aug 2007 19:16:44 GMT
Server: Apache
Content-Length: 2121
Connection: close
Content-Type: text/html

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /</title>
 </head>
 <body>
<h1>Index of /</h1>
<pre><img src="/icons/blank.gif" alt="Icon "> <a href="?C=N;O=D">Name</a>                    <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a><hr><img src="/icons/folder.gif" alt="[DIR]"> <a href="202-vorbereitung/">202-vorbereitung/</a>       06-Jul-2007 14:31    -   
<img src="/icons/layout.gif" alt="[   ]"> <a href="Efficient_Video_on_demand_over_Multicast.pdf">Efficient_Video_on_d..&gt;</a> 19-Dec-2006 03:17  291K  
<img src="/icons/unknown.gif" alt="[   ]"> <a href="Welcome%20Stranger!!!">Welcome Stranger!!!</a>     28-Dec-2006 03:46    0   
<img src="/icons/text.gif" alt="[TXT]"> <a href="barschel.htm">barschel.htm</a>            31-Jul-2007 02:21   44K  
<img src="/icons/folder.gif" alt="[DIR]"> <a href="bnd/">bnd/</a>                    30-Dec-2006 08:59    -   
<img src="/icons/folder.gif" alt="[DIR]"> <a href="cia/">cia/</a>                    28-Jun-2007 00:04    -   
<img src="/icons/layout.gif" alt="[   ]"> <a href="cisco_ccna_640-801_command_reference_guide.pdf">cisco_ccna_640-801_c..&gt;</a> 28-Dec-2006 03:48  236K  
<img src="/icons/folder.gif" alt="[DIR]"> <a href="doc/">doc/</a>                    19-Sep-2006 01:43    -   
<img src="/icons/folder.gif" alt="[DIR]"> <a href="freenetproto/">freenetproto/</a>           06-Dec-2006 09:00    -   
<img src="/icons/folder.gif" alt="[DIR]"> <a href="korrupt/">korrupt/</a>                03-Jul-2007 11:57    -   
<img src="/icons/folder.gif" alt="[DIR]"> <a href="mp3_technosets/">mp3_technosets/</a>         04-Jul-2007 08:56    -   
<img src="/icons/text.gif" alt="[TXT]"> <a href="neues_von_rainald_goetz.htm">neues_von_rainald_go..&gt;</a> 21-Mar-2007 23:27   31K  
<img src="/icons/text.gif" alt="[TXT]"> <a href="neues_von_rainald_goetz0.htm">neues_von_rainald_go..&gt;</a> 21-Mar-2007 23:29   36K  
<img src="/icons/layout.gif" alt="[   ]"> <a href="pruef.pdf">pruef.pdf</a>               28-Dec-2006 07:48   88K  
<hr></pre>
</body></html>
```

Chaining decoders to view flow data for a specific country code in [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted) (note: TCP handshakes are not included in the packet count)

```
Dshell> decode -d country+netflow --country_code=JP ~/pcap/SkypeIRC.cap
2006-08-25 19:32:20.651502       192.168.1.2 ->  202.232.205.123  (-- -> JP)  UDP   60583   33436     1      0       36        0  0.0000s
2006-08-25 19:32:20.766761       192.168.1.2 ->  202.232.205.123  (-- -> JP)  UDP   60583   33438     1      0       36        0  0.0000s
2006-08-25 19:32:20.634046       192.168.1.2 ->  202.232.205.123  (-- -> JP)  UDP   60583   33435     1      0       36        0  0.0000s
2006-08-25 19:32:20.747503       192.168.1.2 ->  202.232.205.123  (-- -> JP)  UDP   60583   33437     1      0       36        0  0.0000s
```

Collecting netflow data for [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted) with vlan headers, then tracking the connection to a specific IP address

```
Dshell> decode -d netflow ~/pcap/vlan.cap
1999-11-05 18:20:43.170500    131.151.20.254 ->  255.255.255.255  (US -> --)  UDP     520     520     1      0       24        0  0.0000s
1999-11-05 18:20:42.063074     131.151.32.71 ->   131.151.32.255  (US -> US)  UDP     138     138     1      0      201        0  0.0000s
1999-11-05 18:20:43.096540     131.151.1.254 ->  255.255.255.255  (US -> --)  UDP     520     520     1      0       24        0  0.0000s
1999-11-05 18:20:43.079765     131.151.5.254 ->  255.255.255.255  (US -> --)  UDP     520     520     1      0       24        0  0.0000s
1999-11-05 18:20:41.521798    131.151.104.96 ->  131.151.107.255  (US -> US)  UDP     137     137     3      0      150        0  1.5020s
1999-11-05 18:20:43.087010     131.151.6.254 ->  255.255.255.255  (US -> --)  UDP     520     520     1      0       24        0  0.0000s
1999-11-05 18:20:43.368210   131.151.111.254 ->  255.255.255.255  (US -> --)  UDP     520     520     1      0       24        0  0.0000s
1999-11-05 18:20:43.250410    131.151.32.254 ->  255.255.255.255  (US -> --)  UDP     520     520     1      0       24        0  0.0000s
1999-11-05 18:20:43.115330    131.151.10.254 ->  255.255.255.255  (US -> --)  UDP     520     520     1      0       24        0  0.0000s
1999-11-05 18:20:43.375145   131.151.115.254 ->  255.255.255.255  (US -> --)  UDP     520     520     1      0       24        0  0.0000s
1999-11-05 18:20:43.363348   131.151.107.254 ->  255.255.255.255  (US -> --)  UDP     520     520     1      0       24        0  0.0000s
1999-11-05 18:20:40.112031      131.151.5.55 ->    131.151.5.255  (US -> US)  UDP     138     138     1      0      201        0  0.0000s
1999-11-05 18:20:43.183825     131.151.32.79 ->   131.151.32.255  (US -> US)  UDP     138     138     1      0      201        0  0.0000s
```
