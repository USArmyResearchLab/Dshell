# Dshell
An extensible network forensic analysis framework. Enables rapid development of plugins to support the dissection of network packet captures.

Key features:
* Deep packet analysis using specialized plugins
* Robust stream reassembly
* IPv4 and IPv6 support
* Custom output handlers
* Chainable plugins

## Requirements
* Linux (developed on Red Hat Enterprise Linux 6.7)
* Python 3 (developed with Python 3.6.2)
* [pypacker](https://gitlab.com/mike01/pypacker)
* [pcapy](https://github.com/helpsystems/pcapy)
* [pyOpenSSL](https://github.com/pyca/pyopenssl)
* [geoip2](https://github.com/maxmind/GeoIP2-python)
  * [MaxMind GeoIP2 datasets](https://dev.maxmind.com/geoip/geoip2/geolite2/)

## Optional
* [oui.txt](http://standards-oui.ieee.org/oui.txt)
  * used by some plugins that handle MAC addresses
  * place in &lt;dshell&gt;/data/
* [elasticsearch](https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/index.html)
  * used in the elasticout output module
  * only necessary if planning to use elasticsearch to store output
* [pyJA3](https://github.com/salesforce/ja3/tree/master/python)
  * used in the tls plugin

## Major Changes Since Previous Release
* This is a major framework update to Dshell. Plugins written for the previous version are not compatible with this version, and vice versa.
* Uses Python 3
  * Rewritten in Python 3 from the ground up. Python 2 language deprecated on [1 JAN 2020](https://www.python.org/doc/sunset-python-2/)
  * By extension, dpkt and pypcap have been replaced with Python3-friendly pypacker and pcapy (respectively).
* Is a Python package
  * Converted into a single package, removing the need for the shell to set several environment variables.
  * Allows easier use of Dshell plugins in other Python scripts
* Changed "decoders" to "plugins"
  * Primarily a word-swap, to clarify that "decoders" can do more than simply decode traffic, and to put Dshell more in line with the terminology of other frameworks.
* Significant reduction in camelCase functions, replaced with more Pythonic snake\_case functions.
  * Notable examples include blobHandler->blob\_handler, rawHandler->raw\_handler, connectionInitHandler->connection\_init\_handler, etc.
* All plugins are now chainable
  * To accommodate this, handler functions in plugins must now use return statements indicating whether a packet, connection, or similar will continue to the next plugin. The type of object(s) to return depends on the type of handler, but will generally match the types of the handler's input. Dshell will display a warning if it's not the right type.
* Plugins can now use all output modules<sup>\*</sup> available to the command line switch, -O
  * That does not mean every output module will be _useful_ to every plugin (e.g. using netflow output for a plugin that looks at individual packets), but they are available.
  * alert(), write(), and dump() are now the same function: write()
  * Output modules can be listed with a new flag in decode.py, --list-output or --lo
  * Arguments for output modules are now passed with the --oargs command-line argument
  * \* pcapout is (currently) the exception to this rule. A method has yet to arise that allows it to work with connection-based plugins
* No more dObj declaration
  * decode.py just looks for the class named DshellPlugin and creates an instance of that
* Improved error handling
  * Dshell handles more of the most common exceptions during everyday use
* Enables development of external plugin packs, allowing the sharing and installation of new, externally-developed plugins without overlapping the core Dshell libraries.

## Installation

1. Install Dshell with pip
  * `python3 -m pip install Dshell/` OR `python3 -m pip install <Dshell-tarball>`
2. Configure geoip2 by moving the MaxMind data files (GeoLite2-ASN.mmdb, GeoLite2-City.mmdb, GeoLite2-Country.mmdb) to [...]/site-packages/dshell/data/GeoIP/
3. Run `dshell`. This should drop you into a `Dshell> ` prompt.

## Basic Usage

* `decode -l`
  * This will list all available plugins, alongside basic information about them
* `decode -h`
  * Show generic command-line flags available to most plugins
* `decode -p <plugin>`
  * Display information about a plugin, including available command line flags
* `decode -p <plugin> <pcap>`
  * Run the selected plugin on a pcap file
* `decode -p <plugin1>+<plugin2> <pcap>`
  * Chain two (or more) plugins together and run them on a pcap file
* `decode -p <plugin> -i <interface>`
  * Run the selected plugin live on an interface (may require superuser privileges)

## Usage Examples
Showing DNS lookups in [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted)

```
Dshell> decode -p dns ~/pcap/dns.cap |sort
[DNS] 2005-03-30 03:47:46    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 4146, TXT? google.com., TXT: b'\x0fv=spf1 ptr ?all' **
[DNS] 2005-03-30 03:47:50    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 63343, MX? google.com., MX: b'\x00(\x05smtp4\xc0\x0c', MX: b'\x00\n\x05smtp5\xc0\x0c', MX: b'\x00\n\x05smtp6\xc0\x0c', MX: b'\x00\n\x05smtp1\xc0\x0c', MX: b'\x00\n\x05smtp2\xc0\x0c', MX: b'\x00(\x05smtp3\xc0\x0c' **
[DNS] 2005-03-30 03:47:59    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 18849, LOC? google.com. **
[DNS] 2005-03-30 03:48:07    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 39867, PTR? 104.9.192.66.in-addr.arpa., PTR: 66-192-9-104.gen.twtelecom.net. **
[DNS] 2005-03-30 03:49:18    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 30144, A? www.netbsd.org., A: 204.152.190.12 (ttl 82159s) **
[DNS] 2005-03-30 03:49:35    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 61652, AAAA? www.netbsd.org., AAAA: 2001:4f8:4:7:2e0:81ff:fe52:9a6b (ttl 86400s) **
[DNS] 2005-03-30 03:50:35    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 32569, AAAA? www.netbsd.org., AAAA: 2001:4f8:4:7:2e0:81ff:fe52:9a6b (ttl 86340s) **
[DNS] 2005-03-30 03:50:44    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 36275, AAAA? www.google.com., CNAME: 'www.l.google.com.' **
[DNS] 2005-03-30 03:50:54    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 56482, AAAA? www.l.google.com. **
[DNS] 2005-03-30 03:51:35    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 48159, AAAA? www.example.com. **
[DNS] 2005-03-30 03:51:46    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 9837, AAAA? www.example.notginh., NXDOMAIN **
[DNS] 2005-03-30 03:52:17    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 65251, AAAA: 2001:4f8:0:2::d (ttl 600s), A: 204.152.184.88 (ttl 600s) **
[DNS] 2005-03-30 03:52:17    192.168.170.8:32796 --   192.168.170.20:53    ** ID: 23123, PTR? 1.0.0.127.in-addr.arpa., PTR: localhost. **
[DNS] 2005-03-30 03:52:17    192.168.170.8:32797 --   192.168.170.20:53    ** ID: 8330, NS: b'\x06ns-ext\x04nrt1\xc0\x0c', NS: b'\x06ns-ext\x04sth1\xc0\x0c', NS: b'\x06ns-ext\xc0\x0c', NS: b'\x06ns-ext\x04lga1\xc0\x0c' **
[DNS] 2005-03-30 03:52:17   192.168.170.56:1707  --      217.13.4.24:53    ** ID: 12910, SRV? _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.utelsystems.local., NXDOMAIN **
[DNS] 2005-03-30 03:52:17   192.168.170.56:1708  --      217.13.4.24:53    ** ID: 61793, SRV? _ldap._tcp.dc._msdcs.utelsystems.local., NXDOMAIN **
[DNS] 2005-03-30 03:52:17   192.168.170.56:1709  --      217.13.4.24:53    ** ID: 33633, SRV? _ldap._tcp.05b5292b-34b8-4fb7-85a3-8beef5fd2069.domains._msdcs.utelsystems.local., NXDOMAIN **
[DNS] 2005-03-30 03:52:17   192.168.170.56:1710  --      217.13.4.24:53    ** ID: 53344, A? GRIMM.utelsystems.local., NXDOMAIN **
[DNS] 2005-03-30 03:52:25   192.168.170.56:1711  --      217.13.4.24:53    ** ID: 30307, A? GRIMM.utelsystems.local., NXDOMAIN **
```

Following and reassembling a stream in [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted)

```
Dshell> decode -p followstream ~/pcap/v6-http.cap 
Connection 1 (TCP)
Start: 2007-08-05 15:16:44.189851
End:   2007-08-05 15:16:44.219460
2001:6f8:102d:0:2d0:9ff:fee3:e8de: 59201 -> 2001:6f8:900:7c0::2:    80 (300 bytes)
2001:6f8:900:7c0::2:    80 -> 2001:6f8:102d:0:2d0:9ff:fee3:e8de: 59201 (2379 bytes)

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

Chaining plugins to view flow data for a specific country code in [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted) (note: TCP handshakes are not included in the packet count)

```
Dshell> decode -p country+netflow --country_code=JP ~/pcap/SkypeIRC.cap
2006-08-25 15:32:20.766761       192.168.1.2 ->  202.232.205.123  (-- -> JP)   UDP   60583   33438     1      0       64        0  0.0000s
2006-08-25 15:32:20.634046       192.168.1.2 ->  202.232.205.123  (-- -> JP)   UDP   60583   33435     1      0       64        0  0.0000s
2006-08-25 15:32:20.747503       192.168.1.2 ->  202.232.205.123  (-- -> JP)   UDP   60583   33437     1      0       64        0  0.0000s
2006-08-25 15:32:20.651501       192.168.1.2 ->  202.232.205.123  (-- -> JP)   UDP   60583   33436     1      0       64        0  0.0000s
```

Collecting DNS traffic from several files and storing it in a new pcap file.

```
Dshell> decode -p dns+pcapwriter --pcapwriter_outfile=test.pcap ~/pcap/*.cap >/dev/null
Dshell> tcpdump -nnr test.pcap |head
reading from file test.pcap, link-type EN10MB (Ethernet)
15:36:08.670569 IP 192.168.1.2.2131 > 192.168.1.1.53: 40209+ A? ui.skype.com. (30)
15:36:08.670687 IP 192.168.1.2.2131 > 192.168.1.1.53: 40210+ AAAA? ui.skype.com. (30)
15:36:08.674022 IP 192.168.1.1.53 > 192.168.1.2.2131: 40209- 1/0/0 A 212.72.49.131 (46)
15:36:09.011208 IP 192.168.1.1.53 > 192.168.1.2.2131: 40210 0/1/0 (94)
15:36:10.171350 IP 192.168.1.2.2131 > 192.168.1.1.53: 40210+ AAAA? ui.skype.com. (30)
15:36:10.961350 IP 192.168.1.1.53 > 192.168.1.2.2131: 40210* 0/1/0 (85)
15:36:10.961608 IP 192.168.1.2.2131 > 192.168.1.1.53: 40211+ AAAA? ui.skype.com. (30)
15:36:11.294333 IP 192.168.1.1.53 > 192.168.1.2.2131: 40211 0/1/0 (94)
15:32:21.664798 IP 192.168.1.2.2130 > 192.168.1.1.53: 39862+ A? ui.skype.com. (30)
15:32:21.664913 IP 192.168.1.2.2130 > 192.168.1.1.53: 39863+ AAAA? ui.skype.com. (30)
```

Collecting TFTP data and converting alerts to JSON format using [sample traffic](https://wiki.wireshark.org/SampleCaptures#TFTP)

```
Dshell> decode -p tftp -O jsonout ~/pcap/tftp_*.pcap
{"dport": 3445, "dip": "192.168.0.10", "data": "read  rfc1350.txt (24599 bytes) ", "sport": 50618, "readwrite": "read", "sip": "192.168.0.253", "plugin": "tftp", "ts": 1367411051.972852, "filename": "rfc1350.txt"}
{"dport": 2087, "dip": "192.168.0.13", "data": "write rfc1350.txt (24599 bytes) ", "sport": 57509, "readwrite": "write", "sip": "192.168.0.1", "plugin": "tftp", "ts": 1367053679.45274, "filename": "rfc1350.txt"}
```

Running a plugin within a separate Python script using [sample traffic](https://wiki.wireshark.org/SampleCaptures#TFTP)

```
# Import required Dshell libraries
import dshell.decode as decode
import dshell.plugins.tftp.tftp as tftp

# Instantiate plugin
plugin = tftp.DshellPlugin()
# Define plugin-specific arguments, if needed
dargs = {plugin: {"outdir": "/tmp/"}}
# Add plugin(s) to plugin chain
decode.plugin_chain = [plugin]
# Run decode main function with all other arguments
decode.main(
    debug=True,
    files=["/home/user/pcap/tftp_rrq.pcap", "/home/user/pcap/tftp_wrq.pcap"],
    plugin_args=dargs
)
```
