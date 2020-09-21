"""
Detect and dissect malformed HTTP headers targeting Joomla

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8562
"""

from dshell.plugins.httpplugin import HTTPPlugin
from dshell.output.alertout import AlertOutput

import re

class DshellPlugin(HTTPPlugin):
    def __init__(self):
        super().__init__(
            name="Joomla CVE-2015-8562",
            author="bg",
            description='detect attempts to enumerate MS15-034 vulnerable IIS servers',
            bpf='tcp and (port 80 or port 8080 or port 8000)',
            output=AlertOutput(label=__name__),
            optiondict={
                "raw_payload": {
                    "action": "store_true",
                    "help": "return the raw payload (do not attempt to decode chr encoding)",
                }
            },
            longdescription='''
Detect and dissect malformed HTTP headers targeting Joomla

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8562

Usage Examples:
---------------

Dshell> decode -d joomla *.pcap
[Joomla CVE-2015-8562] 2015-12-15 20:17:18    192.168.1.119:43865 <-    192.168.1.139:80    ** x-forwarded-for -> system('touch /tmp/2'); **

The module assumes the cmd payload is encoded using chr.  To turn this off run:

Dshell> decode -d joomla --joomla_raw_payload *.pcap
[Joomla CVE-2015-8562] 2015-12-15 20:17:18    192.168.1.119:43865 <-    192.168.1.139:80    ** x-forwarded-for -> "eval(chr(115).chr(121).chr(115).chr(116).chr(101).chr(109).chr(40).chr(39).chr(116).chr(111).chr(117).chr(99).chr(104).chr(32).chr(47).chr(116).chr(109).chr(112).chr(47).chr(50).chr(39).chr(41).chr(59)); **
''',
        )

        # Indicator of (potential) compromise
        self.ioc = "JFactory::getConfig();exit"
        self.ioc_bytes = bytes(self.ioc, "ascii")

    def attempt_decode(self, cmd):
        ptext = ''
        for c in re.findall('\d+', cmd):
            ptext += chr(int(c))
        return ptext

    def parse_cmd(self, data):
        start = data.find('"feed_url";')+11
        end = data.find(self.ioc)
        chunk = data[start:end]

        try:
            cmd = chunk.split(':')[-1]
            if self.raw_payload:
                return cmd

            plaintext_cmd = self.attempt_decode(cmd)
            return plaintext_cmd
        except:
            return None

    def http_handler(self, conn, request, response):
        if not request:
            return

        if self.ioc_bytes not in request.blob.data:
            # indicator of (potential) compromise is not here
            return

        # there is an attempt to exploit Joomla!

        # The Joomla exploit could be sent any HTTP header field
        for hdr, val in request.headers.items():
            if self.ioc in val:
                cmd = self.parse_cmd(val)
                if cmd:
                    self.alert('{} -> {}'.format(hdr, cmd), **conn.info())
                    return conn, request, response

