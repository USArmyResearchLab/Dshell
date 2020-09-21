"""
Proof-of-concept code to detect attempts to enumerate MS15-034 vulnerable
IIS servers and/or cause a denial of service.  Each event will generate an
alert that prints out the HTTP Request method and the range value contained
with the HTTP stream.
"""

from dshell.plugins.httpplugin import HTTPPlugin
from dshell.output.alertout import AlertOutput

class DshellPlugin(HTTPPlugin):
    def __init__(self):
        super().__init__(
            name="ms15-034",
            author="bg",
            description='detect attempts to enumerate MS15-034 vulnerable IIS servers',
            bpf='tcp and (port 80 or port 8080 or port 8000)',
            output=AlertOutput(label=__name__),
            longdescription='''
Proof-of-concept code to detect attempts to enumerate MS15-034 vulnerable
IIS servers and/or cause a denial of service.  Each event will generate an
alert that prints out the HTTP Request method and the range value contained
with the HTTP stream.

Usage:
decode -d ms15-034 -q *.pcap
decode -d ms15-034 -i <interface> -q

References:
https://technet.microsoft.com/library/security/ms15-034
https://ma.ttias.be/remote-code-execution-via-http-request-in-iis-on-windows/
''',
        )


    def http_handler(self, conn, request, response):
        if response == None:
            # Denial of Service (no server response)
            try:
                rangestr = request.headers.get("range", '')
                # check range value to reduce false positive rate
                if not rangestr.endswith('18446744073709551615'):
                    return
            except:
                return
            self.write('MS15-034 DoS [Request Method: "{0}" URI: "{1}" Range: "{2}"]'.format(request.method, request.uri, rangestr), conn.info())
            return conn, request, response

        else:
            # probing for vulnerable server
            try:
                rangestr = request.headers.get("range", '')
                if not rangestr.endswith('18446744073709551615'):
                    return
            except:
                return

            # indication of vulnerable server
            if rangestr and (response.status == '416' or \
                             response.reason == 'Requested Range Not Satisfiable'):
                self.write('MS15-034 Vulnerable Server  [Request Method: "{0}" Range: "{1}"]'.format(request.method,rangestr), conn.info())
                return conn, request, response


