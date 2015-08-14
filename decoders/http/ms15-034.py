import dshell
import util
from httpdecoder import HTTPDecoder

class DshellDecoder(HTTPDecoder):
    '''
    15 April 2015

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
    '''
    def __init__(self):
        HTTPDecoder.__init__(self,
                             name='ms15-034',
                             description='detect attempts to enumerate MS15-034 vulnerable IIS servers',
                             longdescription='''
Proof-of-concept code to detect attempts to enumerate MS15-034 vulnerable
IIS servers and/or cause a denial of service.  Each event will generate an
alert that prints out the HTTP Request method and the range value contained
with the HTTP stream.

Usage: 
decode -d ms15-034 -q *.pcap
decode -d ms15-034 -i <interface> -q
''',
                          filter='tcp and (port 80 or port 8080 or port 8000)',
                          filterfn=lambda ((sip, sp), (dip, dp)): sp in (
                              80, 8000, 8080) or dp in (80, 8000, 8080),
                          author='bg',
                          )

    def HTTPHandler(self, conn, request, response, requesttime, responsetime):
        if response == None: # Denial of Service (no server response)
            try: 
                rangestr = util.getHeader(request,'range')
                # check range value to reduce false positive rate
                if not rangestr.endswith('18446744073709551615'): return 
            except: return
            self.alert('MS15-034 DoS [Request Method: "%s" URI: "%s" Range: "%s"]' % \
                         (request.method, request.uri, rangestr), conn.info())

        else: # probing for vulnerable server
            try:
                rangestr = util.getHeader(request,'range')
                # check range value to reduce false positive rate
                if not rangestr.endswith('18446744073709551615'): return 
            except: return

            # indication of vulnerable server
            if rangestr and (response.status == '416' or \
                             response.reason == 'Requested Range Not Satisfiable'):

                self.alert('MS15-034 Vulnerable Server  [Request Method: "%s" Range: "%s"]' % 
                            (request.method,rangestr), conn.info())

                if request.method != 'GET': # this could be interesting 
                    pass # waiting on more details


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
