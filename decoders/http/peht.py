#
# Author: MM - https://github.com/1modm
#
# Most of the Penetration/Exploit/Hijacking Tools use the HTTP methods to try to inject
# or execute code into the attacked server, also this tools usually have a well known
# "hardcoded" User-Agent, URI or request content.
#
# So if the original scanner is not modified can be detected. This is a PoC in order to generate
# simple rules to detect and identified some of the most commons Penetration/Exploit/Hijacking Tools.
#
# Some of the most commons tools source and information:
#
# Nmap
# User-Agent header by default it is "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)".
# https://nmap.org/nsedoc/lib/http.html
#
# OpenVAS
# http://www.openvas.org/src-doc/openvas-libraries/nasl__http_8c_source.html
# User-Agent header by default: #define OPENVAS_USER_AGENT  "Mozilla/5.0 [en] (X11, U; OpenVAS)"
#
# MASSCAN
# https://github.com/robertdavidgraham/masscan
#
# Morpheus
# https://github.com/r00t-3xp10it/morpheus
# https://latesthackingnews.com/2016/12/19/morpheus-automated-ettercap-tcpip-hijacking-tool/
#
# DataCha0s Web Scanner
# http://eromang.zataz.com/2011/05/23/suc026-datacha0s-web-scannerrobot/
# https://blogs.harvard.edu/zeroday/2006/06/12/data-cha0s-connect-back-backdoor/
#
# HNAP (Home Network Administration Protocol)
# https://nmap.org/nsedoc/scripts/hnap-info.html
#
# ZmEu Scanner
# https://en.wikipedia.org/wiki/ZmEu_(vulnerability_scanner)
# http://linux.m2osw.com/zmeu-attack
# https://code.google.com/archive/p/caffsec-malware-analysis/wikis/ZmEu.wiki
# https://ensourced.wordpress.com/2011/02/25/zmeu-attacks-some-basic-forensic/
# http://philriesch.com/computersecurity_zmeu.html
#
# Jorgee Scanner
# http://www.skepticism.us/2015/05/new-malware-user-agent-value-jorgee/
# https://www.checkpoint.com/defense/advisories/public/2016/cpai-2016-0214.html
# https://blog.paranoidpenguin.net/2017/04/jorgee-goes-on-a-rampage/

import re
import util
import dshell
import datetime
import colorout
from httpdecoder import HTTPDecoder

class DshellDecoder(HTTPDecoder):

    def __init__(self):
        HTTPDecoder.__init__(self,
                                name='peht',
                                description='Penetration/Exploit/Hijacking Tool detector',
                                longdescription="""
The Penetration/Exploit/Hijacking Tool detector will identify the tool used to scan or exploit a server using the
User agent, URI or HTTP content.

General usage:
    decode -d peht <pcap> 

Detailed usage:
    decode -d peht --peht_showcontent <pcap> 

Output:

    Request Timestamp (UTC): 2017-07-16 02:41:47.238549 
    Penetration/Exploit/Hijacking Tool: Open Vulnerability Assessment System
    User-Agent: Mozilla/5.0 [en] (X11, U; OpenVAS 8.0.9)
    Request Method: GET
    URI: /scripts/session/login.php
    Source IP: 1.2.3.4 - Source port: 666 - MAC: 50:b4:02:39:24:56
    Host requested: example.com

    Response Timestamp (UTC): 2017-07-16 02:41:48.238549
    Response Reason: Not Found
    Response Status: 404
    Destination IP: 192.168.1.1 - Destination port: 80 - MAC: a4:42:ab:56:b6:23


    Detailed Output:

    Request Timestamp (UTC): 2017-07-16 02:41:47.238549 
    Penetration/Exploit/Hijacking Tool: Arbitrary Remote Code Execution/injection
    User-Agent: Wget(linux)
    Request Method: POST
    URI: /command.php
    Source IP: 1.2.3.4 - Source port: 666 - MAC: 50:b4:02:39:24:56
    Host requested: example.com

    cmd=%63%64%20%2F%76%61%72%2F%74%6D%70%20%26%26%20%65%63%68%6F%20%2D%6E%65%20%5C%5C%78%33%6B%65%72%20%3E%20%6B%65%72%2E%74%78%74%20%26%26%20%63%61%74%20%6B%65%72%2E%74%78%74

    Response Timestamp (UTC): 2017-07-16 02:41:48.238549
    Response Reason: Found
    Response Status: 302
    Destination IP: 192.168.1.1 - Destination port: 80 - MAC: a4:42:ab:56:b6:23

    <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html><head>
    <title>302 Found</title>
    </head><body>
    <h1>Found</h1>
    <p>The document has moved <a href="https://example.com/command.php">here</a>.</p>
    </body></html>

""",
            filter='tcp and (port 80 or port 81 or port 8080 or port 8000)',
            filterfn=lambda ((sip, sp), (dip, dp)): sp in (
                                 80, 81, 8000, 8080) or dp in (80, 81, 8000, 8080),
            author='mm',
            optiondict={
                'showcontent': {'action': 'store_true', 'default': False, 'help': 'Display the request and response body content.'}
            }
        )
        
        self.out = colorout.ColorOutput()
        self.direction = None
        self.request_ioc = None
        self.request_method = None
        self.request_user_agent = None
        self.request_host = None
        self.request_rangestr = None
        self.request_body = None
        self.request_referer = None
        self.response_content_type = None
        self.response_body = None
        self.response_contentencoding = None
        self.response_status = None
        self.response_contentlength = None
        self.response_reason = None

    def preModule(self):
        if 'setColorMode' in dir(self.out):
            self.out.setColorMode()

    def check_payload(self, payloadheader, payloaduri, requestbody):

        ET_identified = None

        r = re.compile(r'\bbash\b | \bcmd\b | \bsh\b | \bwget\b', flags=re.I | re.X)
        if r.findall(requestbody):
            ET_identified = 'Arbitrary Remote Code Execution/injection'

        if payloadheader.has_key('content-type'):
            struts_ioc = ['cmd', 'ProcessBuilder', 'struts']
            #Will return empty if all words from struts_ioc are in payloadheader['content-type']
            struts_check = list(filter(lambda x: x not in payloadheader['content-type'], struts_ioc))
            if not struts_check:
                ET_identified = 'Apache Struts Content-Type arbitrary command execution'

        if payloadheader.has_key('user-agent'):
            if 'Jorgee' in payloadheader['user-agent']:
                ET_identified = 'Jorgee Scanner'
            elif 'Nmap' in payloadheader['user-agent']:
                ET_identified = 'Nmap'
            elif 'masscan' in payloadheader['user-agent']:
                ET_identified = 'Mass IP port scanner'
            elif ('ZmEu' in payloadheader['user-agent'] and 'w00tw00t' in payloaduri):
                ET_identified = 'ZmEu Vulnerability Scanner'
            elif 'immoral' in payloadheader['user-agent']:
                ET_identified = 'immoral'
            elif 'chroot' in payloadheader['user-agent']:
                ET_identified = 'chroot'
            elif 'DataCha0s' in payloadheader['user-agent']:
                ET_identified = 'DataCha0s Web Scanner'
            elif 'OpenVAS' in payloadheader['user-agent']:
                ET_identified = 'Open Vulnerability Assessment System'
            elif ('bash' or 'sh' or 'cmd' or 'wget') in (payloadheader['user-agent']):
                ET_identified = 'Arbitrary Remote Code Execution/injection'

        if 'muieblackcat' in payloaduri:
                ET_identified = 'Muieblackcat Web Scanner/Robot'
        if '/HNAP1/' in payloaduri:
                ET_identified = 'Home Network Administration Protocol'

        return ET_identified
        


    def HTTPHandler(self, conn, request, response, requesttime, responsetime):

        if not request:
            return

        # Obtain the response content
        try:
            if 'gzip' in util.getHeader(response, 'content-encoding'):
                self.response_body = self.decompressGzipContent(response.body)
                if self.response_body == None:
                    self.response_body = '(gunzip failed)\n' + response.body
                else:
                    self.response_body = '(gzip encoded)\n' + self.response_body
            else:
                self.response_body = response.body
        except AttributeError as e:
            self.response_body = None

        # Obtain the request content
        try:
            if 'gzip' in util.getHeader(request, 'content-encoding'):
                self.request_body = self.decompressGzipContent(request.body)
                if self.request_body == None:
                    self.request_body = '(gunzip failed)\n' + request.body
                else:
                    self.request_body = '(gzip encoded)\n' + self.request_body
            else:
                self.request_body = request.body
        except AttributeError as e:
            self.request_body = None

        # Identify the Exploit/Hijacking Tool
        self.request_ioc = self.check_payload(request.headers, request.uri, self.request_body)
        
        if self.request_ioc:

            # REQUEST
            if request.method in ('GET', 'POST', 'HEAD'):
                self.direction = "sc"
                self.request_method = request.method
                self.request_user_agent = request.headers.get('user-agent')
                self.request_host = util.getHeader(request, 'host')
                self.request_rangestr = util.getHeader(request,'range')
                self.request_body = request.body
                self.request_referer = util.getHeader(request, 'referer')
                
                if request.headers.has_key('user-agent'):
                    self.request_user_agent = request.headers['user-agent']

                self.out.write("\nRequest Timestamp (UTC): {0} \nPenetration/Exploit/Hijacking Tool: {1}\nUser-Agent: {2}\nRequest Method: {3}\nURI: {4}\nSource IP: {5} - Source port: {6} - MAC: {7}\nHost requested: {8}\nReferer: {9}\n".format(datetime.datetime.utcfromtimestamp(
                                requesttime), self.request_ioc, self.request_user_agent, self.request_method, request.uri, conn.sip, conn.sport, conn.smac, self.request_host, self.request_referer), formatTag="H2", direction=self.direction)

                # Show request body content
                if self.showcontent:                
                    self.out.write("\n{0}\n".format(self.request_body), formatTag="H2", direction=self.direction)

                if not response:
                    self.direction = "cs"
                    self.out.write('\nNo response\n', formatTag="H2", direction=self.direction)

                # RESPONSE
                else:
                    self.direction = "cs"
                    self.response_content_type = util.getHeader(response, 'content-type')
                    self.response_contentencoding = util.getHeader(response, 'content-encoding')
                    self.response_status = response.status
                    self.response_reason = response.reason
                    
                    self.out.write("\nResponse Timestamp (UTC): {0} \nResponse Reason: {1}\nResponse Status: {2}\nDestination IP: {3} - Destination port: {4} - MAC: {5}\n".format(datetime.datetime.utcfromtimestamp(
                                responsetime), self.response_reason, self.response_status, conn.dip, conn.dport, conn.dmac), formatTag="H2", direction=self.direction)

                    # Show response body content
                    if self.showcontent:                
                        self.out.write("\n{0}\n".format(self.response_body), formatTag="H2", direction=self.direction)

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()