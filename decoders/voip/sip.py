#
# Author: MM - https://github.com/1modm
#
# The Session Initiation Protocol (SIP) is the IETF protocol for VOIP and other text and multimedia sessions
# and is a communications protocol for signaling and controlling. 
# SIP is independent from the underlying transport protocol. It runs on the Transmission Control Protocol (TCP), 
# the User Datagram Protocol (UDP) or the Stream Control Transmission Protocol (SCTP)
#
# Rate and codec calculation thanks to https://git.ucd.ie/volte-and-of/voip-pcapy
#
# RFC: https://www.ietf.org/rfc/rfc3261.txt
#
# SIP is a text-based protocol with syntax similar to that of HTTP. 
# There are two different types of SIP messages: requests and responses.
# - Requests initiate a SIP transaction between two SIP entities for establishing, controlling, and terminating sessions. 
# - Responses are send by the user agent server indicating the result of a received request.
#
# - SIP session setup example:
#
#       Alice's  . . . . . . . . . . . . . . . . . . . .  Bob's
#      softphone                                        SIP Phone
#         |                |                |                |
#         |    INVITE F1   |                |                |
#         |--------------->|    INVITE F2   |                |
#         |  100 Trying F3 |--------------->|    INVITE F4   |
#         |<---------------|  100 Trying F5 |--------------->|
#         |                |<-------------- | 180 Ringing F6 |
#         |                | 180 Ringing F7 |<---------------|
#         | 180 Ringing F8 |<---------------|     200 OK F9  |
#         |<---------------|    200 OK F10  |<---------------|
#         |    200 OK F11  |<---------------|                |
#         |<---------------|                |                |
#         |                       ACK F12                    |
#         |------------------------------------------------->|
#         |                   Media Session                  |
#         |<================================================>|
#         |                       BYE F13                    |
#         |<-------------------------------------------------|
#         |                     200 OK F14                   |
#         |------------------------------------------------->|
#         |                                                  |
#

import dshell
import dpkt
import datetime
import colorout

class DshellDecoder(dshell.UDPDecoder):

    def __init__(self):
        dshell.UDPDecoder.__init__(self,
                                name='sip',
                                description='Session Initiation Protocol (SIP) capture decoder',
                                longdescription="""
The Session Initiation Protocol (SIP) decoder will extract the Call ID, User agent, Codec, Method, 
SIP call, Host, and Client MAC address from every SIP request or response packet found in the given pcap.  

General usage:
    decode -d sip <pcap> 

Detailed usage:
    decode -d sip --sip_showpkt <pcap> 

Layer2 sll usage:
    decode -d sip --no-vlan --layer2=sll.SLL <pcap> 

SIP over TCP:
    decode -d sip --bpf 'tcp' <pcap> 

SIP is a text-based protocol with syntax similar to that of HTTP, so you can use followstream decoder:
    decode -d followstream --ebpf 'port 5060' --bpf 'udp' <pcap>

Examples:

    https://wiki.wireshark.org/SampleCaptures#SIP_and_RTP
    http://vignette3.wikia.nocookie.net/networker/images/f/fb/Sample_SIP_call_with_RTP_in_G711.pcap/revision/latest?cb=20140723121754

    decode -d sip metasploit-sip-invite-spoof.pcap
    decode -d sip Sample_SIP_call_with_RTP_in_G711.pcap

Output:

    <-- SIP Request --> 
    Timestamp: 2016-09-21 22:44:28.220185 UTC - Protocol: UDP - Size: 435 bytes
    Sequence and Method: 1 ACK
    From: 10.5.1.8:5060 (00:20:80:a1:13:db) to 10.5.1.7:5060 (15:2a:01:b4:0f:47)
    Via: SIP/2.0/UDP 10.5.1.8:5060;branch=z9hG4bK940bdac4-8a13-1410-9e58-08002772a6e9;rport
    SIP call: "M" <sip:M@10.5.1.8>;tag=0ba2d5c4-8a13-1910-9d56-08002772a6e9  -->  "miguel" <sip:demo-alice@10.5.1.7>;tag=84538c9d-ba7e-e611-937f-68a3c4f0d6ce
    Call ID: 0ba2d5c4-8a13-1910-9d57-08002772a6e9@M-PC

    --> SIP Response <-- 
    Timestamp: 2016-09-21 22:44:27.849761 UTC - Protocol: UDP - Size: 919 bytes
    Sequence and Method: 1 INVITE
    From: 10.5.1.7:5060 (02:0a:40:12:30:23) to 10.5.1.8:5060 (d5:02:03:94:31:1b)
    Via: SIP/2.0/UDP 10.5.1.8:5060;branch=z9hG4bK26a8d5c4-8a13-1910-9d58-08002772a6e9;rport=5060;received=10.5.1.8
    SIP call: "M" <sip:M@10.5.1.8>;tag=0ba2d5c4-8a13-1910-9d56-08002772a6e9  -->  "miguel" <sip:demo-alice@10.5.1.7>;tag=84538c9d-ba7e-e611-937f-68a3c4f0d6ce
    Call ID: 0ba2d5c4-8a13-1910-9d57-08002772a6e9@M-PC
    Codec selected: PCMU 
    Rate selected: 8000 

Detailed Output:

    --> SIP Response <-- 
    Timestamp: 2016-09-21 22:44:25.360974 UTC - Protocol: UDP - Size: 349 bytes
    From: 10.5.1.7:5060 (15:2a:01:b4:0f:47) to 10.5.1.8:5060 (00:20:80:a1:13:db) 
    SIP/2.0 100 Trying
    content-length: 0
    via: SIP/2.0/UDP 10.5.1.8:5060;branch=z9hG4bK26a8d5c4-8a13-1910-9d58-08002772a6e9;rport=5060;received=10.5.1.8
    from: "M" <sip:M@10.5.1.8>;tag=0ba2d5c4-8a13-1910-9d56-08002772a6e9
    to: <sip:demo-alice@10.5.1.7>
    cseq: 1 INVITE
    call-id: 0ba2d5c4-8a13-1910-9d57-08002772a6e9@M-PC

    --> SIP Response <-- 
    Timestamp: 2016-09-21 22:44:25.387780 UTC - Protocol: UDP - Size: 585 bytes
    From: 10.5.1.7:5060 (15:2a:01:b4:0f:47) to 10.5.1.8:5060 (00:20:80:a1:13:db)
    SIP/2.0 180 Ringing
    content-length: 0
    via: SIP/2.0/UDP 10.5.1.8:5060;branch=z9hG4bK26a8d5c4-8a13-1910-9d58-08002772a6e9;rport=5060;received=10.5.1.8
    from: "M" <sip:M@10.5.1.8>;tag=0ba2d5c4-8a13-1910-9d56-08002772a6e9
    require: 100rel
    rseq: 694867676
    user-agent: Ekiga/4.0.1
    to: "miguel" <sip:demo-alice@10.5.1.7>;tag=84538c9d-ba7e-e611-937f-68a3c4f0d6ce
    contact: "miguel" <sip:miguel@10.5.1.7>
    cseq: 1 INVITE
    allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING,PRACK
    call-id: 0ba2d5c4-8a13-1910-9d57-08002772a6e9@M-PC
""",
                                filter='udp',
                                author='mm',
                                optiondict={
                                    'showpkt': {'action': 'store_true', 'default': False, 'help': 'Display the full SIP response or request body.'}
                                }
        )
        
        self.out = colorout.ColorOutput()
        self.rate = None
        self.codec = None
        self.direction = None
        self.output = None

    def preModule(self):
        if 'setColorMode' in dir(self.out):
            self.out.setColorMode()

    def packetHandler(self, udp, data):
        # Initialize
        self.output = False
        self.rate = str()
        self.codec = str()
        self.direction = str()

        # Check if exists SIP Request
        try:
            if dpkt.sip.Request(data):
                siptxt = "<-- SIP Request -->"
                sippkt = dpkt.sip.Request(data)
                self.direction = "sc"
                self.output = True
        except dpkt.UnpackError, e:
            pass

        # Check if exists SIP Response
        try:
            if dpkt.sip.Response(data):
                siptxt = "--> SIP Response <--"
                sippkt = dpkt.sip.Response(data)
                self.direction = "cs"
                self.output = True
        except dpkt.UnpackError, e:
            pass

        # If a SIP request or SIP response exists, print the results
        if self.output:
            # Common output
            self.out.write("\n{0} \nTimestamp: {1} UTC - Protocol: {2} - Size: {3} bytes\n".format(siptxt, datetime.datetime.utcfromtimestamp(
                            udp.ts), udp.proto, udp.info()['bytes']), formatTag="H2", direction=self.direction)
            self.out.write("From: {0}:{1} ({2}) to {3}:{4} ({5}) \n".format(udp.sip, udp.sport, udp.smac,
                            udp.dip, udp.dport, udp.dmac), formatTag="H2", direction=self.direction)

            # Show full SIP packet detail
            if self.showpkt:                
                self.out.write("{0}\n".format(sippkt), formatTag="H2", direction=self.direction)

            # Show essential SIP Requests or Responses headers
            else:
                user_agent = sippkt.headers.get('user-agent')
                allow = sippkt.headers.get('allow')
                sip_from = sippkt.headers.get('from')
                sip_to = sippkt.headers.get('to')
                sip_callid  = sippkt.headers.get('call-id')
                via = sippkt.headers.get('via')
                cseq = sippkt.headers.get('cseq')

                if cseq:
                    self.out.write("Sequence and Method: {0}\n".format(cseq), formatTag="H2", direction=self.direction)

                if via:
                    self.out.write("Via: {0}\nSIP call: {1}  -->  {2}\nCall ID: {3}\n".format(via, 
                                    sip_from, sip_to, sip_callid), formatTag="H2", direction=self.direction)
                
                # codec and rate negotiated
                for x in range(sippkt.body.find(' ',sippkt.body.find('a='))+1,sippkt.body.find('/',sippkt.body.find('a='))):
                    self.codec += sippkt.body[x]
                for x in range(sippkt.body.find(' ',sippkt.body.find('a='))+6,sippkt.body.find('/',sippkt.body.find('a='))+5):
                    self.rate +=sippkt.body[x]

                if (self.codec and self.rate):
                    self.out.write("Codec selected: {0} \nRate selected: {1} \n".format(self.codec, self.rate), formatTag="H2", direction=self.direction)

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()