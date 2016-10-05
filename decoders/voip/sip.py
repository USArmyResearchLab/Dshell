#
# Author: MM - https://github.com/1modm
#
# The Session Initiation Protocol (SIP) is the IETF protocol for VOIP and other text and multimedia sessions
# and is a communications protocol for signaling and controlling
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
import output
import util
import dpkt
import datetime
from struct import unpack
import socket


class DshellDecoder(dshell.Decoder):

    def __init__(self):
        dshell.Decoder.__init__(self,
                                name='sip',
                                description='Session Initiation Protocol (SIP) capture decoder',
                                longdescription="""
The Session Initiation Protocol (SIP) decoder will extract the Call ID, User agent, Codec, Method, 
SIP call, Host, and Client MAC address from every SIP request or response packet found 
in the given pcap using by default the port 5060.  

General usage:

    decode -d sip <pcap> 
    or 
    decode -d sip --sip_port=5062 <pcap>

Examples:

    https://wiki.wireshark.org/SampleCaptures#SIP_and_RTP
    http://vignette3.wikia.nocookie.net/networker/images/f/fb/Sample_SIP_call_with_RTP_in_G711.pcap/revision/latest?cb=20140723121754

    decode -d sip metasploit-sip-invite-spoof.pcap
    decode -d sip Sample_SIP_call_with_RTP_in_G711.pcap

    Output:

    sip 2016-09-21 23:44:20         10.5.1.7:5060  --       10.1.30.60:5060  ** 
        --> SIP Request <--
        From: 10.5.1.7 (81:89:23:d6:c2:a1) to 10.1.30.60 (a1:03:fc:f2:01:bc) 
        Sequence and Method: 414 PUBLISH
        Via: SIP/2.0/UDP 10.5.1.7:5060;branch=z9hG1bK8e35adab-ba7e-e611-937f-68a3c4f0d5ce;rport
        SIP call: <sip:demo-alice@10.1.30.60> --> <sip:demo-alice@10.1.30.60> 
        With: Ekiga/4.0.1
        Call ID: ee8ace41-ab7e-e511-917f-64a3a4f0d5ce@ProBook
     **
    sip 2016-09-21 23:44:27         10.5.1.7:5060  --         10.5.1.8:5060  ** 
        --> SIP Response <--
        From: 10.5.1.7 (00:00:00:00:00:00) to 10.5.1.8 (a1:03:fc:f2:02:bc) 
        Sequence and Method: 1 INVITE
        Via: SIP/2.0/UDP 10.5.1.8:5060;branch=z2hG4bK25a8d5a4-8a13-1920-9d58-04002772a5e9;rport=5060;received=10.5.1.8
        SIP call: "M" <sip:M@10.5.1.8>;tag=0ba2d5c4-8a13-1910-9d55-08002772a6e9 --> "miguel" <sip:demo-alice@10.5.1.7>;tag=84548c9d-ba7e-e611-937f-68a3c4f0d5ce 
        With: Ekiga/4.0.1
        Call ID: 0ba2d7c4-8a13-1940-9d57-08002372a6e9@M-PC
        Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING,PRACK
        Codec: PCMU
        Rate: 8000 Hz
     **
  """,
                                filter='',
                                author='mm', asdatetime=True,
                                optiondict={
                                    'port':{'type':'int',
                                            'default': 5060,
                                            'help':'SIP Port used (Default: 5060)'}
                                }
                                )

    def rawHandler(self, dlen, data, ts, **kw):
        """Packet handle function
            Args:
                dlen: length
                data: packet
                ts: timestamp
                kw: kwargs - keyword arguments
        """

        if self.verbose:
            self.log("%.06f %d\n%s" % (ts, dlen, util.hexPlusAscii(str(data))))

        packetype = "VoIP" # by default :)

        try:
            # If Ethernet is being replaced by Linux Cooked Capture
            # the traces are encapsulated similarly but we need to use dpkt.sll.SLL(data)
            # rather than dpkt.ethernet.Ethernet(data)
            eth = "SLL"
            ethsll = dpkt.sll.SLL(str(data))
            ethethernet = dpkt.ethernet.Ethernet(str(data))
            layer3 = ethsll.data
            layer4 = layer3.data
        except AttributeError:
            eth = "Ethernet"
            ethethernet = dpkt.ethernet.Ethernet(str(data))    
            # Check if string to discard
            if not isinstance(ethethernet.data, basestring):
                layer3 = ethethernet.data
                layer4 = layer3.data

        # Make sure the Ethernet data contains an IP packet        
        if (eth == "SLL"):
            if not (ethsll.data.__class__.__name__ == "IP"):
                # ARP, IPv6
                packetype = "ARP or Non IP"
        else:
            if not (ethethernet.data.__class__.__name__ == "IP"):
                # ARP, IPv6
                packetype = "ARP or Non IP"
        
        # Discard IGMP and ICMP packets
        try:
            if isinstance(layer3.data, dpkt.igmp.IGMP):
                packetype = "IGMP"
        except AttributeError:
            pass

        try:
            if isinstance(layer3.data, dpkt.icmp.ICMP):
                packetype = "ICMP"
        except AttributeError:
            pass

        # Process packets with Layer 5 data and port defined for SIP
        if (packetype == "VoIP"):
            src = socket.inet_ntoa(layer3.src)
            dst = socket.inet_ntoa(layer3.dst)
            sipport = self.port
            dictinfo = {'sip': src, 'dip': dst, 'sport': layer4.sport, 'dport': layer4.dport}

            # SIP REQUEST and SIP RESPONSE
            if (layer4.dport==sipport or layer4.sport==sipport) and len(layer4.data) > 0:
                sip_packet = False
                try:
                    layer5 = dpkt.sip.Request(layer4.data)
                    sip_type = "SIP Request"
                    sip_packet = True
                except dpkt.UnpackError, e:
                    try:
                        layer5 = dpkt.sip.Response(layer4.data)
                        sip_type = "SIP Response"
                        sip_packet = True
                    except dpkt.UnpackError, e:
                        pass

                finally:
                    if (sip_packet):
                        user_agent = layer5.headers.get('user-agent')
                        allow = layer5.headers.get('allow')
                        l5_from = layer5.headers.get('from')
                        l5_to = layer5.headers.get('to')
                        l5_callid  = layer5.headers.get('call-id')
                        via = layer5.headers.get('via')
                        cseq = layer5.headers.get('cseq')
                        rate = ""
                        codec = ""
                        for x in range(layer5.body.find(' ',layer5.body.find('a='))+1,layer5.body.find('/',layer5.body.find('a='))):
                            codec += layer5.body[x]
                        for x in range(layer5.body.find(' ',layer5.body.find('a='))+6,layer5.body.find('/',layer5.body.find('a='))+5):
                            rate+=layer5.body[x]
                        
                        if src and dst and layer5.headers:
                            if not allow:
                                self.alert('\n\t--> {0} <--\n\tFrom: {1} ({2}) to {3} ({4}) \n\tSequence and Method: {5}\n\tVia: {6}\n\tSIP call: {7} --> {8} \n\tWith: {9}\n\tCall ID: {10}\n'.format(sip_type, src,
                                    kw['smac'], dst, kw['dmac'], cseq, via, l5_from,
                                    l5_to, user_agent, l5_callid), ts=ts, **dictinfo)
                            else:
                                self.alert('\n\t--> {0} <--\n\tFrom: {1} ({2}) to {3} ({4}) \n\tSequence and Method: {5}\n\tVia: {6}\n\tSIP call: {7} --> {8} \n\tWith: {9}\n\tCall ID: {10}\n\tAllow: {11}\n\tCodec: {12}\n\tRate: {13} Hz\n'.format(sip_type, src,
                                    kw['smac'], dst, kw['dmac'], cseq, via, l5_from,
                                    l5_to, user_agent, l5_callid, allow, codec, rate), ts=ts, **dictinfo)

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()