#
# Author: MM - https://github.com/1modm
#
# RTP provides end-to-end network transport functions suitable for applications transmitting real-time data,
# such as audio, video or simulation data, over multicast or unicast network services.
#
# RFC: https://www.ietf.org/rfc/rfc3550.txt
#
# RTP Payload:
# https://tools.ietf.org/html/rfc2198
# https://tools.ietf.org/html/rfc4855
# https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml
#
# VoIP - Per Call Bandwidth:
# http://www.cisco.com/c/en/us/support/docs/voice/voice-quality/7934-bwidth-consume.html


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
                                name='rtp',
                                description='real-time transport protocol (RTP) capture decoder',
                                longdescription="""
The real-time transport protocol (RTP) decoder will extract the Hosts, Payload Type, Synchronization source, 
Sequence Number, Padding, Marker and Client MAC address from every RTP packet found in the given pcap.

General usage:

    decode -d rtp <pcap> 

Examples:

    https://wiki.wireshark.org/SampleCaptures#SIP_and_RTP
    https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=rtp_example.raw.gz

    decode -d rtp rtp_example.pcap

    Output:
    
    rtp 2002-07-26 07:19:10        10.1.6.18:2006  --       10.1.3.143:5000  ** 
        From: 10.1.6.18 (00:08:21:91:64:60) to 10.1.3.143 (00:04:76:22:20:17) 
        Payload Type (7 bits): PCMA - Audio - 8000 Hz - 1 Channel
        Sequence Number (16 bits): 9825
        Timestamp (32 bits): 54240 
        Synchronization source (32 bits): 4090175489
        Arrival Time: 1027664350.17
        Contributing source (32 bits): 0, Padding (1 bit): 0, Extension (1 bit): 0, Marker (1 bit): 0
    **
    rtp 2002-07-26 07:19:10       10.1.3.143:5000  --        10.1.6.18:2006  ** 
        From: 10.1.3.143 (00:04:76:22:20:17) to 10.1.6.18 (00:d0:50:10:01:66) 
        Payload Type (7 bits): PCMA - Audio - 8000 Hz - 1 Channel
        Sequence Number (16 bits): 59364
        Timestamp (32 bits): 55680 
        Synchronization source (32 bits): 3739283087
        Arrival Time: 1027664350.2
        Contributing source (32 bits): 0, Padding (1 bit): 0, Extension (1 bit): 0, Marker (1 bit): 0
    **

  """,
                                filter='',
                                author='mm', asdatetime=True,
                                )

    def preModule(self):
        self.payload_type = {0: "PCMU - Audio - 8000 Hz - 1 Channel", 1: "Reserved", 2: "Reserved", 3: "GSM - Audio - 8000 Hz - 1 Channel",
                             4: "G723 - Audio - 8000 Hz - 1 Channel", 5: "DVI4 - Audio - 8000 Hz - 1 Channel", 6: "DVI4 - Audio - 16000 Hz - 1 Channel",
                             7: "LPC - Audio - 8000 Hz - 1 Channel", 8: "PCMA - Audio - 8000 Hz - 1 Channel", 9: "G722 - Audio - 8000 Hz - 1 Channel",
                             10: "L16 - Audio - 44100 Hz - 2 Channel", 11: "L16 - Audio - 44100 Hz - 1 Channel", 12: "QCELP - Audio - 8000 Hz - 1 Channel",
                             13: "CN - Audio - 8000 Hz - 1 Channel", 14: "MPA - Audio - 90000 Hz", 15: "G728 - Audio - 8000 Hz - 1 Channel", 16: "DVI4 - Audio - 11025 Hz - 1 Channel",
                             17: "DVI4 - Audio - 22050 Hz - 1 Channel", 18: "G729 - Audio - 8000 Hz - 1 Channel", 19: "Reserved - Audio", 20: "Unassigned - Audio",
                             21: "Unassigned - Audio", 22: "Unassigned - Audio", 23: "Unassigned - Audio", 24: "Unassigned - Video", 25: "CelB - Video - 90000 Hz",
                             26: "JPEG - Video - 90000 Hz", 27: "Unassigned - Video", 28: "nv - Video - 90000 Hz", 29: "Unassigned - Video", 30: "Unassigned - Video",
                             31: "H261 - Video - 90000 Hz", 32: "MPV - Video - 90000 Hz", 33: "MP2T - Audio/Video - 90000 Hz", 34: "H263 - Video - 90000 Hz"}

        for i in range(35,72):
            self.payload_type[i] = "Unassigned"
        for i in range(72,77):
            self.payload_type[i] = "Reserved for RTCP conflict avoidance"
        for i in range(77,96):
            self.payload_type[i] = "Unassigned"
        for i in range(96,128):
            self.payload_type[i] = "Dynamic"


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

        # Process packets with Layer 5 data and RTP type
        if (packetype == "VoIP"):

            src = socket.inet_ntoa(layer3.src)
            dst = socket.inet_ntoa(layer3.dst)
            dictinfo = {'sip': src, 'dip': dst, 'sport': layer4.sport, 'dport': layer4.dport}

            if len(layer4.data) > 0:
                try:
                    layer5 = dpkt.rtp.RTP(layer4.data)
                except dpkt.UnpackError, e:
                    pass
                else:
                    pt = self.payload_type.get(layer5.pt)                 
                    if src and dst:
                        self.alert('\n\tFrom: {0} ({1}) to {2} ({3}) \n\tPayload Type (7 bits): {4}\n\tSequence Number (16 bits): {5}\n\tTimestamp (32 bits): {6} \n\tSynchronization source (32 bits): {7}\n\tArrival Time: {8}\n\tContributing source (32 bits): {9}, Padding (1 bit): {10}, Extension (1 bit): {11}, Marker (1 bit): {12}\n'.format(
                            src, kw['smac'], dst, kw['dmac'], pt, layer5.seq, layer5.ts,layer5.ssrc, ts, layer5.cc, layer5.p, layer5.x, layer5.m), ts=ts, **dictinfo)
                    
if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()