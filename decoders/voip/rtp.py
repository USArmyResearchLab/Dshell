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

    def mac_addr(self, address):
        """Convert a MAC address to a readable/printable string
           Args:
               address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
           Returns:
               str: Printable/readable MAC address
        """
        return ':'.join('%02x' % ord(b) for b in address)


    def payload_type(self, payload):
        """Return RTP payload type 
            Args:
                payload: Payload type
            Returns:
                str: Payload type translation
        """
        payload_type = ""
        if (payload == 0): return "PCMU - Audio - 8000 Hz - 1 Channel"
        elif (payload == 1): return "Reserved"
        elif (payload == 2): return "Reserved"
        elif (payload == 3): return "GSM - Audio - 8000 Hz - 1 Channel"
        elif (payload == 4): return "G723 - Audio - 8000 Hz - 1 Channel"
        elif (payload == 5): return "DVI4 - Audio - 8000 Hz - 1 Channel"
        elif (payload == 6): return "DVI4 - Audio - 16000 Hz - 1 Channel"
        elif (payload == 7): return "LPC - Audio - 8000 Hz - 1 Channel"
        elif (payload == 8): return "PCMA - Audio - 8000 Hz - 1 Channel"
        elif (payload == 9): return "G722 - Audio - 8000 Hz - 1 Channel"
        elif (payload == 10): return "L16 - Audio - 44100 Hz - 2 Channel"
        elif (payload == 11): return "L16 - Audio - 44100 Hz - 1 Channel"
        elif (payload == 12): return "QCELP - Audio - 8000 Hz - 1 Channel"
        elif (payload == 13): return "CN - Audio - 8000 Hz - 1 Channel"
        elif (payload == 14): return "MPA - Audio - 90000 Hz"
        elif (payload == 15): return "G728 - Audio - 8000 Hz - 1 Channel"
        elif (payload == 16): return "DVI4 - Audio - 11025 Hz - 1 Channel"
        elif (payload == 17): return "DVI4 - Audio - 22050 Hz - 1 Channel"       
        elif (payload == 18): return "G729 - Audio - 8000 Hz - 1 Channel"
        elif (payload == 19): return "Reserved - Audio"
        elif (payload == 20): return "Unassigned - Audio"
        elif (payload == 21): return "Unassigned - Audio"
        elif (payload == 22): return "Unassigned - Audio"
        elif (payload == 23): return "Unassigned - Audio"
        elif (payload == 24): return "Unassigned - Video"
        elif (payload == 25): return "CelB - Video - 90000 Hz"
        elif (payload == 26): return "JPEG - Video - 90000 Hz"
        elif (payload == 27): return "Unassigned - Video"   
        elif (payload == 28): return "nv - Video - 90000 Hz"
        elif (payload == 29): return "Unassigned - Video"
        elif (payload == 30): return "Unassigned - Video"
        elif (payload == 31): return "H261 - Video - 90000 Hz"
        elif (payload == 32): return "MPV - Video - 90000 Hz"
        elif (payload == 33): return "MP2T - Audio/Video - 90000 Hz"
        elif (payload == 34): return "H263 - Video - 90000 Hz"
        elif (35 <= payload <= 71): return "Unassigned"
        elif (72 <= payload <= 76): return "Reserved for RTCP conflict avoidance"
        elif (77 <= payload <= 95): return "Unassigned"
        elif (96 <= payload <= 127): return "Dynamic"
        else: return ""



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
        
        except Exception:
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
            try:
                if not (ethethernet.data.__class__.__name__ == "IP"):
                    # ARP, IPv6
                    packetype = "ARP or Non IP"
            except Exception:
                packetype = "ARP or Non IP" 
        
        # Discard IGMP and ICMP packets
        try:
            if isinstance(layer3.data, dpkt.igmp.IGMP):
                packetype = "IGMP"
        except Exception:
            pass

        try:
            if isinstance(layer3.data, dpkt.icmp.ICMP):
                packetype = "ICMP"
        except Exception:
            pass

        # Process packets with Layer 5 data and RTP type
        if (packetype == "VoIP"):
            try:
                src = socket.inet_ntoa(layer3.src)
                dst = socket.inet_ntoa(layer3.dst)
            except Exception:
                pass

            dictinfo = {'sip': src, 'dip': dst, 'sport': layer4.sport, 'dport': layer4.dport}

            if len(layer4.data) > 0:
                try:
                    layer5 = dpkt.rtp.RTP(layer4.data)
                except dpkt.UnpackError, e:
                    pass

                else:

                    pt = self.payload_type(layer5.pt)
                    
                    if src and dst:
                        self.alert('\n\tFrom: {0} ({1}) to {2} ({3}) \n\tPayload Type (7 bits): {4}\n\tSequence Number (16 bits): {5}\n\tTimestamp (32 bits): {6} \n\tSynchronization source (32 bits): {7}\n\tArrival Time: {8}\n\tContributing source (32 bits): {9}, Padding (1 bit): {10}, Extension (1 bit): {11}, Marker (1 bit): {12}\n'.format(
                            src, self.mac_addr(ethethernet.src), dst, self.mac_addr(ethethernet.dst), pt, layer5.seq, layer5.ts,layer5.ssrc, ts, layer5.cc, layer5.p,
                            layer5.x, layer5.m), ts=ts, **dictinfo)

                    
if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()