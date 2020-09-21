"""
Real-time transport protocol (RTP) capture plugin
"""

import datetime

import dshell.core
from dshell.output.alertout import AlertOutput

from pypacker.layer4 import udp
from pypacker.layer567 import rtp

class DshellPlugin(dshell.core.PacketPlugin):

    def __init__(self):
        super().__init__(
            name="RTP",
            author="mm/dev195",
            bpf="udp",
            description="Real-time transport protocol (RTP) capture plugin",
            longdescription="""
The real-time transport protocol (RTP) plugin will extract the Hosts, Payload Type, Synchronization source, 
Sequence Number, Padding, Marker and Client MAC address from every RTP packet found in the given pcap.

General usage:

    decode -d rtp <pcap> 
    decode -d rtp --no-vlan --layer2=sll.SLL <pcap> 

Examples:

    https://wiki.wireshark.org/SampleCaptures#SIP_and_RTP
    https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=rtp_example.raw.gz

    decode -d rtp rtp_example.pcap

Output:
    
    rtp 2016-09-21 23:44:40   50.197.16.141:1195  --     192.168.9.12:44352 ** 
        From: 50.197.16.141 (00:02:31:11:a5:97) to 192.168.9.12 (45:20:01:31:45:40) 
        Payload Type (7 bits): Dynamic
        Sequence Number (16 bits): 58635
        Timestamp (32 bits): 1331328074 
        Synchronization source (32 bits): 1948709792
        Arrival Time: 1474497880.6 --> 2016-09-21 22:44:40.604135
        Contributing source (32 bits): 1, Padding (1 bit): 1, Extension (1 bit): 1, Marker (1 bit): 0
     **
    rtp 2016-09-21 23:44:40         10.5.1.8:5086  --         10.5.1.7:5070  ** 
        From: 10.5.1.8 (00:02:81:11:a0:d7) to 10.5.1.7 (45:00:20:c8:a3:26) 
        Payload Type (7 bits): PCMU - Audio - 8000 Hz - 1 Channel
        Sequence Number (16 bits): 17664
        Timestamp (32 bits): 98240 
        Synchronization source (32 bits): 1671095215
        Arrival Time: 1474497880.6 --> 2016-09-21 22:44:40.604160
        Contributing source (32 bits): 0, Padding (1 bit): 0, Extension (1 bit): 0, Marker (1 bit): 0
     **
  """,
            output=AlertOutput(label=__name__)
        )

    def premodule(self):
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

    def packet_handler(self, pkt):
        # Scrape out the UDP layer of the packet
        udpp = pkt.pkt.upper_layer
        while not isinstance(udpp, udp.UDP):
            try:
                udpp = udpp.upper_layer
            except AttributeError:
                # There doesn't appear to be an UDP layer
                return

        # Parse the RTP protocol from above the UDP layer
        rtpp = rtp.RTP(udpp.body_bytes)

        if rtpp.version != 2:
            # RTP should always be version 2
            return

        pt = self.payload_type.get(rtpp.pt, "??")

        self.write("\n\tFrom: {0} ({1}) to {2} ({3}) \n\tPayload Type (7 bits): {4}\n\tSequence Number (16 bits): {5}\n\tTimestamp (32 bits): {6} \n\tSynchronization source (32 bits): {7}\n\tArrival Time: {8} --> {9}\n\tContributing source (32 bits): {10}, Padding (1 bit): {11}, Extension (1 bit): {12}, Marker (1 bit): {13}\n".format(
            pkt.sip, pkt.smac, pkt.dip, pkt.dmac, pt, rtpp.seq, rtpp.ts,
            rtpp.ssrc, pkt.ts, datetime.datetime.utcfromtimestamp(pkt.ts),
            rtpp.cc, rtpp.p, rtpp.x, rtpp.m), **pkt.info())

        return pkt
