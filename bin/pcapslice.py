#!/usr/bin/env python
'''
split pcap files by ip src/dst pair or tcp/udp stream

Originally created February 2013
Updated from pylibpcap to pypcap, November 2015

@author: amm
'''

import sys
import os
import pcap
import dpkt
import signal
import socket
import output
from optparse import OptionParser

IPprotocols = {
    0: 'IP', 1: 'ICMP', 2: 'IGMP', 3: 'GGP', 4: 'IP-ENCAP', 133: 'FC', 6: 'TCP', 8: 'EGP', 137: 'MPLS-IN-IP', 138: 'MANET', 139: 'HIP', 12: 'PUP', 17: 'UDP', 20: 'HMP', 22: 'XNS-IDP', 132: 'SCTP', 27: 'RDP', 29: 'ISO-TP4', 5: 'ST', 36: 'XTP', 37: 'DDP', 38: 'IDPR-CMTP', 41: 'IPV6', 43: 'IPV6-ROUTE', 44: 'IPV6-FRAG',
    45: 'IDRP', 46: 'RSVP', 47: 'GRE', 136: 'UDPLITE', 50: 'IPSEC-ESP', 51: 'IPSEC-AH', 9: 'IGP', 57: 'SKIP', 58: 'IPV6-ICMP', 59: 'IPV6-NONXT', 60: 'IPV6-OPTS', 73: 'RSPF', 81: 'VMTP', 88: 'EIGRP', 89: 'OSPFIGP', 93: 'AX.25', 94: 'IPIP', 97: 'ETHERIP', 98: 'ENCAP', 103: 'PIM', 108: 'IPCOMP', 112: 'VRRP', 115: 'L2TP', 124: 'ISIS'}
flowtimeout = 1800  # seconds
ctrl_c_Received = False

'''
main
'''


def main():
    global options, ctrl_c_Received

    flows = flowstore()

    parser = OptionParser(
        usage="usage: %prog [options] file", version="%prog: PCAP Slicer")
    parser.add_option('-f', '--bpf', dest='bpf', help='BPF input filter')
    parser.add_option('-o', '--outdir', dest='outdir', default='.',
                      help='directory to write output files (Default: current directory)')
    parser.add_option('--no-vlan', dest='novlan', action="store_true",
                      help='do not examine traffic which has VLAN headers present')
    parser.add_option('--debug', action='store_true', dest='debug')
    (options, args) = parser.parse_args(sys.argv[1:])

    if not args:
        parser.print_version()
        parser.print_help()
        sys.exit()

    filter = ''
    if options.bpf != None:
        filter = options.bpf
    if not options.novlan and not(filter.startswith('vlan')):
        if filter:
            filter = '( ' + filter + ' ) or ( vlan and ( ' + filter + ' ) )'
        else:
            filter = ''  # fix for null filter case

    pcount = 0
    for f in args:
        pcapreader = pcap.pcap(f)
        if options.bpf:
            pcapreader.setfilter(filter)
        while True:
            # Pick a packet
            try:
                ts, spkt = pcapreader.next()
            except:
                break  # EOF
            # Parse IP/Port/Proto Information
            try:
                pkt = dpkt.ethernet.Ethernet(spkt)
                # Only handle IP4/6
                if type(pkt.data) == dpkt.ip.IP:
                    proto = pkt.data.p
                elif type(pkt.data) == dpkt.ip6.IP6:
                    proto = pkt.data.nxt
                else:
                    continue
                # Populate addr tuple
                # (proto, sip, sport, dip, dport)
                if proto == dpkt.ip.IP_PROTO_TCP or proto == dpkt.ip.IP_PROTO_UDP:
                    addr = (
                        proto, pkt.data.src, pkt.data.data.sport, pkt.data.dst, pkt.data.data.dport)
                else:
                    addr = (proto, pkt.data.src, None, pkt.data.dst, None)
            except:
                continue  # Skip Packet if unable to parse
            pcount += 1
            #
            # Look for existing open flow or start new one
            #
            thisflow = flows.find(addr)
            if thisflow == None:
                thisflow = flow(addr)
                flows.add(thisflow)
                warn("New flow to file: %s" % str(thisflow))
            #
            # Write this packet to correct flow
            #
            thisflow.write(len(spkt), spkt, ts)
            #
            # Check for TCP reset or fin
            #
            try:
                if pkt.data.data.flags & (dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN):
                    thisflow.done()
            except:
                pass  # probably not a TCP packet
            #
            # Cleanup Routine
            #
            if pcount % 1000 == 0:
                flows.cleanup(ts)
            #
            # Clean exit
            #
            if ctrl_c_Received:
                sys.stderr.write("Exiting on interrupt signal.\n")
                sys.exit(0)
'''
flow class
  instantiated for each bi-directional flow of data
  maintains pcapwriter for each open session
'''


class flow:

    def __init__(self, addr):
        self.addr = addr
        self.outfilename = localfilename(addr)
        self.pcapwriter = output.PCAPWriter(self.outfilename)
        self.state = 1
        self.lastptime = 0

    def write(self, l, spkt, ts):
        self.pcapwriter.write(l, spkt, ts)
        self.lastptime = ts

    # Mark flow as done (RST/FIN received)
    # but don't close the pcap file yet
    def done(self):
        self.state = 0

    def __del__(self):
        warn("Closing file: %s" % self.outfilename)

    def __str__(self):
        return self.outfilename

    def __repr__(self):
        return self.outfilename

'''
flowstore class
'''


class flowstore:
    global flowtimeout

    def __init__(self):
        self.data = {}  # indexed by addr tuple (proto, sip, sport, dip, dport)

    def find(self, addr):
        # Fwd Search
        if addr in self.data:
            return self.data[addr]
        # Rev Search
        (proto, sip, sport, dip, dport) = addr
        if (proto, dip, dport, sip, sport) in self.data:
            return self.data[(proto, dip, dport, sip, sport)]
        return None

    def add(self, newflow):
        self.data[newflow.addr] = newflow

    def cleanup(self, currentPtime):
        for k in self.data.keys():
            if self.data[k].state > 0:
                continue
            # Check timeout
            if currentPtime - self.data[k].lastptime > flowtimeout:
                del self.data[k]


def warn(text):
    sys.stdout.write("WARN: " + str(text) + "\n")


def normalizedIP(packed):
    if len(packed) == 16:
        return socket.inet_ntop(socket.AF_INET6, packed)
    else:
        ip = socket.inet_ntoa(packed)
        if '.' in ip:
            parts = ip.split('.')
            return '.'.join(['%03d' % int(p) for p in parts])
        return ip


def localfilename(addr):
    global IPprotocols, options
    (proto, sip, sport, dip, dport) = addr
    # Convert Numeric Protocol to Text
    if proto in IPprotocols:
        proto = IPprotocols[proto]
    else:
        proto = '%05d' % int(proto)
    # Convert packed IPs to Text
    nameparts = [proto, normalizedIP(sip), normalizedIP(dip)]
    try:
        nameparts.append('%05d' % int(sport))
    except:
        pass
    try:
        nameparts.append('%05d' % int(dport))
    except:
        pass
    # Filename
    fname = '_'.join(nameparts)
    inc = 0
    while True:
        fullname = os.path.join(options.outdir, '%s_%03d.pcap' % (fname, inc))
        if not os.path.exists(fullname):
            return fullname
        inc += 1


'''
handle interupt events
'''


def ctrlchandler(signum, frame):
    global ctrl_c_Received
    ctrl_c_Received = True
    sys.stderr.write("Interrupt received.  Will exit at next clean break.\n")

if __name__ == '__main__':
    signal.signal(signal.SIGINT, ctrlchandler)
    # sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)  # reopen STDOUT
    # unbuffered
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
