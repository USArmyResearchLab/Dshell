#!/usr/bin/env python
'''
Created on Feb 6, 2012

@author: tparker
'''

import sys
import dpkt
import struct
import pcap
import socket
import time
from Crypto.Random import random
from Crypto.Hash import SHA
from output import PCAPWriter
from util import getopts


def hashaddr(addr, *extra):
    # hash key+address plus any extra data (ports if flow)
    global key, ip_range, ip_mask
    sha = SHA.new(key + addr)
    for e in extra:
        sha.update(str(extra))
    # take len(addr) octets of digest as address, to int, mask, or with range,
    # back to octets
    return inttoip((iptoint(sha.digest()[0:len(addr)]) & ip_mask) | ip_range)


def mangleMAC(addr):
    global zero_mac
    if zero_mac:
        return "\x00\x00\x00\x00\x00\x00"
    if addr in emap:
        return emap[addr]
    haddr = None
    if addr == "\x00\x00\x00\x00\x00\x00":
        haddr = addr  # return null MAC
    if ord(addr[0]) & 0x01:
        haddr = addr  # mac&0x800000000000 == broadcast addr, do not touch
    if not haddr:
        haddr = hashaddr(addr)
        # return hash bytes with first byte set to xxxxxx10 (LAA unicast)
        haddr = chr(ord(haddr[0]) & 0xfc | 0x2) + haddr[1:6]
    emap[addr] = haddr
    return haddr


def mangleIP(addr, *ports):  # addr,extra=our_port,other_port
    global exclude, exclude_port, anon_all, by_flow
    haddr = None
    intip = iptoint(addr)
    if len(addr) == 4 and intip >= 0xE0000000:
        haddr = addr  # pass multicast 224.x.x.x and higher
    ip = iptoa(addr)
    # pass 127.x.x.x, IANA reserved, and autoconfig ranges
    if not anon_all and (ip.startswith('127.')
                         or ip.startswith('10.')
                         or ip.startswith('172.16.')
                         or ip.startswith('192.168.')
                         or ip.startswith('169.254.')):
                    haddr = addr
    # pass ips matching exclude
    for x in exclude:
        if ip.startswith(x):
            haddr = addr
    if ports and ports[0] in exclude_port:
        haddr = addr  # if our port is exclude
    if not haddr:
        if by_flow:
            # use ports if by flow, else just use ip
            haddr = hashaddr(addr, *ports)
        else:
            haddr = hashaddr(addr)
    return haddr


def mangleIPs(src, dst, sport, dport):
    if by_flow:  # if by flow, hash addresses with s/d ports
        if (src, sport, dst, dport) in ipmap:
            src, dst = ipmap[(src, sport, dst, dport)]
        elif (dst, dport, src, sport) in ipmap:
            # make sure reverse flow maps same
            dst, src = ipmap[(dst, dport, src, sport)]
        else:
            src, dst = ipmap.setdefault(
                (src, sport, dst, dport), (mangleIP(src, sport, dport), mangleIP(dst, dport, sport)))
    else:
        if src in ipmap:
            src = ipmap[src]
        else:
            src = ipmap.setdefault(src, mangleIP(src, sport))
        if dst in ipmap:
            dst = ipmap[dst]
        else:
            dst = ipmap.setdefault(dst, mangleIP(dst, dport))
    return src, dst


def mactoa(addr):
    return ':'.join(['%02x' % b for b in struct.unpack('6B', addr)])


def iptoa(addr):
    if len(addr) is 16:
        return socket.inet_ntop(socket.AF_INET6, addr)
    else:
        return socket.inet_ntop(socket.AF_INET, addr)


def iptoint(addr):
    if len(addr) is 16:  # ipv6 to long
        ip = struct.unpack('!IIII', addr)
        return ip[0] << 96 | ip[1] << 64 | ip[2] << 32 | ip[3]
    else:
        return struct.unpack('!I', addr)[0]  # ip to int


def inttoip(l):
    if l > 0xffffffff:  # ipv6
        return struct.pack('!IIII', l >> 96, l >> 64 & 0xffffffff, l >> 32 & 0xffffffff, l & 0xffffffff)
    else:
        return struct.pack('!I', l)


def pcap_handler(ts, pktdata):
    global init_ts, start_ts, replace_ts, by_flow, anon_mac, zero_mac
    if not init_ts:
        init_ts = ts
    if replace_ts:
        ts = start_ts + (ts - init_ts)  # replace timestamps
    try:
        pkt = dpkt.ethernet.Ethernet(pktdata)
        if anon_mac or zero_mac:
            pkt.src = mangleMAC(pkt.src)
            pkt.dst = mangleMAC(pkt.dst)
        if pkt.type == dpkt.ethernet.ETH_TYPE_IP:
            try:
                # TCP or UDP?
                sport, dport = pkt.data.data.sport, pkt.data.data.dport
            except:
                sport = dport = None  # nope
            pkt.data.src, pkt.data.dst = mangleIPs(
                pkt.data.src, pkt.data.dst, sport, dport)
        pktdata = str(pkt)
    except Exception, e:
        print e
    out.write(len(pktdata), pktdata, ts)

if __name__ == '__main__':

    global key, init_ts, start_ts, replace_ts, by_flow, anon_mac, zero_mac, exclude, exclude_port, anon_all, ip_range, ip_mask
    opts, args = getopts(sys.argv[1:], 'i:aezftx:p:rk:', [
                         'ip=', 'all', 'ether', 'zero', 'flow', 'ts', 'exclude=', 'random', 'key=', 'port='], ['-x', '--exclude', '-p', '--port'])

    if '-r' in opts or '--random' in opts:
        key = random.long_to_bytes(random.getrandbits(64), 8)
    else:
        key = ''
    key = opts.get('-k', opts.get('--key', key))

    ip_range = opts.get('-i', opts.get('--ip', '0.0.0.0'))
    ip_mask = 0  # bitmask for hashed address
    ipr = ''
    for o in map(int, ip_range.split('.')):
        ipr += chr(o)
        ip_mask <<= 8  # shift by 8 bits
        if not o:
            ip_mask |= 0xff  # set octet mask to 0xff if ip_range octet is zero
    ip_range = iptoint(ipr)  # convert to int value for hash&mask|ip_range

    replace_ts = '-t' in opts or '--ts' in opts
    by_flow = '-f' in opts or '--flow' in opts
    anon_mac = '-e' in opts or '--ether' in opts
    zero_mac = '-z' in opts or '--zero' in opts
    anon_all = '-a' in opts or '--all' in opts

    start_ts = time.time()
    init_ts = None

    exclude = opts.get('-x', [])
    exclude.extend(opts.get('--exclude', []))

    exclude_port = map(int, opts.get('-p', []))
    exclude_port.extend(map(int, opts.get('--port', [])))

    emap = {}
    ipmap = {}

    if len(args) < 2:
        print "usage: pcapanon.py [options] <in-pcap [in-pcap]...> <out-pcap> > mapping.csv\nOptions:\n\t[-i/--ip range]\n\t[-r/--random | -k/--key 'salt' ]\n\t[-a/--all] [-t/--ts] [-f/--flow]\n\t[-e/--ether | -z/--zero]\n\t[-x/--exclude pattern...]\n\t[-p/--port list...]"
        print "Will anonymize all non-reserved IPs to be in range specified by -i/--ip option,"
        print "\tnonzero range octets are copied to anonymized address,\n\t(default range is 0.0.0.0 for fully random IPs)"
        print "CSV output maps original to anonymized addresses"
        print "By default anonymization will use a straight SHA1 hash of the address"
        print "\t***this is crackable as mapping is always the same***".upper()
        print "Use -r/--random to generate a random salt (cannot easily reverse without knowing map)"
        print "\tor use -k/--key 'salt' (will generate same mapping given same salt),"
        print "-f/--flows will anonymize by flow (per source:port<->dest:port tuples)"
        print "-a/--all will also anonymize reserved IPs"
        print "-x/--exclude will leave IPs starting with pattern unchanged"
        print "-p/--port port will leave IP unchanged if port is in list"
        print "-t/--ts will replace timestamp of first packet with time pcapanon was run,\n\tsubsequent packets will preserve delta from initial ts"
        print "-e/--ether will also anonymize non-broadcast MAC addresses"
        print "-z/--zero will zero all MAC addresses"
        sys.exit(0)

    out = PCAPWriter(args[-1])
    print '#file, packets'
    for f in args[0:-1]:
        p = 0
        cap = pcap.pcap(f)
        while cap.dispatch(1, pcap_handler):
            p += 1  # process whole file
        del cap
        print '%s,%s' % (f, p)
    out.close()

    print "#type,is-anonymized, original, anonymized"
    for ia, oa in sorted(emap.items()):
        print 'ether,%d, %s, %s' % (int(not ia == oa), mactoa(ia), mactoa(oa))
    for ia, oa in sorted(ipmap.items()):
        if by_flow:
            sip, sp, dip, dp = ia
            osip, odip = oa
            print "flow,%d, %s:%s,%s:%s, %s:%s,%s:%s" % (int(sip != osip or dip != odip), iptoa(sip), sp, iptoa(dip), dp, iptoa(osip), sp, iptoa(odip), dp)
        else:
            print 'ip,%d, %s, %s' % (int(ia != oa), iptoa(ia), iptoa(oa))
