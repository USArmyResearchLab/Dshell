"""
Dshell base classes
"""

__version__ = "3.0"

import dpkt
import struct
import socket
import traceback
import util
import os
import logging

# For IP lookups
try:
    import geoip2.database
except:
    pass


class Decoder(object):

    """
    Base class that all decoders will inherit

    The Dshell class initializes the decoder to work in the framework
    and provides common functions such as CC/ASN lookup

    Configuration attributes, settable by Dshell.__init__(attr=value,...) or in subclass __init__:
            name: name of this decoder.
            description: single-line description of this decoder
            longdescription: multi-line description of this decoder
            author: who to blame for this decoder

            filter: default BPF filter for capture.

            format: output format string for this decoder, overrides default for
                            Please read how text, DB, etc.. Output() classes parse a format string.

            optionsdict: optionParser compatible config, specific to decoder
                     dict of {      'optname':{'default':..., 'help':..., etc...
                                                                    <destination is auto-filled from optname>},
                                            'optname':...   }
                     'optname' is set by --deodername_optname=...  on command line
                     and under [decodername] section in config file


            cleanupinterval  - seconds with no activity before state is discarded (default 60)

            chainable - set True to indicate this decoder can be chained (can pass output to another decoder)
            subDecoder - decoder to pass output to, if not None.
                                    (create new Data objects and call subDecoder.XHandler from XHandler, etc..)


    """

    def __super__(self):
        '''convenience function to get bound instance of superclass'''
        return super(self.__class__, self)

    def __init__(self, **kwargs):
        self.name = 'unnamed'
        self.description = ''
        self.longdescription = ''
        self.filter = ''
        self.author = 'xx'
        self.decodedbytes = 0
        self.count = 0
        '''dict of options specific to this decoder in format
                'optname':{configdict} translates to --decodername_optname'''
        self.optiondict = {}

        # out holds the output plugin. If None, will inherit the global output
        self.out = None
        # format is the format string for this plugin, if None, uses global
        self.format = None

        # capture options
        self.l2decoder = dpkt.ethernet.Ethernet  # decoder to use if raw mode
        # strip extra layers before IP/IPv6? (such as PPPoE, IP-over-IP, etc..)
        self.striplayers = 0

        self._DEBUG = False

        # can we chain a decoder off the output of this one?
        self.chainable = False
        self.subDecoder = None  # decoder to pass output to for chaining

        # set flags to indicate if handlers are present
        if 'packetHandler' in dir(self):
            self.isPacketHandlerPresent = True
        else:
            self.isPacketHandlerPresent = False
        if 'connectionHandler' in dir(self):
            self.isConnectionHandlerPresent = True
        else:
            self.isConnectionHandlerPresent = False
        if 'blobHandler' in dir(self):
            self.isBlobHandlerPresent = True
        else:
            self.isBlobHandlerPresent = False

        # for connection tracking, if applicable
        self.connectionsDict = {}
        self.cleanupts = 0

        # instantiate and save references to lookup function
        geoip_dir = os.path.join(os.environ['DATAPATH'], "GeoIP")
        try:
            self.geoccdb = geoip2.database.Reader(
                os.path.join(geoip_dir, "GeoLite2-Country.mmdb")
            ).country
        except:
            self.geoccdb = None

        try:
            self.geoasndb = geoip2.database.Reader(
                os.path.join(geoip_dir, "GeoLite2-ASN.mmdb")
            ).asn
        except:
            self.geoasndb = None

        # import kw args into class members
        if kwargs:
            self.__dict__.update(kwargs)

    ### convenience functions for alert output and logging ###

    def alert(self, *args, **kw):
        '''sends alert to output handler
                typically self.alert will be called with the decoded data and the packet/connection info dict last, as follows:

                self.alert(alert_arg,alert_arg2...,alert_data=value,alert_data2=value2....,**conn/pkt.info())

                example: self.alert(decoded_data,conn.info(),blob.info()) [blob info overrides conn info]

                this will pass all information about the decoder, the connection, and the specific event up to the output module

                if a positional arg is a dict, it updates the kwargs
                if an arg is a list, it extends the arg list
                else it is appended to the arg list

                all arguments are optional, at the very least you want to pass the **pkt/conn.info() so all traffic info is available.

                output modules handle this data as follows:
                         - the name of the alerting decoder is available in the "decoder" field
                         - all non-keyword arguments will be concatenated into the "data" field
                         - keyword arguments, including all provided by .info() will be used to populate matching fields
                         - remaining keyword arguments that do not match fields will be represented by "key=value" strings
                            concatenated together into the "extra" field
        '''
        oargs = []
        for a in args:
            # merge dict args, overriding kws
            if type(a) == dict:
                kw.update(a)
            elif type(a) == list:
                oargs.extend(a)
            else:
                oargs.append(a)
        if 'decoder' not in kw:
            kw['decoder'] = self.name
        self.out.alert(*oargs, **kw)  # add decoder name

    def write(self, obj, **kw):
        '''write session data'''
        self.out.write(obj, **kw)

    def dump(self, *args, **kw):
        '''write packet data (probably to the PCAP writer if present)'''
        if len(args) == 3:
            kw['len'], kw['pkt'], kw['ts'] = args
        elif len(args) == 2:
            kw['pkt'], kw['ts'] = args
        elif len(args) == 1:
            kw['pkt'] = args[0]
        self.out.dump(**kw)

    def log(self, msg, level=logging.INFO):
        '''logs msg at specified level (default of INFO is for -v/--verbose output)'''
        self.out.log(
            msg, level=level)  # default level is INFO (verbose) can be overridden

    def debug(self, msg):
        '''logs msg at debug level'''
        self.log(msg, level=logging.DEBUG)

    def warn(self, msg):
        '''logs msg at warning level'''
        self.log(msg, level=logging.WARN)
        pass

    def error(self, msg):
        '''logs msg at error level'''
        self.log(msg, level=logging.ERROR)

    def __repr__(self):
        return '%s %s %s' % (self.name, self.filter,
                             ' '.join([('%s=%s' % (x, str(self.__dict__.get(x)))) for x in self.optiondict.keys()]))

    def preModule(self):
        '''preModule is called before capture starts
                default preModule, dumps object data to debug'''
        if self.subDecoder:
            self.subDecoder.preModule()
        self.debug(self.name + ' ' + str(self.__dict__))

    def postModule(self):
        '''postModule is called after capture stops
                default postModule, prints basic decoding stats'''
        self.cleanConnectionStore()
        self.log("%s: %d packets (%d bytes) decoded" %
                 (self.name, self.count, self.decodedbytes))
        if self.subDecoder:
            self.subDecoder.postModule()

    def preFile(self):
        if self.subDecoder:
            self.subDecoder.preFile()

    def postFile(self):
        if self.subDecoder:
            self.subDecoder.postFile()

    def parseOptions(self, options={}):
        '''option keys:values will set class members (self.key=value)
                if key is in optiondict'''
        for optname in self.optiondict.iterkeys():
            if optname in options:
                self.__dict__[optname] = options[optname]

    def parseArgs(self, args, options={}):
        '''called to parse command-line arguments and cli/config file options
                if options dict contains 'all' or the decoder name as a key
                class members will be updated from value'''
        # get positional args after the --
        self.args = args
        # update from all decoders section of config file
        if 'all' in options:
            self.parseOptions(options['all'])
        # update from named section of config file
        if self.name in options:
            self.parseOptions(options[self.name])

    def getGeoIP(self, ip, db=None, notfound='--'):
        """
        Get country code associated with an IP.
        Requires GeoIP library (geoip2) and data files.
        """
        if not db:
            db = self.geoccdb
        try:
            # Get country code based on order of importance
            # 1st: Country that owns an IP address registered in another
            #      location (e.g. military bases in foreign countries)
            # 2nd: Country in which the IP address is registered
            # 3rd: Physical country where IP address is located
            # https://dev.maxmind.com/geoip/geoip2/whats-new-in-geoip2/#Country_Registered_Country_and_Represented_Country
            location = db(ip)
            country = (
                location.represented_country.iso_code or
                location.registered_country.iso_code or
                location.country.iso_code or
                notfound
            )
            return country
        except Exception:
            # Many expected exceptions can occur here. Ignore them all and
            # return default value.
            return notfound

    def getASN(self, ip, db=None, notfound='--'):
        """
        Get ASN associated with an IP.
        Requires GeoIP library (geoip2) and data files.
        """
        if not db:
            db = self.geoasndb
        try:
            template = "AS{0.autonomous_system_number} {0.autonomous_system_organization}"
            asn = template.format( db(ip) )
            return asn
        except Exception:
            # Many expected exceptions can occur here. Ignore them all and
            # return default value.
            return notfound

    def close(self, conn, ts=None):
        '''for connection based decoders
                close and discard the connection object'''
        # just return if we have already been called on this connection
        # prevents infinite loop of a handler calling close() when we call it
        if conn.state == 'closed':
            return

        # set state to closed
        conn.state = 'closed'
        if ts:
            conn.endtime = ts
        # we have already stopped this so don't call the handlers if we have
        # already stopped
        if not conn.stop:
            # flush out the last blob to the blob handler
            if self.isBlobHandlerPresent and conn.blobs:
                self.blobHandler(conn, conn.blobs[-1])
            # process connection handler
            if self.isConnectionHandlerPresent:
                self.connectionHandler(conn)
        # connection close handler
        # will be called regardless of conn.stop right before conn object is
        # destroyed
        if 'connectionCloseHandler' in dir(self):
            self.connectionCloseHandler(conn)
        # discard but check first in case a handler deleted it
        if conn.addr in self.connectionsDict:
            del self.connectionsDict[conn.addr]

    def stop(self, conn):
        '''stop following connection
                handlers will not be called, except for connectionCloseHandler'''
        conn.stop = True

    def cleanup(self, ts):
        '''if cleanup interval expired, close connections not updated in last interval'''
        ts = util.mktime(ts)
        # if cleanup interval has passed
        if self.cleanupts < (ts - self.cleanupinterval):
            for conn in self.connectionsDict.values():
                if util.mktime(conn.endtime) <= self.cleanupts:
                    self.close(conn)
            self.cleanupts = ts

    def cleanConnectionStore(self):
        '''cleans connection store of all information, flushing out data'''
        for conn in self.connectionsDict.values():
            self.close(conn)

    def _exc(self, e):
        '''exception handler'''
        self.warn(str(e))
        if self._DEBUG:
            traceback.print_exc()

    def find(self, addr, state=None):
        if addr in self.connectionsDict:
            conn = self.connectionsDict[addr]
        elif (addr[1], addr[0]) in self.connectionsDict:
            conn = self.connectionsDict[(addr[1], addr[0])]
        else:
            return None
        if not state or conn.state == state:
            return conn
        else:
            return None

    def track(self, addr, data=None, ts=None, offset=None, **kwargs):
        '''connection tracking for TCP and UDP
                finds or creates connection based on addr
                updates connection with data if provided (using offset to reorder)
                tracks timestamps if ts provided
                extra args get passed to new connection objects
        '''
        conn = self.find(addr)
        # look for forward and reverse address tuples
        if not conn:  # create new connection
            # if swapping and source has low port, swap source/dest so dest has
            # low port
            if self.swaplowport and addr[0][1] < addr[1][1]:
                addr = (addr[1], addr[0])
            # create connection and call init handler
            conn = Connection(self, addr=addr, ts=ts, **kwargs)
            if 'connectionInitHandler' in dir(self):
                self.connectionInitHandler(conn)
            # save in state dict
            self.connectionsDict[addr] = conn

        # has tracking been stopped?
        if conn.stop:
            return False

        if data:
            # forward or reverse direction?
            if addr == conn.addr:
                direction = 'cs'
            else:
                direction = 'sc'

            original_direction = conn.direction

            # update the connection to update current blob or start a new one
            # and return the last one
            # we will get a blob back if there is data to flush
            blob = conn.update(ts, direction, data, offset=offset)
            if blob and self.isBlobHandlerPresent:
                self.blobHandler(conn, blob)

            # check direction and blob count.
            # If we have switched direction but already have max blobs
            # close connection and replace it with a new one
            if self.maxblobs and (direction != original_direction) and (len(conn.blobs) >= self.maxblobs):
                self.close(conn)  # close and call handlers
                # recurse to create a new connection for the next
                # request/response
                return self.track(addr, ts=ts, **kwargs)

            # we can discard all but the last blob
            if not self.isConnectionHandlerPresent:
                while len(conn.blobs) > 1:
                    conn.blobs.pop(0)

        self.cleanup(ts)  # do stale state cleanup
        return conn  # return a reference to the connection

    '''directly extend Decoder and set raw=True to capture raw PCAP data'''

    # we get the raw output from pcapy as header, data
    def decode(self, *args, **kw):
        if len(args) is 3:
            pktlen, pktdata, ts = args  # orig_len,packet,ts format (pylibpcap)
        else:  # ts,pktdata (pypcap)
            ts, pktdata = args
            pktlen = len(pktdata)
        try:
            if pktlen != len(pktdata):
                raise Exception('packet truncated', pktlen, pktdata)
            # decode with the L2 decoder (probably Ether)
            pkt = self.l2decoder(pktdata)
            # attempt to collect MAC addresses
            if type(pkt) == dpkt.ethernet.Ethernet:
                try:
                    smac = "%02x:%02x:%02x:%02x:%02x:%02x" % (struct.unpack("BBBBBB", pkt.src))
                    dmac = "%02x:%02x:%02x:%02x:%02x:%02x" % (struct.unpack("BBBBBB", pkt.dst))
                except struct.error:  # couldn't get MAC address
                    smac, dmac = None, None
                kw.update(smac=smac, dmac=dmac)
            elif type(pkt) == dpkt.sll.SLL:
                try:
                    # Sometimes MAC address will show up as 00:00:00:00:00:00
                    # TODO decide if it should be set to None or kept as-is
                    smac = "%02x:%02x:%02x:%02x:%02x:%02x" % (struct.unpack("BBBBBB", pkt.hdr[:pkt.hlen]))
                    dmac = None
                except struct.error:
                    smac, dmac = None, None
                kw.update(smac=smac, dmac=dmac)
            # strip any intermediate layers (PPPoE, etc)
            for _ in xrange(int(self.striplayers)):
                pkt = pkt.data
            # will call self.rawHandler(len,pkt,ts)
            # (hdr,data) is the PCAP header and raw packet data
            if 'rawHandler' in dir(self):
                self.rawHandler(pktlen, pkt, ts, **kw)
            else:
                pass
        except Exception, e:
            self._exc(e)

# IP handler


class IPDecoder(Decoder):

    '''extend IP6Decoder to capture IPv4 and IPv6 data
            (but does basic IPv4 defragmentation)
            config:

                    l2decoder: dpkt class for layer-2 decoding (Ethernet)
                    striplayers: strip n layers above layer-2, removes PPP/PPPoE encap, IP-over-IP, etc.. (0)
                    defrag: defragment IPv4 (True)
                    v6only: if True, will ignore IPv4 data. (False)
                    decode6to4: if True, will decode IPv6-over-IP, if False will treat as IP (True)

                    filterfn: lambda function that accepts addr 2x2tuples and returns if packet should pass (addr:True)

            filterfn is required for IPv6 as port-based BPF filters don't work,
            so keep your BPF to 'tcp' or 'udp' and set something like
            self.filterfn = lambda ((sip,sp),(dip,dp)): (sp==53 or dp==53) '''

    IP_PROTO_MAP = {
        dpkt.ip.IP_PROTO_ICMP: 'ICMP',
        dpkt.ip.IP_PROTO_ICMP6: 'ICMP6',
        dpkt.ip.IP_PROTO_TCP: 'TCP',
        dpkt.ip.IP_PROTO_UDP: 'UDP',
        dpkt.ip.IP_PROTO_IP6: 'IP6',
        dpkt.ip.IP_PROTO_IP: 'IP'}

    def __init__(self, **kwargs):
        self.v6only = False
        self.decode6to4 = True
        self.defrag = True
        self.striplayers = 0
        self.l2decoder = dpkt.ethernet.Ethernet
        self.filterfn = lambda addr: True
        Decoder.__init__(self, **kwargs)
        self.frags = {}

    def ipdefrag(self, pkt):
        '''ip fragment reassembly'''
        # if pkt.off&dpkt.ip.IP_DF or pkt.off==0: return pkt #DF or !MF and
        # offset 0
        # if we need to create a store for this IP addr/id
        f = self.frags.setdefault((pkt.src, pkt.dst, pkt.id), {})
        f[pkt.off & dpkt.ip.IP_OFFMASK] = pkt
        offset = 0
        data = ''
        while True:
            if offset not in f:
                return None  # we don't have this offset, can't reassemble yet
            data += str(pkt.data)  # add this to the data
            if not pkt.off & dpkt.ip.IP_MF:
                break  # this is the next packet in order and no more fragments
            offset = len(data) / 8  # calculate the next fragment's offset
        # we hit no MF and last offset, so return a defragged packet
        del self.frags[(pkt.src, pkt.dst, pkt.id)]  # discard store
        pkt.data = data  # replace payload with defragged data
        pkt.off = 0  # no frags, offset 0
        pkt.sum = 0  # recompute checksum
        # dump and redecode packet to get checksum right
        return dpkt.ip.IP(str(pkt))

    def rawHandler(self, pktlen, pkt, ts, **kwargs):
        '''takes ethernet data and determines if it contains IP or IP6.
        defragments IPv4
        if 6to4, unencaps the IPv6
        If IP/IP6, hands off to IPDecoder via IPHandler()'''
        try:
            # if this is an IPv4 packet, defragment, decode and hand it off
            if type(pkt.data) == dpkt.ip.IP:
                if self.defrag:
                    # return packet if whole, None if more frags needed
                    pkt = self.ipdefrag(pkt.data)
                else:
                    pkt = pkt.data  # get the layer 3 packet
                if pkt:  # do we have a whole IP packet?
                    if self.decode6to4 and pkt.p == dpkt.ip.IP_PROTO_IP6:
                        pass  # fall thru to ip6 decode
                    elif not self.v6only:  # if we are decoding ip4
                        sip, dip = socket.inet_ntoa(
                            pkt.src), socket.inet_ntoa(pkt.dst)
                        # try to decode ports
                        try:
                            sport, dport = pkt.data.sport, pkt.data.dport
                        except:  # no ports in this layer-4 protocol
                            sport, dport = None, None
                        # generate int forms of src/dest ips
                        sipint, dipint = struct.unpack(
                            '!L', pkt.src)[0], struct.unpack('!L', pkt.dst)[0]
                        # call IPHandler with extra data
                        self.IPHandler(((sip, sport), (dip, dport)), pkt, ts,
                                       pkttype=dpkt.ethernet.ETH_TYPE_IP,
                                       proto=self.IP_PROTO_MAP.get(
                                           pkt.p, pkt.p),
                                       sipint=sipint, dipint=dipint,
                                       **kwargs)
            if pkt and type(pkt.data) == dpkt.ip6.IP6:
                pkt = pkt.data  # no defrag of ipv6
                # decode ipv6 addresses
                sip, dip = socket.inet_ntop(socket.AF_INET6, pkt.src), socket.inet_ntop(
                    socket.AF_INET6, pkt.dst)
                # try to get layer-4 ports
                try:
                    sport, dport = pkt.data.sport, pkt.data.dport
                except:
                    sport, dport = None, None
                # generate int forms of src/dest ips
                h, l = struct.unpack("!QQ", pkt.src)
                sipint = ( (h << 64) | l )
                h, l = struct.unpack("!QQ", pkt.dst)
                dipint = ( (h << 64) | l )
                # call ipv6 handler
                self.IPHandler(((sip, sport), (dip, dport)), pkt, ts,
                               pkttype=dpkt.ethernet.ETH_TYPE_IP6,
                               proto=self.IP_PROTO_MAP.get(pkt.nxt, pkt.nxt),
                               sipint=sipint, dipint=dipint,
                               **kwargs)
        except Exception, e:
            self._exc(e)

    def IPHandler(self, addr, pkt, ts, **kwargs):
        '''called if packet is IPv4/IPv6
                                check packets using filterfn here'''
        self.decodedbytes += len(str(pkt))
        self.count += 1
        if self.isPacketHandlerPresent and self.filterfn(addr):
            return self.packetHandler(ip=Packet(self, addr, pkt=str(pkt), ts=ts, **kwargs))


class IP6Decoder(IPDecoder):
    pass


class UDPDecoder(IPDecoder):

    '''extend UDPDecoder to decode UDP  optionally track state
            config if tracking state with connectionHandler or blobHandler
            maxblobs - if tracking state, max blobs to track before flushing
            swaplowport - when establishing state, swap source/dest so dest has low port
            cleanupinterval  - seconds with no activity before state is discarded (default 60)      '''

    def __init__(self, **kwargs):
        # by default limit UDP 'connections' to a single request and response
        self.maxblobs = 2
        # can we swap source/dest so dest always has low port?
        self.swaplowport = True
        self.cleanupinterval = 60
        IPDecoder.__init__(self, **kwargs)

    def UDP(self, addr, data, pkt, ts=None, **kwargs):
        ''' will call self.packetHandler(udp=Packet(),data=data)
        (see Packet() for Packet object common attributes)
        udp.pkt will contain the raw IP data
        data will contain the decoded UDP payload

        State tracking:
                only if connectionHandler or blobHandler is present
                and packetHandler is not present

        UDPDecoder will call:
                self.connectionInitHandler(conn=Connection())
                        when UDP state is established
                        (see Connection() for Connection object attributes)

                self.blobHandler(conn=Connection(),blob=Blob())
                        when stream direction switches (if following stream)
                        blob=(see Blob() objects)

                self.connectionHandler(conn=Connection())
                        when UDP state is flushed (if following stream)
                        state is flushed when stale or when maxblobs is exceeded
                        if maxblobs exceeded, current data will go into new connection

                self.connectionCloseHandler(conn=Connection())
                        when state is discarded (always)
        '''
        self.decodedbytes += len(data)
        self.count += 1
        try:
            if self.isPacketHandlerPresent:
                # create a Packet object and populate it
                return self.packetHandler(udp=Packet(self, addr, pkt=pkt, ts=ts, **kwargs), data=data)

            # if no PacketHandler, we need to track state
            conn = self.find(addr)
            if not conn:
                conn = self.track(addr, ts=ts, state='init', **kwargs)
            if conn.nextoffset['cs'] is None:
                conn.nextoffset['cs'] = 0
            if conn.nextoffset['sc'] is None:
                conn.nextoffset['sc'] = 0
            self.track(addr, data, ts, **kwargs)

        except Exception, e:
            self._exc(e)

    def IPHandler(self, addr, pkt, ts, **kwargs):
        '''IPv4 dispatch, hands address, UDP payload and packet up to UDP callback'''
        if self.filterfn(addr):
            if type(pkt.data) == dpkt.udp.UDP:
                return self.UDP(addr, str(pkt.data.data), str(pkt), ts, **kwargs)


class UDP6Decoder(UDPDecoder):
    pass


class TCPDecoder(UDPDecoder):

    '''IPv6 TCP/UDP decoder
            reassembles TCP and UDP streams
            For TCP and UDP (if no packetHandler)
                    self.connectionInitHandler(conn=Connection())
                            when TCP connection is established
                            (see Connection() for Connection object attributes)

                    self.blobHandler(conn=Connection(),blob=Blob())
                            when stream direction switches (if following stream)
                            blob=(see Blob() objects)

                    self.connectionHandler(conn=Connection())
                            when connection closes (if following stream)

                    self.connectionCloseHandler(conn=Connection())
                            when connection closes (always)

            For UDP only:
            self.packetHandler(udp=Packet(),data=data)
                            with every packet
                            data=decoded UDP data

            if packetHandler is present, it will be called only for UDP (and UDP will not be tracked)'''

    def __init__(self, **kwargs):
        self.maxblobs = None  # no limit on connections
        # can we swap source/dest so dest always has low port?
        self.swaplowport = False
        # if set true, will requre TCP handshake to track connection
        self.ignore_handshake = False
        self.cleanupinterval = 300
        # up two levels to IPDecoder
        IPDecoder.__init__(self, **kwargs)
        self.optiondict['ignore_handshake'] = {
            'action': 'store_true', 'help': 'ignore TCP handshake'}

    def IPHandler(self, addr, pkt, ts, **kwargs):
        '''IPv4 dispatch'''
        if self.filterfn(addr):
            if type(pkt.data) == dpkt.udp.UDP:
                return self.UDP(addr, str(pkt.data.data), str(pkt), ts, **kwargs)
            elif type(pkt.data) == dpkt.tcp.TCP:
                return self.TCP(addr, pkt.data, ts, **kwargs)

    def TCP(self, addr, tcp, ts, **kwargs):
        '''TCP dispatch'''
        self.decodedbytes += len(str(tcp))
        self.count += 1

        try:
            # attempt to find an existing connection for this address
            conn = self.find(addr)

            if self.ignore_handshake:
                # if we are ignoring handshakes, we will track all connections,
                # even if we did not see the initialization handshake.
                if not conn:
                    conn = self.track(addr, ts=ts, state='init', **kwargs)
                # align the sequence numbers when we first see a connection
                if conn.nextoffset['cs'] is None and addr == conn.addr:
                    conn.nextoffset['cs'] = tcp.seq + 1
                elif conn.nextoffset['sc'] is None and addr != conn.addr:
                    conn.nextoffset['sc'] = tcp.seq + 1
                self.track(addr, str(tcp.data), ts,
                    state='established', offset=tcp.seq, **kwargs)

            else:
                # otherwise, only track connections if we see a TCP handshake
                if (tcp.flags == dpkt.tcp.TH_SYN
                    or tcp.flags == dpkt.tcp.TH_SYN | dpkt.tcp.TH_CWR | dpkt.tcp.TH_ECE):
                    # SYN
                    if conn:
                        # if a connection already exists for the addr,
                        # close the old one to start fresh
                        self.close(conn, ts)
                    conn = self.track(addr, ts=ts, state='init', **kwargs)
                    if conn:
                        conn.nextoffset['cs'] = tcp.seq + 1
                elif (tcp.flags == dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK
                      or tcp.flags == dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK | dpkt.tcp.TH_ECE):
                    # SYN ACK
                    if conn and tcp.ack == conn.nextoffset['cs']:
                        conn.nextoffset['sc'] = tcp.seq + 1
                        conn.state = 'established'
                if conn and conn.state == 'established':
                    self.track(addr, str(tcp.data), ts,
                        state='established', offset=tcp.seq, **kwargs)

            # close connection
            if conn and tcp.flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
                # flag that an IP is closing a connection with FIN or RST
                conn.closeIP(addr[0])
            if conn and conn.connectionClosed():
                self.close(conn, ts)

        except Exception, e:
            self._exc(e)


class TCP6Decoder(TCPDecoder):
    pass


class Data(object):

    '''base class for data objects (packets,connections, etc..)
            these objects hold data (appendable array, typically of strings)
            and info members (updateable/accessible as members or as dict via info())
            typically one will extend the Data class and replace the data member
            and associated functions (update,iter,str,repr) with a data() function
            and functions to manipulate the data'''

    def __init__(self, *args, **kwargs):
        self.info_keys = []
        # update with list data
        self.data = list(args)
        # update with keyword data
        self.info(**kwargs)

    def info(self, *args, **kwargs):
        '''update/return info stored in this object
                data can be passwd as dict(s) or keyword args'''
        args = list(args) + [kwargs]
        for a in args:
            for k, v in a.iteritems():
                if k not in self.info_keys:
                    self.info_keys.append(k)
                self.__dict__[k] = v
        return dict((k, self.__dict__[k]) for k in self.info_keys)

    def unpack(self, fmt, data, *args):
        '''unpacks data using fmt to keys listed in args'''
        self.info(dict(zip(args, struct.unpack(fmt, data))))

    def pack(self, fmt, *args):
        '''packs info keys in args using fmt'''
        return struct.pack(fmt, *[self.__dict__[k] for k in args])

    def update(self, *args, **kwargs):
        '''updates data (and optionally keyword args)'''
        self.data.extend(args)
        self.info(kwargs)

    def __iter__(self):
        '''returns each data element in order added'''
        for data in self.data:
            yield data

    def __str__(self):
        '''return string built from data'''
        return ''.join(self.data)

    def __repr__(self):
        return ' '.join(['%s=%s' % (k, v) for k, v in self.info().iteritems()])

    def __getitem__(self, k): return self.__dict__[k]

    def __setitem__(self, k, v): self.__dict__[k] = v


class Packet(Data):

    '''metadata class for connectionless data
            Members:
                    sip, sport, dip, dport : source ip and port, dest ip and port
                    addr : ((sip,sport),(dip,dport)) tuple. sport/dport will be None if N/A
                    sipcc, dipcc, sipasn, dipasn : country codes and ASNs for source and dest IPs
                    ts : datetime.datetime() UTC timestamp of packet. use util.mktime(ts) to get POSIX timestamp
                    pkt : raw packet data
                    any additional args will be added to info dict
    '''

    def __init__(self, decoder, addr, ts=None, pkt=None, **kwargs):
        self.info_keys = ['addr', 'sip', 'dip', 'sport', 'dport', 'ts']
        self.addr = addr
        # do not define pkt unless passed in
        self.ts = ts
        ((self.sip, self.sport), (self.dip, self.dport)) = self.addr
        if pkt:
            self.pkt = pkt
            self.info(bytes=len(self.pkt))

        # pass instantiating decoder's cc/asn lookup objects to keep global
        # cache
        try:
            self.info(sipcc=decoder.getGeoIP(self.sip, db=decoder.geoccdb),
                      sipasn=decoder.getASN(self.sip, db=decoder.geoasndb),
                      dipcc=decoder.getGeoIP(self.dip, db=decoder.geoccdb),
                      dipasn=decoder.getASN(self.dip, db=decoder.geoasndb))
        except:
            self.sipcc, self.sipasn, self.dipcc, self.dipasn = None, None, None, None

        # update with additional info
        self.info(**kwargs)

    def __iter__(self):
        for p in self.pkt:
            yield ord(p)

    def __str__(self):
        return self.pkt

    def __repr__(self):
        return "%(ts)s  %(sip)16s :%(sport)-5s -> %(dip)5s :%(dport)-5s (%(sipcc)s -> %(dipcc)s)\n" % self.info()


class Connection(Packet):

    """
    Connection class is used for tracking all information
    contained within an established TCP connection / UDP pseudoconnection

    Extends Packet()

    Additional members:
            {client|server}ip, {client|server}port: aliases of sip,sport,dip,dport
            {client|server}countrycode, {client|server}asn: aliases of sip/dip country codes and ASNs
            clientpackets, serverpackets: counts of packets from client and server
            clientbytes, serverbytes: total bytes from client and server
            clientclosed, serverclosed: flag indicating if a direction has closed the connection
            starttime,endtime: timestamps of start and end (or last packet) time of connection.
            direction: indicates direction of last traffic:
                    'init' : established, no traffic
                    'cs': client to server
                    'sc': server to client
            state: TCP state of this connection
            blobs: array of reassembled half stream blobs
                            a new blob is started when the direction changes
            stop: if True, stopped following stream

    """
    
    MAX_OFFSET = 0xffffffff  # max offset before wrap, default is MAXINT32 for TCP sequence numbers

    def __init__(self, decoder, addr, ts=None, **kwargs):
        self.state = None
        # the offset we expect for the next blob in this direction
        self.nextoffset = {'cs': None, 'sc': None}
        # init IP-level data
        Packet.__init__(self, decoder, addr, ts=ts, **kwargs)
        self.clientip, self.clientport, self.serverip, self.serverport = (
            self.sip, self.sport, self.dip, self.dport)
        self.info_keys.extend(
            ['clientip', 'serverip', 'clientport', 'serverport'])
        self.clientcountrycode, self.clientasn, self.servercountrycode, self.serverasn = (
            self.sipcc, self.sipasn, self.dipcc, self.dipasn)
        self.info_keys.extend(
            ['clientcountrycode', 'servercountrycode', 'clientasn', 'serverasn'])
        self.clientpackets = 0  # we have the first packet for each connection
        self.serverpackets = 0
        self.clientbytes = 0
        self.serverbytes = 0
        self.clientclosed = False
        self.serverclosed = False
        self.starttime = self.ts        # datetime Obj containing start time
        self.endtime = self.ts
        # first update will change this, creating first blob
        self.direction = 'init'
        self.info_keys.extend(['clientpackets', 'clientbytes', 'serverpackets',
                               'serverbytes', 'starttime', 'endtime', 'state', 'direction'])

        # list of tuples of (direction,halfstream,startoffset,endoffset)
        # indicating where each side talks
        self.blobs = []
        self.stop = False

    def __repr__(self):
        # starttime  cip sip
        return '%s  %16s -> %16s  (%s -> %s)  %6s  %6s %5d  %5d  %7d  %7d  %6ds  %s' % (
            self.starttime,
            self.clientip,
            self.serverip,
            self.clientcountrycode,
            self.servercountrycode,
            self.clientport,
            self.serverport,
            self.clientpackets,
            self.serverpackets,
            self.clientbytes,
            self.serverbytes,
            (util.mktime(self.endtime) - util.mktime(self.starttime)),
            self.state)

    def connectionClosed(self):
        return self.serverclosed and self.clientclosed

    def closeIP(self, tuple):
        '''
            Track if we have seen a FIN packet from given tuple
            tuple should be of form (ip, port)
        '''
        if tuple == (self.clientip, self.clientport):
            self.clientclosed = True
        if tuple == (self.serverip, self.serverport):
            self.serverclosed = True

    def update(self, ts, direction, data, offset=None):
        # if we have no blobs or direction changes, start a new blob
        lastblob = None
        if len(self.blobs) > 1 and self.blobs[-2].startoffset <= offset < self.blobs[-2].endoffset:
            self.blobs[-2].update(ts,data,offset=offset)
        else:
            if direction != self.direction:
                self.direction = direction
                # if we have a finished blob, return it
                if self.blobs:
                    lastblob = self.blobs[-1]
                # for tracking offsets across blobs (TCP) set the startoffset of this blob to what we know it should be
                # this may not necessarily be the offset of THIS data if packets
                # are out of order
                self.blobs.append(
                    Blob(ts, direction, startoffset=self.nextoffset[direction]))
            self.blobs[-1].update(ts, data, offset=offset)  # update latest blob
        if direction == 'cs':
            self.clientpackets += 1
            self.clientbytes += len(data)
        elif direction == 'sc':
            self.serverpackets += 1
            self.serverbytes += len(data)
        self.endtime = ts
        # if we are tracking offsets, expect the next blob to be where this one
        # ends so far
        if offset != None and ((offset + len(data)) & self.MAX_OFFSET) >= self.nextoffset[direction]:
            self.nextoffset[direction] = (offset + len(data)) & self.MAX_OFFSET
        return lastblob

    # return one or both sides of the stream
    def data(self, direction=None, errorHandler=None, padding=None, overlap=True, caller=None):
        '''returns reassembled half-stream selected by direction 'sc' or 'cs'
                if no direction, return all stream data interleaved
                see Blob.data() for errorHandler docs'''
        return ''.join([b.data(errorHandler=errorHandler, padding=padding, overlap=overlap, caller=caller) for b in self.blobs if (not direction or b.direction == direction)])

    def __str__(self):
        '''return all data interleaved'''
        return self.data(padding='')

    def __iter__(self):
        '''return each blob in capture order'''
        for blob in self.blobs:
            yield blob


class Blob(Data):

    '''a blob containins a contiguous part of the half-stream
    Members:
            starttime,endtime : start and end timestamps of this blob
            direction : direction of this blob's data 'sc' or 'cs'
            data(): this blob's data
            startoffset,endoffset: offset of this blob start/end in bytes from start of stream
    '''

    # max offset before wrap, default is MAXINT32 for TCP sequence numbers
    MAX_OFFSET = 0xffffffff

    def __init__(self, ts, direction, startoffset):
        self.starttime = ts
        self.endtime = ts
        self.direction = direction
        self.segments = {}  # offset:[segments with offset]
        self.startoffset = startoffset
        self.endoffset = startoffset
        self.info_keys = [
            'starttime', 'endtime', 'direction', 'startoffset', 'endoffset']

    def update(self, ts, data, offset=None):
        # if offsets are not being provided, just keep packets in wire order
        if offset == None:
            offset = self.endoffset
        # buffer each segment in a list, keyed by offset (captures retrans,
        # etc)
        self.segments.setdefault(offset, []).append(data)
        if ts > self.endtime:
            self.endtime = ts
        # update the end offset if this packet goes at the end
        if (offset + len(data)) & self.MAX_OFFSET >= self.endoffset:
            self.endoffset = (offset + len(data)) & self.MAX_OFFSET

    def __repr__(self):
        return '%s %s (%s) +%s %d' % (self.starttime, self.endtime, self.direction, self.startoffset, len(self.segments))

    def __str__(self):
        '''returns segments of blob as string'''
        return self.data(padding='')

    def data(self, errorHandler=None, padding=None, overlap=True, caller=None):
        '''returns segments of blob reassembled into a string
           if next segment offset is not the expected offset
           errorHandler(blob,expected,offset) will be called
            blob is a reference to the blob
            if expected<offset, data is missing
            if expected>offset, data is overlapping
           else a KeyError will be raised.
            if the exception is passed and data is missing
             if padding != None it will be used to fill the gap
            if segment overlaps existing data
                 new data is kept if overlap=True
                 existing data is kept if overlap=False
            caller: a ref to the calling object, passed to errorhandler
            dup: how to handle duplicate segments:
                0: use first segment seen
                -1 (default): use last segment seen
            changing duplicate segment handling to always take largest segment
        '''
        d = ''
        nextoffset = self.startoffset
        for segoffset in sorted(self.segments.iterkeys()):
            if segoffset != nextoffset:
                if errorHandler:  # errorhandler can mangle blob data
                    if not errorHandler(blob=self, expected=nextoffset, offset=segoffset, caller=caller):
                        continue  # errorhandler determines pass or fail here
                elif segoffset > nextoffset:
                    # data missing and padding specified
                    if padding is not None:
                        if len(padding):
                            # add padding to data
                            d += str(padding) * (segoffset - nextoffset)
                    else:
                        # data missing, and no padding
                        raise KeyError(nextoffset)
                elif segoffset < nextoffset and not overlap:
                    continue  # skip if not allowing overlap
            #find most data in segments
            seg = ''
            for x in self.segments[segoffset]:
                if len(x) > len(seg):
                    seg = x
            # advance next expected offset
            nextoffset = (
                segoffset + len(seg)) & self.MAX_OFFSET
            # append or splice data
            d = d[:segoffset - self.startoffset] + \
                seg + \
                d[nextoffset - self.startoffset:]
        return d

    def __iter__(self):
        '''return each segment data in offset order
                for TCP this will return segments ordered but not reassembled
                        (gaps and overlaps may exist)
                for UDP this will return datagrams payloads in capture order,
                        (very useful for RTP or other streaming protocol.)
        '''
        for segoffset in sorted(self.segments.iterkeys()):
            yield self.segments[segoffset][-1]
