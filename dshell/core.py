"""
The core Dshell library

This library contains the base level plugins that all others will inherit.

PacketPlugin contains attributes and functions for plugins that work with
individual packets.

ConnectionPlugin inherits from PacketPlugin and includes additional functions
for handling reassembled connections.

It also contains class definitions used by the plugins, including definitions
for Blob, Connection, and Packet.

"""

# standard Python imports
import datetime
import inspect
import ipaddress
import logging
import os
#import pprint
import struct
from collections import defaultdict
from multiprocessing import Value

# Dshell imports
from dshell.output.output import Output
from dshell.dshellgeoip import DshellGeoIP, DshellFailedGeoIP

# third-party imports
import pcapy
from pypacker.layer12 import can, ethernet, ieee80211, linuxcc, ppp, pppoe, radiotap
from pypacker.layer3 import ip, ip6, icmp, icmp6
from pypacker.layer4 import tcp, udp

logging.basicConfig(format="%(levelname)s (%(name)s) - %(message)s")
logger = logging.getLogger("dshell.core")

__version__ = "1.1"

class SequenceNumberError(Exception):
    """
    Raised when reassembling connections and data is missing or overlapping.
    See Blob.reassemble function
    """
    pass

class DataError(Exception):
    """
    Raised when any data being handled just isn't right.
    For example, invalid headers in httpplugin.py
    """
    pass


# Create GeoIP refrence object
try:
    geoip = DshellGeoIP(logger=logging.getLogger("dshellgeoip.py"))
except FileNotFoundError:
    logger.error("Could not find GeoIP data files! Country and ASN lookups will not be possible. Check README for instructions on where to find and install necessary data files.")
    geoip = DshellFailedGeoIP()


def print_handler_exception(e, plugin, handler):
    """
    A convenience function to display an error message when a handler raises
    an exception.

    If using --debug, it will print a full traceback.

    Args:
        e:          the exception object
        plugin:    the plugin object
        handler:    name of the handler function
    """
    etype = e.__class__.__name__
    if logger.isEnabledFor(logging.DEBUG):
        logger.error("The {!s} for the {!r} plugin raised an exception and failed! ({}: {!s})".format(handler, plugin.name, etype, e))
        logger.exception(e)
    else:
        logger.error("The {!s} for the {!r} plugin raised an exception and failed! ({}: {!s}) Use --debug for more details.".format(handler, plugin.name, etype, e))


class PacketPlugin(object):
    """
    Base level class that plugins will inherit.

    This plugin handles individual packets. To handle reconstructed
    connections, use the ConnectionPlugin.

    Attributes:
        name:           the name of the plugin
        description:    short description of the plugin (used with decode -l)
        longdescription:    verbose description of the plugin (used with -h)
        bpf:            default BPF to apply to traffic entering plugin
        compiled_bpf:   a compiled BPF for pcapy, usually created in bin/decode
        vlan_bpf:       boolean that tells whether BPF should be compiled with
                        VLAN support
        author:         preferably, the initials of the plugin's author
        seen_packet_count:      number of packets this plugin has seen
        handled_packet_count:   number of packets this plugin has passed
                                through a handler function
        seen_conn_count:        number of connections this plugin has seen
        handled_conn_count:     number of connections this plugin has passed
                                through a handler function
        out:            output module instance
        raw_decoder:        pypacker module to use for unpacking packet
        link_layer_type:    numeric label for link layer
        striplayers:    number of layers to automatically strip before handling
                        (such as PPPoE, IP-over-IP, etc.)
        defrag_ip:      rebuild fragmented IP packets (default: True)
    """

    IP_PROTOCOL_MAP = dict((v, k[9:]) for k, v in ip.__dict__.items() if type(v) == int and k.startswith('IP_PROTO_') and k != 'IP_PROTO_HOPOPTS')

    def __init__(self, **kwargs):
        self.name = kwargs.get('name', __name__)
        self.description = kwargs.get('description', '')
        self.longdescription = kwargs.get('longdescription', self.description)
        self.bpf = kwargs.get('bpf', '')
        self.compiled_bpf = kwargs.get('compiled_bpf', None)
        self.vlan_bpf = kwargs.get("vlan_bpf", True)
        self.author = kwargs.get('author', '')
        # define overall counts as multiprocessing Values for --parallel
        self.seen_packet_count = Value('i', 0)
        self.handled_packet_count = Value('i', 0)
        self.seen_conn_count = Value('i', 0)
        self.handled_conn_count = Value('i', 0)
        # dict of options specific to this plugin in format
        #       'optname':{configdict} translates to --pluginname_optname
        self.optiondict = kwargs.get('optiondict', {})

        # queues used by decode.py
        # if a handler decides a packet is worth keeping, it is placed in a
        # queue and later grabbed by decode.py to pass to subplugins
        self.raw_packet_queue = []
        self.packet_queue = []

        # self.out holds the output plugin instance
        # can be overwritten in decode.py by user selection
        self.out = kwargs.get('output', Output(label=__name__))

        # capture options
        # these can be updated with set_link_layer_type function
        self.raw_decoder = ethernet.Ethernet    # assumed link-layer type
        self.link_layer_type = 1                # assume Ethernet
        # strip extra layers before IP/IPv6? (such as PPPoE, IP-over-IP, etc..)
        self.striplayers = 0
        # rebuild fragmented IP packets
        self.defrag_ip = True

        # holder for the pcap file being processing
        self.current_pcap_file = None

        # get the list of functions for this plugin
        # this is used in decode.py
        self.members = tuple([x[0] for x in inspect.getmembers(self, inspect.ismethod)])

        # a holder for IP packet fragments when attempting to reassemble them
        self.packet_fragments = defaultdict(dict)

    def write(self, *args, **kwargs):
        """
        Sends information to the output formatter, after adding some
        additional fields.
        """
        if 'plugin' not in kwargs:
            kwargs['plugin'] = self.name
        if 'pcapfile' not in kwargs:
            kwargs['pcapfile'] = self.current_pcap_file
        self.out.write(*args, **kwargs)

    def log(self, msg, level=logging.INFO):
        '''
        logs msg argument at specified level
        (default of INFO is for -v/--verbose output)

        Arguments:
            msg:        text string to log
            level:      logging level (default: logging.INFO)
        '''
        self.out.log(msg, level=level)

    def debug(self, msg):
        '''logs msg argument at debug level'''
        self.log(msg, level=logging.DEBUG)

    def warn(self, msg):
        '''logs msg argument at warning level'''
        self.log(msg, level=logging.WARN)

    def error(self, msg):
        '''logs msg argument at error level'''
        self.log(msg, level=logging.ERROR)

    def __str__(self):
        return "<{}: {}>".format("Plugin", self.name)

    def __repr__(self):
        return '<{}: {}/{}/{}>'.format("Plugin", self.name, self.bpf,
                             ','.join([('%s=%s' % (x, str(self.__dict__.get(x)))) for x in self.optiondict]))

    def set_link_layer_type(self, datalink):
        """
        Attempts to set the raw_decoder attribute based on the capture file's
        datalink type, which is fetched by pcapy when used in decode.py. It
        takes one argument: the numeric value of the link layer.

        http://www.tcpdump.org/linktypes.html
        """
        # NOTE: Not all of these have been tested
        # TODO add some more of these
        self.link_layer_type = datalink
        if datalink == 1:
            self.raw_decoder = ethernet.Ethernet
        elif datalink == 9:
            self.raw_decoder = ppp.PPP
        elif datalink == 51:
            self.raw_decoder = pppoe.PPPoE
        elif datalink == 105:
            self.raw_decoder = ieee80211.IEEE80211
        elif datalink == 113:
            self.raw_decoder = linuxcc.LinuxCC
        elif datalink == 127:
            self.raw_decoder = radiotap.Radiotap
        elif datalink == 204:
            self.raw_decoder = ppp.PPP
        elif datalink == 227:
            self.raw_decoder = can.CAN
        elif datalink == 228:
            self.raw_decoder = ip.IP
        elif datalink == 229:
            self.raw_decoder = ip6.IP6
        else:
            # by default, assume Ethernet and hope for the best
            self.link_layer_type = 1
            self.raw_decoder = ethernet.Ethernet
        self.debug("Datalink input: {!s}. Setting raw_decoder to {!r}, link_layer_type to {!s}".format(datalink, self.raw_decoder, self.link_layer_type))

    def recompile_bpf(self):
        "Compile the BPF stored in the .bpf attribute"
        # This function is normally only called by the bin/decode.py script,
        # but can also be called by plugins that need to dynamically update
        # their filter.
        if not self.bpf:
            logger.debug("Cannot compile BPF: .bpf attribute not set for plugin {!r}.".format(self.name))
            self.compiled_bpf = None
            return

        # Add VLAN wrapper, if necessary
        if self.vlan_bpf:
            bpf = "({0}) or (vlan and {0})".format(self.bpf)
        else:
            bpf = self.bpf
        self.debug("Compiling BPF as {!r}".format(bpf))

        # Compile BPF and handle any expected errors
        try:
            self.compiled_bpf = pcapy.compile(
                self.link_layer_type, 65536, bpf, True, 0xffffffff
            )
        except pcapy.PcapError as e:
            if str(e).startswith("no VLAN support for data link type"):
                logger.error("Cannot use VLAN filters for {!r} plugin. Recommend running with --no-vlan argument.".format(self.name))
            elif str(e) == "syntax error":
                logger.error("Fatal error when compiling BPF: {!r}".format(bpf))
                sys.exit(1)
            else:
                raise e

    def ipdefrag(self, pkt):
        "IP fragment reassembly"
        if isinstance(pkt, ip.IP): # IPv4
            f = self.packet_fragments[(pkt.src, pkt.dst, pkt.id)]
            f[pkt.offset] = pkt

            if not pkt.flags & 0x1:
                data = b''
                for key in sorted(f.keys()):
                    data += f[key].body_bytes
                del self.packet_fragments[(pkt.src, pkt.dst, pkt.id)]
                newpkt = ip.IP(pkt.header_bytes + data)
                newpkt.bin(update_auto_fields=True)  # refresh checksum
                return newpkt

        elif isinstance(pkt, ip6.IP6): # IPv6
            # TODO handle IPv6 offsets https://en.wikipedia.org/wiki/IPv6_packet#Fragment
            return pkt

    def handle_plugin_options(self):
        """
        A placeholder.

        This function is called immediately after plugin args are processed
        and set in decode.py. A plugin can overwrite this function to perform
        actions based on the arg values as soon as they are set, before
        decoder.py does any further processing (e.g. updating a BPF based on
        provided arguments before handling --ebpf and --bpf flags).
        """
        pass

    def _premodule(self):
        """
        _premodule is called before capture starts or files are read. It will
        attempt to call the child plugin's premodule function.
        """
        self.premodule()
        self.out.setup()
#        self.debug('{}'.format(pprint.pformat(self.__dict__)))
        self.debug(str(self.__dict__))

    def premodule(self):
        """
        A placeholder.

        A plugin can overwrite this function to perform an action before
        capture starts or files are read.
        """
        pass

    def _postmodule(self):
        """
        _postmodule is called when capture ends. It will attempt to call the
        child plugin's postmodule function. It will also print stats if in
        debug mode.
        """
        self.postmodule()
        self.out.close()
        self.log("{} seen packets, {} handled packets, {} seen connections, {} handled connections".format(self.seen_packet_count.value, self.handled_packet_count.value, self.seen_conn_count.value, self.handled_conn_count.value))

    def postmodule(self):
        """
        A placeholder.

        A plugin can overwrite this function to perform an action after
        capture ends or all files are processed.
        """
        pass

    def _prefile(self, infile=None):
        """
        _prefile is called just before an individual file is processed.
        Stores the current pcap file string and calls the child plugin's
        prefile function.
        """
        self.current_pcap_file = infile
        self.prefile(infile)
        self.log('working on file "{}"'.format(infile))

    def prefile(self, infile=None):
        """
        A placeholder.

        A plugin will be able to overwrite this function to perform an action
        before an individual file is processed.

        Arguments:
            infile:     filepath or interface that will be processed
        """
        pass

    def _postfile(self):
        """
        _postfile is called just after an individual file is processed.
        It may expand some day, but for now it just calls a child's postfile
        function.
        """
        self.postfile()

    def postfile(self):
        """
        A placeholder.

        A plugin will be able to overwrite this function to perform an action
        after an individual file is processed.
        """
        pass

    def _raw_handler(self, pktlen, pkt, ts):
        """
        Accepts raw packet data (pktlen, pkt, ts), and handles decapsulation
        and layer stripping.

        Then, it passes the massaged data to the child's raw_handler function,
        if additional custom handling is necessary. The raw_handler function
        should return (pktlen, pkt, ts) if it wishes to continue with the call
        chain. Otherwise, return None.
        """
#        with self.seen_packet_count.get_lock():
#            self.seen_packet_count.value += 1
#
#        # call raw_handler and check its output
#        # decode.py will continue down the chain if it returns proper output or
#        # display a warning if it doesn't return the correct things
#        try:
#            raw_handler_out = self.raw_handler(pktlen, pkt, ts)
#        except Exception as e:
#            print_handler_exception(e, self, 'raw_handler')
#            return
#
#        failed_msg = "The output of {} raw_handler must be (pktlen, pkt, ts) or a list of such lists! Further packet refinement and plugin chaining will not be possible".format(self.name)
#        if raw_handler_out and isinstance(raw_handler_out, (list, tuple)):
#            self.warn(failed_msg)
#            return

        with self.seen_packet_count.get_lock():
            self.seen_packet_count.value += 1
        # decode with the raw decoder (probably ethernet.Ethernet)
        pkt = self.raw_decoder(pkt)

        # strip any intermediate layers (e.g. PPPoE, etc.)
        # NOTE: make sure only the first plugin in a chain has striplayers set
        for _ in range(self.striplayers):
            try:
                pkt = pkt.upper_layer
            except AttributeError:
                # No more layers to strip
                break

        # call raw_handler and check its output
        # decode.py will continue down the chain if it returns proper output or
        # display a warning if it doesn't return the correct things
        try:
            raw_handler_out = self.raw_handler(pktlen, pkt, ts)
        except Exception as e:
            print_handler_exception(e, self, 'raw_handler')
            return
        failed_msg = "The output of {} raw_handler must be (pktlen, pkt, ts) or a list of such lists! Further packet refinement and plugin chaining will not be possible".format(self.name)
        if isinstance(raw_handler_out, (list, tuple)):
            if len(raw_handler_out) == 3 and (
                    isinstance(raw_handler_out[0], type(pktlen)) and
                    isinstance(raw_handler_out[1], type(pkt)) and
                    isinstance(raw_handler_out[2], type(ts))):
                # If it returns one properly formed response, queue and continue
                self.raw_packet_queue.append(raw_handler_out)
            else:
                # If it returns several responses, check them individually
                for rhout in raw_handler_out:
                    if isinstance(rhout, (list, tuple)) and \
                            len(rhout) == 3 and \
                            isinstance(rhout[0], type(pktlen)) and \
                            isinstance(rhout[1], type(pkt)) and \
                            isinstance(rhout[2], type(ts)):
                        self.raw_packet_queue.append(rhout)
                    elif rhout:
                        self.warn(failed_msg)
        elif raw_handler_out:
            self.warn(failed_msg)


    def raw_handler(self, pktlen, pkt, ts):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites on
        raw packet data, such as decapsulation or decryption, before it
        becomes further refined down the chain. It should return the same
        arguments: pktlen, pkt, ts

        Generally speaking, however, this should never be overwritten unless
        there is a very, very good reason for it.

        Arguments:
            pktlen:     length of packet
            pkt:        raw bytes of the packet
            ts:         timestamp of packet
        """
        return pktlen, pkt, ts

    def _packet_handler(self, pktlen, pkt, ts):
        """
        Accepts the output of raw_handler, pulls out addresses, and converts
        it all into a dshell.Packet object before calling the child's
        packet_handler function.
        """
        # Attempt to perform defragmentation
        if isinstance(pkt.upper_layer, (ip.IP, ip6.IP6)):
            ipp = pkt.upper_layer
            if self.defrag_ip:
                ipp = self.ipdefrag(ipp)
                if not ipp:
                    # we do not yet have all of the packet fragments, so move
                    # on to next packet for now
                    return
                else:
                    pkt.upper_layer = ipp

        # Initialize a Packet object
        # This will be populated with values as we continue through
        # the function and eventually be passed to packet_handler
        packet = Packet(self, pktlen, pkt, ts)

        # call packet_handler and return its output
        # decode.py will continue down the chain if it returns anything
        try:
            packet_handler_out = self.packet_handler(packet)
        except Exception as e:
            print_handler_exception(e, self, 'packet_handler')
            return
        failed_msg = "The output from {} packet_handler must be of type dshell.Packet or a list of such objects! Handling connections or chaining from this plugin may not be possible.".format(self.name)
        if isinstance(packet_handler_out, (list, tuple)):
            for phout in packet_handler_out:
                if isinstance(phout, Packet):
                    self.packet_queue.append(phout)
                    with self.handled_packet_count.get_lock():
                        self.handled_packet_count.value += 1
                elif phout:
                    self.warn(failed_msg)
        elif isinstance(packet_handler_out, Packet):
            self.packet_queue.append(packet_handler_out)
            with self.handled_packet_count.get_lock():
                self.handled_packet_count.value += 1
        elif packet_handler_out:
            self.warn(failed_msg)


    def packet_handler(self, pkt):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites on
        Packet data.

        It should return a Packet object for functions further down the chain
        (i.e. connection_handler and/or blob_handler)

        Arguments:
            pkt:    a Packet object
        """
        return pkt



class ConnectionPlugin(PacketPlugin):
    """
    Base level class that plugins will inherit.

    This plugin reassembles connections from packets.
    """

    def __init__(self, **kwargs):
        PacketPlugin.__init__(self, **kwargs)

        # similar to packet_queue and raw_packet_queue in superclass
        self.connection_queue = []

        # dictionary to store packets for connections according to addr()
        self.connection_tracker = {}
        # maximum number of blobs a connection will store before calling
        # connection_handler
        # it defaults to infinite, but this should be lowered for huge datasets
        self.maxblobs = float("inf")  # infinite
        # how long do we wait before deciding a connection is "finished"
        # time is checked by iterating over cached connections and checking if
        # the timestamp of the connection's last packet is older than the
        # timestamp of the current packet, minus this value
        self.connection_timeout = datetime.timedelta(hours=1)

    def _connection_handler(self, pkt):
        """
        Accepts a single Packet object and tracks the connection it belongs to.

        If it is the first packet in a connection, it creates a new Connection
        object and passes it to connection_init_handler. Otherwise, it will
        find the existing Connection in self.connection_tracker.

        The Connection will then be passed to connection_handler.

        If a connection changes direction with this packet, blob_handler will
        be called.

        Finally, if this packet is a FIN or RST, it will determine if the
        connection should close.
        """
        # Sort the addr value for consistent dictionary key purposes
        addr = tuple(sorted(pkt.addr))

        # If this is a new connection, initialize it and call the init handler
        if addr not in self.connection_tracker:
            conn = Connection(self, pkt)
            self.connection_tracker[addr] = conn
            try:
                self.connection_init_handler(conn)
            except Exception as e:
                print_handler_exception(e, self, 'connection_init_handler')
                return
            with self.seen_conn_count.get_lock():
                self.seen_conn_count.value += 1
        else:
            conn = self.connection_tracker[addr]

        if conn.stop:
            # This connection was flagged to not be tracked
            return

        # If connection data is about to change, we set it to a "dirty" state
        # for future calls to connection_handler
        if pkt.data:
            conn.handled = False

        # Check and update the connection's current state
        if pkt.tcp_flags in (tcp.TH_SYN, tcp.TH_ACK, tcp.TH_SYN|tcp.TH_ACK, tcp.TH_SYN|tcp.TH_ACK|tcp.TH_ECE):
            # if new connection and a handshake is taking place, set to "init"
            if not conn.client_state:
                conn.client_state = "init"
            if not conn.server_state:
                conn.server_state = "init"
        else:
            # otherwise, if the connection isn't closed, set to "established"
            # TODO do we care about "listen", "syn-sent", and other in-between states?
            if conn.client_state not in ('finishing', 'closed'):
                conn.client_state = "established"
            if conn.server_state not in ('finishing', 'closed'):
                conn.server_state = "established"

        # Add the packet to the connection
        # If the direction changed, a Blob will be returned for handling
        # Note: The Blob will not be reassembled ahead of time. reassemble()
        # must be run inside the blob_handler to catch any unwanted exceptions.
        previous_blob = conn.add_packet(pkt)
        if previous_blob:
            try:
                blob_handler_out = self._blob_handler(conn, previous_blob)
            except Exception as e:
                print_handler_exception(e, self, 'blob_handler')
                return
            if (blob_handler_out
                    and not isinstance(blob_handler_out[0], Connection)
                    and not isinstance(blob_handler_out[1], Blob)):
                self.warn("The output from {} blob_handler must be of type (dshell.Connection, dshell.Blob)! Chaining plugins from here may not be possible.".format(self.name))
                blob_handler_out = None
            # If the blob_handler decides this Blob isn't interesting, it sets
            # the hidden flag, which excludes it and its packets from further
            # processing along the plugin chain
            if not blob_handler_out:
                conn.blobs[-2].hidden = True

        # Check if a side of the connection is attempting to close the
        # connection using a FIN or RST packet. Once both sides make a
        # closing gesture, the connection is considered closed and handled
        if pkt.tcp_flags and pkt.tcp_flags & (tcp.TH_RST | tcp.TH_FIN):
            if pkt.sip == conn.clientip:
                conn.client_state = "closed"
            else:
                conn.server_state = "closed"

        if conn.connection_closed:
            # Both sides have closed the connection
            self._close_connection(conn, full=True)

        elif len(conn.blobs) > self.maxblobs:
            # Max blobs hit, so we will run connection_handler and decode.py
            # will clear the connection's blob cache
            self._close_connection(conn)

        # The current connection is done processing. Now, look over existing
        # connections and look for any that have timed out.
        # This is based on comparing the time of the current packet, minus
        # self.connection_timeout, to each connection's current endtime value.
        for addr, conn in self.connection_tracker.items():
            if conn.handled:
                continue
            if conn.endtime < (pkt.dt - self.connection_timeout):
                self._close_connection(conn)


    def _close_connection(self, conn, full=False):
        """
        Runs through some standard actions to close a connection
        """
        try:
           connection_handler_out = self.connection_handler(conn)
        except Exception as e:
            print_handler_exception(e, self, 'connection_handler')
            return None
        conn.handled = True
        if connection_handler_out and not isinstance(connection_handler_out, Connection):
            self.warn("The output from {} connection_handler must be of type dshell.Connection! Chaining plugins from here may not be possible.".format(self.name))
            connection_handler_out = None
        if connection_handler_out:
            self.connection_queue.append(connection_handler_out)
            with self.handled_conn_count.get_lock():
                self.handled_conn_count.value += 1
        if full:
            try:
                self.connection_close_handler(conn)
            except Exception as e:
                print_handler_exception(e, self, 'connection_close_handler')
        return connection_handler_out


    def _cleanup_connections(self):
        """
        decode.py will often reach the end of packet capture before all of the
        connections are closed properly. This function is called at the end
        of things to process those dangling connections.

        NOTE: Because the connections did not close cleanly,
        connection_close_handler will not be called.
        """
        for addr, conn in self.connection_tracker.items():
            if not conn.stop and not conn.handled:
                # try to process the final blob in the connection
                try:
                    blob_handler_out = self._blob_handler(conn, conn.blobs[-1])
                except Exception as e:
                    print_handler_exception(e, self, 'blob_handler')
                    blob_handler_out = None
                if (blob_handler_out
                        and not isinstance(blob_handler_out[0], Connection)
                        and not isinstance(blob_handler_out[1], Blob)):
                    self.warn("The output from {} blob_handler must be of type (dshell.Connection, dshell.Blob)! Chaining plugins from here may not be possible.".format(self.name))
                    blob_handler_out = None
                if not blob_handler_out:
                    conn.blobs[-1].hidden = True

                # then, handle the connection itself
                connection_handler_out = self._close_connection(conn)
                yield connection_handler_out

    def _purge_connections(self):
        """
        When finished with handling a pcap file, calling this will clear all
        caches in preparation for next file.
        """
        self.connection_queue = []
        self.connection_tracker = {}

    def _blob_handler(self, conn, blob):
        """
        Accepts a Connection and a Blob.

        It doesn't really do anything except call the blob_handler and is only
        here for consistency and possible future features.
        """
        return self.blob_handler(conn, blob)

    def blob_handler(self, conn, blob):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites on
        Blob data.

        It should return a Connection object and a Blob object for functions
        further down the chain.

        Args:
            conn: Connection object
            blob: Blob object
        """
        return conn, blob

    def connection_init_handler(self, conn):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites on
        a connection it is first seen.

        Args:
            conn: Connection object
        """
        return

    def connection_handler(self, conn):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites on
        Connection data.

        It should return a Connection object for functions further down the chain

        Args:
            conn: Connection object
        """
        return conn

    def connection_close_handler(self, conn):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites on
        a TCP connection when it is cleanly closed with RST or FIN.

        Args:
            conn: Connection object
        """
        return

class Packet(object):
    """
    Class for holding data of individual packets

    def __init__(self, plugin, pktlen, pkt, ts):

    Args:
        plugin:     an instance of the plugin creating this packet
        pktlen:     length of packet
        pkt:        pypacker object for the packet
        ts:         timestamp of packet

    Attributes:
        plugin:     name of plugin creating Packet
        ts:         timestamp of packet
        dt:         datetime of packet
        pkt:        pypacker object for the packet
        rawpkt:     raw bytestring of the packet
        pktlen:     length of packet
        byte_count: length of packet body
        sip:        source IP
        dip:        destination IP
        sip_bytes:  source IP as bytes
        dip_bytes:  destination IP as bytes
        sport:      source port
        dport:      destination port
        smac:       source MAC
        dmac:       destination MAC
        sipcc:      source IP country code
        dipcc:      dest IP country code
        siplat:     source IP latitude
        diplat:     dest IP latitude
        siplon:     source IP longitude
        diplon:     dest IP longitude
        sipasn:     source IP ASN
        dipasn:     dest IP ASN
        protocol:   text version of protocol in layer-3 header
        protocol_num:   numeric version of protocol in layer-3 header
        data:       data of the packet after TCP layer, or highest layer
        sequence_number:    TCP sequence number, or None
        ack_number:         TCP ACK number, or None
        tcp_flags:  TCP header flags, or None
    """

    def __init__(self, plugin, pktlen, pkt, ts):
        self.plugin = plugin.name
        self.ts = ts
        self.dt = datetime.datetime.fromtimestamp(ts)
        self.pkt = pkt
        self.rawpkt = pkt.bin()
        self.pktlen = pktlen
        self.byte_count = None
        self.sip = None
        self.dip = None
        self.sport = None
        self.dport = None
        self.smac = None
        self.dmac = None
        self.sipcc = None
        self.dipcc = None
        self.siplat = None
        self.diplat = None
        self.siplon = None
        self.diplon = None
        self.sipasn = None
        self.dipasn = None
        self.protocol = None
        self.protocol_num = None
        self.data = b''
        self.sequence_number = None
        self.ack_number = None
        self.tcp_flags = None

        # these are the layers Dshell will help parse
        # try to find them in the packet and eventually pull out useful data
        ethernet_p = None
        ieee80211_p = None
        ip_p = None
        tcp_p = None
        udp_p = None
        current_layer = pkt
        while current_layer:
            if isinstance(current_layer, ethernet.Ethernet) and not ethernet_p:
                ethernet_p = current_layer
            elif isinstance(current_layer, ieee80211.IEEE80211) and not ieee80211_p:
                ieee80211_p = current_layer
            elif isinstance(current_layer, (ip.IP, ip6.IP6)) and not ip_p:
                ip_p = current_layer
            elif isinstance(current_layer, tcp.TCP) and not tcp_p:
                tcp_p = current_layer
            elif isinstance(current_layer, udp.UDP) and not udp_p:
                udp_p = current_layer
            try:
                current_layer = current_layer.upper_layer
            except AttributeError:
                break

        # attempt to grab MAC addresses
        if ethernet_p:
            # from Ethernet
            self.smac = ethernet_p.src_s
            self.dmac = ethernet_p.dst_s
        elif ieee80211_p:
            # from 802.11
            try:
                if ieee80211_p.subtype == ieee80211.M_BEACON:
                    ieee80211_p2 = ieee80211_p.beacon
                elif ieee80211_p.subtype == ieee80211.M_DISASSOC:
                    ieee80211_p2 = ieee80211_p.disassoc
                elif ieee80211_p.subtype == ieee80211.M_AUTH:
                    ieee80211_p2 = ieee80211_p.auth
                elif ieee80211_p.subtype == ieee80211.M_DEAUTH:
                    ieee80211_p2 = ieee80211_p.deauth
                elif ieee80211_p.subtype == ieee80211.M_ACTION:
                    ieee80211_p2 = ieee80211_p.action
                else:
                    # can't figure out how pypacker stores the other subtypes
                    raise AttributeError
                self.smac = ieee80211_p2.src_s
                self.dmac = ieee80211_p2.dst_s
            except AttributeError as e:
                pass

        # process IP addresses and associated metadata (if applicable)
        if ip_p:
            # get IP addresses
            sip = ipaddress.ip_address(ip_p.src)
            dip = ipaddress.ip_address(ip_p.dst)
            self.sip = sip.compressed
            self.dip = dip.compressed
            self.sip_bytes = sip.packed
            self.dip_bytes = dip.packed

            # get protocols, country codes, and ASNs
            self.protocol_num = ip_p.p if isinstance(ip_p, ip.IP) else ip_p.nxt
            self.protocol = PacketPlugin.IP_PROTOCOL_MAP.get(self.protocol_num, str(self.protocol_num))
            self.sipcc, self.siplat, self.siplon = geoip.geoip_location_lookup(self.sip)
            self.sipasn = geoip.geoip_asn_lookup(self.sip)
            self.dipcc, self.diplat, self.diplon = geoip.geoip_location_lookup(self.dip)
            self.dipasn = geoip.geoip_asn_lookup(self.dip)

        if tcp_p:
            self.sport = tcp_p.sport
            self.dport = tcp_p.dport
            self.sequence_number = tcp_p.seq
            self.ack_number = tcp_p.ack
            self.tcp_flags = tcp_p.flags
            self.data = tcp_p.body_bytes

        elif udp_p:
            self.sport = udp_p.sport
            self.dport = udp_p.dport
            self.data = udp_p.body_bytes

        else:
            self.data = pkt.highest_layer.body_bytes

        self.byte_count = len(self.data)



    @property
    def addr(self):
        """
        A standard representation of the address:
        ((self.sip, self.sport), (self.dip, self.dport))
        or
        ((self.smac, self.sport), (self.dmac, self.dport))
        """
        # try using IP addresses first
        if self.sip or self.dip:
            return ((self.sip, self.sport), (self.dip, self.dport))
        # then try MAC addresses
        elif self.smac or self.dmac:
            return ((self.smac, self.sport), (self.dmac, self.dport))
        # if all else fails, return Nones
        else:
            return ((None, None), (None, None))

    @property
    def packet_tuple(self):
        """
        A standard representation of the raw packet tuple:
        (self.pktlen, self.rawpkt, self.ts)
        """
        return (self.pktlen, self.rawpkt, self.ts)

    def __repr__(self):
        return "%s  %16s :%-5s -> %5s :%-5s (%s -> %s)" % (self.dt, self.sip, self.sport, self.dip, self.dport, self.sipcc, self.dipcc)

    def info(self):
        """
        Provides a dictionary with information about a packet. Useful for
        calls to a plugin's write() function, e.g. self.write(\\*\\*pkt.info())
        """
        d = dict(self.__dict__)
        del d['pkt']
        del d['rawpkt']
        del d['data']
        return d


class Connection(object):
    """
    Class for holding data about connections

    def __init__(self, plugin, first_packet)

    Args:
        plugin:         an instance of the plugin creating this connection
        first_packet:   the first Packet object to initialize connection

    Attributes:
        plugin:     name of the plugin that created object
        addr:       .addr attribute of first packet
        sip:        source IP
        smac:       source MAC address
        sport:      source port
        sipcc:      country code of source IP
        siplat:     latitude of source IP
        siplon:     longitude of source IP
        sipasn:     ASN of source IP
        clientip:   same as sip
        clientmac:  same as smac
        clientport: same as sport
        clientcc:   same as sipcc
        clientlat:  same as siplat
        clientlon:  same as siplon
        clientasn:  same as sipasn
        dip:        dest IP
        dmac:       dest MAC address
        dport:      dest port
        dipcc:      country code of dest IP
        diplat:     latitude of dest IP
        diplon:     longitude of dest IP
        dipasn:     ASN of dest IP
        serverip:   same as dip
        servermac:  same as dmac
        serverport: same as dport
        servercc:   same as dipcc
        serverlat:  same as diplat
        serverlon:  same as diplon
        serverasn:  same as dipasn
        protocol:   text version of protocol in layer-3 header
        clientpackets:  counts of packets from client side
        clientbytes:    total bytes transferred from client side
        serverpackets:  counts of packets from server side
        serverbytes:    total bytes transferred from server side
        ts:         timestamp of first packet
        dt:         datetime of first packet
        starttime:  datetime of first packet
        endtime:    datetime of last packet
        client_state:   the TCP state on the client side ("init",
                        "established", "closed", etc.)
        server_state:   the TCP state on server side
        blobs:      list of reassembled half-stream Blobs
        stop:       if True, stop following connection
        handled:    used to indicate if a connection was already passed through
                    a plugin's connection_handler function. Resets when new
                    data for a connection comes in.

    """

    def __init__(self, plugin, first_packet):
        """
        Initializes Connection object

        Args:
            plugin:         an instance of the plugin creating this connection
            first_packet:   the first Packet object to initialize connection
        """
        self.plugin = plugin.name
        self.addr = first_packet.addr
        self.sip = first_packet.sip
        self.smac = first_packet.smac
        self.sport = first_packet.sport
        self.sipcc = first_packet.sipcc
        self.siplat = first_packet.siplat
        self.siplon = first_packet.siplon
        self.sipasn = first_packet.sipasn
        self.clientip = first_packet.sip
        self.clientmac = first_packet.smac
        self.clientport = first_packet.sport
        self.clientcc = first_packet.sipcc
        self.clientlat = first_packet.siplat
        self.clientlon = first_packet.siplon
        self.clientasn = first_packet.sipasn
        self.dip = first_packet.dip
        self.dmac = first_packet.dmac
        self.dport = first_packet.dport
        self.dipcc = first_packet.dipcc
        self.diplat = first_packet.diplat
        self.diplon = first_packet.diplon
        self.dipasn = first_packet.dipasn
        self.serverip = first_packet.dip
        self.servermac = first_packet.dmac
        self.serverport = first_packet.dport
        self.servercc = first_packet.dipcc
        self.serverlat = first_packet.diplat
        self.serverlon = first_packet.diplon
        self.serverasn = first_packet.dipasn
        self.protocol = first_packet.protocol
        self.clientpackets = 0
        self.clientbytes = 0
        self.serverpackets = 0
        self.serverbytes = 0
        self.ts = first_packet.ts
        self.dt = first_packet.dt
        self.starttime = first_packet.dt
        self.endtime = first_packet.dt
        self.client_state = None
        self.server_state = None
        self.blobs = []
        self.stop = False
        self.handled = False
        # used to determine if direction changes
        self._current_addr_pair = None

    @property
    def duration(self):
        "total seconds from starttime to endtime"
        tdelta = self.endtime - self.starttime
        return tdelta.total_seconds()

    @property
    def connection_closed(self):
        return self.client_state == "closed" and self.server_state == "closed"

    def add_packet(self, packet):
        """
        Accepts a Packet object and attempts to push it into the current Blob.
        If the direction changes, it creates a new Blob and returns the old one
        to the caller.

        Args:
            packet: a Packet object to add to the connection

        Returns:
            Previous Blob if direction has changed
        """
        if packet.sip == self.clientip and (not packet.sport or packet.sport == self.clientport):
            # packet moving from client to server
            direction = 'cs'
        else:
            # packet moving from server to client
            direction = 'sc'

        if (packet.addr != self._current_addr_pair and packet.data) or len(self.blobs) == 0:
            try:
                old_blob = self.blobs[-1]
            except IndexError:
                old_blob = None
            self.blobs.append(Blob(packet, direction))
            self._current_addr_pair = packet.addr
        else:
            old_blob = None

        blob = self.blobs[-1]
        blob.add_packet(packet)

        # Only count packets if they have data (i.e. ignore SYNs, ACKs, etc.)
        if packet.data:
            if packet.addr == self.addr:
                self.clientpackets += 1
                self.clientbytes += packet.byte_count
            else:
                self.serverpackets += 1
                self.serverbytes += packet.byte_count

        if packet.dt > self.endtime:
            self.endtime = packet.dt

        if old_blob:
            return old_blob

    def info(self):
        """
        Provides a dictionary with information about a connection. Useful for
        calls to a plugin's write() function, e.g. self.write(\\*\\*conn.info())

        Returns:
            Dictionary with information
        """
        d = dict(self.__dict__)
        d['duration'] = self.duration
        del d['blobs']
        del d['stop']
        del d['_current_addr_pair']
        del d['handled']
        return d

    def __repr__(self):
        return '%s  %16s -> %16s  (%s -> %s)  %6s  %6s %5d  %5d  %7d  %7d  %-.4fs' % (
            self.starttime,
            self.clientip,
            self.serverip,
            self.clientcc,
            self.servercc,
            self.clientport,
            self.serverport,
            self.clientpackets,
            self.serverpackets,
            self.clientbytes,
            self.serverbytes,
            self.duration,
        )

class Blob(object):
    """
    Class for holding and reassembling pieces of a connection.

    A Blob holds the packets and reassembled data for traffic moving in one
    direction in a connection, before direction changes.

    def __init__(self, first_packet, direction)

    Args:
        first_packet:   the first Packet object to initialize Blob
        direction:      direction of blob -
                        'cs' for client-to-server, 'sc' for sever-to-client

    Attributes:
        addr:       .addr attribute of the first packet
        ts:         timestamp of the first packet
        starttime:  datetime for first packet
        endtime:    datetime of last packet
        sip:        source IP
        smac:       source MAC address
        sport:      source port
        sipcc:      country code of source IP
        sipasn:     ASN of source IP
        dip:        dest IP
        dmac:       dest MAC address
        dport:      dest port
        dipcc:      country code of dest IP
        dipasn:     ASN of dest IP
        protocol:   text version of protocol in layer-3 header
        direction:  direction of the blob -
                    'cs' for client-to-server, 'sc' for sever-to-client
        ack_sequence_numbers: set of ACK numbers from the receiver for ####################################
                              collected data packets
        all_packets:    list of all packets in the blob
        hidden (bool):  Used to indicate that a Blob should not be passed to
                    next plugin. Can theoretically be overruled in, say, a
                    connection_handler to force a Blob to be passed to next
                    plugin.
    """

    # max offset before wrap, default is MAXINT32 for TCP sequence numbers
    MAX_OFFSET = 0xffffffff

    def __init__(self, first_packet, direction):
        self.addr = first_packet.addr
        self.ts = first_packet.ts
        self.starttime = first_packet.dt
        self.endtime = first_packet.dt
        self.sip = first_packet.sip
        self.smac = first_packet.smac
        self.sport = first_packet.sport
        self.sipcc = first_packet.sipcc
        self.sipasn = first_packet.sipasn
        self.dip = first_packet.dip
        self.dmac = first_packet.dmac
        self.dport = first_packet.dport
        self.dipcc = first_packet.dipcc
        self.dipasn = first_packet.dipasn
        self.protocol = first_packet.protocol
        self.direction = direction
#        self.ack_sequence_numbers = {}
        self.all_packets = []
#        self.data_packets = []
        self.__data_bytes = b''

        # Used to indicate that a Blob should not be passed to next plugin.
        # Can theoretically be overruled in, say, a connection_handler to
        # force a Blob to be passed to next plugin.
        self.hidden = False

    @property
    def data(self):
        """
        Returns the reassembled byte string.

        If it was not already reassembled, reassemble is called with default
        arguments.
        """
        if not self.__data_bytes:
            self.reassemble()
        return self.__data_bytes

    def reassemble(self, allow_padding=True, allow_overlap=True, padding=b'\x00'):
        """
        Rebuild the data string from the current list of data packets
        For each packet, the TCP sequence number is checked.

        If overlapping or padding is disallowed, it will raise a
        SequenceNumberError exception if a respective event occurs.

        Args:
            allow_padding (bool):   If data is missing and allow_padding = True
                                    (default: True), then the padding argument
                                    will be used to fill the gaps.
            allow_overlap (bool):   If data is overlapping, the new data is
                                    used if the allow_overlap argument is True
                                    (default). Otherwise, the earliest data is
                                    kept.
            padding:    Byte character(s) to use to fill in missing data. Used
                        in conjunction with allow_padding (default: b'\\\\x00')
        """
        data = b""
        unacknowledged_data = []
        acknowledged_data = {}
        for pkt in self.all_packets:
            if not pkt.sequence_number:
                # if there are no sequence numbers (i.e. not TCP), just rebuild
                # in chronological order
                data += pkt.data
                continue

            if pkt.data:
                if pkt.sequence_number in acknowledged_data:
                    continue
                unacknowledged_data.append(pkt)

            elif pkt.tcp_flags and pkt.tcp_flags & tcp.TH_ACK:
                ackpkt = pkt
                for i, datapkt in enumerate(unacknowledged_data):
                    if (datapkt.ack_number == ackpkt.sequence_number
                        and ackpkt.ack_number == (datapkt.sequence_number + len(datapkt.data))):
                        # if the seq/ack numbers align, this is the data packet
                        # we want
                        # TODO confirm this logic is correct
                        acknowledged_data[datapkt.sequence_number] = datapkt.data
                        unacknowledged_data.pop(i)
                        break

        if not acknowledged_data and not unacknowledged_data:
            # For non-sequential protocols, just return what we have
            self.__data_bytes = data

        else:
            # Create a list of each segment of the complete data. Use
            # acknowledged data first, and then try to fill in the blanks with
            # unacknowledged data.
            segments = acknowledged_data.copy()
            for pkt in reversed(unacknowledged_data):
                if pkt.sequence_number in segments: continue
                segments[pkt.sequence_number] = pkt.data

            offsets = sorted(segments.keys())
            # iterate over the segments and try to piece them together
            # handle any instances of missing or overlapping segments
            nextoffset = offsets[0]
            startoffset = offsets[0]
            for offset in offsets:
                if offset > nextoffset:
                    # data is missing
                    if allow_padding:
                        data += padding * (offset - nextoffset)
                    else:
                        raise SequenceNumberError("Missing data for sequence number %d %s" % (nextoffset, self.addr))
                elif offset < nextoffset:
                    # data is overlapping
                    if not allow_overlap:
                        raise SequenceNumberError("Overlapping data for sequence number %d %s" % (nextoffset, self.addr))

                nextoffset = (offset + len(segments[offset])) & self.MAX_OFFSET
                data = data[:offset - startoffset] + \
                       segments[offset] + \
                       data[nextoffset - startoffset:]
            self.__data_bytes = data

        return data




#        segments = {}
#        for pkt in self.data_packets:
#            if pkt.sequence_number:
#                segments.setdefault(pkt.sequence_number, []).append(pkt.data)
#            else:
#                # if there are no sequence numbers (i.e. not TCP), just rebuild
#                # in chronological order
#                data += pkt.data
#
#        if not segments:
#            # For non-sequential protocols, just return what we have
#            self.__data_bytes = data
#            return data
#
#        offsets = sorted(segments.keys())
#
#        # iterate over the segments and try to piece them together
#        # handle any instances of missing or overlapping segments
#        nextoffset = offsets[0]
#        startoffset = offsets[0]
#        for offset in offsets:
#            # TODO do we still want to implement custom error handling?
#            if offset > nextoffset:
#                # data is missing
#                if allow_padding:
#                    data += padding * (offset - nextoffset)
#                else:
#                    raise SequenceNumberError("Missing data for sequence number %d %s" % (nextoffset, self.addr))
#            elif offset < nextoffset:
#                # data is overlapping
#                if not allow_overlap:
#                    raise SequenceNumberError("Overlapping data for sequence number %d %s" % (nextoffset, self.addr))
##            nextoffset = (offset + len(segments[offset][dup])) & self.MAX_OFFSET
##            if nextoffset in self.ack_sequence_numbers:
#            if offset in self.ack_sequence_numbers:
#                # If the data packet was acknowledged by the receiver,
#                # we use the first packet received.
#                dup = 0
#            else:
#                # If it went unacknowledged, we use the last packet and hope
#                # for the best.
#                dup = -1
#            print(dup)
#            print(offset)
#            print(nextoffset)
#            print(str(self.ack_sequence_numbers))
#            nextoffset = (offset + len(segments[offset][dup])) & self.MAX_OFFSET
#            data = data[:offset - startoffset] + \
#                   segments[offset][dup] + \
#                   data[nextoffset - startoffset:]
#        self.__data_bytes = data
#        return data

    def info(self):
        """
        Provides a dictionary with information about a blob. Useful for
        calls to a plugin's write() function, e.g. self.write(\\*\\*conn.info())

        Returns:
            Dictionary with information
        """
        d = dict(self.__dict__)
        del d['hidden']
        del d['_Blob__data_bytes']
        del d['all_packets']
        return d

    def add_packet(self, packet):
        """
        Accepts a Packet object and stores it.

        Args:
            packet: a Packet object
        """
        self.all_packets.append(packet)

        if packet.dt > self.endtime:
            self.endtime = packet.dt
