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
import heapq
import inspect
import logging
import warnings
from collections import defaultdict
from multiprocessing import Value
from typing import Iterable, List, Tuple, Union

# Dshell imports
from dshell.output.output import Output
from dshell.dshellgeoip import DshellGeoIP, DshellFailedGeoIP

# third-party imports
import pcapy
from pypacker import pypacker
from pypacker.layer12 import can, ethernet, ieee80211, linuxcc, ppp, pppoe, radiotap
from pypacker.layer3 import ip, ip6, icmp, icmp6
from pypacker.layer4 import tcp, udp


logger = logging.getLogger(__name__)

__version__ = "3.2.1"

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
    geoip = DshellGeoIP()
except FileNotFoundError:
    logger.warning(
        "Could not find GeoIP data files! Country and ASN lookups will not be possible. Check README for instructions on where to find and install necessary data files.")
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
    logger.error(
        "The {!s} for the {!r} plugin raised an exception and failed! ({}: {!s})".format(
            handler, plugin.name, etype, e))
    logger.debug(e, exc_info=True)


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
        compiled_bpf:   a compiled BPF for pcapy, usually created in decode.py
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
        link_layer_type:    numeric label for link layer
        defrag_ip:      rebuild fragmented IP packets (default: True)
    """

    # TODO: Move attributes like name, author, and description to be class attributes instead of instance.
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', __name__)
        self.description = kwargs.get('description', '')
        self.longdescription = kwargs.get('longdescription', self.description)
        self.bpf = kwargs.get('bpf', '')
        self.compiled_bpf = kwargs.get('compiled_bpf', None)
        self.vlan_bpf = kwargs.get("vlan_bpf", True)
        self.author = kwargs.get('author', '')
        self.logger = logging.getLogger(inspect.getmodule(self).__name__)

        # define overall counts as multiprocessing Values for --parallel
        self.seen_packet_count = Value('i', 0)
        self.handled_packet_count = Value('i', 0)

        # dict of options specific to this plugin in format
        #       'optname':{configdict} translates to --pluginname_optname
        self.optiondict = kwargs.get('optiondict', {})

        # queues used by decode.py
        # if a handler decides a packet is worth keeping, it is placed in a
        # queue and later grabbed by decode.py to pass to subplugins
        self._packet_queue = []

        # self.out holds the output plugin instance
        # can be overwritten in decode.py by user selection
        self.out = kwargs.get('output', Output())

        # capture options
        # these can be updated with set_link_layer_type function
        self.link_layer_type = 1  # assume Ethernet
        # rebuild fragmented IP packets
        self.defrag_ip = True

        # holder for the pcap file being processing
        self.current_pcap_file = None

        # a holder for IP packet fragments when attempting to reassemble them
        self._packet_fragments = defaultdict(dict)

    def produce_packets(self) -> Iterable["Packet"]:
        """
        Produces packets ready to be processed by the next plugin in the chain.
        """
        while self._packet_queue:
            yield self._packet_queue.pop(0)

    def flush(self):
        """
        Triggers plugin to finish processing any remaining packets that are being held onto.
        """
        # By default we don't need to do anything because any consumed packet is placed onto the queue
        # right away.
        pass

    def purge(self):
        """
        When finished with handling a pcap file, calling this will clear all
        caches in preparation for next file.
        """
        self._packet_queue = []
        self._packet_fragments = defaultdict(dict)

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
        """
        Logs msg argument at specified level
        (default of INFO is for -v/--verbose output)

        Arguments:
            msg:        text string to log
            level:      logging level (default: logging.INFO)
        """
        warnings.warn("log() function is deprecated. Please use logging library instead.", DeprecationWarning)
        logger.log(level, msg)

    def debug(self, msg):
        """
        Logs msg argument at debug level
        """
        warnings.warn("debug() function is deprecated. Please use logging library instead.", DeprecationWarning)
        logger.debug(msg)

    def warn(self, msg):
        """
        Logs msg argument at warning level
        """
        warnings.warn("warn() function is deprecated. Please use logging library instead.", DeprecationWarning)
        logger.warning(msg)

    def error(self, msg):
        """
        Logs msg argument at error level.
        """
        warnings.warn("error() function is deprecated. Please use logging library instead.", DeprecationWarning)
        logger.warning(msg)

    def __str__(self):
        return "<{}: {}>".format("Plugin", self.name)

    def __repr__(self):
        return '<{}: {}/{}/{}>'.format("Plugin", self.name, self.bpf,
                             ','.join([('%s=%s' % (x, str(self.__dict__.get(x)))) for x in self.optiondict]))

    # TODO: Perhaps make bpf a property which auto-triggers this when the property value is set.
    def recompile_bpf(self):
        """
        Compile the BPF stored in the .bpf attribute
        """
        # This function is normally only called by the decode.py script,
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
        logger.debug("Compiling BPF as {!r}".format(bpf))

        # Compile BPF and handle any expected errors
        try:
            self.compiled_bpf = pcapy.compile(
                self.link_layer_type, 65536, bpf, True, 0xffffffff
            )
        except pcapy.PcapError as e:
            if str(e).startswith("no VLAN support for data link type"):
                logger.error("Cannot use VLAN filters for {!r} plugin. Recommend running with --no-vlan argument.".format(self.name))
            elif str(e) == "syntax error":
                raise ValueError("Fatal error when compiling BPF: {!r}".format(bpf))
            else:
                raise e

    def ipdefrag(self, packet: 'Packet') -> 'Packet':
        """
        IP fragment reassembly

        Store the first seen packet, collect data from followup packets, then
        glue it all together and update that first packet with new data
        """
        pkt = packet.pkt
        ipp = pkt.upper_layer
        if isinstance(ipp, ip.IP):  # IPv4
            f = self._packet_fragments[(ipp.src, ipp.dst, ipp.id)]
            f[ipp.offset] = packet

            if not ipp.flags & 0x1: # If no more fragments (MF)
                if len(f) <= 1 and 0 in f:
                    # If only one unfragmented packet, return that packet
                    del self._packet_fragments[(ipp.src, ipp.dst, ipp.id)]
                    return f[0]
                elif 0 not in f:
                    logger.debug(f"Missing first fragment of fragmented packet. Dropping ({packet.sip} -> {packet.dip}: {ipp.id}:{ipp.flags}:{ipp.offset})")
                    del self._packet_fragments[(ipp.src, ipp.dst, ipp.id)]
                    return None
                fkeys = sorted(f.keys())
                data = b''
                firstpacket = f[fkeys[0]]
                for key in fkeys:
                    data += f[key].pkt.upper_layer.body_bytes
                newip = ip.IP(firstpacket.pkt.upper_layer.header_bytes + data)
                newip.bin(update_auto_fields=True) # refresh checksum
                firstpacket.pkt.upper_layer = newip
                del self._packet_fragments[(ipp.src, ipp.dst, ipp.id)]
                return Packet(
                    firstpacket.pkt.__len__,
                    firstpacket.pkt,
                    firstpacket.ts,
                    firstpacket.frame
                )

        elif isinstance(pkt, ip6.IP6):  # IPv6
            # TODO handle IPv6 offsets https://en.wikipedia.org/wiki/IPv6_packet#Fragment
            return pkt

    def handle_plugin_options(self):
        """
        A placeholder.

        This function is called immediately after plugin args are processed
        and set in decode.py. A plugin can overwrite this function to perform
        actions based on the arg values as soon as they are set, before
        decode.py does any further processing (e.g. updating a BPF based on
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
        logger.info(
            f"{self.seen_packet_count.value} seen packets, "
            f"{self.handled_packet_count.value} handled packets "
        )

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
        logger.info('working on file "{}"'.format(infile))

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

    def filter(self, packet) -> bool:
        """
        Determines if plugin accepts the packet or it should be filtered out.

        :param packet: dshell.Packet object
        :return:
        """
        # By default we filter by running the compiled bpf, but a plugin can
        # inherit this to do extra stuff if desired.
        if not self.compiled_bpf:
            return True
        return bool(self.compiled_bpf.filter(packet.rawpkt))

    # NOTE: This was originally called '_packet_handler'
    def consume_packet(self, packet: "Packet"):
        """
        Filters and defragments packet and then passes the packet along to the packet_handler()
        function to determine whether we should pass the packet(s) along to the next plugin.
        """
        # First apply filter to packet.
        if not self.filter(packet):
            return

        with self.seen_packet_count.get_lock():
            self.seen_packet_count.value += 1

        # Attempt to perform defragmentation
        if self.defrag_ip and isinstance(packet.pkt.upper_layer, (ip.IP, ip6.IP6)):
            defragpkt = self.ipdefrag(packet)
            if not defragpkt:
                # we do not yet have all of the packet fragments, so move
                # on to next packet for now
                return
            else:
                packet = defragpkt

        # call packet_handler and return its output
        # decode.py will continue down the chain if it returns anything
        try:
            packet_handler_out = self.packet_handler(packet)
        except Exception as e:
            print_handler_exception(e, self, 'packet_handler')
            return
        failed_msg = (
            f"The output from {self.name} packet_handler must be of type dshell.Packet or a list of "
            f"such objects! Handling connections or chaining from this plugin may not be possible."
        )
        if isinstance(packet_handler_out, (list, tuple)):
            for phout in packet_handler_out:
                if isinstance(phout, Packet):
                    self._packet_queue.append(phout)
                    with self.handled_packet_count.get_lock():
                        self.handled_packet_count.value += 1
                elif phout:
                    logger.warning(failed_msg)
        elif isinstance(packet_handler_out, Packet):
            self._packet_queue.append(packet_handler_out)
            with self.handled_packet_count.get_lock():
                self.handled_packet_count.value += 1
        elif packet_handler_out:
            logger.warning(failed_msg)

    def packet_handler(self, pkt: "Packet"):
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

    # Determines whether to filter out packets based on blobs or to produce packets directly.
    # Turning this off if the plugin doesn't mark any blobs as hidden can help improve speed.
    # TODO: There is another hacky reason this boolean exists.
    #   Due to how we modified the blob creation code, the ACK and handshake methods are not
    #   part of any of the blobs. Therefore, when the produce_packets() function is called, those
    #   packets are missing if we are only producing the packets within a blob.
    blob_filtering = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # similar to packet_queue and raw_packet_queue in superclass
        self._connection_queue = []
        # Flag used to determine if we are ready to produce closed connections
        # for the next plugin in the chain.
        self._production_ready = True

        # dictionary to store packets for connections according to addr()
        # NOTE: Only currently unhandled (ie. open) connections are stored here.
        self._connection_tracker = {}

        # define overall counts as multiprocessing Values for --parallel
        self.seen_conn_count = Value('i', 0)
        self.handled_conn_count = Value('i', 0)

        # maximum number of blobs a connection will store before calling
        # connection_handler
        # it defaults to infinite, but this should be lowered for huge datasets
        self.maxblobs = float("inf")  # infinite

        # how long do we wait before deciding a connection is "finished"
        # time is checked by iterating over cached connections and checking if
        # the timestamp of the connection's last packet is older than the
        # timestamp of the current packet, minus this value
        self.timeout = datetime.timedelta(hours=1)
        # The number of packets to process between timeout checks.
        self.timeout_frequency = 300
        # The maximum number of open connections allowed at one time.
        # If the maximum number of connections is met, the oldest connections
        # will be force closed.
        self.max_open_connections = 1000

    def _postmodule(self):
        """
        Overwriting _postmodule to add log info about connection counts.
        """
        super()._postmodule()
        logger.info(
            f"{self.seen_conn_count.value} seen connections, "
            f"{self.handled_conn_count.value} handled connections"
        )

    def produce_connections(self) -> Iterable["Connection"]:
        """
        Produces recently closed connections ready to be passed down to the next plugin in the chain.
        """
        # Avoid producing connections if we are still waiting for an older connection to close.
        # This helps to ensure connections are produced in the right order.... for the most part.
        if not self._production_ready:
            return
        while self._connection_queue:
            # Pop off oldest closed connection.
            _, full, connection = heapq.heappop(self._connection_queue)
            # Handle connection
            success = self._handle_connection(connection, full=full)
            if not success or connection.stop:
                continue
            # Pass along connection to next plugin.
            yield connection
        self._production_ready = False

    def produce_packets(self) -> Iterable["Packet"]:
        """
        Produces packets ready to be processed by the next plugin in the chain.
        """
        # Produce connections
        for connection in self.produce_connections():
            if self.blob_filtering:
                for blob in connection.blobs:
                    if not blob.hidden:
                        yield from blob.packets
            else:
                # TODO: Perhaps have a "hidden" field on the packet itself?
                yield from connection.packets

    def consume_packet(self, packet: "Packet"):
        # First run super() to handle the individual packets.
        super().consume_packet(packet)

        # Now process any produced packets to be processed through connection handler.
        for _packet in super().produce_packets():
            self._connection_handler(_packet)

    def flush(self):
        """
        Triggers plugin to finish processing any remaining packets that are being held onto.
        """
        super().flush()
        # Call cleanup_connections() to force close any remaining open connections so they are
        # on the queue ready to be passed down the chain.
        self._cleanup_connections()

    def _connection_handler(self, packet: "Packet"):
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
        addr = tuple(sorted(packet.addr))

        # If this is a new connection, initialize it and call the init handler
        if addr not in self._connection_tracker:
            conn = Connection(packet)
            self._connection_tracker[addr] = conn
            try:
                self.connection_init_handler(conn)
            except Exception as e:
                print_handler_exception(e, self, 'connection_init_handler')
                return
            with self.seen_conn_count.get_lock():
                self.seen_conn_count.value += 1
        else:
            conn = self._connection_tracker[addr]
            conn.add_packet(packet)

        # TODO: Do we need this? This flag is set to False when the connection is initialized and not
        #   set to true until it is closed.
        #   Is there any scenario where we would want to undo a True handled state?
        # # If connection data is about to change, we set it to a "dirty" state
        # # for future calls to connection_handler
        # if pkt.data:
        #     conn.handled = False

        if conn.closed:
            # Both sides have closed the connection, process blobs (messages) and
            # close connection.
            for blob in conn.blobs:
                self._blob_handler(conn, blob)
            self._close_connection(conn, full=True)

        # TODO: Switch to a max_packets option.
        # elif len(conn.blobs) > self.maxblobs:
        #     # Max blobs hit, so we will run connection_handler and decode.py
        #     # will clear the connection's blob cache
        #     self._close_connection(conn)

        # Check for and close old connections every so often.
        if self.handled_packet_count.value % self.timeout_frequency == 0:
            self._timeout_connections(packet.dt)

    def _close_connection(self, conn, full=False):
        """
        Runs through some standard actions to close a connection
        """
        # Add connection to queue ready to be processed, based on order they were received on the wire.
        heapq.heappush(self._connection_queue, (conn.packets[0].frame, full, conn))

        # Remove connection from tracker once in the queue.
        try:
            del self._connection_tracker[tuple(sorted(conn.addr))]
        except KeyError:
            pass

    def _handle_connection(self, conn: "Connection", full=False) -> bool:
        """
        Handles produced connections.

        :returns: True if connection was handled successfully.
        """
        try:
            connection_handler_out = self.connection_handler(conn)
        except Exception as e:
            print_handler_exception(e, self, 'connection_handler')
            return False
        conn.handled = True

        # TODO: Perhaps connection_handler() just returns a True or False indicating success?
        if connection_handler_out and not isinstance(connection_handler_out, Connection):
            logger.warning(
                "The output from {} connection_handler must be of type dshell.Connection! Chaining plugins from here may not be possible.".format(
                    self.name))
            connection_handler_out = None

        if not connection_handler_out:
            return False

        with self.handled_conn_count.get_lock():
            self.handled_conn_count.value += 1

        if full:
            try:
                self.connection_close_handler(conn)
            except Exception as e:
                print_handler_exception(e, self, 'connection_close_handler')
        return True

    def _timeout_connections(self, timestamp: datetime.datetime):
        """
        Checks for and force closes connections that have been alive for too long.
        It also closes the oldest connections if too many connections are open.
        """
        # Force close any connections that have timed out.
        # This is based on comparing the time of the current packet, minus
        # self.timeout, to each connection's current endtime value.
        for conn in list(self._connection_tracker.values()):
            if conn.endtime < (timestamp - self.timeout):
                self._close_connection(conn)

        # Force close oldest connections if we have too many.
        if len(self._connection_tracker) > self.max_open_connections:
            connections = sorted(self._connection_tracker.values(), key=lambda conn: conn.endtime, reverse=True)
            for conn in connections[self.max_open_connections:]:
                self._close_connection(conn)

        # We can produce connections again, now that we have handled lingering old connections.
        self._production_ready = True

    def _cleanup_connections(self):
        """
        decode.py will often reach the end of packet capture before all of the
        connections are closed properly. This function is called at the end
        of things to process those dangling connections.

        NOTE: Because the connections did not close cleanly,
        connection_close_handler will not be called.
        """
        for conn in list(self._connection_tracker.values()):
            if not conn.handled:
                self._close_connection(conn)
        self._production_ready = True

    def purge(self):
        """
        When finished with handling a pcap file, calling this will clear all
        caches in preparation for next file.
        """
        super().purge()
        self._connection_queue = []
        self._connection_tracker = {}
        self._production_ready = False

    # TODO: Have blobs handled with consumer/producer model just like Packets and Connections?
    def _blob_handler(self, conn: "Connection", blob: "Blob"):
        """
        Accepts a Connection and a Blob.

        It doesn't really do anything except call the blob_handler and is only
        here for consistency and possible future features.
        """
        try:
            blob_handler_out = self.blob_handler(conn, blob)
        except Exception as e:
            print_handler_exception(e, self, 'blob_handler')
            blob_handler_out = None
        if blob_handler_out:
            connection, blob = blob_handler_out
            if not isinstance(connection, Connection) or not isinstance(blob, Blob):
                logger.warning(
                    "The output from {} blob_handler must be of type (dshell.Connection, dshell.Blob)! Chaining plugins from here may not be possible.".format(
                        self.name))
                blob_handler_out = None
        if not blob_handler_out:
            blob.hidden = True

    def blob_handler(self, conn: "Connection", blob: "Blob"):
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

    def connection_init_handler(self, conn: "Connection"):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites on
        a connection it is first seen.

        Args:
            conn: Connection object
        """
        return

    def connection_handler(self, conn: "Connection"):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites on
        Connection data.

        It should return a Connection object for functions further down the chain

        Args:
            conn: Connection object
        """
        return conn

    def connection_close_handler(self, conn: "Connection"):
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
        pktlen:     length of packet
        pkt:        pypacker object for the packet
        ts:         timestamp of packet

    Attributes:
        ts:         timestamp of packet
        dt:         datetime of packet
        frame:      sequential packet number as read from data stream
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

    IP_PROTOCOL_MAP = dict((v, k[9:]) for k, v in ip.__dict__.items() if
                           type(v) == int and k.startswith('IP_PROTO_') and k != 'IP_PROTO_HOPOPTS')

    def __init__(self, pktlen, packet: pypacker.Packet, timestamp: int, frame=0):
        # TODO: Use full variable names.
        self.ts = timestamp
        self.dt = datetime.datetime.fromtimestamp(timestamp)
        self.frame = frame
        self.pkt = packet
        self.pktlen = pktlen  # TODO: Is this needed?

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
        self.sequence_number = None
        self.ack_number = None
        self.tcp_flags = None

        # attribute cache
        self._byte_count = None
        self._data = None

        # these are the layers Dshell will help parse
        # try to find them in the packet and eventually pull out useful data
        ethernet_p = None
        ieee80211_p = None
        ip_p = None
        tcp_p = None
        udp_p = None
        highest_layer = None
        for layer in packet:
            highest_layer = layer
            if ethernet_p is None and isinstance(layer, ethernet.Ethernet):
                ethernet_p = layer
            elif ieee80211_p is None and isinstance(layer, ieee80211.IEEE80211):
                ieee80211_p = layer
            elif ip_p is None and isinstance(layer, (ip.IP, ip6.IP6)):
                ip_p = layer
                if ip_p.flags & 0x1 and ip_p.offset > 0:
                    # IP fragmentation, break all further layer processing
                    break
            elif tcp_p is None and isinstance(layer, tcp.TCP):
                tcp_p = layer
            elif udp_p is None and isinstance(layer, udp.UDP):
                udp_p = layer
        self._highest_layer = highest_layer
        self._ethernet_layer = ethernet_p     # type: ethernet.Ethernet
        self._ieee80211_layer = ieee80211_p   # type: ieee80211.IEEE80211
        self._ip_layer = ip_p                 # type: Union[ip.IP, ip6.IP6]
        self._tcp_layer = tcp_p               # type: tcp.TCP
        self._udp_layer = udp_p               # type: udp.UDP

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
            self.sip = ip_p.src_s
            self.dip = ip_p.dst_s
            self.sip_bytes = ip_p.src
            self.dip_bytes = ip_p.dst

            # get protocols, country codes, and ASNs
            self.protocol_num = ip_p.p if isinstance(ip_p, ip.IP) else ip_p.nxt
            self.protocol = self.IP_PROTOCOL_MAP.get(self.protocol_num, str(self.protocol_num))
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

        elif udp_p:
            self.sport = udp_p.sport
            self.dport = udp_p.dport

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
            return (self.sip, self.sport), (self.dip, self.dport)
        # then try MAC addresses
        elif self.smac or self.dmac:
            return (self.smac, self.sport), (self.dmac, self.dport)
        # if all else fails, return Nones
        else:
            return (None, None), (None, None)

    @property
    def byte_count(self) -> int:
        """
        Total number of payload bytes in the packet.
        """
        if self._byte_count is None:
            self._byte_count = len(self.data)
        return self._byte_count

    @property
    def packet_tuple(self):
        """
        A standard representation of the raw packet tuple:
        (self.pktlen, self.rawpkt, self.ts)
        """
        return self.pktlen, self.rawpkt, self.ts

    @property
    def rawpkt(self):
        """
        The raw data that represents the full packet.
        """
        return self.pkt.bin()

    @property
    def data(self):
        """
        Retrieve data bytes from TCP/UDP data layer. Backtracks to data from highest layer.
        """
        if self._data is None:
            # NOTE: Using cached layers because pypacker's __getitem__ is slow.
            # best_layer = self.pkt[tcp.TCP] or self.pkt[udp.UDP] or self.pkt.highest_layer
            best_layer = self._tcp_layer or self._udp_layer or self._highest_layer

            # Pypacker doesn't handle Ethernet trailers correctly, so we need to
            # do some header calculation in order to determine the true body_bytes size.
            ip_layer = self._ip_layer
            tcp_layer = self._tcp_layer
            if ip_layer and tcp_layer:
                if isinstance(ip_layer, ip.IP):  # IPv4
                    data_size = ip_layer.len - (ip_layer.header_len + tcp_layer.header_len)
                    self._data = best_layer.body_bytes[:data_size]
                else:  # IPv6
                    # TODO handle extension headers
                    data_size = ip_layer.dlen - tcp_layer.header_len
                    self._data = best_layer.body_bytes[:data_size]
            else:
                self._data = best_layer.body_bytes

        return self._data

    @data.setter
    def data(self, data):
        """
        Sets data bytes to TCP/UDP data layer. Backtracks to setting data at highest layer.
        """
        # NOTE: Using cached layers because pypacker's __getitem__ is slow.
        # best_layer = self.pkt[tcp.TCP] or self.pkt[udp.UDP] or self.pkt.highest_layer
        best_layer = self._tcp_layer or self._udp_layer or self._highest_layer

        # Pypacker doesn't handle Ethernet trailers correctly, so we need to
        # do some header calculation in order to determine the true body_bytes size.
        ip_layer = self._ip_layer
        tcp_layer = self._tcp_layer
        if ip_layer and tcp_layer:
            if isinstance(ip_layer, ip.IP):  # IPv4
                data_size = ip_layer.len - (ip_layer.header_len + tcp_layer.header_len)
                best_layer.body_bytes = data + best_layer.body_bytes[data_size:]
            else:  # IPv6
                # TODO handle extension headers
                data_size = ip_layer.dlen - tcp_layer.header_len
                best_layer.body_bytes = data + best_layer.body_bytes[data_size:]
        else:
            best_layer.body_bytes = data

        self._data = data
        # TODO: Rebuild packet object to allow for pypacker to do its thing.

    def __repr__(self):
        return "%s  %16s :%-5s -> %5s :%-5s (%s -> %s)" % (
            self.dt, self.sip, self.sport, self.dip, self.dport, self.sipcc, self.dipcc)

    def info(self):
        """
        Provides a dictionary with information about a packet. Useful for
        calls to a plugin's write() function, e.g. self.write(\\*\\*pkt.info())
        """
        d = {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
        d['byte_count'] = self.byte_count
        d['rawpkt'] = self.pkt.bin()
        del d['pkt']
        return d


class Connection(object):
    """
    Class for holding data about connections

    def __init__(self, plugin, first_packet)

    Args:
        first_packet:   the first Packet object to initialize connection

    Attributes:
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

    # status
    # NOTE: Using strings instead of int enum to stay backwards compatible.
    INIT = "init"
    ESTABLISHED = "established"
    FINISHING = "finishing"
    CLOSED = "closed"

    def __init__(self, first_packet):
        """
        Initializes Connection object

        Args:
            first_packet:   the first Packet object to initialize connection
        """
        self.addr = first_packet.addr
        # TODO: Rename these variables to something more verbose like "source_ip"
        #   I keep getting confused whether the "s" stands for "source" or "server".
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
        self.ts = first_packet.ts
        self.dt = first_packet.dt
        self.starttime = first_packet.dt
        self.endtime = first_packet.dt
        self.client_state = None
        self.server_state = None
        # self.blobs = []
        self.packets = []  # keeps track of packets in connection.
        self.stop = False
        self.handled = False

        self.add_packet(first_packet)

    @property
    def duration(self):
        """
        Total seconds from start_time to end_time.
        """
        tdelta = self.endtime - self.starttime
        return tdelta.total_seconds()

    @property
    def closed(self):
        return self.client_state == self.CLOSED and self.server_state == self.CLOSED

    @property
    def established(self):
        return self.client_state == self.ESTABLISHED and self.server_state == self.ESTABLISHED

    @property
    def blobs(self) -> Iterable["Blob"]:
        """
        Iterates the blobs (or messages) contained in this tcp connection

        This is dynamically generated on-demand based on the current set of packets in the connection.
        """
        blobs = []

        for packet in self.packets:
            # TODO: skipping packets without data greatly improves speed, but we may want to
            #   allow them if we support using ack numbers.
            if not packet.data:
                continue

            # If we see a sequence for an old blob, this is a retransmission.
            # Find the blob and add this packet.
            # NOTE: There is probably more to it than this, but this seems to work for now.
            seq = packet.sequence_number
            if seq is not None:
                found = False
                for blob in blobs:
                    if blob.sip == packet.sip and seq in blob.sequence_range:
                        blob.add_packet(packet)
                        found = True
                        break
                if found:
                    continue

            # Create a new message if the first or the other direction has started sending data.
            if not blobs or (packet.sip != blobs[-1].sip and packet.data):
                blobs.append(Blob(self, packet))

            # Otherwise add packet to last blob.
            else:
                blobs[-1].add_packet(packet)

        yield from blobs

    def add_packet(self, packet: Packet):
        """
        Adds packet to connection.

        :param packet: a Packet object to add to the connection
        """
        if packet.sip not in (self.sip, self.dip):
            raise ValueError(f"Address {repr(packet.sip)} is not part of connection.")

        self.packets.append(packet)

        # Adjust state if packet is part of a startup or shutdown.
        if packet.tcp_flags is not None:
            # Acknowledging a completed handshake to open connection.
            if packet.tcp_flags == (tcp.TH_SYN | tcp.TH_ACK):
                self.server_state = self.ESTABLISHED
                self.client_state = self.ESTABLISHED

            # Asking to close connection.
            elif packet.tcp_flags & (tcp.TH_FIN | tcp.TH_RST):
                if packet.sip == self.serverip:
                    self.server_state = self.FINISHING
                else:
                    self.client_state = self.FINISHING

            # Closing connection acknowledged.
            elif packet.tcp_flags & tcp.TH_ACK:
                if packet.dip == self.serverip and self.server_state == self.FINISHING:
                    self.server_state = self.CLOSED
                elif packet.dip == self.clientip and self.client_state == self.FINISHING:
                    self.client_state = self.CLOSED

        if packet.dt > self.endtime:
            self.endtime = packet.dt

    def info(self):
        """
        Provides a dictionary with information about a connection. Useful for
        calls to a plugin's write() function, e.g. self.write(\\*\\*conn.info())

        Returns:
            Dictionary with information
        """
        d = {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
        d['duration'] = self.duration
        d['clientbytes'] = self.clientbytes
        d['clientpackets'] = self.clientpackets
        d['serverbytes'] = self.serverbytes
        d['serverpackets'] = self.serverpackets
        del d['stop']
        del d['handled']
        del d['packets']
        return d

    def _client_packets(self) -> Iterable[Packet]:
        for packet in self.packets:
            if packet.addr == self.addr:
                yield packet

    def _server_packets(self) -> Iterable[Packet]:
        for packet in self.packets:
            if packet.addr != self.addr:
                yield packet

    @property
    def clientbytes(self) -> int:
        """
        The total number of bytes form the client.
        """
        return sum(packet.byte_count for packet in self._client_packets())

    @property
    def clientpackets(self) -> int:
        """
        The total number of packets from the client.
        """
        # (Only counting packets with data.)
        return sum(bool(packet.byte_count) for packet in self._client_packets())

    @property
    def serverbytes(self) -> int:
        """
        The total number of bytes form the server.
        """
        return sum(packet.byte_count for packet in self._server_packets())

    @property
    def serverpackets(self) -> int:
        """
        The total number of packets from the server.
        """
        # (Only counting packets with data.)
        return sum(bool(packet.byte_count) for packet in self._server_packets())

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


# TODO: Rename this "TCPBlob" and then have a more generic "Blob" class it inherits from.
class Blob(object):
    """
    Class for holding and reassembling pieces of a connection.

    A Blob holds the packets and reassembled data for traffic moving in one
    direction in a connection, before direction changes.

    def __init__(self, first_packet, direction)

    Args:
        connection:     The Connection object that this Blob comes from. (Used for validating packets.)
        first_packet:   the first Packet object to initialize Blob

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
                    'cs' for client-to-server, 'sc' for server-to-client
        ack_sequence_numbers: set of ACK numbers from the receiver for ####################################
                              collected data packets
        packets:    list of all packets in the blob
        hidden (bool):  Used to indicate that a Blob should not be passed to
                    next plugin. Can theoretically be overruled in, say, a
                    connection_handler to force a Blob to be passed to next
                    plugin.
    """

    # max offset before wrap, default is MAXINT32 for TCP sequence numbers
    MAX_OFFSET = 0xffffffff

    CLIENT_TO_SERVER = 'cs'
    SERVER_TO_CLIENT = 'sc'

    def __init__(self, connection: Connection, first_packet):
        self.connection = connection
        self.addr = first_packet.addr
        self.ts = first_packet.ts
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
        #        self.ack_sequence_numbers = {}
        self.packets = []
        #        self.data_packets = []
        self.__data_bytes = b''

        # Used for data caching
        self._data = None
        self._segments = None

        # Maps sequence number with packets
        self._seq_map = {}

        # Used to indicate that a Blob should not be passed to next plugin.
        # Can theoretically be overruled in, say, a connection_handler to
        # force a Blob to be passed to next plugin.
        self.hidden = False

        if self.sip == self.connection.clientip and \
                (not self.sport or self.sport == self.connection.clientport):
            # packet moving from client to server
            self.direction = self.CLIENT_TO_SERVER
        else:
            # packet moving from server to client
            self.direction = self.SERVER_TO_CLIENT

        self.add_packet(first_packet)

    @property
    def all_packets(self):
        warnings.warn("all_packets has been replaced with packets attribute", DeprecationWarning)
        return self.packets

    @property
    def starttime(self):
        return min(packet.dt for packet in self.packets)

    @property
    def start_time(self):
        return self.starttime

    @property
    def endtime(self):
        return max(packet.dt for packet in self.packets)

    @property
    def end_time(self):
        return self.endtime

    @property
    def frames(self) -> List[int]:
        """
        The frame identifiers for the packets which contain the message.
        """
        return [packet.frame for packet in self.packets]

    def get_packets(self, start, end=None) -> List["Packet"]:
        """
        Returns the packets that contain data for the given start offset up to the end offset.
        If end offset is not provided, just the packet containing the start offset is provided.
        """
        packets = []

        # TODO: Double check logic on this.

        # If not a TCP connection, return frames that had data.
        if self.packets[0].tcp_flags is None:
            offset = 0
            for packet in self.packets:
                if not packet.data:
                    continue

                offset += len(packet.data)
                if offset > start:
                    packets.append(packet)
                    if end is None or offset >= end:
                        break

        # Otherwise, base offsets on sequence numbers.
        else:
            initial_seq = None
            for seq, packet in self.segments:
                if initial_seq is None:
                    initial_seq = seq
                offset = seq - initial_seq
                end_offset = offset + len(packet.data)
                if end_offset > start:
                    packets.append(packet)
                    if end is None or end_offset >= end:
                        break

        return packets

    def get_frames(self, start, end=None) -> List[int]:
        """
        Returns frame identifiers for the packets that contain data for the given start offset
        up to the end offset.
        If end offset is not provided, just the frame identifier for the packet containing the
        start offset is provided.
        """
        return [packet.frame for packet in self.get_packets(start, end=end)]

    @property
    def sequence_numbers(self) -> List[int]:
        """
        The starting sequence numbers found within the packets.
        """
        return list(self._seq_map.keys())

    @property
    def sequence_range(self) -> range:
        """
        The range of sequence numbers found within the packets.
        """
        sequence_numbers = self.sequence_numbers
        if not sequence_numbers:
            return range(0, 0)

        min_seq = min(sequence_numbers)
        max_seq = max(sequence_numbers)
        return range(min_seq, max_seq + len(self._seq_map[max_seq].data))

    @property
    def segments(self) -> List[Tuple[int, "Packet"]]:
        """
        List of valid (sequence number, packet) tuples in order by sequence number.
        """
        if self._segments is not None:
            return self._segments

        segments = []
        # Iterate through segments, ignoring segments that cause overlap in data.
        expected_seq = None
        prev_packet = None
        for seq, packet in sorted(self._seq_map.items()):
            if expected_seq is None:
                expected_seq = seq

            # If the sequence is greater than or equal to the expected sequence, this segment is valid.
            if seq >= expected_seq:
                segments.append((seq, packet))
                missing_num_bytes = seq - expected_seq
                if missing_num_bytes:
                    logger.debug(
                        f"Missing {missing_num_bytes} bytes of data between packets "
                        f"{prev_packet and prev_packet.frame} and {packet.frame}"
                    )
                expected_seq += missing_num_bytes + len(packet.data)
                prev_packet = packet

            # TODO: Support rollover sequence numbers.
            # Otherwise, we have some overlap in data and need to remove the invalid segment/packet
            # and ignoring adding it to the segments list.
            else:
                logger.debug(f"Packet {packet.frame} contains overlapped data. Removing...")
                self._remove_packet(packet)

        self._segments = segments  # cache for next time.
        return segments

    @property
    def data(self):
        """
        Raw data of tcp message.
        """
        # Return cache if set.
        if self._data is not None:
            return self._data

        # If not a TCP connection, just join packet data as they arrived on the wire.
        # TODO: Move this logic to a base class.
        if self.packets[0].tcp_flags is None:
            return b''.join(packet.data for packet in self.packets)

        # Join packet data based on segment data.
        data = bytearray()  # using bytearray to improve speed.
        initial_seq = None
        for seq, packet in self.segments:
            if initial_seq is None:
                initial_seq = seq

            # Check if we have missing packets.
            if seq - initial_seq != len(data):
                # buffer data with null bytes
                data += b'\x00' * (seq - initial_seq - len(data))

            data += packet.data
        data = bytes(data)

        self._data = data  # set cache
        return data

    @data.setter
    def data(self, data):
        """
        Replaces message data with new data.

        WARNING: Currently, data must match original length.
        """
        # TODO: Support different amount of bytes by adding packets or padding/removing packets.
        orig_len = len(self.data)
        if len(data) != orig_len:
            raise ValueError(
                f'Message data must be of the same length as original. '
                f'Expected {orig_len} bytes, got {len(data)} bytes.')

        # If not a TCP connection, just add data to packets in same order they arrived on wire.
        if self.packets[0].tcp_flags is None:
            written_bytes = 0
            for packet in self.packets:
                packet.data = data[written_bytes : written_bytes + len(packet.data)]
                written_bytes += len(packet.data)
            # Clear old cache.
            self._data = None
            return

        # If TCP connection, add data based on sequence numbers.
        written_bytes = 0
        initial_seq = None
        for seq, packet in self.segments:
            if initial_seq is None:
                initial_seq = seq

            relative_seq = seq - initial_seq
            if relative_seq < written_bytes:
                raise RuntimeError(
                    "Relative sequence is less then written byte count. "
                    "Sequence numbers have be miss-calculated."
                )
            # Skip holes in data. (User should have put padding in these areas)
            elif relative_seq != written_bytes:
                written_bytes = relative_seq

            packet.data = data[written_bytes:written_bytes + len(packet.data)]
            written_bytes += len(packet.data)

        # Clear old cache.
        self._data = None

    # TODO: Merge this in with the add_packet() logic, however I am unsure how using acknowledge numbers
    #   works if we are only looking at one side.
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
        for pkt in self.packets:
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
                        raise SequenceNumberError(
                            "Overlapping data for sequence number %d %s" % (nextoffset, self.addr))

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
        calls to a plugin's write() function, e.g. self.write(\\*\\*blob.info())

        Returns:
            Dictionary with information
        """
        d = {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
        del d['hidden']
        del d['packets']
        return d


    # TODO: Trying to determine if we should do this or take into account acknowledgement numbers
    #   like originally implemented.
    #   Perhaps rewrite their assemble to do some work in add_packet()?
    #   Do we want to ensure all segments are acknowledged or should we avoid that so we can handle
    #   partial/corrupt pcaps?
    def add_packet(self, packet):
        """
        Accepts a Packet object and stores it.

        Args:
            packet: a Packet object
        """
        # Clear old data and segment cache.
        self._data = None
        self._segments = None

        seq = packet.sequence_number

        # If packet is not TCP just add packet to list.
        if seq is None:
            self.packets.append(packet)
            return

        # If this a new sequence number we haven't seen before, add it to the map.
        if seq not in self._seq_map:
            self._seq_map[seq] = packet
            self.packets.append(packet)
            return

        # Otherwise, if we already have the packet for the given sequence
        # then we have a retransmission and will need to determine which packet to keep
        # and possibly remove other packets if this packet overlaps them.
        orig_packet = self._seq_map[seq]

        # ignore duplicate packet.
        if len(packet.data) <= len(orig_packet.data):
            # TODO: should we still handle duplicate packets.
            logger.debug(f'Ignoring duplicate packet: {packet.frame}')
            return

        # If this packet would create more inconsistencies in our sequence numbers (more holes)
        # than the packet to be replaced, then this is most likely an out-of-order packet that the
        # sender has ignored, and we should too.
        orig_next_seq = seq + len(orig_packet.data)
        next_seq = seq + len(packet.data)
        if (
            next_seq < max(self.sequence_numbers)
            and orig_packet.data
            and next_seq not in self._seq_map
            and orig_next_seq in self._seq_map
        ):
            logger.debug(f'Ignoring out-of-order packet: {packet.frame}')
            return

        # Replace packet(s) with retransmitted packet

        # First add the retransmitted packet, replacing the original packet matching the
        # sequence number.
        logger.debug(f'Replacing packet {orig_packet.frame} with {packet.frame}')
        self._seq_map[seq] = packet
        self.packets = [packet if p.sequence_number == seq else p for p in self.packets]

        # Now remove any packets that contained data that is now part of the retransmitted packet.
        packets_to_remove = []
        for seq_, packet_ in self._seq_map.items():
            if 0 < (seq_ - seq) < len(packet.data):
                logger.debug(f'Removing packet: {packet_.frame}')
                packets_to_remove.append(packet_)
        # NOTE: need to remove packets outside the above loop because removing packets affect seq_map
        for packet_ in packets_to_remove:
            self._remove_packet(packet_)

    def _remove_packet(self, packet):
        """
        Removes packet from Blob. (internal use only)
        """
        # Clear old data and segment cache.
        self._data = None
        self._segments = None

        for seq, packet_ in list(self._seq_map.items()):
            if packet_ == packet:
                del self._seq_map[seq]

        self.packets.remove(packet)
