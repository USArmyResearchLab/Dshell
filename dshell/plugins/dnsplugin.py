"""
This is a base-level plugin intended to handle DNS lookups and responses

It inherits from the base ConnectionPlugin and provides a new handler
function: dns_handler(conn, requests, responses)

It automatically pairs request/response packets by ID and passes them to the
handler for a custom plugin, such as dns.py, to use.
"""

import logging

import dshell.core as dshell

from pypacker.pypacker import dns_name_decode
from pypacker.layer567 import dns

logger = logging.getLogger(__name__)


def basic_cname_decode(request, answer):
    """
    DIRTY HACK ALERT

    This function exists to convert DNS CNAME responses into human-readable
    strings. pypacker cannot currently convert these, so this one attempts
    to do it. However, it is not complete and will only work for the most
    common situations (i.e. no pointers, or pointers that only point to the
    first request).

    Feed it the bytes (query.name) of the first request and the bytes for the
    answer (answer.address) with a CNAME, and it will return the parsed string.
    """

    if b"\xc0" not in answer:
        # short-circuit if there is no pointer
        return dns_name_decode(answer)
    # Get the offset into the question by grabbing the number after \xc0
    # Then, offset the offset by subtracting the query header length (12)
    snip_index = answer[answer.index(b"\xc0") + 1] - 12
    # Grab the necessary piece from the request
    snip = request[snip_index:]
    # Reassemble and return
    rebuilt = answer[:answer.index(b"\xc0")] + snip
    return dns_name_decode(rebuilt)


class DNSPlugin(dshell.ConnectionPlugin):
    """
    A base-level plugin that overwrites the connection_handler in
    ConnectionPlugin. It provides a new handler function: dns_handler.
    """

    def __init__(self, **kwargs):
        dshell.ConnectionPlugin.__init__(self, **kwargs)

    def connection_handler(self, conn):
        requests = {}
        responses = {}
        id_to_blob_map = {}
        id_to_packets_map = {}

        for blob in conn.blobs:
            for pkt in blob.packets:
                packet = pkt.pkt
                if not isinstance(packet.highest_layer, dns.DNS):
                    # First packet is not DNS, so we don't care
                    blob.hidden = True
                    break

                dnsp = packet.highest_layer
                id_to_blob_map.setdefault(dnsp.id, []).append(blob)
                id_to_packets_map.setdefault(dnsp.id, []).append(pkt)
                qr_flag = dnsp.flags >> 15
                rcode = dnsp.flags & 15
                setattr(pkt, 'qr', qr_flag)
                setattr(pkt, 'rcode', rcode)
#                print("{0:016b}".format(dnsp.flags))
                if qr_flag == dns.DNS_Q:
                    requests.setdefault(dnsp.id, []).append(pkt)
                elif qr_flag == dns.DNS_A:
                    responses.setdefault(dnsp.id, []).append(pkt)

        all_ids = set(list(requests.keys()) + list(responses.keys()))
        keep_connection = False
        for id in all_ids:
            request_list = requests.get(id, None)
            response_list = responses.get(id, None)
            dns_handler_out = self.dns_handler(conn, requests=request_list, responses=response_list)
            if not dns_handler_out:
                # remove packets from connections that dns_handler did not like
                for blob in id_to_blob_map[id]:
                    for pkt in id_to_packets_map[id]:
                        try:
                            blob.packets.remove(pkt)
                        except ValueError:
                            continue
            else:
                for blob in id_to_blob_map[id]:
                    blob.hidden = False
            try:
                if dns_handler_out and not isinstance(dns_handler_out[0], dshell.Connection):
                    logger.warning("The output from {} dns_handler must be a list with a dshell.Connection as the first element! Chaining plugins from here may not be possible.".format(self.name))
                    continue
            except TypeError:
                logger.warning("The output from {} dns_handler must be a list with a dshell.Connection as the first element! Chaining plugins from here may not be possible.".format(self.name))
                continue
            keep_connection = True
        if keep_connection:
            return conn

    def dns_handler(self, conn, requests, responses):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites
        on DNS data.

        It takes in a Connection, a list of requests (or None), and a list of
        responses (or None). The requests and responses are not intermixed;
        the responses in the list correspond to the requests according to ID.

        It should return a list containing the same types of values that came
        in as arguments (i.e. return (conn, requests, responses)). This is
        mostly a consistency thing, as only the Connection is passed along to
        other plugins.
        """
        return (conn, requests, responses)


DshellPlugin = None
