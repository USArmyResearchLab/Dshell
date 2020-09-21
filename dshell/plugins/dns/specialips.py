"""
Identifies DNS resolutions that fall into special IP spaces (i.e. private,
reserved, loopback, multicast, link-local, or unspecified).

When found, it will print an alert for the request/response pair. The alert
will include the type of special IP in parentheses:
    (loopback)
    (private)
    (reserved)
    (multicast)
    (link-local)
    (unspecified)
"""

from dshell.plugins import dnsplugin
from dshell.output.alertout import AlertOutput

from pypacker.layer567 import dns

import ipaddress


class DshellPlugin(dnsplugin.DNSPlugin):

    def __init__(self, *args, **kwargs):
        super().__init__(
            name="special-ips",
            description="identify DNS resolutions that fall into special IP (IPv4 and IPv6) spaces (i.e. private, reserved, loopback, multicast, link-local, or unspecified)",
            bpf="port 53",
            author="dev195",
            output=AlertOutput(label=__name__),
            longdescription="""
Identifies DNS resolutions that fall into special IP spaces (i.e. private,
reserved, loopback, multicast, link-local, or unspecified).

When found, it will print an alert for the request/response pair. The alert
will include the type of special IP in parentheses:
    (loopback)
    (private)
    (reserved)
    (multicast)
    (link-local)
    (unspecified)

For example, to look for responses with private IPs:
    Dshell> decode -d specialips ~/pcap/SkypeIRC.cap  |grep "(private)"
    [special-ips] 2006-08-25 15:31:06      192.168.1.2:2128  --      192.168.1.1:53    ** ID: 12579, A? voyager.home., A: 192.168.1.1 (private) (ttl 10000s) **

Finding can also be written to a separate pcap file by chaining:
    Dshell> decode -d specialips+pcapwriter --pcapwriter_outfile="special-dns.pcap" ~/pcap/example.pcap
""",
        )


    def dns_handler(self, conn, requests, responses):
        """
        Stores the DNS request, then iterates over responses looking for
        special IP addresses. If it finds one, it will print an alert for the
        request/response pair.
        """
        msg = []

        if requests:
            request_pkt = requests[-1]
            request = request_pkt.pkt.highest_layer
            id = request.id
            for query in request.queries:
                if query.type == dns.DNS_A:
                    msg.append("A? {}".format(query.name_s))
                elif query.type == dns.DNS_AAAA:
                    msg.append("AAAA? {}".format(query.name_s))


        if responses:
            keep_responses = False
            for response in responses:
                response = response.pkt.highest_layer
                for answer in response.answers:
                    if answer.type == dns.DNS_A or answer.type == dns.DNS_AAAA:
                        answer_ip = ipaddress.ip_address(answer.address)
                        msg_fields = {}
                        msg_format = "A: {ip} ({type}) (ttl {ttl}s)"
                        msg_fields['ip'] = str(answer_ip)
                        msg_fields['ttl'] = str(answer.ttl)
                        msg_fields['type'] = ''
                        if answer_ip.is_loopback:
                            msg_fields['type'] = 'loopback'
                            keep_responses = True
                        elif answer_ip.is_private:
                            msg_fields['type'] = 'private'
                            keep_responses = True
                        elif answer_ip.is_reserved:
                            msg_fields['type'] = 'reserved'
                            keep_responses = True
                        elif answer_ip.is_multicast:
                            msg_fields['type'] = 'multicast'
                            keep_responses = True
                        elif answer_ip.is_link_local:
                            msg_fields['type'] = 'link-local'
                            keep_responses = True
                        elif answer_ip.is_unspecified:
                            msg_fields['type'] = 'unspecified'
                            keep_responses = True
                        msg.append(msg_format.format(**msg_fields))
            if keep_responses:
                msg.insert(0, "ID: {}".format(id))
                msg = ", ".join(msg)
                self.write(msg, **conn.info())
                return conn, requests, responses

