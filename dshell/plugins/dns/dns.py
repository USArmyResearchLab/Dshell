"""
Extracts and summarizes DNS queries and responses.
"""

import dshell.core
from dshell.plugins import dnsplugin
from dshell.output.alertout import AlertOutput

from pypacker.pypacker import dns_name_decode
from pypacker.layer567 import dns

import ipaddress

RESPONSE_ERRORS = {
    dns.DNS_RCODE_FORMERR: "FormErr",
    dns.DNS_RCODE_SERVFAIL: "ServFail",
    dns.DNS_RCODE_NXDOMAIN: "NXDOMAIN",
    dns.DNS_RCODE_NOTIMP: "NotImp",
    dns.DNS_RCODE_REFUSED: "Refused",
    dns.DNS_RCODE_YXDOMAIN: "YXDp,aom",
    dns.DNS_RCODE_YXRRSET: "YXRRSet",
    dns.DNS_RCODE_NXRRSET: "NXRRSet",
    dns.DNS_RCODE_NOTAUTH: "NotAuth",
    dns.DNS_RCODE_NOTZONE: "NotZone",
}

class DshellPlugin(dnsplugin.DNSPlugin):

    def __init__(self, *args, **kwargs):
        super().__init__(
            name="DNS",
            description="Extract and summarize DNS queries/responses",
            longdescription="""
The DNS plugin extracts and summarizes DNS queries and their responses. If
possible, each query is paired with its response(s).

Possible anomalies can be found using the --dns_show_noanswer,
--dns_only_noanswer, --dns_show_norequest, or --dns_only_norequest flags
(see --help).

For example, looking for responses that did not come from a request:
    decode -d dns --dns_only_norequest

Additional information for responses can be seen with --dns_country and
--dns_asn to show country codes and ASNs, respectively. These results can be
piped to grep for filtering results.

For example, to look for all traffic from Germany:
    decode -d dns --dns_country |grep "country: DE"

To look for non-US traffic, try:
    decode -d dns --dns_country |grep "country:" |grep -v "country: US"
""",
            author="bg/twp",
            bpf="udp and port 53",
            output=AlertOutput(label=__name__),
            optiondict={'show_noanswer': {'action': 'store_true', 'help': 'report unanswered queries alongside other queries'},
                        'show_norequest': {'action': 'store_true', 'help': 'report unsolicited responses alongside other responses'},
                        'only_noanswer': {'action': 'store_true', 'help': 'report only unanswered queries'},
                        'only_norequest': {'action': 'store_true', 'help': 'report only unsolicited responses'},
                        'country': {'action': 'store_true', 'help': 'show country code for returned IP addresses'},
                        'asn': {'action': 'store_true', 'help': 'show ASN for returned IP addresses'},
                    }
        )

    def premodule(self):
        if self.only_norequest:
            self.show_norequest = True
        if self.only_noanswer:
            self.show_noanswer = True


    def dns_handler(self, conn, requests, responses):
        if self.only_norequest and requests is not None:
            return
        if self.only_noanswer and responses is not None:
            return
        if not self.show_norequest and requests is None:
            return
        if not self.show_noanswer and responses is None:
            return

        msg = []

        # For simplicity, we focus only on the last request if there's more
        # than one.
        if requests:
            request_pkt = requests[-1]
            request = request_pkt.pkt.highest_layer
            id = request.id
            for query in request.queries:
                if query.type == dns.DNS_A:
                    msg.append("A? {}".format(query.name_s))
                elif query.type == dns.DNS_AAAA:
                    msg.append("AAAA? {}".format(query.name_s))
                elif query.type == dns.DNS_CNAME:
                    msg.append("CNAME? {}".format(query.name_s))
                elif query.type == dns.DNS_LOC:
                    msg.append("LOC? {}".format(query.name_s))
                elif query.type == dns.DNS_MX:
                    msg.append("MX? {}".format(query.name_s))
                elif query.type == dns.DNS_PTR:
                    msg.append("PTR? {}".format(query.name_s))
                elif query.type == dns.DNS_SRV:
                    msg.append("SRV? {}".format(query.name_s))
                elif query.type == dns.DNS_TXT:
                    msg.append("TXT? {}".format(query.name_s))
        else:
            request = None

        if responses:
            response_pkt = responses[-1]
            for response in responses:
                rcode = response.rcode
                response = response.pkt.highest_layer
                id = response.id
                # Check for errors in the response code
                err = RESPONSE_ERRORS.get(rcode, None)
                if err:
                    msg.append(err)
                    continue
                # Get the response counts
                msg.append("{}/{}/{}".format(response.answers_amount, response.authrr_amount, response.addrr_amount))
                # Parse the answers from the response
                for answer in response.answers:
                    if answer.type == dns.DNS_A or answer.type == dns.DNS_AAAA:
                        msg_fields = {}
                        msg_format = "A: {ip} (ttl {ttl}s)"
                        answer_ip = ipaddress.ip_address(answer.address)
                        msg_fields['ip'] = str(answer_ip)
                        msg_fields['ttl'] = str(answer.ttl)
                        if self.country:
                            msg_fields['country'] = dshell.core.geoip.geoip_country_lookup(msg_fields['ip']) or '--'
                            msg_format += " (country: {country})"
                        if self.asn:
                            msg_fields['asn'] = dshell.core.geoip.geoip_asn_lookup(msg_fields['ip'])
                            msg_format += " (ASN: {asn})"
                        msg.append(msg_format.format(**msg_fields))
                    # TODO pypacker doesn't really parse CNAMEs out. We try
                    #      to get what we can manually, but keep checking if
                    #      if it gets officially included in pypacker
                    elif answer.type == dns.DNS_CNAME:
                        if request:
                            cname = dnsplugin.basic_cname_decode(request.queries[0].name, answer.address)
                        else:
                            cname = dns_name_decode(answer.address)
                        msg.append('CNAME: {!r}'.format(cname))
                    elif answer.type == dns.DNS_LOC:
                        msg.append("LOC: {!s}".format(answer.address))
                    elif answer.type == dns.DNS_MX:
                        msg.append('MX: {!s}'.format(answer.address))
                    elif answer.type == dns.DNS_NS:
                        msg.append('NS: {!s}'.format(answer.address))
                    elif answer.type == dns.DNS_PTR:
                        ptr = dns_name_decode(answer.address)
                        msg.append('PTR: {!s}'.format(ptr))
                    elif answer.type == dns.DNS_SRV:
                        msg.append('SRV: {!s}'.format(answer.address))
                    elif answer.type == dns.DNS_TXT:
                        msg.append('TXT: {!s}'.format(answer.address))

        else:
            msg.append("No response")

        msg.insert(0, "ID: {}".format(id))
        msg = ", ".join(msg)
        if request:
            self.write(msg, **request_pkt.info())
        elif response:
            self.write(msg, **response_pkt.info())
        else:
            self.write(msg, **conn.info())

        return conn, requests, responses
