"""
Identifies DNS queries and finds the country code of the record response.
"""

import dshell.core
from dshell.plugins import dnsplugin
from dshell.output.alertout import AlertOutput

from pypacker.pypacker import dns_name_decode
from pypacker.layer567 import dns

import ipaddress

class DshellPlugin(dnsplugin.DNSPlugin):

    def __init__(self, *args, **kwargs):
        super().__init__(
            name="DNS Country Code",
            description="identify country code of DNS A/AAAA record responses",
            bpf="port 53",
            author="bg",
            output=AlertOutput(label=__name__),
            optiondict={
                'foreign': {
                    'action': 'store_true',
                    'help': 'report responses in non-US countries'
                },
                'code': {
                    'type': str,
                    'help': 'filter on a specific country code (ex. US, DE, JP, etc.)'
                }
            }
        )

    def dns_handler(self, conn, requests, responses):
        "pull out the A/AAAA queries from the last DNS request in a connection"
        queries = []
        if requests:
            request = requests[-1].pkt.highest_layer
            id = request.id
            for query in request.queries:
                if query.type == dns.DNS_A:
                    queries.append("A? {}".format(query.name_s))
                elif query.type == dns.DNS_AAAA:
                    queries.append("AAAA? {}".format(query.name_s))
        queries = ', '.join(queries)

        answers = []
        if responses:
            for response in responses:
                response = response.pkt.highest_layer
                id = response.id
                for answer in response.answers:
                    if answer.type == dns.DNS_A:
                        ip = ipaddress.ip_address(answer.address).compressed
                        cc = dshell.core.geoip.geoip_country_lookup(ip) or '--'
                        if self.foreign and (cc == 'US' or cc == '--'):
                            continue
                        elif self.code and cc != self.code:
                            continue
                        answers.append("A: {} ({}) (ttl: {}s)".format(
                            ip, cc, answer.ttl))
                    elif answer.type == dns.DNS_AAAA:
                        ip = ipaddress.ip_address(answer.address).compressed
                        if ip == '::':
                            cc = '--'
                        else:
                            cc = dshell.core.geoip.geoip_country_lookup(ip) or '--'
                        if self.foreign and (cc == 'US' or cc == '--'):
                            continue
                        elif self.code and cc != self.code:
                            continue
                        answers.append("AAAA: {} ({}) (ttl: {}s)".format(
                            ip, cc, answer.ttl))
        answers = ', '.join(answers)

        if answers:
            msg = "ID: {}, {} / {}".format(id, queries, answers)
            self.write(msg, queries=queries, answers=answers, **conn.info())
            return conn, requests, responses
        else:
            return


