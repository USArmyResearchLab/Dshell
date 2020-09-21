"""
Proof-of-concept Dshell plugin to detect INNUENDO DNS Channel

Based on the short marketing video (http://vimeo.com/115206626) the
INNUENDO DNS Channel relies on DNS to communicate with an authoritative
name server. The name server will respond with a base64 encoded TXT
answer. This plugin will analyze DNS TXT queries and responses to
determine if it matches the network traffic described in the video.
There are multiple assumptions (*very poor*) in this detection plugin
but serves as a proof-of-concept detector. This detector has not been
tested against authentic INNUENDO DNS Channel traffic.
"""


from dshell.plugins.dnsplugin import DNSPlugin
from dshell.output.alertout import AlertOutput

from pypacker.layer567 import dns

import base64

class DshellPlugin(DNSPlugin):
    """
    Proof-of-concept Dshell plugin to detect INNUENDO DNS Channel

    Usage: decode -d innuendo *.pcap
    """

    def __init__(self):
        super().__init__(
            name="innuendo-dns",
            description="proof-of-concept detector for INNUENDO DNS channel",
            bpf="port 53",
            author="primalsec",
            output=AlertOutput(label=__name__),
        )

    def dns_handler(self, conn, requests, responses):
        response = responses[-1]

        query = None
        answers = []

        if requests:
            request = requests[-1].pkt.highest_layer
            query = request.queries[-1]
            # DNS Question, extract query name if it is a TXT record request
            if query.type == dns.DNS_TXT:
                query = query.name_s

        if responses:
            for response in responses:
                rcode = response.rcode
                response = response.pkt.highest_layer
                # DNS Answer with data and no errors
                if rcode == dns.DNS_RCODE_NOERR and response.answers:
                    for answer in response.answers:
                        if answer.type == dns.DNS_TXT:
                            answers.append(answer.address)

        if query and answers:
            # assumption: INNUENDO will use the lowest level domain for C2
            # example: AAAABBBBCCCC.foo.bar.com -> AAAABBBBCCCC is the INNUENDO
            # data
            subdomain = query.split('.', 1)[0]

            # weak test based on video observation *very poor assumption*
            if subdomain.isupper():
                # check each answer in the TXT response
                for answer in answers:
                    try:
                        # INNUENDO DNS channel base64 encodes the response, check to see if
                        # it contains a valid base64 string  *poor assumption*
                        dummy = base64.b64decode(answer)

                        self.write('INNUENDO DNS Channel', query, '/', answer, **conn.info())

                        # here would be a good place to decrypt the payload (if you have the keys)
                        # decrypt_payload( answer )
                    except:
                        return None
                return conn, requests, responses

        return None

