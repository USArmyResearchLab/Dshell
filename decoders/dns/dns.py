import dpkt
import socket
from dnsdecoder import DNSDecoder


class DshellDecoder(DNSDecoder):

    def __init__(self):
        DNSDecoder.__init__(self,
                            name='dns',
                            description='extract and summarize DNS queries/responses (defaults: A,AAAA,CNAME,PTR records)',
                            filter='(udp and port 53)',
                            author='bg/twp',
                            optiondict={'show_noanswer': {'action': 'store_true', 'help': 'report unanswered queries alongside other queries'},
                                        'show_norequest': {'action': 'store_true', 'help': 'report unsolicited responses alongside other responses'},
                                        'only_noanswer': {'action': 'store_true', 'help': 'report only unanswered queries'},
                                        'only_norequest': {'action': 'store_true', 'help': 'report only unsolicited responses'},
                                        'showall': {'action': 'store_true', 'help': 'show all answered queries/responses'}}
                            )

    def decode_q(self, dns):
        queried = ""
        if dns.qd[0].type == dpkt.dns.DNS_A:
            queried = queried + "A? %s" % (dns.qd[0].name)
        if dns.qd[0].type == dpkt.dns.DNS_CNAME:
            queried = queried + "CNAME? %s" % (dns.qd[0].name)
        if dns.qd[0].type == dpkt.dns.DNS_AAAA:
            queried = queried + "AAAA? %s" % (dns.qd[0].name)
        if dns.qd[0].type == dpkt.dns.DNS_PTR:
            if dns.qd[0].name.endswith('.in-addr.arpa'):
                query_name = '.'.join(
                    reversed(dns.qd[0].name.split('.in-addr.arpa')[0].split('.')))
            else:
                query_name = dns.qd[0].name
            queried = queried + "PTR? %s" % (query_name)

        if not self.showall:
            return queried

        if dns.qd[0].type == dpkt.dns.DNS_NS:
            queried = queried + "NS? %s" % (dns.qd[0].name)
        if dns.qd[0].type == dpkt.dns.DNS_MX:
            queried = queried + "MX? %s" % (dns.qd[0].name)
        if dns.qd[0].type == dpkt.dns.DNS_TXT:
            queried = queried + "TXT? %s" % (dns.qd[0].name)
        if dns.qd[0].type == dpkt.dns.DNS_SRV:
            queried = queried + "SRV? %s" % (dns.qd[0].name)

        return queried

    def DNSHandler(self, conn, request, response, **kwargs):
        if self.only_norequest and request is not None:
            return
        if not self.show_norequest and request is None:
            return
        anstext = ''
        queried = ''
        id = None
        for dns in request, response:
            if dns is None:
                continue
            id = dns.id
            # DNS Question, update connection info with query
            if dns.qr == dpkt.dns.DNS_Q:
                conn.info(query=self.decode_q(dns))

            # DNS Answer with data and no errors
            elif (dns.qr == dpkt.dns.DNS_A and dns.rcode == dpkt.dns.DNS_RCODE_NOERR and len(dns.an) > 0):

                queried = self.decode_q(dns)

                answers = []
                for an in dns.an:
                    if an.type == dpkt.dns.DNS_A:
                        try:
                            answers.append(
                                'A: %s (ttl %ss)' % (socket.inet_ntoa(an.ip), str(an.ttl)))
                        except:
                            continue
                    elif an.type == dpkt.dns.DNS_AAAA:
                        try:
                            answers.append('AAAA: %s (ttl %ss)' % (
                                socket.inet_ntop(socket.AF_INET6, an.ip6), str(an.ttl)))
                        except:
                            continue
                    elif an.type == dpkt.dns.DNS_CNAME:
                        answers.append('CNAME: ' + an.cname)
                    elif an.type == dpkt.dns.DNS_PTR:
                        answers.append('PTR: ' + an.ptrname)
                    elif an.type == dpkt.dns.DNS_NS:
                        answers.append('NS: ' + an.nsname)
                    elif an.type == dpkt.dns.DNS_MX:
                        answers.append('MX: ' + an.mxname)
                    elif an.type == dpkt.dns.DNS_TXT:
                        answers.append('TXT: ' + ' '.join(an.text))
                    elif an.type == dpkt.dns.DNS_SRV:
                        answers.append('SRV: ' + an.srvname)
                    else:
                        # un-handled type
                        continue
                if queried != '':
                    anstext = ", ".join(answers)

            #NXDOMAIN in response
            elif dns.qr == dpkt.dns.DNS_A and dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN:
                queried = self.decode_q(dns)  # decode query part

                if queried != '':
                    anstext = 'NXDOMAIN'

        # did we get an answer?
        if anstext and not self.only_noanswer and not self.only_norequest:
            self.alert(
                str(id) + ' ' + queried + ' / ' + anstext, **conn.info(response=anstext))
        elif not anstext and (self.show_noanswer or self.only_noanswer):
            self.alert(
                str(id) + ' ' + conn.query + ' / (no answer)', **conn.info())

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
