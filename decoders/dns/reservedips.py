import dshell
import dpkt
import socket
from dnsdecoder import DNSDecoder
import IPy


class DshellDecoder(DNSDecoder):

    def __init__(self):
        DNSDecoder.__init__(self,
                            name='reservedips',
                            description='identify DNS resolutions that fall into reserved ip space',
                            filter='(port 53)',
                            author='bg',
                            cleanupinterval=10,
                            maxblobs=2,
                            )

        # source: https://en.wikipedia.org/wiki/Reserved_IP_addresses
        nets = ['0.0.0.0/8',  # Used for broadcast messages to the current ("this") network as specified by RFC 1700, page 4.
                # Used for local communications within a private network as
                # specified by RFC 1918.
                '10.0.0.0/8',
                # Used for communications between a service provider and its
                # subscribers when using a Carrier-grade NAT, as specified by
                # RFC 6598.
                '100.64.0.0/10',
                # Used for loopback addresses to the local host, as specified
                # by RFC 990.
                '127.0.0.0/8',
                # Used for autoconfiguration between two hosts on a single
                # link when no IP address is otherwise specified
                '169.254.0.0/16',
                # Used for local communications within a private network as
                # specified by RFC 1918
                '172.16.0.0/12',
                # Used for the DS-Lite transition mechanism as specified by
                # RFC 6333
                '192.0.0.0/29',
                # Assigned as "TEST-NET" in RFC 5737 for use solely in
                # documentation and example source code and should not be used
                # publicly
                '192.0.2.0/24',
                # Used by 6to4 anycast relays as specified by RFC 3068
                '192.88.99.0/24',
                # Used for local communications within a private network as
                # specified by RFC 1918
                '192.168.0.0/16',
                # Used for testing of inter-network communications between two
                # separate subnets as specified in RFC 2544
                '198.18.0.0/15',
                # Assigned as "TEST-NET-2" in RFC 5737 for use solely in
                # documentation and example source code and should not be used
                # publicly
                '198.51.100.0/24',
                # Assigned as "TEST-NET-3" in RFC 5737 for use solely in
                # documentation and example source code and should not be used
                # publicly
                '203.0.113.0/24',
                # Reserved for multicast assignments as specified in RFC 5771
                '224.0.0.0/4',
                # Reserved for future use, as specified by RFC 6890
                '240.0.0.0/4',
                # Reserved for the "limited broadcast" destination address, as
                # specified by RFC 6890
                '255.255.255.255/32',

                '::/128',  # Unspecified address
                '::1/128',  # loopback address to the local host.
                '::ffff:0:0/96',  # IPv4 mapped addresses
                '100::/64',  # Discard Prefix RFC 6666
                '64:ff9b::/96',  # IPv4/IPv6 translation (RFC 6052)
                '2001::/32',  # Teredo tunneling
                # Overlay Routable Cryptographic Hash Identifiers (ORCHID)
                '2001:10::/28',
                '2001:db8::/32',  # Addresses used in documentation
                '2002::/16',  # 6to4
                'fc00::/7',  # Unique local address
                'fe80::/10',  # Link-local address
                'ff00::/8',  # Multicast
                ]

        self.reservednets = []
        for net in nets:
            self.reservednets.append(IPy.IP(net))
        self.domains = []       # list for known domains

    def inReservedSpace(self, ipaddress):
        for net in self.reservednets:
            if ipaddress in net:
                return True
        return False

    def decode_q(self, dns):
        queried = ""
        if dns.qd[0].type == dpkt.dns.DNS_A:
            queried = queried + "A? %s" % (dns.qd[0].name)
        if dns.qd[0].type == dpkt.dns.DNS_AAAA:
            queried = queried + "AAAA? %s" % (dns.qd[0].name)
        return queried

    def DNSHandler(self, conn, request, response, **kwargs):
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
                            if self.inReservedSpace(socket.inet_ntoa(an.ip)):
                                answers.append(
                                    'A: ' + socket.inet_ntoa(an.ip) + ' (ttl ' + str(an.ttl) + 's)')
                        except:
                            continue
                    elif an.type == dpkt.dns.DNS_AAAA:
                        try:
                            if self.inReservedSpace(socket.inet_ntop(socket.AF_INET6, an.ip6)):
                                answers.append(
                                    'AAAA: ' + socket.inet_ntop(socket.AF_INET6, an.ip6) + ' (ttl ' + str(an.ttl) + 's)')
                        except:
                            continue
                    else:
                        # un-handled type
                        continue
                if queried != '':
                    anstext = ", ".join(answers)

        if anstext:  # did we get an answer?
            self.alert(
                str(id) + ' ' + queried + ' / ' + anstext, **conn.info(response=anstext))


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
