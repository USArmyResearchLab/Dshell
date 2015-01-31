
try:
    import dshell
    import dpkt
    import socket
    from dnsdecoder import DNSDecoder
except ImportError as error:
    print("Import error. Could not find module: %s", error)

class DshellDecoder(DNSDecoder):
    def __init__(self):
        DNSDecoder.__init__(self,
                        name = 'dns-asn',
                        description = 'identify AS of DNS A/AAAA record responses',
                        filter = '(port 53)',
                        author = 'bg',
                        cleanupinterval=10,
                        maxblobs=2,
                        )

    def decode_q(self,dns):
        queried = ""
        if dns.qd[0].type == dpkt.dns.DNS_A:
            queried = queried + "A? %s" % (dns.qd[0].name)
        if dns.qd[0].type == dpkt.dns.DNS_AAAA:
            queried = queried + "AAAA? %s" % (dns.qd[0].name)
        return queried

    def DNSHandler(self,conn,request,response,**kwargs):
        anstext=''
        queried=''
        id=None
        for dns in request,response:
            if dns is None: continue
            id=dns.id
            #DNS Question, update connection info with query
            if dns.qr==dpkt.dns.DNS_Q: conn.info(query=self.decode_q(dns))

            # DNS Answer with data and no errors
            elif (dns.qr == dpkt.dns.DNS_A and dns.rcode == dpkt.dns.DNS_RCODE_NOERR and len(dns.an)>0):

                queried=self.decode_q(dns)

                answers = []
                for an in dns.an:
                    if an.type == dpkt.dns.DNS_A:
                        try:
                            cc = self.getASN( socket.inet_ntoa(an.ip) )
                            answers.append('A: %s (%s) (ttl %s)' % (socket.inet_ntoa(an.ip), cc, an.ttl) )
                        except: continue
                    elif an.type == dpkt.dns.DNS_AAAA:
                        try:
                            cc = self.getASN( socket.inet_ntop(socket.AF_INET6, an.ip6) )
                            answers.append('AAAA: %s (%s) (ttl %s)' % (socket.inet_ntop(socket.AF_INET6, an.ip6), cc, an.ttl) )
                        except: continue
                    else:
                        # un-handled type
                        continue
                if queried != '':
                    anstext =", ".join(answers)

        if anstext: #did we get an answer?
            self.alert(str(id)+' '+queried+' / '+anstext,**conn.info(response=anstext))



if __name__=='__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
