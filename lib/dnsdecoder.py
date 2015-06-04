#!/usr/bin/env python

import dshell
import util
import dpkt


class DNSDecoder(dshell.TCPDecoder):

    '''extend DNSDecoder to handle DNS request/responses
            pairs request and response(s) by connection and query ID
            to allow for detection of DNS spoofing, etc.. (multiple responses to request with same ID)
            will call DNSHandler(
                                                            conn=Connection(),
                                                            request=dpkt.dns.DNS,
                                                            response=dpkt.dns.DNS,
                                                            requesttime=timestamp, responsetime=timestamp,
                                                            responsecount=responsecount
                                                    )
            after each response.

            config: noanswer: if True and discarding w/o response, will call with response,responsetime=None,None (True)

    '''

    def __init__(self, **kwargs):
        self.noanswer = True
        dshell.TCPDecoder.__init__(self, **kwargs)  # DNS is over UDP and TCP!
        self.requests = {}
        self.maxblobs = None

    def packetHandler(self,udp,data):
	'''for each UDP packet , examine each segment (UDP packet) seperately as each will be a DNS Q/A
                pair Q/A by ID and return as pairs'''
	addr=udp.addr
	if addr[0][1] < addr[1][1]: addr=addr[1],addr[0] #swap ports if source port is lower, to keep tuple (client,server)
	connrqs = self.requests.setdefault(addr, {})
	try:
		dns = dpkt.dns.DNS(data)
	except Exception, e:
		self._exc(e)
	if dns.qr == dpkt.dns.DNS_Q: 
		connrqs[dns.id] = [udp.ts, dns, 0]
	elif dns.qr == dpkt.dns.DNS_A:
                rq = connrqs.get(dns.id, [None, None, 0])
                rq[2] += 1
                if "DNSHandler" in dir(self):
                    self.DNSHandler(conn=udp, request=rq[1], response=dns, requesttime=rq[0],
                                    responsetime=udp.ts, responsecount=rq[2])
	
    def blobHandler(self, conn, blob):
        '''for each blob, examine each segment (UDP packet) seperately as each will be a DNS Q/A
                pair Q/A by ID and return as pairs'''
        connrqs = self.requests.setdefault(conn, {})
        # iterate blob as each packet will be a seperate request (catches spoofing)
        for data in blob:
            try:
                dns = dpkt.dns.DNS(data)
            except Exception, e:
                self._exc(e)
                continue
            if dns.qr == dpkt.dns.DNS_Q:
                connrqs[dns.id] = [blob.starttime, dns, 0]
            elif dns.qr == dpkt.dns.DNS_A:
                rq = connrqs.get(dns.id, [None, None, 0])
                rq[2] += 1
                if "DNSHandler" in dir(self):
                    self.DNSHandler(conn=conn, request=rq[1], response=dns, requesttime=rq[0],
                                    responsetime=blob.starttime, responsecount=rq[2])

    def connectionHandler(self,conn):
        '''clean up unanswered requests when we discard the connection'''
	if self.noanswer and "DNSHandler" in dir(self) and self.requests.get(conn):
		for requesttime, request, responsecount in self.requests[conn].values():
			if not responsecount:
				if type(conn) is tuple: conn=dshell.Packet(self,conn) #wrap UDP addresses
				self.DNSHandler(conn=conn, request=request, response=None,
						requesttime=requesttime, responsetime=None, responsecount=responsecount)
	if conn in self.requests:
		del self.requests[conn]

    def postModule(self):
	'''flush out all remaining request state when module exits'''
	for conn in self.requests.keys():
		self.connectionHandler(conn)


class displaystub(dshell.Decoder):

    def __init__(self):
        dshell.Decoder.__init__(self,
                                name='dnsdecoder',
                                description='Intermediate class to support DNS based decoders.',
                                longdescription="See source code or pydoc for details on use."
                                )

if __name__ == '__main__':
    dObj = displaystub()
    print dObj
else:  # do we always want to print something here? Maybe only in debug mode?:
    dObj = displaystub()
