import dpkt
from dnsdecoder import DNSDecoder
import base64
import math

MIN_ENTROPY = 4.7

class DshellDecoder(DNSDecoder):
    """ 
    Proof-of-concept Dshell decoder to detect INNUENDO DNS Channel

	Added a more mathamatical check based on entropy in the domain name, it is
	set fairly low as a demonstration but you can move the 4.7 up to 5 or 6 in 
	real world noisy test and slide it down to something interesting.  That base64
	test is probably not very useful, see below. (added a commit comment)

	Based on the short marketing video [http://vimeo.com/115206626] the INNUENDO
	DNS Channel relies on DNS to communicate with an authoritative name server.
	The name server will respond with a base64 encoded TXT answer. This decoder
	will analyze DNS TXT queries and responses to determine if it matches the
	network traffic described in the video. There are multiple assumptions (*very
	poor*) in this detection plugin but serves as a proof-of-concept detector. This
	detector has not been tested against authentic INNUENDO DNS Channel traffic.  

	Usage: decode -d innuendo-dns *.pcap

    """
    def range_bytes():
	''' range '''
        return range(256)

    def entropy_score(data, iterator=range_bytes):
	''' simple entropy score'''
	if not data:
	    return 0
	entropy = 0
	for byte in iterator():
	    p_x = float(data.count(chr(byte)))/len(data)
	    if p_x > 0:
		entropy += - p_x*math.log(p_x, 2)
	return entropy


    def __init__(self):
        DNSDecoder.__init__(self,
                        name = 'innuendo-dns',
                        description = 'proof-of-concept detector for INNUENDO DNS channel',
                        filter = '(port 53)',
                        author = 'primalsec',
                        )
        self.whitelist = [] # probably be necessary to whitelist A/V domains

    def in_whitelist(self, domain): 
        # add logic
        return False

    def decrypt_payload(payload): pass

    def DNSHandler(self,conn,request,response,**kwargs):
        query = ''
        answers = []

        for dns in request,response:

            if dns is None: continue

            id = dns.id

            #DNS Question, extract query name if it is a TXT record request
            if dns.qr==dpkt.dns.DNS_Q and dns.qd[0].type == dpkt.dns.DNS_TXT: 
                query = dns.qd[0].name

            # DNS Answer with data and no errors
            elif (dns.qr == dpkt.dns.DNS_A and dns.rcode == dpkt.dns.DNS_RCODE_NOERR and len(dns.an)>0):

                for an in dns.an:
                    if an.type == dpkt.dns.DNS_TXT:
                        answers.append(an.text[0])

        if query != '' and len(answers)>0:
            # add check here to see if the second level domain and top level domain are not in a white list
            if self.in_whitelist(query): return

            # assumption: INNUENDO will use the lowest level domain for C2
            # example: AAAABBBBCCCC.foo.bar.com -> AAAABBBBCCCC is the INNUENDO data
            subdomain = query.split('.')[0]

            if subdomain.isupper(): # weak test based on video observation *very poor assumption*
                # check each answer in the TXT response
                for answer in answers:
                    try:
                        # INNUENDO DNS channel base64 encodes the response, check to see if 
                        # it contains a valid base64 string  *poor assumption*
                        dummy = base64.b64decode( answer )

                        self.alert('INNUENDO DNS Channel', query ,'/',answer,**conn.info())
			
			if entropy_score(answer) > MIN_ENTROPY:
			    self.alert('HIGH ENTROPY, possible DNS C2 score'+entropy_score(answer)[0:5],'/',answer,**conn.info())
   
                        # here would be a good place to decrypt the payload (if you have the keys)
                        # decrypt_payload( answer )
                    except: pass
            

if __name__=='__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()

