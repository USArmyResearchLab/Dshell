from httpdecoder import HTTPDecoder
import urllib
from collections import defaultdict

'''
JPCERT Coordination Center (JPCERT/CC) released a series of capabilities to
detect and understand compromises involving the Emdivi HTTP bot.  Additional
references from JPCERT:

http://blog.jpcert.or.jp/2015/11/emdivi-and-the-rise-of-targeted-attacks-in-japan.html
https://github.com/JPCERTCC/aa-tools
https://github.com/JPCERTCC/aa-tools/blob/master/emdivi_postdata_decoder.py

The emdivi_c2 decoder is based on the hardwork of JPCERT/CC and thus deserve
all the credit.

LICENSE
Copyright (C) 2015 JPCERT Coordination Center. All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following acknowledgments and disclaimers.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following acknowledgments and disclaimers in
the documentation and/or other materials provided with the distribution.
3. Products derived from this software may not include "JPCERT Coordination
Center" in the name of such derived product, nor shall "JPCERT Coordination
Center"  be used to endorse or promote products derived from this software
without prior written permission. For written permission, please contact
pr@jpcret.or.jp.
'''


class DshellDecoder(HTTPDecoder):

    def __init__(self):
        HTTPDecoder.__init__(self,
                             name='emdivi_c2',
                             description='deobfuscate Emdivi http c2',
                             filter='tcp and port 80',
                             author='bg',
                             )

    def decode_payload(self, payload):
        '''logic from JPCERTCC emdivi_postdata_decoder.py'''

        decoded = defaultdict()

        if ';' in payload:
            delim = ';'
        else:
            delim = '&'

        fields = [x for x in payload.split(delim) if x]

        for field in fields:
            try:
                name, value = field.split('=')
            except ValueError:
                continue

            xor_key = 0x00
            for c in name:
                xor_key = (ord(c)) ^ xor_key

            plaintext = ''
            for c in urllib.unquote(value):
                plaintext += chr(ord(c) ^ xor_key)

            decoded[name] = plaintext
        return decoded

    def validate_payload(self, payload_dict):
        ''' attempt to validate Emdivi payload. if a valid payload is found,
            return the key associated with Emdivi version information '''
        # this check is very simple and will only validate payloads that content like:
        # ?VER: t20.09.Koitochu.8530.7965.4444 | NT: 5.1.2600.5512 [en-US] | MEM: 128M | GMT(-6)

        version_info_key = None
        for k in payload_dict:
            if 'GMT' in payload_dict[k]:
                version_info_key = k
                break

        return version_info_key

    def HTTPHandler(self, conn, request, response, requesttime, responsetime):
        if not request:
            return

        decoded = defaultdict()

        if request.method in ('GET', 'POST'):
            # first check the body of the GET or POST
            if len(request.body) > 0:
                decoded.update(self.decode_payload(request.body))

        if not decoded and 'cookie' in request.headers:
            # some traffic had encoded information
            # embedded within the Cookie header
            decoded.update(self.decode_payload(request.headers['cookie']))

        if decoded:
            version_info_key = self.validate_payload(decoded)

            if version_info_key:
                self.alert('{}'.format(decoded[version_info_key]), **conn.info())

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
