import urllib
import sys
import time
import socket
import struct
import datetime

# dShell Utility Functions


def xor(input, key):
    """
    Xor an input string with a given character key.
    """
    output = ''.join([chr(ord(c) ^ key) for c in input])
    return output

# decode_base64 - decodes Base64 text with (optional) custom alphabet
#
# Author: amm
# Inputs:
#    intext:   string, text to decode
#    alphabet: string, 64 chars, custom alphabet for decoding (optional)
#    padchar:  char, single character used for padding bytes in input (optional)
# Returns: decoded string
#


def decode_base64(intext, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', padchar='=', debug=False):

    # Build dictionary from alphabet
    b64DictDec = {}
    i = 0
    for c in alphabet:
        if c in b64DictDec:
            print '%c already exists in alphabet' % (c)
            sys.exit(-1)
        b64DictDec[c] = i
        i += 1

    b64DictDec[padchar] = 0
    alphabet += padchar

    outtext = ''

    # support DOS and Unix line endings
    intext = intext.rstrip('\r\n')

    i = 0
    while i < len(intext) - 3:
        if intext[i] not in alphabet or intext[i + 1] not in alphabet or intext[i + 2] not in alphabet or intext[i + 3] not in alphabet:
            if debug:
                sys.stderr.write(
                    "Non-alphabet character found in chunk: %s\n" % (hexPlusAscii(intext[i:i + 4])))
            if debug:
                sys.stderr.write("Input: %s" % hexPlusAscii(intext))
            raise Exception
        val = b64DictDec[intext[i]] * 262144
        val += b64DictDec[intext[i + 1]] * 4096
        val += b64DictDec[intext[i + 2]] * 64
        val += b64DictDec[intext[i + 3]]
        i += 4
        for factor in [65536, 256, 1]:
            outtext += chr(int(val / factor))
            val = val % factor

    return outtext


# printableText - returns text suitable for screen display
#
# Author: amm
# Input:  intext (string)
#         onlyText (bool)
#            False = print tab and line-feed chars
#            True = Don't print tab and line-feed chars
# Output: string
#
def printableText(intext, onlyText=False):
    if onlyText:
        FILTER_std_display = ''.join(
            [chr(x) if x in range(32, 127) else '.' for x in range(256)])
    else:
        FILTER_std_display = ''.join(
            [chr(x) if x in [9, 10, 13] + range(32, 127) else '.' for x in range(256)])
    return intext.translate(FILTER_std_display)

# printableUnicode - returns unicode text minus control characters
#
# Author: amm
# Input:  intext (unicode string)
#         onlyText (bool)
#            False = print tab and line-feed chars
#            True = Don't print tab and line-feed chars
# Output: unicode string
#
# Reference: http://en.wikipedia.org/wiki/Unicode_control_characters
#
UNICODE_CONTROL_CHARS = [unichr(x) for x in range(
    0, 9) + [11, 12] + range(14, 0x20) + [0x7f] + range(0x80, 0xA0)]


def printableUnicode(intext, onlyText=False):
    if not type(intext) == unicode:
        # Attempt to cast it
        try:
            intext = unicode(intext)
        except:
            try:
                intext = unicode(intext, 'utf-8')
            except:
                return unicode(printableText(intext, onlyText))
    if onlyText:
        return ''.join([x for x in intext if x not in UNICODE_CONTROL_CHARS + [u'\t', u'\n', u'\r']])
    else:
        return ''.join([x for x in intext if x not in UNICODE_CONTROL_CHARS])

# hexPlusAscii - returns two-column hex/ascii display text for binary input
#
# Author: amm
# Input:  indata (string/binary)
#         width (optional, bytes of hex to display per line)
#         offset (optional, byte offset for display)
# Output: string
#


def hexPlusAscii(data, width=16, offset=0):
    FILTER_hex_display = ''.join(
        [(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    dlen = len(data)
    output = ''
    for i in xrange(0, dlen, width):
        s = data[i:i + width]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        printable = s.translate(FILTER_hex_display)
        output += "%08X   %-*s   %s\n" % (i +
                                          offset, 16 * 3 + 1, hexa, printable)
    return output

# URLDataToParameterDict - parses URL format string (i.e. the stuff after
#                          the question mark) and returns dictionary
#                          of parameters
#
# Author: amm
# Input:  urldata (string)
# Output: dictionary, indexed by parameter names
# Requires: urllib
#


def URLDataToParameterDict(data):
    if not ' ' in data:
        p, kwp = strtok(data, sep='&')
        return dict((urllib.unquote(k), urllib.unquote(kwp[k]))for k in kwp.keys())

# strtok - string tokenizer a lot like C strtok
# Author: twp
# Input: a string, optionally a param sep and a key/value sep, as_list will force a list even if 0/1 params
# Output: tuple of: None or string or list of params, dictionary indexed by key=value names of k/v params
# Example : a,b,c=d,e=f returns ([a,b],{c:d,e:f})


def strtok(data, sep=',', kvsep='=', as_list=False):
    kwparams = {}
    params = []
    for p in data.split(sep):
        if kvsep in p:
            (k, v) = p.split(kvsep, 1)
            kwparams[k.strip()] = v.strip()
        else:
            params.append(p.strip())
    if not as_list:
        if not len(params):
            params = None
        elif len(params) == 1:
            params = params[0]
    return params, kwparams

# mktime: if python timestamp object convery back to POSIX timestamp
# utctime: return UTC POSIX timestamp
# Author tparker


def mktime(ts):
    if type(ts) == datetime.datetime:
        return time.mktime(ts.timetuple())
    return ts


def utctime():
    return time.mktime(time.gmtime())

# xordecode(key,data)


def xorStringDecode(key=None, data=None):
    ptext = ''
    for pos in range(0, len(data)):
        ptext += chr(ord(data[pos]) ^ ord(key[pos % len(key)]))
    return ptext


def iptoint(ip): return struct.unpack('!L', socket.inet_aton(ip))[0]


def inttoip(i): return socket.inet_ntoa(struct.pack('!L', i))

# universal q&d options parser
# standard args:
# args = cmdline args to parse (usually sys.argv[1:])
# options = short option string, see getopt docs
# long_options = long options string, see getopt docs
#
# for repeated options:
# list_options = list of repeatable option keys ['-o','--option'] to make into lists
# auto_list = True to place any repeated options' values into lists
# replace_value = True to replace existing value if repeated option


def getopts(args, options,
            long_options=[],
            list_options=None,
            auto_list=False,
            replace_value=False):
    import getopt
    optd = {}
    opts, args = getopt.getopt(args, options, long_options)
    for o, v in opts:
        if o not in optd:  # new option
            if list_options and o in list_options:
                optd[o] = [v]  # this option wil be a list
            else:
                optd[o] = v  # else set to value
        elif type(optd[o]) == list:
            optd[o].append(v)  # append this value to list
        elif auto_list:
            optd[o] = [optd[o], v]  # else make value into a list
        elif replace_value:
            optd[o] = v  # replace value if desired
    return optd, args

# getHeader - Extracts header information from dpkt HTTP request or response
#             objects.
#
#    This utility function serves two main purposes:
#      1) Tests (with try block) to see if keyword is defined in the dpkt
#         header dictionary.  Returns empty string if not defined.
#      2) Handles duplicate headers.  If dpkt sees more than one named
#         header (e.g. User-Agent), it stores a list instead of a string,
#         which is generally confusing to upstream code.  We'll test for
#         that here and ALWAYS return a string.  (Lists will be comma
#         separated.)
#
# Author: amm
# Input:  request_or_response, header_name
# Output: string (always)
#


def getHeader(request_or_response, header_name):
    try:
        httpHdr = request_or_response.headers[header_name]
    except:
        return ''
    if type(httpHdr) == str:
        return httpHdr
    elif type(httpHdr) == list:
        # return unique list joined by ','
        return ', '.join(set(httpHdr))
    else:
        return ''

# HTTPlastmodified - Extracts last-modified (or date) header from
#                    HTTP response headers and normalizes date string format
#
# Author: amm
# Input:  dpkt.http.response
# Output: normalized datetime string
#


def HTTPlastmodified(response):
    try:
        return datetime.datetime.strptime(response.headers['last-modified'], '%a, %d %b %Y %H:%M:%S %Z').strftime('%Y-%m-%d %H:%M:%S')
    except:
        try:
            return datetime.datetime.strptime(response.headers['date'], '%a, %d %b %Y %H:%M:%S %Z').strftime('%Y-%m-%d %H:%M:%S')
        except:
            return ''
