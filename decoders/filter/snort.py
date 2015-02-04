import dshell


class DshellDecoder(dshell.IPDecoder):

    def __init__(self):
        dshell.IPDecoder.__init__(self,
                                  name='snort',
                                  description='filter packets by snort rule',
                                  longdescription="""Chainable decoder to filter TCP/UDP streams by snort rule
rule is parsed by dshell, a limited number of options are supported:
        currently supported rule options:
                content
                nocase
                depth
                offset
                within
                distance

Mandatory option:

--snort_rule: snort rule to filter by

or

-snort_conf: snort.conf formatted file to read for multiple rules

Modifier options:

--snort_all: Pass only if all rules pass
--snort_none: Pass only if no rules pass
--snort_alert: Alert if rule matches?

Example:
decode -d snort+followstream traffic.pcap --snort_rule 'alert tcp any any -> any any (content:"....."; nocase; depth .... )'

""",
                                  filter='ip or ip6',
                                  author='twp',
                                  optiondict={'rule': {'type': 'string', 'help': 'snort rule to filter packets'},
                                              'conf': {'type': 'string', 'help': 'snort.conf file to read'},
                                              'alerts': {'action': 'store_true', 'help': 'alert if rule matched'},
                                              'none': {'action': 'store_true', 'help': 'pass if NO rules matched'},
                                              'all': {'action': 'store_true', 'help': 'all rules must match to pass'}
                                              }
                                  )
        self.chainable = True

    def preModule(self):
        rules = []
        if self.conf:
            fh = file(self.conf)
            rules = [r for r in (r.strip() for r in fh.readlines()) if len(r)]
            fh.close()
        else:
            if not self.rule or not len(self.rule):
                self.warn("No rule specified (--%s_rule)" % self.name)
            else:
                rules = [self.rule]
        self.rules = []
        for r in rules:
            try:
                self.rules.append((self.parseSnortRule(r)))
            except Exception, e:
                self.error('bad snort rule "%s": %s' % (r, e))
                if self._DEBUG:
                    self._exc(e)
        if self.subDecoder:
            # we filter individual packets so session-based subdecoders will
            # need this set
            self.subDecoder.ignore_handshake = True
        dshell.IPDecoder.preModule(self)

    def rawHandler(self, pktlen, pkt, ts, **kwargs):
        kwargs['raw'] = pkt  # put the raw frame in the kwargs
        # continue decoding
        return dshell.IPDecoder.rawHandler(self, pktlen, pkt, ts, **kwargs)

    def IPHandler(self, addr, pkt, ts, **kwargs):
        '''check packets using filterfn here'''
        raw = str(
            kwargs['raw'])  # get the raw frame for forwarding if we match
        p = dshell.Packet(self, addr, pkt=str(pkt), ts=ts, **kwargs)
        a = []
        match = None
        for r, msg in self.rules:
            if r(p):  # if this rule matched
                match = True
                if msg:
                    a.append(msg)  # append rule message to alerts
                if self.none or not self.all:
                    break  # unless matching all, one match does it
            else:  # last rule did not match
                match = False
                if self.all:
                    break  # stop once no match if all

        # all rules processed, match = state of last rule match
        if (match is not None) and ((match and not self.none) or (self.none and not match)):
            self.decodedbytes += len(str(pkt))
            self.count += 1
            if self.alerts:
                self.alert(*a, **p.info())
            if self.subDecoder:
                # decode or dump packet
                self.subDecoder.decode(len(raw), raw, ts)
            else:
                self.dump(len(raw), raw, ts)

    def parseSnortRule(self, ruletext):
        '''returns a lambda function that can be used to filter traffic and the alert message
                this function will expect a Packet() object and return True or False'''
        KEYWORDS = (
            'msg', 'content')  # rule start, signal when we process all seen keywords
        msg = ''
        f = []
        rule = ruletext.split(' ', 7)
        (a, proto, sip, sp, arrow, dip, dp) = rule[:7]
        if len(rule) > 7:
            rule = rule[7]
        else:
            rule = None
        if a != 'alert':
            raise Exception('Must be alert rule')
        f.append('p.proto == "' + proto.upper() + '"')
        if sip != 'any':
            f.append('p.sip == "' + sip + '"')
        if dip != 'any':
            f.append('p.dip == "' + dip + '"')
        if sp != 'any':
            f.append('p.sport == ' + sp)
        if dp != 'any':
            f.append('p.dport == ' + dp)
        f = ['(' + (' and '.join(f)) + ')']  # create header condition
        if rule:
            # split between () and split on ;
            rule = rule.strip('()').split(';')
        last = None  # no last match
        while rule:
            try:
                k, v = rule.pop(0).strip().split(':', 1)
            except:
                continue
            if k.lower() == 'content':  # reset content match
                content = v.strip().strip('"')
                # hex bytes?
                if content.startswith('|') and content.endswith('|'):
                    content = ''.join(
                        '\\x' + c for c in content.strip('|').split())
                nocase = depth = offset = distance = within = None
                while rule:
                    r = rule[0].strip()
                    if ':' in r:
                        k, v = r.split(':', 1)
                    else:
                        k, v = r, None
                    k = k.lower()
                    if k in KEYWORDS:
                        break  # next rule part
                    elif k == 'nocase':
                        nocase = True
                    elif k == 'depth':
                        depth = int(v)
                    elif k == 'offset':
                        offset = int(v)
                    elif k == 'distance':
                        distance = int(v)
                    elif k == 'within':
                        within = int(v)
                    rule.pop(0)  # remove this keyword:valuea
                # add coerce to lower if nocase?
                if nocase:
                    nocase = '.lower()'
                else:
                    nocase = ''
                # start,end offsets of find(), maybe number or result of
                # another find()
                st, end = offset, depth
                # if we have a last content match, use the distance/within kws
                if last:
                    # within means this match has to be within X from
                    # previous+distance, so use previous as offset and within
                    # as depth
                    if within:
                        # set to last match and X from last match
                        st, end = last, last + '+' + str(within)
                    # distance means the next match must be AT LEAST X from the
                    # last
                    if distance:
                        # set start to last match+distance
                        st = last + '+' + str(distance)
                # else use the offset/depth values as given
                last = 'p.pkt' + nocase + \
                    '.find(' + "'" + content + "'" + nocase + ',' + \
                    str(st) + ',' + str(end) + ') != -1'
            if k.lower() == 'msg':
                msg = v.strip().strip('"')  # get alert message
        if last:
            f.append('(' + last + ')')
        f = ' and '.join(f)
        self.debug('%s\t%s\t"%s"' % (ruletext, f, msg))
        return eval('lambda(p): ' + f), msg  # return fn and msg


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
