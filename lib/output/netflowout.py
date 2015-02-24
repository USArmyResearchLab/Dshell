'''
@author: amm
'''

import output
import util
import sys
import datetime


class NetflowOutput(output.TextOutput):

    '''
    Netflow Output module
    use with --output=netflowoutput
`       use group=clientip,serverip for grouping by clientip,serverip
    '''
    #_DEFAULT_FIELDS=[('decoder','s'),('datetime','s'),('sip','s'),('sport','s'),('dip','s'),('dport','s')]
    #_DEFAULT_FORMAT="%(starttime)s %(sip)16s:%(sport)-5s -> %(dip)16s:%(dport)-5s"

    def __init__(self, *args, **kwargs):
        self.group = kwargs.get('group')
        self.groups = {}
        if self.group:
            self.group = self.group.split('/')
        # Call parent init
        output.TextOutput.__init__(self, **kwargs)

    def alert(self, *args, **kw):
        if self.group:
            k = tuple(kw[g] for g in self.group)  # group by selected fields
            if k not in self.groups:
                r = k[::-1]
                if r in self.groups:
                    k = r  # is other dir in groups
                else:
                    self.groups[k] = []
            self.groups[k].append(kw)
        else:
            self.__alert(**kw)  # not grouping, just print it

    def close(self):
        # dump groups if we are closing output
        if self.group:
            for k in sorted(self.groups.iterkeys()):
                # write header
                self.fh.write(' '.join(
                    '%s=%s' % (self.group[i], k[i]) for i in xrange(len(self.group))) + '\n')
                for kw in self.groups[k]:
                    self.fh.write('\t')
                    self.__alert(self, **kw)
                self.fh.write('\n')
        output.TextOutput.close(self)

    def __alert(self, *args, **kw):
        self.fh.write('%s  %16s -> %16s  (%s -> %s) %4s  %6s  %6s %5d  %5d  %7d  %7d  %-.4fs\n' % (datetime.datetime.utcfromtimestamp(kw['starttime']),
                                                                                                   kw[
                                                                                                       'clientip'],
                                                                                                   kw[
                                                                                                       'serverip'],
                                                                                                   kw[
                                                                                                       'clientcountrycode'],
                                                                                                   kw[
                                                                                                       'servercountrycode'],
                                                                                                   kw[
                                                                                                       'proto'],
                                                                                                   kw[
                                                                                                       'clientport'],
                                                                                                   kw[
                                                                                                       'serverport'],
                                                                                                   kw[
                                                                                                       'clientpackets'],
                                                                                                   kw[
                                                                                                       'serverpackets'],
                                                                                                   kw[
                                                                                                       'clientbytes'],
                                                                                                   kw[
                                                                                                       'serverbytes'],
                                                                                                   (
                                                                                                       kw['endtime'] - kw['starttime'])
                                                                                                   )
                      )
        if self.nobuffer:
            self.fh.flush()

obj = NetflowOutput
