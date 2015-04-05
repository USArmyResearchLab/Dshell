'''
dShell output classes

@author: tparker
'''
import os
import sys
import logging
import struct
import datetime
import dshell
import util


class Output(object):

    '''
    dShell output base class, extended by output types
    '''

    _DEFAULT_FORMAT = ''
    _DEFAULT_TIMEFORMAT = '%Y-%m-%d %H:%M:%S'
    _DEFAULT_DELIM = ' '
    _NULL = None

    # true if you want to remove extra fields from the parsed record
    _FILTER_EXTRA = False

    def __init__(self, *a, **kw):
        '''
        base output class constructor
        configuration kwords:
                logger=<existing logging object> to pass in a logger
                format='format string' to override default formatstring for output class
                pcap = filename to write pcap
        '''
        # setup the logger
        self.logger = kw.get('logger', logging)

        # parse the format string
        self.setformat(kw.get('format', self._DEFAULT_FORMAT))
        self.timeformat = (kw.get('timeformat', self._DEFAULT_TIMEFORMAT))
        self.delim = (kw.get('delim', self._DEFAULT_DELIM))

        # Run flush() after every relevant write() if this is true
        self.nobuffer = (kw.get('nobuffer', False))

        if 'pcap' in kw:
            self.pcapwriter = PCAPWriter(kw['pcap'])
        else:
            self.pcapwriter = None

        # this is up to the output plugin to process
        # by default stuffs extra fields and data into 'extra' field
        # if _FILTER_EXTRA is true
        self.extra = kw.get('extra', False)

        # create the default session writer
        if 'session' in kw:
            self.sessionwriter = SessionWriter(**kw)
        else:
            self.sessionwriter = None

    # write a message to the log
    def log(self, msg, level=logging.INFO, *args, **kw):
        '''write a message to the log
                passes all args and kwargs thru to logging
                except for level= is used to set logging level'''
        self.logger.log(level, msg, *args, **kw)

    def setformat(self, formatstr=None, typemap=None):
        '''parse a format string and extract the field info
                if no string given, reverts to default for class
           will set self.fields to be a list of (name,type,spec) tuples
           self.fieldnames to a list of fieldnames
                and self.fieldmap to a list of key=in value=out mappings
        format string can also map in field to out field with %(in:out)spectype
         or specify an explicit out type with %(in:out)specintype:outtype
        (note this breaks compatibility with text formatting,
          but useful for db or other output modules)
          a typemap of [intype]=outtype (or [in]=(newintype,outtype)
                          can be used to map and replace types
           '''
        if formatstr:
            self.format = formatstr + "\n"
        else:
            self.format = self._DEFAULT_FORMAT + "\n"
        self.fields = []  # will be a (name,type,length) tuple
        self.fieldnames = []
        self.fieldmap = {}
        # get all the field names
        e = 0
        while True:
            # find the next format spec of %(...)
            s = self.format.find('%', e) + 1
            if s < 1 or self.format[s] != '(':
                break  # not %(...
            e = self.format.find(')', s)
            if e < 0:
                break  # didn't find a closing paren
            # get text between parens as field name
            fname = self.format[s + 1:e]
            # len/precision specs will be 0-9 between ) and type char
            fspec = ''
            for i in xrange(e + 1, len(self.format)):
                if self.format[i] in '1234567890.+-# lLh':
                    fspec += self.format[i]
                else:
                    break  # this char is not a spec char, it is the type char
            ftype = self.format[i]
            i += 1
            # is the field type a intype:outtype def?
            if i < len(self.format) and self.format[i] == ':':
                e = self.format.find(' ', i)  # find the end whitespace
                # split on: to get input:output mapping
                ftype, outtype = self.format[i - 1:e].split(':')
            else:
                outtype = None  # output will be same as input type
            e = i  # start at next char on loop
            try:  # field name to column mapping
                fname, fmap = fname.split(':')
            except:
                fmap = fname  # no mapping
            if typemap and ftype in typemap and not outtype:
                try:
                    (ftype, outtype) = typemap[ftype]
                except:
                    outtype = typemap[ftype]
            # append the field name,type,spec,mapping
            self.fields.append((fname, ftype, fspec))
            self.fieldnames.append(fname)
            if outtype:
                self.fieldmap[fname] = (fmap, outtype)  # map of in to out,type

    def parse(self, *args, **kw):
        '''parse the input args/kwargs into a record dict according to format string
         - timestamps are formatted to date/time strings
                 - fields not in the input will be defined but blank
                 - extra fields in the record will be formatted into a
                        "name=value name2=value2..." string and put in 'extra'
                 - args will go into 'data'
                 - format keyword can contain a new format string to use (this also sets format for future output)
        '''
        # convert timestamps to proper format
        for ts in [k for k in kw if k == 'ts' or k.endswith('time')]:
            dt = ts[:-4] + 'datetime'  # ts->datetime , Xtime -> Xdatetime
            kw[dt] = datetime.datetime.fromtimestamp(
                float(kw[ts])).strftime(self.timeformat)  # format properly
        if kw.get('direction') is 'cs':
            kw['dir_arrow'] = '->'
        elif kw.get('direction') is 'sc':
            kw['dir_arrow'] = '<-'
        else:
            kw['dir_arrow'] = '--'
        if 'format' in kw:
            self.setformat(kw['format'])  # change the format string?
            del kw['format']
        # create the record initialized to the _NULL value
        rec = dict((f, self._NULL) for f in self.fieldnames)
        # populate record from datadict if datadict key is a field
        if self._FILTER_EXTRA:
            rec.update(
                dict((f, kw[f]) for f in self.fieldnames if (f in kw and kw[f] != None)))
            # place extra datadict keys into the extra field (and exclude the
            # addr tuple)
            if self.extra:
                rec['extra'] = self.delim.join(['%s=%s' % (f, kw[f]) for f in sorted(
                    kw.keys()) if f not in self.fieldnames and f != 'addr'])
        else:  # not filtering extra, just lump them in as fields
            rec.update(kw)
        # populate the data field
        if args:
            rec['data'] = self.delim.join(map(str, args))
        return rec

    def dump(self, pkt=None, **kw):  # pass packets to pcap
        '''dump raw packet data to an output
                override this if you want a format other than pcap'''
        pktdata = str(pkt)  # might be string, might be a dpkt object
        pktlen = kw.get('len', len(pktdata))
        if self.pcapwriter:
            self.pcapwriter.write(pktlen, pktdata, kw['ts'])
        else:
            self.log(util.hexPlusAscii(str(pkt)), level=logging.DEBUG)

    # close the PCAP output
    def close(self):
        if self.pcapwriter:
            self.pcapwriter.close()

    def dispatch(self, m, *args, **kwargs):
        '''dispatch from Q pop'''
        if m == 'write':
            self.write(*args, **kwargs)
        if m == 'alert':
            self.alert(*args, **kwargs)
        if m == 'dump':
            self.dump(*args, **kwargs)


class FileOutput(Output):

    def __init__(self, *args, **kw):
        '''configuration for fileoutput:
                fh=<existing open file handle>
                file=filename to write to
                mode=mode to open file as, default 'w'
        '''
        # do base init first
        Output.__init__(self, *args, **kw)
        # get the output filehandle or file
        f = None
        if 'fh' in kw:
            self.fh = kw['fh']
            return
        elif 'file' in kw:
            f = kw['file']
        elif args:
            f = args[0]
        if f:
            if 'mode' in kw:
                mode = kw['mode']
            else:
                mode = 'w'
            if mode == 'noclobber':
                mode = 'w'
                try:
                    while os.stat(f):
                        p = f.split('-')
                        try:
                            p, n = p[:-1], int(p[-1])
                        except ValueError:
                            n = 0
                        f = '-'.join(p + ['%04d' % (int(n) + 1)])
                except OSError:
                    pass  # file not found
            self.fh = open(f, mode)
        else:
            self.fh = sys.stdout

    def write(self, obj, **kw):
        '''write session data to the session output or stdout'''
        if self.sessionwriter:
            self.sessionwriter.write(obj, **kw)
        elif self.fh:
            self.fh.write(str(obj))
            if self.nobuffer:
                self.fh.flush()

    def close(self):
        '''close output if not stdout'''
        if self.fh != sys.stdout:
            self.fh.close()
        Output.close(self)


class TextOutput(FileOutput):

    '''formatted text output to file or stdout'''

    _DEFAULT_FORMAT = "%(decoder)s %(datetime)s %(sip)16s:%(sport)-5s %(dir_arrow)s %(dip)16s:%(dport)-5s ** %(data)s **"
    _NULL = ''

    _FILTER_EXTRA = True

    def __init__(self, *args, **kw):
        if 'extra' in kw:
            self._DEFAULT_FORMAT += " [ %(extra)s ]"
        FileOutput.__init__(self, *args, **kw)

    def alert(self, *args, **kw):
        '''write an alert record
                we pass in the decoder object and args/dict'''
        rec = self.parse(*args, **kw)
        if rec:
            self.fh.write(self.format % rec)
            if self.nobuffer:
                self.fh.flush()


class DBOutput(Output):

    '''format strings as used by the DBOutput module to create tables and map fields
       these follow the usual %(name)type and in most cases a custom format string will work
            defualt type maps are:
                    s,r = VARCHAR (if field len given) /TEXT (if no len)
                    c = CHAR(1)
                    x,X,o = VARCHAR
                    d,i,u = INTEGER
                    e,E,f,F,g,G = DECIMAL
            with the following extra: (using these breaks text format string compatibility)
                    b = boolean
                    t = timestamp
                    D = datetime
                    T = this field selects table
                    (following are postgres-only)
                            A = inet
                            H = host
                            N = cidr
                            M = macaddr
            format string can also map field to column with %(field:column)type
             or specify an explicit column type with %(field:column)pytype:DBTYPE
            (note this also breaks compatibility with text format strings)
    '''

    _DEFAULT_FORMAT = "%(decoder)T %(ts:timestamp)t %(sip)s %(sport)s %(dip)s %(dport)s %(data:alert)s"
    _NULL = None
    # format type to (type,coltype) map
    _TYPEMAP = {'s': 'VARCHAR', 'r': 'VARCHAR', 'c': 'CHAR(1)',
                'x': 'VARCHAR', 'X': 'VARCHAR', 'o': 'VARCHAR',
                'd': 'INTEGER', 'i': 'INTEGER', 'u': 'INTEGER',
                'e': 'DECIMAL', 'E': 'DECIMAL',
                'f': 'DECIMAL', 'F': 'DECIMAL',
                'g': 'DECIMAL', 'G': 'DECIMAL',
                # 'b' isn't a python type, so (ftype,DBTYPE) tuple for value formats input as ftype
                'b': ('d', 'BOOLEAN'),
                # not standard across database types!
                't': ('f', 'TIMESTAMP'), 'D': ('s', 'DATETIME'),
                'A': ('s', 'INET'), 'H': ('s', 'HOST'), 'N': ('s', 'CIDR'), 'M': ('s', 'MACADDR')}  # these are postgres specific

    # acceptable params to pass to db module connect method
    _DBCONNPARAMS = ['host', 'user', 'passwd',
                     'password', 'db', 'database', 'port', 'charset']

    # map of db type to insert placeholder. '%s' is the default, but sqlite3 doesn't like it
    # you can override this with the 'placeholder' config keyword
    _DBTYPE_PLACEHOLDER_MAP = {'sqlite3': '?'}

    def __init__(self, *args, **kw):
        '''configuration:
                config=db config .ini file name to parse

                config keywords:

                dbtype=database type, selects DB API module to load
                                in conf file use [dbtype] section name instead

                host,user,passwd,password,db,database,port will be passed to db module if present

                table=db table to use if not specified by a field

                insert_param=character to use as parameter placeholder for INSERT
                                        (sqlite3=?, default=%%s)

                format_types=types to format before insert (default=x)
                                        ('s' to pad strings, 'x' to convert to hex, 'f' to format floats, 'fx' for hex and floats...)
        '''
        self.dbconfig = kw.copy()
        # if we were passed a config.ini file, parse it and add the k/v pairs
        # to the config
        if 'config' in self.dbconfig:
            import ConfigParser
            config = ConfigParser.ConfigParser()
            config.read(self.dbconfig['config'])
            sections = config.sections()
            if len(sections) > 0:
                self.dbconfig['dbtype'] = sections[0]
                for k, v in config.items(sections[0], raw=True):
                    self.dbconfig[k] = v
        # import the db module
        self.db = __import__(self.dbconfig['dbtype'])
        # create a connection, using a dict filtered to db conn params
        self.dbconn = self.db.connect(
            *args, **dict((k, self.dbconfig[k]) for k in self._DBCONNPARAMS if k in self.dbconfig))
        # do the base init last to catch the format string, etc.. (as it may
        # have come from the config file)
        Output.__init__(self, *args, **self.dbconfig)

    def createtable(self, table=None):
        '''creates a table based on the format string'''
        if not table and 'table' in self.dbconfig:
            table = self.dbconfig['table']
        try:
            cursor = self.dbconn.cursor()
            sqlfields = []
            for fname, ftype, fspec in [f for f in self.fields if f[1] != 'T']:
                ctype = self.fieldmap[fname][1]
                # if no width spec, use TEXT instead of VARCHAR and hope the db
                # likes it
                if ctype == 'VARCHAR' and not fspec:
                    ctype = 'TEXT'
                fdef = self.fieldmap[fname][0] + ' ' + ctype
                if fspec:
                    # try to conver python format spec to something SQL will
                    # take
                    fdef += '(' + \
                        fspec.strip('+-# lLh').replace('.', ',') + ')'
                sqlfields.append(fdef)
            sql = 'CREATE TABLE "' + table + '" (' + ','.join(sqlfields) + ')'
            self.log(sql, logging.DEBUG)
            return cursor.execute(sql)
        except:
            raise

    def close(self):
        '''closes database connection'''
        self.dbconn.close()
        Output.close(self)

    def alert(self, *args, **kw):
        '''write an output record
                we pass in the decoder object and args/dict'''
        rec = self.parse(self, *args, **kw)
        if rec:
            self.insert(rec)

    def setformat(self, formatstr=None):
        '''calls main setformat and then builds the insert SQL'''
        # what is the insert param??  some databases use %s, some use ?
        # try to map it or take the placeholder keyword from config
        ph = self.dbconfig.get('insert_param',
                               self._DBTYPE_PLACEHOLDER_MAP.get(
                                   self.dbconfig['dbtype'], '%%s')
                               )
        # these are the types we need to format before passing to the db
        self.format_types = self.dbconfig.get('format_types', 'x')
        Output.setformat(self, formatstr, typemap=self._TYPEMAP)
        # build all fields we map (except for [T]able select)
        self.tablefield = 'decoder'  # default to decodername
        for fname, ftype, fspec in self.fields:
            if ftype == 'T':
                self.tablefield = fname
        sqlfields = [self.fieldmap[fname][0]
                     for (fname, ftype, fspec) in self.fields if fname in self.fieldmap]
        self.insertsql = 'INSERT INTO "%%s" (%s) VALUES (%s)' % (
            ','.join(sqlfields), ','.join([ph] * len(sqlfields)))

    def insert(self, rec, table=None):
        ''' inserts rec dict using self.format into table (if given, else default or specified by field)
                if insert fails, tries to create table and insert again before raising exception  '''
        if not table:
            if 'table' in self.dbconfig:
                table = self.dbconfig['table']
            elif rec[self.tablefield]:
                table = rec[self.tablefield]
        try:
            sqlvalues = []
            cursor = self.dbconn.cursor()
            for fname, ftype, fspec in self.fields:
                if fname in self.fieldmap:
                    # do we preformat this data?
                    if ftype in self.format_types:
                        sqlvalues.append(('%' + fspec + ftype) % rec[fname])
                    else:
                        sqlvalues.append(rec[fname])
            # create a INSERT INTO table (fields) VALUES (?,?,?) for execute
            sql = self.insertsql % table
            self.log(sql + ' %s' % sqlvalues, logging.DEBUG)
        except:
            raise
        # try once, if it fails, try to create table and retry
        # throws on second failure or create table failure
        fail = False
        while True:
            try:
                cursor.execute(sql, sqlvalues)
                self.dbconn.commit()
                break  # success
            except Exception, e:
                self.log(e, level=logging.WARNING)
                if fail:
                    raise
                else:
                    fail = True
                    try:
                        self.createtable(table)
                    except:
                        raise


class PCAPWriter(FileOutput):

    '''writes a pcap file'''

    def __init__(self, *args, **kw):
        FileOutput.__init__(self, *args, **kw)
        if self.fh:
            self.fh.write(
                struct.pack('IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    # overrides Output.write to write session as PCAP
    # data flow is Output.dump->pcapwriter.write
    def write(self, pktlen, pktdata, ts):
        if self.fh:
            self.fh.write(
                struct.pack('II', int(ts), int((ts - int(ts)) * 1000000)))
            # captured length, original length
            self.fh.write(struct.pack('II', len(pktdata), pktlen))
            self.fh.write(pktdata)


class SessionWriter(Output):

    '''writes the session to one or more files'''

    def __init__(self, session=None, **kw):
        self.file = kw.get('session', session)
        self.dir = kw.get('direction', 'both')
        self.mode = kw.get('mode', 'a')
        self.timeformat = (kw.get('timeformat', self._DEFAULT_TIMEFORMAT))
        self.fieldnames = []

    def write(self, obj, **kwargs):
        out = None
        kw = dict(**kwargs)
        # if a session object with info() and data() methods (conn or blob, but
        # not packet)
        try:
            kw.update(**obj.info())  # get object info
            kw = self.parse(**kw)
            if self.dir == 'both':
                ds = [None]
            elif self.dir == 'split':
                ds = ['cs', 'sc']
            else:
                ds = [self.dir]
            for d in ds:
                kw.update(direction=d if d else 'both')  # set direction
                # format filename and open
                out = FileOutput(self.file % kw, mode=self.mode)
                # write obj data for direction
                out.fh.write(obj.data(direction=d))
                out.close()
        except:  # if not a session object
            # build filename from kw
            out = FileOutput(self.file % kw, mode=self.mode)
            out.fh.write(str(obj))
            out.close()


class QueueOutput(Output):

    '''pipes pickled packets to parent process'''

    def __init__(self, q, **kwargs):
        self.queue = q
        Output.__init__(self, **kwargs)

    def write(self, *args, **kw): self.dispatch('write', *args, **kw)

    def alert(self, *args, **kw): self.dispatch('alert', *args, **kw)

    def dump(self, *args, **kw): self.dispatch('dump', *args, **kw)

    def dispatch(self, m, *args, **kw):  # takes (method,...) to Q
        self.queue.put((m, args, kw))

    def close(self):
        self.queue.close()
        Output.close(self)


# default output module
obj = TextOutput
