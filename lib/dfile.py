'''
Dshell external file class/utils
for use in rippers, dumpers, etc.

@author: amm
'''
import os
from dshell import Blob
from shutil import move
from hashlib import md5

'''
Mode Constants
'''
FILEONDISK = 1  # Object refers to file already written to disk
FILEINMEMORY = 2  # Object contains file contents in data member

'''
dfile -- Dshell file class.

Extends blob for offset based file chunk (segment) reassembly.
Removes time and directionality from segments.

Decoders can instantiate this class and pass it to
output modules or other decoders.

Decoders can choose to pass a file in memory or already
written to disk.

A dfile object can have one of the following modes:
  FILEONDISK
  FILEINMEMORY

'''


class dfile(Blob):

    def __init__(self, mode=FILEINMEMORY, name=None, data=None, **kwargs):

        # Initialize Segments
        # Only really used in memory mode
        self.segments = {}
        self.startoffset = 0
        self.endoffset = 0

        # Initialize consistent info members
        self.mode = mode
        self.name = name
        self.diskpath = None
        self.info_keys = [
            'mode', 'name', 'diskpath', 'startoffset', 'endoffset']

        # update with additional info
        self.info(**kwargs)
        # update data
        if data != None:
            self.update(data)

    def __iter__(self):
        '''
        Undefined
        '''
        pass

    def __str__(self):
        '''
        Returns filename (string)
        '''
        return self.name

    def __repr__(self):
        '''
        Returns filename (string)
        '''
        return self.name

    def md5(self):
        '''
        Returns md5 of file
          Calculate based on reassembly from FILEINMEMORY
          or loads from FILEONDISK
        '''
        if self.mode == FILEINMEMORY:
            return md5(self.data()).hexdigest()
        elif self.mode == FILEONDISK:
            m = md5()
            fh = open(self.diskpath, 'r')
            m.update(fh.read())
            fh.close()
            return m.hexdigest()
        else:
            return None

    def load(self):
        '''
        Load file from disk.  Converts object to mode FILEINMEMORY
        '''
        if not self.mode == FILEONDISK:
            return False
        try:
            fh = open(self.diskpath, 'r')
            self.update(fh.read())
            fh.close()
            self.mode = FILEINMEMORY
        except:
            return False

    def write(self, path='.', name=None, clobber=False, errorHandler=None, padding=None, overlap=True):
        '''
        Write file contents at location relative to path.
        Name on disk will be based on internal name unless one is provided.

        For mode FILEINMEMORY, file will data() will be called for reconstruction.
          After writing to disk, mode will be changed to FILEONDISK.
        If mode is already FILEONDISK, file will be moved to new location.

        '''
        olddiskpath = self.diskpath
        if name == None:
            name = self.name
        self.diskpath = self.__localfilename(name, path, clobber)
        if self.mode == FILEINMEMORY:
            fh = open(self.diskpath, 'w')
            fh.write(self.data())
            fh.close()
            self.segments = {}
            self.startoffset = 0
            self.endoffset = 0
            return self.diskpath
        elif self.mode == FILEONDISK:
            move(olddiskpath, self.diskpath)
            return self.diskpath

    def update(self, data, offset=None):
        if self.mode != FILEINMEMORY:
            return
        # if offsets are not being provided, just keep packets in wire order
        if offset == None:
            offset = self.endoffset
        # don't buffer duplicate packets
        if offset not in self.segments:
            self.segments[offset] = data
        # update the end offset if this packet goes at the end
        if offset >= self.endoffset:
            self.endoffset = offset + len(data)

    #
    # Generate a local (extracted) filename based on the original
    #
    def __localfilename(self, origname, path='.', clobber=False):
        tmp = origname.replace("\\", "_")
        tmp = tmp.replace("/", "_")
        tmp = tmp.replace(":", "_")
        tmp = tmp.replace("?", "_")
        tmp = tmp.lstrip('_')
        localname = ''
        for c in tmp:
            if ord(c) > 32 and ord(c) < 127:
                localname += c
            else:
                localname += "%%%02X" % ord(c)
        # Truncate (from left) to max filename length on filesystem (-3 in case
        # we need to add a suffix)
        localname = localname[os.statvfs(path).f_namemax * -1:]
        # Empty filename not allowed
        if localname == '':
            localname = 'blank'
        localname = os.path.realpath(os.path.join(path, localname))
        if clobber:
            return localname
        # No Clobber mode, check to see if file exists
        suffix = ''
        i = 0
        while os.path.exists(localname + suffix):
            i += 1
            suffix = "_%02d" % i
        return localname + suffix
