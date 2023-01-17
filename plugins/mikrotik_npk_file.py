import array
import os
import struct
import binwalk.core.common
import binwalk.core.compat
import binwalk.core.plugin
import zlib
from datetime import datetime

# Each plugin must be subclassed from binwalk.core.plugin.Plugin
class MikrotikNPKFileParser(binwalk.core.plugin.Plugin):
    '''
    A binwalk plugin module for Mikrotik NPK file-container sections.
    '''

    # A list of module names that this plugin should be enabled for (see self.module.name).
    # If not specified, the plugin will be enabled for all modules.
    MODULES = ['Signature']

    SIGNATURE_DESCRIPTION = "NPK section file-container header".lower()

    # The init method is invoked once, during module initialization.
    # At this point the module has been initialized, so plugins have access to the self.module object.
    # The self.module object is the currently running module instance; data from it can be read, but
    # should not be modified.
    def init(self):
        print ("MikrotikNPKFile initialized for module '%s'!" % self.module.name)

    # The new_file method is invoked once per file, after the file has been opened, but before
    # the module has processed the file. It is passed an instance of binwalk.core.common.BlockFile.
    def new_file(self, fp):
        pass
        print ("Module '%s' is about to scan file '%s'!" % (self.module.name, fp.path))

    _debug = False

    _npk_file_item_types = {
            0x81a4: "file",
            0x81ed: "ELF",
            0x41ed: "dir"
    }

    def _parse_npk_file_item(self, data):
        npk_file_item_offset = data.tell()
        npk_file_item_type = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        if (self._debug):
            print("type: 0x{:x}".format(npk_file_item_type))
        npk_file_item_zeros1 = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
        npk_file_item_zeros1b = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        if ((npk_file_item_zeros1<<8 | npk_file_item_zeros1) != 0):
            print("!!zeroes1: 0x{:x} 0x{:x}".format(npk_file_item_zeros1,npk_file_item_zeros1b))

        npk_file_item_unknown1 = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
        npk_file_item_mtime = datetime.fromtimestamp(npk_file_item_unknown1)
        if (self._debug):
            print("unknown1: 0x{:08x} {}".format(npk_file_item_unknown1,
                                          datetime.fromtimestamp(npk_file_item_unknown1))
                  )
        npk_file_item_unknown2 = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
        if (self._debug):
            print("unknown2: 0x{:08x}".format(npk_file_item_unknown2))
        npk_file_item_unknown3 = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
        npk_file_item_ctime = datetime.fromtimestamp(npk_file_item_unknown3)
        if (self._debug):
            print("unknown3: 0x{:08x} {}".format(npk_file_item_unknown3,
                                          datetime.fromtimestamp(npk_file_item_unknown3))
                  )

        if (False):
            data.seek(data.tell()-12)

            data.seek(data.tell()+2)

            npk_file_item_file_sep = struct.unpack("10s", binwalk.core.compat.str2bytes(data.read(n=10)))[0]
            data.seek(data.tell()-10)

            npk_file_item_file_sep1 = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
            npk_file_item_file_sep2 = struct.unpack("6s", binwalk.core.compat.str2bytes(data.read(n=6)))[0]
            npk_file_item_file_sep1rep = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
            if (True):
                print("file separator: {}".format(npk_file_item_file_sep.hex(" ")))
            if (npk_file_item_file_sep1 != npk_file_item_file_sep1rep):
                print("!!file first & last two bytes !=: {:x} {:x}".format(npk_file_item_file_sep1, npk_file_item_file_sep1rep))

        npk_file_item_zeros2 = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
        if ((npk_file_item_zeros2) != 0):
            print("!!zeroes2: 0x{:x}".format(npk_file_item_zeros2))
        npk_file_item_size = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
        if (self._debug):
            print("item size: 0x{:x}".format(npk_file_item_size))
        npk_file_item_namelen = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        if (self._debug):
            print("item namelen: 0x{:x}".format(npk_file_item_namelen))
        npk_file_item_name = struct.unpack("{}s".format(npk_file_item_namelen), binwalk.core.compat.str2bytes(data.read(n=npk_file_item_namelen)))[0]
        if (self._debug):
            print("item name: {}".format(npk_file_item_name))
        npk_file_item_name = npk_file_item_name.decode()
        if (self._debug):
            print("item name decoded: {}".format(npk_file_item_name))
        npk_file_item_data_offset = data.tell()
        npk_file_item = ""
        #print("offset: 0x{:x} of 0x{:x}".format(data.tell(), data.size))

        npk_file_item = struct.unpack("{}s".format(npk_file_item_size), binwalk.core.compat.str2bytes(data.read(n=npk_file_item_size)))[0]

        if(True):
            print ("NPK item header:"
                   + " at 0x{: <{width}x}".format(
                       npk_file_item_offset,
                       width=len("{:x}".format(data.size))
                       )
                   + " type:{:x} {: <4}".format(
                       npk_file_item_type,
                       self._npk_file_item_types[npk_file_item_type]
                       )
                   + " size 0x{: <{width}x}".format(
                       npk_file_item_size,
                       width=len("{:x}".format(data.size))
                       )
                   + " name: {}".format(npk_file_item_name)
                   + " (unzlib) data offset 0x{:x}".format(
                       npk_file_item_data_offset
                       )
                   + " ctime: {} mtime: {}".format(
                       npk_file_item_ctime,
                       npk_file_item_mtime
                       )
            )

        return {"type": npk_file_item_type,
                "name": npk_file_item_name,
                "bytes": npk_file_item,
                "ctime": npk_file_item_ctime,
                "mtime": npk_file_item_mtime
                }

    # The scan method is invoked each time the module registers a result during the file scan.
    # The plugin has full read/write access to the result data.
    def scan(self, result):
        if result.valid is True:
            if result.description.lower().startswith(self.SIGNATURE_DESCRIPTION) is True:
                print ("Module '%s' has reported a valid result:" % self.module.name)
                print ("\tFile: %s" % result.file.name)
                print ("\tOffset: 0x%X" % result.offset)
                print ("\tDescription: %s" % result.description)

                offset = result.offset
                npk_file_item_offsets = array.array('L')

                filename = os.path.abspath(result.file.path)
                data = binwalk.core.common.BlockFile(filename, mode='rb', offset=result.offset)

                print ("\t length of loaded NPK section: {}".format(data.size))

                decompressor = zlib.decompressobj()
                decompressed = decompressor.decompress(binwalk.core.compat.str2bytes(data.read()))
                decompressed_all_consumed = decompressor.eof
                decompressed_unused = decompressor.unused_data
                decompressor.flush()
                print ("zlib decompressed all input: {}".format(decompressed_all_consumed))
                if (self._debug):
                    print ("all bytes consumed?: {}".format(
                               decompressor.eof)
                           + " first 0x10 bytes: {}".format(
                               decompressed[:0x10].hex(" "))
                           + " unused data len 0x{:x}".format(
                               len(decompressed_unused))
                           + " {}".format(
                               decompressed_unused[:0x10].hex(" "))
                           )
                data.close()

                data = binwalk.core.common.BlockFile(decompressed,
                                                     subclass=binwalk.core.common.StringFile)
                print ("NPK file items")
                print ("data tell {}".format(data.tell()))
                print ("data size{}".format(data.size))
                count = 0
                while data.tell() < data.size:
                    #print ("index: %d" % count)
                    count += 1
                    self._parse_npk_file_item(data)

                print("FILE ITEMS END")
