import array
import os
import struct
import binwalk.core.common
import binwalk.core.compat
import binwalk.core.plugin

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

    _npk_file_item_types = {
            0x81a4: "file",
            0x81ed: "ELF",
            0x41ed: "dir"
    }

    npk_file_chunk_full_size = 0x8000
    npk_file_chunk_next_header = 2
    npk_file_chunk_final = False

    def _parse_npk_file_chunkheader(self, data):
        npk_file_chunk_start = struct.unpack("1s", binwalk.core.compat.str2bytes(data.read(n=1)))[0]
        npk_file_chunk_len = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        npk_file_chunk_magic = struct.unpack("2s", binwalk.core.compat.str2bytes(data.read(n=2)))[0]

        self.npk_file_chunk_next_header = data.tell() + npk_file_chunk_len
        self.npk_file_chunk_final = npk_file_chunk_len < self.npk_file_chunk_full_size
        if (self.npk_file_chunk_final):
            print ("\t chunk at 0x{: <{}x} start:{} size:0x{:x} end:{}{})".format(
                data.tell() - 5,
                len("{:x}".format(data.size)),
                npk_file_chunk_start.hex(" "),
                npk_file_chunk_len,
                npk_file_chunk_magic.hex(" "),
                " final chunk header" if self.npk_file_chunk_final else ""
            ))

    def _parse_npk_file_item(self, data):
        debug = False
        npk_file_item_offset = data.tell()
        npk_file_item_type = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        if (debug):
            print("type: 0x{:x}".format(npk_file_item_type))
        npk_file_item_zeros1 = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
        npk_file_item_zeros1b = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        if ((npk_file_item_zeros1<<8 | npk_file_item_zeros1) != 0):
            print("!!zeroes1: 0x{:x} 0x{:x}".format(npk_file_item_zeros1,npk_file_item_zeros1b))
        npk_file_item_unknown1 = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        if (True):
            print("unknown1: 0x{:x}".format(npk_file_item_unknown1))
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
        if (debug):
            print("item size: 0x{:x}".format(npk_file_item_size))
        npk_file_item_namelen = struct.unpack("<H", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        if (debug):
            print("item namelen: 0x{:x}".format(npk_file_item_namelen))
        npk_file_item_name = struct.unpack("{}s".format(npk_file_item_namelen), binwalk.core.compat.str2bytes(data.read(n=npk_file_item_namelen)))[0]
        if (debug):
            print("item name: {}".format(npk_file_item_name))
        npk_file_item_name = npk_file_item_name.decode()
        if (debug):
            print("item name decoded: {}".format(npk_file_item_name))
        npk_file_item_data_offset = data.tell()
        npk_file_item = ""
        #print("offset: 0x{:x} of 0x{:x}".format(data.tell(), data.size))

        next_item = data.tell() + npk_file_item_size
        npk_file_item_size_remaining = npk_file_item_size

        while (npk_file_item_size_remaining):
            chunk_header_within_file = (next_item > self.npk_file_chunk_next_header)
            if (chunk_header_within_file):
                npk_file_item_size_here = self.npk_file_chunk_next_header - data.tell()
            else:
                npk_file_item_size_here = npk_file_item_size_remaining

            npk_file_item = struct.unpack("{}s".format(npk_file_item_size_here), binwalk.core.compat.str2bytes(data.read(n=npk_file_item_size_here)))[0]
            npk_file_item_size_remaining -= npk_file_item_size_here
            if (chunk_header_within_file):
                    self._parse_npk_file_chunkheader(data)

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
            )

        return {"type": npk_file_item_type,
                "name": npk_file_item_name,
                "bytes": npk_file_item}

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
                npk_file_magic = struct.unpack("2s", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
                print ("\t Magic: {}".format(npk_file_magic.hex(" ")))
                self._parse_npk_file_chunkheader(data)

                # skip the NPK file header
                #data.seek(7)
                # NPK total size (NPK file length - 4 for tailing ?CRC)
                npk_file_total_size = data.size - 4

                #data.seek(0)
                print ("NPK file items")
                count = 0
                while data.tell() < (self.npk_file_chunk_next_header - 4):
                    print ("index: %d" % count)
                    count += 1
                    self._parse_npk_file_item(data)

                npk_file_crc32 = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
                print("FILE ITEMS END")
                print("file crc32?: 0x{:08x}".format(npk_file_crc32))

                data.close()
