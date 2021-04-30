import array
import hashlib
import os
import struct
import binwalk.core.common
import binwalk.core.compat
import binwalk.core.plugin


# Each plugin must be subclassed from binwalk.core.plugin.Plugin
class MikrotikNPKParser(binwalk.core.plugin.Plugin):
    '''
    A binwalk plugin module for Mikrotik NPK files.
    '''

    # A list of module names that this plugin should be enabled for (see self.module.name).
    # If not specified, the plugin will be enabled for all modules.
    MODULES = ['Signature']

    SIGNATURE_DESCRIPTION = "NPK package header".lower()

    # The init method is invoked once, during module initialization.
    # At this point the module has been initialized, so plugins have access to the self.module object.
    # The self.module object is the currently running module instance; data from it can be read, but
    # should not be modified.
    def init(self):
        print ("MikrotikNPK initialized for module '%s'!" % self.module.name)

    # The new_file method is invoked once per file, after the file has been opened, but before
    # the module has processed the file. It is passed an instance of binwalk.core.common.BlockFile.
    def new_file(self, fp):
        print ("Module '%s' is about to scan file '%s'!" % (self.module.name, fp.path))

    # from tenable
    # https://github.com/tenable/routeros/blob/master/ls_npk/src/main.cpp
    _npk_item_types = {
            1: "part info",
            2: "part description",
            3: "dependencies",
            4: "file container",
            5: "install script [libinstall]",
            6: "uninstall script [libinstall]",
            7: "install script [bash]",
            8: "uninstall script [bash]",
            9: "signature",
            16: "architecture",
            17: "package conflicts",
            18: "package info",
            19: "part features",
            20: "package features",
            21: "squashfs block",
            22: "zero padding",
            23: "digest",
            24: "channel"
                }

    _npk_footer = b'\x10\x00\x01\x00\x00\x00\x49'
    _signature_reached = False
    _hash = hashlib.sha1()

    def _parse_npk_item(self, data):
        #npk_item_type = struct.unpack("h", binwalk.core.compat.str2bytes(header[offset:offset+2]))[0]
        npk_item_offset = data.tell()
        npk_item_type = struct.unpack("h", binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        npk_item_size = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
        npk_item_data_offset = data.tell()
        npk_item = ""
        if npk_item_type not in [4,21,22]:
            npk_item = struct.unpack("{}s".format(npk_item_size), binwalk.core.compat.str2bytes(data.read(n=npk_item_size)))[0]
        else:
            data.seek(data.tell() + npk_item_size)
        if npk_item_type == 9:
            self._signature_reached = True
            data.seek(npk_item_offset)
            self._hash.update(binwalk.core.compat.str2bytes(data.read(n=6)))
            data.seek(data.tell() + npk_item_size)
            hash_match = False
            stored_hash = npk_item[:self._hash.digest_size]
            if (stored_hash == self._hash.digest()):
                hash_match = True
            if hash_match:
                print ("hashes match")
            else:
                print ("hashes nomatch")
            print ("hash: {:s}".format(self._hash.hexdigest()))
        if not self._signature_reached:
            data.seek(npk_item_offset)
            self._hash.update(binwalk.core.compat.str2bytes(data.read(n=npk_item_size+6)))

        print ("offset 0x%x" % npk_item_offset)
        print ("Type: 0x{0:x} {1:s}".format(npk_item_type, self._npk_item_types[npk_item_type]))
        print ("Size: 0x%x" % npk_item_size)
        print ("{}".format(npk_item))

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
                npk_item_offsets = array.array('L')

                filename = os.path.abspath(result.file.path)
                data = binwalk.core.common.BlockFile(filename, 'rb', offset=offset)

                # skip the NPK header
                data.seek(4)
                # NPK total size (NPK file length - 8)
                npk_total_size = struct.unpack("<L", binwalk.core.compat.str2bytes(data.read(n=4)))[0]
                #npk_total_size = struct.unpack("<L", binwalk.core.compat.str2bytes(data[offset:offset+4]))[0]


                #data.seek(0)
                #self._hash.update(binwalk.core.compat.str2bytes(data.read(n=4)))
                print ("NPK size from header: 0x%x" % npk_total_size)
                print ("NPK items")
                count = 0
                while data.tell() < (npk_total_size):
                    print ("index: %d" % count)
                    count += 1
                    self._parse_npk_item(data)

                data.close()
