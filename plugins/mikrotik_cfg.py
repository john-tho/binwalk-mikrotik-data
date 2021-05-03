import array
import hashlib
import os
import struct
import binwalk.core.common
import binwalk.core.compat
import binwalk.core.plugin


# Each plugin must be subclassed from binwalk.core.plugin.Plugin
class MikrotikCFGParser(binwalk.core.plugin.Plugin):
    '''
    A binwalk plugin module for Mikrotik CFG files.
    '''

    # A list of module names that this plugin should be enabled for (see self.module.name).
    # If not specified, the plugin will be enabled for all modules.
    MODULES = ['Signature']

    SIGNATURE_DESCRIPTION = "Mikrotik CFG header".lower()

    # The init method is invoked once, during module initialization.
    # At this point the module has been initialized, so plugins have access to the self.module object.
    # The self.module object is the currently running module instance; data from it can be read, but
    # should not be modified.
    def init(self):
        print ("MikrotikCFG initialized for module '%s'!" % self.module.name)

    # The new_file method is invoked once per file, after the file has been opened, but before
    # the module has processed the file. It is passed an instance of binwalk.core.common.BlockFile.
    def new_file(self, fp):
        pass
        #print ("Module '%s' is about to scan file '%s'!" % (self.module.name, fp.path))

    # from OpenWrt
    # https://github.com/openwrt/openwrt/blob/master/target/linux/generic/files/drivers/platform/mikrotik/rb_hardconfig.c
    _hardcfg_item_types = {
            3: "flash info",
            4: "mac address",
            5: "board product code",
            6: "bios version",
            8: "sdram timings",
            9: "device timings",
            10: "software ID",
            11: "serial number",
            13: "memory size"
                }

    _cfg_footer = b'\x10\x00\x01\x00\x00\x00\x49'
    _signature_reached = False
    _hash = hashlib.sha1()

    def _parse_cfg_item(self, data, endian):
        tag_start_offset = data.tell()
        tag_part1 = struct.unpack(endian+"H",
                binwalk.core.compat.str2bytes(data.read(n=2)))[0]
        tag_part2 = struct.unpack(endian+"H",
                binwalk.core.compat.str2bytes(data.read(n=2)))[0]

        # little endian has type, size
        cfg_item_type = tag_part1
        cfg_item_size = tag_part2

        # big endian has size, type
        if endian == ">":
            cfg_item_size = tag_part1
            cfg_item_type = tag_part2

        if (cfg_item_type < 0 or cfg_item_type > 0x100 or
                cfg_item_size <= 0 or cfg_item_size > 0x10000):
            data.seek(tag_start_offset)
            return False

        cfg_item = struct.unpack("{}s".format(cfg_item_size), binwalk.core.compat.str2bytes(data.read(n=cfg_item_size)))[0]

        print ("\t tag@0x{:x}:".format(tag_start_offset) +
                " Type: 0x{0:x}".format(cfg_item_type) +
                " (len: 0x%x)" % cfg_item_size, end="")
        print (" Bytes: {}".format(cfg_item[0:9]))

        return True

    # The scan method is invoked each time the module registers a result during the file scan.
    # The plugin has full read/write access to the result data.
    def scan(self, result):
        if result.valid is True:
            if result.description.lower().startswith(self.SIGNATURE_DESCRIPTION) is True:
                #print ("Module '%s' has reported a valid result:" % self.module.name)
                #print ("\tFile: %s" % result.file.name)
                #print ("\tOffset: 0x%X" % result.offset)
                #print ("\tDescription: %s" % result.description)

                offset = result.offset
                cfg_item_offsets = array.array('L')
                endian = "<" # little endian default
                crc32 = 0

                filename = os.path.abspath(result.file.path)
                data = binwalk.core.common.BlockFile(filename, 'rb', offset=offset)
                # if 4 byte header is:
                # tfoS | draH, then BE
                # Soft | Hard, then LE

                header_type = struct.unpack("4s",
                        binwalk.core.compat.str2bytes(data.read(n=4)))[0]

                if header_type == b"tfoS":
                    header_type = b"Soft"
                    endian = ">"
                elif header_type == b"draH":
                    header_type = b"Hard"
                    endian = ">"

                print ("\tHeader type: %s" % header_type)

                # soft CFG has CRC32
                if header_type == b"Soft":
                    crc32 = struct.unpack(endian+"L",
                            binwalk.core.compat.str2bytes(data.read(n=4)))[0]
                    print ("\tCFG CRC32: 0x%x" % crc32)

                while True:
                    if not self._parse_cfg_item(data, endian):
                        break

                data.close()