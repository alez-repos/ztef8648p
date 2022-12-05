# Disclaimer: this part of the code is an adaptation from
# a script that was found on pastebin

import struct
import sys
import zcu
from zcu import constants
from zcu.xcryptors import CBCXcryptor
 
def configdec(key):
    infile = open("config.bin","rb")
    outfile = open("config.bin.txt","wb")
    header_magic = struct.unpack('>4I', infile.read(16))
    if header_magic == constants.ZTE_MAGIC:
        header = struct.unpack('>28I', infile.read(112))
    else:
        infile.seek(0)
    signature = zcu.zte.read_signature(infile).decode()
    print("[Configdecryptor]: Signature: %s" % signature)
    payload_type = zcu.zte.read_payload_type(infile)
 
    decryptor = CBCXcryptor("")
    decryptor.set_key(key,'ZTE%FN$GponNJ025')
 
    start_pos = infile.tell()
    if payload_type in (2, 4, 6):
        print("[Configdecryptor]: Has decrypt payload")
        try:
            infile_dec = decryptor.decrypt(infile)
            infile_dec.seek(0)
            if zcu.zte.read_payload_type(infile_dec, raise_on_error=False) is None:
                error("[Configdecryptor]: Malformed decrypted payload, likely you used the wrong key!")
                return
            infile = infile_dec
        except ValueError as ex:
            error("[Configdecryptor]: Failed to decrypt payload.")
            return
    else:
        print("[Configdecryptor]: No decrypt payload")
        pass
    res, _ = zcu.compression.decompress(infile)
    outfile.write(res.read())
    print("[Configdecryptor]: Successfully decoded! decrypted backup file is config.bin.txt")
 
def error(err):
    print(err, file=sys.stderr)
 