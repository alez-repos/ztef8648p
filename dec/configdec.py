#!/usr/bin/python

# Disclaimer: this is not my work, I found it on pastebin

import struct
import sys
import argparse
 
import zcu
from zcu import constants
 
from zcu.xcryptors import T4Xcryptor
 
def main():
    parser = argparse.ArgumentParser(description="Decode config.bin from ZTE Routers",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("infile", type=argparse.FileType("rb"),
                        help="Encoded configuration file e.g. config.bin")
    parser.add_argument("outfile", type=argparse.FileType("wb"),
                        help="Output file e.g. config.xml")
    parser.add_argument("--key-prefix", type=str, default="",
                        help="Override key prefix for Type 6 devices")
    parser.add_argument("--iv-prefix", type=str, default="",
                        help="Override iv prefix for Type 6 devices")
    args = parser.parse_args()
 
    infile = args.infile
    outfile = args.outfile
    #print(constants.ZTE_MAGIC)
     
    header_magic = struct.unpack('>4I', infile.read(16))
    #print(header_magic)
    if header_magic == constants.ZTE_MAGIC:
        header = struct.unpack('>28I', infile.read(112))
    else:
        infile.seek(0)
 
    signature = zcu.zte.read_signature(infile).decode()
    print("Signature: %s" % signature)
    payload_type = zcu.zte.read_payload_type(infile)
 
    decryptor = T4Xcryptor("")
    if args.key_prefix:
        decryptor.set_key_prefix(args.key_prefix)
    if args.iv_prefix:
        decryptor.set_iv_prefix(args.iv_prefix)
    decryptor.set_key("")
 
    start_pos = infile.tell()
    if payload_type in (2, 4, 6):
        print("Has decrypt payload")
        try:
            infile_dec = decryptor.decrypt(infile)
            #print(infile_dec.read().hex()) 
            # try again
            infile_dec.seek(0)
            if zcu.zte.read_payload_type(infile_dec, raise_on_error=False) is None:
                error("Malformed decrypted payload, likely you used the wrong key!")
                return
            infile = infile_dec
        except ValueError as ex:
            error("Failed to decrypt payload.")
            return
    else:
        print("No decrypt payload")
        pass
    #print(infile.read().hex())
    #infile.seek(0)
    res, _ = zcu.compression.decompress(infile)
    outfile.write(res.read())
    print("Successfully decoded!")
 
 
def error(err):
    print(err, file=sys.stderr)
 
 
if __name__ == "__main__":
    main()
 
