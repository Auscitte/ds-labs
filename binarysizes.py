""" Collects stats about sizes of PE binaries.

:Copyright:
    Copyright Ry Auscitte 2022. This script is distributed under MIT License.
    
:Authors:
    Ry Auscitte
"""

import os
import sys
import struct

def check_pe_magic_numbers(path, size):
    """Checks magic numbers indicating that the file is a PE binary"""
    s = struct.Struct("<H58xI")
    if size < s.size:
        return False;
    
    with open(path, "rb") as fl:
        ps = s.unpack(fl.read(s.size))
        if ps[0] != 0x5A4D or size < ps[1] + 2:
            return False
        fl.seek(ps[1], 0)
        return fl.read(1) == b'P' and fl.read(1) == b'E'


def main(args):
    if len(args) < 3:
        print("usage: ", args[0], "<root dir> <out csv>")
        return;

    sizes = {}
    for root, dirs, files in os.walk(args[1]):
        fls = [ f for f in files if f.lower().endswith((".dll", ".exe", ".sys")) ]
        for f in fls:
            try:
                path = os.path.join(root, f)
                fsz = os.path.getsize(path)

                if not check_pe_magic_numbers(path, fsz):
                    continue

                if not fsz in sizes:
                    sizes[fsz] = 0
                sizes[fsz] += 1

            except Exception as e:
                print("Error accessing", path, "(", str(e), ")")

    lns = [ str(sz) + " " + str(sizes[sz]) + "\n" for sz in sizes ]
    with open(args[2], "w") as fl:
        fl.writelines(lns)

if __name__ == "__main__":
    main(sys.argv)
