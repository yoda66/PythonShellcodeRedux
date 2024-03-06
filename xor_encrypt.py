#!/usr/bin/env python3

import argparse
import numpy
import sys
import base64
import pathlib


def xorch(data: bytes, k: int) -> str:
    newkey = k.to_bytes(1, 'little') * len(data)
    res = numpy.bitwise_xor(bytearray(data), bytearray(newkey))
    return bytes(res)

def process_data(data, outfile, enckey=None):
    if enckey:
        data = xorch(data, enckey)
    prefix = outfile.stem
    print(f'[+] Writing data to [{outfile}]')
    of = open(outfile, 'wt')
    line = []
    of.write(f'{prefix} =  b""\n')
    for i, ch in enumerate(data):
        if i and not i % 16:
            of.write(f'{prefix} += b"' + ''.join(line) + '"\n')
            line = []
        line.append(f'\\x{ch:02x}')
    if i and i % 16:
        of.write(f'{prefix} += b"' + ''.join(line) + '"\n')
    of.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-k', type=int, default=None,
        help='single int/byte encryption key')
    parser.add_argument(
        '-f', default='', help='raw shellcode file name')
    args = parser.parse_args()
    outfile = ''
    if args.f:
        outfile = pathlib.Path(pathlib.Path(args.f).stem + '.enc')
        with open(args.f, 'rb') as fh:
            data = fh.read()
    else:
        print('[*] Shellcode filename not provided, ' +
              'waiting on piped data from stdin.')
        print('[*] <CTRL-C> to quit.')
        try:
            outfile = pathlib.Path('xor.enctxt')
            data = sys.stdin.buffer.read()
        except KeyboardInterrupt:
            print('\r[+] <CTRL-C> received. Quitting!')
            sys.exit()
    process_data(data, outfile, enckey=args.k)
