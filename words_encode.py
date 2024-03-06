import argparse
import pathlib
import random

class EncodeShellcode():

    ew = []
    picked = []

    def __init__(self, wordfile, shellcode_file,
                 indent=12, outfile='', minlen=0, maxlen=99):
        self.wordfile = pathlib.Path(wordfile)
        self.indent = indent
        self.shellcode_file = pathlib.Path(shellcode_file)
        self.minlen = minlen
        self.maxlen = maxlen

        if outfile:
            self.of = open(outfile, 'wt')
        else:
            self.of = open(f'{self.shellcode_file.stem}_encoded.py', 'wt')
        self.get_words()
        self.process_shellcode()
        self.of.close()

    def pick_word(self):
        while True:
            w = random.choice(self.words)
            if w not in self.picked and self.minlen <= len(w) <= self.maxlen:
                self.picked.append(w)
                return w

    def pick_num(self):
        while True:
            n = random.randint(1000, 1900)
            if n not in self.picked:
                self.picked.append(n)
                return n

    def get_words(self):
        fh = open(self.wordfile, 'rt')
        self.words = [x[:-1] for x in fh.readlines()]
        fh.close()
        while len(self.ew) < 256:
            self.ew.append(self.pick_word())

        self.of.write('dec = {')
        self.of.write(
            ','.join([f'"{x}": {i}'
            for i, x in enumerate(self.ew)]))
        self.of.write('}\n')

    def process_shellcode(self):
        fh = open(self.shellcode_file, 'rb')
        contents = fh.read()
        fh.close()
        self.of.write('sce = [')
        self.of.write((','.join([f'"{self.ew[int(x)]}"' for x in contents])))
        self.of.write(']\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-w', default='wordlists/lang-english.txt',
        help='words file')
    parser.add_argument(
        '-o', default='',
        help='output filename')
    parser.add_argument(
        '-minlen', type=int, default=0,
        help='minimum word length')
    parser.add_argument(
        '-maxlen', type=int, default=99,
        help='maximum word length')
    parser.add_argument(
        'shellcode', help='shellcode binary content')
    args = parser.parse_args()
    EncodeShellcode(
        args.w, args.shellcode, outfile=args.o,
        minlen=args.minlen, maxlen=args.maxlen)
