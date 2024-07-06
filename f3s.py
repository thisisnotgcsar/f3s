import os
import sys
# adding the src directory to the system path for searching modules inside it
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from src.f3s_core import f3s
from src.utils import print_banner
import argparse

# GIULIO GOLINELLI
# golinelli.giulio13@gmail.com - https://github.com/thisisnotgcsar
#
# Front-end of f3s. Interacts with the main module and display the results.

# Initializing argument parser
parser = argparse.ArgumentParser(	description='f3s: Find format strings',
				
									formatter_class=argparse.RawTextHelpFormatter,
									usage="f3s [-h, --help] [-v, --verbose] BINARY_FILE")
parser.add_argument('BINARY_FILE', type=argparse.FileType('rb'), help="Path of the binary file to analyze.")
parser.add_argument('-v', '--verbose', action='store_true', help='Output verbose informations while analyzing.')
args = parser.parse_args()

# print_banner()
results = f3s(str(os.path.abspath(args.BINARY_FILE.name)), args.verbose)
print(results)

if __name__ != "__main__":
	sys.stderr.write("This is a script, it should be run not imported.")
	exit(0)
