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

if __name__ != "__main__":
	sys.stderr.write("This is a script, it should be run not imported.")
	exit(-1)

def depth_handler(v: int):
	v = int(v)
	if v <= 0:
		raise argparse.ArgumentTypeError(f"{v} for option depth is not a positive integer")
	return v

# just pretty prints the results in a easily parsable format
def present_results(results: list[tuple[str, int, list[tuple[str, int]]]]) -> None:
	if results:
		for result in results:
			sys.stdout.write(result[0] + "\t")			# print sink name
			sys.stdout.write(hex(result[1]) + "\t")		# print sink address
			for f in result[2]:							# print calltrace
				sys.stdout.write(f[0]+"@"+hex(f[1])+" ")
			print()
	else:
		print("No vulnerable sinks found.")

# Initializing argument parser
parser = argparse.ArgumentParser(	description='f3s: Format String Static Scanner\n\nTakes in input a binary file from any architecture and applies static taint analysis to find format string vulnerabilities. Vulnerabilities are then printed in the easily parsable format: [sink_name] [sink_address] [call trace].\n\nGIULIO GOLINELLI - golinelli.giulio13@gmail.com - https://github.com/thisisnotgcsar',
									formatter_class=argparse.RawTextHelpFormatter,
									usage="f3s [-h, --help] [-v, --verbose] BINARY_FILE")
parser.add_argument('BINARY_FILE', type=argparse.FileType('rb'), help="Path of the binary file to analyze.")
parser.add_argument('-v', '--verbose', action='store_true', help='Output verbose informations while analyzing.')
parser.add_argument('-d', '--depth', type=depth_handler, default=2, help='depth to reconstruct the calltrace from the backward slice of the sink. Higher value equals higher time of computation. Defaults to 10.')
args = parser.parse_args()

results: list[tuple[str, int, list[tuple[str, int]]]] = f3s(str(os.path.abspath(args.BINARY_FILE.name)), args.depth, args.verbose)
present_results(results)

if results:
	exit(0)		# if vulnerable sinks found
exit(1)			# otherwise exit code is 1
